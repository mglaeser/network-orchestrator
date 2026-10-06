"""User-owned, supervised DNS-SD endpoint projection using Apple's system client.

The endpoint accepts fixed discovery intent only. The independent scanner and
publisher read canonical policy, durable operator intent and fresh owner reports
themselves. Neither commands, fabricated records nor privileged operations are
accepted from the coordinator.
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import math
import os
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .bonjour_process import (
    DiscoveryFailure,
    Registration,
    RegistrationExpired,
    interface_index,
    scan,
)
from .codec import MAX_JSON_BYTES, CodecError, canonical_bytes, digest, strict_loads
from .config import config_digest, load_config, profile_digest
from .discovery import (
    Publication,
    Record,
    dns_name_key,
    is_own_projection,
    project_export,
    txt_from_json,
    txt_to_json,
)
from .discovery_plan import discovery_digest
from .model import Config, Discovery
from .owners import effective_admissions, load_bindings, observe
from .planner import plan
from .state import (
    Intent,
    Observation,
    Snapshot,
    admissions_from_dict,
    intent_from_dict,
    observation_to_dict,
    snapshot_to_dict,
)
from .storage import Store
from .workflow_gate import (
    NOT_QUALIFIED,
    StageNotQualified,
    require_mutation_qualified,
    require_request_qualified,
)


@dataclass(frozen=True, slots=True)
class GuestInterface:
    id: str
    guest_interface: str
    guest_ipv4: str


@dataclass(frozen=True, slots=True)
class BonjourSettings:
    owner: str
    config: Path
    bindings: Path
    admissions: Path
    intent: Path
    state_dir: Path
    scopes: tuple[GuestInterface, ...]
    scan_seconds: int = 2
    poll_seconds: int = 5
    eligible_model_prefixes: tuple[str, ...] = ("AudioAccessory", "AppleTV")
    pass_seconds: int | None = None
    miss_tolerance: int = 1

    @property
    def pass_interval(self) -> int:
        """Seconds the scanner rests between two passes.

        ``poll_seconds`` also paces the publisher's independent evidence, which
        must stay younger than each dependency's own limit. A slower scan
        therefore has a value of its own; unset, it is ``poll_seconds`` as before.
        """
        return self.poll_seconds if self.pass_seconds is None else self.pass_seconds


def private_json(path: Path) -> Any:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise ValueError("owner settings and intent must be private regular files")
        with os.fdopen(os.dup(fd), "rb") as stream:
            return strict_loads(stream.read(1_048_577))
    finally:
        os.close(fd)


def load_settings(path: Path) -> BonjourSettings:
    raw = private_json(path)
    required = {
        "schema_version",
        "owner",
        "config",
        "bindings",
        "admissions",
        "intent",
        "state_dir",
        "scopes",
    }
    optional = {
        "scan_seconds",
        "poll_seconds",
        "eligible_model_prefixes",
        "pass_seconds",
        "miss_tolerance",
    }
    if (
        not isinstance(raw, dict)
        or not required <= raw.keys()
        or set(raw) - required - optional
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
    ):
        raise ValueError("invalid Bonjour settings")
    paths: dict[str, Path] = {}
    for key in ("config", "bindings", "admissions", "intent", "state_dir"):
        if not isinstance(raw[key], str) or "\0" in raw[key] or not os.path.isabs(raw[key]):
            raise ValueError("Bonjour paths must be explicit and absolute")
        paths[key] = Path(raw[key])
    config = load_config(paths["config"])
    owner = config.owner(raw["owner"])
    if owner.privilege != "user" or "discovery" not in owner.capabilities:
        raise ValueError("Bonjour owner requires an unprivileged discovery owner")
    scopes = []
    if not isinstance(raw["scopes"], list) or not raw["scopes"]:
        raise ValueError("Bonjour guest interfaces are required")
    for item in raw["scopes"]:
        if not isinstance(item, dict) or set(item) != {"id", "guest_interface", "guest_ipv4"}:
            raise ValueError("invalid Bonjour guest interface fields")
        scope = config.scope(item["id"])
        address = ipaddress.IPv4Address(item["guest_ipv4"])
        if address not in ipaddress.IPv4Network(scope.guest_cidr):
            raise ValueError("guest interface address is outside its configured network")
        interface = item["guest_interface"]
        if (
            not isinstance(interface, str)
            or not interface
            or not interface[0].isalpha()
            or not all(
                character.isascii() and (character.isalnum() or character in "_.-")
                for character in interface
            )
            or interface == scope.interface
        ):
            raise ValueError("invalid guest interface")
        scopes.append(GuestInterface(item["id"], interface, str(address)))
    if len({item.id for item in scopes}) != len(scopes):
        raise ValueError("duplicate Bonjour scope")
    if {item.scope for item in config.discovery if item.owner == owner.id} - {
        item.id for item in scopes
    }:
        raise ValueError("every owned discovery policy needs a guest interface")
    # This owner decides import eligibility on a device's _airplay._tcp record
    # and lets related types follow that record's host. An owned import policy
    # that does not list the type could never import anything, yet it would
    # read present for as long as it is active.
    if any(
        item.direction == "import" and "_airplay._tcp" not in item.types
        for item in config.discovery
        if item.owner == owner.id
    ):
        raise ValueError("an owned import policy needs the _airplay._tcp type")
    for key, default, maximum in (("scan_seconds", 2, 5), ("poll_seconds", 5, 10)):
        value = raw.get(key, default)
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError("Bonjour polling must be bounded")
    pass_seconds = raw.get("pass_seconds")
    if "pass_seconds" in raw:
        if type(pass_seconds) is not int or not 5 <= pass_seconds <= 120:
            raise ValueError("Bonjour polling must be bounded")
        # A pass refreshes each lease once. Its candidate has to stay fresh until
        # the next one is written, a rest and two scans later.
        if any(
            2 * pass_seconds > item.max_age_seconds
            for item in config.discovery
            if item.owner == owner.id
        ):
            raise ValueError("Bonjour pass interval must leave room inside every owned lease")
    prefixes = raw.get("eligible_model_prefixes", ["AudioAccessory", "AppleTV"])
    if (
        not isinstance(prefixes, list)
        or not prefixes
        or len(prefixes) > 16
        or any(
            not isinstance(item, str) or not item.isascii() or not item.isalnum()
            for item in prefixes
        )
        or len(set(prefixes)) != len(prefixes)
    ):
        raise ValueError("invalid Apple media model eligibility")
    tolerance = raw.get("miss_tolerance", 1)
    if type(tolerance) is not int or not 1 <= tolerance <= 8:
        raise ValueError("Bonjour miss tolerance must be bounded")
    settings = BonjourSettings(
        owner.id,
        **paths,
        scopes=tuple(scopes),
        scan_seconds=raw.get("scan_seconds", 2),
        poll_seconds=raw.get("poll_seconds", 5),
        miss_tolerance=tolerance,
        eligible_model_prefixes=tuple(prefixes),
        pass_seconds=pass_seconds,
    )
    # A missed record is carried only inside its lease (MissMemory). Where no
    # owned lease leaves room for that, a tolerance could never have an effect.
    if tolerance > 1 and not any(
        item.max_age_seconds > settings.pass_interval + carry_horizon(config, settings)
        for item in _owned(config, settings)
    ):
        raise ValueError("Bonjour miss tolerance needs a lease that outlasts two passes")
    return settings


def record_to_dict(record: Record) -> dict[str, Any]:
    return {
        "name": record.name,
        "service_type": record.service_type,
        "hostname": record.hostname,
        "port": record.port,
        "ipv4": record.ipv4,
        "txt": txt_to_json(record.txt),
        "interface": record.interface,
        "seen_at": record.seen_at,
        "source_service": record.source_service,
        "source_generation": record.source_generation,
    }


def record_from_dict(value: Any) -> Record:
    fields = {
        "name",
        "service_type",
        "hostname",
        "port",
        "ipv4",
        "txt",
        "interface",
        "seen_at",
        "source_service",
        "source_generation",
    }
    if not isinstance(value, dict) or set(value) != fields or not isinstance(value["txt"], list):
        raise ValueError("invalid discovery record fields")
    return Record(**{**value, "txt": txt_from_json(value["txt"])})


def _owned(config: Config, settings: BonjourSettings) -> tuple[Discovery, ...]:
    return tuple(item for item in config.discovery if item.owner == settings.owner)


def _interfaces(config: Config, settings: BonjourSettings) -> dict[str, tuple[int, int]]:
    result = {}
    for guest in settings.scopes:
        scope = config.scope(guest.id)
        result[guest.id] = (
            interface_index(scope.interface, scope.host_ipv4),
            interface_index(guest.guest_interface, guest.guest_ipv4),
        )
    return result


def independent_snapshot(
    config: Config, settings: BonjourSettings, now: float
) -> tuple[Snapshot, Intent, frozenset[str]]:
    """Read each established owner, not coordinator-supplied dependency claims."""
    clients = load_bindings(config, settings.bindings)
    clients.pop(settings.owner, None)
    snapshot = observe(config, clients)
    user_admissions = admissions_from_dict(private_json(settings.admissions))
    admissions = effective_admissions(config, clients, snapshot, user_admissions, now)
    intent = intent_from_dict(private_json(settings.intent))
    transport = plan(config, snapshot, admissions, intent, now)
    return snapshot, intent, transport.ready_profiles


def dependencies_ready(
    config: Config,
    policy: Discovery,
    snapshot: Snapshot,
    intent: Intent,
    ready: frozenset[str],
    now: float,
) -> bool:
    if (
        intent.blocked
        or snapshot.network_generation is None
        or not set(policy.dependencies) <= ready
    ):
        return False
    endpoint = snapshot.services.get(policy.service)
    if endpoint is None:
        return False
    endpoint = endpoint.at(now, policy.max_age_seconds)
    if (
        endpoint.state != "present"
        or endpoint.generation is None
        or endpoint.data.get("contract_sha256") != config.service(policy.service).contract_sha256
    ):
        return False
    for identifier in policy.dependencies:
        dependency = config.profile(identifier)
        observed = snapshot.profiles.get(identifier)
        service = snapshot.services.get(dependency.service)
        if observed is None or service is None:
            return False
        observed = observed.at(now, dependency.safety.max_age_seconds)
        service = service.at(now, dependency.safety.max_age_seconds)
        degraded = observed.data.get("effective_strategy") == "degraded-fallback"
        if degraded and (
            dependency.fallback_publication is None
            or observed.data.get("direct_available") is not False
            or not dependencies_ready(
                config,
                replace(policy, dependencies=(dependency.fallback_publication,)),
                snapshot,
                intent,
                ready,
                now,
            )
        ):
            return False
        expected_target = (
            config.scope(dependency.scope).host_ipv4
            if dependency.kind == "host-redirect" or degraded
            else service.data.get("ipv4")
        )
        if (
            observed.state != "present"
            or service.state != "present"
            or observed.data.get("policy_digest") != profile_digest(config, dependency)
            or observed.data.get("target_ipv4") != expected_target
            or observed.data.get("target_generation") != service.generation
            or observed.data.get("network_generation") != snapshot.network_generation
            or not isinstance(observed.data.get("states"), tuple)
        ):
            return False
    return True


def publications(
    config: Config, policy: Discovery, snapshot: Snapshot, ready: frozenset[str]
) -> tuple[Publication, ...]:
    endpoint = snapshot.services[policy.service]
    result = []
    for profile in config.profiles:
        if (
            profile.id not in ready
            or profile.service != policy.service
            or profile.scope != policy.scope
            or profile.kind != "publication"
            or endpoint.generation is None
        ):
            continue
        targets = profile.target_ports or profile.ports
        for offset in range(profile.ports.width):
            result.append(
                Publication(
                    policy.service,
                    endpoint.generation,
                    targets.first + offset,
                    profile.ports.first + offset,
                    config.scope(policy.scope).host_ipv4,
                    profile.protocol,
                )
            )
    return tuple(result)


def project_records(
    config: Config,
    policy: Discovery,
    records: tuple[Record, ...],
    snapshot: Snapshot,
    ready: frozenset[str],
    settings: BonjourSettings,
    now: float,
) -> tuple[Record, ...]:
    if len(records) > policy.max_records:
        raise DiscoveryFailure("incomplete")
    guest = next(item for item in settings.scopes if item.id == policy.scope)
    if policy.direction == "import":
        scope = config.scope(policy.scope)
        fresh = tuple(
            record
            for record in records
            if record.interface == scope.interface
            and record.service_type in policy.types
            and record.seen_at <= now <= record.seen_at + policy.max_age_seconds
            and ipaddress.IPv4Address(record.ipv4) in ipaddress.IPv4Network(scope.lan_cidr)
            and not is_own_projection(record, config.discovery_names)
        )
        eligible = {
            (dns_name_key(record.hostname), record.ipv4)
            for record in fresh
            if record.service_type == "_airplay._tcp"
            and apple_eligible(record.txt, settings.eligible_model_prefixes)
        }
        selected = tuple(
            record for record in fresh if (dns_name_key(record.hostname), record.ipv4) in eligible
        )
        import_keys = [(record.name, record.service_type) for record in selected]
        if len(import_keys) != len(set(import_keys)) or not set(policy.dependencies) <= ready:
            raise DiscoveryFailure("incomplete")
        return tuple(
            replace(
                record,
                interface=guest.guest_interface,
                hostname=config.discovery_names.import_prefix
                + digest(
                    {
                        "host": record.hostname,
                        "ipv4": record.ipv4,
                        "name": record.name,
                        "type": record.service_type,
                    }
                )[:16]
                + ".local.",
            )
            for record in selected
        )
    endpoint = snapshot.services[policy.service]
    own = tuple(
        replace(record, source_service=policy.service, source_generation=endpoint.generation)
        for record in records
        if record.ipv4 == endpoint.data.get("ipv4")
    )
    projected = []
    for record in own:
        projection = project_export(
            config,
            policy,
            record,
            endpoint,
            publications(config, policy, snapshot, ready),
            ready,
            now,
            interface_confirmed=True,
        )
        if projection.record is not None:
            projected.append(
                replace(
                    projection.record,
                    txt=rewrite_endpoint_urls(record, projection.record),
                    hostname=config.discovery_names.export_prefix
                    + digest(
                        {"policy": policy.id, "name": record.name, "type": record.service_type}
                    )[:16]
                    + ".local.",
                )
            )
    keys = [(record.name, record.service_type, record.interface) for record in projected]
    if len(keys) != len(set(keys)):
        raise DiscoveryFailure("incomplete")
    return tuple(projected)


def rewrite_endpoint_urls(source: Record, target: Record) -> tuple[bytes, ...]:
    """Retain the existing HA URL-field projection; unrelated metadata is opaque."""
    if source.service_type != "_home-assistant._tcp":
        return source.txt
    rewritten = []
    for entry in source.txt:
        key, separator, value = entry.partition(b"=")
        if key in {b"internal_url", b"base_url"}:
            try:
                address = urlsplit(value.decode("utf-8"))
                # The host as the URL spells it: urlsplit's own hostname is
                # lower-cased with Unicode rules, DNS names compare by ASCII case.
                host = address.netloc.rpartition("@")[2].partition(":")[0]
                if (
                    address.scheme in {"http", "https"}
                    and address.hostname is not None
                    and dns_name_key(host.rstrip("."))
                    in {source.ipv4, dns_name_key(source.hostname.rstrip("."))}
                    and address.username is None
                    and address.password is None
                ):
                    value = urlunsplit(
                        (
                            address.scheme,
                            f"{target.ipv4}:{target.port}",
                            address.path,
                            address.query,
                            address.fragment,
                        )
                    ).encode()
            except (ValueError, UnicodeError):
                pass
        rewritten.append(key + separator + value)
    return tuple(rewritten)


def apple_eligible(txt: tuple[bytes, ...], prefixes: tuple[str, ...]) -> bool:
    """Preserve the existing native owner's model/am eligibility contract."""
    fields: dict[bytes, bytes] = {}
    for entry in txt:
        key, _separator, value = entry.partition(b"=")
        key = key.lower()
        if key in {b"model", b"am"}:
            if key in fields:
                return False
            fields[key] = value.lower()
    return any(
        fields.get(b"model", b"").startswith(prefix.lower().encode()) for prefix in prefixes
    ) or fields.get(b"am", b"").startswith(b"appletv")


def _observation(
    config: Config,
    policy: Discovery,
    state: str,
    reason: str,
    now: float,
    snapshot: Snapshot | None,
    *,
    interface: bool,
    count: int = 0,
    skipped: int = 0,
) -> Observation:
    endpoint = snapshot.services.get(policy.service) if snapshot else None
    return Observation(
        state,
        reason,
        now,
        endpoint.generation if endpoint else None,
        {
            "policy_digest": discovery_digest(config, policy),
            "interface_confirmed": interface,
            "service_generation": endpoint.generation if endpoint else None,
            "network_generation": snapshot.network_generation if snapshot else None,
            "states": [],
            "record_count": count,
            "skipped_count": skipped,
        },
    )


# Time limits of one scanner pass, in seconds; pass_budget adds them up.
_OWNER_READ_LIMIT = 10  # owners.ProcessOwner: the report of one other owner
_INTERFACE_CHECK_LIMIT = 2  # bonjour_process.interface_index; twice for each scope
_SCAN_LIMIT = 45  # bonjour_process.scan: one service type
_SCAN_BATCH = 8  # service types that scan_policy reads at once
_PASS_SLACK = 5  # process clean-up, the pass's writes and the publisher's next tick


def pass_budget(config: Config, settings: BonjourSettings) -> int:
    """Seconds one scanner pass may take from its clock reading to its candidate in force.

    Every native read of a pass has a time limit of its own, so the pass takes
    no longer than their sum: one report read for each other owner, two
    interface checks for each scope and one scan for each batch of service
    types of each owned policy. A report file is read well inside the limit of
    an owner process unless every one of its permission checks nearly times out.
    """
    return (
        _OWNER_READ_LIMIT * (len(config.owners) - 1)
        + 2 * _INTERFACE_CHECK_LIMIT * len(settings.scopes)
        + _SCAN_LIMIT * sum(-(-len(item.types) // _SCAN_BATCH) for item in _owned(config, settings))
        + _PASS_SLACK
    )


def carry_horizon(config: Config, settings: BonjourSettings) -> int:
    """Seconds after a pass reads its clock until the next pass's candidate is in force.

    The pass writes its candidate within one budget, the scanner rests, and the
    next pass writes within another. lease_records refuses a whole candidate for
    one expired record, so a record that a pass missed is carried only while its
    lease lasts longer than this: it must not end between two candidates.
    """
    return settings.pass_interval + 2 * pass_budget(config, settings)


Fence = tuple[str, str | None, str | None]
Remembered = dict[tuple[str, str], tuple[Record, int]]


class MissMemory:
    """Source records the scanner has read, so that a later pass may miss them.

    A record that a completed pass of its policy does not read again stays among
    that pass's sources, with the time it was last seen, until as many
    consecutive completed passes as the settings tolerate have missed it. The
    pass decides about it as about any source it read, so what it would not
    project now is not kept. The time of sight is never refreshed: the lease,
    the client's own lifetime and the publisher's deadline end a carried record
    as they end any other. The memory belongs to this scanner process. A restart
    forgets it, and so does a failed or skipped pass of the policy.
    """

    def __init__(self, tolerance: int) -> None:
        self.tolerance = tolerance
        self.listed: dict[str, tuple[Fence, Remembered]] = {}

    def begin(self, policy: Discovery, fence: Fence, needed_until: float) -> MissedSources:
        """Start one policy's pass; unless it completes, nothing is carried over."""
        kept, known = self.listed.pop(policy.id, (fence, {}))
        # Nothing read under another policy digest, guest or network generation is kept.
        return MissedSources(self, policy, fence, known if kept == fence else {}, needed_until)


@dataclass(slots=True)
class MissedSources:
    """One policy's pass: what it adds to the sources it read, and what it then keeps."""

    memory: MissMemory
    policy: Discovery
    fence: Fence
    known: Remembered
    needed_until: float
    read: Remembered | None = None

    def __call__(self, sources: tuple[Record, ...]) -> tuple[Record, ...]:
        """Sources an earlier pass listed that this pass did not read and may carry."""
        read: Remembered = {(record.name, record.service_type): (record, 0) for record in sources}
        carried = sorted(
            (misses + 1, -record.seen_at, key, record)
            for key, (record, misses) in self.known.items()
            # A record read now under the same name and type takes its place.
            if key not in read
            and misses + 1 < self.memory.tolerance
            and record.seen_at + self.policy.max_age_seconds > self.needed_until
        )
        # Carried sources never push a pass over the policy's record bound.
        room = max(0, self.policy.max_records - len(sources))
        for misses, _seen, key, record in carried[:room]:
            read[key] = (record, misses)
        self.read = read
        return tuple(record for record, misses in read.values() if misses)

    def completed(self, records: tuple[Record, ...]) -> None:
        """Remember the sources of what the completed pass listed, and nothing else."""
        names = {(record.name, record.service_type) for record in records}
        self.memory.listed[self.policy.id] = (
            self.fence,
            {key: value for key, value in (self.read or {}).items() if key in names},
        )


def scan_policy(
    config: Config,
    settings: BonjourSettings,
    policy: Discovery,
    snapshot: Snapshot,
    ready: frozenset[str],
    interfaces: dict[str, tuple[int, int]],
    now: float,
    missed: Callable[[tuple[Record, ...]], tuple[Record, ...]] | None = None,
) -> tuple[tuple[Record, ...], int]:
    """The policy's projected records and the number of instances left out."""
    scope = config.scope(policy.scope)
    guest = next(item for item in settings.scopes if item.id == policy.scope)
    source = scope.interface if policy.direction == "import" else guest.guest_interface
    index = interfaces[policy.scope][0 if policy.direction == "import" else 1]
    # An export ties a record to its service by the inspected guest address; a
    # guest may hold further addresses. An import keeps exactly one address.
    inspected = snapshot.services[policy.service].data.get("ipv4")
    guest_ipv4 = inspected if policy.direction == "export" and isinstance(inspected, str) else None
    left_out: list[str] = []
    with ThreadPoolExecutor(max_workers=min(8, len(policy.types))) as pool:
        futures = [
            pool.submit(
                scan,
                source,
                index,
                kind,
                policy.max_records,
                settings.scan_seconds,
                now,
                guest_ipv4=guest_ipv4,
                skipped=left_out,
            )
            for kind in policy.types
        ]
        collected: list[Record] = []
        deadline = time.monotonic() + min(45, policy.max_age_seconds / 2)
        for future in futures:
            collected.extend(future.result(timeout=max(0.01, deadline - time.monotonic())))
            if len(collected) > policy.max_records:
                raise DiscoveryFailure("incomplete")
    sources = tuple(collected)
    if missed is not None:
        sources += missed(sources)
    projected = project_records(config, policy, sources, snapshot, ready, settings, now)
    return projected, len(left_out)


def scan_pass(
    config: Config, settings: BonjourSettings, store: Store, memory: MissMemory | None = None
) -> None:
    """A complete policy pass refreshes its lease independently of its siblings."""
    now = time.time()
    snapshot, intent, ready = independent_snapshot(config, settings, now)
    interfaces = _interfaces(config, settings)
    candidates: dict[str, Any] = {}
    for policy in _owned(config, settings):
        records: tuple[Record, ...] = ()
        skipped = 0
        error = None
        missed = None
        if memory is not None:
            missed = memory.begin(
                policy,
                (
                    discovery_digest(config, policy),
                    snapshot.services[policy.service].generation,
                    snapshot.network_generation,
                ),
                now + carry_horizon(config, settings),
            )
        try:
            if dependencies_ready(config, policy, snapshot, intent, ready, now):
                records, skipped = scan_policy(
                    config, settings, policy, snapshot, ready, interfaces, now, missed
                )
                if missed is not None:
                    missed.completed(records)
        except Exception as exc:
            error = exc.reason if isinstance(exc, DiscoveryFailure) else "malformed"
        candidates[policy.id] = {
            "policy_digest": discovery_digest(config, policy),
            "service_generation": snapshot.services[policy.service].generation,
            "network_generation": snapshot.network_generation,
            "records": [record_to_dict(record) for record in records],
            "interface_confirmed": True,
            "observed_at": now,
        }
        # Left out while zero: a pass that read every instance writes the same
        # candidate as before.
        if skipped:
            candidates[policy.id]["skipped"] = skipped
        if error is not None:
            candidates[policy.id]["reason"] = error
    document = {
        "schema_version": 1,
        "config_digest": config_digest(config),
        "observed_at": now,
        "policies": candidates,
    }
    # One state file holds every policy's candidate. When it would exceed the
    # file's bounds, the bulkiest policy loses its records with a reason of its
    # own until the rest fits; the other policies keep their lease.
    while not _storable(document):
        bulky = [key for key, value in candidates.items() if value["records"]]
        if not bulky:
            break
        largest = max(bulky, key=lambda key: (len(json.dumps(candidates[key]["records"])), key))
        candidates[largest]["records"] = []
        candidates[largest]["reason"] = "incomplete"
        if memory is not None:
            # Its pass counts as failed: nothing of it is carried into the next one.
            memory.listed.pop(largest, None)
    store.write("candidates.json", document)


def _storable(document: dict[str, Any]) -> bool:
    """Whether the store's writer would accept this document: its line fits."""
    try:
        return len(canonical_bytes(document)) < MAX_JSON_BYTES
    except CodecError:
        return False


def desired_requests(config: Config, settings: BonjourSettings, store: Store) -> dict[str, Any]:
    try:
        raw = store.read("requests.json")
    except FileNotFoundError:
        return {}
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "policies"}
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or not isinstance(raw["policies"], dict)
    ):
        raise ValueError("invalid desired discovery intent")
    # The state directory outlives a policy: a declaration that was retired or
    # renamed leaves its request behind. Only declared policies are ever read, so
    # such an entry cannot cause a registration; it is dropped here and is gone
    # from the file with the endpoint's next write under the lock.
    owned = {item.id for item in _owned(config, settings)}
    return {key: value for key, value in raw["policies"].items() if key in owned}


def lease_records(
    config: Config,
    policy: Discovery,
    request: Any,
    candidate: Any,
    snapshot: Snapshot,
    intent: Intent,
    ready: frozenset[str],
    now: float,
) -> tuple[Record, ...] | None:
    """Revalidate all independent fences before handing records to the publisher."""
    if (
        not isinstance(request, dict)
        or set(request)
        != {"active", "policy_digest", "service_generation", "network_generation", "requested_at"}
        or type(request["active"]) is not bool
    ):
        return None
    if not request["active"]:
        return ()
    if not isinstance(candidate, dict) or set(candidate) - {"skipped"} != {
        "policy_digest",
        "service_generation",
        "network_generation",
        "records",
        "interface_confirmed",
        "observed_at",
    }:
        return None
    # Instances the scan left out: absent while none, at most one per browsed
    # name of each type.
    if "skipped" in candidate and (
        type(candidate["skipped"]) is not int
        or not 1 <= candidate["skipped"] <= policy.max_records * len(policy.types)
    ):
        return None
    endpoint = snapshot.services.get(policy.service)
    if endpoint is None or not dependencies_ready(config, policy, snapshot, intent, ready, now):
        return None
    if (
        candidate["interface_confirmed"] is not True
        or request["policy_digest"] != discovery_digest(config, policy)
        or candidate["policy_digest"] != discovery_digest(config, policy)
        or request["service_generation"] != endpoint.generation
        or candidate["service_generation"] != endpoint.generation
        or request["network_generation"] != snapshot.network_generation
        or candidate["network_generation"] != snapshot.network_generation
        or type(candidate["observed_at"]) not in {float, int}
        or not candidate["observed_at"] <= now <= candidate["observed_at"] + policy.max_age_seconds
        or not isinstance(candidate["records"], list)
        or len(candidate["records"]) > policy.max_records
    ):
        return None
    records = tuple(record_from_dict(value) for value in candidate["records"])
    scope = config.scope(policy.scope)
    for record in records:
        expected_network = scope.lan_cidr
        if (
            record.service_type not in policy.types
            or ipaddress.IPv4Address(record.ipv4) not in ipaddress.IPv4Network(expected_network)
            or not record.seen_at <= now <= record.seen_at + policy.max_age_seconds
        ):
            return None
        if policy.direction == "export" and (
            record.ipv4 != scope.host_ipv4
            or record.source_service != policy.service
            or record.source_generation != endpoint.generation
        ):
            return None
    return records


class Publisher:
    """Independent watchdog owns all registration children and their deadlines."""

    def __init__(self, factory: Callable[[Record, int, int], Registration] = Registration) -> None:
        self.factory = factory
        self.children: dict[str, Registration] = {}
        self.deadlines: dict[str, float] = {}
        self.sources_seen_at: dict[str, float] = {}
        # Confirmed records whose client ended on its own timer and whose
        # replacement has not confirmed yet.
        self.renewing: set[str] = set()

    def reconcile(
        self, policy: Discovery, records: tuple[Record, ...], index: int, now: float
    ) -> bool:
        desired = {
            policy.id + ":" + digest(record_to_dict(replace(record, seen_at=0))): record
            for record in records
        }
        for key in tuple(self.children):
            if key.startswith(policy.id + ":") and key not in desired:
                self.children.pop(key).close()
                self.deadlines.pop(key, None)
                self.sources_seen_at.pop(key, None)
                self.renewing.discard(key)
        confirmed = True
        for key, record in desired.items():
            lifetime = min(120, max(1, math.ceil(record.seen_at + policy.max_age_seconds - now)))
            if key not in self.children:
                # Native CLI self-expiry also bounds orphan registrations after
                # SIGKILL of this watchdog. No daemon timer alone can do that.
                self.children[key] = self.factory(record, index, lifetime)
            deadline = time.monotonic() + max(0, record.seen_at + policy.max_age_seconds - now)
            if record.seen_at > self.sources_seen_at.get(key, -1):
                self.deadlines[key] = deadline
                self.sources_seen_at[key] = record.seen_at
            else:
                self.deadlines[key] = min(self.deadlines[key], deadline)
            try:
                try:
                    active = self.children[key].poll()
                except RegistrationExpired:
                    # Only this record's own native timer ended; nothing failed and
                    # its siblings are not touched. The client has ended, so its
                    # replacement never runs beside it. The lease deadline stays.
                    ended = self.children[key]
                    ended.close()
                    self.children[key] = self.factory(record, index, lifetime)
                    # A confirmed record keeps the policy's state while its
                    # replacement confirms; Registration.poll bounds that wait.
                    if ended.active:
                        self.renewing.add(key)
                    else:
                        self.renewing.discard(key)
                    active = False
            except DiscoveryFailure:
                self.children.pop(key).close()
                self.deadlines.pop(key, None)
                self.sources_seen_at.pop(key, None)
                self.renewing.discard(key)
                raise
            if active:
                self.renewing.discard(key)
            confirmed = (active or key in self.renewing) and confirmed
        return confirmed

    def renewals(self, policy: Discovery) -> int:
        """Records of this policy that are between two clients right now."""
        return sum(key.startswith(policy.id + ":") for key in self.renewing)

    def expire(self, now: float) -> None:
        for key, deadline in tuple(self.deadlines.items()):
            if now >= deadline:
                self.children.pop(key).close()
                self.deadlines.pop(key)
                self.sources_seen_at.pop(key, None)
                self.renewing.discard(key)

    def close(self) -> None:
        for child in self.children.values():
            child.close()
        self.children.clear()
        self.deadlines.clear()
        self.sources_seen_at.clear()
        self.renewing.clear()


def _signal_stop(callback: Callable[[], None]) -> None:
    def stop(_number: int, _frame: Any) -> None:
        callback()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)


Proof = tuple[Snapshot, Intent, frozenset[str], dict[str, tuple[int, int]]]


def collect_proof(config: Config, settings: BonjourSettings, now: float) -> Proof:
    if config_digest(load_config(settings.config)) != config_digest(config):
        raise ValueError("installed discovery policy changed")
    snapshot, intent, ready = independent_snapshot(config, settings, now)
    return snapshot, intent, ready, _interfaces(config, settings)


def publisher_tick(
    config: Config,
    settings: BonjourSettings,
    store: Store,
    publisher: Publisher,
    proof: Proof | None,
    proof_age: float,
    now: float,
) -> Snapshot:
    """No subprocess reads run in this watchdog's event loop."""
    profiles: dict[str, Observation] = {}
    try:
        requests = desired_requests(config, settings, store)
        try:
            candidates = store.read("candidates.json")
        except FileNotFoundError:
            candidates = {
                "schema_version": 1,
                "config_digest": config_digest(config),
                "policies": {},
            }
        if (
            not isinstance(candidates, dict)
            or candidates.get("config_digest") != config_digest(config)
            or type(candidates.get("schema_version")) is not int
            or candidates["schema_version"] != 1
            or not isinstance(candidates.get("policies"), dict)
        ):
            raise ValueError("candidate policy changed")
        # Pause is read directly, independently of a potentially blocked probe.
        current_intent = intent_from_dict(private_json(settings.intent))
        for policy in _owned(config, settings):
            request = requests.get(policy.id)
            inactive = request is None or (
                isinstance(request, dict) and request.get("active") is False
            )
            records: tuple[Record, ...] | None = None
            left_out = 0
            maximum = min(
                [
                    policy.max_age_seconds,
                    *(config.profile(item).safety.max_age_seconds for item in policy.dependencies),
                ]
            )
            valid_proof = proof is not None and 0 <= proof_age <= maximum
            if valid_proof and proof is not None:
                if inactive or current_intent.blocked:
                    records = ()
                else:
                    records = lease_records(
                        config,
                        policy,
                        request,
                        candidates["policies"].get(policy.id),
                        proof[0],
                        current_intent,
                        proof[2],
                        now,
                    )
                    if records is not None:
                        # lease_records has accepted this candidate and its count.
                        left_out = candidates["policies"][policy.id].get("skipped", 0)
            if records is None:
                publisher.reconcile(policy, (), 1, now)
                uncertainty = (
                    "local-network-denied"
                    if candidates.get("reason") == "local-network-denied"
                    or (
                        isinstance(candidates["policies"].get(policy.id), dict)
                        and candidates["policies"][policy.id].get("reason")
                        == "local-network-denied"
                    )
                    else "unobserved"
                )
                profiles[policy.id] = _observation(
                    config,
                    policy,
                    "unknown",
                    uncertainty,
                    now,
                    proof[0] if proof else None,
                    interface=valid_proof,
                )
                continue
            assert proof is not None
            index = proof[3][policy.scope][0 if policy.direction == "export" else 1]
            try:
                active = publisher.reconcile(policy, records, index, now)
            except DiscoveryFailure as exc:
                publisher.reconcile(policy, (), 1, now)
                profiles[policy.id] = _observation(
                    config, policy, "unknown", exc.reason, now, proof[0], interface=True
                )
                continue
            if not active:
                profiles[policy.id] = _observation(
                    config, policy, "unknown", "unobserved", now, proof[0], interface=True
                )
            else:
                state = "absent" if inactive or current_intent.blocked else "present"
                profiles[policy.id] = _observation(
                    config,
                    policy,
                    state,
                    "verified" if state == "present" else "confirmed-absent",
                    now,
                    proof[0],
                    skipped=left_out,
                    interface=True,
                    count=len(records) - publisher.renewals(policy),
                )
    except Exception as exc:
        publisher.close()
        reason = exc.reason if isinstance(exc, DiscoveryFailure) else "malformed"
        profiles = {
            policy.id: _observation(config, policy, "unknown", reason, now, None, interface=False)
            for policy in _owned(config, settings)
        }
    result = Snapshot(now, proof[0].network_generation if proof else None, {}, profiles)
    store.write("readback.json", snapshot_to_dict(result))
    store.write(
        "publisher-heartbeat.json", {"schema_version": 1, "observed_at": now, "pid": os.getpid()}
    )
    return result


def publisher_loop(
    config: Config, settings: BonjourSettings, store: Store, parent_pid: int | None = None
) -> None:
    """Independent proof collection never blocks lease expiry and child polling."""
    publisher = Publisher()
    _signal_stop(publisher.close)
    pool = ThreadPoolExecutor(max_workers=1)
    future: Future[Proof] | None = None
    proof: Proof | None = None
    proof_at = 0.0
    last_probe = 0.0
    try:
        while True:
            if parent_pid is not None and os.getppid() != parent_pid:
                return
            now = time.time()
            publisher.expire(time.monotonic())
            if future is None and time.monotonic() - last_probe >= settings.poll_seconds:
                last_probe = time.monotonic()
                future = pool.submit(collect_proof, config, settings, now)
            if future is not None and future.done():
                try:
                    proof = future.result()
                    proof_at = time.monotonic()
                except Exception:
                    proof = None
                future = None
            publisher_tick(
                config, settings, store, publisher, proof, time.monotonic() - proof_at, now
            )
            time.sleep(0.25)
    finally:
        publisher.close()
        pool.shutdown(wait=False, cancel_futures=True)


def serve(config: Config, settings: BonjourSettings, settings_path: Path) -> None:
    store = Store(settings.state_dir)
    # The independently running child owns registrations; SIGKILL of the
    # scanner cannot leave indefinite registrations in mDNSResponder.
    child = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "netorch.bonjour_owner",
            "--settings",
            str(settings_path),
            "publisher",
            "--parent-pid",
            str(os.getpid()),
        ],
        stdin=subprocess.DEVNULL,
    )

    def close() -> None:
        child.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            child.wait(timeout=3)
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)

    _signal_stop(close)
    # Kept in this process only: a scanner restart withdraws on the first miss again.
    memory = MissMemory(settings.miss_tolerance) if settings.miss_tolerance > 1 else None
    try:
        while child.poll() is None:
            try:
                scan_pass(config, settings, store, memory)
                store.write(
                    "scanner-heartbeat.json",
                    {"schema_version": 1, "observed_at": time.time(), "pid": os.getpid()},
                )
            except Exception as exc:
                # Do not refresh a previous lease after a partial/failed pass.
                if memory is not None:
                    memory.listed.clear()
                store.write(
                    "candidates.json",
                    {
                        "schema_version": 1,
                        "config_digest": config_digest(config),
                        "observed_at": time.time(),
                        "policies": {},
                        "reason": (
                            exc.reason if isinstance(exc, DiscoveryFailure) else "malformed"
                        ),
                    },
                )
            time.sleep(settings.pass_interval)
    finally:
        close()


def readback(config: Config, settings: BonjourSettings, store: Store, now: float) -> Snapshot:
    from .state import snapshot_from_dict

    try:
        snapshot = snapshot_from_dict(store.read("readback.json"))
        profiles = {}
        for policy in _owned(config, settings):
            item = snapshot.profiles[policy.id].at(
                now, min(2 * settings.poll_seconds, policy.max_age_seconds)
            )
            if item.data.get("policy_digest") != discovery_digest(config, policy):
                item = Observation("unknown", "identity-mismatch", now, None)
            profiles[policy.id] = item
        return Snapshot(now, snapshot.network_generation, {}, profiles)
    except (OSError, ValueError, KeyError):
        return Snapshot(
            now,
            None,
            {},
            {
                policy.id: Observation("unknown", "unobserved", now, None)
                for policy in _owned(config, settings)
            },
        )


def endpoint(
    config: Config, settings: BonjourSettings, store: Store, request: Any
) -> dict[str, Any]:
    if (
        not isinstance(request, dict)
        or request.get("owner") != settings.owner
        or type(request.get("protocol_version")) is not int
        or request["protocol_version"] != 1
    ):
        raise ValueError("invalid owner request envelope")
    if request.get("operation") == "observe":
        if set(request) != {"protocol_version", "operation", "owner", "config"} or config_digest(
            config
        ) != config_digest(load_config_value(request["config"])):
            raise ValueError("owner policy changed")
        result = snapshot_to_dict(readback(config, settings, store, time.time()))
    elif request.get("operation") == "reconcile-discovery":
        fields = {
            "protocol_version",
            "operation",
            "owner",
            "policy_digest",
            "discovery_digest",
            "discovery",
            "active",
            "config",
            "service_generation",
            "network_generation",
        }
        policy = next(
            (item for item in _owned(config, settings) if item.id == request.get("discovery")), None
        )
        if (
            set(request) != fields
            or policy is None
            or type(request["active"]) is not bool
            or request["policy_digest"] != config_digest(config)
            or request["discovery_digest"] != discovery_digest(config, policy)
            or config_digest(load_config_value(request["config"])) != config_digest(config)
        ):
            raise ValueError("invalid fixed discovery request")
        with store.lock():
            desired = desired_requests(config, settings, store)
            desired[policy.id] = {
                "active": request["active"],
                "policy_digest": request["discovery_digest"],
                "service_generation": request["service_generation"],
                "network_generation": request["network_generation"],
                "requested_at": time.time(),
            }
            store.write("requests.json", {"schema_version": 1, "policies": desired})
        deadline = time.monotonic() + 7
        while True:
            current = readback(config, settings, store, time.time()).profiles[policy.id]
            expected = "present" if request["active"] else "absent"
            if (
                current.state == expected
                and current.data.get("policy_digest") == request["discovery_digest"]
                and (
                    not request["active"]
                    or (
                        current.generation == request["service_generation"]
                        and current.data.get("network_generation") == request["network_generation"]
                    )
                )
            ):
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.1)
        result = observation_to_dict(current)
    else:
        raise ValueError("unsupported owner operation")
    return {"protocol_version": 1, "owner": settings.owner, "result": result}


def load_config_value(value: Any) -> Config:
    from .config import parse_config

    return parse_config(canonical_bytes(value))


def health(settings: BonjourSettings, store: Store) -> bool:
    now = time.time()
    # The scanner writes its heartbeat once per pass, the publisher on every tick.
    for filename, interval in (
        ("scanner-heartbeat.json", settings.pass_interval),
        ("publisher-heartbeat.json", settings.poll_seconds),
    ):
        raw = store.read(filename)
        if (
            not isinstance(raw, dict)
            or set(raw) != {"schema_version", "observed_at", "pid"}
            or type(raw["schema_version"]) is not int
            or raw["schema_version"] != 1
            or type(raw["observed_at"]) not in {float, int}
            or not raw["observed_at"] <= now <= raw["observed_at"] + max(60, interval * 3)
        ):
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", required=True, type=Path)
    parser.add_argument("--parent-pid", type=int)
    parser.add_argument("command", choices=("endpoint", "serve", "publisher", "health"))
    args = parser.parse_args(argv)
    try:
        if args.command in {"serve", "publisher"}:
            require_mutation_qualified("discovery-publication")
        request: Any = None
        if args.command == "endpoint":
            request = strict_loads(sys.stdin.buffer.read(1_048_577))
            require_request_qualified("bonjour", request)
        if os.geteuid() == 0:
            raise ValueError("Bonjour must run as its existing unprivileged user identity")
        settings = load_settings(args.settings)
        config = load_config(settings.config)
        if not settings.state_dir.is_dir():
            raise ValueError("existing discovery state is required")
        store = Store(settings.state_dir)
        if args.command == "endpoint":
            sys.stdout.buffer.write(
                canonical_bytes(endpoint(config, settings, store, request)) + b"\n"
            )
        elif args.command == "serve":
            with Store(settings.state_dir / "scanner").lock():
                serve(config, settings, args.settings)
        elif args.command == "publisher":
            if args.parent_pid is None or args.parent_pid <= 0:
                raise ValueError("publisher needs its actual scanner parent")
            with Store(settings.state_dir / "publisher").lock():
                publisher_loop(config, settings, store, args.parent_pid)
        elif not health(settings, store):
            return 1
        return 0
    except StageNotQualified as exc:
        print(canonical_bytes(exc.to_dict()).decode("utf-8"), file=sys.stderr)
        return NOT_QUALIFIED
    except Exception:
        sys.stderr.write("Bonjour owner could not establish complete scoped evidence.\n")
        return 65


if __name__ == "__main__":
    raise SystemExit(main())

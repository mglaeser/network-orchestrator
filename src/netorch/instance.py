"""Canonical, bounded, data-only instance loading and offline invariants."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import asdict
from datetime import datetime
from functools import lru_cache
from importlib import resources
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path, PurePosixPath
from typing import Any, cast

from jsonschema import Draft202012Validator

from .codec import MAX_JSON_BYTES, canonical_bytes, digest, strict_loads
from .instance_model import (
    LAN,
    Acceptance,
    Account,
    Authoring,
    Baseline,
    BoundedDecision,
    Component,
    ContractRef,
    Decisions,
    Deviation,
    DiscoverySelection,
    FrameworkPin,
    Host,
    Instance,
    LifecycleDecision,
    LifecycleTool,
    NamedPortRange,
    Names,
    Platform,
    Ports,
    RecoveryDecision,
    Runtime,
    Supervision,
    Transport,
    VisibilityDecision,
    Workload,
)
from .profile_library import discovery_profile, strategy
from .requirements import REQUIREMENTS
from .safety_contract import assess_bounded_safety

SECTIONS = (
    "host",
    "names",
    "workloads",
    "port_ranges",
    "transport",
    "discovery",
    "supervision",
    "lifecycle_tools",
    "decisions",
    "acceptance",
    "deviations",
)
_ADDRESS = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?(?![0-9.])")
# C0, DEL and C1 controls plus the Unicode line and paragraph separators.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


class InstanceError(ValueError):
    """Instance syntax or an explicit host-independent invariant failed."""


@lru_cache(maxsize=1)
def instance_validator() -> Draft202012Validator:
    resource = resources.files("netorch").joinpath("instance.schema.json")
    path = Path(__file__).resolve().parents[2] / "schemas/instance.schema.json"
    schema = strict_loads(resource.read_bytes() if resource.is_file() else read_data(path))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def read_data(path: Path) -> bytes:
    """Only bounded local regular data; no state creation, code or owner calls."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise InstanceError("local data must be a single-link regular file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            raise InstanceError("local data exceeds its byte bound")
        after = os.fstat(fd)
        current = path.lstat()
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_flags",
        )
        if any(
            getattr(info, field, 0) != getattr(before, field, 0)
            for info in (after, current)
            for field in fields
        ):
            raise InstanceError("local data changed during capture")
        return raw
    finally:
        os.close(fd)


def _ports(data: dict[str, Any] | None) -> Ports | None:
    return None if data is None else Ports(**data)


def _construct(data: dict[str, Any]) -> Instance:
    host = data["host"]
    baseline = host["baseline"]
    decision = data["decisions"]
    return Instance(
        data["schema_version"],
        data["instance"],
        data["namespace"],
        FrameworkPin(**data["framework"]),
        Host(
            Account(**host["account"]),
            LAN(**host["lan"]),
            Runtime(**host["runtime"]),
            Platform(**host["platform"]),
            Baseline(
                **{
                    **baseline,
                    **{
                        key: tuple(baseline[key])
                        for key in ("network_extensions", "proxies", "vpns")
                    },
                }
            ),
        ),
        Names(**data["names"]),
        tuple(
            Workload(
                item["id"],
                item["name"],
                item["application_profile"],
                ContractRef(**item["contract"]),
                item["automatic_port_range"],
                item["recovery"],
                tuple(Component(**value) for value in item["components"]),
            )
            for item in data["workloads"]
        ),
        tuple(NamedPortRange(**item) for item in data["port_ranges"]),
        tuple(
            Transport(
                item["id"],
                item["service"],
                item["strategy"],
                item["version"],
                item["protocol"],
                _ports(item["ports"]),
                _ports(item["target_ports"]),
                tuple(item["dependencies"]),
                item["fallback_publication"],
            )
            for item in data["transport"]
        ),
        tuple(
            DiscoverySelection(**{**item, "dependencies": tuple(item["dependencies"])})
            for item in data["discovery"]
        ),
        Supervision(**data["supervision"]),
        tuple(LifecycleTool(**item) for item in data["lifecycle_tools"]),
        Decisions(
            tuple(BoundedDecision(**item) for item in decision["bounded"]),
            RecoveryDecision(**decision["unattended_recovery"]),
            VisibilityDecision(**decision["import_visibility"]),
            LifecycleDecision(**decision["lifecycle_control"]),
        ),
        tuple(Acceptance(**item) for item in data["acceptance"]),
        tuple(Deviation(**item) for item in data["deviations"]),
        tuple(
            Authoring(
                **{**item, "sections": tuple(item["sections"]), "subjects": tuple(item["subjects"])}
            )
            for item in data["authoring"]
        ),
    )


def instance_to_dict(instance: Instance) -> dict[str, Any]:
    data = cast(dict[str, Any], strict_loads(canonical_bytes(asdict(instance))))
    for item in data["transport"]:
        for key in ("ports", "target_ports"):
            value = item[key]
            if value is not None:
                item[key] = (
                    {"range": value["range"]}
                    if value["range"] is not None
                    else {"first": value["first"], "last": value["last"]}
                )
    return data


def canonical_instance_bytes(instance: Instance) -> bytes:
    validate_instance(instance)
    return canonical_bytes(instance_to_dict(instance)) + b"\n"


def instance_digest(instance: Instance) -> str:
    return digest({"instance_digest_version": 1, "instance": instance_to_dict(instance)})


def instance_contract_digest(instance: Instance) -> str:
    """Bind desired behavior and its authorship without hashing its own proofs.

    Source hashes and owner flips change the provenance being attested, even
    when rendered behavior stays byte-identical. Historical acceptance must
    therefore be renewed after either changes.
    """
    data = instance_to_dict(instance)
    for key in ("acceptance", "deviations"):
        del data[key]
    return digest({"instance_contract_version": 2, "contract": data})


def resolve_ports(instance: Instance, ports: Ports | None) -> tuple[int, int] | None:
    if ports is None:
        return None
    if ports.range is not None:
        value = instance.port_range(ports.range)
        return value.first, value.last
    if ports.first is None or ports.last is None:
        raise InstanceError("port selector is incomplete")
    return ports.first, ports.last


def resolved_profile(instance: Instance, profile: Transport) -> dict[str, Any]:
    workload = instance.workload(profile.service)
    decision = next(
        (item for item in instance.decisions.bounded if item.profile == profile.id), None
    )
    return {
        "id": profile.id,
        "strategy": profile.strategy,
        "version": profile.version,
        "protocol": profile.protocol,
        "ports": resolve_ports(instance, profile.ports),
        "target_ports": resolve_ports(instance, profile.target_ports),
        "dependencies": list(profile.dependencies),
        "fallback_publication": profile.fallback_publication,
        "lan": asdict(instance.host.lan),
        "workload": {
            "id": workload.id,
            "name": workload.name,
            "contract_sha256": workload.contract.sha256,
        },
        "bounded_policy": None
        if decision is None
        else {
            "max_age_seconds": decision.max_age_seconds,
            "unknown_limit": decision.unknown_limit,
            "residual": decision.residual,
        },
    }


def resolved_profile_digest(instance: Instance, profile: Transport) -> str:
    references: dict[str, Any] = {}
    pending = [profile.id]
    while pending:
        identifier = pending.pop()
        if identifier in references:
            continue
        value = instance.transport_profile(identifier)
        references[identifier] = resolved_profile(instance, value)
        pending.extend(value.dependencies)
        if value.fallback_publication is not None:
            pending.append(value.fallback_publication)
    return digest(
        {
            "resolved_profile_version": 2,
            "profile": profile.id,
            "references": references,
            "names": resolved_names(instance),
            "framework": asdict(instance.framework),
            "supervision": asdict(instance.supervision),
            "account": asdict(instance.host.account),
            "runtime": asdict(instance.host.runtime),
            "platform": asdict(instance.host.platform),
        }
    )


def resolved_discovery_digest(instance: Instance, selection: DiscoverySelection) -> str:
    return digest(
        {
            "resolved_discovery_version": 2,
            "selection": asdict(selection),
            "lan": asdict(instance.host.lan),
            "names": resolved_names(instance),
            "workload_contract": instance.workload(selection.service).contract.sha256,
            "dependencies": {
                identifier: resolved_profile_digest(
                    instance, instance.transport_profile(identifier)
                )
                for identifier in selection.dependencies
            },
        }
    )


def resolved_names(instance: Instance) -> dict[str, str]:
    namespace = instance.namespace
    slug = namespace.replace(".", "-")
    defaults = {
        "coordinator_label": namespace + ".coordinator",
        "bonjour_label": namespace + ".discovery",
        "supervisor_label": namespace + ".supervisor",
        "pf_label": namespace + ".forwarding",
        "pf_anchor": "com.apple/" + namespace + ".forwarding",
        "helper_label": namespace + ".endpoint",
        "state_directory": instance.host.account.home + "/Library/Application Support/" + namespace,
        "root_state_directory": "/Library/Application Support/" + namespace + "/root",
        "bonjour_prefix": slug + "-container-",
        "import_prefix": slug + "-lan-",
    }
    return {key: value or defaults[key] for key, value in asdict(instance.names).items()}


def check_plain_data(data: Any, float_keys: frozenset[str] = frozenset()) -> None:
    """Closed documents hold JSON integers and single-line text only.

    The schema library accepts ``1.0`` wherever an integer is required, and a
    pattern ending in ``$`` accepts one trailing newline; both are refused here.
    ``float_keys`` names the only members that may be fractional.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            check_plain_data(key)
            if not (isinstance(value, float) and key in float_keys):
                check_plain_data(value, float_keys)
    elif isinstance(data, list):
        for value in data:
            check_plain_data(value, float_keys)
    elif isinstance(data, float):
        raise InstanceError("closed data requires JSON integers, not fractional numbers")
    elif isinstance(data, str) and _CONTROL.search(data):
        raise InstanceError("closed data strings cannot contain control characters")


def _check_data_strings(data: Any, allowed_addresses: set[str]) -> None:
    if isinstance(data, dict):
        for value in data.values():
            _check_data_strings(value, allowed_addresses)
    elif isinstance(data, list):
        for value in data:
            _check_data_strings(value, allowed_addresses)
    elif isinstance(data, str):
        if any(marker in data for marker in ("$(`", "$(", "${", "`", "{{", "}}", "\x00")):
            raise InstanceError("instance data cannot contain expressions or shell expansion")
        if data.startswith("/") and (
            "/bin/" in data
            or "/sbin/" in data
            or data.endswith((".sh", ".py", ".rb", ".pl", ".command"))
        ):
            raise InstanceError("instance data cannot select an executable path")
        if re.match(
            r"\s*(?:nat on|rdr on|pass in|pass out|block in|block out|load anchor)\b", data
        ):
            raise InstanceError("instance data cannot contain packet-filter text")
        for address in _ADDRESS.findall(data):
            if address not in allowed_addresses:
                raise InstanceError("instance cannot contain live guest or receiver addresses")


def _timestamp(value: str | None) -> None:
    if value is not None:
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise InstanceError("invalid UTC record timestamp") from exc


def validate_instance(instance: Instance) -> None:
    data = instance_to_dict(instance)
    errors = list(instance_validator().iter_errors(data))
    if errors:
        raise InstanceError("instance violates its closed versioned schema")
    check_plain_data(data)
    try:
        lan = IPv4Network(instance.host.lan.cidr, strict=True)
        address = IPv4Address(instance.host.lan.ipv4)
    except ValueError as exc:
        raise InstanceError("instance LAN must use canonical IPv4") from exc
    if (
        lan.prefixlen < 1
        or address not in lan
        or address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or (lan.prefixlen < 31 and address in (lan.network_address, lan.broadcast_address))
    ):
        raise InstanceError("instance LAN address must be usable in its declared prefix")
    _check_data_strings(data, {instance.host.lan.ipv4, instance.host.lan.cidr})
    resolved = resolved_names(instance)
    if any(len(value) > 128 for key, value in resolved.items() if key.endswith("label")) or any(
        len(resolved[key]) > 63 for key in ("bonjour_prefix", "import_prefix")
    ):
        raise InstanceError("namespace-derived names exceed native name bounds; pin explicit names")
    labels = [value for key, value in resolved.items() if key.endswith("label")]
    if (
        len(set(labels)) != len(labels)
        or resolved["bonjour_prefix"] == resolved["import_prefix"]
        or resolved["state_directory"] == resolved["root_state_directory"]
    ):
        raise InstanceError(
            "launchd labels, discovery prefixes and state directories must each be distinct"
        )
    for path in (
        instance.host.account.home,
        instance.names.state_directory,
        instance.names.root_state_directory,
    ):
        if path is not None and (
            ".." in PurePosixPath(path).parts or str(PurePosixPath(path)) != path
        ):
            raise InstanceError("data paths must be canonical without traversal")
    groups = (
        instance.workloads,
        instance.port_ranges,
        instance.transport,
        instance.discovery,
        instance.lifecycle_tools,
        instance.deviations,
    )
    for items in groups:
        identifiers = [item.id for item in items]
        if len(set(identifiers)) != len(identifiers):
            raise InstanceError("duplicate instance identifier")
    container_names = [item.name for item in instance.workloads]
    if len(set(container_names)) != len(container_names):
        raise InstanceError("duplicate workload container name")
    # The alias carries no parameter: it is the one LAN address inside one workload.
    aliased = [item.service for item in instance.transport if item.strategy == "guest-lan-alias"]
    if len(set(aliased)) != len(aliased):
        raise InstanceError("a workload declares its LAN alias at most once")
    if {item.id for item in instance.transport}.intersection(
        item.id for item in instance.discovery
    ):
        raise InstanceError("transport and discovery identifiers must be disjoint")
    for named_ports in instance.port_ranges:
        if named_ports.first > named_ports.last:
            raise InstanceError("named port range is reversed")
    try:
        for workload in instance.workloads:
            contract_path = PurePosixPath(workload.contract.data_path)
            if (
                contract_path.is_absolute()
                or ".." in contract_path.parts
                or str(contract_path) != workload.contract.data_path
            ):
                raise InstanceError("contract reference escapes its data directory")
            if workload.automatic_port_range is not None:
                instance.port_range(workload.automatic_port_range)
            ids = [item.id for item in workload.components]
            if len(ids) != len(set(ids)):
                raise InstanceError("duplicate component identity")
        for profile in instance.transport:
            workload = instance.workload(profile.service)
            capability = strategy(profile.strategy, profile.version)
            ports = resolve_ports(instance, profile.ports)
            targets = resolve_ports(instance, profile.target_ports)
            if profile.strategy == "guest-lan-alias":
                if profile.protocol != "ipv4" or ports is not None or targets is not None:
                    raise InstanceError("LAN alias declares an address capability, not port rules")
            elif profile.protocol not in {"tcp", "udp"} or ports is None:
                raise InstanceError("port strategy requires a TCP/UDP range")
            if any(value is not None and value[0] > value[1] for value in (ports, targets)):
                raise InstanceError("transport range is reversed")
            if (
                ports is not None
                and targets is not None
                and ports[1] - ports[0] != targets[1] - targets[0]
            ):
                raise InstanceError("transport target range width differs")
            for dependency in profile.dependencies:
                if dependency == profile.id:
                    raise InstanceError("profile cannot depend on itself")
                instance.transport_profile(dependency)
            if profile.strategy == "guest-udp-range-forward" and (
                profile.protocol != "udp"
                or targets is not None
                or workload.automatic_port_range is None
                or profile.ports is None
                or profile.ports.range != workload.automatic_port_range
            ):
                raise InstanceError("UDP return must reference the one workload automatic range")
            if profile.strategy == "host-port-redirect":
                publications = [
                    item
                    for item in instance.transport
                    if item.strategy == "published-port"
                    and item.service == profile.service
                    and item.protocol == profile.protocol
                    and resolve_ports(instance, item.ports) == targets
                ]
                if len(publications) != 1 or publications[0].id not in profile.dependencies:
                    raise InstanceError(
                        "host redirect requires its own exact publication dependency"
                    )
            if profile.fallback_publication is not None:
                fallback = instance.transport_profile(profile.fallback_publication)
                if (
                    profile.strategy != "guest-direct-redirect"
                    or fallback.strategy != "published-port"
                    or fallback.service != profile.service
                    or fallback.protocol != profile.protocol
                    or resolve_ports(instance, fallback.target_ports or fallback.ports)
                    != (targets or ports)
                ):
                    raise InstanceError(
                        "fallback must be the same service's exact native publication"
                    )
            if capability.gate == "structural" and profile.id in {
                value.profile for value in instance.decisions.bounded
            }:
                raise InstanceError("bounded decisions cannot change structural strategy semantics")
        for selection in instance.discovery:
            instance.workload(selection.service)
            selected = discovery_profile(selection.profile, selection.version)
            if selected.direction != selection.direction:
                raise InstanceError("discovery profile direction mismatch")
            dependencies = [instance.transport_profile(value) for value in selection.dependencies]
            matching = [value for value in dependencies if value.service == selection.service]
            required = (
                "published-port" if selection.direction == "export" else "guest-udp-range-forward"
            )
            if not any(value.strategy == required for value in matching):
                raise InstanceError("discovery requires its own service's transport dependency")
            if selection.direction == "export" and not any(
                value.strategy == "published-port" and value.protocol == "tcp" for value in matching
            ):
                # Every supported export profile emits TCP DNS-SD services.
                # A UDP socket on the same numeric port is a different endpoint.
                raise InstanceError("discovery export requires its own TCP publication")
        decision_ids = [item.profile for item in instance.decisions.bounded]
        if len(set(decision_ids)) != len(decision_ids):
            raise InstanceError("duplicate bounded decision")
        for decision in instance.decisions.bounded:
            value = instance.transport_profile(decision.profile)
            if strategy(value.strategy, value.version).gate != "bounded":
                raise InstanceError("bounded decision names a structural strategy")
            _timestamp(decision.signed_at)
            if (decision.signed_by is None) != (decision.signed_at is None):
                raise InstanceError("owner signature and timestamp must occur together")
            try:
                # The report assesses every decision; refuse here what it would refuse.
                assess_bounded_safety(
                    decision.max_age_seconds,
                    decision.unknown_limit,
                    decision.residual,
                    decision.signed_by,
                    decision.signed_at,
                    interval_seconds=instance.supervision.reconcile_seconds,
                )
            except ValueError as exc:
                raise InstanceError("bounded decision cannot be assessed") from exc
    except (StopIteration, KeyError) as exc:
        raise InstanceError("instance reference does not identify declared data") from exc
    for index, item in enumerate(instance.transport):
        ports = resolve_ports(instance, item.ports)
        for other in instance.transport[index + 1 :]:
            other_ports = resolve_ports(instance, other.ports)
            if (
                ports is not None
                and other_ports is not None
                and item.protocol == other.protocol
                and ports[0] <= other_ports[1]
                and other_ports[0] <= ports[1]
            ):
                raise InstanceError("overlapping host port claims")

    visited: set[str] = set()

    def visit(identifier: str, stack: frozenset[str]) -> None:
        if identifier in visited:
            return
        if identifier in stack:
            raise InstanceError("profile dependency cycle")
        value = instance.transport_profile(identifier)
        for dependency in value.dependencies + (
            () if value.fallback_publication is None else (value.fallback_publication,)
        ):
            visit(dependency, stack | {identifier})
        visited.add(identifier)

    for profile in instance.transport:
        visit(profile.id, frozenset())
    claimed: set[tuple[str, str]] = set()
    section_subjects = {
        "workloads": {item.id for item in instance.workloads},
        "port_ranges": {item.id for item in instance.port_ranges},
        "transport": {item.id for item in instance.transport},
        "discovery": {item.id for item in instance.discovery},
        "lifecycle_tools": {item.id for item in instance.lifecycle_tools},
        "deviations": {item.id for item in instance.deviations},
    }
    for row in instance.authoring:
        if (row.mode == "generated") != (row.source_sha256 is not None):
            raise InstanceError(
                "generated sections require their source digest; authored sections do not"
            )
        for section in row.sections:
            if row.subjects and (
                section not in section_subjects
                or not set(row.subjects).issubset(section_subjects[section])
            ):
                raise InstanceError(
                    "authoring subjects must identify data in their selected section"
                )
            subjects = row.subjects or ("*",)
            for subject in subjects:
                key = section, subject
                if (
                    key in claimed
                    or (section, "*") in claimed
                    or (subject == "*" and any(value[0] == section for value in claimed))
                ):
                    raise InstanceError("instance setting has more than one author")
                claimed.add(key)
    known_profiles = {item.id for item in instance.transport} | {
        item.id for item in instance.discovery
    }
    registered = {item.id for item in REQUIREMENTS}
    for acceptance_entry in instance.acceptance:
        _timestamp(acceptance_entry.observed_at)
        if acceptance_entry.requirement not in registered:
            raise InstanceError("acceptance names an unregistered requirement")
        if acceptance_entry.profile is not None and acceptance_entry.profile not in known_profiles:
            raise InstanceError("acceptance names an undeclared profile")
    for deviation_entry in instance.deviations:
        _timestamp(deviation_entry.accepted_at)
        if deviation_entry.requirement not in registered:
            raise InstanceError("deviation names an unregistered requirement")
        if (deviation_entry.accepted_by is None) != (deviation_entry.accepted_at is None):
            raise InstanceError("deviation signature and timestamp must occur together")
    for owner_decision in (
        instance.decisions.import_visibility,
        instance.decisions.lifecycle_control,
    ):
        _timestamp(owner_decision.signed_at)
        if (owner_decision.signed_by is None) != (owner_decision.signed_at is None):
            raise InstanceError("decision signature and timestamp must occur together")


def parse_instance(raw: bytes | str, *, require_canonical: bool = True) -> Instance:
    try:
        data = strict_loads(raw)
        if list(instance_validator().iter_errors(data)):
            raise InstanceError("instance violates its closed versioned schema")
        expected = canonical_bytes(data) + b"\n"
        given = raw.encode("utf-8") if isinstance(raw, str) else raw
        if require_canonical and given != expected:
            raise InstanceError("committed instance must equal canonical JSON plus one newline")
        result = _construct(data)
        validate_instance(result)
        return result
    except (TypeError, KeyError, ValueError) as exc:
        if isinstance(exc, InstanceError):
            raise
        raise InstanceError("instance data cannot be decoded safely") from exc


def load_instance(path: Path) -> Instance:
    return parse_instance(read_data(path))


def verify_release(instance: Instance, artifact: Path) -> bool:
    return hashlib.sha256(read_data(artifact)).hexdigest() == instance.framework.artifact_sha256

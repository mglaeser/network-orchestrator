"""Canonical, bounded, data-only instance loading and offline invariants."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import MISSING, asdict, fields
from datetime import datetime
from functools import lru_cache
from importlib import resources
from ipaddress import IPv4Address, IPv4Network, IPv6Address
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
    Deadlines,
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
    RestartBudget,
    Runtime,
    Supervision,
    Transport,
    VisibilityDecision,
    Workload,
)
from .profile_library import AUTOMATIC_TYPES, discovery_profile, strategy
from .requirements import REQUIREMENTS
from .safety_contract import RECOVERY_FAILURE_EXIT_CODE, assess_bounded_safety

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
# An address may end a sentence. Only a dot that continues into another component
# makes it part of a longer token.
_ADDRESS = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?(?![0-9])(?!\.\w)")
# Hexadecimal groups joined by at least two colons, optionally ending in a dotted
# quad. This only finds candidates; ``ipaddress`` decides what is an address.
_ADDRESS6 = re.compile(
    r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{1,4}(?=:)|(?=::))(?::[0-9A-Fa-f]{0,4}){2,}"
    r"(?:\.[0-9]{1,3}){0,3}(?![0-9A-Za-z])"
)
# C0, DEL and C1 controls plus the Unicode line and paragraph separators.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
# Optional supervision vocabulary has one spelling for "not stated": absent. Leaving
# these members out keeps the bytes and every digest of a document that states none.
_OPTIONAL_SUPERVISION = ("component_exit_code", "restart_budget", "action_timeout_seconds")
_DEADLINES = ("probe_seconds", "action_seconds")
# What the retained supervisor can be told. Its Monit rule matches the reserved start
# status only, a monitor's check timeout is at most 120 seconds, and no setting bounds
# a start action: the vendor start call is cut off after a fixed four seconds.
RETAINED_PROBE_DEADLINE_MAXIMUM = 120
RETAINED_ACTION_DEADLINE_MAXIMUM: int | None = None


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


def _supervision(data: dict[str, Any]) -> Supervision:
    budget = data.get("restart_budget")
    return Supervision(
        **{**data, "restart_budget": None if budget is None else RestartBudget(**budget)}
    )


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
                Deadlines(**item["deadlines"]) if "deadlines" in item else None,
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
                item.get("source_scope", "lan"),
            )
            for item in data["transport"]
        ),
        tuple(
            DiscoverySelection(
                **{
                    **item,
                    **{
                        key: tuple(item[key])
                        for key in ("dependencies", "service_types")
                        if key in item
                    },
                }
            )
            for item in data["discovery"]
        ),
        _supervision(data["supervision"]),
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


def _stated(data: dict[str, Any], optional: tuple[str, ...]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value is not None or key not in optional}


def instance_to_dict(instance: Instance) -> dict[str, Any]:
    data = cast(dict[str, Any], strict_loads(canonical_bytes(asdict(instance))))
    data["supervision"] = _stated(data["supervision"], _OPTIONAL_SUPERVISION)
    for item in data["workloads"]:
        if item["deadlines"] is None:
            del item["deadlines"]
        else:
            item["deadlines"] = _stated(item["deadlines"], _DEADLINES)
    for item in data["transport"]:
        if item["source_scope"] == "lan":
            # The default has no spelling: one byte form per row, earlier digests unchanged.
            del item["source_scope"]
        for key in ("ports", "target_ports"):
            value = item[key]
            if value is not None:
                item[key] = (
                    {"range": value["range"]}
                    if value["range"] is not None
                    else {"first": value["first"], "last": value["last"]}
                )
    for item in data["discovery"]:
        _selection_data(item)
    for item in data["lifecycle_tools"]:
        # An absent member is left out: earlier documents keep their bytes and digests.
        if not item["starts_fleet"]:
            del item["starts_fleet"]
    return data


_SELECTION_DEFAULTS = {
    item.name: item.default for item in fields(DiscoverySelection) if item.default is not MISSING
}


def _selection_data(selection: dict[str, Any]) -> dict[str, Any]:
    """Leave out each optional member of a discovery selection that has its default.

    A default has no spelling. A selection written before a member existed
    therefore keeps its canonical bytes and its resolved digest.
    """
    for key, default in _SELECTION_DEFAULTS.items():
        if selection[key] == default:
            del selection[key]
    return selection


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


def selection_types(selection: DiscoverySelection) -> tuple[str, ...] | None:
    """The DNS-SD service types a selection names, or ``None`` for the automatic form.

    The generic export names none unless the selection lists them. Its automatic
    form, whatever TCP services the workload announces, is implemented by no
    retained owner. Whatever turns an instance into retained discovery policy
    refuses ``None``; it never guesses a list.
    """
    if selection.service_types is not None:
        return selection.service_types
    library = discovery_profile(selection.profile, selection.version).service_types
    return None if library == AUTOMATIC_TYPES else library


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
        # Bound only where declared, so every resolved digest without it is unchanged.
        **({} if profile.source_scope == "lan" else {"source_scope": profile.source_scope}),
        "lan": asdict(instance.host.lan),
        "workload": {
            "id": workload.id,
            "name": workload.name,
            "contract_sha256": workload.contract.sha256,
            # Its own deadlines replace site defaults the envelope binds as ``supervision``.
            **(
                {}
                if workload.deadlines is None
                else {"deadlines": _stated(asdict(workload.deadlines), _DEADLINES)}
            ),
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
            "supervision": _stated(asdict(instance.supervision), _OPTIONAL_SUPERVISION),
            "account": asdict(instance.host.account),
            "runtime": asdict(instance.host.runtime),
            "platform": asdict(instance.host.platform),
        }
    )


def resolved_discovery_digest(instance: Instance, selection: DiscoverySelection) -> str:
    return digest(
        {
            "resolved_discovery_version": 2,
            "selection": _selection_data(asdict(selection)),
            "lan": asdict(instance.host.lan),
            "names": resolved_names(instance),
            "workload_contract": instance.workload(selection.service).contract.sha256,
            "dependencies": {
                identifier: resolved_profile_digest(
                    instance, instance.transport_profile(identifier)
                )
                for identifier in selection.dependencies
            },
            **_independent_context(instance, selection),
        }
    )


def _independent_context(instance: Instance, selection: DiscoverySelection) -> dict[str, Any]:
    """What a selection otherwise binds through its required transport dependency.

    The resolved digest of that dependency carries the target workload's
    container name, the release pin, the supervision settings and the account,
    runtime and platform context. An independent import may list no dependency
    at all, so its envelope carries the same members itself. A selection without
    the setting gets nothing here and keeps its digest.
    """
    if selection.return_path == "required":
        return {}
    return {
        "context": {
            "workload_name": instance.workload(selection.service).name,
            "framework": asdict(instance.framework),
            "supervision": asdict(instance.supervision),
            "account": asdict(instance.host.account),
            "runtime": asdict(instance.host.runtime),
            "platform": asdict(instance.host.platform),
        }
    }


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


def _routed_ipv6(text: str) -> bool:
    """Whether a candidate is an address a guest or receiver could be reached at."""
    if text.endswith(":") and not text.endswith("::"):
        text = text[:-1]  # a colon that ends a clause, not the address
    try:
        value = int(IPv6Address(text))
    except ValueError:
        return False  # a clock time or a hardware address has colons too
    unique_local = value >> 121 == 0b1111110  # RFC 4193
    global_unicast = value >> 125 == 0b001  # RFC 4291
    documentation = value >> 96 == 0x20010DB8  # RFC 3849, 2001:db8::/32
    return (unique_local or global_unicast) and not documentation


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
        if any(_routed_ipv6(candidate) for candidate in _ADDRESS6.findall(data)):
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
    if sum(item.kind == "supervisor" for item in instance.lifecycle_tools) > 1:
        raise InstanceError("an instance declares at most one supervisor tool")
    if any(
        item.starts_fleet and (item.kind != "supervisor" or not item.container_api_access)
        for item in instance.lifecycle_tools
    ):
        raise InstanceError("only a supervisor tool with container API access starts the fleet")
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
            if profile.source_scope != "lan" and profile.strategy != "host-port-redirect":
                raise InstanceError(
                    "an unrestricted source is declared only for a host-port redirect"
                )
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
            chosen = selection.service_types
            if chosen is not None:
                listed = selected.service_types
                if listed == AUTOMATIC_TYPES:
                    # The generic export has no list of its own: one order, one spelling.
                    # DNS compares a service type without regard to ASCII case.
                    if list(chosen) != sorted(chosen) or len(
                        {kind.lower() for kind in chosen}
                    ) != len(chosen):
                        raise InstanceError(
                            "explicit export service types are distinct and in ascending order"
                        )
                elif (
                    # The whole list is said by leaving the member out.
                    chosen != tuple(kind for kind in listed if kind in chosen)
                    or len(chosen) == len(listed)
                    or (
                        selected.eligibility_type is not None
                        and selected.eligibility_type not in chosen
                    )
                ):
                    raise InstanceError(
                        "service types are a proper subset of the profile's, in its order, "
                        "and keep the type eligibility is decided from"
                    )
            dependencies = [instance.transport_profile(value) for value in selection.dependencies]
            matching = [value for value in dependencies if value.service == selection.service]
            required = (
                "published-port" if selection.direction == "export" else "guest-udp-range-forward"
            )
            if selection.return_path != "required":
                # The setting lifts the requirement below and nothing else. A selection
                # that lists a return path depends on it and cannot say otherwise.
                if selection.direction != "import":
                    raise InstanceError("only an import can be independent of the return path")
                if any(value.strategy == "guest-udp-range-forward" for value in dependencies):
                    raise InstanceError("an independent import lists no return-path dependency")
            elif not any(value.strategy == required for value in matching):
                raise InstanceError("discovery requires its own service's transport dependency")
            if selection.direction == "export" and not any(
                value.strategy == "published-port" and value.protocol == "tcp" for value in matching
            ):
                # Every supported export profile emits TCP DNS-SD services.
                # A UDP socket on the same numeric port is a different endpoint.
                raise InstanceError("discovery export requires its own TCP publication")
            if selection.misses == instance.supervision.discovery_misses:
                # The instance-wide tolerance is said by leaving the member out.
                raise InstanceError(
                    "a selection's own miss tolerance differs from the instance-wide one"
                )
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
    supervision = instance.supervision
    ensured = any(
        component.recovery == "supervisor-ensure"
        for item in instance.workloads
        for component in item.components
    )
    if ensured != (supervision.component_exit_code is not None):
        raise InstanceError(
            "a supervisor-ensure component and the component exit code require each other"
        )
    if supervision.component_exit_code == supervision.failure_exit_code:
        raise InstanceError("the component exit code must differ from the failure exit code")


def _beyond(value: int | None, maximum: int | None) -> bool:
    """Whether a stated deadline is more than the retained supervisor can be given."""
    return value is not None and (maximum is None or value > maximum)


def retained_supervision_gaps(instance: Instance) -> tuple[str, ...]:
    """Name each stated member that the retained supervisor cannot honour.

    An instance describes the supervisor of its site. The retained supervisor
    implements part of that vocabulary: the reserved start status, no second
    status, no in-guest ensure, no restart budget, a probe deadline up to its
    monitor timeout, and no deadline for a start action. Each result is a JSON
    pointer into the canonical instance, in document order. A renderer for the
    retained supervisor must refuse an instance for which the result is not
    empty. Nothing is read, rendered or run here.
    """
    supervision = instance.supervision
    gaps: list[str] = []
    if _beyond(supervision.action_timeout_seconds, RETAINED_ACTION_DEADLINE_MAXIMUM):
        gaps.append("/supervision/action_timeout_seconds")
    if supervision.component_exit_code is not None:
        gaps.append("/supervision/component_exit_code")
    if supervision.failure_exit_code != RECOVERY_FAILURE_EXIT_CODE:
        gaps.append("/supervision/failure_exit_code")
    if supervision.restart_budget is not None:
        gaps.append("/supervision/restart_budget")
    for index, workload in enumerate(instance.workloads):
        gaps.extend(
            f"/workloads/{index}/components/{position}/recovery"
            for position, component in enumerate(workload.components)
            if component.recovery == "supervisor-ensure"
        )
        deadlines = workload.deadlines
        if deadlines is not None:
            if _beyond(deadlines.action_seconds, RETAINED_ACTION_DEADLINE_MAXIMUM):
                gaps.append(f"/workloads/{index}/deadlines/action_seconds")
            if _beyond(deadlines.probe_seconds, RETAINED_PROBE_DEADLINE_MAXIMUM):
                gaps.append(f"/workloads/{index}/deadlines/probe_seconds")
    return tuple(gaps)


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

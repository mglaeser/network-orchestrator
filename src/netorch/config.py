"""Closed, offline policy validation and content-bound admission digests."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from functools import lru_cache
from importlib import resources
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker

from .codec import CodecError, digest, read_bounded_file, strict_load, strict_loads
from .model import (
    Config,
    Discovery,
    DiscoveryNames,
    Owner,
    PortRange,
    Profile,
    Safety,
    Scope,
    Service,
)


class ConfigError(ValueError):
    """Schema or cross-owner invariants are not satisfied."""


# The independent root owner's installation record holds its own identifier, and
# its protected admission and rule records are keyed by the identifiers of its
# profiles. Those stores accept one character fewer than the schema's 64. (The
# anchor named after the owner ends earlier: that record bounds the whole path
# of an anchor, and an owner with a longer identifier pins another name.)
ROOT_IDENTIFIER_LENGTH = 63


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema_file = resources.files("netorch").joinpath("network.schema.json")
    if schema_file.is_file():
        schema = strict_loads(schema_file.read_bytes())
    else:
        # Source checkout only; built wheels bundle the same single schema file.
        schema = strict_load(Path(__file__).resolve().parents[2] / "schemas/network.schema.json")
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _ports(value: dict[str, int] | None) -> PortRange | None:
    return None if value is None else PortRange(first=value["first"], last=value["last"])


def _required_ports(value: dict[str, int]) -> PortRange:
    return PortRange(first=value["first"], last=value["last"])


def _construct(data: dict[str, Any]) -> Config:
    return Config(
        schema_version=data["schema_version"],
        site=data["site"],
        scopes=tuple(Scope(**item) for item in data["scopes"]),
        owners=tuple(
            Owner(item["id"], item["privilege"], tuple(item["capabilities"]))
            for item in data["owners"]
        ),
        services=tuple(
            Service(
                item["id"],
                item["owner"],
                item["contract_sha256"],
                _ports(item.get("automatic_ports")),
            )
            for item in data["services"]
        ),
        profiles=tuple(
            Profile(
                item["id"],
                item["service"],
                item["scope"],
                item["kind"],
                item["protocol"],
                _required_ports(item["ports"]),
                _ports(item.get("target_ports")),
                Safety(
                    item["safety"]["kind"],
                    item["safety"]["max_age_seconds"],
                    item["safety"]["unknown_limit"],
                    item["safety"].get("statement"),
                ),
                item.get("owner"),
                item.get("fallback_publication"),
                item.get("source_scope", "lan"),
            )
            for item in data["profiles"]
        ),
        discovery=tuple(
            Discovery(
                item["id"],
                item["owner"],
                item["service"],
                item["scope"],
                item["direction"],
                tuple(item["types"]),
                tuple(item["dependencies"]),
                item["max_age_seconds"],
                item["max_records"],
                item.get("return_path", "required"),
                item.get("misses"),
            )
            for item in data["discovery"]
        ),
        discovery_names=(
            DiscoveryNames(**data["discovery_names"])
            if "discovery_names" in data
            else DiscoveryNames()
        ),
    )


def backing_publication(config: Config, profile: Profile) -> Profile:
    """The one native publication of the same service that a host redirect exposes."""
    matching = [
        publication
        for publication in config.profiles
        if publication.kind == "publication"
        and publication.service == profile.service
        and publication.scope == profile.scope
        and publication.protocol == profile.protocol
        and profile.target_ports is not None
        and publication.ports.contains(profile.target_ports)
    ]
    if profile.kind != "host-redirect" or len(matching) != 1:
        raise ConfigError(
            f"Profile {profile.id}: host redirect requires its own publication target"
        )
    return matching[0]


def _check_range(ports: PortRange | None, label: str) -> None:
    if ports is not None and (type(ports.first) is not int or type(ports.last) is not int):
        raise ConfigError(f"{label}: port bounds must be integers")
    if ports is not None and ports.first > ports.last:
        raise ConfigError(f"{label}: port range is reversed")


def _check_references(config: Config) -> None:
    # JSON Schema accepts an integral float as an integer. The native command
    # and digest contracts use actual integer values, without coercion.
    if type(config.schema_version) is not int:
        raise ConfigError("Schema version must be an integer")
    if re.fullmatch(r"[a-z][a-z0-9-]*", config.site) is None:
        raise ConfigError("Invalid site identifier")
    for kind, items in (
        ("scope", config.scopes),
        ("owner", config.owners),
        ("service", config.services),
        ("profile", config.profiles),
        ("discovery", config.discovery),
    ):
        identifiers = [item.id for item in items]
        if any(re.fullmatch(r"[a-z][a-z0-9-]*", identifier) is None for identifier in identifiers):
            raise ConfigError(f"Invalid {kind} identifier")
        if len(identifiers) != len(set(identifiers)):
            raise ConfigError(f"Duplicate {kind} identifier")
    if {profile.id for profile in config.profiles}.intersection(
        item.id for item in config.discovery
    ):
        raise ConfigError("Transport and discovery identifiers must be disjoint")
    try:
        for service in config.services:
            config.owner(service.owner)
        for profile in config.profiles:
            config.service(profile.service)
            config.scope(profile.scope)
            config.profile_owner(profile)
            if profile.fallback_publication is not None:
                config.profile(profile.fallback_publication)
        for item in config.discovery:
            config.service(item.service)
            config.scope(item.scope)
            config.owner(item.owner)
            for dependency in item.dependencies:
                config.profile(dependency)
    except KeyError as exc:
        raise ConfigError(str(exc)) from exc
    # Refuse here what a root owner could install and admit once but never read
    # back: nothing is stored for a policy that does not pass this validation.
    for owner in config.owners:
        if owner.privilege == "external-root" and len(owner.id) > ROOT_IDENTIFIER_LENGTH:
            raise ConfigError(
                f"Owner {owner.id}: an external-root owner's identifier is limited to "
                f"{ROOT_IDENTIFIER_LENGTH} characters"
            )
    for profile in config.profiles:
        if (
            config.profile_owner(profile).privilege == "external-root"
            and len(profile.id) > ROOT_IDENTIFIER_LENGTH
        ):
            raise ConfigError(
                f"Profile {profile.id}: an external-root owner's profile identifier is limited "
                f"to {ROOT_IDENTIFIER_LENGTH} characters"
            )


def _check_scopes(config: Config) -> None:
    for scope in config.scopes:
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", scope.interface) is None:
            raise ConfigError(f"Scope {scope.id}: invalid interface identity")
        try:
            host = IPv4Address(scope.host_ipv4)
            lan = IPv4Network(scope.lan_cidr, strict=True)
            guest = IPv4Network(scope.guest_cidr, strict=True)
        except ValueError as exc:
            raise ConfigError(
                f"Scope {scope.id}: requires canonical IPv4 address and CIDRs"
            ) from exc
        if host not in lan or (
            lan.prefixlen < 31 and host in (lan.network_address, lan.broadcast_address)
        ):
            raise ConfigError(f"Scope {scope.id}: host address must be usable within its LAN")
        if host.is_multicast or host.is_unspecified or host.is_loopback:
            raise ConfigError(f"Scope {scope.id}: host address must identify a LAN interface")
        if lan.overlaps(guest):
            raise ConfigError(f"Scope {scope.id}: LAN and guest networks overlap")
        if lan.prefixlen == 0 or guest.prefixlen == 0:
            raise ConfigError(f"Scope {scope.id}: unrestricted IPv4 scope is forbidden")


def _check_profiles(config: Config) -> None:
    for service in config.services:
        if re.fullmatch(r"[0-9a-f]{64}", service.contract_sha256) is None:
            raise ConfigError(f"Service {service.id}: invalid contract digest")
        _check_range(service.automatic_ports, service.id)
    for profile in config.profiles:
        _check_range(profile.ports, profile.id)
        _check_range(profile.target_ports, profile.id)
        if (
            type(profile.safety.max_age_seconds) is not int
            or type(profile.safety.unknown_limit) is not int
        ):
            raise ConfigError(f"Profile {profile.id}: safety bounds must be integers")
        service = config.service(profile.service)
        owner = config.profile_owner(profile)
        if profile.kind not in owner.capabilities:
            raise ConfigError(f"Profile {profile.id}: owner lacks the required capability")
        if (
            profile.kind in {"host-redirect", "guest-direct", "udp-return"}
            and owner.privilege != "external-root"
        ):
            raise ConfigError(
                f"Profile {profile.id}: privileged transport requires an external-root owner"
            )
        if profile.target_ports is not None and profile.target_ports.width != profile.ports.width:
            raise ConfigError(f"Profile {profile.id}: source and target ranges differ in width")
        if profile.fallback_publication is not None:
            fallback = config.profile(profile.fallback_publication)
            if (
                profile.kind != "guest-direct"
                or fallback.kind != "publication"
                or fallback.service != profile.service
                or fallback.scope != profile.scope
                or fallback.protocol != profile.protocol
                or fallback.ports.width != profile.ports.width
                or (fallback.target_ports or fallback.ports)
                != (profile.target_ports or profile.ports)
            ):
                raise ConfigError(
                    f"Profile {profile.id}: fallback requires its own exact native publication"
                )
        if profile.source_scope != "lan" and (
            profile.kind != "host-redirect" or profile.safety.kind != "structural"
        ):
            # Only a rule that ends at the host's own published socket may match
            # every source. A guest is reached through the translation alone, so
            # there, and for the UDP return pair, the LAN prefix is the control.
            raise ConfigError(
                f"Profile {profile.id}: an unrestricted source needs a structural host redirect"
            )
        if profile.kind == "host-redirect":
            backing_publication(config, profile)
        if profile.safety.kind == "bounded" and not (
            profile.safety.statement and profile.safety.statement.strip()
        ):
            raise ConfigError(
                f"Profile {profile.id}: bounded safety requires an explicit risk statement"
            )
        if profile.kind in {"guest-direct", "udp-return"} and profile.safety.kind != "bounded":
            raise ConfigError(
                f"Profile {profile.id}: direct guest targets require bounded risk acceptance"
            )
        if profile.kind == "udp-return":
            if profile.protocol != "udp" or profile.target_ports is not None:
                raise ConfigError(
                    f"Profile {profile.id}: UDP return uses UDP with no explicit target port"
                )
            if service.automatic_ports != profile.ports:
                raise ConfigError(
                    f"Profile {profile.id}: UDP return must equal the guest automatic port range"
                )
    for index, profile in enumerate(config.profiles):
        scope = config.scope(profile.scope)
        for other in config.profiles[index + 1 :]:
            other_scope = config.scope(other.scope)
            if (
                scope.host_ipv4 == other_scope.host_ipv4
                and profile.protocol == other.protocol
                and profile.ports.overlaps(other.ports)
            ):
                raise ConfigError(
                    f"Profiles {profile.id} and {other.id}: overlapping host port claims"
                )


def _check_discovery(config: Config) -> None:
    for item in config.discovery:
        if type(item.max_age_seconds) is not int or type(item.max_records) is not int:
            raise ConfigError(f"Discovery {item.id}: discovery bounds must be integers")
        if any(
            re.fullmatch(r"_[A-Za-z0-9][A-Za-z0-9-]{0,62}\._(?:tcp|udp)", service_type) is None
            for service_type in item.types
        ):
            raise ConfigError(f"Discovery {item.id}: invalid DNS-SD service type")
        owner = config.owner(item.owner)
        if owner.privilege != "user" or "discovery" not in owner.capabilities:
            raise ConfigError(f"Discovery {item.id}: requires a user discovery owner")
        dependencies = [config.profile(identifier) for identifier in item.dependencies]
        matching = [
            profile
            for profile in dependencies
            if profile.service == item.service and profile.scope == item.scope
        ]
        if item.direction == "export" and not any(
            profile.kind == "publication" for profile in matching
        ):
            raise ConfigError(
                f"Discovery {item.id}: export requires its own publication dependency"
            )
        if item.return_path != "required":
            # The setting lifts the requirement below and nothing else. An entry
            # that lists a return path depends on it and cannot say otherwise.
            if item.direction != "import" or any(
                profile.kind == "udp-return" for profile in dependencies
            ):
                raise ConfigError(
                    f"Discovery {item.id}: only an import that lists no UDP return "
                    "dependency is independent of the return path"
                )
        elif (
            item.direction == "import"
            and {"_airplay._tcp", "_raop._tcp"}.intersection(item.types)
            and not any(profile.kind == "udp-return" for profile in matching)
        ):
            raise ConfigError(
                f"Discovery {item.id}: media import requires its UDP return dependency"
            )
        # The schema's "integer" also accepts a number written as 2.0, and a
        # constructed entry was never parsed.
        if item.misses is not None and (type(item.misses) is not int or not 1 <= item.misses <= 8):
            raise ConfigError(f"Discovery {item.id}: a miss tolerance is an integer from 1 to 8")


# One DNS label holds 63 bytes. The bundled discovery owner forms the first
# label of a projected host name from a prefix and 16 hexadecimal digits
# (bonjour_owner.project_records), which leaves 47 bytes for the prefix.
_PREFIX_MAX = 63 - 16


def _check_discovery_names(config: Config) -> None:
    names = config.discovery_names
    for prefix in (names.export_prefix, names.import_prefix):
        # fullmatch: the schema's pattern would let one trailing line feed pass.
        if re.fullmatch(r"[a-z][a-z0-9-]*", prefix) is None or len(prefix) > _PREFIX_MAX:
            raise ConfigError("Discovery names: invalid host name prefix")
    # A projected name must tell which direction made it; equal prefixes and a
    # prefix that begins with the other one cannot.
    if names.export_prefix.startswith(names.import_prefix) or names.import_prefix.startswith(
        names.export_prefix
    ):
        raise ConfigError("Discovery names: one prefix begins with the other")


def validate_config(config: Config) -> None:
    """Validate an already constructed model as rigorously as loaded input."""
    errors = sorted(
        _validator().iter_errors(to_dict(config)),
        key=lambda item: tuple(map(str, item.absolute_path)),
    )
    if errors:
        path = "/".join(map(str, errors[0].absolute_path)) or "<root>"
        raise ConfigError(f"Schema violation at {path} ({errors[0].validator})")
    _check_references(config)
    _check_scopes(config)
    _check_profiles(config)
    _check_discovery(config)
    _check_discovery_names(config)


def parse_config(text: str | bytes) -> Config:
    try:
        data = strict_loads(text)
    except CodecError as exc:
        raise ConfigError(str(exc)) from exc
    errors = sorted(
        _validator().iter_errors(data), key=lambda item: tuple(map(str, item.absolute_path))
    )
    if errors:
        path = "/".join(map(str, errors[0].absolute_path)) or "<root>"
        raise ConfigError(f"Schema violation at {path} ({errors[0].validator})")
    config = _construct(data)
    _check_references(config)
    _check_scopes(config)
    _check_profiles(config)
    _check_discovery(config)
    _check_discovery_names(config)
    return config


def load_config(path: str | Path) -> Config:
    return parse_config(read_bounded_file(path))


def to_dict(config: Config) -> dict[str, Any]:
    # JSON arrays, rather than internal tuples, also satisfy the external schema.
    result = cast(dict[str, Any], strict_loads(json.dumps(asdict(config))))
    # The default pair is left out: canonical bytes and config_digest of a policy
    # that does not name its prefixes stay those of every earlier release.
    if config.discovery_names == DiscoveryNames():
        del result["discovery_names"]
    for profile in result["profiles"]:
        if profile["fallback_publication"] is None:
            del profile["fallback_publication"]
        if profile["source_scope"] == "lan":
            del profile["source_scope"]
    for item in result["discovery"]:
        # The default has no place in the canonical form, so a policy written
        # before the member existed keeps its form and its digests.
        if item["return_path"] == "required":
            del item["return_path"]
        # An entry that states no tolerance of its own has no such member.
        if item["misses"] is None:
            del item["misses"]
    return result


def profile_view(profile: Profile) -> dict[str, Any]:
    """One profile as an admission review prints it; the default source scope is left out."""
    view = asdict(profile)
    if profile.source_scope == "lan":
        del view["source_scope"]
    return view


def profile_digest(config: Config, profile: Profile) -> str:
    """Bind every authority-bearing resolved field, not merely a profile ID."""
    service = config.service(profile.service)
    resolved = asdict(profile)
    if profile.fallback_publication is None:
        del resolved["fallback_publication"]
    if profile.source_scope == "lan":
        # Left out, so a digest issued before the field existed still matches.
        del resolved["source_scope"]
    payload = {
        "digest_version": 2 if profile.fallback_publication is not None else 1,
        "schema_version": config.schema_version,
        "profile": resolved,
        "scope": asdict(config.scope(profile.scope)),
        "service": asdict(service),
        "owner": asdict(config.profile_owner(profile)),
        "service_owner": asdict(config.owner(service.owner)),
        "address_family": "inet",
    }
    if profile.fallback_publication is not None:
        payload["fallback_profile_digest"] = profile_digest(
            config, config.profile(profile.fallback_publication)
        )
    if profile.source_scope != "lan":
        # An unrestricted source has its own digest version and is approved
        # together with the one native publication it exposes.
        payload["digest_version"] = 3
        payload["publication_profile_digest"] = profile_digest(
            config, backing_publication(config, profile)
        )
    return digest(payload)


def config_digest(config: Config) -> str:
    return digest({"digest_version": 1, "policy": to_dict(config)})

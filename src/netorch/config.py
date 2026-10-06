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
from .model import Config, Discovery, Owner, PortRange, Profile, Safety, Scope, Service


class ConfigError(ValueError):
    """Schema or cross-owner invariants are not satisfied."""


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
            )
            for item in data["discovery"]
        ),
    )


def _check_range(ports: PortRange | None, label: str) -> None:
    if ports is not None and ports.first > ports.last:
        raise ConfigError(f"{label}: port range is reversed")


def _check_references(config: Config) -> None:
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
        if profile.kind == "host-redirect":
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
            if len(matching) != 1:
                raise ConfigError(
                    f"Profile {profile.id}: host redirect requires its own publication target"
                )
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
        if (
            item.direction == "import"
            and {"_airplay._tcp", "_raop._tcp"}.intersection(item.types)
            and not any(profile.kind == "udp-return" for profile in matching)
        ):
            raise ConfigError(
                f"Discovery {item.id}: media import requires its UDP return dependency"
            )


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
    return config


def load_config(path: str | Path) -> Config:
    return parse_config(read_bounded_file(path))


def to_dict(config: Config) -> dict[str, Any]:
    # JSON arrays, rather than internal tuples, also satisfy the external schema.
    result = cast(dict[str, Any], strict_loads(json.dumps(asdict(config))))
    for profile in result["profiles"]:
        if profile["fallback_publication"] is None:
            del profile["fallback_publication"]
    return result


def profile_digest(config: Config, profile: Profile) -> str:
    """Bind every authority-bearing resolved field, not merely a profile ID."""
    service = config.service(profile.service)
    resolved = asdict(profile)
    if profile.fallback_publication is None:
        del resolved["fallback_publication"]
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
    return digest(payload)


def config_digest(config: Config) -> str:
    return digest({"digest_version": 1, "policy": to_dict(config)})

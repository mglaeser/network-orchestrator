"""Pure DNS-SD record admission/projection, separate from packet transport."""

from __future__ import annotations

import base64
import ipaddress
import math
import re
from dataclasses import dataclass, replace

from .model import Config, Discovery, DiscoveryNames
from .state import Observation

_DNS_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def dns_name_key(value: str) -> str:
    """RFC 4343 section 3: compare ASCII letter case, never Unicode casefold.

    Only comparison keys are normalized; records retain their observed spelling.
    """
    return value.translate(_DNS_ASCII_LOWER)


def is_own_projection(record: Record, names: DiscoveryNames) -> bool:
    """Reserved projection prefixes cannot be reflected in either direction."""
    prefixes = (dns_name_key(names.export_prefix), dns_name_key(names.import_prefix))
    return any(dns_name_key(value).startswith(prefixes) for value in (record.name, record.hostname))


@dataclass(frozen=True, slots=True)
class Record:
    name: str
    service_type: str
    hostname: str
    port: int
    ipv4: str
    txt: tuple[bytes, ...]
    interface: str
    seen_at: float
    source_service: str | None = None
    source_generation: str | None = None

    def __post_init__(self) -> None:
        ipaddress.IPv4Address(self.ipv4)
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("invalid DNS-SD port")
        if any(not isinstance(item, bytes) for item in self.txt):
            raise ValueError("TXT entries must be raw bytes")
        if (
            not self.name
            or len(self.name.encode("utf-8")) > 63
            or not self.hostname
            or len(self.hostname.encode("utf-8")) > 255
            or any(len(item) > 255 for item in self.txt)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", self.interface)
            or not re.fullmatch(r"_[A-Za-z0-9-]+\._(?:tcp|udp)", self.service_type)
        ):
            raise ValueError("invalid DNS-SD record")
        _time(self.seen_at)


@dataclass(frozen=True, slots=True)
class Publication:
    service: str
    generation: str
    guest_port: int
    host_port: int
    host_ipv4: str
    protocol: str = "tcp"

    def __post_init__(self) -> None:
        ipaddress.IPv4Address(self.host_ipv4)
        if (
            not self.service
            or not self.generation
            or self.protocol not in {"tcp", "udp"}
            or type(self.guest_port) is not int
            or not 1 <= self.guest_port <= 65535
            or type(self.host_port) is not int
            or not 1 <= self.host_port <= 65535
        ):
            raise ValueError("invalid publication provenance")


def _time(value: float) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (float, int))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError("time must be finite and nonnegative")


@dataclass(frozen=True, slots=True)
class Projection:
    state: str
    reason: str
    record: Record | None = None


def project_export(
    config: Config,
    policy: Discovery,
    record: Record,
    endpoint: Observation,
    publications: tuple[Publication, ...],
    verified_dependencies: frozenset[str],
    now: float,
    *,
    interface_confirmed: bool,
) -> Projection:
    """Match exact announcing service/generation, never a coincident port number."""
    scope = config.scope(policy.scope)
    _time(now)
    if policy.direction != "export":
        raise ValueError("an export policy is required")
    if not interface_confirmed or record.interface == scope.interface:
        return Projection("unknown", "interface-unverified")
    if is_own_projection(record, config.discovery_names):
        return Projection("absent", "loop-excluded")
    if not set(policy.dependencies) <= verified_dependencies:
        return Projection("absent", "dependency-unverified")
    if now < record.seen_at or now - record.seen_at > policy.max_age_seconds:
        return Projection("absent", "expired")
    current = endpoint.at(now, policy.max_age_seconds)
    if current.state != "present":
        return Projection("unknown", "source-unverified")
    if (
        record.service_type not in policy.types
        or record.source_service != policy.service
        or record.source_generation != current.generation
        or record.ipv4 != current.data.get("ipv4")
    ):
        return Projection("absent", "source-mismatch")
    matches = [
        item
        for item in publications
        if item.service == policy.service
        and item.generation == current.generation
        and item.guest_port == record.port
        and item.host_ipv4 == scope.host_ipv4
        and item.protocol == ("tcp" if record.service_type.endswith("._tcp") else "udp")
    ]
    if len(matches) != 1:
        return Projection("absent", "publication-not-unique")
    item = matches[0]
    projected = replace(
        record,
        hostname=f"{config.discovery_names.export_prefix}{policy.service}.local.",
        port=item.host_port,
        ipv4=item.host_ipv4,
        interface=scope.interface,
    )
    return Projection("present", "verified", projected)


def select_imports(
    config: Config,
    policy: Discovery,
    records: tuple[Record, ...],
    verified_dependencies: frozenset[str],
    now: float,
    *,
    eligible_models: frozenset[bytes],
    target_interface: str,
    interface_confirmed: bool,
) -> tuple[Record, ...]:
    """Import eligible Apple-media tuples, associating related records by endpoint.

    Eligibility data is supplied by the existing discovery owner, never elevated
    to PF authority. This selector does not authenticate a discovered device.
    """
    if policy.direction != "import":
        raise ValueError("an import policy is required")
    _time(now)
    if (
        not interface_confirmed
        or not target_interface
        or target_interface == "0"
        or not set(policy.dependencies) <= verified_dependencies
    ):
        return ()
    scope = config.scope(policy.scope)
    fresh = [
        item
        for item in records
        if item.interface == scope.interface
        and item.service_type in policy.types
        and item.seen_at <= now <= item.seen_at + policy.max_age_seconds
        and ipaddress.IPv4Address(item.ipv4) in ipaddress.IPv4Network(scope.lan_cidr)
        and not is_own_projection(item, config.discovery_names)
    ]
    eligible = {
        (dns_name_key(item.hostname), item.ipv4)
        for item in fresh
        if item.service_type == "_airplay._tcp"
        and any(value in eligible_models for value in item.txt if value.startswith(b"model="))
    }
    selected = [
        replace(item, interface=target_interface)
        for item in fresh
        if (dns_name_key(item.hostname), item.ipv4) in eligible
    ]
    # A flood or ambiguous duplicate registration is not truncated into success.
    if len(selected) > policy.max_records:
        return ()
    keys = [(item.name, item.service_type, item.interface) for item in selected]
    if len(keys) != len(set(keys)):
        return ()
    return tuple(sorted(selected, key=lambda item: (item.name, item.service_type, item.ipv4)))


def txt_to_json(values: tuple[bytes, ...]) -> list[str]:
    """Lossless JSON representation, including TXT bytes not representable as argv."""
    return [base64.b64encode(value).decode("ascii") for value in values]


def txt_from_json(values: list[str]) -> tuple[bytes, ...]:
    return tuple(base64.b64decode(value, validate=True) for value in values)

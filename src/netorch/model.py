"""Immutable policy types. Loading and cross-owner validation live in config."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PortRange:
    first: int
    last: int

    @property
    def width(self) -> int:
        return self.last - self.first + 1

    def contains(self, other: PortRange) -> bool:
        return self.first <= other.first and other.last <= self.last

    def overlaps(self, other: PortRange) -> bool:
        return self.first <= other.last and other.first <= self.last


@dataclass(frozen=True, slots=True)
class Scope:
    id: str
    interface: str
    host_ipv4: str
    lan_cidr: str
    guest_cidr: str


@dataclass(frozen=True, slots=True)
class Owner:
    id: str
    privilege: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Service:
    id: str
    owner: str
    contract_sha256: str
    automatic_ports: PortRange | None = None


@dataclass(frozen=True, slots=True)
class Safety:
    kind: str
    max_age_seconds: int
    unknown_limit: int
    statement: str | None = None


@dataclass(frozen=True, slots=True)
class Profile:
    id: str
    service: str
    scope: str
    kind: str
    protocol: str
    ports: PortRange
    target_ports: PortRange | None
    safety: Safety
    owner: str | None = None
    fallback_publication: str | None = None
    # "lan": the rule matches the scope's LAN prefix. "any": every source; only
    # a structural host redirect behind its own publication may declare it.
    source_scope: str = "lan"


@dataclass(frozen=True, slots=True)
class Discovery:
    id: str
    owner: str
    service: str
    scope: str
    direction: str
    types: tuple[str, ...]
    dependencies: tuple[str, ...]
    max_age_seconds: int
    max_records: int


@dataclass(frozen=True, slots=True)
class Config:
    schema_version: int
    site: str
    scopes: tuple[Scope, ...]
    owners: tuple[Owner, ...]
    services: tuple[Service, ...]
    profiles: tuple[Profile, ...]
    discovery: tuple[Discovery, ...]

    def scope(self, identifier: str) -> Scope:
        for item in self.scopes:
            if item.id == identifier:
                return item
        raise KeyError(f"Unknown scope: {identifier}")

    def owner(self, identifier: str) -> Owner:
        for item in self.owners:
            if item.id == identifier:
                return item
        raise KeyError(f"Unknown owner: {identifier}")

    def service(self, identifier: str) -> Service:
        for item in self.services:
            if item.id == identifier:
                return item
        raise KeyError(f"Unknown service: {identifier}")

    def profile(self, identifier: str) -> Profile:
        for item in self.profiles:
            if item.id == identifier:
                return item
        raise KeyError(f"Unknown profile: {identifier}")

    def profile_owner(self, profile: Profile | str) -> Owner:
        profile = self.profile(profile) if isinstance(profile, str) else profile
        return self.owner(profile.owner or self.service(profile.service).owner)

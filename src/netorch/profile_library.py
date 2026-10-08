"""Reviewed named capabilities, never expressions or host-specific branches."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Strategy:
    name: str
    version: int
    gate: str
    preserves_client_identity: bool
    retirement: str
    proving_tests: tuple[str, ...]


STRATEGIES = (
    Strategy(
        "published-port",
        1,
        "structural",
        False,
        "Vendor publication replaced",
        ("native-publication",),
    ),
    Strategy(
        "host-port-redirect",
        1,
        "structural",
        False,
        "Vendor LAN bind capability",
        ("rule-readback", "first-packet"),
    ),
    Strategy(
        "guest-direct-redirect",
        1,
        "bounded",
        True,
        "Vendor structural direct ingress",
        ("first-packet", "state-drain", "dns-client-identity"),
    ),
    Strategy(
        "guest-udp-range-forward",
        4,
        "bounded",
        True,
        "Vendor source-preserving UDP return",
        ("first-packet", "state-drain", "heard-audio"),
    ),
    Strategy(
        "guest-lan-alias",
        1,
        "native-owner",
        False,
        "Vendor application LAN identity",
        ("application-connect",),
    ),
)


@dataclass(frozen=True, slots=True)
class DiscoveryProfile:
    name: str
    version: int
    direction: str
    service_types: tuple[str, ...]
    transformations: tuple[str, ...]
    proving_tests: tuple[str, ...]
    # The record type an import decides a receiver's eligibility from.
    eligibility_type: str | None = None


# The generic export names no service type of its own. Its one token stands for
# whatever TCP services the workload announces; no retained owner enumerates them.
AUTOMATIC_TYPES = ("auto-tcp",)
DISCOVERY_PROFILES = (
    DiscoveryProfile(
        "published-tcp-export",
        1,
        "export",
        AUTOMATIC_TYPES,
        (),
        ("genuine-record", "publication-identity"),
    ),
    DiscoveryProfile(
        "homekit-export", 1, "export", ("_hap._tcp",), (), ("genuine-record", "application-connect")
    ),
    DiscoveryProfile(
        "home-assistant-export",
        1,
        "export",
        ("_home-assistant._tcp",),
        ("home-assistant-endpoint-urls",),
        ("genuine-record", "publication-identity"),
    ),
    DiscoveryProfile(
        "apple-media-import",
        1,
        "import",
        (
            "_airplay._tcp",
            "_raop._tcp",
            "_companion-link._tcp",
            "_mediaremotetv._tcp",
            "_appletv-v2._tcp",
        ),
        ("ipv4-only", "genuine-apple-model", "exclude-own-projection"),
        ("cold-application-scan", "receiver-change", "heard-audio"),
        "_airplay._tcp",
    ),
)


APPLICATION_PROFILES = (
    "generic",
    "resolver",
    "reverse-proxy",
    "home-assistant",
    "media-controller",
    "camera",
    "dashboard",
    "inference",
    "management-ui",
)


def strategy(name: str, version: int) -> Strategy:
    for item in STRATEGIES:
        if item.name == name and item.version == version:
            return item
    raise ValueError("unknown strategy or strategy version")


def discovery_profile(name: str, version: int) -> DiscoveryProfile:
    for item in DISCOVERY_PROFILES:
        if item.name == name and item.version == version:
            return item
    raise ValueError("unknown discovery profile or profile version")

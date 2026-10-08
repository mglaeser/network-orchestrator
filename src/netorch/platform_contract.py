"""Source-backed candidate platform facts; fixtures confer no host acceptance."""

from __future__ import annotations

from dataclasses import dataclass

CANDIDATE_MACOS_VERSION = "27.0.1"
CANDIDATE_MACOS_BUILD = "26A434"
CANDIDATE_RUNTIME_VERSION = "1.5.0"
CONTAINERIZATION_VERSION = "0.47.0"
RECOVERY_EXIT_CODE = 42
LAUNCHD_INTERVAL_FLOOR = 10
# The most bytes of a PF anchor name, for one component and for the complete
# path. The kernel refuses to create a component of 64 bytes or more (xnu
# `bsd/net/pf_ruleset.c`, `pf_find_or_create_ruleset`, with `PF_ANCHOR_NAME_SIZE`
# of `bsd/net/pfvar.h`, tag xnu-12377.121.6). Apple does not publish its pfctl.
# The nearest published source of that tool (FreeBSD `contrib/pf/pfctl/pfctl.c`,
# `pfctl_rules`, releases 8.4.0 and 9.3.0) copies the whole `-a` argument, parent
# anchors and slashes included, into a buffer of that size and stops at 64 bytes
# or more. Until a real pfctl has answered, the complete path is therefore held
# to the bound of one component. No fact row: the reports do not state it.
PF_ANCHOR_BYTES = 63
# A populated hardware acceptance ledger is required; candidate parsing is not
# a mutation support declaration, and this framework ships no host acceptance.
ACCEPTED_PLATFORMS: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class PlatformFact:
    id: str
    statement: str
    sources: tuple[str, ...]
    source_versions: tuple[str, ...]
    proving_test: str
    retirement: str


FACTS = (
    PlatformFact(
        "apple-silicon",
        "The vendor runtime requires Apple silicon.",
        ("https://github.com/apple/container/blob/1.5.0/README.md",),
        ("container-1.5.0",),
        "test_candidate_platform_is_not_hardware_acceptance",
        "Vendor supports other hardware",
    ),
    PlatformFact(
        "rotating-addresses",
        (
            "Released guest addresses return to the allocation tail; "
            "a rebuilt pool needs fresh identity."
        ),
        (
            "https://github.com/apple/container/blob/1.5.0/Package.swift",
            "https://github.com/apple/containerization/blob/0.47.0/Sources/ContainerizationExtras/RotatingAddressAllocator.swift",
        ),
        ("container-1.5.0", "containerization-0.47.0"),
        "test_released_slot_waits_at_fifo_tail_until_other_available_slots_are_used",
        "Vendor structural endpoint identity",
    ),
    PlatformFact(
        "local-network-consent",
        (
            "User LaunchAgents need their own Local Network identity; "
            "Terminal success proves no agent consent."
        ),
        (
            "https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy",
        ),
        ("macOS-15-and-later",),
        "test_host_entrypoint_never_contacts_network",
        "Vendor stable consent-preserving adapter",
    ),
    PlatformFact(
        "pf-state-lifetime",
        "Removing translation rules does not establish withdrawal of retained states.",
        (
            "https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api",
            "https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pf_ioctl.c",
        ),
        ("Darwin-source-xnu-12377.121.6",),
        "test_unknown_runtime_withdraws_and_drains_both_directions",
        "Vendor structural ingress capability",
    ),
    PlatformFact(
        "native-discovery-identity",
        (
            "Registration needs a verified interface and genuine records; "
            "successful child exit alone proves neither."
        ),
        (
            "https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-2881.120.11/Clients/dns-sd.c",
        ),
        ("mDNSResponder-2881.120.11",),
        "test_exit_zero_does_not_prove_interface",
        "Demonstrated parser failure justifies reviewed native adapter",
    ),
)


def candidate_matches(macos_version: str, macos_build: str, runtime_version: str) -> bool:
    return (macos_version, macos_build, runtime_version) == (
        CANDIDATE_MACOS_VERSION,
        CANDIDATE_MACOS_BUILD,
        CANDIDATE_RUNTIME_VERSION,
    )

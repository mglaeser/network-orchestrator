"""Readiness flags of the name-service path: proposed behaviour, as strict expected failures.

Five of the findings R-N1 to R-N8 can be stated against the code. For each, a
test asserts what the proposed change would make the PF owner do with the
name-service rules on port 53, and fails on this release with an assertion
whose message says what the owner does today, for the reason that the finding
names. R-N5 and R-N6 are recorded in the owner's own documents, and existing
tests prove them; R-N7 has no interface that a test could use without inventing
one. The records, the proposed changes and the decisions they need are in
docs/reviews/2026-10-09-readiness-dns.md.

A strict expected failure becomes a failure of the suite once the behaviour
exists: the marker then goes, and the test stays as the regression of that
change. A step that only prepares a scenario fails with `pytest.fail`, never
with an assertion, so that it cannot pass for the expected failure. One test is
an ordinary one that passes today: it holds a safety property that the change
proposed for R-N4 must keep.

Every kernel and runtime tool is a fake. Addresses are documentation values and
the name of the listener's process is the one the platform's DNS exception
names.
"""

from __future__ import annotations

from dataclasses import fields, replace
from itertools import pairwise
from typing import Any

import pytest

from netorch.model import Config, Profile, Scope
from netorch.pf_owner import Installation, PFError, ShellBackend
from netorch.process import OutputLimit, ProcessTimeout
from netorch.state import Observation, Snapshot, intent_from_dict, intent_to_dict
from tests.test_pf_deferral import observed_pass
from tests.test_pf_owner import FakeBackend, approve_all, configure_fallback, environment

__all__ = ["environment"]

HOST = "192.0.2.10"  # the host's own address in the fixture's scope
GUEST = "198.51.100.10"  # the resolver guest's address in the fixture
DNS = ("dns-tcp", "dns-udp")
WEB = "proxy-standard"  # the web redirect, a host redirect to the host's own published socket
OTHERS = ["media-udp", WEB]
# Where each port-53 rule sends a LAN client's query, by profile.
DIRECT = dict.fromkeys(DNS, f"{GUEST}:53")
FALLBACK = dict.fromkeys(DNS, f"{HOST}:1053")
# The installation decision that R-N2 proposes, under a key of its own. No
# release knows it yet.
SWITCH = {"direct_unknown": "fallback"}
# How a state listing can run over one of the runner's two bounds.
LIMITS = ["slower than its time limit", "larger than its output bound"]
Row = tuple[str, int, int, str, str]


def port_53(rules: str) -> dict[str, str]:
    """The target address and port of every loaded name-service redirect, by profile."""
    loaded: dict[str, str] = {}
    for line in rules.splitlines():
        rule, _, key = line.partition(" # netorch:")
        if key in DNS:
            words = rule.split()
            arrow = words.index("->")
            loaded[key] = f"{words[arrow + 1]}:{words[arrow + 3]}"
    return loaded


def changes(
    old: dict[str, str], loads: list[dict[str, str]]
) -> list[tuple[dict[str, str], dict[str, str]]]:
    """Each anchor load that changed port 53, as what port 53 held before and after it."""
    return [(before, after) for before, after in pairwise([old, *loads]) if before != after]


class Kernel(FakeBackend):
    """The owner tests' fake kernel, which keeps what every anchor load left on port 53.

    A load that does not find the expected rules is refused with the owner's
    own error, as the backend script refuses it, never with an assertion. The
    socket inventory is root's listing of listening sockets, by protocol.
    """

    def __init__(self) -> None:
        super().__init__()
        self.loads: list[dict[str, str]] = []
        self.sockets: dict[str, list[Row]] = {"tcp": [], "udp": []}

    def replace(self, expected: str, candidate: str) -> str:
        if self.normalize(expected) != self.normalize(self.rules):
            raise PFError("the loaded rules are not the expected ones")
        loaded = super().replace(expected, candidate)
        self.loads.append(port_53(candidate))
        return loaded

    def socket_inventory(self, protocol: str) -> tuple[Row, ...]:
        self.commands.append(("inventory", protocol))
        return tuple(self.sockets[protocol])


class Unreadable(Kernel):
    """The fake kernel whose state listing runs over one of the runner's bounds at a chosen read.

    Reads are counted from the start of a pass. The runner raises these two
    when a listing exceeds its time limit or its output bound.
    """

    def __init__(self, limit: str) -> None:
        super().__init__()
        self.limit = limit
        self.reads = 0
        self.failing: int | None = None

    def states(self) -> str:
        self.reads += 1
        if self.reads == self.failing:
            if self.limit == LIMITS[0]:
                raise ProcessTimeout("command exceeded its time limit")
            raise OutputLimit("command exceeded its combined output bound")
        return super().states()


def with_kernel(environment: Any, kernel: Kernel) -> Any:
    root, config, settings, _, snapshots = environment
    return root, config, settings, kernel, snapshots


def installed(environment: Any, **decisions: str) -> tuple[Any, bool]:
    """The site under these decisions of the installation, and whether it has them.

    This release refuses the key of the decision that R-N2 proposes, as a key it
    does not know. Then, and only then, the site keeps its default installation,
    under which the scenario shows today's behaviour. Any other refusal ends the
    test. Admissions are given after this.
    """
    root, config, settings, kernel, snapshots = environment
    raw = {**settings.to_dict(), **decisions}
    try:
        chosen = Installation.from_dict(raw)
    except PFError as refused:
        unknown = set(decisions) - {field.name for field in fields(Installation)}
        if unknown != set(SWITCH) or str(refused) != "unsupported installation schema":
            pytest.fail(f"the installation refuses {decisions}: {refused}")
        known = {key: value for key, value in raw.items() if key not in unknown}
        try:
            Installation.from_dict(known)
        except PFError as other:
            pytest.fail(f"the installation refuses {known}: {other}")
        return environment, False
    root.write("installation.json", chosen.to_dict())
    return (root, config, chosen, kernel, snapshots), True


def precondition(holds: bool, what: str) -> None:
    """A step before the behaviour under test; its failure is never the expected one."""
    if not holds:
        pytest.fail(f"precondition not met: {what}")


def ready(report: Snapshot) -> list[str]:
    return sorted(key for key, item in report.profiles.items() if item.data["root_ready"] is True)


def loaded(kernel: Kernel, key: str) -> bool:
    return any(line.endswith(f" # netorch:{key}") for line in kernel.rules.splitlines())


def publications_of(config: Config, service: str) -> set[str]:
    return {
        profile.id
        for profile in config.profiles
        if profile.kind == "publication" and profile.service == service
    }


def timed_out(config: Config, snapshot: Snapshot, service: str) -> Snapshot:
    """The read of one service's container ran out of time; the rest of the read is intact.

    The bundled observer then gives the service's publications the state and the
    reason of the service.
    """
    unknown = Observation("unknown", "timed-out", snapshot.observed_at, None)
    return replace(
        snapshot,
        services={**snapshot.services, service: unknown},
        profiles={
            key: replace(unknown, data={"states": ()})
            if key in publications_of(config, service)
            else item
            for key, item in snapshot.profiles.items()
        },
    )


def restarted(config: Config, snapshot: Snapshot, service: str, generation: str) -> Snapshot:
    """The service's guest started again, with a new start time and so a new generation.

    Its definition, network, address and link address stay what they were.
    """
    publications = publications_of(config, service)
    return replace(
        snapshot,
        services={
            **snapshot.services,
            service: replace(snapshot.services[service], generation=generation),
        },
        profiles={
            key: replace(
                item, generation=generation, data={**item.data, "target_generation": generation}
            )
            if key in publications
            else item
            for key, item in snapshot.profiles.items()
        },
    )


def unreadable_pass(site: Any, kernel: Unreadable, read: int) -> str:
    """One pass whose state listing runs over its bound at the given read: how it ended."""
    kernel.reads, kernel.failing = 0, read
    ended = "ends"
    try:
        observed_pass(site)
    except (OSError, RuntimeError, ValueError) as error:
        ended = f"raises {type(error).__name__} and ends"
    finally:
        kernel.failing = None
    journal = site[0].read("journal.json")
    why = f"reason {journal['reason']}" if "reason" in journal else "no reason recorded"
    return f"{ended} {journal['phase']} ({why})"


def fallback_site(environment: Any, kernel: Kernel) -> Any:
    """The fixture's site with the name service in its fallback form, all profiles ready.

    The direct path to the resolver does not verify, so the name service is
    loaded in its fallback form, which is recorded as a host redirect, beside
    the web redirect and the UDP return pair.
    """
    site = with_kernel(environment, kernel)
    configure_fallback(site)
    kernel.unavailable_guests = {GUEST}
    result, report = observed_pass(site)
    precondition(
        result["phase"] == "committed"
        and port_53(kernel.rules) == FALLBACK
        and ready(report) == sorted([*DNS, *OTHERS]),
        "the fallback form, the web redirect and the return pair are loaded and ready",
    )
    return site


# ---- R-N1: a switch between the direct form and the fallback form


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "readiness R-N1: a pass that switches the name service between its direct and its "
        "fallback form replaces both port-53 rules in one anchor load"
    ),
)
@pytest.mark.parametrize("direction", ["to the fallback", "back to direct"])
def test_r_n1_a_switch_of_the_name_service_path_never_leaves_port_53_without_a_rule(
    environment: Any, direction: str
) -> None:
    kernel = Kernel()
    site = with_kernel(environment, kernel)
    configure_fallback(site)
    observed_pass(site)
    precondition(port_53(kernel.rules) == DIRECT, "the direct form is loaded")
    if direction == "to the fallback":
        # The route or the neighbour entry of the resolver stops verifying.
        kernel.unavailable_guests = {GUEST}
        new = FALLBACK
    else:
        kernel.unavailable_guests = {GUEST}
        observed_pass(site)
        observed_pass(site)
        precondition(port_53(kernel.rules) == FALLBACK, "the fallback form is loaded")
        # The route and the neighbour entry verify again.
        kernel.unavailable_guests = set()
        new = DIRECT
    old = port_53(kernel.rules)
    kernel.loads.clear()

    result, report = observed_pass(site)
    loads = list(kernel.loads)
    following, _ = observed_pass(site)

    # The switch is one anchor load: of the loads of the switching pass, one
    # changes port 53, for both profiles together, from the old form to the new.
    assert changes(old, loads) == [(old, new)], (
        f"switching {direction}, the anchor loads of the switching pass leave port 53 with "
        f"{loads} ({result['phase']}, {result['changed']}); the next pass changes "
        f"{following['changed']}"
    )
    assert set(DNS) <= set(ready(report))


# ---- R-N2: a runtime read that timed out while the direct form is loaded


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "readiness R-N2: under a decision of its own, a timed-out read replaces loaded direct "
        "DNS by its declared, listening fallback in one load instead of leaving port 53 empty"
    ),
)
def test_r_n2_a_timed_out_read_moves_direct_dns_to_its_listening_fallback(
    environment: Any,
) -> None:
    kernel = Kernel()
    # As the vendor's forwarder holds a published port: on the host's own address.
    kernel.sockets = {
        protocol: [(HOST, 1053, 501, "forwarder", "IPv4")] for protocol in ("tcp", "udp")
    }
    site, decided = installed(
        with_kernel(environment, kernel), runtime_unknown="keep-host-paths", **SWITCH
    )
    config = configure_fallback(site)
    observed_pass(site)
    precondition(port_53(kernel.rules) == DIRECT, "the direct form is loaded")
    site[4].append(timed_out(config, site[4][-1], "resolver"))
    kernel.loads.clear()
    kernel.commands.clear()

    result, report = observed_pass(site)

    under = (
        "with the decision"
        if decided
        else f"with the default installation (this release refuses {set(SWITCH)} as unknown)"
    )
    assert port_53(kernel.rules) == FALLBACK, (
        f"{under} and a fallback that is declared, admitted and listening, a read of the "
        f"resolver that ran out of time leaves port 53 with {port_53(kernel.rules)} "
        f"({result['phase']}, {result['changed']}, withheld {result.get('withheld', {})})"
    )
    # One load replaces both rules that name the guest.
    assert changes(DIRECT, kernel.loads) == [(DIRECT, FALLBACK)]
    # Without runtime evidence the fallback form is withheld, never reported
    # ready, and the owner takes no enable reference for it.
    assert {key: report.profiles[key].data.get("withheld") for key in DNS} == dict.fromkeys(
        DNS, "runtime-unknown"
    )
    assert not set(DNS) & set(ready(report))
    assert ("reference",) not in kernel.commands


# ---- R-N3: a resolver that restarts on the same address


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "readiness R-N3: a resolver restart that keeps its address keeps the direct port-53 "
        "rule loaded, or loads it again within the same pass"
    ),
)
def test_r_n3_a_resolver_restart_on_the_same_address_keeps_port_53_served(
    environment: Any,
) -> None:
    kernel = Kernel()
    site = with_kernel(environment, kernel)
    approve_all(site)
    observed_pass(site)
    precondition(port_53(kernel.rules) == DIRECT, "the direct form is loaded")
    site[4].append(restarted(site[1], site[4][-1], "resolver", "instance-2"))

    result, report = observed_pass(site)
    after = port_53(kernel.rules)
    records = site[0].read("live.json")["records"]
    following, _ = observed_pass(site)

    assert after == DIRECT, (
        "a restart of the resolver with the same address, link address, definition and network "
        f"leaves port 53 with {after} ({result['phase']}, {result['changed']}); the next pass "
        f"changes {following['changed']}"
    )
    assert {key: records[key]["target_generation"] for key in DNS} == dict.fromkeys(
        DNS, "instance-2"
    )
    assert set(DNS) <= set(ready(report))


# ---- R-N4: a state listing that runs over its time limit or its output bound


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "readiness R-N4: a state listing over its time or output bound retires the rules that "
        "need the table; a host redirect follows a plan that needs none"
    ),
)
@pytest.mark.parametrize("limit", LIMITS, ids=["too slow", "too large"])
@pytest.mark.parametrize("read", [1, 2], ids=["first read", "final read"])
def test_r_n4_a_listing_over_its_bound_leaves_host_redirects_to_their_own_plan(
    environment: Any, read: int, limit: str
) -> None:
    kernel = Unreadable(limit)
    site = fallback_site(environment, kernel)
    # A pass that changes nothing reads the table twice: when it starts and in
    # its final readback.
    first = unreadable_pass(site, kernel, read)
    after_first = port_53(kernel.rules)
    # The web service is held, so the plan retires the web redirect, and the
    # listing runs over the same bound when the next pass starts.
    held = intent_from_dict(site[0].read("operator-intent.json"))
    site[0].write("operator-intent.json", intent_to_dict(held.hold("web-proxy", "work", "admin")))
    second = unreadable_pass(site, kernel, 1)
    after_second = port_53(kernel.rules)
    web_after_second = loaded(kernel, WEB)

    result, report = observed_pass(site)

    owed = site[0].read("journal.json")["phase"] == "failed"
    kept = after_first == FALLBACK and after_second == FALLBACK
    assert kept and not web_after_second and set(DNS) <= set(ready(report)), (
        f"a state listing {limit} at the {'first' if read == 1 else 'final'} read of a pass "
        f"{first} with port 53 at {after_first}; with the web service held, the next pass, "
        f"whose listing runs over the same bound when it starts, {second} with port 53 at "
        f"{after_second} and the web redirect {'loaded' if web_after_second else 'withdrawn'}; "
        f"the pass after it, with a readable table, ends {result['phase']}"
        f"{', owing the acknowledgement,' if owed else ''} with port 53 at "
        f"{port_53(kernel.rules)} and {ready(report)} ready"
    )


@pytest.mark.parametrize("limit", LIMITS, ids=["too slow", "too large"])
def test_r_n4_a_pause_withdraws_every_rule_also_while_the_state_table_cannot_be_read(
    environment: Any, limit: str
) -> None:
    """A guard that passes today, and that the change proposed for R-N4 must keep.

    Under that change a host redirect outlasts a listing over its bound only
    where its own plan keeps it. An operator pause retires every rule, so a pass
    that is paused withdraws every rule, host redirects included, whether or not
    the state table can be read.
    """
    kernel = Unreadable(limit)
    site = fallback_site(environment, kernel)
    paused = intent_from_dict(site[0].read("operator-intent.json")).pause()
    site[0].write("operator-intent.json", intent_to_dict(paused))

    ended = unreadable_pass(site, kernel, 1)

    left = sorted({line.partition(" # netorch:")[2] for line in kernel.rules.splitlines()})
    assert kernel.rules == "", f"a paused pass whose listing is {limit} {ended}, leaving {left}"


# ---- R-N8: the platform's own DNS listener appears after the activation


class Listening(Kernel):
    """The fake kernel with the owner's own host-socket check over its socket inventory."""

    def ports_clear(self, scope: Scope, profile: Profile, *, apple_dns: bool) -> bool:
        self.commands.append(("ports", profile.id))
        return ShellBackend.ports_clear(self, scope, profile, apple_dns=apple_dns)  # type: ignore[arg-type]


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "readiness R-N8: every pass that leaves a port-53 rule loaded repeats the host-socket "
        "check, and a listener that appeared ends the rule's readiness"
    ),
)
def test_r_n8_a_listener_that_appears_on_port_53_ends_the_readiness_of_the_dns_rules(
    environment: Any,
) -> None:
    kernel = Listening()
    site = with_kernel(environment, kernel)
    approve_all(site)
    result, report = observed_pass(site)
    precondition(
        result["phase"] == "committed" and ready(report) == sorted([*DNS, *OTHERS]),
        "every profile is loaded and ready, its host ports checked at its activation",
    )
    # The platform's own DNS listener starts on the host's port 53, on every
    # address. The installation did not admit the platform's DNS exception.
    for protocol in ("tcp", "udp"):
        kernel.sockets[protocol].append(("*", 53, 4242, "mDNSResponder", "IPv4"))
    kernel.commands.clear()

    result, report = observed_pass(site)

    checks = [command for command in kernel.commands if command[0] == "ports"]
    named = ready(report)
    assert not set(DNS) & set(named), (
        f"the pass after a listener appeared on the host's port 53 ends {result['phase']}, "
        f"reports {named} ready and runs the host-socket check {len(checks)} times"
    )
    assert named == OTHERS

"""Readiness flags of the UDP return pair: R-U1, R-U2, R-U3, R-U4 and R-U7.

Each test states a proposed behaviour of the root PF owner and is a strict
expected failure on the commit it was written against. The record
docs/reviews/2026-10-09-readiness-udp-return.md gives each finding, the proposed
change and the acceptance that would close it. `--runxfail` shows today's
behaviour in the assertion message. Once a change is implemented its test
passes, the strict marker turns that into a failure, and the marker is removed.
R-U5 and R-U6 have no test; the record says why.

Only an assertion about the finding raises `AssertionError`. A set-up step that
does not hold, a consistency check inside a fake, and a proposed decision that
the installation refuses for another reason than not knowing it fail the test
through `pytest.fail`, so that none of them can count as the expected failure.

Where the record proposes an installation decision, the test writes it through
`decided`. The commit the tests were written against has none of these
decisions, and its installation refuses a key it does not know; the test then
runs with the default installation, whose behaviour is the one the record flags.

Every kernel and runtime tool is a fake from the existing suites. Addresses are
documentation values and link-local constants, ports are synthetic. Nothing
here shows what a macOS kernel prints or what its invalidation removes.
"""

from __future__ import annotations

import contextlib
import dataclasses
from collections.abc import Iterator
from typing import Any

import pytest

from netorch.config import to_dict, validate_config
from netorch.pf_owner import Installation, PFError, state_rows
from netorch.state import Observation, Snapshot
from tests.test_pf_deferral import observed_pass
from tests.test_pf_own_states import Kernel
from tests.test_pf_owner import STAMP, FakeBackend, approve_all, environment, run_pass
from tests.test_pf_withdraw_order import LiveKernel, active, owned

__all__ = ["environment"]

HOST = "192.0.2.10"
RECEIVER = "192.0.2.77"
ROUTER = "192.0.2.1"
OUTSIDE = "203.0.113.5"
# The media guest's address, and the ones it holds after a first and a second restart.
MEDIA = "198.51.100.12"
MOVED = "198.51.100.14"
MOVED_AGAIN = "198.51.100.16"
# A state of the pair: a flow of the media guest to a LAN receiver through the
# static-port rule, with the same port on the guest and on the host.
PAIR_STATE = f"ALL udp {MEDIA}:45001 -> {HOST}:45001 -> {RECEIVER}:7000 SINGLE:MULTIPLE"
# Connections the media guest opens itself, through the vendor's translation.
OWN_OUTSIDE = f"ALL tcp {MEDIA}:51000 -> {HOST}:61001 -> {OUTSIDE}:443 ESTABLISHED:ESTABLISHED"
OWN_RECEIVER = f"ALL tcp {MEDIA}:45010 -> {HOST}:61002 -> {RECEIVER}:7000 ESTABLISHED:ESTABLISHED"
# Another guest that now holds the old address: a flow from a port inside the
# pair's range to a LAN host, through the vendor's translation to another host port.
TENANT = f"ALL udp {MEDIA}:45100 -> {HOST}:61000 -> {ROUTER}:53 SINGLE:MULTIPLE"
# A row that the pair itself can make at the address it held: the same flow
# shape, with the same port on the guest and on the host.
CONTROL = f"ALL udp {MOVED}:45002 -> {HOST}:45002 -> {ROUTER}:53 SINGLE:MULTIPLE"
# A state of an IPv6 link-local flow whose addresses carry their zone, an interface name.
ZONED = "ALL udp fe80::1%example0[5353] -> fe80::2%example0[5353] SINGLE:NO_TRAFFIC"


@contextlib.contextmanager
def setting_up(step: str) -> Iterator[None]:
    """A step that is not the finding: an `AssertionError` in it fails the test outright."""
    try:
        yield
    except AssertionError as error:
        pytest.fail(f"not the finding: {step} does not hold: {error}")


class Checked:
    """The suites' fakes, with their own consistency checks failing the test outright."""

    def replace(self, expected: str, candidate: str) -> str:
        with setting_up("the fake kernel's check of a rule load"):
            return super().replace(expected, candidate)  # type: ignore[misc, no-any-return]

    def call(self, operation: str, *arguments: str) -> str:
        with setting_up("the fake kernel's check of a backend call"):
            return super().call(operation, *arguments)  # type: ignore[misc, no-any-return]


class Fake(Checked, FakeBackend):
    """`FakeBackend` of tests/test_pf_owner.py."""


class Live(Checked, LiveKernel):
    """`LiveKernel` of tests/test_pf_withdraw_order.py: the owner's own drain, counted."""


class Lasting(Checked, Kernel):
    """`Kernel` of tests/test_pf_own_states.py: rows listed again after every invalidation."""


def using(environment: Any, backend: Any) -> Any:
    root, config, settings, _, snapshots = environment
    return root, config, settings, backend, snapshots


def activated(environment: Any, backend: Any) -> Any:
    """Every profile admitted and loaded by one committed pass (`active` of the suites)."""
    with setting_up("the activation of every profile"):
        return active(environment, backend)


def decided(environment: Any, **decision: str) -> Any:
    """The environment with an installation decision that the record proposes.

    Written where the installation accepts it, before any admission, so that
    every profile is admitted under it. Where the installation does not know the
    decision, it refuses the key as an unsupported schema; nothing is written
    and the default installation is measured. Any other refusal fails the test.
    """
    root, config, settings, backend, snapshots = environment
    stored = root.read("installation.json")
    try:
        Installation.from_dict(stored)
    except PFError as refused:
        pytest.fail(f"not the finding: the stored installation is refused: {refused}")
    known = {field.name for field in dataclasses.fields(Installation)}
    try:
        settings = Installation.from_dict({**stored, **decision})
    except PFError as refused:
        if known.isdisjoint(decision) and str(refused) == "unsupported installation schema":
            return environment
        pytest.fail(f"not the finding: the installation refuses {decision}: {refused}")
    root.write("installation.json", {**stored, **decision})
    return root, config, settings, backend, snapshots


def tolerating(environment: Any, key: str, passes: int) -> Any:
    """The policy with another `unknown_limit` (K) for one profile, before any admission."""
    root, config, settings, backend, snapshots = environment
    profiles = tuple(
        dataclasses.replace(item, safety=dataclasses.replace(item.safety, unknown_limit=passes))
        if item.id == key
        else item
        for item in config.profiles
    )
    updated = dataclasses.replace(config, profiles=profiles)
    validate_config(updated)
    root.write("policy.json", to_dict(updated))
    return root, updated, settings, backend, snapshots


def observe(environment: Any, service: str, observation: Observation) -> None:
    """The next snapshot of the runtime, with one service observed as given."""
    snapshots = environment[4]
    current = snapshots[-1]
    services = {**current.services, service: observation}
    snapshots.append(Snapshot(STAMP, current.network_generation, services, current.profiles))


def restarted(environment: Any, address: str, generation: str) -> Observation:
    """The media guest as the runtime reports it after a restart at another address."""
    media = environment[4][-1].services["media-controller"]
    return Observation("present", "verified", STAMP, generation, {**media.data, "ipv4": address})


def pair_target(backend: Any) -> str | None:
    """The guest address of the loaded pair's outbound translation, or None."""
    for line in backend.rules.splitlines():
        words = line.split()
        if words[:1] == ["nat"] and line.endswith("# netorch:media-udp"):
            return words[7]
    return None


def media(result: dict[str, Any], backend: Any) -> tuple[str, str | None, str | None]:
    """One pass as the trace of a test shows it: phase, deferral of the pair, its target."""
    return result["phase"], result.get("deferred", {}).get("media-udp"), pair_target(backend)


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "readiness R-U1: where the installation decides so, missing runtime evidence withdraws "
        "the pair at once and invalidates its states only on the K-th pass without evidence"
    ),
)
def test_r_u1_a_read_that_timed_out_withdraws_the_pair_and_invalidates_no_state(
    environment: Any,
) -> None:
    # K = 2 for the pair: the second pass in a row without evidence invalidates.
    environment = tolerating(environment, "media-udp", 2)
    environment = activated(decided(environment, drain_on_unknown="defer"), Live(set()))
    backend = environment[3]
    table = [PAIR_STATE, OWN_OUTSIDE, OWN_RECEIVER]
    backend.flow_states = "\n".join(table)
    evidence = environment[4][-1]
    timed_out = Observation("unknown", "timed-out", STAMP, None)
    observe(environment, "media-controller", timed_out)

    result, _ = observed_pass(environment)

    left = backend.flow_states.splitlines()
    assert pair_target(backend) is None and backend.kills == [] and left == table, (
        "one runtime read that timed out retired the pair and invalidated the states from and "
        f"to the guest's address: changed {result['changed']}, addresses invalidated "
        f"{backend.kills}, states left {left}"
    )

    # The next read answers for the same guest: the pair returns, its states unharmed.
    environment[4].append(evidence)
    result, _ = observed_pass(environment)

    left = backend.flow_states.splitlines()
    assert pair_target(backend) == MEDIA and backend.kills == [] and left == table, (
        f"evidence returned: changed {result['changed']}, invalidated {backend.kills}"
    )

    # The bound: two passes in a row without evidence. The first keeps the states,
    # the second, the K-th, invalidates them as today.
    observe(environment, "media-controller", timed_out)
    observed_pass(environment)
    first = list(backend.kills)
    observed_pass(environment)

    assert first == [] and backend.kills == [MEDIA], (
        f"no bound of K = 2 passes: invalidated after the first pass {first}, "
        f"after the second {backend.kills}"
    )


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "readiness R-U2: where the installation decides so, a failed invalidation owes the "
        "acknowledgement only for the profiles whose records name that address"
    ),
)
def test_r_u2_a_failed_invalidation_of_the_pair_leaves_the_other_services_loaded(
    environment: Any,
) -> None:
    environment = decided(environment, failed_invalidation="hold-address")
    environment = activated(environment, Fake())
    root, _, _, backend, _ = environment
    backend.flow_states = PAIR_STATE
    # The media guest restarts at another address, and the invalidation of its
    # old address fails once. Whether that pass raises is not prescribed here.
    observe(environment, "media-controller", restarted(environment, MOVED, "instance-2"))
    backend.undrainable = True
    with contextlib.suppress(PFError):
        run_pass(environment)
    if pair_target(backend) is not None or ("drain", MEDIA) not in backend.commands:
        pytest.fail("not the finding: the failing invalidation of the old address was not reached")
    failed = root.read("journal.json")["phase"]
    backend.undrainable = False

    trace = []
    for _ in range(3):
        result, _ = observed_pass(environment)
        trace.append((result["phase"], owned(backend)))

    others = ["dns-tcp", "dns-udp", "proxy-standard"]
    assert all(rules == others for _, rules in trace), (
        f"one failed invalidation of the pair's old address (journal {failed}), then three "
        f"passes whose reads all work, (phase, rules loaded): {trace}"
    )


@pytest.mark.parametrize(
    "check",
    [
        pytest.param("host socket", id="host-socket"),
        pytest.param("route or neighbour entry", id="route-arp"),
    ],
)
@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "readiness R-U3: where the installation decides so, re-check a loaded pair on every "
        "pass: withhold it for a host socket in its range, retire it for a failing route/ARP"
    ),
)
def test_r_u3_a_loaded_pair_is_not_ready_once_a_check_of_its_activation_fails(
    environment: Any, check: str
) -> None:
    environment = using(decided(environment, loaded_checks="every-pass"), Fake())
    approve_all(environment)
    backend = environment[3]
    first, report = observed_pass(environment)
    if (
        first["phase"] != "committed"
        or pair_target(backend) != MEDIA
        or report.profiles["media-udp"].data["root_ready"] is not True
    ):
        pytest.fail("not the finding: the pair was not loaded for its guest and ready at first")
    backend.flow_states = PAIR_STATE
    if check == "host socket":
        # A host socket now listens on a port inside the pair's range.
        backend.clear = False
    else:
        # The guest's address no longer has a verified route and neighbour entry.
        backend.unavailable_guests = {MEDIA}

    result, report = observed_pass(environment)

    data = report.profiles["media-udp"].data
    if check == "host socket":
        # Withheld: the rules and the state stay, the pair is not ready.
        outcome = (
            pair_target(backend) == MEDIA
            and PAIR_STATE in backend.flow_states
            and data.get("withheld") == "ports-unverified"
        )
    else:
        # Retired: the rules are withdrawn and the state invalidated.
        outcome = (
            pair_target(backend) is None
            and PAIR_STATE not in backend.flow_states
            and data.get("deferred") == "endpoint-unverified"
        )
    assert outcome and data["root_ready"] is False, (
        f"a failing {check} after the activation: the pass ended {result['phase']}, the pair is "
        f"loaded for {pair_target(backend)} and root_ready is {data['root_ready']} "
        f"(withheld {data.get('withheld')}, deferred {data.get('deferred')})"
    )


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "readiness R-U4: count a row for the pair only where it names the host address with the "
        "target's port, so the pair follows its guest and the old address is invalidated once"
    ),
)
def test_r_u4_the_pair_follows_its_guest_while_another_guest_holds_the_old_address(
    environment: Any,
) -> None:
    environment = activated(environment, Lasting())
    backend = environment[3]
    backend.flow_states = PAIR_STATE
    # The media guest restarts at another address. Another guest is given the
    # old one and keeps its flow, which is listed again after every invalidation.
    observe(environment, "media-controller", restarted(environment, MOVED, "instance-2"))
    backend.lasting.append(TENANT)

    trace = [media(observed_pass(environment)[0], backend) for _ in range(3)]

    invalidated = backend.kills.count(MEDIA)
    assert [target for *_, target in trace][1:] == [MOVED, MOVED] and invalidated <= 1, (
        f"the guest moved and another guest keeps a flow on the old address: passes "
        f"(phase, media deferral, pair target) {trace}; old address invalidated {invalidated} times"
    )

    # Control: the guest moves again, and a row that the pair itself can make is
    # listed again at the address it leaves. That row must hold the pair back.
    observe(environment, "media-controller", restarted(environment, MOVED_AGAIN, "instance-3"))
    backend.lasting.append(CONTROL)

    control = [media(observed_pass(environment)[0], backend) for _ in range(3)]

    assert all(target is None for *_, target in control), (
        f"a row the pair itself can make is listed again at the address it left, and the pair "
        f"followed anyway: passes (phase, media deferral, pair target) {control}"
    )


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "readiness R-U7: read a zoned link-local IPv6 endpoint as foreign and use the rest of "
        "the state table"
    ),
)
def test_r_u7_a_zoned_link_local_row_is_foreign_and_the_rest_of_the_table_is_read(
    environment: Any,
) -> None:
    environment = activated(environment, Fake())
    root, _, _, backend, _ = environment
    try:
        state_rows(PAIR_STATE)
    except PFError as refused:
        pytest.fail(f"not the finding: the pair's own row is refused: {refused}")
    backend.flow_states = f"{ZONED}\n{PAIR_STATE}"
    try:
        read: object = [row.endpoints for row in state_rows(backend.flow_states)]
    except PFError as refused:
        read = f"PFError: {refused}"

    result, report = observed_pass(environment)

    pair = ((MEDIA, 45001), (HOST, 45001), (RECEIVER, 7000))
    states = report.profiles["media-udp"].data.get("states")
    assert read == [(), pair] and result["phase"] == "committed" and states == ("retained",), (
        f"one row whose addresses carry a zone: the reader answered {read}; the pass ended "
        f"{result['phase']} with reason {root.read('journal.json').get('reason')}, "
        f"changed {result['changed']}, rules loaded {owned(backend)}"
    )

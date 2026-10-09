"""What a drain ends: every state of the retired target's address, at that moment.

The backend's two invalidations name the address alone (`pfctl -k <target>` and
`pfctl -k 0.0.0.0/0 -k <target>`, proved for the script in
`test_pf_backend_script.py`). `LiveKernel` removes every row that names the
drained address, which for the states these rules make and for the guest's own
connections through the runtime's translation is what those two invalidations
end, and its drain runs through the owner's own `ShellBackend.drain`. So a
retirement that finds a retained state of its rules ends the guest's own
connections as well; one that finds none ends nothing. The cause of the
retirement does not matter: here it is a runtime read that timed out. A pass
whose state table cannot be read invalidates every remembered guest address
without reading the table.
"""

from __future__ import annotations

from typing import Any

from netorch.pf_owner import PFError, reconcile
from netorch.state import Observation, Snapshot
from tests.test_pf_owner import STAMP, approve_all, environment, run_pass
from tests.test_pf_withdraw_order import LiveKernel

__all__ = ["environment"]

HOST = "192.0.2.10"
RESOLVER = "198.51.100.10"  # the `resolver` guest, the target of both DNS profiles
GUEST = "198.51.100.12"  # the `media-controller` guest, the target of the UDP return pair
RECEIVER = "192.0.2.77"
OUTSIDE = "203.0.113.5"
# A state of the pair: the guest's datagram from a port of the range to a LAN receiver.
PAIR_STATE = f"ALL udp {GUEST}:45001 -> {HOST}:45001 -> {RECEIVER}:7000 SINGLE:MULTIPLE"
# The guest's own connections, which are not states of the owner's rules.
OWN_OUTSIDE = f"ALL tcp {GUEST}:51000 -> {HOST}:51000 -> {OUTSIDE}:443 ESTABLISHED:ESTABLISHED"
OWN_RECEIVER = f"ALL tcp {GUEST}:45010 -> {HOST}:62000 -> {RECEIVER}:7000 ESTABLISHED:ESTABLISHED"


def pair_rules(backend: LiveKernel) -> list[str]:
    return [line for line in backend.rules.splitlines() if "# netorch:media-udp" in line]


def loaded(environment: Any, kernel: LiveKernel) -> Any:
    root, config, settings, _, snapshots = environment
    environment = (root, config, settings, kernel, snapshots)
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    assert len(pair_rules(kernel)) == 2
    return environment


def read_timed_out(environment: Any) -> None:
    snapshots = environment[4]
    current = snapshots[-1]
    services = dict(current.services)
    services["media-controller"] = Observation("unknown", "timed-out", STAMP, None)
    snapshots.append(Snapshot(STAMP, current.network_generation, services, current.profiles))


def one_pass(environment: Any) -> dict[str, Any]:
    root, _, _, backend, snapshots = environment
    return reconcile(
        root,
        lambda config, settings: snapshots[-1],
        lambda root, settings: backend,
        now=lambda: STAMP,
        report=lambda settings, snapshot: None,
    )


def test_a_retirement_that_finds_a_retained_state_ends_every_state_of_the_address(
    environment: Any,
) -> None:
    kernel = LiveKernel(set())
    environment = loaded(environment, kernel)
    kernel.flow_states = "\n".join((PAIR_STATE, OWN_OUTSIDE, OWN_RECEIVER))
    read_timed_out(environment)

    result = one_pass(environment)

    assert result["changed"] == ["media-udp:withdraw", "media-udp:drain"]
    assert pair_rules(kernel) == []
    assert kernel.kills == [GUEST]
    # The invalidation is by address: the guest's own connections, to a host
    # outside the LAN and to the receiver, end with the state of the pair.
    assert kernel.flow_states == ""


def test_a_retirement_that_finds_no_retained_state_leaves_the_guest_connections(
    environment: Any,
) -> None:
    kernel = LiveKernel(set())
    environment = loaded(environment, kernel)
    kernel.flow_states = "\n".join((OWN_OUTSIDE, OWN_RECEIVER))
    read_timed_out(environment)

    result = one_pass(environment)

    assert result["changed"] == ["media-udp:withdraw", "media-udp:drain"]
    assert pair_rules(kernel) == []
    assert kernel.kills == []
    assert kernel.flow_states.splitlines() == [OWN_OUTSIDE, OWN_RECEIVER]


def test_each_pass_of_a_retirement_that_stays_states_retained_invalidates_the_address(
    environment: Any,
) -> None:
    # The guest keeps an ordinary outbound connection, opened again after each
    # invalidation, and a LAN receiver's state of the pair survives it.
    kernel = LiveKernel({GUEST}, held={GUEST: 45001})
    environment = loaded(environment, kernel)
    read_timed_out(environment)

    first = one_pass(environment)
    second = one_pass(environment)

    assert first["deferred"] == {"media-udp": "states-retained"}
    assert second["deferred"] == {"media-udp": "states-retained"}
    # One invalidation of the whole address on each pass: each of them ends
    # the guest's other connections again.
    assert kernel.kills == [GUEST, GUEST]


class Unreadable(LiveKernel):
    """A kernel whose state table cannot be read once `unreadable` is set."""

    unreadable = False

    def states(self) -> str:
        if self.unreadable:
            raise PFError("state table cannot be read")
        return super().states()


def test_a_pass_whose_state_table_cannot_be_read_invalidates_every_guest_address(
    environment: Any,
) -> None:
    kernel = Unreadable(set())
    environment = loaded(environment, kernel)
    resolver_own = f"ALL udp {RESOLVER}:51001 -> {HOST}:51001 -> {OUTSIDE}:53 MULTIPLE:SINGLE"
    kernel.flow_states = "\n".join((OWN_OUTSIDE, resolver_own))
    kernel.unreadable = True

    first = run_pass(environment)

    assert first["phase"] == "failed"
    # No retained state could be looked for: every remembered record that is
    # not a host redirect has its address invalidated (the two DNS profiles
    # name the resolver), and both guests' own connections end.
    assert kernel.kills == [RESOLVER, RESOLVER, GUEST]
    assert kernel.flow_states == ""
    assert environment[0].read("journal.json")["reason"] == "kernel-state-unknown"

    kernel.flow_states = "\n".join((OWN_OUTSIDE, resolver_own))
    second = run_pass(environment)

    assert second["phase"] == "failed"
    assert kernel.kills == [RESOLVER, RESOLVER, GUEST] * 2
    assert kernel.flow_states == ""

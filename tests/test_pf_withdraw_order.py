"""The periodic pass retires every rule before it invalidates any state."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from netorch.pf_owner import PFError, ShellBackend, state_addresses
from netorch.state import Intent, Observation, Snapshot, intent_to_dict
from tests.test_pf_owner import STAMP, FakeBackend, approve_all, environment, run_pass

__all__ = ["environment"]

REMAIN = "scoped PF states remain"


class LiveKernel(FakeBackend):
    """Fake rules and states, with the owner's own drain.

    A guest in `live_guests` keeps one ordinary outbound connection, so a new
    state row naming its address exists again right after its states are killed.
    With `clients`, a LAN client keeps using every redirect that is still loaded.
    A guest in `held` has a LAN client whose state, to the given port of the
    guest, is not removed by an invalidation: a state of the owner's rule.
    """

    def __init__(
        self, live_guests: set[str], *, clients: bool = False, held: dict[str, int] | None = None
    ) -> None:
        super().__init__()
        self.live_guests = live_guests
        self.clients = clients
        self.held = held or {}
        self.kills: list[str] = []
        self.shell = object.__new__(ShellBackend)
        self.shell._call = self.call  # type: ignore[method-assign]

    def call(self, operation: str, *arguments: str) -> str:
        if operation == "states":
            return self.states()
        assert operation == "drain"
        self.kills.append(arguments[0])
        self.flow_states = "\n".join(
            line
            for line, addresses in state_addresses(self.flow_states)
            if arguments[0] not in addresses
        )
        return ""

    def states(self) -> str:
        rows = [line for line in self.flow_states.splitlines() if line.strip()]
        rows += [
            f"all tcp {guest}:51000 -> 203.0.113.5:443 ESTABLISHED:ESTABLISHED"
            for guest in sorted(self.live_guests)
        ]
        rows += [
            f"all udp 192.0.2.78:54321 -> {guest}:{port} NO_TRAFFIC:SINGLE"
            for guest, port in sorted(self.held.items())
        ]
        if self.clients:
            for rule in self.rules.splitlines():
                words = rule.split("#", 1)[0].split()
                if words[:1] == ["rdr"] and words[words.index("->") + 1].startswith("198.51.100."):
                    target = words[words.index("->") + 1]
                    rows.append(f"all udp 192.0.2.77:54321 -> {target}:53 NO_TRAFFIC:SINGLE")
        return "\n".join(rows)

    def drain(self, ipv4: str) -> None:
        self.commands.append(("drain", ipv4))
        self.shell.drain(ipv4)


def owned(backend: FakeBackend) -> list[str]:
    return sorted(line.split("# netorch:")[1] for line in backend.rules.splitlines() if line)


def active(environment: Any, backend: LiveKernel) -> Any:
    root, config, settings, _, snapshots = environment
    environment = (root, config, settings, backend, snapshots)
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    assert owned(backend) == ["dns-tcp", "dns-udp", "media-udp", "media-udp", "proxy-standard"]
    return environment


def address(environment: Any, service: str) -> str:
    return str(environment[4][-1].services[service].data["ipv4"])


def test_pause_retires_every_rule_although_one_state_readback_fails(environment: Any) -> None:
    resolver = address(environment, "resolver")
    # The resolver guest is simply still running; its own connection is not a
    # state of a rule. One client's state of its DNS rule survives invalidation.
    backend = LiveKernel({resolver}, held={resolver: 53})
    environment = active(environment, backend)
    root = environment[0]
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))

    result = run_pass(environment)

    assert result["deferred"] == {"dns-udp": "states-retained"}
    assert owned(backend) == []
    assert root.read("journal.json")["phase"] == "inhibited"
    operations = [item["operation"] for item in root.read("journal.json")["actions"]]
    first_drain = operations.index("drain")
    assert "withdraw" not in operations[first_drain:]
    assert operations.count("withdraw") == 4


def test_unknown_runtime_identity_retires_every_rule_in_the_same_pass(environment: Any) -> None:
    resolver = address(environment, "resolver")
    backend = LiveKernel({resolver}, held={resolver: 53})
    environment = active(environment, backend)
    snapshots = environment[4]
    snapshots.append(
        Snapshot(
            STAMP,
            None,
            {
                key: Observation("unknown", "inaccessible", STAMP, None)
                for key in snapshots[0].services
            },
            {},
        )
    )

    result = run_pass(environment)

    assert result["deferred"] == {"dns-udp": "states-retained"}
    assert owned(backend) == []


def test_sibling_rule_no_longer_refills_the_states_of_a_restarted_guest(environment: Any) -> None:
    backend = LiveKernel(set(), clients=True)
    environment = active(environment, backend)
    root, _, _, _, snapshots = environment
    old = address(environment, "resolver")
    current = snapshots[-1]
    services = dict(current.services)
    services["resolver"] = Observation(
        "present",
        "verified",
        STAMP,
        "instance-2",
        {**current.services["resolver"].data, "ipv4": "198.51.100.50"},
    )
    snapshots.append(replace(current, services=services))
    # The state a client made through the UDP rule before the restart is still
    # in the table; it is the only state of a retired rule.
    backend.flow_states = f"all udp 192.0.2.77:54321 -> {old}:53 NO_TRAFFIC:SINGLE"

    # Both rules to the old address go first, so no client can create a new
    # state for it while the first profile is drained. The pass completes.
    assert run_pass(environment)["phase"] != "failed"
    assert old not in backend.rules
    assert backend.kills.count(old) == 1

    # The next pass serves the restarted guest at its new address.
    assert run_pass(environment)["phase"] == "committed"
    assert backend.rules.count("-> 198.51.100.50 port 53") == 2
    assert root.read("journal.json")["phase"] == "committed"


def test_stale_rule_of_a_later_profile_goes_although_an_earlier_drain_fails(
    environment: Any,
) -> None:
    backend = LiveKernel(set())
    environment = active(environment, backend)
    root, config, _, _, snapshots = environment
    media = address(environment, "media-controller")
    # The media controller moves away and an unrelated running guest now holds
    # its former address. The network generation changes for every profile.
    current = snapshots[-1]
    moved = {"media-controller": "198.51.100.77", "camera": media}
    services = {
        key: Observation(
            "present",
            "verified",
            STAMP,
            "instance-2",
            {**value.data, "ipv4": moved.get(key, value.data["ipv4"])},
        )
        for key, value in current.services.items()
    }
    publications = {
        key: Observation(
            value.state,
            value.reason,
            STAMP,
            "instance-2",
            {
                **value.data,
                "target_ipv4": services[config.profile(key).service].data["ipv4"],
                "target_generation": "instance-2",
                "network_generation": "network-2",
            },
        )
        for key, value in current.profiles.items()
    }
    snapshots.append(Snapshot(STAMP, "network-2", services, publications))
    backend.live_guests = {media}
    # A LAN receiver's return flow to the old address survives the invalidation.
    backend.held = {media: 45001}

    result = run_pass(environment)

    # `proxy-standard` sorts after the profile whose drain fails; it is gone.
    assert result["deferred"] == {"media-udp": "states-retained"}
    assert owned(backend) == []
    assert root.read("journal.json")["phase"] == "inhibited"


def test_drains_and_activations_keep_their_planned_order(environment: Any) -> None:
    backend = LiveKernel(set())
    environment = active(environment, backend)
    root, _, _, _, snapshots = environment
    current = snapshots[-1]
    services = dict(current.services)
    services["resolver"] = Observation(
        "present",
        "verified",
        STAMP,
        "instance-2",
        {**current.services["resolver"].data, "ipv4": "198.51.100.50"},
    )
    snapshots.append(replace(current, services=services))

    result = run_pass(environment)

    assert result["changed"] == [
        "dns-tcp:withdraw",
        "dns-udp:withdraw",
        "dns-tcp:drain",
        "dns-udp:drain",
    ]
    assert owned(backend) == ["media-udp", "media-udp", "proxy-standard"]
    planned = [
        (item["profile"], item["operation"]) for item in root.read("journal.json")["actions"]
    ]
    rest = [item for item in planned if item[1] != "withdraw"]
    assert rest == sorted(rest, key=lambda item: item[0])


@pytest.mark.parametrize("withdrawal", range(1, 5))
@pytest.mark.parametrize("boundary", ["before-replace", "after-replace", "after-live-write"])
def test_interrupted_withdrawal_retries_retirement_before_a_failing_drain(
    environment: Any, monkeypatch: Any, withdrawal: int, boundary: str
) -> None:
    resolver = address(environment, "resolver")
    backend = LiveKernel({resolver}, held={resolver: 53})
    environment = active(environment, backend)
    root = environment[0]
    admissions = root.read("admissions.json")
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    original_replace = backend.replace
    original_write = root.write
    replacements = 0
    fired = False

    def inject(point: str) -> None:
        nonlocal fired
        if not fired and replacements == withdrawal and boundary == point:
            fired = True
            raise PFError("interrupted withdrawal")

    def replace_rules(expected: str, candidate: str) -> str:
        nonlocal replacements
        replacements += 1
        inject("before-replace")
        result = original_replace(expected, candidate)
        inject("after-replace")
        return result

    def write(name: str, value: Any) -> None:
        original_write(name, value)
        if name == "live.json":
            inject("after-live-write")

    monkeypatch.setattr(backend, "replace", replace_rules)
    monkeypatch.setattr(root, "write", write)
    backend.commands.clear()
    with pytest.raises(PFError, match="interrupted withdrawal"):
        run_pass(environment)
    assert fired
    # Retrying is still inhibited by the failed journal. It must identify either
    # the old or candidate kernel state, retire every remaining rule and only
    # then reach the drain that a client's surviving state keeps open.
    result = run_pass(environment)
    assert result["phase"] == "failed"
    assert result["deferred"] == {"dns-udp": "states-retained"}
    assert owned(backend) == []
    assert all(not item["active"] for item in root.read("live.json")["records"].values())
    assert root.read("journal.json")["phase"] == "failed"
    assert root.read("operator-intent.json")["operator_paused"] is True
    assert root.read("admissions.json") == admissions
    first_drain = next(i for i, command in enumerate(backend.commands) if command[0] == "drain")
    assert not any(command[0] == "replace" for command in backend.commands[first_drain:])


def test_cleared_drain_does_not_acknowledge_a_failed_generation_change(environment: Any) -> None:
    resolver = address(environment, "resolver")
    backend = LiveKernel({resolver}, held={resolver: 53})
    environment = active(environment, backend)
    root, _, _, _, snapshots = environment
    # No operator pause: a generation change alone requires retirement.
    snapshots.append(replace(snapshots[-1], network_generation="network-2"))
    # A drain that stays open is not a failure. The retirement fails here
    # because its first withdrawal is a write in doubt.
    backend.fail_after_replace = True
    with pytest.raises(PFError, match="interrupted write"):
        run_pass(environment)
    assert run_pass(environment)["deferred"] == {"dns-udp": "states-retained"}
    assert not owned(backend)
    backend.held.clear()
    backend.live_guests.clear()
    backend.commands.clear()
    for _ in range(2):
        assert run_pass(environment)["phase"] == "failed"
        assert not owned(backend)
    assert root.read("journal.json")["phase"] == "failed"
    assert not root.read("operator-intent.json")["operator_paused"]
    assert not any(command[0] == "reference" for command in backend.commands)

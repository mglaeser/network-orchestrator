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
    """Fake rules and states, with the owner's own drain and its readback.

    A guest in `live_guests` keeps one ordinary outbound connection, so a new
    state row naming its address exists again right after its states are killed.
    With `clients`, a LAN client keeps using every redirect that is still loaded.
    """

    def __init__(self, live_guests: set[str], *, clients: bool = False) -> None:
        super().__init__()
        self.live_guests = live_guests
        self.clients = clients
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
    backend = LiveKernel({resolver})  # the resolver guest is simply still running
    environment = active(environment, backend)
    root = environment[0]
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))

    with pytest.raises(PFError, match=REMAIN):
        run_pass(environment)

    assert owned(backend) == []
    assert root.read("journal.json")["phase"] == "failed"
    operations = [item["operation"] for item in root.read("journal.json")["actions"]]
    first_drain = operations.index("drain")
    assert "withdraw" not in operations[first_drain:]
    assert operations.count("withdraw") == 4


def test_unknown_runtime_identity_retires_every_rule_in_the_same_pass(environment: Any) -> None:
    backend = LiveKernel({address(environment, "resolver")})
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

    with pytest.raises(PFError, match=REMAIN):
        run_pass(environment)

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

    # Both rules to the old address go first, so no client can create a new
    # state for it while the first profile is drained. The pass completes.
    assert run_pass(environment)["phase"] != "failed"
    assert old not in backend.rules
    assert backend.kills.count(old) == 2

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

    with pytest.raises(PFError, match=REMAIN):
        run_pass(environment)

    # `proxy-standard` sorts after the profile whose drain fails; it is gone.
    assert owned(backend) == []
    assert root.read("journal.json")["phase"] == "failed"


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

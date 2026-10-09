"""Offline native-format replay, distinct from native forwarding acceptance.

The fixtures retain provenance and explicit redactions. Test mutations below
are synthetic counterexamples, never relabelled as host captures. No native
tool, production owner, packet probe or playback is run by these tests.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

import netorch.pf_owner as implementation
from netorch.model import Scope
from netorch.pf_owner import PFError, ShellBackend
from netorch.process import Result
from tests.recorded import load_recording
from tests.test_pf_owner import environment, shell_backend

__all__ = ["environment"]

LAN = Scope("lan", "en0", "192.0.2.10", "192.0.2.0/24", "198.51.100.0/24")


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        (LAN, True),
        (replace(LAN, lan_cidr="192.0.2.0/25"), True),
        (replace(LAN, lan_cidr="192.0.0.0/16"), False),
        (replace(LAN, host_ipv4="192.0.2.11"), False),
    ],
    ids=["matching-prefix", "narrower-prefix", "overbroad-prefix", "wrong-host"],
)
def test_recorded_interface_does_not_authorize_a_larger_prefix_or_another_host(
    monkeypatch: pytest.MonkeyPatch, scope: Scope, expected: bool
) -> None:
    recording = load_recording("packet", "native-lan-interface")
    assert recording.returncode == 0 and recording.stderr == b""
    calls: list[list[str]] = []

    def native(argv: list[str]) -> str:
        calls.append(argv)
        assert argv == ["/sbin/ifconfig", "en0"]
        return recording.stdout.decode()

    backend = ShellBackend.__new__(ShellBackend)
    monkeypatch.setattr(backend, "_native", native)
    assert backend.endpoint(scope, scope.host_ipv4, None, direct=False) is expected
    assert calls == [["/sbin/ifconfig", "en0"]]


@pytest.mark.parametrize("protocol,expected_rows", [("tcp", 54), ("udp", 329)])
def test_complete_recorded_socket_table_is_parsed_and_dns_listener_is_not_assumed_safe(
    environment: Any,
    monkeypatch: pytest.MonkeyPatch,
    protocol: str,
    expected_rows: int,
) -> None:
    recording = load_recording("packet", f"native-sockets-{protocol}")
    assert recording.returncode == 0 and recording.stderr == b""
    backend = shell_backend(environment, monkeypatch)

    def native(argv: list[str]) -> str:
        assert argv == ["/usr/sbin/netstat", "-anlv", "-W", "-p", protocol]
        return recording.stdout.decode()

    monkeypatch.setattr(backend, "_native", native)
    inventory = backend.socket_inventory(protocol)
    assert len(inventory) == expected_rows
    dns = [row for row in inventory if row[1] == 53]
    assert {(row[0], row[3], row[4]) for row in dns} == {
        ("*", "mDNSResponder", "IPv4"),
        ("*", "mDNSResponder", "IPv6"),
    }
    config = environment[1]
    profile = config.profile(f"dns-{protocol}")
    assert backend.ports_clear(config.scope(profile.scope), profile, apple_dns=False) is False
    # A captured name/PID alone proves no signed process identity. This mocked
    # refusal is a synthetic boundary case layered on the recorded grammar.
    monkeypatch.setattr(backend, "_apple_dns_pid", lambda pid: False)
    assert backend.ports_clear(config.scope(profile.scope), profile, apple_dns=True) is False


def test_unavailable_native_pf_read_is_never_replayed_as_an_empty_state_table(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    recording = load_recording("packet", "native-pf-read-unavailable")
    assert recording.returncode == 1 and recording.stdout == b"" and recording.stderr
    backend = shell_backend(environment, monkeypatch)
    calls: list[list[str]] = []

    def failed_result(argv: list[str], **kwargs: Any) -> Result:
        calls.append(argv)
        return Result(recording.returncode, recording.stdout, recording.stderr)

    # The captured command failed at sudo authentication, before pfctl ran.
    # Injecting its nonzero result at the owner's tool boundary is a failure
    # simulation, not evidence about the backend's actual privileged context.
    monkeypatch.setattr(implementation, "run", failed_result)
    with pytest.raises(PFError, match="bounded PF backend operation failed") as caught:
        backend.states()
    assert len(calls) == 1 and calls[0][2] == "states"
    assert recording.stderr.decode().strip() not in str(caught.value)


def test_recorded_route_without_neighbour_does_not_establish_guest_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interface = load_recording("packet", "native-lan-interface")
    forwarding = load_recording("packet", "native-ipv4-forwarding")
    route = load_recording("packet", "native-guest-route")
    neighbour = load_recording("packet", "native-guest-neighbour-missing")
    target = "198.51.100.12"
    assert route.returncode == 0 and neighbour.returncode == 1
    calls: list[list[str]] = []
    responses = {
        ("/sbin/ifconfig", "en0"): Result(0, interface.stdout, interface.stderr),
        ("/usr/sbin/sysctl", "-n", "net.inet.ip.forwarding"): Result(
            forwarding.returncode, forwarding.stdout, forwarding.stderr
        ),
        ("/sbin/route", "-n", "get", "-inet", target): Result(
            route.returncode, route.stdout, route.stderr
        ),
        ("/usr/sbin/arp", "-n", target): Result(
            neighbour.returncode, neighbour.stdout, neighbour.stderr
        ),
    }

    def recorded(argv: list[str], **kwargs: Any) -> Result:
        calls.append(argv)
        return responses[tuple(argv)]

    monkeypatch.setattr(implementation, "run", recorded)
    backend = ShellBackend.__new__(ShellBackend)
    with pytest.raises(PFError, match="observation is unknown"):
        backend.endpoint(LAN, target, "02:00:00:00:00:12", direct=True)
    assert calls == [list(arguments) for arguments in responses]


@pytest.mark.parametrize("damage", ["missing-mask", "duplicate-interface", "noncontiguous-mask"])
def test_synthetic_damage_of_recorded_interface_cannot_prove_endpoint(
    monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    native = load_recording("packet", "native-lan-interface").stdout.decode()
    if damage == "missing-mask":
        altered = native.replace("netmask 0xffffff00", "")
    elif damage == "duplicate-interface":
        altered = native + native
    else:
        altered = native.replace("0xffffff00", "0xff00ff00")
    assert altered != native
    backend = ShellBackend.__new__(ShellBackend)
    monkeypatch.setattr(backend, "_native", lambda argv: altered)
    assert backend.endpoint(LAN, LAN.host_ipv4, None, direct=False) is False

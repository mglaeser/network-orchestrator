"""Loaded PF rules keep proving their endpoint and socket preconditions.

All native operations are fakes. The socket collision tests call the shipped
socket decision, but these are not packet-path or native qualification tests.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from netorch.model import Profile, Scope
from netorch.pf_owner import PFError, ShellBackend, _loaded_checks
from netorch.state import Observation, Snapshot
from tests.test_pf_deferral import observed_pass
from tests.test_pf_owner import FakeBackend, approve_all, environment

__all__ = ["environment"]

MEDIA = "198.51.100.12"
PAIR = "media-udp"
PAIR_STATE = f"ALL udp {MEDIA}:45001 -> 192.0.2.10:45001 -> 192.0.2.77:7000 SINGLE:MULTIPLE"


class Kernel(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.sockets: dict[str, list[tuple[str, int, int, str, str]]] = {"tcp": [], "udp": []}
        self.socket_errors: set[str] = set()
        self.endpoint_errors: set[str] = set()
        self.held = True

    def reference_held(self) -> bool:
        return self.held

    def socket_inventory(self, protocol: str) -> tuple[tuple[str, int, int, str, str], ...]:
        self.commands.append(("sockets", protocol))
        if protocol in self.socket_errors:
            raise PFError("socket read failed")
        return tuple(self.sockets[protocol])

    def ports_clear(self, scope: Scope, profile: Profile, *, apple_dns: bool) -> bool:
        return ShellBackend.ports_clear(self, scope, profile, apple_dns=apple_dns)  # type: ignore[arg-type]

    def endpoint(self, scope: Scope, ipv4: str, mac: Any, *, direct: bool) -> bool:
        if ipv4 in self.endpoint_errors:
            raise PFError("endpoint read failed")
        return super().endpoint(scope, ipv4, mac, direct=direct)


def activated(environment: Any, kernel: Kernel | None = None, *, reacquire: bool = False) -> Any:
    root, config, settings, _, snapshots = environment
    kernel = kernel or Kernel()
    if reacquire:
        settings = replace(settings, enable_reference="reacquire")
        root.write("installation.json", settings.to_dict())
    site = root, config, settings, kernel, snapshots
    approve_all(site)
    result, report = observed_pass(site)
    assert result["phase"] == "committed"
    assert all(item.data["root_ready"] for item in report.profiles.values())
    kernel.commands.clear()
    return site


@pytest.mark.parametrize("failure", ["mismatch", "read-error"])
def test_loaded_guest_endpoint_failure_withdraws_and_drains_only_that_service(
    environment: Any, failure: str
) -> None:
    site = activated(environment)
    kernel = site[3]
    kernel.flow_states = PAIR_STATE
    if failure == "mismatch":
        kernel.unavailable_guests.add(MEDIA)
    else:
        kernel.endpoint_errors.add(MEDIA)

    result, report = observed_pass(site)

    assert result["changed"] == [f"{PAIR}:withdraw", f"{PAIR}:drain"]
    assert result["deferred"] == {PAIR: "endpoint-unverified"}
    assert report.profiles[PAIR].state == "absent"
    assert report.profiles[PAIR].data["root_ready"] is False
    assert kernel.flow_states == ""
    assert ("drain", MEDIA) in kernel.commands
    assert all(item.data["root_ready"] for key, item in report.profiles.items() if key != PAIR)

    kernel.endpoint_errors.clear()
    kernel.unavailable_guests.clear()
    restored, _ = observed_pass(site)
    assert restored["changed"] == [f"{PAIR}:activate"]
    assert restored["phase"] == "committed"


@pytest.mark.parametrize(
    "protocol,port,affected", [("udp", 45001, {PAIR}), ("tcp", 53, {"dns-tcp"})]
)
def test_late_socket_collision_withholds_without_changing_rules_or_states(
    environment: Any, protocol: str, port: int, affected: set[str]
) -> None:
    site = activated(environment)
    kernel = site[3]
    rules = kernel.rules
    kernel.flow_states = PAIR_STATE
    kernel.sockets[protocol].append(("*", port, 321, "example-listener", "IPv4"))

    result, report = observed_pass(site)

    assert result["phase"] == "inhibited" and result["changed"] == []
    assert result["withheld"] == dict.fromkeys(affected, "ports-unverified")
    assert kernel.rules == rules and kernel.flow_states == PAIR_STATE
    assert not any(call[0] in {"drain", "replace", "reference"} for call in kernel.commands)
    for key, item in report.profiles.items():
        assert item.data["root_ready"] is (key not in affected)

    kernel.sockets[protocol].clear()
    recovered, _ = observed_pass(site)
    assert recovered["phase"] == "committed" and recovered["changed"] == []


def test_apple_dns_listener_is_not_assumed_admitted_after_activation(environment: Any) -> None:
    site = activated(environment)
    kernel = site[3]
    for protocol in ("tcp", "udp"):
        kernel.sockets[protocol].append(("*", 53, 321, "mDNSResponder", "IPv4"))

    result, report = observed_pass(site)

    assert result["withheld"] == dict.fromkeys(["dns-tcp", "dns-udp"], "ports-unverified")
    assert report.profiles[PAIR].data["root_ready"] is True
    assert report.profiles["proxy-standard"].data["root_ready"] is True


def test_failed_loaded_socket_read_never_reacquires_a_reference(environment: Any) -> None:
    site = activated(environment, reacquire=True)
    kernel = site[3]
    kernel.held = False
    kernel.socket_errors.add("udp")

    result, report = observed_pass(site)

    assert result["withheld"] == dict.fromkeys(["dns-udp", PAIR], "ports-unverified")
    assert "reference" not in result
    assert ("reference",) not in kernel.commands
    assert not any(item.data["root_ready"] for item in report.profiles.values())


def test_endpoint_failure_at_final_read_is_withheld_then_retired_next_pass(
    environment: Any,
) -> None:
    site = activated(environment)
    kernel = site[3]
    calls = 0

    def observe(config: Any, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        if calls == 2:
            kernel.unavailable_guests.add(MEDIA)
        return site[4][-1]

    result, report = observed_pass(site, observe)

    assert result["changed"] == []
    assert result["withheld"] == {PAIR: "endpoint-unverified"}
    assert report.profiles[PAIR].state == "present"
    assert report.profiles[PAIR].data["root_ready"] is False
    following, _ = observed_pass(site)
    assert following["changed"] == [f"{PAIR}:withdraw", f"{PAIR}:drain"]


def test_failed_drain_stays_a_failed_journal_and_no_replacement(environment: Any) -> None:
    site = activated(environment)
    kernel = site[3]
    kernel.unavailable_guests.add(MEDIA)
    kernel.flow_states = PAIR_STATE
    kernel.undrainable = True

    with pytest.raises(PFError, match="remaining states"):
        observed_pass(site)

    assert site[0].read("journal.json")["phase"] == "failed"
    assert "netorch:media-udp" not in kernel.rules
    assert not any(call[0] == "reference" for call in kernel.commands)


def test_loaded_check_cache_is_per_batch_and_shares_only_identical_endpoints(
    environment: Any,
) -> None:
    site = activated(environment)
    root, config, settings, kernel, snapshots = site
    records = root.read("live.json")["records"]
    verified = set(records)
    for _ in range(2):
        kernel.commands.clear()
        refused = _loaded_checks(
            config, settings, snapshots[-1], records, kernel, verified, ports=True
        )
        assert refused == {}
        assert [call for call in kernel.commands if call == ("endpoint", "198.51.100.10")] == [
            ("endpoint", "198.51.100.10")
        ]
        assert sum(call[0] == "endpoint" for call in kernel.commands) == 3


def test_loaded_check_deadline_does_not_start_later_reads_or_accept_a_late_result(
    environment: Any,
) -> None:
    class Slow(Kernel):
        instant = 0.0

        def endpoint(self, scope: Scope, ipv4: str, mac: Any, *, direct: bool) -> bool:
            self.instant += 9.0
            return super().endpoint(scope, ipv4, mac, direct=direct)

    site = activated(environment)
    root, config, settings, _, snapshots = site
    records = root.read("live.json")["records"]
    kernel = Slow()
    refused = _loaded_checks(
        config,
        settings,
        snapshots[-1],
        records,
        kernel,
        set(records),
        ports=True,
        clock=lambda: kernel.instant,
    )
    assert refused == dict.fromkeys(sorted(records), "endpoint-unverified")
    assert len(kernel.commands) == 1


def test_unknown_runtime_never_reaches_loaded_check_or_activates_fallback(environment: Any) -> None:
    site = activated(environment)
    current = site[4][-1]
    unknown = Observation("unknown", "timed-out", current.observed_at, None)
    site[4].append(replace(current, services=dict.fromkeys(current.services, unknown)))

    result, _ = observed_pass(site)

    assert site[3].rules == ""
    assert not any(call[0] in {"endpoint", "sockets", "reference"} for call in site[3].commands)
    assert not any(change.endswith(":activate") for change in result["changed"])

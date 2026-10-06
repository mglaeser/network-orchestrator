"""An observation says whether states remain; it does not carry the kernel's rows."""

from __future__ import annotations

from typing import Any

import pytest

from netorch.codec import CodecError, canonical_bytes
from netorch.pf_owner import compose_rules, reconcile
from netorch.state import Intent, Snapshot, intent_to_dict, snapshot_to_dict
from tests.test_pf_owner import STAMP, approve_all, environment, run_pass

__all__ = ["environment"]

PEER = "203.0.113.5"
CLIENT = "192.0.2.77"


def published(environment: Any) -> Snapshot:
    """The snapshot the owner hands to its report writer on one pass."""
    root, _, _, backend, snapshots = environment
    reports: list[Snapshot] = []
    reconcile(
        root,
        lambda config, settings: snapshots[-1],
        lambda root, settings: backend,
        now=lambda: STAMP,
        report=lambda settings, snapshot: reports.append(snapshot),
    )
    return reports[-1]


def resolver(environment: Any) -> str:
    return str(environment[4][-1].services["resolver"].data["ipv4"])


def test_published_report_names_no_peer_or_client_of_a_guest(environment: Any) -> None:
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    guest = resolver(environment)
    environment[3].flow_states = (
        f"all tcp {guest}:43210 -> {PEER}:443 ESTABLISHED:ESTABLISHED\n"
        f"all udp {CLIENT}:54321 -> {guest}:53 NO_TRAFFIC:SINGLE"
    )

    report = published(environment)

    assert report.profiles["dns-udp"].data["states"] == ("retained",)
    # The only tcp row is the guest's own connection, not a state of the rule.
    assert report.profiles["dns-tcp"].data["states"] == ()
    assert report.profiles["media-udp"].data["states"] == ()
    text = canonical_bytes(snapshot_to_dict(report)).decode()
    assert PEER not in text and CLIENT not in text
    assert "ESTABLISHED" not in text and "54321" not in text


def test_host_redirect_still_reports_no_states_of_the_host_address(environment: Any) -> None:
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    _, config, _, backend, _ = environment
    host = config.scope(config.profile("proxy-standard").scope).host_ipv4
    backend.flow_states = f"all tcp {CLIENT}:50000 -> {host}:80 ESTABLISHED:ESTABLISHED"

    assert published(environment).profiles["proxy-standard"].data["states"] == ()


def many_rows(guest: str, count: int) -> str:
    return "\n".join(
        f"all udp 192.0.2.{20 + index % 200}:{20000 + index} -> {guest}:53 NO_TRAFFIC:SINGLE"
        for index in range(count)
    )


def test_many_states_of_one_guest_do_not_stop_the_pass_or_a_pause(environment: Any) -> None:
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    root, _, _, backend, _ = environment
    backend.flow_states = many_rows(resolver(environment), 9000)
    # A legal inventory: well below the bound on one backend output.
    assert len(backend.flow_states.encode()) < 1_048_576

    try:
        result = run_pass(environment)
    except CodecError as error:
        pytest.fail(f"state rows were copied into the plan snapshot: {error}")
    assert result["phase"] == "committed"

    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    assert run_pass(environment)["phase"] == "inhibited"
    assert backend.rules == ""
    assert root.read("live.json")["records"] == {}


def test_the_marker_still_makes_the_planner_drain_a_retired_target(environment: Any) -> None:
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    root, _, _, backend, _ = environment
    guest = resolver(environment)
    # One profile is recorded as retired while states for its target remain.
    live = root.read("live.json")
    live["records"]["dns-udp"].update(active=False, rules="")
    root.write("live.json", live)
    backend.rules = compose_rules(live["records"])
    backend.flow_states = f"all udp {CLIENT}:54321 -> {guest}:53 NO_TRAFFIC:SINGLE"
    mark = len(backend.commands)

    result = run_pass(environment)

    assert "dns-udp:drain" in result["changed"]
    assert ("drain", guest) in backend.commands[mark:]
    assert backend.flow_states == ""

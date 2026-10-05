from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from netorch.codec import canonical_json
from netorch.config import load_config, parse_config, profile_digest, to_dict
from netorch.mock import initial_snapshot, mock_admissions
from netorch.pf import render
from netorch.state import Intent, Observation


@pytest.fixture
def config():
    return load_config(Path(__file__).resolve().parents[1] / "examples/network.json")


def test_admitted_preview_splits_udp_static_nat_from_targetless_rdr(config):
    snapshot = initial_snapshot(config)
    result = render(config, snapshot, mock_admissions(config), Intent(), 1000)
    nat = next(line for line in result.splitlines() if line.startswith("nat "))
    udp_rdr = next(
        line
        for line in result.splitlines()
        if line.startswith("rdr ") and "netorch:media-udp" in line
    )
    assert "proto udp" in nat and "port 45000:45127" in nat and "static-port" in nat
    assert "to 192.0.2.0/24 -> 192.0.2.10" in nat
    assert "from 192.0.2.0/24 to 192.0.2.10 port 45000:45127" in udp_rdr
    assert " port " not in udp_rdr.split("->", 1)[1]
    assert result.index(nat) < result.index(udp_rdr)
    assert "39999" not in result and "45128" not in result


def test_host_redirect_uses_host_publication_and_publication_is_only_comment(config):
    snapshot = initial_snapshot(config)
    assert "netorch:proxy-standard" not in render(
        config, snapshot, mock_admissions(config), Intent(), 1000
    )
    profiles = dict(snapshot.profiles)
    endpoint = snapshot.services["web-proxy"]
    profiles["proxy-high"] = Observation(
        "present",
        "verified",
        1000,
        endpoint.generation,
        {
            "policy_digest": profile_digest(config, config.profile("proxy-high")),
            "target_ipv4": endpoint.data["ipv4"],
            "target_generation": endpoint.generation,
            "network_generation": snapshot.network_generation,
            "states": [],
        },
    )
    snapshot = replace(snapshot, profiles=profiles)
    result = render(config, snapshot, mock_admissions(config), Intent(), 1000)
    line = next(line for line in result.splitlines() if "netorch:proxy-standard" in line)
    assert "port 80 -> 192.0.2.10 port 8080" in line
    assert "# proxy-high: native runtime publication" in result
    assert not any(
        line.startswith(("nat ", "rdr ")) and "netorch:proxy-high" in line
        for line in result.splitlines()
    )
    assert "proto tcp" in result and "proto udp" in result


@pytest.mark.parametrize(
    "state", ["not-admitted", "paused", "suspended", "unknown-network", "stale"]
)
def test_unreviewed_or_unverified_policy_has_no_active_pf_preview(config, state):
    snapshot = initial_snapshot(config)
    admissions = mock_admissions(config)
    intent = Intent()
    if state == "not-admitted":
        admissions = {}
    elif state == "paused":
        intent = intent.pause()
    elif state == "suspended":
        intent = intent.suspend("maintenance", "holder")
    elif state == "unknown-network":
        snapshot = replace(snapshot, network_generation=None)
    else:
        snapshot = replace(snapshot, observed_at=900)
    result = render(config, snapshot, admissions, intent, 1000)
    assert not any(line.startswith(("nat ", "rdr ")) for line in result.splitlines())


def test_changed_range_stays_pending_under_old_admission(config):
    snapshot = initial_snapshot(config)
    old_admissions = mock_admissions(config)
    data = to_dict(config)
    data["services"][2]["automatic_ports"]["last"] += 1
    data["profiles"][4]["ports"]["last"] += 1
    changed = parse_config(canonical_json(data))
    result = render(changed, snapshot, old_admissions, Intent(), 1000)
    assert "netorch:media-udp" not in result
    assert "netorch:dns-udp" in result


def test_outside_guest_subnet_cannot_be_rendered_as_udp_target(config):
    snapshot = initial_snapshot(config)
    services = dict(snapshot.services)
    services["media-controller"] = replace(
        services["media-controller"],
        data={
            **dict(services["media-controller"].data),
            "ipv4": "203.0.113.7",
        },
    )
    result = render(
        config, replace(snapshot, services=services), mock_admissions(config), Intent(), 1000
    )
    assert "netorch:media-udp" not in result


def test_retained_states_require_drain_and_are_not_a_rendered_activation(config):
    snapshot = initial_snapshot(config)
    profiles = dict(snapshot.profiles)
    profiles["media-udp"] = Observation(
        "absent",
        "confirmed-absent",
        1000,
        "old-instance",
        {
            "states": ["owned-state"],
            "target_ipv4": "198.51.100.90",
            "target_generation": "old-instance",
        },
    )
    result = render(
        config, replace(snapshot, profiles=profiles), mock_admissions(config), Intent(), 1000
    )
    assert "netorch:media-udp" not in result


def test_optional_direct_target_defaults_to_identity_mapping(config):
    data = to_dict(config)
    data["profiles"][0].pop("target_ports")
    config = parse_config(canonical_json(data))
    result = render(config, initial_snapshot(config), mock_admissions(config), Intent(), 1000)
    assert any(
        "netorch:dns-udp" in line and " port 53 # netorch:" in line for line in result.splitlines()
    )


def test_render_has_no_process_or_global_pf_side_effect(config, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Pure preview must not execute commands")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    result = render(config, initial_snapshot(config), mock_admissions(config), Intent(), 1000)
    for forbidden_text in ("pfctl", "/etc/pf", "-F all", "pass quick", "sudo", "anchor "):
        assert forbidden_text not in result

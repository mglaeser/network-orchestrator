import socket
import subprocess
from dataclasses import replace
from ipaddress import IPv4Address, IPv4Network

import pytest

from netorch.config import profile_digest
from netorch.mock import MockOwner, initial_snapshot, mock_admissions, simulate
from netorch.model import Config, Owner, PortRange, Profile, Safety, Scope, Service
from netorch.owners import OwnerFailure
from netorch.planner import plan
from netorch.state import Intent, Observation

NOW = 1000.0


def policy(*, external=False):
    kind = "guest-direct" if external else "publication"
    owner = Owner("owner", "external-root" if external else "user", (kind,))
    service = Service("service", owner.id, "a" * 64)
    scope = Scope("lan", "test0", "192.0.2.10", "192.0.2.0/24", "198.51.100.0/24")
    safety = (
        Safety("bounded", 10, 2, "Synthetic residual address-reuse window accepted.")
        if external
        else Safety("structural", 10, 1)
    )
    profile = Profile(
        "profile",
        service.id,
        scope.id,
        kind,
        "tcp",
        PortRange(8000, 8000),
        PortRange(8000, 8000),
        safety,
    )
    return Config(1, "synthetic", (scope,), (owner,), (service,), (profile,), ())


def context(*, external=False):
    config = policy(external=external)
    snapshot = initial_snapshot(config, NOW)
    admissions = mock_admissions(config)
    owner = MockOwner(config, snapshot, admissions)
    action = plan(config, snapshot, admissions, Intent(), NOW).actions[0]
    return config, snapshot, admissions, owner, action


def test_mock_fixture_is_explicitly_synthetic_and_content_bound():
    config, snapshot, admissions, owner, _action = context()
    assert owner.simulation is True
    assert snapshot.network_generation == "mock-network-1"
    assert snapshot.services["service"].generation == "mock-service-1"
    assert snapshot.services["service"].data["ipv4"] == "198.51.100.10"
    assert snapshot.profiles["profile"].state == "absent"
    assert snapshot.profiles["profile"].data["states"] == ()
    assert admissions["profile"].approved_by == "simulation-only"
    assert admissions["profile"].digest == profile_digest(config, config.profiles[0])


def test_mock_activation_updates_only_owned_profile_and_returns_exact_evidence():
    config, snapshot, _admissions, owner, action = context()
    result = owner.apply(action)
    assert result.state == "present"
    assert result.reason == "verified"
    assert result.data["policy_digest"] == profile_digest(config, config.profiles[0])
    assert result.data["target_ipv4"] == action.target_ipv4
    assert result.data["target_generation"] == action.target_generation
    assert result.data["network_generation"] == snapshot.network_generation
    assert result.data["states"] == ()
    assert owner.snapshot.services == snapshot.services
    assert owner.observe().profiles["profile"] == result
    assert owner.calls == [action]


@pytest.mark.parametrize("change", ["missing", "digest", "risk"])
def test_mock_owner_independently_checks_admission(change):
    _config, snapshot, admissions, owner, action = context(external=True)
    changed = dict(admissions)
    if change == "missing":
        changed.clear()
    elif change == "digest":
        changed["profile"] = replace(changed["profile"], digest="b" * 64)
    else:
        changed["profile"] = replace(changed["profile"], risk_acknowledged=False)
    owner.admissions = changed
    with pytest.raises(OwnerFailure, match="preconditions"):
        owner.apply(action)
    assert not owner.calls
    assert owner.snapshot == snapshot


@pytest.mark.parametrize("change", ["unknown", "absent", "generation", "contract"])
def test_mock_owner_independently_checks_endpoint(change):
    _config, snapshot, _admissions, owner, action = context()
    endpoint = snapshot.services["service"]
    if change == "unknown":
        endpoint = Observation("unknown", "timed-out", NOW, endpoint.generation, endpoint.data)
    elif change == "absent":
        endpoint = Observation("absent", "confirmed-absent", NOW, None, {})
    elif change == "generation":
        endpoint = replace(endpoint, generation="changed-instance")
    else:
        endpoint = replace(endpoint, data={**endpoint.data, "contract_sha256": "b" * 64})
    owner.snapshot = replace(snapshot, services={"service": endpoint})
    with pytest.raises(OwnerFailure, match="preconditions"):
        owner.apply(action)
    assert not owner.calls


def test_mock_owner_rejects_a_target_different_from_its_current_endpoint():
    _config, snapshot, _admissions, owner, action = context()
    with pytest.raises(OwnerFailure, match="preconditions"):
        owner.apply(replace(action, target_ipv4="198.51.100.200"))
    assert not owner.calls
    assert owner.snapshot == snapshot


@pytest.mark.parametrize("state", ["present", "unknown", "retained-states"])
def test_mock_never_activates_without_clean_absent_profile(state):
    _config, snapshot, _admissions, owner, action = context()
    applied = snapshot.profiles["profile"]
    if state == "present":
        applied = Observation("present", "verified", NOW, "old-instance", {"states": []})
    elif state == "unknown":
        applied = Observation("unknown", "incomplete", NOW, None, {})
    else:
        applied = replace(applied, data={"states": [{"id": "old-state"}]})
    owner.snapshot = replace(snapshot, profiles={"profile": applied})
    with pytest.raises(OwnerFailure, match="preconditions"):
        owner.apply(action)
    assert not owner.calls


def test_wrong_owner_cannot_use_a_valid_action():
    _config, _snapshot, _admissions, owner, action = context()
    with pytest.raises(OwnerFailure, match="owner mismatch"):
        owner.apply(replace(action, owner="different-owner"))
    assert not owner.calls


def test_profile_owner_override_is_respected_in_mixed_ownership_model():
    config = policy(external=True)
    service_owner = Owner("service-manager", "user", ("publication",))
    config = replace(
        config,
        owners=(*config.owners, service_owner),
        services=(replace(config.services[0], owner=service_owner.id),),
        profiles=(replace(config.profiles[0], owner="owner"),),
    )
    snapshot = initial_snapshot(config, NOW)
    admissions = mock_admissions(config)
    backend = MockOwner(config, snapshot, admissions)
    action = plan(config, snapshot, admissions, Intent(), NOW).actions[0]
    assert action.owner == "owner"
    assert backend.apply(action).state == "present"


def test_withdraw_and_drain_are_distinct_and_do_not_discard_state_evidence_early():
    _config, _snapshot, _admissions, owner, action = context()
    owner.apply(action)
    applied = replace(
        owner.snapshot.profiles["profile"],
        data={**owner.snapshot.profiles["profile"].data, "states": [{"id": "retained"}]},
    )
    owner.snapshot = replace(owner.snapshot, profiles={"profile": applied})
    withdraw = replace(action, operation="withdraw", reason="paused")
    result = owner.apply(withdraw)
    assert result.state == "absent"
    assert result.data["states"]
    drain = replace(withdraw, operation="drain")
    drained = owner.apply(drain)
    assert drained.state == "absent"
    assert drained.data["states"] == ()
    assert owner.calls == [action, withdraw, drain]


@pytest.mark.parametrize("operation", ["withdraw", "drain"])
def test_mock_retirement_cannot_target_an_unrelated_address(operation):
    _config, _snapshot, _admissions, owner, action = context()
    owner.apply(action)
    before = owner.snapshot
    wrong = replace(
        action, operation=operation, reason="target-replaced", target_ipv4="198.51.100.200"
    )
    with pytest.raises(OwnerFailure, match="retirement target"):
        owner.apply(wrong)
    assert owner.snapshot == before
    assert len(owner.calls) == 1


@pytest.mark.parametrize("operation", ["noop", "pending", "blocked"])
def test_mock_rejects_nonmutating_action_as_apply_request(operation):
    _config, _snapshot, _admissions, owner, action = context()
    with pytest.raises(OwnerFailure, match="unsupported mock operation"):
        owner.apply(replace(action, operation=operation))
    assert not owner.calls


def test_injected_mock_fault_fails_before_mutation():
    _config, snapshot, _admissions, owner, action = context()
    owner.fail_on = 1
    with pytest.raises(OwnerFailure, match="injected owner fault"):
        owner.apply(action)
    assert owner.snapshot == snapshot
    assert not owner.calls


def test_mock_network_capacity_error_is_explicit():
    config = policy()
    config = replace(config, scopes=(replace(config.scopes[0], guest_cidr="198.51.100.0/30"),))
    with pytest.raises(ValueError, match="too small"):
        initial_snapshot(config)


def test_simulation_covers_lifecycle_without_any_socket_or_subprocess(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("mock simulation invoked a native operation")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    config = policy(external=True)
    result = simulate(config)
    assert result["simulation"] is True
    assert result["all_verified"] is True
    assert "no native network or audio acceptance" in result["claim"]
    events = {event["stage"]: event for event in result["events"]}
    assert set(events) == {
        "unadmitted",
        "activate",
        "verify-and-complete-dependencies",
        "withdraw-for-maintenance",
        "operator-pause-survives-release",
        "resume",
        "retire-old-generation",
        "activate-new-generation",
        "final-readback",
    }
    assert events["unadmitted"]["plan"]["actions"][0]["operation"] == "pending"
    assert events["operator-pause-survives-release"]["phase"] == "inhibited"
    assert events["activate-new-generation"]["phase"] == "committed"
    assert events["final-readback"]["completed"] == 0
    final = result["final_snapshot"]["profiles"]["profile"]
    assert final["data"]["target_generation"] == "mock-recreated-2"
    target = final["data"]["target_ipv4"]
    assert target != initial_snapshot(config).services["service"].data["ipv4"]
    assert IPv4Address(target) in IPv4Network(config.scopes[0].guest_cidr)
    assert target == result["final_snapshot"]["services"]["service"]["data"]["ipv4"]


def test_simulation_is_repeatable():
    config = policy()
    assert simulate(config) == simulate(config)

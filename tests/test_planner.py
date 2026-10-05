from dataclasses import replace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netorch.config import profile_digest
from netorch.model import Config, Owner, PortRange, Profile, Safety, Scope, Service
from netorch.planner import plan, plan_from_dict, plan_to_dict
from netorch.state import Admission, Intent, Observation, Snapshot

NOW = 100.0
CONTRACT = "a" * 64


def config_for(kind="guest-direct", privilege="external-root"):
    scope = Scope("lan", "test0", "192.0.2.10", "192.0.2.0/24", "198.51.100.0/24")
    capabilities = (kind, "publication") if kind == "host-redirect" else (kind,)
    owner = Owner("packet-owner", privilege, capabilities)
    service = Service("edge", owner.id, CONTRACT, PortRange(42000, 42010))
    safety = (
        Safety("structural", 10, 1)
        if kind == "host-redirect"
        else Safety("bounded", 10, 3, "Address reuse within the observation bound is accepted.")
    )
    profile = Profile(
        "edge-web",
        service.id,
        scope.id,
        kind,
        "tcp",
        PortRange(8080, 8080),
        PortRange(8081, 8081),
        safety,
    )
    profiles = (profile,)
    if kind == "host-redirect":
        backing = Profile(
            "backing-web",
            service.id,
            scope.id,
            "publication",
            "tcp",
            PortRange(8081, 8081),
            PortRange(8080, 8080),
            Safety("structural", 10, 1),
        )
        profiles = (*profiles, backing)
    return Config(1, "example", (scope,), (owner,), (service,), profiles, ())


def admitted(config, risk=True, approved_at=NOW):
    return {
        profile.id: Admission(
            profile.id, profile_digest(config, profile), "test-reviewer", approved_at, risk
        )
        for profile in config.profiles
    }


def snapshot_for(
    config,
    *,
    present=False,
    target="198.51.100.2",
    generation="instance-1",
    states=(),
    observed_at=NOW,
    endpoint_state="present",
    reason="verified",
):
    profile = config.profiles[0]
    endpoint = Observation(
        endpoint_state,
        reason,
        observed_at,
        generation,
        {"ipv4": target, "contract_sha256": CONTRACT},
    )
    applied_target = config.scopes[0].host_ipv4 if profile.kind == "host-redirect" else target
    applied = Observation(
        "present" if present else "absent",
        "verified" if present else "confirmed-absent",
        observed_at,
        "owner-read-1",
        {
            "policy_digest": profile_digest(config, profile),
            "target_ipv4": applied_target if present else None,
            "target_generation": generation if present else None,
            "network_generation": "network-1",
            "states": list(states),
        },
    )
    return Snapshot(observed_at, "network-1", {"edge": endpoint}, {profile.id: applied})


def operations(result):
    return [action.operation for action in result.actions]


def test_absent_complete_read_exact_admission_activates():
    config = config_for()
    result = plan(config, snapshot_for(config), admitted(config), Intent(), NOW)
    assert operations(result) == ["activate"]
    assert result.actions[0].target_ipv4 == "198.51.100.2"
    assert result.actions[0].target_generation == "instance-1"
    assert not result.ready_profiles
    assert plan_from_dict(plan_to_dict(result)) == result


def test_verified_current_readback_is_only_ready_dependency():
    config = config_for()
    result = plan(config, snapshot_for(config, present=True), admitted(config), Intent(), NOW)
    assert operations(result) == ["noop"]
    assert result.ready_profiles == {"edge-web"}


def test_new_pending_admission_never_activates():
    config = config_for()
    assert operations(plan(config, snapshot_for(config), {}, Intent(), NOW)) == ["pending"]


@pytest.mark.parametrize(
    "field", ["interface", "host_ipv4", "contract", "capability", "ports", "risk"]
)
def test_admission_is_invalidated_by_every_resolved_policy_change(field):
    original = config_for()
    admissions = admitted(original)
    config = original
    if field == "interface":
        config = replace(config, scopes=(replace(config.scopes[0], interface="test1"),))
    elif field == "host_ipv4":
        config = replace(config, scopes=(replace(config.scopes[0], host_ipv4="192.0.2.11"),))
    elif field == "contract":
        config = replace(config, services=(replace(config.services[0], contract_sha256="b" * 64),))
    elif field == "capability":
        config = replace(
            config, owners=(replace(config.owners[0], capabilities=("guest-direct", "udp-return")),)
        )
    elif field == "ports":
        config = replace(
            config, profiles=(replace(config.profiles[0], ports=PortRange(8082, 8082)),)
        )
    elif field == "risk":
        config = replace(
            config,
            profiles=(
                replace(
                    config.profiles[0],
                    safety=replace(config.profiles[0].safety, max_age_seconds=11),
                ),
            ),
        )
    result = plan(config, snapshot_for(original), admissions, Intent(), NOW)
    assert operations(result) == ["pending"]
    assert result.actions[0].reason == "not-admitted"


@pytest.mark.parametrize(
    "risk,approved_at,reason",
    [
        (False, NOW, "risk-unacknowledged"),
        (True, NOW + 1, "admission-future"),
    ],
)
def test_bounded_and_time_admission_gates(risk, approved_at, reason):
    config = config_for()
    result = plan(config, snapshot_for(config), admitted(config, risk, approved_at), Intent(), NOW)
    assert operations(result) == ["pending"]
    assert result.actions[0].reason == reason


@pytest.mark.parametrize(
    "uncertainty",
    ["timed-out", "incomplete", "inaccessible", "busy", "malformed", "local-network-denied"],
)
def test_unknown_never_initiates_recovery(uncertainty):
    config = config_for()
    snapshot = snapshot_for(config, endpoint_state="unknown", reason=uncertainty)
    assert operations(plan(config, snapshot, admitted(config), Intent(), NOW)) == ["blocked"]


def test_missing_observation_is_unknown():
    config = config_for()
    snapshot = Snapshot(NOW, "network-1", {}, {})
    result = plan(config, snapshot, admitted(config), Intent(), NOW)
    assert operations(result) == ["blocked"]
    assert result.actions[0].reason == "endpoint-unknown"


@pytest.mark.parametrize("age", [11, -1])
def test_stale_future_existing_target_must_withdraw_and_drain(age):
    config = config_for()
    snapshot = snapshot_for(
        config,
        present=True,
        observed_at=NOW - age,
        states=[{"id": "owned-state-1", "target_ipv4": "198.51.100.2"}],
    )
    result = plan(config, snapshot, admitted(config), Intent(), NOW)
    assert operations(result) == ["withdraw", "drain", "blocked"]
    assert result.actions[1].target_ipv4 == "198.51.100.2"
    assert not result.ready_profiles


@pytest.mark.parametrize("change", ["guest", "instance", "network"])
def test_replacement_generation_requires_old_state_drain_before_new_activation(change):
    config = config_for()
    snapshot = snapshot_for(config, present=True, states=[{"id": "owned-state-1"}])
    endpoint = snapshot.services["edge"]
    if change == "guest":
        endpoint = replace(endpoint, data={"ipv4": "198.51.100.3", "contract_sha256": CONTRACT})
        snapshot = replace(snapshot, services={"edge": endpoint})
    elif change == "instance":
        snapshot = replace(snapshot, services={"edge": replace(endpoint, generation="instance-2")})
    else:
        snapshot = replace(snapshot, network_generation="network-2")
    result = plan(config, snapshot, admitted(config), Intent(), NOW)
    assert operations(result) == ["withdraw", "drain"]
    assert result.actions[1].target_ipv4 == "198.51.100.2"
    assert result.actions[1].target_generation == "instance-1"
    assert not result.ready_profiles


def test_removed_rule_with_retained_states_is_not_clean_absence():
    config = config_for()
    snapshot = snapshot_for(config, states=[{"id": "owned-state-1", "target_ipv4": "198.51.100.2"}])
    applied = replace(
        snapshot.profiles["edge-web"],
        data={
            **snapshot.profiles["edge-web"].data,
            "target_ipv4": "198.51.100.2",
            "target_generation": "instance-old",
        },
    )
    snapshot = replace(snapshot, profiles={"edge-web": applied})
    result = plan(config, snapshot, admitted(config), Intent(), NOW)
    assert operations(result) == ["drain"]
    assert result.actions[0].target_generation == "instance-old"
    # Only another complete, empty-state read permits the new target.
    assert operations(plan(config, snapshot_for(config), admitted(config), Intent(), NOW)) == [
        "activate"
    ]


@pytest.mark.parametrize(
    "intent",
    [Intent(operator_paused=True), Intent(suspensions={"stop": "holder"}), Intent(damaged=True)],
)
def test_intent_pause_blocks_new_exposure_and_retires_existing(intent):
    config = config_for()
    assert operations(plan(config, snapshot_for(config), admitted(config), intent, NOW)) == [
        "blocked"
    ]
    assert operations(
        plan(config, snapshot_for(config, present=True), admitted(config), intent, NOW)
    ) == [
        "withdraw",
        "drain",
        "blocked",
    ]


def test_structural_host_redirect_does_not_use_shared_guest_as_target():
    config = config_for("host-redirect")
    snapshot = snapshot_for(config)
    backing = config.profile("backing-web")
    publication = Observation(
        "present",
        "verified",
        NOW,
        "owner-read-1",
        {
            "policy_digest": profile_digest(config, backing),
            "target_ipv4": "198.51.100.2",
            "target_generation": "instance-1",
            "network_generation": "network-1",
            "states": [],
        },
    )
    snapshot = replace(snapshot, profiles={**snapshot.profiles, backing.id: publication})
    result = plan(config, snapshot, admitted(config, risk=False), Intent(), NOW)
    redirect = next(action for action in result.actions if action.profile == "edge-web")
    assert redirect.operation == "activate"
    assert redirect.target_ipv4 == "192.0.2.10"


def test_structural_redirect_requires_verified_publication_not_a_declaration():
    config = config_for("host-redirect")
    result = plan(config, snapshot_for(config), admitted(config), Intent(), NOW)
    redirect = next(action for action in result.actions if action.profile == "edge-web")
    assert redirect.operation == "blocked"
    assert redirect.reason == "publication-not-ready"


def test_mixed_owner_redirect_preserves_service_and_publication_ownership():
    config = config_for("host-redirect")
    runtime = Owner("runtime-owner", "user", ("publication",))
    service = replace(config.services[0], owner=runtime.id)
    redirect = replace(config.profile("edge-web"), owner="packet-owner")
    config = replace(
        config,
        owners=(*config.owners, runtime),
        services=(service,),
        profiles=(redirect, config.profile("backing-web")),
    )
    snapshot = snapshot_for(config)
    backing = config.profile("backing-web")
    publication = Observation(
        "present",
        "verified",
        NOW,
        "owner-read-1",
        {
            "policy_digest": profile_digest(config, backing),
            "target_ipv4": "198.51.100.2",
            "target_generation": "instance-1",
            "network_generation": "network-1",
            "states": [],
        },
    )
    snapshot = replace(snapshot, profiles={**snapshot.profiles, backing.id: publication})
    result = plan(config, snapshot, admitted(config), Intent(), NOW)
    decisions = {action.profile: action for action in result.actions}
    assert decisions["edge-web"].owner == "packet-owner"
    assert decisions["edge-web"].operation == "activate"
    assert decisions["backing-web"].owner == "runtime-owner"
    assert decisions["backing-web"].operation == "noop"


def test_direct_dataclass_bypass_cannot_skip_config_validation():
    config = config_for()
    invalid = replace(config, owners=(replace(config.owners[0], privilege="user"),))
    with pytest.raises(ValueError, match="external-root"):
        plan(invalid, snapshot_for(config), admitted(config), Intent(), NOW)


def test_contract_mismatch_and_guest_outside_scope_fail_closed():
    config = config_for()
    snapshot = snapshot_for(config, present=True)
    endpoint = replace(
        snapshot.services["edge"], data={"ipv4": "203.0.113.2", "contract_sha256": CONTRACT}
    )
    bad = replace(snapshot, services={"edge": endpoint})
    assert operations(plan(config, bad, admitted(config), Intent(), NOW)) == [
        "withdraw",
        "drain",
        "blocked",
    ]
    mismatch = replace(endpoint, data={"ipv4": "198.51.100.2", "contract_sha256": "b" * 64})
    bad = replace(snapshot, services={"edge": mismatch})
    assert (
        plan(config, bad, admitted(config), Intent(), NOW).actions[-1].reason == "contract-mismatch"
    )


def test_external_root_plan_is_data_and_invokes_nothing(monkeypatch):
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("planner invoked a process")

    monkeypatch.setattr(subprocess, "run", forbidden)
    config = config_for()
    result = plan(config, snapshot_for(config), admitted(config), Intent(), NOW)
    assert result.actions[0].owner == "packet-owner"
    assert config.owner(result.actions[0].owner).privilege == "external-root"


@given(st.sampled_from(["unknown", "absent"]), st.booleans(), st.booleans())
def test_no_unknown_or_paused_state_can_activate(endpoint_state, paused, suspended):
    config = config_for()
    reason = "timed-out" if endpoint_state == "unknown" else "confirmed-absent"
    snapshot = snapshot_for(config, endpoint_state=endpoint_state, reason=reason)
    intent = Intent(9, paused, {"test": "holder"} if suspended else {})
    result = plan(config, snapshot, admitted(config), intent, NOW)
    assert "activate" not in operations(result)


def test_plan_fencing_binds_observation_policy_and_intent_revision():
    config = config_for()
    snapshot = snapshot_for(config)
    first = plan(config, snapshot, admitted(config), Intent(), NOW)
    second = plan(
        config, replace(snapshot, network_generation="network-2"), admitted(config), Intent(), NOW
    )
    assert first.snapshot_digest != second.snapshot_digest
    changed_intent = plan(config, snapshot, admitted(config), Intent(2), NOW)
    assert changed_intent.intent_revision == 2
    assert changed_intent.policy_digest == first.policy_digest


@pytest.mark.parametrize("now", [True, -1, float("nan"), float("inf")])
def test_invalid_plan_time_rejected(now):
    config = config_for()
    with pytest.raises(ValueError):
        plan(config, snapshot_for(config), admitted(config), Intent(), now)

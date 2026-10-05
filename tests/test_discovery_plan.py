from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netorch.config import config_digest, load_config, profile_digest
from netorch.discovery_plan import DiscoveryAction, discovery_digest, plan_discovery
from netorch.mock import initial_snapshot, mock_admissions
from netorch.planner import Action, Plan, plan
from netorch.state import Intent, Observation, snapshot_digest

NOW = 1000.0


@pytest.fixture
def config():
    return load_config(Path(__file__).resolve().parents[1] / "examples/network.json")


def ready_snapshot(config, *, publisher_state="absent"):
    initial = initial_snapshot(config)
    profiles = {}
    for profile in config.profiles:
        endpoint = initial.services[profile.service]
        scope = config.scope(profile.scope)
        target = scope.host_ipv4 if profile.kind == "host-redirect" else endpoint.data["ipv4"]
        profiles[profile.id] = Observation(
            "present",
            "verified",
            NOW,
            "owner-instance-1",
            {
                "policy_digest": profile_digest(config, profile),
                "target_ipv4": target,
                "target_generation": endpoint.generation,
                "network_generation": initial.network_generation,
                "states": [],
            },
        )
    for item in config.discovery:
        profiles[item.id] = Observation(
            publisher_state,
            "confirmed-absent" if publisher_state == "absent" else "verified",
            NOW,
            None if publisher_state == "absent" else "publisher-instance-1",
            {
                "policy_digest": discovery_digest(config, item),
                "interface_confirmed": True,
                "service_generation": initial.services[item.service].generation,
                "network_generation": initial.network_generation,
            },
        )
    return replace(initial, profiles=profiles)


def decisions(config, snapshot, *, intent=None, now=NOW, transport=None):
    intent = Intent() if intent is None else intent
    transport = (
        plan(config, snapshot, mock_admissions(config), intent, now)
        if transport is None
        else transport
    )
    return {
        action.id: action for action in plan_discovery(config, snapshot, transport, intent, now)
    }


def publisher_replace(snapshot, identifier, observation):
    return replace(snapshot, profiles={**snapshot.profiles, identifier: observation})


def test_verified_dependencies_and_confirmed_absence_allow_publication(config):
    result = decisions(config, ready_snapshot(config))
    assert len(result) == len(config.discovery)
    assert all(action.active and action.reason == "ready" for action in result.values())
    assert all(config.owner(action.owner).privilege == "user" for action in result.values())


def test_degraded_fallback_dependency_requires_exact_verified_native_backing(config):
    from netorch.codec import canonical_bytes
    from netorch.config import parse_config, to_dict

    data = to_dict(config)
    source = next(item for item in data["profiles"] if item["id"] == "dns-udp")
    source["fallback_publication"] = "dns-native-udp"
    data["profiles"].append(
        {
            "id": "dns-native-udp",
            "service": source["service"],
            "scope": source["scope"],
            "kind": "publication",
            "protocol": "udp",
            "ports": {"first": 1053, "last": 1053},
            "target_ports": {"first": 53, "last": 53},
            "safety": {"kind": "structural", "max_age_seconds": 10, "unknown_limit": 1},
        }
    )
    data["discovery"].append(
        {
            "id": "dns-discovery",
            "owner": "bonjour-manager",
            "service": source["service"],
            "scope": source["scope"],
            "direction": "import",
            "types": ["_example._udp"],
            "dependencies": ["dns-udp"],
            "max_age_seconds": 10,
            "max_records": 10,
        }
    )
    configured = parse_config(canonical_bytes(data))
    snapshot = ready_snapshot(configured)
    original = snapshot.profiles["dns-udp"]
    observations = dict(snapshot.profiles)
    observations["dns-udp"] = replace(
        original,
        data={
            **original.data,
            "effective_strategy": "degraded-fallback",
            "direct_available": False,
            "target_ipv4": configured.scopes[0].host_ipv4,
        },
    )
    snapshot = replace(snapshot, profiles=observations)
    assert decisions(configured, snapshot)["dns-discovery"].active
    backing = observations["dns-native-udp"]
    observations["dns-native-udp"] = replace(backing, state="absent", reason="confirmed-absent")
    missing = replace(snapshot, profiles=observations)
    assert decisions(configured, missing)["dns-discovery"].reason == "transport-unverified"


def test_current_publication_retains_only_exact_verified_policy(config):
    result = decisions(config, ready_snapshot(config, publisher_state="present"))
    assert all(action.active and action.reason == "verified" for action in result.values())


def test_new_transport_activation_is_not_discovery_readiness(config):
    initial = initial_snapshot(config)
    publishers = ready_snapshot(config).profiles
    snapshot = replace(
        initial,
        profiles={
            **initial.profiles,
            **{item.id: publishers[item.id] for item in config.discovery},
        },
    )
    result = decisions(config, snapshot)
    assert all(
        not action.active and action.reason == "transport-unverified" for action in result.values()
    )


def test_missing_publisher_evidence_always_requests_inactive_cleanup(config):
    snapshot = ready_snapshot(config)
    snapshot = replace(
        snapshot,
        profiles={
            key: value
            for key, value in snapshot.profiles.items()
            if key not in {item.id for item in config.discovery}
        },
    )
    assert all(
        not action.active and action.reason == "publisher-unknown"
        for action in decisions(config, snapshot).values()
    )


@pytest.mark.parametrize(
    "reason",
    ["incomplete", "malformed", "inaccessible", "timed-out", "busy", "local-network-denied"],
)
def test_unknown_publisher_never_activates_even_with_last_known_data(config, reason):
    snapshot = ready_snapshot(config)
    item = config.discovery[0]
    previous = snapshot.profiles[item.id]
    unknown = Observation("unknown", reason, NOW, "previous-job", previous.data)
    snapshot = publisher_replace(snapshot, item.id, unknown)
    result = decisions(config, snapshot)[item.id]
    assert not result.active and result.reason == "publisher-unknown"


@pytest.mark.parametrize(
    "observed_at,reason", [(NOW - 121, "publisher-stale"), (NOW + 1, "publisher-future")]
)
def test_stale_future_publisher_requests_cleanup(config, observed_at, reason):
    snapshot = ready_snapshot(config)
    item = config.discovery[0]
    snapshot = publisher_replace(
        snapshot, item.id, replace(snapshot.profiles[item.id], observed_at=observed_at)
    )
    result = decisions(config, snapshot)[item.id]
    assert not result.active and result.reason == reason


@pytest.mark.parametrize("confirmed", [False, None, "true", 1, 0])
def test_interface_confirmation_requires_true_not_a_truthy_value(config, confirmed):
    snapshot = ready_snapshot(config)
    item = config.discovery[0]
    publisher = replace(snapshot.profiles[item.id], data={"interface_confirmed": confirmed})
    result = decisions(config, publisher_replace(snapshot, item.id, publisher))[item.id]
    assert not result.active and result.reason == "interface-unconfirmed"


def test_changed_policy_must_withdraw_before_reactivation(config):
    snapshot = ready_snapshot(config, publisher_state="present")
    item = config.discovery[0]
    old = replace(
        snapshot.profiles[item.id],
        data={
            **snapshot.profiles[item.id].data,
            "interface_confirmed": True,
            "policy_digest": "0" * 64,
        },
    )
    snapshot = publisher_replace(snapshot, item.id, old)
    result = decisions(config, snapshot)[item.id]
    assert not result.active and result.reason == "policy-changed"
    absent = replace(old, state="absent", reason="confirmed-absent")
    result = decisions(config, publisher_replace(snapshot, item.id, absent))[item.id]
    assert result.active and result.reason == "ready"


@pytest.mark.parametrize("field", ["service_generation", "network_generation"])
@pytest.mark.parametrize("publisher_state", ["present", "absent"])
def test_publisher_identity_must_match_current_service_and_network(config, field, publisher_state):
    snapshot = ready_snapshot(config, publisher_state=publisher_state)
    item = config.discovery[0]
    previous = snapshot.profiles[item.id]
    changed = replace(previous, data={**previous.data, field: "retired-generation"})
    result = decisions(config, publisher_replace(snapshot, item.id, changed))[item.id]
    assert not result.active and result.reason == "publisher-generation-changed"


def test_active_discovery_action_carries_both_runtime_generations(config):
    snapshot = ready_snapshot(config)
    item = config.discovery[0]
    action = decisions(config, snapshot)[item.id]
    assert action.service_generation == snapshot.services[item.service].generation
    assert action.network_generation == snapshot.network_generation
    for field in ("service_generation", "network_generation"):
        with pytest.raises(ValueError, match="requires"):
            replace(action, **{field: None})


@pytest.mark.parametrize(
    "intent,reason",
    [
        (Intent(operator_paused=True), "paused"),
        (Intent(suspensions={"maintenance": "holder"}), "suspended"),
        (Intent(damaged=True), "intent-damaged"),
    ],
)
def test_effective_pause_withdraws_discovery_independently_of_existing_transport(
    config, intent, reason
):
    result = decisions(config, ready_snapshot(config, publisher_state="present"), intent=intent)
    assert all(not action.active and action.reason == reason for action in result.values())


@pytest.mark.parametrize(
    "state,reason,expected",
    [
        ("unknown", "timed-out", "service-unknown"),
        ("absent", "confirmed-absent", "service-absent"),
    ],
)
def test_unverified_service_never_advertises(config, state, reason, expected):
    snapshot = ready_snapshot(config)
    item = config.discovery[0]
    previous = snapshot.services[item.service]
    endpoint = replace(previous, state=state, reason=reason)
    snapshot = replace(snapshot, services={**snapshot.services, item.service: endpoint})
    result = decisions(config, snapshot)[item.id]
    assert not result.active and result.reason == expected


@pytest.mark.parametrize(
    "change,reason",
    [
        ("contract", "contract-mismatch"),
        ("generation", "generation-unknown"),
        ("age", "service-stale"),
        ("future", "service-future"),
    ],
)
def test_service_contract_generation_and_freshness_are_required(config, change, reason):
    snapshot = ready_snapshot(config)
    item = config.discovery[0]
    previous = snapshot.services[item.service]
    changes = {
        "contract": {"data": {**previous.data, "contract_sha256": "0" * 64}},
        "generation": {"generation": None},
        "age": {"observed_at": NOW - 121},
        "future": {"observed_at": NOW + 1},
    }
    snapshot = replace(
        snapshot, services={**snapshot.services, item.service: replace(previous, **changes[change])}
    )
    result = decisions(config, snapshot)[item.id]
    assert not result.active and result.reason == reason


@pytest.mark.parametrize("change", ["policy", "snapshot", "intent"])
def test_old_transport_plan_is_fenced(config, change):
    snapshot = ready_snapshot(config)
    transport = plan(config, snapshot, mock_admissions(config), Intent(), NOW)
    changes = {
        "policy": {"policy_digest": "0" * 64},
        "snapshot": {"snapshot_digest": "0" * 64},
        "intent": {"intent_revision": 99},
    }
    transport = replace(transport, **changes[change])
    result = decisions(config, snapshot, transport=transport)
    assert all(
        not action.active and action.reason == "transport-plan-stale" for action in result.values()
    )


def test_forged_noop_cannot_establish_readiness_from_absence(config):
    snapshot = ready_snapshot(config)
    item = config.discovery[0]
    identifier = item.dependencies[0]
    observed = snapshot.profiles[identifier]
    snapshot = publisher_replace(
        snapshot, identifier, replace(observed, state="absent", reason="confirmed-absent")
    )
    transport = Plan(
        config_digest(config),
        snapshot_digest(snapshot),
        0,
        tuple(
            Action(
                profile.id,
                config.profile_owner(profile).id,
                "noop",
                "verified",
                snapshot.profiles[profile.id].data.get("target_ipv4"),
                snapshot.profiles[profile.id].data.get("target_generation"),
            )
            for profile in config.profiles
        ),
    )
    result = decisions(config, snapshot, transport=transport)[item.id]
    assert not result.active and result.reason == "transport-unverified"


@pytest.mark.parametrize("change", ["discovery", "scope", "service", "owner", "dependency"])
def test_discovery_digest_binds_all_resolved_authority(change, config):
    item = config.discovery[0]
    previous = discovery_digest(config, item)
    if change == "discovery":
        item = replace(item, max_records=item.max_records + 1)
    elif change == "scope":
        config = replace(config, scopes=(replace(config.scopes[0], interface="en1"),))
    elif change == "service":
        config = replace(
            config,
            services=tuple(
                replace(service, contract_sha256="0" * 64)
                if service.id == item.service
                else service
                for service in config.services
            ),
        )
    elif change == "owner":
        config = replace(
            config,
            owners=tuple(
                replace(owner, capabilities=(*owner.capabilities, "publication"))
                if owner.id == item.owner
                else owner
                for owner in config.owners
            ),
        )
    else:
        dependency = item.dependencies[0]
        config = replace(
            config,
            profiles=tuple(
                replace(profile, safety=replace(profile.safety, max_age_seconds=29))
                if profile.id == dependency
                else profile
                for profile in config.profiles
            ),
        )
    assert discovery_digest(config, item) != previous


@given(st.booleans(), st.booleans())
def test_pause_or_suspension_never_emits_active_publication(paused, suspended):
    config = load_config(Path(__file__).resolve().parents[1] / "examples/network.json")
    intent = Intent(5, paused, {"test": "holder"} if suspended else {})
    result = decisions(config, ready_snapshot(config), intent=intent)
    if paused or suspended:
        assert all(not action.active for action in result.values())
    else:
        assert all(action.active for action in result.values())


@pytest.mark.parametrize(
    "change",
    [
        {"active": "true"},
        {"reason": "new-reason"},
        {"policy_digest": "invalid"},
        {"owner": "root/command"},
        {"active": True, "reason": "paused"},
        {"active": False, "reason": "ready"},
    ],
)
def test_discovery_action_is_closed(change):
    args = {
        "id": "media-import",
        "owner": "bonjour-manager",
        "active": False,
        "reason": "paused",
        "policy_digest": "a" * 64,
        **change,
    }
    with pytest.raises(ValueError):
        DiscoveryAction(**args)


@pytest.mark.parametrize("now", [True, -1, float("nan"), float("inf")])
def test_invalid_clock_is_rejected(config, now):
    snapshot = ready_snapshot(config)
    transport = plan(config, snapshot, mock_admissions(config), Intent(), NOW)
    with pytest.raises(ValueError):
        plan_discovery(config, snapshot, transport, Intent(), now)


def test_pure_discovery_planning_invokes_no_processes(config, monkeypatch):
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("discovery planner invoked a process")

    monkeypatch.setattr(subprocess, "run", forbidden)
    assert all(action.active for action in decisions(config, ready_snapshot(config)).values())

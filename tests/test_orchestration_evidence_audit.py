"""Synthetic adversarial proofs for orchestration; no production or native calls."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from netorch import config as config_module
from netorch.config import ConfigError, load_config, parse_config, to_dict, validate_config
from netorch.owners import OwnerFailure
from netorch.planner import plan_from_dict, plan_to_dict
from tests.test_executor import context, run

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/network.json"


@pytest.mark.parametrize(
    "path",
    [
        ("schema_version",),
        ("services", 2, "automatic_ports", "first"),
        ("services", 2, "automatic_ports", "last"),
        ("profiles", 0, "ports", "first"),
        ("profiles", 0, "ports", "last"),
        ("profiles", 0, "target_ports", "first"),
        ("profiles", 0, "target_ports", "last"),
        ("profiles", 0, "safety", "max_age_seconds"),
        ("profiles", 0, "safety", "unknown_limit"),
        ("discovery", 0, "max_age_seconds"),
        ("discovery", 0, "max_records"),
    ],
)
@pytest.mark.parametrize("boundary", ["json", "constructed"])
def test_integral_json_float_never_enters_typed_policy(path, boundary):
    value = to_dict(load_config(EXAMPLE))
    target = value
    for key in path[:-1]:
        target = target[key]
    assert type(target[path[-1]]) is int
    target[path[-1]] = float(target[path[-1]])
    # JSON Schema calls 53.0 an integer; native syntax/typed consumers do not.
    # Both entry points must reject instead of rendering a port such as 53.0.
    with pytest.raises(ConfigError):
        if boundary == "json":
            parse_config(json.dumps(value))
        else:
            validate_config(config_module._construct(value))


@pytest.mark.parametrize("field", ["operation", "reason", "effective_strategy"])
@pytest.mark.parametrize("value", [[], {}])
def test_malformed_action_enums_raise_controlled_plan_error(tmp_path, field, value):
    *_, candidate = context(tmp_path)
    document = plan_to_dict(candidate)
    document["actions"][0][field] = value
    with pytest.raises(ValueError):
        plan_from_dict(document)


@pytest.mark.parametrize("field", ["policy_digest", "snapshot_digest"])
@pytest.mark.parametrize("value", [None, [], {}, 1])
def test_malformed_plan_digest_raises_controlled_error(tmp_path, field, value):
    *_, candidate = context(tmp_path)
    document = plan_to_dict(candidate)
    document[field] = value
    with pytest.raises(ValueError):
        plan_from_dict(document)


@pytest.mark.parametrize("value", [True, 1, 3221225994])
def test_plan_address_is_text_not_integer_address_coercion(tmp_path, value):
    *_, candidate = context(tmp_path)
    document = plan_to_dict(candidate)
    document["actions"][0]["target_ipv4"] = value
    with pytest.raises(ValueError):
        plan_from_dict(document)


@pytest.mark.parametrize("value", [[], {}])
def test_malformed_journal_phase_stops_before_any_owner_operation(tmp_path, value):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    original = {"schema_version": 1, "phase": value}
    store.write("journal.json", original)
    with pytest.raises(OwnerFailure, match="unknown journal format"):
        run(config, snapshot, admissions, intent, store, backend, candidate)
    assert not backend.calls
    assert store.read("journal.json") == original
    assert not (store.directory / "receipt.json").exists()


def test_executor_rejects_unexpected_effective_strategy_readback(tmp_path):
    from tests.test_executor import LiveClient

    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)

    def corrupt(result, action):
        return replace(result, data={**result.data, "effective_strategy": "degraded-fallback"})

    with pytest.raises(OwnerFailure, match="exact activation readback"):
        run(config, snapshot, admissions, intent, store, LiveClient(backend, corrupt), candidate)
    assert store.read("journal.json")["phase"] == "failed"
    assert not (store.directory / "receipt.json").exists()


@pytest.mark.parametrize(
    "fault",
    ["approval-profile", "approval-future", "network", "endpoint-age", "profile-age", "states"],
)
def test_mock_cannot_make_incomplete_activation_preconditions_look_successful(tmp_path, fault):
    _config, snapshot, admissions, _intent, _store, backend, candidate = context(tmp_path)
    action = candidate.actions[0]
    if fault == "approval-profile":
        backend.admissions = {"p0": replace(admissions["p0"], profile="another-profile")}
    elif fault == "approval-future":
        backend.admissions = {"p0": replace(admissions["p0"], approved_at=snapshot.observed_at + 1)}
    elif fault == "network":
        backend.snapshot = replace(snapshot, network_generation=None)
    elif fault == "endpoint-age":
        endpoint = replace(snapshot.services["service"], observed_at=snapshot.observed_at - 11)
        backend.snapshot = replace(snapshot, services={"service": endpoint})
    else:
        current = snapshot.profiles["p0"]
        current = (
            replace(current, observed_at=snapshot.observed_at - 11)
            if fault == "profile-age"
            else replace(current, data={})
        )
        backend.snapshot = replace(snapshot, profiles={"p0": current})
    before = backend.snapshot
    with pytest.raises(OwnerFailure, match="preconditions"):
        backend.apply(action)
    assert backend.snapshot == before
    assert not backend.calls


def test_mock_requires_unrestricted_source_risk_acknowledgement():
    from netorch.mock import MockOwner, initial_snapshot, mock_admissions
    from netorch.planner import Action

    config = load_config(EXAMPLE)
    profile = replace(config.profile("proxy-standard"), source_scope="any")
    config = replace(
        config,
        profiles=tuple(profile if p.id == profile.id else p for p in config.profiles),
    )
    snapshot = initial_snapshot(config)
    admissions = mock_admissions(config)
    admissions[profile.id] = replace(admissions[profile.id], risk_acknowledged=False)
    backend = MockOwner(config, snapshot, admissions)
    action = Action(
        profile.id,
        config.profile_owner(profile).id,
        "activate",
        "ready",
        config.scope(profile.scope).host_ipv4,
        snapshot.services[profile.service].generation,
    )
    with pytest.raises(OwnerFailure, match="preconditions"):
        backend.apply(action)
    assert not backend.calls
    assert backend.snapshot == snapshot

"""Synthetic status-v1 protocol cases, never native/production acceptance evidence.

The fixture uses the complete public dashboard response shape and reserved
example URLs. It is deliberately generated test data, not a captured Luck API
response. Malformations are derived from it to prove fail-closed evaluation.
"""

from __future__ import annotations

import copy
import hashlib
import json
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netorch.codec import canonical_bytes
from netorch.migration_health import PHASES, main, validate_contract
from tests.test_migration_health import NOW, check, timestamp

FIXTURE = Path(__file__).parent / "fixtures" / "dashboard-status-v1-synthetic.json"


def fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    dashboard = json.loads(FIXTURE.read_text())
    contract = {
        "schema_version": 2,
        "plan_sha256": "a" * 64,
        "catalog_sha256": "b" * 64,
        "dashboard_api": "status-v1",
        "critical_severity_max": 3,
        "steps": ["discovery", "supervisor"],
        "services": [
            {
                "id": component["id"],
                "category": component["category"][:-1],
                "checks": [entry["name"] for entry in component["checks"]],
                "max_age_seconds": 300,
                "severity": component["severity"],
            }
            for component in dashboard["components"]
        ],
    }
    snapshot = {
        "schema_version": 2,
        "contract_sha256": hashlib.sha256(canonical_bytes(contract)).hexdigest(),
        "catalog_sha256": contract["catalog_sha256"],
        "step": "discovery",
        "phase": "post",
        "generation": "attempt-one",
        "started_at": NOW - 20,
        "completed_at": NOW - 1,
        "source": "dashboard-status-api-v1",
        "dashboard": dashboard,
    }
    return contract, snapshot


def rebind(contract: dict[str, Any], snapshot: dict[str, Any]) -> None:
    snapshot["contract_sha256"] = hashlib.sha256(canonical_bytes(contract)).hexdigest()


def aggregate(snapshot: dict[str, Any]) -> None:
    """Keep a test mutation internally honest; do not turn failures green."""
    dashboard = snapshot["dashboard"]
    components = dashboard["components"]
    counts = {"total": len(components), "operational": 0, "degraded": 0, "unknown": 0}
    for component in components:
        counts[component["status"]] += 1
    affected = [c["severity"] for c in components if c["status"] == "degraded"]
    dashboard["status"] = {
        "state": "degraded"
        if counts["degraded"]
        else ("unknown" if counts["unknown"] or not components else "operational"),
        "highest_affected_severity": min(affected) if affected else None,
        "counts": counts,
    }


def refused(contract: Any, snapshot: Any, **kwargs: Any) -> dict[str, Any] | None:
    """Both malformed-input refusal and recorded-health blockers are safe."""
    try:
        result = check(contract, snapshot, **kwargs)
    except ValueError:
        return None
    assert result["recorded_health_passed"] is False
    assert result["mutation_available"] is False
    assert result["native_qualified"] is False
    return result


@pytest.mark.parametrize("phase", PHASES)
def test_complete_summary_preserves_offline_authority_boundary(phase: str) -> None:
    contract, snapshot = fixture()
    snapshot["phase"] = phase
    result = check(contract, snapshot, phase=phase)
    assert result["schema_version"] == 2
    assert result["recorded_health_passed"] is True
    assert result["critical_health_passed"] is True
    assert result["critical_services"] == 2
    assert result["noncritical_services"] == 2
    assert result["blockers"] == []
    assert result["mutation_available"] is False
    assert result["native_qualified"] is False
    assert result["provenance_authenticated"] is False
    assert snapshot["dashboard"]["status"]["highest_affected_severity"] is None


@pytest.mark.parametrize("index", range(4))
def test_every_component_failure_blocks_even_noncritical(index: int) -> None:
    contract, snapshot = fixture()
    component = snapshot["dashboard"]["components"][index]
    component.update(status="degraded", status_reason="checks_failed")
    component["checks"][0]["status"] = "fail"
    aggregate(snapshot)
    result = check(contract, snapshot)
    assert result["recorded_health_passed"] is False
    assert result["critical_health_passed"] is (component["severity"] > 3)
    assert component["id"] + ":not-healthy" in result["blockers"]


@pytest.mark.parametrize("level", [1, 2, 3])
def test_all_three_critical_levels_are_mandatory(level: int) -> None:
    contract, snapshot = fixture()
    contract["services"][0]["severity"] = level
    component = snapshot["dashboard"]["components"][0]
    component["severity"] = level
    component.update(status="degraded", status_reason="checks_failed")
    component["checks"][0]["status"] = "fail"
    aggregate(snapshot)
    rebind(contract, snapshot)
    assert check(contract, snapshot)["critical_health_passed"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("dashboard_api", "services-v1"),
        ("dashboard_api", None),
        ("critical_severity_max", 4),
        ("critical_severity_max", 2),
        ("critical_severity_max", True),
        ("critical_severity_max", 3.0),
        ("schema_version", True),
        ("schema_version", "2"),
        ("schema_version", 2.0),
    ],
)
def test_policy_is_explicit_and_cannot_weaken_threshold(field: str, value: Any) -> None:
    contract, _ = fixture()
    contract[field] = value
    with pytest.raises(ValueError):
        validate_contract(contract)


@pytest.mark.parametrize("value", [True, False, None, "3", 3.0, 0, 6, [], {}])
def test_contract_severity_is_required_integer_1_to_5(value: Any) -> None:
    contract, _ = fixture()
    contract["services"][0]["severity"] = value
    with pytest.raises(ValueError):
        validate_contract(contract)


@pytest.mark.parametrize("field", ["dashboard_api", "critical_severity_max"])
def test_v2_policy_cannot_be_omitted(field: str) -> None:
    contract, _ = fixture()
    del contract[field]
    with pytest.raises(ValueError):
        validate_contract(contract)


def test_contract_cannot_infer_severity_from_live_response() -> None:
    contract, snapshot = fixture()
    del contract["services"][0]["severity"]
    with pytest.raises(ValueError):
        check(contract, snapshot)


@pytest.mark.parametrize("index,level", [(0, 5), (1, 4), (2, 1), (3, 4)])
def test_downgrade_or_any_unreviewed_severity_change_invalidates_entire_gate(
    index: int, level: int
) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["components"][index]["severity"] = level
    result = check(contract, snapshot)
    assert result["recorded_health_passed"] is False
    assert result["critical_health_passed"] is False
    assert any(item.endswith(":severity-changed") for item in result["blockers"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 1),
        ("schema_version", True),
        ("source", "dashboard-api"),
        ("source", "fabricated"),
        ("contract_sha256", "c" * 64),
        ("catalog_sha256", "d" * 64),
        ("step", "supervisor"),
        ("phase", "pre"),
        ("generation", "attempt-zero"),
        ("started_at", NOW - 31),
        ("completed_at", NOW + 1),
    ],
)
def test_global_context_cannot_hide_behind_healthy_critical_rows(field: str, value: Any) -> None:
    contract, snapshot = fixture()
    snapshot[field] = value
    result = refused(contract, snapshot)
    if result is not None:
        assert result["critical_health_passed"] is False


def test_legacy_response_cannot_be_relabelled_as_new_api() -> None:
    from tests.test_migration_health import fixture as legacy_fixture

    contract, snapshot = fixture()
    _, legacy = legacy_fixture()
    snapshot["dashboard"] = legacy["dashboard"]
    refused(contract, snapshot)


@pytest.mark.parametrize("version", [1, True, "2", "1.0", None, [], {}])
def test_api_schema_version_is_exact_string_one(version: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["schema_version"] = version
    refused(contract, snapshot)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "disk-cache"),
        ("source", None),
        ("interval_seconds", 0),
        ("interval_seconds", True),
        ("max_age_seconds", 4200),
        ("max_age_seconds", 301),
        ("max_age_seconds", True),
        ("max_age_seconds", 300.0),
        ("max_age_seconds", 0),
        ("refreshing", True),
        ("refreshing", 0),
    ],
)
def test_api_observation_contract(field: str, value: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["observation"][field] = value
    result = refused(contract, snapshot)
    if result is not None:
        assert result["critical_health_passed"] is False


@pytest.mark.parametrize("operation", ["missing", "extra", "duplicate", "empty"])
def test_complete_roster_including_sev4_and_sev5_is_still_mandatory(operation: str) -> None:
    contract, snapshot = fixture()
    components = snapshot["dashboard"]["components"]
    if operation == "missing":
        components.pop()
    elif operation == "extra":
        extra = copy.deepcopy(components[0])
        extra["id"] = "unreviewed-service"
        components.append(extra)
    elif operation == "duplicate":
        components.append(copy.deepcopy(components[-1]))
    else:
        components.clear()
    aggregate(snapshot)
    result = refused(contract, snapshot)
    if result is not None:
        assert result["critical_health_passed"] is False


@pytest.mark.parametrize("value", [None, "service", "devices", "Services", [], {}])
def test_category_is_exact_plural_and_pinned(value: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["components"][0]["category"] = value
    result = refused(contract, snapshot)
    if result is not None:
        assert result["critical_health_passed"] is False


@pytest.mark.parametrize("operation", ["missing", "extra", "duplicate", "renamed", "empty"])
def test_check_roster_drift_on_noncritical_also_invalidates_critical_gate(operation: str) -> None:
    contract, snapshot = fixture()
    checks = snapshot["dashboard"]["components"][-1]["checks"]
    if operation == "missing":
        checks.pop()
    elif operation == "extra":
        checks.append({"name": "Unreviewed", "status": "pass", "message": "Synthetic"})
    elif operation == "duplicate":
        checks.append(copy.deepcopy(checks[0]))
    elif operation == "renamed":
        checks[0]["name"] = "Different proof"
    else:
        checks.clear()
    result = check(contract, snapshot)
    assert result["critical_health_passed"] is False
    assert result["recorded_health_passed"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "unknown"),
        ("status", "degraded"),
        ("status", True),
        ("status_reason", "checks_failed"),
        ("status_reason", "stale"),
        ("refreshing", True),
        ("refreshing", 0),
        ("severity", True),
        ("checked_at", None),
        ("checked_at", timestamp(NOW + 1)),
        ("checked_at", "2026-02-31T00:00:00Z"),
        ("checked_at", "2026-01-01T00:00:00+00:00"),
        ("age_seconds", 0),
        ("age_seconds", True),
        ("age_seconds", -1),
        ("expires_at", timestamp(NOW + 500)),
        ("expires_at", None),
    ],
)
def test_false_healthy_component_or_contradictory_times_fail(field: str, value: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["components"][0][field] = value
    refused(contract, snapshot)


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", ""),
        ("name", "bad\nname"),
        ("name", {}),
        ("status", "fail"),
        ("status", True),
        ("status", "green"),
        ("status", []),
        ("status", {}),
        ("message", False),
    ],
)
def test_checks_cannot_be_replaced_by_displayed_operational(field: str, value: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["components"][0]["checks"][0][field] = value
    refused(contract, snapshot)


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "degraded"),
        ("state", "unknown"),
        ("state", True),
        ("highest_affected_severity", 1),
        ("highest_affected_severity", True),
        ("highest_affected_severity", 0),
        ("highest_affected_severity", 6),
    ],
)
def test_aggregate_is_recomputed_not_trusted(field: str, value: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["status"][field] = value
    result = refused(contract, snapshot)
    if result is not None:
        assert result["critical_health_passed"] is False


@pytest.mark.parametrize("field", ["total", "operational", "degraded", "unknown"])
@pytest.mark.parametrize("value", [True, 1.0, -1, 128, 129, "4", None, [], {}])
def test_aggregate_counts_are_strict_and_exact(field: str, value: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["status"]["counts"][field] = value
    result = refused(contract, snapshot)
    if result is not None:
        assert result["critical_health_passed"] is False


@pytest.mark.parametrize("stamp", [timestamp(NOW - 21), timestamp(NOW), None, True, [], {}])
def test_response_generation_is_inside_recorded_window(stamp: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["generated_at"] = stamp
    result = refused(contract, snapshot)
    if result is not None:
        assert result["critical_health_passed"] is False


def test_fresh_before_step_is_not_fresh_after_step() -> None:
    contract, snapshot = fixture()
    component = snapshot["dashboard"]["components"][0]
    component.update(
        checked_at=timestamp(NOW - 21), age_seconds=20, expires_at=timestamp(NOW - 21 + 300)
    )
    result = check(contract, snapshot)
    assert result["critical_health_passed"] is False
    assert "console:stale-or-outside-checkpoint" in result["blockers"]


@pytest.mark.parametrize("elapsed,passes", [(300, True), (300.000001, False)])
def test_evaluation_time_freshness_has_no_tolerance(elapsed: float, passes: bool) -> None:
    contract, snapshot = fixture()
    result = check(contract, snapshot, now=NOW - 10 + elapsed)
    assert result["recorded_health_passed"] is passes
    assert result["critical_health_passed"] is passes


def test_millisecond_timestamp_consistency_accepts_real_javascript_precision() -> None:
    contract, snapshot = fixture()
    component = snapshot["dashboard"]["components"][0]
    component.update(
        checked_at=timestamp(NOW - 10.123),
        age_seconds=9.123,
        expires_at=timestamp(NOW - 10.123 + 300),
    )
    assert check(contract, snapshot)["recorded_health_passed"] is True
    component["age_seconds"] += 0.001
    refused(contract, snapshot)


@pytest.mark.parametrize(
    "reason",
    [
        "not_checked",
        "context_changed",
        "invalid_timestamp",
        "invalid_result",
        "credentials_error",
        "configuration_error",
    ],
)
def test_honest_unavailable_observation_cannot_pass(reason: str) -> None:
    contract, snapshot = fixture()
    component = snapshot["dashboard"]["components"][0]
    component.update(
        status="unknown",
        status_reason=reason,
        checked_at=None,
        age_seconds=None,
        expires_at=None,
        checks=[],
    )
    aggregate(snapshot)
    result = check(contract, snapshot)
    assert result["recorded_health_passed"] is False
    assert result["critical_health_passed"] is False
    assert "dashboard-aggregate-inconsistent" not in result["blockers"]


def test_honest_stale_check_keeps_diagnostics_without_becoming_healthy() -> None:
    contract, snapshot = fixture()
    component = snapshot["dashboard"]["components"][0]
    component.update(
        status="unknown",
        status_reason="stale",
        checked_at=timestamp(NOW - 302),
        age_seconds=301,
        expires_at=timestamp(NOW - 2),
    )
    aggregate(snapshot)
    result = check(contract, snapshot)
    assert result["recorded_health_passed"] is False
    assert "dashboard-aggregate-inconsistent" not in result["blockers"]
    assert "console:observation-inconsistent" not in result["blockers"]


def test_shorter_reviewed_freshness_bound_cannot_be_overridden_by_query() -> None:
    contract, snapshot = fixture()
    contract["services"][0]["max_age_seconds"] = 5
    rebind(contract, snapshot)
    refused(contract, snapshot)


def test_additive_private_metadata_is_bounded_ignored_and_never_echoed() -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["future_metadata"] = {"command": "do not execute", "token": "secret"}
    snapshot["dashboard"]["components"][0]["checks"][0]["message"] = "private token secret"
    result = check(contract, snapshot)
    assert result["recorded_health_passed"] is True
    assert "secret" not in json.dumps(result)
    assert "command" not in result
    snapshot["dashboard"]["future_metadata"]["token"] = "x" * 65_537
    refused(contract, snapshot)


@given(
    st.sampled_from(
        [
            "schema_version",
            "generated_at",
            "status",
            "observation",
            "components",
            "page",
            "hosts",
            "severity_levels",
        ]
    ),
    st.sampled_from([None, True, 1, "wrong", [], {}]),
)
def test_malformed_top_fields_never_escape_as_typeerror(field: str, value: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"][field] = value
    # Display-only page/host/policy metadata is deliberately not authoritative.
    if field in {"page", "hosts", "severity_levels"}:
        assert check(contract, snapshot)["recorded_health_passed"] is True
    else:
        refused(contract, snapshot)


def test_cli_is_offline_without_refresh_process_or_file_mutation(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    contract, snapshot = fixture()
    contract_file, snapshot_file = tmp_path / "contract.json", tmp_path / "snapshot.json"
    contract_file.write_bytes(canonical_bytes(contract) + b"\n")
    snapshot_file.write_bytes(canonical_bytes(snapshot) + b"\n")
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network, process or write attempted")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr("netorch.migration_health.time.time", lambda: NOW)
    argv = [
        "--contract",
        str(contract_file),
        "--snapshot",
        str(snapshot_file),
        "--step",
        "discovery",
        "--phase",
        "post",
        "--generation",
        "attempt-one",
        "--since",
        str(NOW - 30),
    ]
    assert main(argv) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["critical_health_passed"] is True
    assert result["provenance_authenticated"] is False
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_nested_malformed_json_never_leaks_typeerror_data_or_authority(monkeypatch: Any) -> None:
    contract, baseline = fixture()
    paths: list[tuple[str | int, ...]] = []

    def visit(value: Any, path: tuple[str | int, ...] = ()) -> None:
        paths.append(path)
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, (*path, key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, (*path, index))

    visit(baseline)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("offline evaluator attempted I/O")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    marker = "private-metadata-sentinel"
    mutations = [None, True, False, 0, 1, 1.5, -1, marker, [], {}, [marker], {marker: []}]
    for path in paths:
        for mutation in mutations:
            snapshot = copy.deepcopy(baseline)
            if not path:
                snapshot = mutation
            else:
                parent: Any = snapshot
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = mutation
            try:
                result = check(contract, snapshot)
            except ValueError:
                continue
            assert marker not in json.dumps(result), path
            assert result["mutation_available"] is False
            assert result["native_qualified"] is False
            assert result["provenance_authenticated"] is False
    assert len(paths) > 100


@pytest.mark.parametrize("malformed", [False, True])
def test_cli_failure_exits_and_output_do_not_expose_private_check_details(
    malformed: bool, tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    contract, snapshot = fixture()
    component = snapshot["dashboard"]["components"][0]
    component.update(status="degraded", status_reason="checks_failed")
    component["checks"][0].update(status="fail", message="secret-token-never-echo")
    aggregate(snapshot)
    if malformed:
        component["checks"][0]["status"] = {"secret-token-never-echo": True}
    contract_file, snapshot_file = tmp_path / "contract.json", tmp_path / "snapshot.json"
    contract_file.write_bytes(canonical_bytes(contract) + b"\n")
    snapshot_file.write_bytes(canonical_bytes(snapshot))
    monkeypatch.setattr("netorch.migration_health.time.time", lambda: NOW)
    argv = [
        "--contract",
        str(contract_file),
        "--snapshot",
        str(snapshot_file),
        "--step",
        "discovery",
        "--phase",
        "post",
        "--generation",
        "attempt-one",
        "--since",
        str(NOW - 30),
    ]
    assert main(argv) == (65 if malformed else 1)
    output = capsys.readouterr().out
    assert "secret-token-never-echo" not in output
    assert json.loads(output)["mutation_available"] is False

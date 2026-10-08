"""A green tile, an old batch or a successful subset cannot pass a checkpoint."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netorch.codec import canonical_bytes
from netorch.migration_health import PHASES, evaluate, main, validate_contract

NOW = 1800000100.0


def timestamp(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")


def fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    contract = {
        "schema_version": 1,
        "plan_sha256": "a" * 64,
        "catalog_sha256": "b" * 64,
        "steps": ["discovery", "supervisor"],
        "services": [
            {
                "id": name,
                "category": "service",
                "checks": ["Login", "Functional outcome"],
                "max_age_seconds": 120,
            }
            for name in ("console", "resolver", "remote-sentinel")
        ],
    }
    snapshot = {
        "schema_version": 1,
        "contract_sha256": hashlib.sha256(canonical_bytes(contract)).hexdigest(),
        "catalog_sha256": contract["catalog_sha256"],
        "step": "discovery",
        "phase": "post",
        "generation": "attempt-one",
        "started_at": NOW - 20,
        "completed_at": NOW - 1,
        "source": "dashboard-api",
        "dashboard": {
            "configError": None,
            "running": False,
            "hosts": [],
            "intervalSeconds": 3600,
            "services": [
                {
                    "id": entry["id"],
                    "result": {
                        "status": "green",
                        "running": False,
                        "checkedAt": timestamp(NOW - 10),
                        "checks": [
                            {"name": name, "ok": True, "message": "private detail"}
                            for name in entry["checks"]
                        ],
                    },
                }
                for entry in contract["services"]
            ],
        },
    }
    return contract, snapshot


def check(contract: Any, snapshot: Any, **kwargs: Any) -> dict[str, Any]:
    args = {
        "step": "discovery",
        "phase": "post",
        "generation": "attempt-one",
        "since": NOW - 30,
        "now": NOW,
    }
    args.update(kwargs)
    return evaluate(contract, snapshot, **args)


def test_complete_recording_never_grants_authority_or_authenticates_it() -> None:
    result = check(*fixture())
    assert result["recorded_health_passed"]
    assert result["blockers"] == []
    for field in ("mutation_available", "native_qualified", "provenance_authenticated"):
        assert result[field] is False


@pytest.mark.parametrize("phase", PHASES)
def test_each_checkpoint_requires_the_whole_roster(phase: str) -> None:
    contract, snapshot = fixture()
    snapshot["phase"] = phase
    snapshot["dashboard"]["services"].pop()
    result = check(contract, snapshot, phase=phase)
    assert not result["recorded_health_passed"]
    assert "remote-sentinel:missing" in result["blockers"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("contract_sha256", "c" * 64),
        ("catalog_sha256", "d" * 64),
        ("step", "supervisor"),
        ("phase", "pre"),
        ("generation", "attempt-zero"),
        ("source", "synthetic"),
        ("started_at", NOW - 31),
        ("completed_at", NOW + 1),
        ("completed_at", NOW - 21),
    ],
)
def test_wrong_context_or_generation_never_reuses_a_green_record(field: str, value: Any) -> None:
    contract, snapshot = fixture()
    snapshot[field] = value
    assert not check(contract, snapshot)["recorded_health_passed"]


@pytest.mark.parametrize(
    "stamp",
    [None, "", "not-a-date", "2026-02-31T00:00:00Z", timestamp(NOW + 1), timestamp(NOW - 21)],
)
def test_stale_cached_and_future_results_fail(stamp: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["services"][0]["result"]["checkedAt"] = stamp
    assert not check(contract, snapshot)["recorded_health_passed"]


def test_freshness_is_measured_at_evaluation_not_capture_end() -> None:
    contract, snapshot = fixture()
    assert not check(contract, snapshot, now=NOW + 200)["recorded_health_passed"]


@pytest.mark.parametrize(
    "field,value", [("running", True), ("running", 0), ("configError", "private diagnostic")]
)
def test_dashboard_configuration_or_refresh_blocks(field: str, value: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"][field] = value
    result = check(contract, snapshot)
    assert not result["recorded_health_passed"]
    assert "private diagnostic" not in json.dumps(result)


@pytest.mark.parametrize(
    "field,value",
    [("status", "red"), ("status", "unknown"), ("running", True), ("running", 0), ("checks", [])],
)
def test_result_status_and_complete_checks_are_both_required(field: str, value: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["services"][0]["result"][field] = value
    assert not check(contract, snapshot)["recorded_health_passed"]


@pytest.mark.parametrize("value", [False, None, 1, "true", "unknown"])
def test_green_status_does_not_hide_failed_checks(value: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["services"][1]["result"]["checks"][0]["ok"] = value
    assert not check(contract, snapshot)["recorded_health_passed"]


@pytest.mark.parametrize("operation", ["missing", "extra", "duplicate", "renamed"])
def test_exact_check_names_prevent_partial_success(operation: str) -> None:
    contract, snapshot = fixture()
    checks = snapshot["dashboard"]["services"][0]["result"]["checks"]
    if operation == "missing":
        checks.pop()
    elif operation == "extra":
        checks.append({"name": "Unexpected success", "ok": True})
    elif operation == "duplicate":
        checks.append(copy.deepcopy(checks[0]))
    else:
        checks[0]["name"] = "Different proof"
    assert not check(contract, snapshot)["recorded_health_passed"]


def test_new_dashboard_entry_requires_explicit_contract_review() -> None:
    contract, snapshot = fixture()
    extra = copy.deepcopy(snapshot["dashboard"]["services"][0])
    extra["id"] = "new-service"
    snapshot["dashboard"]["services"].append(extra)
    assert "dashboard-roster-changed" in check(contract, snapshot)["blockers"]


def test_duplicate_service_is_invalid_even_when_healthy() -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["services"].append(snapshot["dashboard"]["services"][0])
    with pytest.raises(ValueError):
        check(contract, snapshot)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("plan_sha256", "unknown"),
        ("steps", []),
        ("steps", ["discovery", "discovery"]),
        ("services", []),
    ],
)
def test_invalid_contract_is_refused(field: str, value: Any) -> None:
    contract, _ = fixture()
    contract[field] = value
    with pytest.raises(ValueError):
        validate_contract(contract)


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_age_seconds", True),
        ("max_age_seconds", 301),
        ("max_age_seconds", 0),
        ("checks", ["same", "same"]),
        ("checks", [[]]),
        ("checks", ["bad\nname"]),
        ("category", "ignored"),
        ("id", "../escape"),
    ],
)
def test_no_mutable_exemptions_or_arbitrary_executables(field: str, value: Any) -> None:
    contract, _ = fixture()
    contract["services"][0][field] = value
    with pytest.raises(ValueError):
        validate_contract(contract)


@given(st.sampled_from(["command", "sudo", "ignore_failed", "allow_stale", "optional"]))
def test_no_action_or_exemption_fields(key: str) -> None:
    contract, _ = fixture()
    contract[key] = True
    with pytest.raises(ValueError):
        validate_contract(contract)


@pytest.mark.parametrize("clock", [True, float("nan"), float("inf"), -1, "now"])
def test_clock_must_be_finite_and_unambiguous(clock: Any) -> None:
    with pytest.raises(ValueError):
        check(*fixture(), now=clock)


def test_plan_change_invalidates_existing_recording() -> None:
    contract, snapshot = fixture()
    contract["plan_sha256"] = "e" * 64
    assert not check(contract, snapshot)["recorded_health_passed"]


def test_cli_is_offline_and_does_not_write(tmp_path: Path, monkeypatch: Any, capsys: Any) -> None:
    contract, snapshot = fixture()
    contract_file, snapshot_file = tmp_path / "contract.json", tmp_path / "recording.json"
    contract_file.write_bytes(canonical_bytes(contract) + b"\n")
    snapshot_file.write_bytes(canonical_bytes(snapshot))
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("native action attempted")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
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
    assert json.loads(capsys.readouterr().out)["provenance_authenticated"] is False
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before
    snapshot_file.write_text('{"private-secret": true, "private-secret": false}')
    assert main(argv) == 65
    assert "private-secret" not in capsys.readouterr().out
    contract_file.write_text(json.dumps(contract, indent=2))
    assert main(argv) == 65


def test_missing_envelope_keys_are_not_healthy() -> None:
    contract, snapshot = fixture()
    del snapshot["dashboard"]["running"]
    with pytest.raises(ValueError):
        check(contract, snapshot)

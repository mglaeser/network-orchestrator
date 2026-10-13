"""The externally supplied refresh boundary owns the status-v2 collection budget."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from netorch.codec import canonical_bytes
from netorch.migration_health import PHASES, main
from tests.test_migration_health import NOW, check
from tests.test_migration_health import fixture as legacy_fixture
from tests.test_migration_status_api import fixture


@pytest.mark.parametrize("phase", PHASES)
@pytest.mark.parametrize(
    "elapsed,passes", [(299.999999, True), (300, True), (300.000001, False), (3600, False)]
)
def test_status_collection_deadline_uses_external_boundary_without_tolerance(
    phase: str, elapsed: float, passes: bool
) -> None:
    contract, snapshot = fixture()
    snapshot["phase"] = phase
    since = snapshot["completed_at"] - elapsed
    result = check(contract, snapshot, since=since, phase=phase)
    assert result["recorded_health_passed"] is passes
    assert result["critical_health_passed"] is passes
    assert ("checkpoint-window-invalid" in result["blockers"]) is not passes
    assert result["mutation_available"] is False
    assert result["native_qualified"] is False


@pytest.mark.parametrize("recorded_start", [NOW - 20, NOW - 11])
def test_shorter_self_reported_capture_cannot_restart_the_original_budget(
    recorded_start: float,
) -> None:
    contract, snapshot = fixture()
    snapshot["started_at"] = recorded_start
    # All checks and timestamps are fresh and consistent. Only the independent
    # refresh boundary reveals that collection missed its original deadline.
    result = check(contract, snapshot, since=NOW - 3600)
    assert result["blockers"] == ["checkpoint-window-invalid"]
    assert result["recorded_health_passed"] is False
    assert result["critical_health_passed"] is False


def test_legacy_contract_keeps_its_original_recording_duration_semantics() -> None:
    contract, snapshot = legacy_fixture()
    result = check(contract, snapshot, since=NOW - 3600)
    assert result["schema_version"] == 1
    assert result["recorded_health_passed"] is True


def test_collection_deadline_is_separate_from_evaluation_freshness() -> None:
    contract, snapshot = fixture()
    # Capture finishes inside its budget. Evaluation later remains valid while
    # the recorded checks still meet their independently enforced maximum age.
    since = snapshot["completed_at"] - 300
    result = check(contract, snapshot, since=since, now=NOW + 100)
    assert result["recorded_health_passed"] is True
    assert result["critical_health_passed"] is True


@pytest.mark.parametrize("elapsed,exit_code", [(300, 0), (301, 1)])
def test_cli_honours_original_status_collection_deadline(
    elapsed: float, exit_code: int, tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    contract, snapshot = fixture()
    contract_file, snapshot_file = tmp_path / "contract.json", tmp_path / "snapshot.json"
    contract_file.write_bytes(canonical_bytes(contract) + b"\n")
    snapshot_file.write_bytes(canonical_bytes(snapshot) + b"\n")
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
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
        str(snapshot["completed_at"] - elapsed),
    ]
    assert main(argv) == exit_code
    result = json.loads(capsys.readouterr().out)
    assert result["recorded_health_passed"] is (exit_code == 0)
    assert result["critical_health_passed"] is (exit_code == 0)
    assert result["provenance_authenticated"] is False
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before

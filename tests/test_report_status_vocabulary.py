"""An unproven requirement reads ``unverified``; outputs that carry a status are version 2."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from netorch import host_cli
from netorch.codec import canonical_bytes
from netorch.host_report import build_report, empty_evidence
from netorch.instance import load_instance

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
NOW = 1000.0
STATUSES = frozenset(
    {"fulfilled-verified", "unverified", "accepted-residual", "not-applicable", "not-fulfilled"}
)
# The outputs that print a status moved to 2 when the word changed; the others did not.
SCHEMA_VERSIONS = {"validate": 1, "preflight": 1, "status": 2, "plan": 2, "check": 2, "report": 2}


def carried(value: Any) -> set[str]:
    """Every text stored under a member named ``status``, at any depth."""
    found: set[str] = set()
    if isinstance(value, dict):
        if isinstance(value.get("status"), str):
            found.add(value["status"])
        for member in value.values():
            found |= carried(member)
    elif isinstance(value, list):
        for member in value:
            found |= carried(member)
    return found


def without_evidence(variant: str) -> dict[str, Any]:
    instance = load_instance(EXAMPLES / variant)
    return build_report(instance, empty_evidence(NOW), now=NOW, data_directory=EXAMPLES)


@pytest.mark.parametrize(
    "requirement", ["HEARD-AUDIO", "RESTORE-REHEARSAL", "OWNER-ROLLBACK", "UDP-FIRST-PACKET"]
)
def test_requirement_nobody_has_proven_is_unverified(requirement: str) -> None:
    result = without_evidence("instance.json")
    row = next(item for item in result["requirements"] if item["id"] == requirement)
    assert row["status"] == "unverified"


@pytest.mark.parametrize("variant", ["instance.json", "instance-structural.json"])
def test_only_a_verified_row_is_called_fulfilled(variant: str) -> None:
    result = without_evidence(variant)
    statuses = [row["status"] for row in result["requirements"]]
    assert set(statuses) <= STATUSES and "unverified" in statuses
    assert {status for status in statuses if status.startswith("fulfilled")} == {
        "fulfilled-verified"
    }


@pytest.mark.parametrize("command", host_cli.COMMANDS)
def test_output_that_carries_a_status_has_schema_version_two(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    data = json.loads((EXAMPLES / "instance.json").read_bytes())
    # A signed bounded decision gives the return profile a safety assessment in every
    # output that lists profiles.
    data["decisions"]["bounded"] = [
        {
            "profile": "example-return",
            "max_age_seconds": 30,
            "unknown_limit": 3,
            "residual": "The shared address pool has residual reuse risk.",
            "signed_by": "example-reviewer",
            "signed_at": "1970-01-01T00:15:00Z",
        }
    ]
    target = tmp_path / "instance.json"
    target.write_bytes(canonical_bytes(data) + b"\n")
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    host_cli.main([command, "--instance", str(target), "--data-dir", str(EXAMPLES)], now=NOW)
    result = json.loads(capsys.readouterr().out)
    statuses = carried(result)
    assert result["schema_version"] == SCHEMA_VERSIONS[command]
    assert bool(statuses) is (result["schema_version"] == 2)
    assert statuses <= STATUSES
    if command == "plan":
        assert statuses == {"unverified"}

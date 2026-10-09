"""Offline fault injection for retained CLI internals; native gates stay closed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netorch import cli
from netorch.storage import Store
from netorch.workflow_gate import NOT_QUALIFIED


@pytest.mark.parametrize("phase", [["planned"], {"phase": "planned"}])
def test_malformed_journal_phase_is_a_closed_refusal_not_a_traceback(
    phase: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    store = Store(tmp_path / "state")
    store.write("journal.json", {"schema_version": 1, "plan_digest": "a" * 64, "phase": phase})
    before = (store.directory / "journal.json").read_bytes()
    arguments = [
        "acknowledge-journal",
        "--state-dir",
        str(store.directory),
        "--plan-digest",
        "a" * 64,
    ]
    assert cli.main(arguments) == NOT_QUALIFIED
    assert json.loads(capsys.readouterr().out)["error"] == "stage-not-qualified"
    # Reach only the retained internal behavior, never a production mutation path.
    monkeypatch.setattr(cli, "require_mutation_qualified", lambda stage: None)
    assert cli.main(arguments) == 65
    assert json.loads(capsys.readouterr().out) == {
        "error": "invalid-or-unverified",
        "message": "operation stopped; inspect private inputs and owner evidence",
    }
    assert (store.directory / "journal.json").read_bytes() == before

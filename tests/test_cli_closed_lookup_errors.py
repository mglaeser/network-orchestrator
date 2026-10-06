"""An unknown identifier on the command line gets the closed diagnostic, not a traceback."""

from __future__ import annotations

from pathlib import Path

import pytest

from netorch import cli
from netorch.codec import canonical_bytes, strict_loads

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
CLOSED = {
    "error": "invalid-or-unverified",
    "message": "operation stopped; inspect private inputs and owner evidence",
}


def test_unknown_profile_gets_the_closed_diagnostic(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(
        ["review-admission", "--config", str(EXAMPLES / "network.json"), "--profile", "no-such"]
    )
    captured = capsys.readouterr()
    assert code == 65
    assert strict_loads(captured.out) == CLOSED
    assert "no-such" not in captured.out and captured.err == ""


def test_binding_for_an_unknown_owner_gets_the_closed_diagnostic(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bindings = tmp_path / "bindings.json"
    bindings.write_bytes(
        canonical_bytes(
            {
                "schema_version": 1,
                "owners": [{"id": "no-such-owner", "kind": "process", "argv": ["/protected/tool"]}],
            }
        )
    )
    bindings.chmod(0o600)
    code = cli.main(
        ["observe", "--config", str(EXAMPLES / "network.json"), "--bindings", str(bindings)]
    )
    captured = capsys.readouterr()
    assert code == 65
    assert strict_loads(captured.out) == CLOSED
    assert "no-such-owner" not in captured.out and captured.err == ""

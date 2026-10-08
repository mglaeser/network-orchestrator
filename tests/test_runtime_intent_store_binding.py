"""A separate unpaused file must never replace the operator store's pause."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.codec import canonical_bytes
from netorch.state import Intent, intent_to_dict
from netorch.storage import Store, UnsafeState
from tests.test_apple_runtime import FakeRunner, enrolled

__all__ = ["enrolled"]


def test_recovery_reads_only_the_intent_that_its_operation_lock_protects(enrolled: Any) -> None:
    config, settings, items = enrolled
    store = Store(Path(settings.state_dir))
    store.write("intent.json", intent_to_dict(Intent().pause()))
    # A genuine private file, but outside the state store: it is not operator intent.
    other = store.directory.parent / "other-intent.json"
    other.write_bytes(canonical_bytes(intent_to_dict(Intent())))
    other.chmod(0o600)
    settings = replace(settings, intent=str(other))
    runner = FakeRunner(settings, items)
    runner.items["example-camera"]["status"]["state"] = "stopped"
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert not any(argv[1:2] == ["start"] for argv, _ in runner.calls)
    assert runtime._intent(settings).damaged


def test_start_cli_redacts_an_unsafe_state_directory(
    enrolled: Any, monkeypatch: Any, capsys: Any
) -> None:
    config, settings, _ = enrolled
    monkeypatch.setattr(runtime, "load_settings", lambda _: settings)
    monkeypatch.setattr(runtime, "load_config", lambda _: config)
    monkeypatch.setattr(runtime, "require_mutation_qualified", lambda _: None)

    def refused(*args: Any, **kwargs: Any) -> None:
        raise UnsafeState("private path must not be printed")

    monkeypatch.setattr(runtime, "recover_service", refused)
    assert runtime.main(["--settings", "/unused", "start", "--service", "camera"]) == 69
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == '{"error":"runtime-evidence-or-authority-incomplete"}\n'

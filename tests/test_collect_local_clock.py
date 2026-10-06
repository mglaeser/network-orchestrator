"""Facts collected by --collect-local are judged against a clock read after collection."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from netorch import host_cli
from netorch import macos_preflight as preflight

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
INSTANCE = str(EXAMPLES / "instance.json")


class Ticker:
    """A wall clock that advances one second on every read."""

    def __init__(self, start: float = 1000.0) -> None:
        self.value = start

    def __call__(self) -> float:
        self.value += 1.0
        return self.value


def collector_stamping(clock: Ticker) -> Any:
    def collector(instance: Any) -> dict[str, Any]:
        observed_at = clock()
        return {
            "schema_version": 1,
            "source": "local-collector",
            "observed_at": observed_at,
            "facts": [
                {
                    "key": key,
                    "state": "present",
                    "reason": "complete",
                    "observed_at": clock(),
                    "value": value,
                }
                for key, value in (("macos_version", "27.0.1"), ("macos_build", "26A434"))
            ],
            "profiles": [],
        }

    return collector


def facts(output: str) -> dict[str, dict[str, Any]]:
    return {item["key"]: item for item in json.loads(output.splitlines()[-1])["facts"]}


@pytest.mark.parametrize("command", ["preflight", "status", "report"])
def test_collected_facts_are_not_discarded_as_future_dated(
    command: str, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    clock = Ticker()
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(host_cli, "time", SimpleNamespace(time=clock))

    assert (
        host_cli.main(
            [command, "--collect-local", "--instance", INSTANCE],
            collector=collector_stamping(clock),
        )
        == 0
    )
    rows = facts(capsys.readouterr().out)
    for key, value in (("macos_version", "27.0.1"), ("macos_build", "26A434")):
        assert (rows[key]["state"], rows[key]["reason"], rows[key]["value"]) == (
            "present",
            "complete",
            value,
        )
        assert rows[key]["age_seconds"] is not None and rows[key]["age_seconds"] >= 0


def test_report_keeps_the_collectors_own_reason(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """Off macOS the bundled collector says `unsupported`; the report must not rewrite it."""
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight.sys, "platform", "linux")

    assert host_cli.main(["preflight", "--collect-local", "--instance", INSTANCE]) == 0
    rows = facts(capsys.readouterr().out)
    assert rows["macos_build"]["state"] == "unknown"
    assert rows["macos_build"]["reason"] == "unsupported"


def test_injected_report_clock_is_still_authoritative(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """A caller-supplied `now` earlier than the facts keeps them contradictory."""
    clock = Ticker()
    monkeypatch.setattr(os, "geteuid", lambda: 501)

    assert (
        host_cli.main(
            ["preflight", "--collect-local", "--instance", INSTANCE],
            collector=collector_stamping(clock),
            now=999.0,
        )
        == 0
    )
    rows = facts(capsys.readouterr().out)
    assert (rows["macos_build"]["state"], rows["macos_build"]["reason"]) == (
        "unknown",
        "contradictory",
    )

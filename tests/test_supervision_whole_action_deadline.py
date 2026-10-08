"""A vendor call timeout is not a budget for the complete recovery action."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netorch import apple_runtime as runtime
from netorch.instance import retained_supervision_gaps
from tests.test_apple_runtime import enrolled
from tests.test_report_truthfulness import parsed
from tests.test_runtime_start_timeout import START, stopped_camera

__all__ = ["enrolled"]


@pytest.mark.parametrize("seconds", [40, 120])
def test_successful_start_can_exceed_whole_action_deadline(enrolled, monkeypatch, seconds):
    config, settings, runner, clock = stopped_camera(
        enrolled, monkeypatch, seconds, start_takes=seconds - 0.5
    )

    def timed_reads(argv, **kwargs):
        # Three separate bounded observations occur outside the vendor call's
        # budget. Each consumes only one second and stays within its own limit.
        if argv[1:] == ["--version"]:
            clock[0] += 1
        return runner(argv, **kwargs)

    actual = runtime.recover_service(config, settings, "camera", timed_reads)
    assert actual.services["camera"].state == "present"
    assert runner.bounds(settings.executable)[0] == [seconds]
    assert clock[0] - START == seconds + 2.5

    data = json.loads((Path(__file__).resolve().parents[1] / "examples/instance.json").read_bytes())
    data["supervision"]["action_timeout_seconds"] = seconds
    data["workloads"][0]["deadlines"] = {"action_seconds": seconds}
    assert retained_supervision_gaps(parsed(data)) == (
        "/supervision/action_timeout_seconds",
        "/workloads/0/deadlines/action_seconds",
    )

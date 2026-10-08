"""A retained peer cannot use an API-reset stopped row to bypass the writer guard."""

from __future__ import annotations

from typing import Any

import pytest

from netorch import apple_runtime as runtime
from tests.test_apple_runtime import enrolled
from tests.test_runtime_fleet_start import declared, starts
from tests.test_runtime_tolerated_stopped_peer import RETAINED, retain, tolerating

__all__ = ["enrolled"]


@pytest.mark.parametrize("domain", ["gui", "user"])
def test_loaded_retained_peer_job_is_not_a_proven_stopped_writer(
    enrolled: Any, domain: str
) -> None:
    config, settings, runner = declared(enrolled)
    retain(runner)
    runner.items[RETAINED]["configuration"]["id"] = RETAINED
    runner.jobs.setdefault(f"{domain}/{settings.account.uid}", set()).add(RETAINED)
    config, settings = tolerating(config, settings, "camera", RETAINED)
    result = runtime.observe_runtime(config, settings, runner)
    assert result.services["camera"].state == "unknown"
    runner.items["example-camera"]["status"]["state"] = "stopped"
    runner.jobs[runner.domain].discard("example-camera")
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert starts(runner) == []


def test_tolerance_without_independent_job_evidence_cannot_verify_a_writer(enrolled: Any) -> None:
    from tests.test_apple_runtime import FakeRunner

    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    retain(runner)
    config, settings = tolerating(config, settings, "camera", RETAINED)
    from netorch.process import Result

    def unavailable(argv: list[str], **kwargs: Any) -> Result:
        if argv[:2] == ["/bin/launchctl", "print"] and argv[2].endswith("." + RETAINED):
            return Result(1, b"", b"unavailable")
        return runner(argv, **kwargs)

    result = runtime.observe_runtime(config, settings, unavailable)
    assert result.services["camera"].state == "unknown"
    assert result.services["resolver"].state == "present"


@pytest.mark.parametrize(
    "member,value",
    [("id", "example-other"), ("runtimeHandler", None), ("runtimeHandler", "Other.Runtime")],
)
def test_retained_peer_identity_must_name_the_job_being_proved(
    enrolled: Any, member: str, value: Any
) -> None:
    config, settings, runner = declared(enrolled)
    retain(runner)
    runner.items[RETAINED]["configuration"][member] = value
    config, settings = tolerating(config, settings, "camera", RETAINED)
    result = runtime.observe_runtime(config, settings, runner)
    assert result.services["camera"].state == "unknown"

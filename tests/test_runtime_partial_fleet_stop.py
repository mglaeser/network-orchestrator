"""An API-reset stopped row is not authority, even in a partly running fleet."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.process import Result
from tests.test_apple_runtime import enrolled
from tests.test_runtime_fleet_start import declared, starts

__all__ = ["enrolled"]


def partial(enrolled: Any, domain: str) -> tuple[Any, Any, Any]:
    config, settings, runner = declared(enrolled)
    settings = replace(settings, fleet_start=None)
    runner.items["example-camera"]["status"]["state"] = "stopped"
    runner.jobs = {f"{domain}/{settings.account.uid}": {"example-camera"}}
    assert runner.items["example-resolver"]["status"]["state"] == "running"
    return config, settings, runner


@pytest.mark.parametrize("domain", ["gui", "user"])
def test_partial_fleet_cannot_call_a_surviving_runtime_job_stopped(
    enrolled: Any, domain: str
) -> None:
    config, settings, runner = partial(enrolled, domain)
    result = runtime.observe_runtime(config, settings, runner)
    assert result.services["camera"].state == "unknown"
    assert result.services["resolver"].state == "present"


@pytest.mark.parametrize("domain", ["gui", "user"])
def test_recovery_cannot_start_api_reset_guest_in_partial_fleet(enrolled: Any, domain: str) -> None:
    config, settings, runner = partial(enrolled, domain)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert starts(runner) == []


@pytest.mark.parametrize("result", [Result(1, b"", b"unavailable"), Result(0, b"", b"")])
def test_partial_fleet_unknown_service_manager_read_never_authorizes_start(
    enrolled: Any, result: Result
) -> None:
    config, settings, runner = partial(enrolled, "gui")
    runner.job_print = result
    assert runtime.observe_runtime(config, settings, runner).services["camera"].state == "unknown"
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert starts(runner) == []


def test_partial_fleet_with_absent_job_can_recover_without_fleet_opt_in(enrolled: Any) -> None:
    config, settings, runner = partial(enrolled, "gui")
    runner.jobs = {}
    assert runtime.observe_runtime(config, settings, runner).services["camera"].state == "absent"
    assert (
        runtime.recover_service(config, settings, "camera", runner).services["camera"].state
        == "present"
    )
    assert starts(runner) == ["example-camera"]

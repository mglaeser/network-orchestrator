"""What `restart_budget` bounds: the guarded start of a workload, not the vendor runtime's.

The deployment guide says that a budget of starts belongs to the guarded start
and that, once it is spent, the probe no longer returns 42. That holds for a
workload (`recover_service` spends the budget; `test_runtime_restart_budget.py`).
`runtime-start` does not read the budget: a runtime monitor that repeats its
rule gets one more vendor start on every firing while the probe returns 42,
whether the starts fail or the runtime comes up and stops again. Everything
native is the fake of the existing runtime-start tests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.process import Result
from netorch.runtime_settings import parse_settings, settings_to_dict
from tests.test_apple_runtime import enrolled
from tests.test_runtime_start_vendor_runtime import World, command

__all__ = ["enrolled"]


def budgeted(enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    """The fake world with settings that declare a budget of one start in 600 seconds."""
    # The user database of the machine that runs the tests is no part of this test.
    monkeypatch.setattr(runtime, "_listed_home", lambda _uid: None)
    world = World(enrolled, tmp_path)
    world.settings = world.runner.settings = parse_settings(
        {**settings_to_dict(world.settings), "restart_budget": {"starts": 1, "window_seconds": 600}}
    )
    return world


def test_runtime_start_does_not_spend_the_restart_budget(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = budgeted(enrolled, tmp_path, monkeypatch)
    # A runtime that does not come up: the vendor's start fails and loads no job.
    world.runner.start_answer = Result(1, b"", b"failed\n")
    world.runner.after_start = lambda: setattr(world.runner, "job", None)

    for firing in range(1, 4):
        assert command(monkeypatch, world, "runtime-probe") == runtime.STOPPED
        assert command(monkeypatch, world, "runtime-start") == runtime.UNKNOWN
        assert world.vendor_calls() == [world.start_arguments()] * firing
    # A budget of one start, and still the probe answers 42 after three.
    assert command(monkeypatch, world, "runtime-probe") == runtime.STOPPED


def test_runtime_start_that_comes_up_does_not_spend_the_restart_budget_either(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = budgeted(enrolled, tmp_path, monkeypatch)

    for firing in range(1, 4):
        # The runtime stopped again: no job is loaded.
        world.runner.job = None
        assert command(monkeypatch, world, "runtime-probe") == runtime.STOPPED
        assert command(monkeypatch, world, "runtime-start") == 0
        # The vendor's start loaded the job: the runtime came up.
        assert world.runner.job is not None
        assert world.vendor_calls() == [world.start_arguments()] * firing

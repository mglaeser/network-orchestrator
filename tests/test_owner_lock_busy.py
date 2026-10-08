"""A busy lock is a bounded wait: for the root installer and for the workload start.

No test here sleeps. The clock and the sleep are injected, so every bound is
counted exactly.
"""

from __future__ import annotations

import contextlib
import copy
import inspect
import time
from pathlib import Path
from typing import Any

import pytest

import netorch.apple_runtime as runtime
import netorch.deployment as implementation
from netorch.deployment import install_bundle, recover_install, rollback_install
from netorch.deployment_config import DeploymentError
from netorch.process import Result
from netorch.state import intent_from_dict
from netorch.storage import Busy, Store
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest
from tests.test_full_deployment import IntegratedTools, setup_forwarding

__all__ = ["config", "enrolled", "fake_platform", "manifest"]


class Clock:
    """Time only passes when the code under test sleeps."""

    def __init__(self) -> None:
        self.now = 100.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


class BusyOwner(IntegratedTools):
    """The owner's scheduled pass holds its lock while some owner commands arrive.

    A busy owner command exits 75 and does nothing, as `pf_owner.main` does
    when it cannot take the lock. Every other call reaches the real owner
    functions of the integration lab.
    """

    def __init__(self) -> None:
        super().__init__()
        self.operation = ""
        self.remaining: int | None = 0
        self.status = 75
        self.refused: list[tuple[str, ...]] = []

    def busy(self, operation: str, times: int | None, status: int = 75) -> None:
        self.operation, self.remaining, self.status = operation, times, status

    def __call__(self, argv: tuple[str, ...]) -> Result:
        if self.remaining != 0 and "netorch.pf_owner" in argv and self.operation in argv:
            if self.remaining is not None:
                self.remaining -= 1
            self.calls.append(argv)
            self.refused.append(argv)
            return Result(self.status, b"", b"")
        return super().__call__(argv)


def root_label(manifest: dict[str, Any]) -> str:
    return str(manifest["jobs"][1]["label"])


@pytest.mark.parametrize("operation", ["install", "suspend", "withdraw", "release"])
@pytest.mark.parametrize("times", [1, 4])
def test_root_install_waits_out_a_busy_owner_command(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    times: int,
) -> None:
    setup_forwarding(manifest, monkeypatch)
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    tools, clock = BusyOwner(), Clock()
    tools.busy(operation, times)
    result = install_bundle(
        bundle,
        "root",
        expected_digest=metadata["bundle_digest"],
        runner=tools,
        clock=clock,
        sleep=clock.sleep,
    )
    assert result["phase"] == "committed"
    assert clock.slept == [implementation.OWNER_BUSY_RETRY_SECONDS] * times
    assert len(tools.refused) == times and all(operation in argv for argv in tools.refused)
    store = Store(Path(manifest["root"]["state_directory"]))
    assert store.read("installation-journal.json")["phase"] == "committed"
    assert tools.loaded == {root_label(manifest)}
    owner = Store(Path(manifest["forwarding"]["directory"]))
    assert not intent_from_dict(owner.read("operator-intent.json")).suspensions


def test_owner_busy_beyond_the_bound_fails_in_its_phase_after_a_counted_wait(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup_forwarding(manifest, monkeypatch)
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    digest = metadata["bundle_digest"]
    tools, clock = BusyOwner(), Clock()
    tools.busy("release", None)
    with pytest.raises(DeploymentError, match="managed tool operation failed"):
        install_bundle(
            bundle, "root", expected_digest=digest, runner=tools, clock=clock, sleep=clock.sleep
        )
    # Ten repeats half a second apart: five seconds, then the old outcome.
    assert clock.slept == [0.5] * 10
    assert sum(clock.slept) == implementation.OWNER_BUSY_WAIT_SECONDS == 5.0
    assert len(tools.refused) == 11
    state_dir = Path(manifest["root"]["state_directory"])
    journal = Store(state_dir).read("installation-journal.json")
    assert (journal["phase"], journal["failed_phase"]) == ("failed", "starting-jobs")
    owner = Store(Path(manifest["forwarding"]["directory"]))
    assert intent_from_dict(owner.read("operator-intent.json")).suspensions == {
        "installation": digest
    }
    # The documented next step is unchanged and waits the same way.
    tools.busy("withdraw", 2)
    clock.slept.clear()
    result = recover_install(
        state_dir,
        "root",
        expected_failed_digest=digest,
        runner=tools,
        clock=clock,
        sleep=clock.sleep,
    )
    assert result["phase"] == "rolled-back" and clock.slept == [0.5, 0.5]


@pytest.mark.parametrize("status", [1, 65, 69, 78])
def test_any_other_owner_status_is_fatal_at_once(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    setup_forwarding(manifest, monkeypatch)
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    tools = BusyOwner()
    tools.busy("release", None, status)
    with pytest.raises(DeploymentError, match="managed tool operation failed"):
        install_bundle(bundle, "root", expected_digest=metadata["bundle_digest"], runner=tools)
    assert len(tools.refused) == 1


@pytest.mark.parametrize("tool", ["-t", "bootout", "bootstrap", "print"])
def test_status_75_from_launchctl_or_monit_is_never_repeated(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None, tool: str
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    seen: list[tuple[str, ...]] = []
    tools = FakeTools()

    def runner(argv: tuple[str, ...]) -> Result:
        if tool in argv and (tool != "print" or tools.loaded):
            seen.append(argv)
            return Result(75, b"", b"")
        return tools(argv)

    with pytest.raises(DeploymentError):
        install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"], runner=runner)
    assert len(seen) == 1


def test_installer_with_its_default_clock_survives_a_busy_release(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The path the command line takes; only the pause between attempts is removed."""
    monkeypatch.setattr(implementation, "OWNER_BUSY_RETRY_SECONDS", 0.0, raising=False)
    setup_forwarding(manifest, monkeypatch)
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    tools = BusyOwner()
    # The job the installer has just loaded holds the owner's lock for one pass.
    tools.busy("release", 1)
    result = install_bundle(bundle, "root", expected_digest=metadata["bundle_digest"], runner=tools)
    assert result["phase"] == "committed" and len(tools.refused) == 1
    assert tools.loaded == {root_label(manifest)}


def test_root_rollback_waits_out_a_busy_owner_command(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup_forwarding(manifest, monkeypatch)
    newer = copy.deepcopy(manifest)
    newer["jobs"][1]["log_directory"] += "-v2"
    first, old = make_bundle(tmp_path, manifest, config, "first")
    second, new = make_bundle(tmp_path, newer, config, "second")
    tools, clock = BusyOwner(), Clock()
    for bundle, metadata in ((first, old), (second, new)):
        install_bundle(bundle, "root", expected_digest=metadata["bundle_digest"], runner=tools)
    tools.busy("suspend", 3)
    result = rollback_install(
        Path(manifest["root"]["state_directory"]),
        "root",
        expected_current_digest=new["bundle_digest"],
        runner=tools,
        clock=clock,
        sleep=clock.sleep,
    )
    assert result["release_id"] == old["release_id"] and clock.slept == [0.5] * 3


def test_the_command_line_uses_real_time() -> None:
    for function in (install_bundle, rollback_install, recover_install):
        parameters = inspect.signature(function).parameters
        assert parameters["clock"].default is time.monotonic
        assert parameters["sleep"].default is time.sleep
    parameters = inspect.signature(runtime.recover_service).parameters
    assert parameters["clock"].default is time.monotonic
    assert parameters["sleep"].default is time.sleep
    # Both waits are half of the 10-second example schedule.
    assert implementation.OWNER_BUSY_WAIT_SECONDS == runtime.START_LOCK_WAIT_SECONDS == 5.0


def stopped_camera(enrolled: Any) -> tuple[Any, Any, FakeRunner]:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    runner.items["example-camera"]["status"]["state"] = "stopped"
    return config, settings, runner


def test_start_waits_for_the_coordinator_pass_to_release_the_state_lock(enrolled: Any) -> None:
    config, settings, runner = stopped_camera(enrolled)
    clock = Clock()
    with contextlib.ExitStack() as coordinator:
        # netorch.executor.execute holds exactly this lock for its whole pass.
        coordinator.enter_context(Store(Path(settings.state_dir)).lock())

        def sleep(seconds: float) -> None:
            clock.sleep(seconds)
            if len(clock.slept) == 3:
                coordinator.close()

        result = runtime.recover_service(
            config, settings, "camera", runner, clock=clock, sleep=sleep
        )
    assert result.services["camera"].state == "present"
    assert clock.slept == [runtime.START_LOCK_RETRY_SECONDS] * 3
    assert sum(call[0][1:2] == ["start"] for call in runner.calls) == 1


def test_start_gives_up_after_a_counted_wait_and_touches_nothing(enrolled: Any) -> None:
    config, settings, runner = stopped_camera(enrolled)
    clock = Clock()
    with Store(Path(settings.state_dir)).lock(), pytest.raises(Busy):
        runtime.recover_service(config, settings, "camera", runner, clock=clock, sleep=clock.sleep)
    assert clock.slept == [0.25] * 20
    assert sum(clock.slept) == runtime.START_LOCK_WAIT_SECONDS
    assert runner.calls == []


def test_busy_raised_under_the_lock_is_not_mistaken_for_contention(tmp_path: Path) -> None:
    store, clock = Store(tmp_path / "state"), Clock()
    with pytest.raises(Busy, match="inside"), runtime._state_lock(store, clock, clock.sleep):
        raise Busy("inside")
    assert clock.slept == []
    with store.lock():
        pass


def test_start_command_reports_busy_as_75_with_a_closed_diagnostic(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The real entry point with its default clock; only the wait itself is removed."""
    config, settings, _items = enrolled
    monkeypatch.setattr(runtime, "START_LOCK_WAIT_SECONDS", 0.0, raising=False)
    monkeypatch.setattr(runtime, "require_mutation_qualified", lambda _capability: None)
    monkeypatch.setattr(runtime, "load_settings", lambda _path: settings)
    monkeypatch.setattr(runtime, "load_config", lambda _path: config)
    with Store(Path(settings.state_dir)).lock():
        code = runtime.main(["--settings", "/unused", "start", "--service", "camera"])
    captured = capsys.readouterr()
    assert code == 75
    assert captured.out == "" and captured.err == '{"error":"busy"}\n'

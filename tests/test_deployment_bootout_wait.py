"""A job that is loaded again is awaited after its `bootout`, bounded and never fatal.

No test here sleeps and none calls a native tool: the clock and the sleep are
injected (or the pause is set to zero), and launchd is a fake that keeps a job's
record for a chosen number of reads after `bootout` has returned. The one
exception is the hosted-macOS contract test at the end, which is skipped
everywhere else.
"""

from __future__ import annotations

import copy
import inspect
import os
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch.deployment import install_bundle, recover_install, rollback_install
from netorch.deployment_config import DeploymentError
from netorch.process import ProcessTimeout, Result
from netorch.state import intent_from_dict
from netorch.storage import Store
from tests.test_deployment import config, fake_platform, make_bundle, manifest

__all__ = ["config", "fake_platform", "manifest"]

# The contract, stated here and compared with the module in one test below.
BOUND = 20.0
POLL = 0.25
ABSENT = (3, 113)
# Reads that fit into the bound: one at once, then one after every pause.
READS_AT_BOUND = int(BOUND / POLL) + 1
FAILED = "managed tool operation failed; inspect installation journal"


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


class Launchd:
    """Fake launchctl (and Monit) whose job records can outlive their `bootout`.

    After a `bootout` that found a loaded job, the next `linger` reads of that
    job still find it (`None`: every read, for ever) and the read after those
    reports it absent. Until a read has reported it absent, a `bootstrap` of the
    same label is refused, unless `early_reload` says that this launchd would
    accept it.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.loaded: set[str] = set()
        self.leaving: dict[str, int | None] = {}
        self.linger: int | None = 0
        self.absent = 113
        self.found = 0
        self.early_reload = False
        self.fail: str | None = None
        self.unreadable: set[str] = set()
        self.read_error: Exception | None = None

    def __call__(self, argv: tuple[str, ...]) -> Result:
        self.calls.append(argv)
        if self.fail is not None and self.fail in argv:
            return Result(1, b"", b"")
        operation = argv[1]
        if operation == "bootout":
            label = argv[2].rsplit("/", 1)[1]
            if label not in self.loaded:
                return Result(self.absent, b"", b"")
            self.loaded.discard(label)
            if self.linger != 0:
                self.leaving[label] = self.linger
            return Result(0, b"", b"")
        if operation == "print":
            label = argv[2].rsplit("/", 1)[1]
            remaining = self.leaving.get(label, 0)
            if remaining == 0:
                self.leaving.pop(label, None)
            else:
                if remaining is not None:
                    self.leaving[label] = remaining - 1
                if self.read_error is not None:
                    raise self.read_error
                return Result(self.found, b"", b"")
            if label in self.loaded:
                return Result(1 if label in self.unreadable else 0, b"", b"")
            return Result(self.absent, b"", b"")
        if operation == "bootstrap":
            label = Path(argv[3]).stem
            if label in self.leaving and not self.early_reload:
                return Result(5, b"", b"")
            self.leaving.pop(label, None)
            self.loaded.add(label)
        return Result(0, b"", b"")

    def about(self, label: str) -> list[str]:
        """The launchctl operations that named this job, in order."""
        return [
            argv[1]
            for argv in self.calls
            if (argv[1] in {"bootout", "print"} and argv[2].rsplit("/", 1)[1] == label)
            or (argv[1] == "bootstrap" and Path(argv[3]).stem == label)
        ]


def label_of(manifest: dict[str, Any], scope: str) -> str:
    return str(manifest["jobs"][0 if scope == "user" else 1]["label"])


def changed(manifest: dict[str, Any], scope: str) -> dict[str, Any]:
    """The same jobs in a release with another identity."""
    newer = copy.deepcopy(manifest)
    if scope == "user":
        newer["jobs"][0]["interval_seconds"] = 15
    else:
        newer["jobs"][1]["log_directory"] += "-v2"
    return newer


def with_second_user_job(manifest: dict[str, Any], *, first: bool = False) -> dict[str, Any]:
    wider = copy.deepcopy(manifest)
    second = copy.deepcopy(wider["jobs"][0])
    second["label"] += "-second"
    second["role"] = "existing-manager"
    wider["jobs"].insert(0 if first else 1, second)
    return wider


def journal(manifest: dict[str, Any], scope: str) -> dict[str, Any]:
    value = Store(Path(manifest[scope]["state_directory"])).read("installation-journal.json")
    assert isinstance(value, dict)
    return value


def loaded_job(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    scope: str,
    operation: str,
    *,
    inject: bool = True,
) -> tuple[Launchd, Clock, Callable[[], dict[str, Any]]]:
    """Bring one scope to the point where `operation` replaces its loaded job.

    Returns the fake, a clock and a callable that runs the operation, with that
    clock unless `inject` is false. Nothing lingers while the state is prepared.
    """
    tools, clock = Launchd(), Clock()
    timing: dict[str, Any] = {"clock": clock, "sleep": clock.sleep} if inject else {}
    label = label_of(manifest, scope)
    state = Path(manifest[scope]["state_directory"])
    first, old = make_bundle(tmp_path, manifest, config, "first")
    install_bundle(first, scope, expected_digest=old["bundle_digest"], runner=tools)
    second, new = make_bundle(tmp_path, changed(manifest, scope), config, "second")
    if operation == "upgrade":

        def run() -> dict[str, Any]:
            return install_bundle(
                second, scope, expected_digest=new["bundle_digest"], runner=tools, **timing
            )

    elif operation == "rollback":
        install_bundle(second, scope, expected_digest=new["bundle_digest"], runner=tools)

        def run() -> dict[str, Any]:
            return rollback_install(
                state, scope, expected_current_digest=new["bundle_digest"], runner=tools, **timing
            )

    else:
        # The upgrade loads the new job and then cannot read it back, so the
        # recovery finds a loaded job that it has to replace.
        tools.unreadable = {label}
        with pytest.raises(DeploymentError, match=FAILED):
            install_bundle(second, scope, expected_digest=new["bundle_digest"], runner=tools)
        tools.unreadable = set()
        assert journal(manifest, scope)["failed_phase"] == "starting-jobs"

        def run() -> dict[str, Any]:
            return recover_install(
                state, scope, expected_failed_digest=new["bundle_digest"], runner=tools, **timing
            )

    assert tools.loaded == {label} and not tools.leaving
    tools.calls.clear()
    return tools, clock, run


OPERATIONS = ["upgrade", "rollback", "recover"]
FINISHED = {"upgrade": "committed", "rollback": "rolled-back", "recover": "rolled-back"}


@pytest.mark.parametrize("scope", ["user", "root"])
@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("reads", [1, 3, READS_AT_BOUND - 1])
def test_a_replaced_job_is_loaded_only_after_launchd_reports_it_gone(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    scope: str,
    operation: str,
    reads: int,
) -> None:
    tools, clock, run = loaded_job(tmp_path, manifest, config, scope, operation)
    label = label_of(manifest, scope)
    tools.linger = reads
    assert run()["phase"] == FINISHED[operation]
    # One pause after every read that still found the job, none after the first
    # read that did not, and the reload only after that read.
    assert clock.slept == [POLL] * reads
    assert tools.about(label) == ["bootout", *["print"] * (reads + 1), "bootstrap", "print"]
    assert tools.loaded == {label} and not tools.leaving
    assert journal(manifest, scope)["phase"] == FINISHED[operation]


@pytest.mark.parametrize("operation", OPERATIONS)
def test_the_command_line_path_waits_without_any_injection(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    # The real clock and the real sleep, with the pause set to zero.
    monkeypatch.setattr(implementation, "BOOTOUT_POLL_SECONDS", 0.0, raising=False)
    tools, _, run = loaded_job(tmp_path, manifest, config, "user", operation, inject=False)
    label = label_of(manifest, "user")
    tools.linger = 3
    assert run()["phase"] == FINISHED[operation]
    assert tools.about(label) == ["bootout", *["print"] * 4, "bootstrap", "print"]
    assert tools.loaded == {label}


@pytest.mark.parametrize("operation", OPERATIONS)
def test_a_job_that_is_gone_at_once_costs_one_read_and_no_pause(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None, operation: str
) -> None:
    tools, clock, run = loaded_job(tmp_path, manifest, config, "user", operation)
    assert run()["phase"] == FINISHED[operation]
    assert clock.slept == []
    assert tools.about(label_of(manifest, "user")) == ["bootout", "print", "bootstrap", "print"]


@pytest.mark.parametrize("scope", ["user", "root"])
@pytest.mark.parametrize("operation", OPERATIONS)
def test_at_the_bound_the_operation_goes_on_and_bootstrap_decides(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    scope: str,
    operation: str,
) -> None:
    tools, clock, run = loaded_job(tmp_path, manifest, config, scope, operation)
    label = label_of(manifest, scope)
    tools.linger = None
    # Exactly the outcome of the code without a wait: the reload is attempted,
    # launchd refuses it, and the operation fails where it failed before.
    with pytest.raises(DeploymentError, match=FAILED):
        run()
    assert sum(clock.slept) == BOUND == 20.0
    assert clock.slept == [POLL] * (READS_AT_BOUND - 1)
    assert tools.about(label) == ["bootout", *["print"] * READS_AT_BOUND, "bootstrap"]
    failed = journal(manifest, scope)
    assert failed["phase"] == "failed"
    # A failed recovery keeps the phase of the installation it tried to recover.
    expected = "rolling-back" if operation == "rollback" else "starting-jobs"
    assert failed["failed_phase"] == expected


@pytest.mark.parametrize("operation", OPERATIONS)
def test_at_the_bound_a_reload_that_launchd_accepts_still_succeeds(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None, operation: str
) -> None:
    tools, clock, run = loaded_job(tmp_path, manifest, config, "user", operation)
    tools.linger = None
    tools.early_reload = True
    assert run()["phase"] == FINISHED[operation]
    assert sum(clock.slept) == BOUND
    assert tools.loaded == {label_of(manifest, "user")}


def test_one_read_past_the_bound_is_never_made(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    tools, clock, run = loaded_job(tmp_path, manifest, config, "user", "upgrade")
    label = label_of(manifest, "user")
    # The record would go with the read after the last one the bound allows.
    tools.linger = READS_AT_BOUND
    with pytest.raises(DeploymentError, match=FAILED):
        run()
    assert sum(clock.slept) == BOUND
    assert tools.about(label).count("print") == READS_AT_BOUND
    assert tools.leaving == {label: 0}


@pytest.mark.parametrize("absent", ABSENT)
@pytest.mark.parametrize("operation", OPERATIONS)
def test_no_wait_and_no_read_when_bootout_reports_nothing_loaded(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    operation: str,
    absent: int,
) -> None:
    tools, _, run = loaded_job(tmp_path, manifest, config, "user", operation, inject=False)
    label = label_of(manifest, "user")
    # Someone unloaded the job by hand. Its record would linger for ever if it
    # were asked for, but `bootout` already said that there is none.
    tools.loaded.clear()
    tools.linger = None
    tools.absent = absent
    assert run()["phase"] == FINISHED[operation]
    # No read between the two, and a pause only ever follows a read.
    assert tools.about(label) == ["bootout", "bootstrap", "print"]


def test_first_installation_reads_each_label_once_before_and_once_after(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    tools = Launchd()
    tools.linger = None
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    result = install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"], runner=tools)
    assert result["phase"] == "committed"
    # Preflight read, bootout of nothing, load, readback.
    assert tools.about(label_of(manifest, "user")) == ["print", "bootout", "bootstrap", "print"]


@pytest.mark.parametrize("found", [0, 1, 36, -9])
@pytest.mark.parametrize("absent", ABSENT)
def test_only_the_two_absent_statuses_end_the_wait(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    found: int,
    absent: int,
) -> None:
    tools, clock, run = loaded_job(tmp_path, manifest, config, "user", "upgrade")
    tools.linger = 2
    tools.found = found
    tools.absent = absent
    assert run()["phase"] == "committed"
    # A status that is neither success nor "absent" is not read as "gone".
    assert clock.slept == [POLL, POLL]


@pytest.mark.parametrize(
    "error", [ProcessTimeout("read did not complete"), OSError("read could not start")]
)
@pytest.mark.parametrize("linger", [2, None])
def test_a_read_that_cannot_complete_never_fails_the_operation(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    error: Exception,
    linger: int | None,
) -> None:
    tools, clock, run = loaded_job(tmp_path, manifest, config, "user", "upgrade")
    tools.linger = linger
    tools.read_error = error
    tools.early_reload = True
    assert run()["phase"] == "committed"
    assert clock.slept == [POLL] * (2 if linger == 2 else READS_AT_BOUND - 1)
    assert journal(manifest, "user")["phase"] == "committed"


def test_a_failed_bootout_still_fails_at_once_without_a_wait(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    tools, _, run = loaded_job(tmp_path, manifest, config, "user", "upgrade", inject=False)
    tools.fail = "bootout"
    with pytest.raises(DeploymentError, match=FAILED):
        run()
    assert tools.about(label_of(manifest, "user")) == ["bootout"]
    assert journal(manifest, "user")["failed_phase"] == "stopping-jobs"


def test_upgrade_does_not_wait_for_a_job_the_new_release_drops(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    tools, clock = Launchd(), Clock()
    kept = label_of(manifest, "user")
    dropped = kept + "-second"
    first, old = make_bundle(tmp_path, with_second_user_job(manifest), config, "first")
    install_bundle(first, "user", expected_digest=old["bundle_digest"], runner=tools)
    second, new = make_bundle(tmp_path, changed(manifest, "user"), config, "second")
    assert tools.loaded == {kept, dropped}
    tools.calls.clear()
    tools.linger = 2
    result = install_bundle(
        second,
        "user",
        expected_digest=new["bundle_digest"],
        runner=tools,
        clock=clock,
        sleep=clock.sleep,
    )
    assert result["phase"] == "committed"
    # Only the job that is loaded again was read and waited for.
    assert tools.about(dropped) == ["bootout"]
    assert tools.about(kept) == ["bootout", "print", "print", "print", "bootstrap", "print"]
    assert clock.slept == [POLL, POLL]
    assert tools.loaded == {kept} and tools.leaving == {dropped: 2}


def test_rollback_does_not_wait_for_a_job_the_predecessor_lacks(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    tools, clock = Launchd(), Clock()
    kept = label_of(manifest, "user")
    added = kept + "-second"
    first, old = make_bundle(tmp_path, manifest, config, "first")
    install_bundle(first, "user", expected_digest=old["bundle_digest"], runner=tools)
    wider = with_second_user_job(changed(manifest, "user"))
    second, new = make_bundle(tmp_path, wider, config, "second")
    install_bundle(second, "user", expected_digest=new["bundle_digest"], runner=tools)
    assert tools.loaded == {kept, added}
    tools.calls.clear()
    tools.linger = 1
    result = rollback_install(
        Path(manifest["user"]["state_directory"]),
        "user",
        expected_current_digest=new["bundle_digest"],
        runner=tools,
        clock=clock,
        sleep=clock.sleep,
    )
    assert result["phase"] == "rolled-back"
    assert tools.about(added) == ["bootout"]
    assert tools.about(kept) == ["bootout", "print", "print", "bootstrap", "print"]
    assert clock.slept == [POLL]
    assert tools.loaded == {kept}


def test_recovery_does_not_wait_for_a_job_only_the_failed_release_has(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    tools = Launchd()
    kept = label_of(manifest, "user")
    added = kept + "-second"
    agents = Path(manifest["user"]["launchd_directory"])
    first, old = make_bundle(tmp_path, manifest, config, "first")
    install_bundle(first, "user", expected_digest=old["bundle_digest"], runner=tools)
    # The new release loads its additional job first; the reload of the job
    # both releases have then fails.
    wider = with_second_user_job(changed(manifest, "user"), first=True)
    second, new = make_bundle(tmp_path, wider, config, "second")
    tools.fail = str(agents / f"{kept}.plist")
    with pytest.raises(DeploymentError, match=FAILED):
        install_bundle(second, "user", expected_digest=new["bundle_digest"], runner=tools)
    tools.fail = None
    assert tools.loaded == {added}
    tools.calls.clear()
    tools.linger = None
    result = recover_install(
        Path(manifest["user"]["state_directory"]),
        "user",
        expected_failed_digest=new["bundle_digest"],
        runner=tools,
    )
    assert result["phase"] == "rolled-back"
    # The loaded job is only removed and the job that is restored was not loaded:
    # neither is read before the reload.
    assert tools.about(added) == ["bootout"]
    assert tools.about(kept) == ["bootout", "bootstrap", "print"]
    assert not (agents / f"{added}.plist").exists()


def test_recovery_of_a_first_installation_only_unloads_and_never_waits(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    tools = Launchd()
    label = label_of(manifest, "user")
    agents = Path(manifest["user"]["launchd_directory"])
    wider = with_second_user_job(manifest)
    bundle, metadata = make_bundle(tmp_path, wider, config)
    tools.fail = str(agents / f"{label}-second.plist")
    with pytest.raises(DeploymentError, match=FAILED):
        install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"], runner=tools)
    tools.fail = None
    assert tools.loaded == {label}
    tools.calls.clear()
    tools.linger = None
    result = recover_install(
        Path(manifest["user"]["state_directory"]),
        "user",
        expected_failed_digest=metadata["bundle_digest"],
        runner=tools,
    )
    assert result["phase"] == "rolled-back"
    # Nothing is loaded again, so the lingering record is never asked for.
    assert tools.about(label) == ["bootout"]
    assert not tools.loaded and not (agents / f"{label}.plist").exists()
    state = Store(Path(manifest["user"]["state_directory"]))
    assert not intent_from_dict(state.read("intent.json")).suspensions


@pytest.mark.parametrize("operation", [install_bundle, rollback_install, recover_install])
def test_callers_that_inject_nothing_get_the_monotonic_clock_and_the_stated_bounds(
    operation: Any,
) -> None:
    parameters = inspect.signature(operation).parameters
    assert parameters["clock"].default is time.monotonic
    assert parameters["sleep"].default is time.sleep
    assert parameters["clock"].kind is parameters["sleep"].kind is inspect.Parameter.KEYWORD_ONLY
    assert implementation.BOOTOUT_WAIT_SECONDS == BOUND
    assert implementation.BOOTOUT_POLL_SECONDS == POLL
    assert sorted(implementation._JOB_ABSENT) == list(ABSENT)


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
def test_launchctl_print_of_an_absent_job_exits_with_a_status_read_as_gone() -> None:
    """Read-only: asks launchd for a label that no job has, and changes nothing."""
    label = ".".join(["org", "example", "netorch", "bootout-wait", "no-such-job"])
    result = subprocess.run(
        ["/bin/launchctl", "print", f"user/{os.getuid()}/{label}"],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode in implementation._JOB_ABSENT

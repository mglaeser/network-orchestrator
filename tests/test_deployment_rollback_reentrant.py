"""A rollback that failed or was stopped is repeated; other journals are not its to replace.

The oracle for every repeated rollback is the state an uninterrupted rollback
of the same pair of releases leaves behind.
"""

from __future__ import annotations

import contextlib
import copy
import os
import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch.deployment import install_bundle, recover_install, rollback_install
from netorch.deployment_config import DeploymentError
from netorch.process import Result
from netorch.state import Intent, intent_from_dict, intent_to_dict
from netorch.storage import Store
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest
from tests.test_full_deployment import IntegratedTools, setup_forwarding

__all__ = ["config", "fake_platform", "manifest"]

Runner = Callable[[tuple[str, ...]], Result]


class Killed(BaseException):
    """The process is gone; no handler may write after this."""


class Steps:
    """Counts a rollback's own steps and stops the process before one of them."""

    def __init__(self, stop_before: int | None = None) -> None:
        self.count = 0
        self.stop_before = stop_before
        self.dead = False

    def __call__(self) -> None:
        if self.dead or self.count == self.stop_before:
            self.dead = True
            raise Killed
        self.count += 1


@contextlib.contextmanager
def stepped(
    monkeypatch: pytest.MonkeyPatch, steps: Steps, state_dir: Path, runner: Runner
) -> Iterator[Runner]:
    """Every journal, receipt or intent write, restored file and tool call is one step."""
    write = Store.write
    write_new = implementation._write_new

    def state_write(self: Store, name: str, value: Any) -> None:
        if self.directory == state_dir:
            steps()
        write(self, name, value)

    def file_write(path: Path, payload: bytes, mode: int = 0o600, **kwargs: Any) -> None:
        steps()
        write_new(path, payload, mode, **kwargs)

    def counted(argv: tuple[str, ...]) -> Result:
        steps()
        return runner(argv)

    with monkeypatch.context() as patch:
        patch.setattr(Store, "write", state_write)
        patch.setattr(implementation, "_write_new", file_write)
        yield counted


@pytest.fixture
def no_flush(monkeypatch: pytest.MonkeyPatch) -> None:
    """The sweeps model which steps happened, not durability; skip the disk flushes."""
    monkeypatch.setattr(os, "fsync", lambda descriptor: None)


def launchd(tools: FakeTools) -> Runner:
    """Like the lab's fake, but loading a label that is already loaded fails."""

    def runner(argv: tuple[str, ...]) -> Result:
        if len(argv) > 1 and argv[1] == "bootstrap" and Path(argv[-1]).stem in tools.loaded:
            tools.calls.append(argv)
            return Result(5, b"", b"")
        return tools(argv)

    return runner


def failing(runner: Runner, index: int) -> tuple[Runner, list[tuple[str, ...]]]:
    """Fail exactly the tool call with this index; it has no effect."""
    seen: list[tuple[str, ...]] = []

    def wrapped(argv: tuple[str, ...]) -> Result:
        seen.append(argv)
        if len(seen) - 1 == index:
            return Result(1, b"", b"")
        return runner(argv)

    return wrapped, seen


def releases(manifest: dict[str, Any], scope: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Two releases whose job labels differ: each has one job the other lacks."""
    old, new = copy.deepcopy(manifest), copy.deepcopy(manifest)
    if scope == "user":
        new["jobs"][0]["interval_seconds"] = 15
        for value, suffix in ((old, "-old"), (new, "-new")):
            extra = copy.deepcopy(value["jobs"][0])
            extra.update(
                label=extra["label"] + suffix,
                role="existing-manager",
                argv=["/protected/tool", "serve"],
                interval_seconds=None,
                keep_alive=True,
            )
            value["jobs"].append(extra)
    else:
        new["jobs"][1]["label"] += "-next"
        new["jobs"][1]["log_directory"] += "-next"
    return old, new


class Lab:
    """Two installed releases of one scope in the disposable namespace."""

    def __init__(
        self,
        tmp_path: Path,
        manifest: dict[str, Any],
        config: Any,
        scope: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        if scope == "root":
            setup_forwarding(manifest, monkeypatch)
        self.tmp_path = tmp_path
        self.scope = scope
        self.state_dir = Path(manifest[scope]["state_directory"])
        self.jobs = Path(manifest[scope]["launchd_directory"])
        self.owner = Path(manifest["forwarding"]["directory"])
        older, newer = releases(manifest, scope)
        self.first, self.old = make_bundle(tmp_path, older, config, "first")
        self.second, self.new = make_bundle(tmp_path, newer, config, "second")
        self.tools: FakeTools = FakeTools()

    def prepare(self) -> Runner:
        for entry in self.tmp_path.iterdir():
            if entry.name in {"first", "second", "settings.json", "backend.sh"}:
                continue
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
        self.tools = IntegratedTools() if self.scope == "root" else FakeTools()
        runner = launchd(self.tools)
        for bundle, metadata in ((self.first, self.old), (self.second, self.new)):
            install_bundle(
                bundle, self.scope, expected_digest=metadata["bundle_digest"], runner=runner
            )
        if self.scope == "user":
            Store(self.state_dir).write(
                "intent.json", intent_to_dict(Intent().pause().suspend("backup", "other"))
            )
        return runner

    def rollback(self, runner: Runner) -> dict[str, Any]:
        return rollback_install(
            self.state_dir,
            self.scope,
            expected_current_digest=self.new["bundle_digest"],
            runner=runner,
        )

    def state(self) -> dict[str, Any]:
        store = Store(self.state_dir)
        if self.scope == "user":
            intent = intent_from_dict(store.read("intent.json"))
        else:
            intent = intent_from_dict(Store(self.owner).read("operator-intent.json"))
        return {
            "journal": store.read("installation-journal.json")["phase"],
            "receipt": store.read("installation-receipt.json"),
            "jobs": {path.name: path.read_bytes() for path in sorted(self.jobs.iterdir())},
            "loaded": set(self.tools.loaded),
            "paused": intent.operator_paused,
            "holds": dict(intent.suspensions),
        }


def uninterrupted(lab: Lab) -> dict[str, Any]:
    runner = lab.prepare()
    assert lab.rollback(runner)["release_id"] == lab.old["release_id"]
    state = lab.state()
    assert state["journal"] == "rolled-back"
    assert state["receipt"]["bundle_digest"] == lab.old["bundle_digest"]
    assert state["loaded"] == {item["label"] for item in state["receipt"]["jobs"]}
    assert "installation" not in state["holds"]
    return state


@pytest.mark.parametrize("scope", ["user", "root"])
def test_rollback_failed_at_any_tool_call_is_repeated_to_the_same_result(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    no_flush: None,
    scope: str,
) -> None:
    lab = Lab(tmp_path, manifest, config, scope, monkeypatch)
    expected = uninterrupted(lab)
    counting, calls = failing(lab.prepare(), -1)
    lab.rollback(counting)
    assert len(calls) == (6 if scope == "user" else 7)
    journals: list[dict[str, Any]] = []
    for index, call in enumerate(calls):
        runner = lab.prepare()
        broken, _ = failing(runner, index)
        with pytest.raises(DeploymentError, match="managed tool operation failed"):
            lab.rollback(broken)
        journals.append(Store(lab.state_dir).read("installation-journal.json"))
        assert (journals[-1]["phase"], journals[-1]["failed_phase"]) == ("failed", "rolling-back")
        assert lab.rollback(runner)["phase"] == "rolled-back", call
        assert lab.state() == expected, call
    # What makes the repeat possible: the failed journal names the exact pair.
    for journal in journals:
        assert journal["scope"] == scope
        assert journal["from_bundle_digest"] == lab.new["bundle_digest"]
        assert journal["to_bundle_digest"] == lab.old["bundle_digest"]


@pytest.mark.parametrize("scope", ["user", "root"])
def test_rollback_killed_before_any_step_is_repeated_to_the_same_result(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    no_flush: None,
    scope: str,
) -> None:
    lab = Lab(tmp_path, manifest, config, scope, monkeypatch)
    expected = uninterrupted(lab)
    steps = Steps()
    with stepped(monkeypatch, steps, lab.state_dir, lab.prepare()) as counted:
        lab.rollback(counted)
    assert steps.count == (13 if scope == "user" else 11)
    for stop_before in range(steps.count):
        runner = lab.prepare()
        with (
            stepped(monkeypatch, Steps(stop_before), lab.state_dir, runner) as counted,
            pytest.raises(Killed),
        ):
            lab.rollback(counted)
        assert lab.rollback(runner)["phase"] == "rolled-back", stop_before
        assert lab.state() == expected, stop_before


@pytest.mark.parametrize("scope", ["user", "root"])
def test_interrupted_rollback_is_recorded_as_failed_and_repeated(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
) -> None:
    lab = Lab(tmp_path, manifest, config, scope, monkeypatch)
    expected = uninterrupted(lab)
    runner = lab.prepare()

    def interrupted(argv: tuple[str, ...]) -> Result:
        if "bootstrap" in argv:
            raise KeyboardInterrupt
        return runner(argv)

    with pytest.raises(KeyboardInterrupt):
        lab.rollback(interrupted)
    journal = Store(lab.state_dir).read("installation-journal.json")
    assert (journal["phase"], journal["failed_phase"]) == ("failed", "rolling-back")
    assert lab.rollback(runner)["phase"] == "rolled-back"
    assert lab.state() == expected


class FailedUpgrade:
    """Three releases; the upgrade to the third failed at launchd bootstrap."""

    def __init__(
        self,
        tmp_path: Path,
        manifest: dict[str, Any],
        config: Any,
        scope: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        if scope == "root":
            setup_forwarding(manifest, monkeypatch)
        self.scope = scope
        self.state_dir = Path(manifest[scope]["state_directory"])
        self.owner = Path(manifest["forwarding"]["directory"])
        self.tools: FakeTools = IntegratedTools() if scope == "root" else FakeTools()
        self.fail_bootstrap = False

        def release(number: int) -> dict[str, Any]:
            value = copy.deepcopy(manifest)
            if scope == "user":
                value["jobs"][0]["interval_seconds"] = 10 + 5 * number
            elif number:
                value["jobs"][1]["log_directory"] += f"-v{number}"
            return value

        bundles = [make_bundle(tmp_path, release(n), config, f"v{n}") for n in range(3)]
        self.digests = [metadata["bundle_digest"] for _, metadata in bundles]
        self.release_ids = [metadata["release_id"] for _, metadata in bundles]
        for bundle, metadata in bundles[:2]:
            install_bundle(
                bundle, scope, expected_digest=metadata["bundle_digest"], runner=self.runner
            )
        self.fail_bootstrap = True
        with pytest.raises(DeploymentError):
            install_bundle(
                bundles[2][0], scope, expected_digest=self.digests[2], runner=self.runner
            )
        self.fail_bootstrap = False
        self.third = bundles[2][0]

    def runner(self, argv: tuple[str, ...]) -> Result:
        if self.fail_bootstrap and len(argv) > 1 and argv[1] == "bootstrap":
            self.tools.calls.append(argv)
            return Result(1, b"", b"")
        return self.tools(argv)

    def holds(self) -> dict[str, str]:
        if self.scope == "user":
            return dict(intent_from_dict(Store(self.state_dir).read("intent.json")).suspensions)
        return dict(intent_from_dict(Store(self.owner).read("operator-intent.json")).suspensions)


@pytest.mark.parametrize("scope", ["user", "root"])
def test_rollback_leaves_a_failed_installation_journal_byte_identical(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
) -> None:
    lab = FailedUpgrade(tmp_path, manifest, config, scope, monkeypatch)
    path = lab.state_dir / "installation-journal.json"
    before = path.read_bytes()
    failed = Store(lab.state_dir).read("installation-journal.json")
    assert (failed["phase"], failed["bundle_digest"]) == ("failed", lab.digests[2])
    assert lab.holds() == {"installation": lab.digests[2]}
    calls = len(lab.tools.calls)
    # `rollback` takes the same options as `recover`; the digest of the release
    # still recorded as current is the natural wrong argument.
    with pytest.raises(ValueError) as refusal:
        rollback_install(
            lab.state_dir, scope, expected_current_digest=lab.digests[1], runner=lab.runner
        )
    assert path.read_bytes() == before
    assert len(lab.tools.calls) == calls
    assert lab.holds() == {"installation": lab.digests[2]}
    assert isinstance(refusal.value, DeploymentError)
    assert "unfinished installation" in str(refusal.value)
    # The command that was meant still works.
    result = recover_install(
        lab.state_dir, scope, expected_failed_digest=lab.digests[2], runner=lab.runner
    )
    assert result["release_id"] == lab.release_ids[1]
    assert "installation" not in lab.holds()


def failed_rollback(lab: Lab) -> Runner:
    runner = lab.prepare()
    broken, seen = failing(runner, -1)
    lab.rollback(broken)
    last_bootstrap = max(index for index, argv in enumerate(seen) if "bootstrap" in argv)
    runner = lab.prepare()
    broken, _ = failing(runner, last_bootstrap)
    with pytest.raises(DeploymentError):
        lab.rollback(broken)
    return runner


def test_failed_rollback_is_not_recovered_installed_over_or_rolled_back_by_another_digest(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab = Lab(tmp_path, manifest, config, "user", monkeypatch)
    runner = failed_rollback(lab)
    path = lab.state_dir / "installation-journal.json"
    before = path.read_bytes()
    for digest in (lab.new["bundle_digest"], lab.old["bundle_digest"]):
        with pytest.raises(DeploymentError, match="does not match a failed installation"):
            recover_install(lab.state_dir, "user", expected_failed_digest=digest, runner=runner)
    for bundle, metadata in ((lab.first, lab.old), (lab.second, lab.new)):
        with pytest.raises(DeploymentError, match="unfinished installation"):
            install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"], runner=runner)
    for digest in (lab.old["bundle_digest"], "0" * 64):
        with pytest.raises(DeploymentError, match="unfinished installation"):
            rollback_install(lab.state_dir, "user", expected_current_digest=digest, runner=runner)
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "change",
    [
        {"scope": "root"},
        {"scope": None},
        {"to_bundle_digest": "0" * 64},
        {"to_bundle_digest": None},
        {"failed_phase": "starting-jobs"},
        {"phase": "recovering"},
    ],
)
def test_rollback_journal_of_another_scope_pair_or_phase_is_not_resumed(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    change: dict[str, Any],
) -> None:
    lab = Lab(tmp_path, manifest, config, "user", monkeypatch)
    runner = failed_rollback(lab)
    store = Store(lab.state_dir)
    journal = {**store.read("installation-journal.json"), **change}
    store.write(
        "installation-journal.json",
        {key: value for key, value in journal.items() if value is not None},
    )
    before = (lab.state_dir / "installation-journal.json").read_bytes()
    calls = len(lab.tools.calls)
    with pytest.raises(DeploymentError, match="unfinished installation"):
        lab.rollback(runner)
    assert (lab.state_dir / "installation-journal.json").read_bytes() == before
    assert len(lab.tools.calls) == calls


def test_repeated_rollback_refuses_a_job_file_of_neither_release(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab = Lab(tmp_path, manifest, config, "user", monkeypatch)
    runner = failed_rollback(lab)
    shared = lab.jobs / f"{manifest['jobs'][0]['label']}.plist"
    shared.write_bytes(b"neither release")
    calls = len(lab.tools.calls)
    with pytest.raises(DeploymentError, match="current managed file changed"):
        lab.rollback(runner)
    assert not any("bootstrap" in argv for argv in lab.tools.calls[calls:])
    assert shared.read_bytes() == b"neither release"


@pytest.mark.parametrize("fault", ["predecessor-bytes", "removed"])
def test_first_rollback_attempt_still_requires_the_current_job_bytes(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    """What a repeated rollback tolerates is not tolerated on a committed release."""
    lab = Lab(tmp_path, manifest, config, "user", monkeypatch)
    runner = lab.prepare()
    label = manifest["jobs"][0]["label"]
    if fault == "predecessor-bytes":
        release = Path(manifest["user"]["directory"]) / "releases" / lab.old["release_id"]
        (lab.jobs / f"{label}.plist").write_bytes(
            (release / "launchd" / f"{label}.plist").read_bytes()
        )
    else:
        (lab.jobs / f"{label}-new.plist").unlink()
    calls = len(lab.tools.calls)
    with pytest.raises((DeploymentError, FileNotFoundError)):
        lab.rollback(runner)
    assert not any("bootstrap" in argv for argv in lab.tools.calls[calls:])
    assert (
        Store(lab.state_dir).read("installation-receipt.json")["bundle_digest"]
        == (lab.new["bundle_digest"])
    )

"""An installation stopped at any point must leave a state that `recover` accepts.

Two kinds of stop are modelled. An interrupt (Ctrl-C) is an exception the
installer's handler sees. A kill, a dropped session or lost power is modelled
by `Killed`: from that step on nothing runs and nothing is written, not even
the handler's journal update.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import os
import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch.deployment import install_bundle, recover_install
from netorch.deployment_config import DeploymentError
from netorch.process import Result
from netorch.state import Intent, intent_from_dict, intent_to_dict
from netorch.storage import Busy, Store
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest
from tests.test_full_deployment import IntegratedTools, setup_forwarding

__all__ = ["config", "fake_platform", "manifest"]


class Interrupting(FakeTools):
    """The operator presses Ctrl-C while one native tool call is running."""

    def __init__(self, at: str) -> None:
        super().__init__()
        self.at = at

    def __call__(self, argv: tuple[str, ...]) -> Result:
        if self.at in argv:
            raise KeyboardInterrupt
        return super().__call__(argv)


class Killed(BaseException):
    """The installer process is gone; no handler may write after this."""


class Steps:
    """Counts the installer's own steps and stops the process before one of them."""

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
    monkeypatch: pytest.MonkeyPatch, steps: Steps, state_dir: Path, tools: FakeTools
) -> Iterator[Callable[[tuple[str, ...]], Result]]:
    """Every journal, receipt or intent write, release file and tool call is one step."""
    write = Store.write
    write_new = implementation._write_new

    def state_write(self: Store, name: str, value: Any) -> None:
        if self.directory == state_dir:
            steps()
        write(self, name, value)

    def file_write(path: Path, payload: bytes, mode: int = 0o600, **kwargs: Any) -> None:
        steps()
        write_new(path, payload, mode, **kwargs)

    def runner(argv: tuple[str, ...]) -> Result:
        steps()
        return tools(argv)

    with monkeypatch.context() as patch:
        patch.setattr(Store, "write", state_write)
        patch.setattr(implementation, "_write_new", file_write)
        yield runner


@pytest.fixture
def no_flush(monkeypatch: pytest.MonkeyPatch) -> None:
    """The sweeps model which steps happened, not durability; skip the disk flushes."""
    monkeypatch.setattr(os, "fsync", lambda descriptor: None)


def wipe(tmp_path: Path, keep: set[str]) -> None:
    for entry in tmp_path.iterdir():
        if entry.name in keep:
            continue
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def variant(manifest: dict[str, Any], scope: str, number: int) -> dict[str, Any]:
    value = copy.deepcopy(manifest)
    if scope == "user":
        value["jobs"][0]["interval_seconds"] = 10 + 5 * number
    else:
        value["jobs"][1]["log_directory"] += f"-v{number}"
    return value


def suspensions(store: Store, name: str = "intent.json") -> dict[str, str]:
    return dict(intent_from_dict(store.read(name)).suspensions)


def label(manifest: dict[str, Any], scope: str) -> str:
    return next(str(job["label"]) for job in manifest["jobs"] if job["scope"] == scope)


def plist(manifest: dict[str, Any], scope: str) -> Path:
    return Path(manifest[scope]["launchd_directory"]) / f"{label(manifest, scope)}.plist"


@pytest.mark.parametrize(
    ("at", "phase"),
    [("-t", "preflight-jobs"), ("bootout", "stopping-jobs"), ("bootstrap", "starting-jobs")],
)
def test_interrupt_is_recorded_as_failed_and_recovery_releases_the_hold(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    at: str,
    phase: str,
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    digest = metadata["bundle_digest"]
    with pytest.raises(KeyboardInterrupt):
        install_bundle(bundle, "user", expected_digest=digest, runner=Interrupting(at))
    state_dir = Path(manifest["user"]["state_directory"])
    store = Store(state_dir)
    journal = store.read("installation-journal.json")
    assert (journal["phase"], journal["failed_phase"]) == ("failed", phase)
    assert suspensions(store) == {"installation": digest}

    tools = FakeTools()
    result = recover_install(state_dir, "user", expected_failed_digest=digest, runner=tools)
    assert result["phase"] == "rolled-back"
    intent = intent_from_dict(store.read("intent.json"))
    assert intent.operator_paused and not intent.suspensions
    assert not plist(manifest, "user").exists()
    assert not tools.loaded


def test_interrupt_in_the_root_owner_command_is_recorded_and_recoverable(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    digest = metadata["bundle_digest"]
    with pytest.raises(KeyboardInterrupt):
        install_bundle(bundle, "root", expected_digest=digest, runner=Interrupting("install"))
    state_dir = Path(manifest["root"]["state_directory"])
    journal = Store(state_dir).read("installation-journal.json")
    assert (journal["phase"], journal["failed_phase"]) == (
        "failed",
        "installing-forwarding-owner",
    )
    result = recover_install(state_dir, "root", expected_failed_digest=digest, runner=FakeTools())
    assert result["phase"] == "rolled-back"


def test_interrupted_recovery_is_recorded_as_failed_and_can_be_repeated(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    first, old = make_bundle(tmp_path, manifest, config, "first")
    tools = FakeTools()
    install_bundle(first, "user", expected_digest=old["bundle_digest"], runner=tools)
    second, new = make_bundle(tmp_path, variant(manifest, "user", 1), config, "second")
    tools.fail = "bootstrap"
    with pytest.raises(DeploymentError):
        install_bundle(second, "user", expected_digest=new["bundle_digest"], runner=tools)
    state_dir = Path(manifest["user"]["state_directory"])
    store = Store(state_dir)
    with pytest.raises(KeyboardInterrupt):
        recover_install(
            state_dir,
            "user",
            expected_failed_digest=new["bundle_digest"],
            runner=Interrupting("bootstrap"),
        )
    journal = store.read("installation-journal.json")
    assert (journal["phase"], journal["failed_phase"]) == ("failed", "starting-jobs")
    tools.fail = None
    result = recover_install(
        state_dir, "user", expected_failed_digest=new["bundle_digest"], runner=tools
    )
    assert result["release_id"] == old["release_id"]
    assert tools.loaded == {label(manifest, "user")} and not suspensions(store)


def killed_user_install(
    tmp_path: Path,
    manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    bundle: Path,
    digest: str,
    tools: FakeTools,
    stop_before: int | None,
) -> int:
    steps = Steps(stop_before)
    state_dir = Path(manifest["user"]["state_directory"])
    with stepped(monkeypatch, steps, state_dir, tools) as runner:
        if stop_before is None:
            install_bundle(bundle, "user", expected_digest=digest, runner=runner)
        else:
            with pytest.raises(Killed):
                install_bundle(bundle, "user", expected_digest=digest, runner=runner)
    return steps.count


def test_first_user_install_killed_before_any_step_is_recoverable(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    no_flush: None,
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config, "bundle")
    other, later = make_bundle(tmp_path, variant(manifest, "user", 1), config, "other")
    keep = {"bundle", "other", "settings.json", "backend.sh"}
    digest = metadata["bundle_digest"]
    state_dir = Path(manifest["user"]["state_directory"])
    total = killed_user_install(tmp_path, manifest, monkeypatch, bundle, digest, FakeTools(), None)
    assert total > 12
    outcomes: list[str] = []
    for stop_before in range(1, total):
        wipe(tmp_path, keep)
        killed_user_install(
            tmp_path, manifest, monkeypatch, bundle, digest, FakeTools(), stop_before
        )
        store = Store(state_dir)
        assert suspensions(store) in ({"installation": digest}, {}), stop_before
        tools = FakeTools()
        result = recover_install(state_dir, "user", expected_failed_digest=digest, runner=tools)
        outcomes.append(result["phase"])
        intent = intent_from_dict(store.read("intent.json"))
        assert intent.operator_paused and not intent.suspensions, stop_before
        assert not plist(manifest, "user").exists() and not tools.loaded, stop_before
        assert not (state_dir / "installation-receipt.json").exists(), stop_before
        if result["phase"] == "rolled-back":
            assert store.read("installation-journal.json")["phase"] == "rolled-back"
        else:
            assert not (state_dir / "installation-journal.json").exists()
        # No dead end: the next reviewed release installs.
        assert (
            install_bundle(other, "user", expected_digest=later["bundle_digest"], runner=tools)[
                "phase"
            ]
            == "committed"
        ), stop_before
    # Step 0 is the suspension, step 1 the first journal write.
    assert outcomes[0] == "hold-released"
    assert set(outcomes[1:]) == {"rolled-back"}


def test_user_upgrade_killed_before_any_step_recovers_the_previous_release(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    no_flush: None,
) -> None:
    first, old = make_bundle(tmp_path, manifest, config, "first")
    second, new = make_bundle(tmp_path, variant(manifest, "user", 1), config, "second")
    third, last = make_bundle(tmp_path, variant(manifest, "user", 2), config, "third")
    keep = {"first", "second", "third", "settings.json", "backend.sh"}
    state_dir = Path(manifest["user"]["state_directory"])

    def installed_first() -> FakeTools:
        wipe(tmp_path, keep)
        tools = FakeTools()
        install_bundle(first, "user", expected_digest=old["bundle_digest"], runner=tools)
        Store(state_dir).write("intent.json", intent_to_dict(Intent().suspend("backup", "other")))
        return tools

    total = killed_user_install(
        tmp_path, manifest, monkeypatch, second, new["bundle_digest"], installed_first(), None
    )
    outcomes: list[str] = []
    for stop_before in range(1, total):
        tools = installed_first()
        killed_user_install(
            tmp_path, manifest, monkeypatch, second, new["bundle_digest"], tools, stop_before
        )
        store = Store(state_dir)
        result = recover_install(
            state_dir, "user", expected_failed_digest=new["bundle_digest"], runner=tools
        )
        outcomes.append(result["phase"])
        # The operator did not pause, and another holder's suspension is not ours.
        intent = intent_from_dict(store.read("intent.json"))
        assert not intent.operator_paused, stop_before
        assert dict(intent.suspensions) == {"backup": "other"}, stop_before
        receipt = store.read("installation-receipt.json")
        assert receipt["bundle_digest"] == old["bundle_digest"], stop_before
        installed = hashlib.sha256(plist(manifest, "user").read_bytes()).hexdigest()
        assert installed == receipt["jobs"][0]["sha256"], stop_before
        assert tools.loaded == {label(manifest, "user")}, stop_before
        assert (
            install_bundle(third, "user", expected_digest=last["bundle_digest"], runner=tools)[
                "phase"
            ]
            == "committed"
        ), stop_before
    assert outcomes[0] == "hold-released"
    assert set(outcomes[1:]) == {"rolled-back"}


def test_killed_recovery_can_be_repeated_from_every_step(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    no_flush: None,
) -> None:
    first, old = make_bundle(tmp_path, manifest, config, "first")
    second, new = make_bundle(tmp_path, variant(manifest, "user", 1), config, "second")
    keep = {"first", "second", "settings.json", "backend.sh"}
    state_dir = Path(manifest["user"]["state_directory"])

    def failed_upgrade() -> FakeTools:
        wipe(tmp_path, keep)
        tools = FakeTools()
        install_bundle(first, "user", expected_digest=old["bundle_digest"], runner=tools)
        tools.fail = "bootstrap"
        with pytest.raises(DeploymentError):
            install_bundle(second, "user", expected_digest=new["bundle_digest"], runner=tools)
        tools.fail = None
        return tools

    def recovery(tools: FakeTools, stop_before: int | None) -> int:
        steps = Steps(stop_before)
        with stepped(monkeypatch, steps, state_dir, tools) as runner:
            if stop_before is None:
                recover_install(
                    state_dir, "user", expected_failed_digest=new["bundle_digest"], runner=runner
                )
            else:
                with pytest.raises(Killed):
                    recover_install(
                        state_dir,
                        "user",
                        expected_failed_digest=new["bundle_digest"],
                        runner=runner,
                    )
        return steps.count

    total = recovery(failed_upgrade(), None)
    assert total > 5
    for stop_before in range(total):
        tools = failed_upgrade()
        recovery(tools, stop_before)
        store = Store(state_dir)
        result = recover_install(
            state_dir, "user", expected_failed_digest=new["bundle_digest"], runner=tools
        )
        assert result["release_id"] == old["release_id"], stop_before
        assert store.read("installation-journal.json")["phase"] == "rolled-back"
        assert store.read("installation-receipt.json")["bundle_digest"] == old["bundle_digest"]
        assert tools.loaded == {label(manifest, "user")} and not suspensions(store), stop_before


@pytest.mark.parametrize("upgrade", [False, True])
def test_root_install_killed_before_any_step_is_recoverable(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    no_flush: None,
    upgrade: bool,
) -> None:
    setup_forwarding(manifest, monkeypatch)
    first, old = make_bundle(tmp_path, manifest, config, "first")
    second, new = make_bundle(tmp_path, variant(manifest, "root", 1), config, "second")
    third, last = make_bundle(tmp_path, variant(manifest, "root", 2), config, "third")
    keep = {"first", "second", "third", "settings.json", "backend.sh"}
    state_dir = Path(manifest["root"]["state_directory"])
    owner_dir = Path(manifest["forwarding"]["directory"])
    bundle, digest = (second, new["bundle_digest"]) if upgrade else (first, old["bundle_digest"])

    def prepared() -> IntegratedTools:
        wipe(tmp_path, keep)
        tools = IntegratedTools()
        if upgrade:
            install_bundle(first, "root", expected_digest=old["bundle_digest"], runner=tools)
        return tools

    def attempt(tools: IntegratedTools, stop_before: int | None) -> int:
        steps = Steps(stop_before)
        with stepped(monkeypatch, steps, state_dir, tools) as runner:
            if stop_before is None:
                install_bundle(bundle, "root", expected_digest=digest, runner=runner)
            else:
                with pytest.raises(Killed):
                    install_bundle(bundle, "root", expected_digest=digest, runner=runner)
        return steps.count

    total = attempt(prepared(), None)
    assert total > 15
    for stop_before in range(1, total):
        tools = prepared()
        attempt(tools, stop_before)
        result = recover_install(state_dir, "root", expected_failed_digest=digest, runner=tools)
        assert result["phase"] == "rolled-back", stop_before
        store = Store(state_dir)
        assert store.read("installation-journal.json")["phase"] == "rolled-back"
        if (owner_dir / "operator-intent.json").exists():
            assert not suspensions(Store(owner_dir), "operator-intent.json"), stop_before
        assert not tools.backend.rules
        if upgrade:
            receipt = store.read("installation-receipt.json")
            assert receipt["bundle_digest"] == old["bundle_digest"], stop_before
            assert tools.loaded == {label(manifest, "root")}, stop_before
        else:
            assert not (state_dir / "installation-receipt.json").exists()
            assert not tools.loaded, stop_before
        assert (
            install_bundle(third, "root", expected_digest=last["bundle_digest"], runner=tools)[
                "phase"
            ]
            == "committed"
        ), stop_before


def test_hold_without_journal_is_released_only_for_its_exact_digest(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config, "bundle")
    other, later = make_bundle(tmp_path, variant(manifest, "user", 1), config, "other")
    digest = metadata["bundle_digest"]
    state_dir = Path(manifest["user"]["state_directory"])
    # Stop between the suspension (step 0) and the first journal write (step 1).
    killed_user_install(tmp_path, manifest, monkeypatch, bundle, digest, FakeTools(), 1)
    store = Store(state_dir)
    assert suspensions(store) == {"installation": digest}
    assert not (state_dir / "installation-journal.json").exists()
    # Without the fix a different reviewed bundle is refused from here on.
    with pytest.raises(ValueError, match="owned by another holder"):
        install_bundle(other, "user", expected_digest=later["bundle_digest"], runner=FakeTools())
    tools = FakeTools()
    with pytest.raises(DeploymentError, match="does not match"):
        recover_install(
            state_dir, "user", expected_failed_digest=later["bundle_digest"], runner=tools
        )
    with pytest.raises(DeploymentError, match="does not match"):
        recover_install(state_dir, "root", expected_failed_digest=digest, runner=tools)
    assert suspensions(store) == {"installation": digest}
    result = recover_install(state_dir, "user", expected_failed_digest=digest, runner=tools)
    assert result["phase"] == "hold-released"
    intent = intent_from_dict(store.read("intent.json"))
    assert intent.operator_paused and not intent.suspensions
    assert tools.calls == []
    assert not (state_dir / "installation-journal.json").exists()


def test_closed_journal_without_a_hold_is_still_not_recoverable(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    digest = metadata["bundle_digest"]
    tools = FakeTools()
    install_bundle(bundle, "user", expected_digest=digest, runner=tools)
    state_dir = Path(manifest["user"]["state_directory"])
    before = (state_dir / "installation-journal.json").read_bytes()
    calls = len(tools.calls)
    with pytest.raises(DeploymentError, match="does not match"):
        recover_install(state_dir, "user", expected_failed_digest=digest, runner=tools)
    assert (state_dir / "installation-journal.json").read_bytes() == before
    assert len(tools.calls) == calls and tools.loaded == {label(manifest, "user")}


@pytest.mark.parametrize(
    "change",
    [
        {"phase": "rolling-back"},
        {"phase": "inspecting"},
        {"phase": 7},
        {"scope": "root"},
        {"bundle_digest": "0" * 64},
    ],
)
def test_open_journal_of_another_operation_scope_or_digest_is_refused(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    change: dict[str, Any],
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    digest = metadata["bundle_digest"]
    state_dir = Path(manifest["user"]["state_directory"])
    killed_user_install(tmp_path, manifest, monkeypatch, bundle, digest, FakeTools(), 13)
    store = Store(state_dir)
    journal = store.read("installation-journal.json")
    assert journal["phase"] == "installing-jobs"
    store.write("installation-journal.json", {**journal, **change})
    before = (state_dir / "installation-journal.json").read_bytes()
    tools = FakeTools()
    with pytest.raises(DeploymentError, match="does not match"):
        recover_install(state_dir, "user", expected_failed_digest=digest, runner=tools)
    assert (state_dir / "installation-journal.json").read_bytes() == before
    assert tools.calls == [] and suspensions(store) == {"installation": digest}


@pytest.mark.parametrize("damage", ["foreign-holder", "damaged"])
def test_recovery_never_takes_over_a_foreign_or_damaged_hold(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    damage: str,
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    digest = metadata["bundle_digest"]
    state_dir = Path(manifest["user"]["state_directory"])
    killed_user_install(tmp_path, manifest, monkeypatch, bundle, digest, FakeTools(), 12)
    store = Store(state_dir)
    value: dict[str, Any] = (
        intent_to_dict(Intent().pause().suspend("installation", "someone-else"))
        if damage == "foreign-holder"
        else {"schema_version": 999}
    )
    store.write("intent.json", value)
    before = (state_dir / "installation-journal.json").read_bytes()
    tools = FakeTools()
    with pytest.raises(DeploymentError, match="original suspension"):
        recover_install(state_dir, "user", expected_failed_digest=digest, runner=tools)
    assert store.read("intent.json") == value
    assert (state_dir / "installation-journal.json").read_bytes() == before
    assert tools.calls == []


def test_recovery_is_busy_while_the_installer_still_holds_the_lock(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
) -> None:
    """The premise of accepting an open phase: it is only ever read under this lock."""
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    digest = metadata["bundle_digest"]
    state_dir = Path(manifest["user"]["state_directory"])
    seen: list[str] = []

    class Concurrent(FakeTools):
        def __call__(self, argv: tuple[str, ...]) -> Result:
            if "bootout" in argv:
                seen.append(Store(state_dir).read("installation-journal.json")["phase"])
                with pytest.raises(Busy):
                    recover_install(
                        state_dir, "user", expected_failed_digest=digest, runner=FakeTools()
                    )
            return super().__call__(argv)

    result = install_bundle(bundle, "user", expected_digest=digest, runner=Concurrent())
    assert seen == ["stopping-jobs"] and result["phase"] == "committed"

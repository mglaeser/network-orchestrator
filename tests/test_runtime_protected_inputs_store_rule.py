"""The runtime owner reads its two records by the whole rule of the state store.

The store writes a record only into a directory of mode 0700 that its user owns
and that is no symbolic link, and only as a regular file of mode 0600 with one
link, owned by that user. The reader refuses exactly what the store refuses to
write into: the directory is held to the store's own check and the record is
opened relative to the checked directory. What the operator commands themselves
create is read as before, whatever the caller's umask.

The second half pins each check of the reader on its own: that it concerns the
opened file and not its name, the file type, the exact mode, the link count,
the owner of the record and the bound of the read.
"""

from __future__ import annotations

import os
import stat
import threading
from collections.abc import Callable
from dataclasses import replace
from io import BytesIO, TextIOWrapper
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch import cli as cli_module
from netorch import codec
from netorch.cli import main as netorch
from netorch.codec import canonical_bytes
from netorch.config import profile_digest
from netorch.state import Intent, intent_to_dict
from netorch.storage import Store, UnsafeState
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_runtime_protected_inputs import (
    REDACTED,
    RUNNING,
    STOPPED,
    Site,
    activation,
    probe,
    site,
    starts,
)

__all__ = ["enrolled", "site"]

# Usual umasks. The store asks for exactly the modes it needs, and none of these takes one away.
UMASKS = [0o000, 0o002, 0o022, 0o027, 0o077]
# Forms of the directory that the state store refuses to read from or to write into.
# The target of the symbolic link is itself a private directory: the link alone is refused.
DIRECTORY_FORMS = ["mode-0755", "mode-0770", "mode-0777", "symbolic-link"]
PAUSED = Intent(1, operator_paused=True)


def weaken_directory(directory: Path, form: str) -> None:
    """Give a directory the store made a form the store itself does not accept."""
    if form == "symbolic-link":
        moved = directory.with_name("moved-" + directory.name)
        directory.rename(moved)
        directory.symlink_to(moved)
    else:
        directory.chmod(int(form.removeprefix("mode-"), 8))


def alone(site: Site, tmp_path: Path, record: str) -> tuple[Any, Any, FakeRunner, Path]:
    """Leave only `record` in the first store; the other record moves to a second one.

    One record's directory can then be weakened while the other stays as the
    store keeps it, so that the outcome belongs to that one record.
    """
    config, settings, runner, store = site
    other = "admissions" if record == "intent" else "intent"
    elsewhere = Store(tmp_path / "second-state")
    elsewhere.write(other + ".json", store.read(other + ".json"))
    (store.directory / (other + ".json")).unlink()
    settings = replace(settings, **{other: str(elsewhere.directory / (other + ".json"))})
    return config, settings, runner, store.directory


def endpoint(
    monkeypatch: pytest.MonkeyPatch, settings: Any, runner: FakeRunner, request: dict[str, Any]
) -> int:
    """The endpoint command with the stage gate's request check replaced, natives faked."""
    handle = runtime.handle_request
    with monkeypatch.context() as patch:
        patch.setattr(runtime, "require_request_qualified", lambda _provider, _request: None)
        patch.setattr(runtime, "load_settings", lambda _path: settings)
        patch.setattr(runtime, "handle_request", lambda *arguments: handle(*arguments, runner))
        patch.setattr(runtime.sys, "stdin", TextIOWrapper(BytesIO(canonical_bytes(request))))
        return runtime.main(["--settings", "/unused/settings.json", "request"])


def stat_with_another_owner(kind: Callable[[int], bool]) -> Callable[[int], os.stat_result]:
    """`os.fstat` that reports another owner for descriptors of one file type only."""
    real = os.fstat

    def fstat(fd: int) -> os.stat_result:
        info = real(fd)
        if not kind(info.st_mode):
            return info
        fields = list(info)
        fields[stat.ST_UID] = info.st_uid + 1
        return os.stat_result(fields)

    return fstat


def after_the_record_is_opened(
    monkeypatch: pytest.MonkeyPatch, record: Path, action: Callable[[], None]
) -> None:
    """Run `action` once, right after the reader has opened `record` and before it checks it."""
    real = os.open
    done: list[bool] = []

    def opened(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        fd = real(path, flags, mode, dir_fd=dir_fd)
        if not done and os.path.basename(os.fspath(path)) == record.name:
            done.append(True)
            action()
        return fd

    monkeypatch.setattr(os, "open", opened)


@pytest.fixture
def retained_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit CI-only seam for preserved owner internals; never qualification.

    The stage gate refuses `init-state`, `resume` and `admit`. The writer behind
    the gate is what an installation of the retained owners has used.
    """
    monkeypatch.setattr(cli_module, "require_mutation_qualified", lambda _capability: None)


@pytest.mark.usefixtures("retained_commands")
@pytest.mark.parametrize("umask", UMASKS)
def test_what_the_operator_commands_create_is_read(
    enrolled: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    umask: int,
) -> None:
    """An existing installation does not stop: directory and records as the commands make them."""
    config, settings, items = enrolled
    profile = config.profile("camera-web")
    state = tmp_path / "operator" / "state"
    previous = os.umask(umask)
    try:
        for command in ("init-state", "resume", "pause", "resume"):
            assert netorch([command, "--state-dir", str(state)]) == 0
        admitted = netorch(
            [
                "admit",
                "--config",
                settings.policy,
                "--profile",
                profile.id,
                "--state-dir",
                str(state),
                "--expected-digest",
                profile_digest(config, profile),
                "--approved-by",
                "reviewer",
            ]
        )
    finally:
        os.umask(previous)
    capsys.readouterr()
    assert admitted == 0
    assert stat.S_IMODE(state.stat().st_mode) == 0o700 and not state.is_symlink()
    for name in ("intent.json", "admissions.json"):
        info = (state / name).lstat()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        assert (info.st_nlink, info.st_uid) == (1, os.geteuid())
    settings = replace(
        settings,
        intent=str(state / "intent.json"),
        admissions=str(state / "admissions.json"),
        state_dir=str(state),
    )
    runner = FakeRunner(settings, items)
    runner.items[settings.contract(STOPPED).name]["status"]["state"] = "stopped"
    # Paused at initialization, resumed, paused and resumed again: revision 3.
    assert runtime._intent(settings) == Intent(3)
    assert probe(monkeypatch, settings, runner, RUNNING) == 0
    assert probe(monkeypatch, settings, runner, STOPPED) == runtime.STOPPED
    request = activation(config, settings, runner)
    assert runtime.handle_request(config, settings, request, runner)["result"]["state"] == "present"
    result = runtime.recover_service(config, settings, STOPPED, runner)
    assert result.services[STOPPED].state == "present" and starts(runner) == 1


@pytest.mark.parametrize("form", DIRECTORY_FORMS)
def test_a_directory_that_can_take_no_pause_holds_damaged_intent(
    site: Site,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    form: str,
) -> None:
    """The record is untouched; its directory is what the store refuses."""
    config, settings, runner, directory = alone(site, tmp_path, "intent")
    request = activation(config, settings, runner)
    record = Path(settings.intent)
    content = record.read_bytes()
    weaken_directory(directory, form)
    # The operator's pause is refused and nothing is written.
    assert netorch(["pause", "--state-dir", str(directory)]) == 65
    capsys.readouterr()
    with pytest.raises(UnsafeState):
        Store(directory)
    assert record.read_bytes() == content == canonical_bytes(intent_to_dict(Intent())) + b"\n"
    # The record itself is still in the form the store writes.
    info = record.stat()
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
    # A record that can take no pause is not acted on: it is damaged intent.
    intent = runtime._intent(settings)
    assert intent.damaged and intent.blocks(STOPPED)
    assert probe(monkeypatch, settings, runner, STOPPED) == runtime.UNKNOWN
    assert probe(monkeypatch, settings, runner, RUNNING) == runtime.UNKNOWN
    with pytest.raises(runtime.RuntimeReadError) as refused:
        runtime.handle_request(config, settings, request, runner)
    assert refused.value.reason == "incomplete"
    # The lock of a start lies in a directory the store accepts, so the intent decides.
    lock = Store(tmp_path / "lock-state")
    with pytest.raises(runtime.RuntimeReadError) as refused:
        runtime.recover_service(
            config, replace(settings, state_dir=str(lock.directory)), STOPPED, runner
        )
    assert refused.value.reason == "incomplete"
    assert not starts(runner)


@pytest.mark.parametrize("form", DIRECTORY_FORMS)
def test_a_directory_that_can_take_no_admission_admits_nothing(
    site: Site,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    form: str,
) -> None:
    config, settings, runner, directory = alone(site, tmp_path, "admissions")
    request = activation(config, settings, runner)
    assert runtime.handle_request(config, settings, request, runner)["result"]["state"] == "present"
    weaken_directory(directory, form)
    # The intent lies elsewhere and is read; the admissions alone decide.
    assert runtime._intent(settings) == Intent()
    with pytest.raises((OSError, ValueError)):
        runtime.handle_request(config, settings, request, runner)
    # Through the endpoint command the refusal is one redacted line and no trace.
    assert endpoint(monkeypatch, settings, runner, request) == runtime.UNKNOWN
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", REDACTED)


def test_a_directory_of_another_owner_is_refused(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The records are the caller's own; only their directory is reported as someone else's."""
    config, settings, runner, _store = site
    request = activation(config, settings, runner)
    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", stat_with_another_owner(stat.S_ISDIR))
        assert runtime._intent(settings) == Intent(damaged=True)
        with pytest.raises(ValueError, match="private directory"):
            runtime.handle_request(config, settings, request, runner)
    assert runtime._intent(settings) == Intent()
    assert runtime.handle_request(config, settings, request, runner)["result"]["state"] == "present"


def test_the_record_is_read_from_the_directory_that_was_checked(
    site: Site, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory put under the same name after the check is not the one that is read."""
    _config, settings, _runner, store = site
    assert netorch(["pause", "--state-dir", str(store.directory)]) == 0
    assert runtime._intent(settings) == PAUSED
    # A second directory that the store refuses, holding a record that says "not paused".
    decoy = Store(tmp_path / "decoy")
    decoy.write("intent.json", intent_to_dict(Intent()))
    decoy.directory.chmod(0o755)
    real = os.fstat
    swapped: list[bool] = []

    def fstat(fd: int) -> os.stat_result:
        info = real(fd)
        if not swapped and stat.S_ISDIR(info.st_mode):
            swapped.append(True)
            store.directory.rename(tmp_path / "checked")
            decoy.directory.rename(store.directory)
        return info

    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", fstat)
        first = runtime._intent(settings)
    assert swapped and stat.S_IMODE(store.directory.stat().st_mode) == 0o755
    # The pause of the checked directory is read, not the record under the name now.
    assert first == PAUSED
    # From the next read on the name leads to a directory the store refuses.
    assert runtime._intent(settings) == Intent(damaged=True)


def test_a_named_pipe_in_place_of_the_directory_is_closed_without_waiting(
    site: Site, tmp_path: Path
) -> None:
    """Opening a named pipe for reading waits for a writer unless a directory is asked for."""
    _config, settings, _runner, _store = site
    pipe = tmp_path / "pipe"
    os.mkfifo(pipe, 0o700)
    settings = replace(settings, intent=str(pipe / "intent.json"))
    outcome: list[Intent] = []
    reader = threading.Thread(target=lambda: outcome.append(runtime._intent(settings)))
    reader.daemon = True
    reader.start()
    reader.join(10)
    waiting = reader.is_alive()
    if waiting:
        # Let a reader that waits in its open go on, so that no thread is left behind.
        os.close(os.open(pipe, os.O_WRONLY | os.O_NONBLOCK))
        reader.join(10)
    assert not waiting
    assert outcome == [Intent(damaged=True)]


def test_the_checks_are_made_on_the_opened_record_not_on_its_name(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unprotected record stays refused when a private file takes its name after the open."""
    _config, settings, _runner, store = site
    record = Path(settings.intent)
    record.chmod(0o644)
    store.write("replacement.json", intent_to_dict(Intent()))
    aside = record.with_name("moved-aside.json")

    def exchange() -> None:
        record.rename(aside)
        (store.directory / "replacement.json").rename(record)

    with monkeypatch.context() as patch:
        after_the_record_is_opened(patch, record, exchange)
        first = runtime._intent(settings)
    # The opened file keeps its one link under another name and still says "not paused".
    assert aside.stat().st_nlink == 1 and stat.S_IMODE(aside.stat().st_mode) == 0o644
    assert first == Intent(damaged=True)
    assert runtime._intent(settings) == Intent()


def test_a_record_replaced_after_it_was_opened_is_not_read(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The store replaces a record by renaming; the opened one then has no link at all."""
    _config, settings, _runner, store = site
    record = Path(settings.intent)
    with monkeypatch.context() as patch:
        after_the_record_is_opened(
            patch, record, lambda: store.write("intent.json", intent_to_dict(PAUSED))
        )
        first = runtime._intent(settings)
    assert first == Intent(damaged=True)
    assert runtime._intent(settings) == PAUSED


def test_a_named_pipe_with_a_waiting_document_is_not_read(site: Site) -> None:
    """A private single-link pipe of the caller is still no record, even with a document in it."""
    _config, settings, _runner, _store = site
    path = Path(settings.intent)
    document = path.read_bytes()
    path.unlink()
    os.mkfifo(path, 0o600)
    reading = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    writing = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
    outcome: list[Intent] = []
    try:
        assert os.write(writing, document) == len(document)
        reader = threading.Thread(target=lambda: outcome.append(runtime._intent(settings)))
        reader.daemon = True
        reader.start()
        reader.join(10)
        assert not reader.is_alive()
        assert outcome == [Intent(damaged=True)]
        # Nothing took the document out of the pipe.
        assert os.read(reading, len(document) + 1) == document
    finally:
        os.close(writing)
        os.close(reading)


@pytest.mark.parametrize("mode", [0o700, 0o4600], ids=["0700", "04600"])
def test_only_mode_0600_is_read(site: Site, mode: int) -> None:
    """Owner-only is not enough: the store writes no executable and no set-user-ID record."""
    config, settings, runner, _store = site
    request = activation(config, settings, runner)
    for name in ("intent", "admissions"):
        path = Path(getattr(settings, name))
        path.chmod(mode)
        if stat.S_IMODE(path.stat().st_mode) != mode:
            pytest.skip("this file system does not keep the mode bit")
    assert runtime._intent(settings) == Intent(damaged=True)
    Path(settings.intent).chmod(0o600)
    assert runtime._intent(settings) == Intent()
    with pytest.raises((OSError, ValueError)):
        runtime.handle_request(config, settings, request, runner)


def test_a_record_of_another_owner_in_the_caller_s_directory_is_refused(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The directory is the caller's own; only the records are reported as someone else's."""
    config, settings, runner, _store = site
    request = activation(config, settings, runner)
    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", stat_with_another_owner(stat.S_ISREG))
        assert runtime._intent(settings) == Intent(damaged=True)
        with pytest.raises(ValueError, match="private regular files"):
            runtime.handle_request(config, settings, request, runner)
    assert runtime._intent(settings) == Intent()
    assert runtime.handle_request(config, settings, request, runner)["result"]["state"] == "present"


def test_no_more_than_the_bound_is_read_from_a_larger_record(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Four mebibytes on disk: the parser is handed one byte more than the bound, then refuses."""
    _config, settings, _runner, _store = site
    path = Path(settings.intent)
    document = canonical_bytes(intent_to_dict(Intent(7)))
    path.write_bytes(document + b" " * (4 * 1_048_576 - len(document)))
    assert path.stat().st_size == 4 * 1_048_576 and stat.S_IMODE(path.stat().st_mode) == 0o600
    real = codec.strict_loads
    handed: list[int] = []

    def loads(text: str | bytes, **limits: int) -> Any:
        handed.append(len(text))
        return real(text, **limits)

    # Wherever the reader finds the parser, it is this one.
    monkeypatch.setattr(runtime, "strict_loads", loads)
    monkeypatch.setattr(codec, "strict_loads", loads)
    assert runtime._intent(settings) == Intent(damaged=True)
    assert handed == [1_048_577]

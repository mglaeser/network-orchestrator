"""The runtime owner reads its durable intent and its user admissions as protected records.

The state store writes both as regular files of mode 0600 with one link, owned
by its user, and refuses to replace a record in any other form. Such a record
can therefore take no pause and no admission, and the discovery owner reads it
as unreadable. The runtime owner holds its two records to the same file rule:
anything else is damaged intent or no admission, never "not paused".

This file covers the record itself. The store's rule for the directory that
holds it, which the runtime owner applies as well, is covered in
`test_runtime_protected_inputs_store_rule.py`.
"""

from __future__ import annotations

import os
import threading
from dataclasses import replace
from io import BytesIO, TextIOWrapper
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch import bonjour_owner
from netorch.cli import main as netorch
from netorch.codec import canonical_bytes
from netorch.config import config_digest, profile_digest
from netorch.mock import mock_admissions
from netorch.state import Intent, admissions_to_dict, intent_to_dict
from netorch.storage import Store
from tests.test_apple_runtime import FakeRunner, enrolled

__all__ = ["enrolled"]

Site = tuple[Any, Any, FakeRunner, Store]
# Forms of the record itself that the state store refuses to read or to replace.
# The target of the symbolic link is itself a private single-link file: the link
# alone is refused.
UNPROTECTED = ["symbolic-link", "second-link", "mode-0644", "mode-0660", "mode-0666", "mode-0400"]
STOPPED, RUNNING = "media-controller", "camera"
REDACTED = '{"error":"runtime-evidence-or-authority-incomplete"}\n'


@pytest.fixture
def site(enrolled: Any, tmp_path: Path) -> Site:
    """Runtime settings that name the state store's own records; one workload is stopped."""
    config, settings, items = enrolled
    store = Store(tmp_path / "state")
    store.write("intent.json", intent_to_dict(Intent()))
    store.write("admissions.json", admissions_to_dict(mock_admissions(config)))
    settings = replace(
        settings,
        intent=str(store.directory / "intent.json"),
        admissions=str(store.directory / "admissions.json"),
    )
    runner = FakeRunner(settings, items)
    runner.items[settings.contract(STOPPED).name]["status"]["state"] = "stopped"
    return config, settings, runner, store


def weaken(path: Path, form: str) -> None:
    """Give a record the store wrote a form the store itself does not maintain."""
    outside = path.parent.parent
    if form == "symbolic-link":
        target = outside / ("moved-" + path.name)
        path.rename(target)
        path.symlink_to(target)
    elif form == "second-link":
        os.link(path, outside / ("second-name-" + path.name))
    else:
        path.chmod(int(form.removeprefix("mode-"), 8))


def probe(monkeypatch: pytest.MonkeyPatch, settings: Any, runner: FakeRunner, service: str) -> int:
    """The supervisor's check as the command runs it, with the native tools faked."""
    observe = runtime.observe_runtime
    with monkeypatch.context() as patch:
        patch.setattr(runtime, "load_settings", lambda _path: settings)
        patch.setattr(
            runtime, "observe_runtime", lambda config, actual: observe(config, actual, runner)
        )
        return runtime.main(["--settings", "/unused/settings.json", "probe", "--service", service])


def activation(config: Any, settings: Any, runner: FakeRunner) -> dict[str, Any]:
    """The coordinator's request to verify the running workload's native publication."""
    profile = config.profile("camera-web")
    observed = runtime.observe_runtime(config, settings, runner)
    return {
        "protocol_version": 1,
        "operation": "reconcile",
        "owner": settings.owner,
        "policy_digest": config_digest(config),
        "profile_digest": profile_digest(config, profile),
        "profile": profile.id,
        "action": "activate",
        "target_ipv4": observed.services[profile.service].data["ipv4"],
        "target_generation": observed.services[profile.service].generation,
    }


def starts(runner: FakeRunner) -> int:
    return sum(argv[1:2] == ["start"] for argv, _ in runner.calls)


def test_the_records_the_state_store_writes_are_read(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, settings, runner, _store = site
    assert probe(monkeypatch, settings, runner, RUNNING) == 0
    assert probe(monkeypatch, settings, runner, STOPPED) == runtime.STOPPED
    request = activation(config, settings, runner)
    assert runtime.handle_request(config, settings, request, runner)["result"]["state"] == "present"
    result = runtime.recover_service(config, settings, STOPPED, runner)
    assert result.services[STOPPED].state == "present" and starts(runner) == 1
    assert probe(monkeypatch, settings, runner, STOPPED) == 0


def test_a_pause_the_operator_command_records_is_read(
    site: Site, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The store replaces the record by renaming a new private file over it."""
    config, settings, runner, store = site
    request = activation(config, settings, runner)
    before = os.stat(settings.intent).st_ino
    assert netorch(["pause", "--state-dir", str(store.directory)]) == 0
    capsys.readouterr()
    assert os.stat(settings.intent).st_ino != before
    assert runtime._intent(settings) == Intent(1, operator_paused=True)
    assert probe(monkeypatch, settings, runner, STOPPED) == runtime.UNKNOWN
    assert probe(monkeypatch, settings, runner, RUNNING) == runtime.UNKNOWN
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, STOPPED, runner)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.handle_request(config, settings, request, runner)
    assert not starts(runner)


@pytest.mark.parametrize("form", UNPROTECTED)
def test_a_record_that_can_take_no_pause_is_damaged_intent(
    site: Site, capsys: pytest.CaptureFixture[str], form: str
) -> None:
    """Every other reader of such a record is closed; the runtime owner is no exception."""
    _config, settings, _runner, store = site
    path = Path(settings.intent)
    weaken(path, form)
    content = path.read_bytes()
    # The operator's pause is refused and nothing is written.
    assert netorch(["pause", "--state-dir", str(store.directory)]) == 65
    capsys.readouterr()
    assert path.read_bytes() == content == canonical_bytes(intent_to_dict(Intent())) + b"\n"
    # The discovery owner does not read the record.
    with pytest.raises((OSError, ValueError)):
        bonjour_owner.private_json(path)
    # Neither does the runtime owner: an unreadable intent inhibits.
    intent = runtime._intent(settings)
    assert intent.damaged and intent.blocks(STOPPED)


@pytest.mark.parametrize("form", UNPROTECTED)
def test_an_unprotected_intent_record_is_never_a_proven_stop(
    site: Site, monkeypatch: pytest.MonkeyPatch, form: str
) -> None:
    """Only 42 makes the supervisor run its start rule."""
    _config, settings, runner, _store = site
    weaken(Path(settings.intent), form)
    assert probe(monkeypatch, settings, runner, STOPPED) == runtime.UNKNOWN
    assert probe(monkeypatch, settings, runner, RUNNING) == runtime.UNKNOWN


@pytest.mark.parametrize("form", UNPROTECTED)
def test_an_unprotected_intent_record_starts_nothing(site: Site, form: str) -> None:
    config, settings, runner, _store = site
    weaken(Path(settings.intent), form)
    with pytest.raises(runtime.RuntimeReadError) as refused:
        runtime.recover_service(config, settings, STOPPED, runner)
    assert refused.value.reason == "incomplete"
    assert not starts(runner)
    assert runner.items[settings.contract(STOPPED).name]["status"]["state"] == "stopped"


@pytest.mark.parametrize("form", UNPROTECTED)
def test_an_unprotected_intent_record_verifies_no_activation(site: Site, form: str) -> None:
    config, settings, runner, _store = site
    request = activation(config, settings, runner)
    weaken(Path(settings.intent), form)
    with pytest.raises(runtime.RuntimeReadError) as refused:
        runtime.handle_request(config, settings, request, runner)
    assert refused.value.reason == "incomplete"


@pytest.mark.parametrize("form", UNPROTECTED)
def test_an_unprotected_admissions_record_admits_nothing(
    site: Site, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], form: str
) -> None:
    config, settings, runner, _store = site
    request = activation(config, settings, runner)
    path = Path(settings.admissions)
    weaken(path, form)
    # The record still names the exact admission; only its form is refused.
    assert path.read_bytes() == canonical_bytes(admissions_to_dict(mock_admissions(config))) + b"\n"
    with pytest.raises((OSError, ValueError)):
        runtime.handle_request(config, settings, request, runner)
    # Through the endpoint command the refusal is one redacted line and no trace.
    # The stage gate refuses every activation before it is read; this seam lets
    # the retained endpoint itself answer.
    handle = runtime.handle_request
    monkeypatch.setattr(runtime, "require_request_qualified", lambda _provider, _request: None)
    monkeypatch.setattr(runtime, "load_settings", lambda _path: settings)
    monkeypatch.setattr(runtime, "handle_request", lambda *arguments: handle(*arguments, runner))
    monkeypatch.setattr(runtime.sys, "stdin", TextIOWrapper(BytesIO(canonical_bytes(request))))
    assert runtime.main(["--settings", "/unused/settings.json", "request"]) == runtime.UNKNOWN
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", REDACTED)


def test_an_intent_record_of_another_user_is_damaged_intent(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The caller must own the record; here the caller is made someone else."""
    _config, settings, _runner, _store = site
    assert runtime._intent(settings) == Intent()
    stranger = os.geteuid() + 1
    monkeypatch.setattr(os, "geteuid", lambda: stranger)
    assert runtime._intent(settings) == Intent(damaged=True)


def test_an_admissions_record_of_another_user_admits_nothing(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, settings, runner, _store = site
    request = activation(config, settings, runner)
    stranger = os.geteuid() + 1
    monkeypatch.setattr(os, "geteuid", lambda: stranger)
    # The intent is made readable so that the admissions alone decide.
    monkeypatch.setattr(runtime, "_intent", lambda _settings: Intent())
    with pytest.raises(ValueError):
        runtime.handle_request(config, settings, request, runner)


@pytest.mark.parametrize("kind", ["named-pipe", "directory", "missing"])
def test_a_record_that_is_no_file_is_closed_without_waiting(site: Site, kind: str) -> None:
    """Opening a named pipe for reading waits for a writer unless the open is nonblocking."""
    config, settings, runner, _store = site
    request = activation(config, settings, runner)
    for name in ("intent", "admissions"):
        path = Path(getattr(settings, name))
        path.unlink()
        if kind == "named-pipe":
            os.mkfifo(path, 0o600)
        elif kind == "directory":
            path.mkdir(mode=0o700)
    outcome: list[object] = []

    def read() -> None:
        outcome.append(runtime._intent(settings))
        try:
            runtime.handle_request(config, settings, request, runner)
        except (OSError, ValueError):
            outcome.append("admissions refused")

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    reader.join(10)
    assert not reader.is_alive()
    assert outcome == [Intent(damaged=True), "admissions refused"]


@pytest.mark.parametrize("excess", [0, 1])
def test_a_record_is_read_up_to_one_mebibyte(site: Site, excess: int) -> None:
    _config, settings, _runner, _store = site
    path = Path(settings.intent)
    document = canonical_bytes(intent_to_dict(Intent(7)))
    path.write_bytes(document + b" " * (1_048_576 - len(document) + excess))
    assert path.stat().st_mode & 0o777 == 0o600 and path.stat().st_size == 1_048_576 + excess
    assert runtime._intent(settings) == (Intent(damaged=True) if excess else Intent(7))

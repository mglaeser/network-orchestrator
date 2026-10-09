"""Synthetic boundary regressions from the PF/deployment evidence audit.

These tests do not invoke PF, launchd or a production owner. The subprocess
lock test uses only disposable user-owned files and this test interpreter.
"""

from __future__ import annotations

import os
import select
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as deployment
import netorch.pf_owner as pf_owner
from netorch.codec import canonical_bytes
from netorch.deployment_config import DeploymentError
from netorch.pf_owner import PFError
from netorch.process import Result
from netorch.storage import Busy, Store, UnsafeState
from tests.test_deployment import config, make_bundle, manifest
from tests.test_pf_owner import environment, shell_backend

__all__ = ["config", "environment", "manifest"]


@pytest.mark.parametrize("method", ["ensure_reference", "reference_held"])
@pytest.mark.parametrize(
    "saved",
    [{"token": 42}, {"token": True}, {"token": 42.0}, {"token": None}, {"token": []}],
    ids=["integer", "boolean", "float", "null", "list"],
)
def test_corrupt_reference_type_never_acquires_or_reads_native_state(
    environment: Any, monkeypatch: pytest.MonkeyPatch, method: str, saved: Any
) -> None:
    backend = shell_backend(environment, monkeypatch)
    root = environment[0]
    root.write("reference.json", saved)
    calls: list[str] = []

    def native(operation: str, *arguments: str) -> str:
        calls.append(operation)
        if operation == "enable":
            return "pf enabled\nToken : 43"
        if operation == "references":
            return "123 owner 42 0 days 00:00:00\n124 owner 43 0 days 00:00:00"
        return ""

    monkeypatch.setattr(backend, "_call", native)
    with pytest.raises(PFError, match="damaged"):
        getattr(backend, method)()
    assert calls == []
    assert root.read("reference.json") == saved


@pytest.mark.parametrize("count", [0, -1])
def test_state_write_without_progress_preserves_old_record_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, count: int
) -> None:
    store = Store(tmp_path / "private")
    store.write("intent.json", {"paused": True})
    calls: list[int] = []

    def no_progress(fd: int, payload: Any) -> int:
        calls.append(len(payload))
        return count

    monkeypatch.setattr("netorch.storage.os.write", no_progress)
    with pytest.raises(UnsafeState, match="progress"):
        store.write("intent.json", {"paused": False})
    assert len(calls) == 1
    assert store.read("intent.json") == {"paused": True}
    assert not list(store.directory.glob(".write-*"))


def test_short_state_writes_persist_complete_bytes_before_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = Store(tmp_path / "private")
    native_write = os.write
    counts: list[int] = []

    def short_write(fd: int, payload: Any) -> int:
        written = native_write(fd, payload[:7])
        counts.append(written)
        return written

    monkeypatch.setattr("netorch.storage.os.write", short_write)
    value = {"paused": True, "reason": "bounded partial writes"}
    store.write("intent.json", value)
    path = store.directory / "intent.json"
    assert len(counts) > 1 and all(0 < count <= 7 for count in counts)
    assert path.read_bytes() == canonical_bytes(value) + b"\n"
    assert store.read("intent.json") == value
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_directory_sync_failure_is_not_misreported_as_an_unchanged_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = Store(tmp_path / "private")
    store.write("intent.json", {"paused": False})
    native_fsync = os.fsync

    def fail_parent_sync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected durability failure after rename")
        native_fsync(fd)

    monkeypatch.setattr("netorch.storage.os.fsync", fail_parent_sync)
    with pytest.raises(OSError, match="after rename"):
        store.write("intent.json", {"paused": True})
    # The rename happened before the parent sync failed. Recovery must read
    # the current complete record; this exception proves no crash durability.
    assert store.read("intent.json") == {"paused": True}
    assert not list(store.directory.glob(".write-*"))


def test_process_death_releases_flock_without_replacing_its_inode(tmp_path: Path) -> None:
    store = Store(tmp_path / "private")
    script = """
import sys
from pathlib import Path
from netorch.storage import Store
with Store(Path(sys.argv[1])).lock():
    print("locked", flush=True)
    sys.stdin.buffer.read(1)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(store.directory)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert child.stdout is not None
        ready, _, _ = select.select([child.stdout], [], [], 10)
        assert ready, "disposable lock holder did not become ready"
        assert child.stdout.readline() == b"locked\n"
        identity = (store.directory / "owner.lock").stat().st_ino
        with pytest.raises(Busy), store.lock():
            pytest.fail("a live process still owns the lock")
        child.kill()
        child.wait(timeout=10)
        with store.lock():
            assert (store.directory / "owner.lock").stat().st_ino == identity
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)


def test_prepared_bundle_does_not_claim_reviewed_bytes_after_source_changes(
    tmp_path: Path, manifest: dict[str, Any], config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, _ = make_bundle(tmp_path, manifest, config)
    output = tmp_path / "prepared"
    native_validate = deployment.validate_bundle

    def validate_then_change(path: Path) -> dict[str, Any]:
        admitted = native_validate(path)
        # A new single-link file with safe mode may still have different bytes
        # by the time prepare reads it. Installation must not be relied upon to
        # discover that a supposedly prepared bundle was copied incorrectly.
        (path / "user/data/network.json").write_bytes(b"{}\n")
        return admitted

    monkeypatch.setattr(deployment, "validate_bundle", validate_then_change)
    with pytest.raises(DeploymentError, match=r"changed.*preparation"):
        deployment.prepare_root_bundle(bundle, output)
    assert not output.exists()


@pytest.mark.parametrize("operation", ["owner-busy", "bootout"])
def test_delayed_wakeup_does_not_start_another_tool_after_the_wait_deadline(
    operation: str,
) -> None:
    current = 100.0
    calls: list[tuple[float, tuple[str, ...]]] = []
    slept: list[float] = []

    def clock() -> float:
        return current

    def delayed_sleep(seconds: float) -> None:
        nonlocal current
        slept.append(seconds)
        # A real scheduler may resume this process well after a requested
        # short sleep. A requested duration is not an observation of elapsed time.
        current += 30.0

    def runner(argv: tuple[str, ...]) -> Result:
        calls.append((current, argv))
        return Result(75 if operation == "owner-busy" else 0, b"", b"")

    if operation == "owner-busy":
        bounded = deployment._owner_busy_retry(runner, clock, delayed_sleep)
        result = bounded(("/test/python", "-I", "-m", "netorch.pf_owner", "withdraw"))
        assert result.returncode == 75
        assert len(calls) == 1
    else:
        deployment._bootout(
            runner,
            "/bin/launchctl",
            "system/example.owner",
            reloaded=True,
            clock=clock,
            sleep=delayed_sleep,
        )
        assert [argv[1] for _, argv in calls] == ["bootout", "print"]
    assert len(slept) == 1
    assert all(started == 100.0 for started, _ in calls)


@pytest.mark.parametrize("field", ["kind", "effective_strategy"])
@pytest.mark.parametrize("value", [[], {}], ids=["array", "object"])
def test_malformed_owned_record_enums_fail_with_a_closed_owner_error(
    field: str, value: Any
) -> None:
    record = {
        "active": False,
        "kind": "guest-direct",
        "effective_strategy": None,
        "target_ipv4": "198.51.100.12",
        "target_generation": "instance-one",
        "network_generation": "network-one",
        "policy_digest": "a" * 64,
        "rules": "",
    }
    record[field] = value
    with pytest.raises(PFError, match="owned profile record is damaged"):
        pf_owner._records({"schema_version": 1, "records": {"dns-tcp": record}})

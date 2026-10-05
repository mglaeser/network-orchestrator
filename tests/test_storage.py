import os
import stat
from pathlib import Path

import pytest

from netorch.storage import Busy, Store, UnsafeState


def test_write_byte_bound_includes_framing_and_preserves_previous_state(tmp_path: Path):
    store = Store(tmp_path / "private")
    store.write("intent.json", {"operator_paused": True})
    # Exactly 1 MiB of canonical JSON; a trailing newline exceeds the read bound.
    value = ["a" * 65533 for _ in range(16)]
    value[0] = value[0][:-1]
    with pytest.raises(UnsafeState, match="size bound"):
        store.write("intent.json", value)
    assert store.read("intent.json") == {"operator_paused": True}
    assert not list(store.directory.glob(".write-*"))


def test_round_trip_and_lock(tmp_path: Path):
    store = Store(tmp_path / "private")
    store.write("intent.json", {"paused": True})
    assert store.read("intent.json") == {"paused": True}
    with store.lock(), pytest.raises(Busy), Store(tmp_path / "private").lock():
        pass


def test_symlink_and_wrong_permissions(tmp_path: Path):
    store = Store(tmp_path / "private")
    (store.directory / "secret.json").symlink_to(tmp_path / "outside")
    with pytest.raises(OSError):
        store.write("secret.json", {})
    store.write("regular.json", {})
    (store.directory / "regular.json").chmod(0o644)
    with pytest.raises(UnsafeState):
        store.read("regular.json")
    with pytest.raises(UnsafeState):
        store.write("../escape", {})


def test_hardlinks_and_unsafe_directory(tmp_path: Path):
    store = Store(tmp_path / "private")
    store.write("a.json", {})
    (store.directory / "b.json").hardlink_to(store.directory / "a.json")
    with pytest.raises(UnsafeState):
        store.read("a.json")
    (tmp_path / "public").mkdir(mode=0o755)
    with pytest.raises(UnsafeState):
        Store(tmp_path / "public")


@pytest.mark.parametrize("operation", ["read", "write", "lock"])
def test_directory_replacement_after_initialization_is_rejected(tmp_path, operation):
    store = Store(tmp_path / "state")
    store.write("intent.json", {"paused": True})
    original = tmp_path / "original-state"
    store.directory.rename(original)
    store.directory.mkdir(mode=0o700)
    marker = store.directory / "intent.json"
    marker.write_text('{"replacement":true}')
    marker.chmod(0o600)
    with pytest.raises(UnsafeState, match="identity"):
        if operation == "read":
            store.read("intent.json")
        elif operation == "write":
            store.write("intent.json", {"paused": False})
        else:
            with store.lock():
                pytest.fail("a replacement directory cannot acquire the original owner lock")
    assert marker.read_text() == '{"replacement":true}'
    assert (original / "intent.json").read_text() == '{"paused":true}\n'


@pytest.mark.parametrize("operation", ["read", "write", "lock"])
def test_private_directory_permissions_rechecked_on_every_operation(tmp_path, operation):
    store = Store(tmp_path / "state")
    store.write("intent.json", {})
    store.directory.chmod(0o755)
    with pytest.raises(UnsafeState):
        if operation == "read":
            store.read("intent.json")
        elif operation == "write":
            store.write("intent.json", {})
        else:
            with store.lock():
                pytest.fail("insecure directory cannot acquire a lock")


def test_initial_and_replacement_symlink_directories_are_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    link = tmp_path / "linked"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafeState):
        Store(link)
    store = Store(tmp_path / "state")
    store.directory.rename(tmp_path / "old-state")
    store.directory.symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafeState):
        store.write("intent.json", {})
    assert list(outside.iterdir()) == []


def test_path_swap_during_write_uses_owned_descriptor_and_cleans_original_temp(
    tmp_path, monkeypatch
):
    store = Store(tmp_path / "state")
    store.write("intent.json", {"old": True})
    original = tmp_path / "original"
    from netorch.codec import canonical_bytes

    def swap_then_encode(value):
        result = canonical_bytes(value)
        store.directory.rename(original)
        store.directory.mkdir(mode=0o700)
        return result

    monkeypatch.setattr("netorch.storage.canonical_bytes", swap_then_encode)
    with pytest.raises(UnsafeState, match="identity"):
        store.write("intent.json", {"replacement": True})
    assert (original / "intent.json").read_text() == '{"old":true}\n'
    assert not list(original.glob(".write-*"))
    assert list(store.directory.iterdir()) == []


def test_failed_atomic_replace_preserves_old_value_and_removes_temporary(tmp_path, monkeypatch):
    store = Store(tmp_path / "state")
    store.write("intent.json", {"old": True})
    calls = []

    def fail_replace(source, destination, **kwargs):
        calls.append((source, destination, kwargs))
        raise OSError("injected replacement failure")

    monkeypatch.setattr("netorch.storage.os.replace", fail_replace)
    with pytest.raises(OSError, match="replacement failure"):
        store.write("intent.json", {"new": True})
    assert store.read("intent.json") == {"old": True}
    assert not list(store.directory.glob(".write-*"))
    assert calls[0][0].startswith(".write-") and calls[0][1] == "intent.json"
    assert calls[0][2]["src_dir_fd"] == calls[0][2]["dst_dir_fd"]


def test_failed_temporary_fsync_leaves_old_state_and_no_temp(tmp_path, monkeypatch):
    store = Store(tmp_path / "state")
    store.write("intent.json", {"old": True})
    real_fsync = os.fsync

    def fail_regular_file(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("injected file sync failure")
        real_fsync(fd)

    monkeypatch.setattr("netorch.storage.os.fsync", fail_regular_file)
    with pytest.raises(OSError, match="sync failure"):
        store.write("intent.json", {"new": True})
    assert store.read("intent.json") == {"old": True}
    assert not list(store.directory.glob(".write-*"))


def test_atomic_write_syncs_file_then_pinned_directory(tmp_path, monkeypatch):
    store = Store(tmp_path / "state")
    synced = []
    real_fsync = os.fsync

    def record_fsync(fd):
        synced.append(os.fstat(fd).st_mode)
        real_fsync(fd)

    monkeypatch.setattr("netorch.storage.os.fsync", record_fsync)
    store.write("intent.json", {"paused": True})
    assert len(synced) == 2
    assert stat.S_ISREG(synced[0]) and stat.S_ISDIR(synced[1])
    assert stat.S_IMODE((store.directory / "intent.json").stat().st_mode) == 0o600


def test_exclusive_temporary_name_never_overwrites_preexisting_file(tmp_path, monkeypatch):
    store = Store(tmp_path / "state")
    collision = store.directory / ".write-collision"
    collision.write_text("retain this preexisting file")
    collision.chmod(0o600)
    monkeypatch.setattr("netorch.storage.secrets.token_hex", lambda count: "collision")
    with pytest.raises(UnsafeState, match="exclusive"):
        store.write("intent.json", {})
    assert collision.read_text() == "retain this preexisting file"
    assert not (store.directory / "intent.json").exists()


def test_temporary_collision_retries_with_new_exclusive_name(tmp_path, monkeypatch):
    store = Store(tmp_path / "state")
    collision = store.directory / ".write-collision"
    collision.write_text("original")
    collision.chmod(0o600)
    tokens = iter(("collision", "fresh"))
    monkeypatch.setattr("netorch.storage.secrets.token_hex", lambda count: next(tokens))
    store.write("intent.json", {"paused": True})
    assert store.read("intent.json") == {"paused": True}
    assert collision.read_text() == "original"
    assert not (store.directory / ".write-fresh").exists()


@pytest.mark.parametrize(
    "name", ["", ".", "..", "../escape", "/absolute", "bad\x00name", "newline\n", "x" * 256]
)
def test_state_names_are_bounded_leaf_names(tmp_path, name):
    store = Store(tmp_path / "state")
    with pytest.raises(UnsafeState, match="name"):
        store.write(name, {})


def test_lock_symlink_and_hardlink_are_rejected(tmp_path):
    store = Store(tmp_path / "state")
    outside = tmp_path / "outside"
    outside.write_text("")
    outside.chmod(0o600)
    (store.directory / "owner.lock").symlink_to(outside)
    with pytest.raises(OSError), store.lock():
        pass
    (store.directory / "owner.lock").unlink()
    (store.directory / "owner.lock").hardlink_to(outside)
    with pytest.raises(UnsafeState), store.lock():
        pass

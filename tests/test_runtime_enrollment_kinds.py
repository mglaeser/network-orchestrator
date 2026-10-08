"""Whatever `capture_enrollment` returns, `parse_settings` accepts.

`enroll` writes the capture, and every later command reads it through the
settings loader. A capture the loader refuses is therefore a file that nothing
can use: a mount that is neither a directory, a file nor a socket, a mount
source that is no canonical absolute path, more mounts than a contract may
list, or a volume identifier in another spelling. The capture refuses each of
them itself, with the closed error of its other checks, and writes nothing.
Everything native is faked here.
"""

from __future__ import annotations

import copy
import os
import socket
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from netorch import apple_runtime as runtime
from netorch.runtime_settings import FileIdentity, load_settings, parse_settings, settings_to_dict
from tests.test_apple_runtime import FakeRunner, enrolled

__all__ = ["enrolled"]

VOLUME = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
NIL = "00000000-0000-0000-0000-000000000000"
REDACTED = '{"error":"runtime-evidence-or-authority-incomplete"}\n'
# The three kinds the settings loader reads, and what else a host path can be.
LOADABLE = ["directory", "file", "socket"]
OTHER_KINDS = ["pipe", "device"]
# A source the loader does not take as a path. `memory` and `empty` are what the
# vendor records for a memory-backed mount, which has no host path: `tmpfs`
# (apple/container `Filesystem.tmpfs`, tags 1.2.0 and 1.5.0) and, for
# `--mount type=tmpfs` at 1.2.0, the empty default of `Filesystem()`. Both name
# an existing directory here, seen from the working directory.
NO_PATH = ["dot-dot", "dot", "memory", "empty"]
UNREADABLE = ["link", "missing"]


@pytest.fixture(autouse=True)
def without_acl_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ACL reader has its own tests and, on Darwin, its own list of file types."""
    monkeypatch.setattr(runtime, "_identity_acl", lambda _path, **_kwargs: None)


@pytest.fixture
def sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """One mount source of every kind, and spellings of the directory that are no path."""
    root = (tmp_path / "sources").resolve()
    for path in (root, root / "directory", root / "tmpfs"):
        path.mkdir(mode=0o700)
    (root / "file").write_bytes(b"content")
    (root / "file").chmod(0o600)
    os.mkfifo(root / "pipe", 0o600)
    (root / "link").symlink_to(root / "directory")
    # A relative source is resolved against the working directory of the command.
    monkeypatch.chdir(root)
    leaf = socket.socket(socket.AF_UNIX)
    try:
        # Bound by its relative name: the whole path can be longer than an address.
        leaf.bind("socket")
    finally:
        leaf.close()
    return {
        **{name: str(root / name) for name in ("directory", "file", "socket", "pipe", "link")},
        "device": "/dev/null",
        "missing": str(root / "missing"),
        "dot-dot": f"{root}/directory/../directory",
        "dot": f"{root}/./directory",
        "memory": "tmpfs",
        "empty": "",
    }


def mounted(enrolled: Any, sources: list[str], service: str = "camera") -> tuple[Any, Any]:
    """The enrolled settings, and the fleet with one guest's mounts replaced."""
    _config, settings, items = enrolled
    items = copy.deepcopy(items)
    items[settings.contract(service).name]["configuration"]["mounts"] = [
        {"source": source, "options": ["rw"]} for source in sources
    ]
    return settings, items


def capture(settings: Any, items: Any, binding: str = "device") -> Any:
    return runtime.capture_enrollment(
        settings, FakeRunner(settings, items), identity_binding=binding
    )


@pytest.mark.parametrize("binding", ["device", "volume-uuid"])
def test_a_capture_of_directories_files_and_sockets_loads_again(
    enrolled: Any, sources: dict[str, str], monkeypatch: pytest.MonkeyPatch, binding: str
) -> None:
    asked: list[int] = []

    def provider(fd: int) -> str:
        asked.append(os.fstat(fd).st_ino)
        return VOLUME

    monkeypatch.setattr(runtime, "volume_uuid", provider)
    settings, items = mounted(enrolled, [sources[kind] for kind in LOADABLE])
    captured = capture(settings, items, binding)
    assert parse_settings(settings_to_dict(captured)) == captured
    mounts = captured.contract("camera").mounts
    assert [(item.path, item.kind) for item in mounts] == [
        (sources[kind], kind) for kind in LOADABLE
    ]
    # A socket binds neither a device nor an inode, and it is never opened.
    leaf = os.lstat(sources["socket"])
    assert mounts[2] == FileIdentity(sources["socket"], "socket", leaf.st_uid)
    assert leaf.st_ino not in asked
    bound = [os.lstat(sources[kind]).st_ino for kind in ("directory", "file")]
    assert [inode for inode in asked if inode in bound] == (
        bound if binding == "volume-uuid" else []
    )


@pytest.mark.parametrize("kind", OTHER_KINDS)
@pytest.mark.parametrize("binding", ["device", "volume-uuid"])
def test_a_mount_of_another_kind_is_refused_before_it_is_examined(
    enrolled: Any, sources: dict[str, str], monkeypatch: pytest.MonkeyPatch, kind: str, binding: str
) -> None:
    examined: list[str] = []
    check = runtime.check_identity

    def recording(identity: FileIdentity, **arguments: Any) -> None:
        examined.append(identity.path)
        check(identity, **arguments)

    monkeypatch.setattr(runtime, "check_identity", recording)
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: VOLUME)
    settings, items = mounted(enrolled, [sources["directory"], sources[kind]])
    with pytest.raises(runtime.RuntimeReadError) as refused:
        capture(settings, items, binding)
    assert refused.value.reason == "identity-mismatch"
    assert sources["directory"] in examined and sources[kind] not in examined


@pytest.mark.parametrize("spelling", NO_PATH)
@pytest.mark.parametrize("binding", ["device", "volume-uuid"])
def test_a_source_that_is_no_canonical_absolute_path_is_refused(
    enrolled: Any,
    sources: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    spelling: str,
    binding: str,
) -> None:
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: VOLUME)
    # The source names an existing private directory, so every identity check passes.
    assert Path(sources[spelling]).is_dir()
    settings, items = mounted(enrolled, [sources[spelling]])
    with pytest.raises(runtime.RuntimeReadError) as refused:
        capture(settings, items, binding)
    assert refused.value.reason == "identity-mismatch"


@pytest.mark.parametrize("count", [128, 129])
def test_a_contract_is_captured_with_the_mounts_it_may_list(
    enrolled: Any, sources: dict[str, str], count: int
) -> None:
    settings, items = mounted(enrolled, [sources["directory"]] * count)
    if count == 128:
        captured = capture(settings, items)
        assert len(captured.contract("camera").mounts) == 128
        assert parse_settings(settings_to_dict(captured)) == captured
    else:
        with pytest.raises(runtime.RuntimeReadError) as refused:
            capture(settings, items)
        assert refused.value.reason == "identity-mismatch"


@pytest.mark.parametrize("reply", [VOLUME.upper(), NIL, "", "no-volume", VOLUME + "\n"])
def test_a_volume_identifier_in_another_spelling_is_refused(
    enrolled: Any, sources: dict[str, str], monkeypatch: pytest.MonkeyPatch, reply: str
) -> None:
    """The real provider decodes one lower-case form; the capture does not rely on that."""
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: reply)
    settings, items = mounted(enrolled, [sources["directory"]])
    assert capture(settings, items).contract("camera").mounts[0].volume_uuid is None
    with pytest.raises(runtime.RuntimeReadError) as refused:
        capture(settings, items, "volume-uuid")
    assert refused.value.reason == "identity-mismatch"


@pytest.mark.parametrize("reply", [VOLUME, VOLUME.upper()])
def test_a_receipt_alone_decides_whether_the_capture_loads(
    enrolled: Any, sources: dict[str, str], monkeypatch: pytest.MonkeyPatch, reply: str
) -> None:
    """Every mount loads; only the one receipt gets the provider's other spelling."""
    settings, items = mounted(enrolled, [sources["socket"]])
    meta = os.lstat(sources["file"])
    receipt = FileIdentity(sources["file"], "file", meta.st_uid, meta.st_dev, meta.st_ino)
    settings = replace(
        settings,
        contracts=tuple(
            replace(contract, receipts=(receipt,)) if contract.service == "camera" else contract
            for contract in settings.contracts
        ),
    )
    monkeypatch.setattr(
        runtime,
        "volume_uuid",
        lambda fd: reply if os.fstat(fd).st_ino == meta.st_ino else VOLUME,
    )
    if reply == VOLUME:
        captured = capture(settings, items, "volume-uuid")
        assert parse_settings(settings_to_dict(captured)) == captured
        assert captured.contract("camera").receipts == (
            replace(receipt, device=None, volume_uuid=VOLUME),
        )
    else:
        with pytest.raises(runtime.RuntimeReadError) as refused:
            capture(settings, items, "volume-uuid")
        assert refused.value.reason == "identity-mismatch"


def test_the_capture_returns_the_given_settings_with_new_contracts(
    enrolled: Any, sources: dict[str, str]
) -> None:
    """Checked through the loader, never replaced by what the loader builds.

    A caller may hold its networks in a list where the loader makes a tuple. The
    stored form is the same, so the capture is not refused, and every member but
    the contracts is the caller's own object.
    """
    settings, items = mounted(enrolled, [sources["directory"]])
    settings = replace(settings, networks=list(settings.networks))
    captured = capture(settings, items)
    assert captured.networks is settings.networks and captured.account is settings.account
    read_back = parse_settings(settings_to_dict(captured))
    assert read_back != captured
    assert read_back == replace(captured, networks=tuple(settings.networks))


def enroll(
    monkeypatch: pytest.MonkeyPatch, settings: Any, items: Any, output: Path, *options: str
) -> int:
    """The command as it runs, with the settings given and the native tool faked."""
    real = runtime.capture_enrollment
    with monkeypatch.context() as patch:
        patch.setattr(runtime, "load_settings", lambda _path: settings)
        patch.setattr(
            runtime,
            "capture_enrollment",
            lambda actual, **keywords: real(actual, FakeRunner(actual, items), **keywords),
        )
        return runtime.main(["--settings", "/unused", "enroll", "--output", str(output), *options])


@pytest.mark.parametrize("options", [(), ("--identity", "volume-uuid")])
def test_enroll_writes_what_the_settings_loader_reads(
    enrolled: Any,
    sources: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    options: tuple[str, ...],
) -> None:
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: VOLUME)
    settings, items = mounted(enrolled, [sources[kind] for kind in LOADABLE])
    output = tmp_path / "enrollment.next.json"
    assert enroll(monkeypatch, settings, items, output, *options) == 0
    assert '"captured":true' in capsys.readouterr().out
    written = load_settings(output)
    assert written == capture(settings, items, options[-1] if options else "device")
    assert [item.kind for item in written.contract("camera").mounts] == LOADABLE


@pytest.mark.parametrize("unloadable", [*OTHER_KINDS, *NO_PATH])
def test_enroll_writes_nothing_that_the_settings_loader_refuses(
    enrolled: Any,
    sources: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    unloadable: str,
) -> None:
    settings, items = mounted(enrolled, [sources["directory"], sources[unloadable]])
    output = tmp_path / "enrollment.next.json"
    assert enroll(monkeypatch, settings, items, output) == runtime.UNKNOWN
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", REDACTED)
    assert not output.exists()


@hypothesis_settings(max_examples=100, deadline=None, suppress_health_check=list(HealthCheck))
@given(
    chosen=st.lists(
        st.lists(st.sampled_from([*LOADABLE, *OTHER_KINDS, *NO_PATH, *UNREADABLE]), max_size=4),
        min_size=4,
        max_size=4,
    ),
    binding=st.sampled_from(["device", "volume-uuid"]),
    reply=st.sampled_from([VOLUME, VOLUME.upper(), NIL, "no-volume"]),
)
def test_whatever_the_capture_returns_the_settings_loader_accepts(
    enrolled: Any,
    sources: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    chosen: list[list[str]],
    binding: str,
    reply: str,
) -> None:
    """Each guest gets up to four mounts of any kind or spelling; both bindings; any reply."""
    _config, settings, items = enrolled
    items = copy.deepcopy(items)
    for contract, kinds in zip(settings.contracts, chosen, strict=True):
        items[contract.name]["configuration"]["mounts"] = [
            {"source": sources[kind], "options": ["rw"]} for kind in kinds
        ]
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: reply)
    try:
        captured = capture(settings, items, binding)
    except (runtime.RuntimeReadError, OSError):
        captured = None
    everything = [kind for kinds in chosen for kind in kinds]
    # The volume is asked for directories and files only, and only when it is bound.
    asked = binding == "volume-uuid" and bool({"directory", "file"} & set(everything))
    loadable = set(everything) <= set(LOADABLE) and (not asked or reply == VOLUME)
    # A capture is refused exactly when its stored form would not load.
    assert (captured is not None) == loadable
    if captured is not None:
        assert parse_settings(settings_to_dict(captured)) == captured
        assert [[item.path for item in contract.mounts] for contract in captured.contracts] == [
            [sources[kind] for kind in kinds] for kinds in chosen
        ]

"""An enrolled mount or receipt can bind its volume instead of a device number.

A device number is assigned when a volume is mounted, so it can differ after a
restart while the volume and its inode numbers are unchanged. The volume-bound
identity is opt-in; every device-bound enrollment keeps its bytes and digests.

The Darwin call itself is never made here: the decoder gets constructed replies,
the entry point gets a stand-in library, and the reader gets a provider that
answers from the descriptor. Synthetic data only.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import importlib
import os
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch import pf_owner as owner
from netorch.codec import canonical_bytes, digest, strict_load
from netorch.config import load_config, to_dict
from netorch.model import Config
from netorch.pf_owner import STRATEGY, Installation, admit, reconcile
from netorch.process import Result
from netorch.runtime_settings import (
    FileIdentity,
    RuntimeSettings,
    contract_digest,
    load_settings,
    parse_settings,
    settings_to_dict,
)
from netorch.state import Intent, intent_to_dict
from netorch.storage import Store
from netorch.workloads import parse_workloads, provision_digest
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_pf_owner import FakeBackend

__all__ = ["enrolled"]

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
VOLUME_BYTES = bytes(range(0x10, 0x20))
OTHER_BYTES = bytes(range(0xA0, 0xB0))


def _text(raw: bytes) -> str:
    value = raw.hex()
    return "-".join((value[:8], value[8:12], value[12:16], value[16:20], value[20:]))


VOLUME = _text(VOLUME_BYTES)
OTHER = _text(OTHER_BYTES)
EMPTY = _text(bytes(16))


def _provider() -> Any:
    """Imported on use, so that this file is still collected without the module."""
    return importlib.import_module("netorch.darwin_volume")


def _word(value: int) -> bytes:
    return value.to_bytes(4, sys.byteorder)


def _reply(
    identifier: bytes = VOLUME_BYTES,
    *,
    length: int = 40,
    common: int = 0x80000000,
    volume: int = 0x00040000,
    directory: int = 0,
    file: int = 0,
    fork: int = 0,
) -> bytes:
    words = (length, common, volume, directory, file, fork)
    return b"".join(_word(item) for item in words) + identifier


# The decoder and the call ----------------------------------------------------


def test_decoder_accepts_one_complete_reply_only() -> None:
    decode = _provider().decode_volume_uuid
    assert decode(_reply()) == VOLUME
    assert decode(_reply(OTHER_BYTES)) == OTHER
    # The request fixes the layout, so further bits of the two requested groups
    # cannot move the identifier.
    assert decode(_reply(volume=0x80040000)) == VOLUME
    assert decode(_reply(common=0x80000001)) == VOLUME
    refused = {
        "one byte short": _reply()[:-1],
        "one byte long": _reply() + b"\0",
        "empty": b"",
        "length word says less": _reply(length=36),
        "length word says more": _reply(length=44),
        "returned set not marked": _reply(common=0),
        "volume without identifier": _reply(bytes(16), volume=0),
        "another volume attribute only": _reply(volume=0x80000000),
        "directory group named": _reply(directory=1),
        "file group named": _reply(file=1),
        "fork group named": _reply(fork=1),
        "identifier all zero": _reply(bytes(16)),
    }
    for name, reply in refused.items():
        with pytest.raises(ValueError):
            decode(reply)
            pytest.fail(f"accepted a reply that is {name}")


def test_provider_refuses_other_platforms(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = _provider()
    monkeypatch.setattr(provider.sys, "platform", "linux")
    monkeypatch.setattr(
        provider.ctypes, "CDLL", lambda *args, **kwargs: pytest.fail("library loaded off Darwin")
    )
    with pytest.raises(OSError):
        provider.volume_uuid(0)


class _Entry:
    """Stands in for the C library's entry point and records what it is given."""

    def __init__(self, reply: bytes = b"", error: int = 0) -> None:
        self.reply = reply
        self.error = error
        self.calls: list[tuple[int, bytes, int, int, int]] = []
        self.argtypes: list[Any] = []
        self.restype: Any = None

    def __call__(self, fd: int, request: bytes, buffer: Any, size: int, options: int) -> int:
        self.calls.append((fd, bytes(request), len(buffer), size, options))
        if self.error:
            ctypes.set_errno(self.error)
            return -1
        buffer.raw = self.reply
        return 0


def _library(monkeypatch: pytest.MonkeyPatch, entry: _Entry) -> list[tuple[Any, dict[str, Any]]]:
    provider = _provider()
    loaded: list[tuple[Any, dict[str, Any]]] = []

    def load(name: Any, **kwargs: Any) -> Any:
        loaded.append((name, kwargs))
        return type("Library", (), {"fgetattrlist": entry})()

    monkeypatch.setattr(provider.sys, "platform", "darwin")
    monkeypatch.setattr(provider.ctypes, "CDLL", load)
    return loaded


def test_provider_makes_one_fixed_request(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = _Entry(_reply())
    loaded = _library(monkeypatch, entry)
    assert _provider().volume_uuid(7) == VOLUME
    # The process's own C library, with the error number kept for this call.
    assert loaded == [(None, {"use_errno": True})]
    # struct attrlist: count 5, reserved 0, ATTR_CMN_RETURNED_ATTRS,
    # ATTR_VOL_INFO | ATTR_VOL_UUID, and no directory, file or fork attribute.
    request = (
        (5).to_bytes(2, sys.byteorder)
        + bytes(2)
        + _word(0x80000000)
        + _word(0x80040000)
        + bytes(12)
    )
    # FSOPT_REPORT_FULLSIZE | FSOPT_PACK_INVAL_ATTRS, into a buffer of 40 bytes.
    assert entry.calls == [(7, request, 40, 40, 0x4 | 0x8)]
    # int fgetattrlist(int, void *, void *, size_t, unsigned int)
    assert entry.argtypes == [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint,
    ]
    assert entry.restype is ctypes.c_int


def test_provider_reports_a_failed_call_and_an_unusable_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _library(monkeypatch, _Entry(error=errno.EBADF))
    with pytest.raises(OSError) as failed:
        _provider().volume_uuid(7)
    assert failed.value.errno == errno.EBADF
    # The call succeeded but the volume has no identifier: nothing is returned.
    _library(monkeypatch, _Entry(_reply(bytes(16), volume=0)))
    with pytest.raises(ValueError):
        _provider().volume_uuid(7)


# Settings and digests --------------------------------------------------------


def _authored() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "owner": "camera-manager",
        "executable": "/usr/bin/example-container",
        "accepted_version": "1.5.0",
        "account": {"uid": 1001, "gid": 1001, "home": "/private/operator"},
        "networks": [
            {
                "scope": "wired-lan",
                "name": "test-network",
                "gateway": "198.51.100.1",
                "helper_domain": "gui/1001",
                "helper_label": ".".join(["org", "example", "network"]),
                "helper_executable": "/usr/libexec/example-network",
                "helper_uid": 1001,
            }
        ],
        "contracts": [
            {
                "service": "camera",
                "name": "example-camera",
                "scope": "wired-lan",
                "configuration_sha256": "a" * 64,
                "mounts": [
                    {
                        "path": "/private/volumes/camera",
                        "kind": "directory",
                        "uid": 1001,
                        "device": 1,
                        "inode": 2,
                    },
                    {"path": "/private/runtime/api.sock", "kind": "socket", "uid": 1001},
                ],
                "receipts": [
                    {
                        "path": "/private/receipts/camera.json",
                        "kind": "file",
                        "uid": 1001,
                        "device": 1,
                        "inode": 3,
                        "sha256": "b" * 64,
                    }
                ],
            }
        ],
        "policy": "/private/network.json",
        "admissions": "/private/admissions.json",
        "intent": "/private/state/intent.json",
        "state_dir": "/private/state/runtime",
    }


def test_device_bound_contracts_keep_digest_and_bytes() -> None:
    """Every literal below was computed with the tree this change is based on."""
    settings = parse_settings(_authored())
    assert (
        contract_digest(settings.contract("camera"))
        == "6aebeced64e17d06b35bd73f3a0b616850c5b49168545bbadf30207ecfeb345d"
    )
    stored = canonical_bytes(settings_to_dict(settings))
    assert b"volume_uuid" not in stored
    assert (
        hashlib.sha256(stored).hexdigest()
        == "756bc5a72017441d664b0ae0ee5992e97e1cea4f49e9716e225b42ecc2aee218"
    )
    assert parse_settings(settings_to_dict(settings)) == settings

    shipped = load_settings(EXAMPLES / "runtime-settings.json")
    assert {item.service: contract_digest(item) for item in shipped.contracts} == {
        "resolver": "738717b976875cab43dc7235150aebbaa3b894a4904c86334dcd9d63250ee153",
        "web-proxy": "afcfdc49c1a7fd7b435a54f1cb75b32fb48fb3ea1865f3e31b4b854081bb5508",
        "media-controller": "0067741a703af180b7fac6e0be8d1880699e1db21517ff09d047cfa83d479d19",
        "camera": "07b9fec3b2403f238c5b4689d80815a7bdb0913a1e887c5fb4228a7fc8cc3f45",
    }
    assert (
        hashlib.sha256(canonical_bytes(settings_to_dict(shipped))).hexdigest()
        == "d1307ffc7cb45fb28b71c4cd190e57a4f8548b76b28a66fad9c4eec52cc28ab8"
    )
    # The stored settings are hashed whole into every approved initial provision.
    recipe = parse_workloads(
        {
            "schema_version": 1,
            "workloads": [
                {
                    "service": item.service,
                    "image": f"example.invalid/containers/{item.service}@sha256:" + "0" * 64,
                    "options": [{"flag": "--volume", "value": f"{item.mounts[0].path}:/config:rw"}],
                    "arguments": [],
                }
                for item in shipped.contracts
            ],
        }
    )
    policy = load_config(EXAMPLES / "network.json")
    assert (
        provision_digest(policy, shipped, recipe)
        == "e1cc07334052affe353a6e2c1bf457c02330fe322c3c242c4c959d4f10a265ac"
    )
    assert (
        provision_digest(policy, shipped, recipe, start_initial=True)
        == "d160cf33f2d57008921105f33e80cd83501c630bed9760c98a490bceca99178d"
    )


def test_volume_bound_contract_uses_strategy_v2() -> None:
    document = _authored()
    mount = document["contracts"][0]["mounts"][0]
    del mount["device"]
    mount["volume_uuid"] = VOLUME
    settings = parse_settings(document)
    contract = settings.contract("camera")
    assert contract.mounts[0] == FileIdentity(
        "/private/volumes/camera", "directory", 1001, None, 2, None, VOLUME
    )
    # The complete digest input, spelled out: only the bound identity names a
    # volume; the socket and the device-bound receipt keep their earlier shape.
    assert contract_digest(contract) == digest(
        {
            "strategy": "apple-runtime-enrollment-v2",
            "contract": {
                "service": "camera",
                "name": "example-camera",
                "scope": "wired-lan",
                "configuration_sha256": "a" * 64,
                "mounts": [
                    {
                        "path": "/private/volumes/camera",
                        "kind": "directory",
                        "uid": 1001,
                        "device": None,
                        "inode": 2,
                        "sha256": None,
                        "volume_uuid": VOLUME,
                    },
                    {
                        "path": "/private/runtime/api.sock",
                        "kind": "socket",
                        "uid": 1001,
                        "device": None,
                        "inode": None,
                        "sha256": None,
                    },
                ],
                "receipts": [
                    {
                        "path": "/private/receipts/camera.json",
                        "kind": "file",
                        "uid": 1001,
                        "device": 1,
                        "inode": 3,
                        "sha256": "b" * 64,
                    }
                ],
            },
        }
    )
    # A receipt alone makes the contract volume-bound as well.
    device_bound = parse_settings(_authored()).contract("camera")
    receipt_bound = replace(
        device_bound,
        receipts=(replace(device_bound.receipts[0], device=None, volume_uuid=VOLUME),),
    )
    assert contract_digest(receipt_bound) == digest(
        {
            "strategy": "apple-runtime-enrollment-v2",
            "contract": {
                "service": "camera",
                "name": "example-camera",
                "scope": "wired-lan",
                "configuration_sha256": "a" * 64,
                "mounts": [
                    {
                        "path": "/private/volumes/camera",
                        "kind": "directory",
                        "uid": 1001,
                        "device": 1,
                        "inode": 2,
                        "sha256": None,
                    },
                    {
                        "path": "/private/runtime/api.sock",
                        "kind": "socket",
                        "uid": 1001,
                        "device": None,
                        "inode": None,
                        "sha256": None,
                    },
                ],
                "receipts": [
                    {
                        "path": "/private/receipts/camera.json",
                        "kind": "file",
                        "uid": 1001,
                        "device": None,
                        "inode": 3,
                        "sha256": "b" * 64,
                        "volume_uuid": VOLUME,
                    }
                ],
            },
        }
    )
    assert len({contract_digest(item) for item in (contract, receipt_bound, device_bound)}) == 3
    # The stored form names the volume, carries no device number and loads again.
    stored = settings_to_dict(settings)
    assert stored["contracts"][0]["mounts"][0] == {
        "path": "/private/volumes/camera",
        "kind": "directory",
        "uid": 1001,
        "device": None,
        "inode": 2,
        "sha256": None,
        "volume_uuid": VOLUME,
    }
    assert "volume_uuid" not in stored["contracts"][0]["mounts"][1]
    assert "volume_uuid" not in stored["contracts"][0]["receipts"][0]
    assert parse_settings(stored) == settings


def _identity(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "path": "/private/volumes/camera",
        "kind": "directory",
        "uid": 1001,
        "inode": 2,
        "volume_uuid": VOLUME,
    }
    value.update(changes)
    return {key: item for key, item in value.items() if item is not ...}


@pytest.mark.parametrize(
    "identity",
    [
        pytest.param(_identity(device=1), id="both bindings"),
        pytest.param(_identity(device=0), id="both bindings, device zero"),
        pytest.param(_identity(volume_uuid=...), id="neither binding"),
        pytest.param(_identity(volume_uuid=..., device=None), id="neither, device null"),
        pytest.param(_identity(kind="socket"), id="socket with a volume"),
        pytest.param(_identity(kind="socket", inode=...), id="socket with a volume only"),
        pytest.param(_identity(volume_uuid=VOLUME.upper()), id="upper case"),
        pytest.param(_identity(volume_uuid=EMPTY), id="all zero"),
        pytest.param(_identity(volume_uuid=None), id="explicit null"),
        pytest.param(_identity(volume_uuid=None, device=1), id="explicit null beside a device"),
        pytest.param(_identity(volume_uuid=VOLUME.replace("-", "")), id="no separators"),
        pytest.param(_identity(volume_uuid="{" + VOLUME + "}"), id="braces"),
        pytest.param(_identity(volume_uuid=VOLUME + "\n"), id="trailing newline"),
        pytest.param(_identity(volume_uuid=VOLUME[:-1]), id="short"),
        pytest.param(_identity(volume_uuid=7), id="number"),
        pytest.param(_identity(volume_uuid=[VOLUME]), id="list"),
        pytest.param(_identity(inode=...), id="volume without inode"),
        pytest.param(_identity(inode=None), id="volume with null inode"),
        pytest.param(_identity(inode=True), id="volume with boolean inode"),
        pytest.param(_identity(inode=-1), id="volume with negative inode"),
    ],
)
@pytest.mark.parametrize("table", ["mounts", "receipts"])
def test_identity_names_exactly_one_binding(table: str, identity: dict[str, Any]) -> None:
    document = _authored()
    document["contracts"][0][table] = [identity]
    with pytest.raises(ValueError):
        parse_settings(document)


def test_identity_accepts_each_binding_in_its_one_form() -> None:
    document = _authored()
    document["contracts"][0]["mounts"] = [
        _identity(),
        _identity(path="/private/volumes/stored-form", device=None, kind="file"),
    ]
    document["contracts"][0]["receipts"] = [_identity(kind="file", sha256="c" * 64)]
    contract = parse_settings(document).contracts[0]
    assert [item.volume_uuid for item in (*contract.mounts, *contract.receipts)] == [VOLUME] * 3
    assert [item.device for item in (*contract.mounts, *contract.receipts)] == [None] * 3
    # What was valid before is read as before: a device-bound directory and a
    # socket that may or may not repeat numbers nobody compares.
    document = _authored()
    document["contracts"][0]["mounts"][1].update({"device": 1, "inode": 9})
    contract = parse_settings(document).contracts[0]
    assert (contract.mounts[0].device, contract.mounts[0].volume_uuid) == (1, None)
    assert (contract.mounts[1].device, contract.mounts[1].inode) == (1, 9)


# The reader ------------------------------------------------------------------


def _rebind(config: Config, settings: RuntimeSettings) -> tuple[Config, RuntimeSettings]:
    """The enrolled fixture with every mount bound to `VOLUME` and no device number."""
    contracts = tuple(
        replace(
            contract,
            mounts=tuple(
                replace(item, device=None, volume_uuid=VOLUME) for item in contract.mounts
            ),
        )
        for contract in settings.contracts
    )
    settings = replace(settings, contracts=contracts)
    config = replace(
        config,
        services=tuple(
            replace(item, contract_sha256=contract_digest(settings.contract(item.id)))
            for item in config.services
        ),
    )
    return config, settings


def _states(snapshot: Any) -> set[tuple[str, str]]:
    return {(item.state, item.reason) for item in snapshot.services.values()}


class _Renumbered:
    """A file status as a later boot reports it: the same object, another device number."""

    def __init__(self, real: os.stat_result) -> None:
        self._real = real

    def __getattr__(self, name: str) -> Any:
        value = getattr(self._real, name)
        return value + 5 if name == "st_dev" else value


def _renumber(monkeypatch: pytest.MonkeyPatch) -> None:
    lstat, fstat = Path.lstat, os.fstat
    monkeypatch.setattr(Path, "lstat", lambda path: _Renumbered(lstat(path)))
    monkeypatch.setattr(runtime.os, "fstat", lambda fd: _Renumbered(fstat(fd)))


def test_volume_bound_identity_survives_a_changed_device_number(
    enrolled: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device_config, device_settings, items = enrolled
    config, settings = _rebind(device_config, device_settings)
    assert all(item.device is None for contract in settings.contracts for item in contract.mounts)
    # The volume is a property of the file system, whatever number it is mounted under.
    fstat = os.fstat
    volumes = {Path(device_settings.account.home).stat().st_dev: VOLUME}
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: volumes[fstat(fd).st_dev])
    runner = FakeRunner(settings, items)
    assert _states(runtime.observe_runtime(config, settings, runner)) == {("present", "verified")}
    with monkeypatch.context() as boot:
        _renumber(boot)
        after = runtime.observe_runtime(config, settings, runner)
        # The same boot with the device-bound enrollment: nothing can be verified.
        device_bound = runtime.observe_runtime(
            device_config, device_settings, FakeRunner(device_settings, items)
        )
    assert _states(after) == {("present", "verified")}
    assert _states(device_bound) == {("unknown", "identity-mismatch")}
    # Without the renumbering the device-bound enrollment reads as it always did.
    assert _states(
        runtime.observe_runtime(device_config, device_settings, FakeRunner(device_settings, items))
    ) == {("present", "verified")}


def test_volume_bound_identity_still_binds_the_inode(
    enrolled: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, settings = _rebind(*enrolled[:2])
    asked: list[int] = []

    def provider(fd: int) -> str:
        asked.append(os.fstat(fd).st_ino)
        return VOLUME

    monkeypatch.setattr(runtime, "volume_uuid", provider)
    mount = settings.contract("camera").mounts[0]
    directory = Path(mount.path)
    directory.rename(directory.with_name("retired"))
    directory.mkdir(mode=0o700)
    assert directory.stat().st_ino != mount.inode
    snapshot = runtime.observe_runtime(config, settings, FakeRunner(settings, enrolled[2]))
    assert (snapshot.services["camera"].state, snapshot.services["camera"].reason) == (
        "unknown",
        "identity-mismatch",
    )
    others = [item for key, item in snapshot.services.items() if key != "camera"]
    assert others and all(item.state == "present" for item in others)
    # The replaced directory is refused by its inode before anything is opened.
    assert directory.stat().st_ino not in asked and len(asked) == len(others)


def test_another_volume_is_a_mismatch(
    enrolled: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, settings = _rebind(*enrolled[:2])
    mount = settings.contract("camera").mounts[0]
    # The same path and inode number, on a volume that is not the enrolled one.
    monkeypatch.setattr(
        runtime,
        "volume_uuid",
        lambda fd: OTHER if os.fstat(fd).st_ino == mount.inode else VOLUME,
    )
    snapshot = runtime.observe_runtime(config, settings, FakeRunner(settings, enrolled[2]))
    assert (snapshot.services["camera"].state, snapshot.services["camera"].reason) == (
        "unknown",
        "identity-mismatch",
    )
    assert all(
        item.state == "present" for key, item in snapshot.services.items() if key != "camera"
    )
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: OTHER)
    snapshot = runtime.observe_runtime(config, settings, FakeRunner(settings, enrolled[2]))
    assert _states(snapshot) == {("unknown", "identity-mismatch")}


def _raising(error: Exception) -> Callable[[int], str]:
    def provider(fd: int) -> str:
        raise error

    return provider


@pytest.mark.parametrize(
    "failure",
    [
        "interface missing",
        "call refused",
        "call denied",
        "reply refused",
        "open denied",
        "open finds another object",
    ],
)
def test_provider_failure_is_unknown(
    enrolled: Any,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    config, settings = _rebind(*enrolled[:2])
    target = settings.contract("camera").mounts[0].path
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: VOLUME)
    real_open = os.open
    if failure == "interface missing":
        monkeypatch.setattr(runtime, "volume_uuid", _raising(OSError(errno.ENOTSUP, "absent")))
    elif failure == "call refused":
        monkeypatch.setattr(runtime, "volume_uuid", _raising(OSError(errno.EINVAL, "refused")))
    elif failure == "call denied":
        monkeypatch.setattr(runtime, "volume_uuid", _raising(PermissionError(errno.EPERM, "no")))
    elif failure == "reply refused":
        monkeypatch.setattr(runtime, "volume_uuid", _raising(ValueError("truncated")))
    elif failure == "open denied":

        def denied(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if os.fspath(path) == target:
                raise PermissionError(errno.EACCES, "denied")
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(runtime.os, "open", denied)
    else:
        other = settings.contract("resolver").mounts[0].path

        def swapped(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            return real_open(other if os.fspath(path) == target else path, flags, *args, **kwargs)

        monkeypatch.setattr(runtime.os, "open", swapped)
    snapshot = runtime.observe_runtime(config, settings, FakeRunner(settings, enrolled[2]))
    # Never present, and never a weaker reason than a failed identity.
    assert (snapshot.services["camera"].state, snapshot.services["camera"].reason) == (
        "unknown",
        "identity-mismatch",
    )
    if failure.startswith("open"):
        assert all(
            item.state == "present" for key, item in snapshot.services.items() if key != "camera"
        )
    else:
        assert _states(snapshot) == {("unknown", "identity-mismatch")}


def test_the_object_is_opened_without_following_and_closed_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runtime, "_identity_acl", lambda _path, **_kwargs: None)
    directory = (tmp_path / "data").resolve()
    directory.mkdir(mode=0o700)
    file = directory / "receipt"
    file.write_bytes(b"content")
    file.chmod(0o600)
    opened: list[tuple[str, int]] = []
    descriptors: list[int] = []
    real_open = os.open

    def recorded(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        opened.append((os.fspath(path), flags))
        return real_open(path, flags, *args, **kwargs)

    def provider(fd: int) -> str:
        descriptors.append(fd)
        return VOLUME

    monkeypatch.setattr(runtime.os, "open", recorded)
    monkeypatch.setattr(runtime, "volume_uuid", provider)
    uid = os.geteuid()
    runtime.check_identity(
        FileIdentity(str(directory), "directory", uid, None, directory.stat().st_ino, None, VOLUME)
    )
    runtime.check_identity(
        FileIdentity(str(file), "file", uid, None, file.stat().st_ino, None, VOLUME)
    )
    plain = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    assert opened == [(str(directory), plain | os.O_DIRECTORY), (str(file), plain)]
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)
    # A hashed receipt binds its contents as before, beside the volume.
    receipt = FileIdentity(
        str(file),
        "file",
        uid,
        None,
        file.stat().st_ino,
        hashlib.sha256(b"content").hexdigest(),
        VOLUME,
    )
    runtime.check_identity(receipt)
    file.write_bytes(b"changed")
    with pytest.raises(runtime.RuntimeReadError):
        runtime.check_identity(receipt)
    # An identity that names both bindings, or a volume for a socket, is refused
    # whoever constructed it.
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: pytest.fail("provider was asked"))
    meta = directory.stat()
    for identity in (
        FileIdentity(str(directory), "directory", uid, meta.st_dev, meta.st_ino, None, VOLUME),
        FileIdentity(str(directory), "socket", uid, None, meta.st_ino, None, VOLUME),
    ):
        with pytest.raises(runtime.RuntimeReadError):
            runtime.check_identity(identity)


# Enrollment ------------------------------------------------------------------


def test_enrolment_binds_what_was_asked(
    enrolled: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, settings, items = enrolled
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: pytest.fail("provider was asked"))
    runner = FakeRunner(settings, items)
    # Nothing asked, or the device asked: the enrollment of today, unchanged.
    assert runtime.capture_enrollment(settings, runner) == settings
    assert runtime.capture_enrollment(settings, runner, identity_binding="device") == settings
    # An unknown binding is refused before anything is read.
    runner = FakeRunner(settings, items)
    for unknown in ("inode", "volume", "", "Device"):
        with pytest.raises(ValueError):
            runtime.capture_enrollment(settings, runner, identity_binding=unknown)
    assert not runner.calls
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: VOLUME)
    bound = runtime.capture_enrollment(settings, runner, identity_binding="volume-uuid")
    assert [(contract.service, contract.configuration_sha256) for contract in bound.contracts] == [
        (contract.service, contract.configuration_sha256) for contract in settings.contracts
    ]
    for contract, before in zip(bound.contracts, settings.contracts, strict=True):
        assert contract.mounts == tuple(
            replace(item, device=None, volume_uuid=VOLUME) for item in before.mounts
        )
    assert not any(
        call[0][1:2] in [["start"], ["stop"], ["run"], ["delete"]] for call in runner.calls
    )
    # The result is a loadable document and verifies in the next pass.
    assert parse_settings(settings_to_dict(bound)) == bound
    derived = runtime.derive_policy(config, bound)
    assert derived != config
    assert _states(runtime.observe_runtime(derived, bound, FakeRunner(bound, items))) == {
        ("present", "verified")
    }
    # Neither policy covers the other enrollment: what was derived and admitted for
    # one binding is refused where the reader compares the contract.
    for policy, enrollment in ((config, bound), (derived, settings)):
        snapshot = runtime.observe_runtime(policy, enrollment, FakeRunner(enrollment, items))
        assert _states(snapshot) == {("unknown", "identity-mismatch")}


def test_enrolment_opens_directories_and_files_only(
    enrolled: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _config, settings, items = enrolled
    # The ACL reader has its own tests and, on Darwin, its own list of file types.
    monkeypatch.setattr(runtime, "_identity_acl", lambda _path, **_kwargs: None)
    pipe = (tmp_path / "other-kind").resolve()
    os.mkfifo(pipe, 0o600)
    contract = settings.contract("camera")
    configuration = items[contract.name]["configuration"]
    configuration["mounts"].append({"source": str(pipe), "options": ["rw"]})
    asked: list[int] = []

    def provider(fd: int) -> str:
        asked.append(os.fstat(fd).st_ino)
        return VOLUME

    monkeypatch.setattr(runtime, "volume_uuid", provider)
    bound = runtime.capture_enrollment(
        settings, FakeRunner(settings, items), identity_binding="volume-uuid"
    )
    meta = pipe.lstat()
    # What is neither a directory nor a file is described exactly as before.
    assert bound.contract("camera").mounts[1] == FileIdentity(
        str(pipe), "other", meta.st_uid, meta.st_dev, meta.st_ino
    )
    assert meta.st_ino not in asked


def _receipt(path: Path) -> FileIdentity:
    path.write_bytes(b"verified")
    path.chmod(0o600)
    meta = path.stat()
    return FileIdentity(
        str(path.resolve()),
        "file",
        meta.st_uid,
        meta.st_dev,
        meta.st_ino,
        hashlib.sha256(b"verified").hexdigest(),
    )


def test_enrolment_rebinds_a_verified_receipt_only(
    enrolled: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _config, settings, items = enrolled
    authored = _receipt(tmp_path / "receipt")

    def with_receipt(receipt: FileIdentity) -> RuntimeSettings:
        return replace(
            settings,
            contracts=tuple(
                replace(contract, receipts=(receipt,)) if contract.service == "camera" else contract
                for contract in settings.contracts
            ),
        )

    asked: list[int] = []

    def provider(fd: int) -> str:
        asked.append(os.fstat(fd).st_ino)
        return VOLUME

    monkeypatch.setattr(runtime, "volume_uuid", provider)
    source = with_receipt(authored)
    # Not asked: a receipt stays exactly as authored.
    assert runtime.capture_enrollment(source, FakeRunner(source, items)) == source
    # Asked: the verified device number is replaced; inode and contents stay bound.
    bound = runtime.capture_enrollment(
        source, FakeRunner(source, items), identity_binding="volume-uuid"
    )
    assert bound.contract("camera").receipts == (
        replace(authored, device=None, volume_uuid=VOLUME),
    )
    runtime.check_identity(bound.contract("camera").receipts[0])
    # A receipt that already names a volume is verified against it, never rewritten.
    volume_bound = with_receipt(replace(authored, device=None, volume_uuid=VOLUME))
    for binding in ("device", "volume-uuid"):
        again = runtime.capture_enrollment(
            volume_bound, FakeRunner(volume_bound, items), identity_binding=binding
        )
        assert again.contract("camera").receipts == volume_bound.contract("camera").receipts
    elsewhere = with_receipt(replace(authored, device=None, volume_uuid=OTHER))
    with pytest.raises(runtime.RuntimeReadError):
        runtime.capture_enrollment(
            elsewhere, FakeRunner(elsewhere, items), identity_binding="volume-uuid"
        )
    # An authored device number that no longer agrees is refused, as it is today,
    # and is not papered over by the volume read.
    assert authored.device is not None
    stale = with_receipt(replace(authored, device=authored.device + 1))
    asked.clear()
    for binding in ("device", "volume-uuid"):
        with pytest.raises(runtime.RuntimeReadError):
            runtime.capture_enrollment(stale, FakeRunner(stale, items), identity_binding=binding)
    assert authored.inode not in asked


def test_enrolment_fails_closed_when_the_volume_cannot_be_read(
    enrolled: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config, settings, items = enrolled
    for error in (OSError(errno.ENOTSUP, "absent"), ValueError("truncated")):
        monkeypatch.setattr(runtime, "volume_uuid", _raising(error))
        with pytest.raises(type(error)):
            runtime.capture_enrollment(
                settings, FakeRunner(settings, items), identity_binding="volume-uuid"
            )
    # A directory replaced between its verification and the volume read.
    target = Path(settings.contract("camera").mounts[0].path)
    real_check = runtime.check_identity

    def replaced(identity: FileIdentity, **kwargs: Any) -> None:
        real_check(identity, **kwargs)
        if identity.path == str(target):
            target.rename(target.with_name("retired"))
            target.mkdir(mode=0o700)

    monkeypatch.setattr(runtime, "check_identity", replaced)
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: VOLUME)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.capture_enrollment(
            settings, FakeRunner(settings, items), identity_binding="volume-uuid"
        )


def test_enroll_command_takes_the_binding(
    enrolled: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config, settings, _items = enrolled
    _bound_config, bound = _rebind(config, settings)
    asked: list[dict[str, Any]] = []

    def capture(actual: RuntimeSettings, **kwargs: Any) -> RuntimeSettings:
        assert actual == settings
        asked.append(kwargs)
        return bound if kwargs else settings

    monkeypatch.setattr(runtime, "load_settings", lambda _path: settings)
    monkeypatch.setattr(runtime, "capture_enrollment", capture)
    outputs = [tmp_path / name for name in ("default.json", "device.json", "volume.json")]
    arguments = ["--settings", "/unused", "enroll", "--output"]
    assert runtime.main([*arguments, str(outputs[0])]) == 0
    assert runtime.main([*arguments, str(outputs[1]), "--identity", "device"]) == 0
    assert runtime.main([*arguments, str(outputs[2]), "--identity", "volume-uuid"]) == 0
    assert asked == [{}, {}, {"identity_binding": "volume-uuid"}]
    assert outputs[0].read_bytes() == outputs[1].read_bytes()
    assert b"volume_uuid" not in outputs[0].read_bytes()
    assert load_settings(outputs[0]) == settings
    assert load_settings(outputs[2]) == bound
    assert strict_load(outputs[2])["contracts"][0]["mounts"][0]["volume_uuid"] == VOLUME
    assert capsys.readouterr().out.count('"captured":true') == 3
    with pytest.raises(SystemExit) as usage:
        runtime.main([*arguments, str(tmp_path / "refused.json"), "--identity", "inode"])
    assert usage.value.code == 2
    assert not (tmp_path / "refused.json").exists() and len(asked) == 3
    # A provider that cannot answer ends the command with the closed diagnostic.
    monkeypatch.setattr(runtime, "capture_enrollment", _raising(OSError(errno.ENOTSUP, "absent")))
    assert runtime.main([*arguments, str(tmp_path / "failed.json")]) == 69
    assert not (tmp_path / "failed.json").exists()


# The root owner --------------------------------------------------------------


def test_root_pass_checks_a_volume_bound_identity(
    enrolled: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config, settings = _rebind(*enrolled[:2])
    runner = FakeRunner(settings, enrolled[2])
    monkeypatch.setattr(owner, "protected_native_code", lambda paths: None)

    def routed(arguments: list[str], **kwargs: Any) -> Result:
        if arguments[:2] == ["/bin/launchctl", "asuser"]:
            # The fixed wrapper that runs the vendor CLI as the enrolled account.
            account = settings.account
            return runner(
                arguments[10:],
                run_uid=account.uid,
                run_gid=account.gid,
                account_home=account.home,
                **kwargs,
            )
        return runner(arguments, **kwargs)

    monkeypatch.setattr(owner, "run", routed)
    installation = Installation(
        "site-forwarding",
        "com.apple/netorch.site-forwarding",
        settings_to_dict(settings),
        hashlib.sha256(b"backend").hexdigest(),
        str(tmp_path / "report.json"),
    )
    assert "volume_uuid" in installation.observer["contracts"][0]["mounts"][0]
    root = Store(tmp_path / "root")
    root.write("installation.json", installation.to_dict())
    root.write("policy.json", to_dict(config))
    root.write("admissions.json", {"schema_version": 1, "strategy": STRATEGY, "profiles": {}})
    root.write("operator-intent.json", intent_to_dict(Intent()))
    for profile in config.profiles:
        if config.profile_owner(profile).id == installation.owner:
            admit(root, profile.id, acknowledge_bounded_risk=True, now=time.time() - 1)
    backend = FakeBackend()

    def root_pass() -> dict[str, Any]:
        # The owner's own observer, as its scheduled command passes it.
        return reconcile(
            root,
            owner._runtime_observer,
            lambda store, record: backend,
            report=lambda record, snapshot: None,
        )

    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: OTHER)
    refused = root_pass()
    assert refused["changed"] == [] and refused["phase"] == "inhibited"
    assert not backend.rules
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: VOLUME)
    accepted = root_pass()
    assert accepted["changed"]
    assert all(item.endswith(":activate") for item in accepted["changed"])
    assert backend.rules
    # The volume under the enrolled path is no longer the enrolled one.
    monkeypatch.setattr(runtime, "volume_uuid", lambda fd: OTHER)
    retired = root_pass()
    assert any(item.endswith(":withdraw") for item in retired["changed"])
    assert not backend.rules


def test_root_owner_lists_the_provider_before_its_code_inventory() -> None:
    """`protected_code` checks the files that are imported when it runs.

    The reader is imported after that inventory. Whatever it adds from outside
    the package would be loaded unchecked, so nothing may be left to add.
    """
    child = (
        "import sys\n"
        "import netorch.pf_owner\n"
        "listed = set(sys.modules)\n"
        "import netorch.apple_runtime, netorch.observer_child, netorch.runtime_settings\n"
        "later = sorted(set(sys.modules) - listed)\n"
        "print([name for name in later if not name.startswith('netorch.')])\n"
        "print(sorted(name for name in ('ctypes', '_ctypes') if name in listed))\n"
    )
    # subprocess.run kills and reaps the child if it does not finish.
    result = subprocess.run(
        [sys.executable, "-c", child], capture_output=True, text=True, timeout=120, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["[]", "['_ctypes', 'ctypes']"]

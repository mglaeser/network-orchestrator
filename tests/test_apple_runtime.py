from __future__ import annotations

import copy
import hashlib
import io
import os
from dataclasses import replace
from pathlib import Path

import pytest

from netorch import apple_runtime as runtime
from netorch.codec import canonical_bytes, digest
from netorch.config import config_digest, load_config, profile_digest, to_dict
from netorch.mock import mock_admissions
from netorch.process import OutputLimit, ProcessTimeout, Result
from netorch.runtime_settings import (
    FileIdentity,
    RuntimeAccount,
    RuntimeContract,
    RuntimeNetwork,
    RuntimeSettings,
    contract_digest,
)
from netorch.state import Intent, Observation, admissions_to_dict, intent_to_dict


@pytest.fixture
def enrolled(tmp_path, monkeypatch):
    # This fixture supplies mocked vendor reads. Keep native ACL I/O in its
    # dedicated tests below, too: concurrent test directory creation can change
    # a shared ancestor while /bin/ls runs and correctly invalidate its snapshot.
    # Identity metadata and deadline checks remain live; ACL-specific tests can
    # replace this syscall stub explicitly.
    monkeypatch.setattr(runtime, "reject_acl", lambda _path, **_kwargs: None)
    config = load_config(Path(__file__).resolve().parents[1] / "examples/network.json")
    uid, gid = os.geteuid(), os.getegid()
    contracts, items = [], {}
    for index, service in enumerate(config.services):
        directory = (tmp_path / service.id).resolve()
        directory.mkdir(mode=0o700)
        meta = directory.stat()
        published = [
            {
                "hostAddress": config.scope(p.scope).host_ipv4,
                "hostPort": p.ports.first,
                "containerPort": p.target_ports.first,
                "count": p.ports.width,
                "proto": p.protocol,
            }
            for p in config.profiles
            if p.service == service.id and p.kind == "publication"
        ]
        configuration = {
            "id": "example-" + service.id,
            "runtimeHandler": "container-runtime-linux",
            "mounts": [{"source": str(directory), "options": ["rw"]}],
            "publishedPorts": published,
            "cpus": 2,
            "memory": 1024,
        }
        contract = RuntimeContract(
            service.id,
            "example-" + service.id,
            "wired-lan",
            digest(configuration),
            (FileIdentity(str(directory), "directory", uid, meta.st_dev, meta.st_ino),),
        )
        contracts.append(contract)
        items[contract.name] = {
            "id": contract.name,
            "configuration": configuration,
            "status": {
                "state": "running",
                "startedDate": "2026-01-01T00:00:00Z",
                "networks": [
                    {
                        "network": "example-network",
                        "ipv4Address": f"198.51.100.{index + 10}/24",
                        "ipv4Gateway": "198.51.100.1",
                    }
                ],
            },
        }
    config = replace(
        config,
        services=tuple(
            replace(
                service,
                contract_sha256=contract_digest(
                    next(c for c in contracts if c.service == service.id)
                ),
            )
            for service in config.services
        ),
    )
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    paths = {key: tmp_path / (key + ".json") for key in ("policy", "admissions", "intent")}
    paths["intent"] = state / "intent.json"
    values = {
        "policy": to_dict(config),
        "admissions": admissions_to_dict(mock_admissions(config)),
        "intent": intent_to_dict(Intent()),
    }
    for key, path in paths.items():
        path.write_bytes(canonical_bytes(values[key]))
        path.chmod(0o600)
    settings = RuntimeSettings(
        1,
        "camera-manager",
        "/usr/bin/example-container",
        "1.5.0",
        RuntimeAccount(uid, gid, str(tmp_path)),
        (
            RuntimeNetwork(
                "wired-lan",
                "example-network",
                "198.51.100.1",
                f"gui/{uid}",
                "org.example.network",
                "/usr/libexec/example-network",
                uid,
            ),
        ),
        tuple(contracts),
        **{key: str(path) for key, path in paths.items()},
        state_dir=str(tmp_path / "state"),
    )
    return config, settings, items


class FakeRunner:
    def __init__(self, settings, items):
        self.settings = settings
        self.items = copy.deepcopy(items)
        self.calls = []
        self.failure = None
        self.helper_calls = 0
        self.network_calls = 0

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.failure == "timeout":
            raise ProcessTimeout("bounded")
        if self.failure == "output":
            raise OutputLimit("bounded")
        if self.failure == "permission":
            raise PermissionError("denied")
        if argv[0] == self.settings.executable:
            assert kwargs["run_uid"] == self.settings.account.uid
            assert kwargs["run_gid"] == self.settings.account.gid
            assert kwargs["account_home"] == self.settings.account.home
            arguments = argv[1:]
            if arguments == ["--version"]:
                return Result(
                    0, f"container CLI version {self.settings.accepted_version}\n".encode(), b""
                )
            if arguments == ["list", "--all", "--format", "json"]:
                data = list(self.items.values())
                if self.failure == "duplicate":
                    data.append(data[0])
            elif arguments[0] == "inspect":
                data = [copy.deepcopy(self.items[arguments[1]])]
                if self.failure == "race":
                    data[0]["status"]["startedDate"] = "changed"
            elif arguments[:2] == ["network", "inspect"]:
                self.network_calls += 1
                data = [
                    {
                        "id": "example-network",
                        "configuration": {
                            "name": "example-network",
                            "mode": "nat",
                            "plugin": "container-network-vmnet",
                        },
                        "status": {"ipv4Subnet": "198.51.100.0/24", "ipv4Gateway": "198.51.100.1"},
                    }
                ]
                if self.failure == "network-race" and self.network_calls > 1:
                    data[0]["status"]["extra"] = "changed"
            elif arguments[0] == "exec":
                payload = b"45000 45127\n" if self.failure != "range" else b"32768 60999\n"
                return Result(0, payload, b"")
            elif arguments[0] == "start":
                self.items[arguments[1]]["status"]["state"] = "running"
                return Result(0, b"started", b"")
            else:
                raise AssertionError(argv)
            return Result(0, canonical_bytes(data), b"")
        if argv[0] == "/usr/sbin/sysctl":
            return Result(0, b"0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D\n", b"")
        if argv[0] == "/sbin/ifconfig":
            return Result(0, b"en0: flags=0\n inet 192.0.2.10 netmask 0xffffff00\n", b"")
        if argv[0] == "/bin/launchctl":
            # Explicit service-manager evidence in the ordinary mock scenario.
            # Surviving jobs and unknown reads are separate regression fixtures.
            if argv[2].rpartition("/")[2].startswith("com.apple.container."):
                return Result(113, b"", b"Could not find service\n")
            self.helper_calls += 1
            pid = 111 if self.failure != "helper-race" or self.helper_calls == 1 else 112
            return Result(
                0,
                f"state = running\npid = {pid}\nprogram = /usr/libexec/example-network\n".encode(),
                b"",
            )
        if argv[0] == "/bin/ps":
            return Result(
                0,
                (
                    f"{self.settings.account.uid} Mon Oct  5 08:00:00 2026 "
                    "/usr/libexec/example-network\n"
                ).encode(),
                b"",
            )
        raise AssertionError(argv)


def test_full_runtime_snapshot_enrolled_identity_publications_and_generations(enrolled):
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    result = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert all(item.state == "present" for item in result.services.values())
    assert all(item.state == "present" for item in result.profiles.values())
    assert result.network_generation.startswith("network-")
    assert result.services["media-controller"].generation.startswith("guest-")
    assert any(call[0][1:3] == ["exec", "--user"] for call in runner.calls)


@pytest.mark.parametrize(
    "failure,reason",
    [
        ("timeout", "timed-out"),
        ("output", "malformed"),
        ("permission", "inaccessible"),
        ("duplicate", "malformed"),
        ("helper-race", "generation-mismatch"),
        ("network-race", "generation-mismatch"),
    ],
)
def test_native_incomplete_observations_never_recover_or_activate(enrolled, failure, reason):
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    runner.failure = failure
    result = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert result.network_generation is None
    assert all(
        item.state == "unknown" and item.reason == reason for item in result.services.values()
    )


@pytest.mark.parametrize(
    "failure,reason", [("race", "generation-mismatch"), ("range", "identity-mismatch")]
)
def test_per_guest_race_or_allocator_drift_is_unknown(enrolled, failure, reason):
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    runner.failure = failure
    result = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert result.services["media-controller"].state == "unknown"
    assert result.services["media-controller"].reason == reason


def test_all_stopped_is_helper_outage_unknown_but_one_stopped_is_proven(enrolled):
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    runner.items["example-camera"]["status"]["state"] = "stopped"
    one = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert one.services["camera"].state == "absent"
    assert one.profiles["camera-web"].state == "absent"
    for item in runner.items.values():
        item["status"]["state"] = "stopped"
    all_stopped = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert all(item.state == "unknown" for item in all_stopped.services.values())


@pytest.mark.parametrize(
    "change",
    [
        "contract",
        "configuration",
        "mount-replaced",
        "missing",
        "attachment",
        "gateway",
        "subnet",
        "address",
        "stopping",
    ],
)
def test_guest_contract_and_network_drift_fail_closed(enrolled, change):
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    contract = settings.contract("camera")
    item = runner.items[contract.name]
    if change == "contract":
        config = replace(
            config,
            services=tuple(
                replace(s, contract_sha256="0" * 64) if s.id == "camera" else s
                for s in config.services
            ),
        )
    elif change == "configuration":
        item["configuration"]["cpus"] = 3
    elif change == "mount-replaced":
        directory = Path(contract.mounts[0].path)
        directory.rename(directory.with_name("retired"))
        directory.mkdir()
    elif change == "missing":
        del runner.items[contract.name]
    elif change == "attachment":
        item["status"]["networks"].append(copy.deepcopy(item["status"]["networks"][0]))
    elif change == "gateway":
        item["status"]["networks"][0]["ipv4Gateway"] = "198.51.100.2"
    elif change == "subnet":
        item["status"]["networks"][0]["ipv4Address"] = "203.0.113.10/24"
    elif change == "address":
        item["status"]["networks"][0]["ipv4Address"] = "198.51.100.255/24"
    else:
        item["status"]["state"] = "stopping"
    result = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert result.services["camera"].state == "unknown"


def test_writable_state_is_exclusive_to_enrolled_workload(enrolled):
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    target = settings.contract("camera")
    other = runner.items["example-resolver"]
    other["configuration"]["mounts"] = [{"source": target.mounts[0].path, "options": ["rw"]}]
    result = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert result.services["camera"].state == "unknown"


def test_native_port_collision_does_not_count_as_wrong_service_publication(enrolled):
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    runner.items["example-camera"]["configuration"]["publishedPorts"] = []
    contract = settings.contract("camera")
    updated = replace(
        contract, configuration_sha256=digest(runner.items[contract.name]["configuration"])
    )
    settings = replace(
        settings,
        contracts=tuple(
            updated if c.service == contract.service else c for c in settings.contracts
        ),
    )
    config = replace(
        config,
        services=tuple(
            replace(s, contract_sha256=contract_digest(updated)) if s.id == contract.service else s
            for s in config.services
        ),
    )
    result = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert result.services["camera"].state == "present"
    assert result.profiles["camera-web"].state == "absent"


@pytest.mark.parametrize("version", ["1.2.0", "1.4.1", "1.5.0"])
def test_versioned_snapshot_envelope_parser(version):
    nested = {
        "id": "example",
        "configuration": {},
        "status": {"state": "running", "startedDate": "started", "networks": []},
    }
    assert runtime.decode_snapshot(nested, version)["state"] == "running"
    flat = {
        "id": "example",
        "configuration": {},
        "status": "running",
        "startedDate": "started",
        "networks": [],
    }
    with pytest.raises(runtime.RuntimeReadError):
        runtime.decode_snapshot(flat, version)


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [],
        {},
        {"id": "a", "configuration": {}, "status": "running"},
        {"id": "a", "configuration": {}, "status": {"state": "running", "startedDate": None}},
        {
            "id": "a",
            "configuration": {},
            "status": {"state": "running", "startedDate": "s", "unknown": 1},
        },
        {"id": "a", "configuration": {}, "status": {"state": "invalid"}},
    ],
)
def test_snapshot_shape_is_not_guessed(raw):
    with pytest.raises(runtime.RuntimeReadError):
        runtime.decode_snapshot(raw, "1.2.0")


def test_capture_enrollment_does_not_approve_or_modify_container(enrolled):
    _config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    captured = runtime.capture_enrollment(settings, runner)
    assert captured.contracts == settings.contracts
    assert not any(
        call[0][1:2] in [["start"], ["stop"], ["run"], ["delete"]] for call in runner.calls
    )


def test_read_only_file_receipt_is_hash_and_inode_bound(tmp_path):
    path = (tmp_path / "receipt").resolve()
    path.write_bytes(b"verified")
    path.chmod(0o600)
    meta = path.stat()
    identity = FileIdentity(
        str(path),
        "file",
        meta.st_uid,
        meta.st_dev,
        meta.st_ino,
        hashlib.sha256(b"verified").hexdigest(),
    )
    runtime.check_identity(identity)
    path.write_bytes(b"different")
    with pytest.raises(runtime.RuntimeReadError):
        runtime.check_identity(identity)


def file_receipt(path):
    meta = path.stat()
    return FileIdentity(
        str(path.resolve()),
        "file",
        meta.st_uid,
        meta.st_dev,
        meta.st_ino,
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def test_kernel_sized_receipt_above_old_cap_is_hashed_in_bounded_chunks(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "_identity_acl", lambda _path, **_kwargs: None)
    path = tmp_path / "synthetic-kernel"
    with path.open("wb") as stream:
        stream.truncate(17 * 1_048_576)
    path.chmod(0o600)
    identity = file_receipt(path)
    original_read = runtime.os.read
    requests = []

    def bounded(fd, count):
        requests.append(count)
        assert count == 1_048_576
        return original_read(fd, count)

    monkeypatch.setattr(runtime.os, "read", bounded)
    runtime.check_identity(identity)
    assert len(requests) == 18


def test_receipt_larger_than_512_mib_is_rejected_before_read(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "_identity_acl", lambda _path, **_kwargs: None)
    path = tmp_path / "oversized-sparse-receipt"
    with path.open("wb") as stream:
        stream.truncate(536_870_913)
    path.chmod(0o600)
    meta = path.stat()
    identity = FileIdentity(
        str(path.resolve()), "file", meta.st_uid, meta.st_dev, meta.st_ino, "0" * 64
    )
    monkeypatch.setattr(runtime.os, "read", lambda *_args: pytest.fail("oversized file read"))
    with pytest.raises(runtime.RuntimeReadError):
        runtime.check_identity(identity)


def test_receipt_hash_checks_aggregate_deadline_between_chunks(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "_identity_acl", lambda _path, **_kwargs: None)
    path = tmp_path / "receipt"
    path.write_bytes(b"content")
    path.chmod(0o600)
    identity = file_receipt(path)
    clock = [0.0]
    original_read = runtime.os.read

    def slow(fd, count):
        value = original_read(fd, count)
        clock[0] = 6
        return value

    monkeypatch.setattr(runtime.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(runtime.os, "read", slow)
    with pytest.raises(ProcessTimeout):
        runtime.check_identity(identity)


def test_identity_respects_shorter_shared_runtime_deadline(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "_identity_acl", lambda _path, **_kwargs: None)
    path = tmp_path / "receipt"
    path.write_bytes(b"content")
    path.chmod(0o600)
    identity = file_receipt(path)
    monkeypatch.setattr(runtime.time, "monotonic", lambda: 8)
    with pytest.raises(ProcessTimeout):
        runtime.check_identity(identity, deadline=8)


def test_receipt_mutation_during_hash_is_not_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "_identity_acl", lambda _path, **_kwargs: None)
    path = tmp_path / "receipt"
    path.write_bytes(b"content")
    path.chmod(0o600)
    identity = file_receipt(path)
    original_read = runtime.os.read
    changed = []

    def replaced(fd, count):
        data = original_read(fd, count)
        if not changed:
            path.write_bytes(b"changed content")
            changed.append(True)
        return data

    monkeypatch.setattr(runtime.os, "read", replaced)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.check_identity(identity)


@pytest.mark.parametrize("mutation", ["mode", "link", "mtime-restored-content"])
def test_receipt_hash_rejects_full_metadata_race(tmp_path, monkeypatch, mutation):
    monkeypatch.setattr(runtime, "_identity_acl", lambda _path, **_kwargs: None)
    path = tmp_path / "receipt"
    path.write_bytes(b"content")
    path.chmod(0o600)
    identity = file_receipt(path)
    original = path.stat()
    original_read = runtime.os.read
    changed = []

    def race(fd, count):
        data = original_read(fd, count)
        if not changed:
            changed.append(True)
            if mutation == "mode":
                path.chmod(0o400)
            elif mutation == "link":
                os.link(path, tmp_path / "second-link")
            else:
                # Hash bytes and original mtime match; ctime must still fence it.
                path.write_bytes(b"content")
                os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
        return data

    monkeypatch.setattr(runtime.os, "read", race)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.check_identity(identity)


def test_receipt_post_hash_acl_recheck_remains_bounded(tmp_path, monkeypatch):
    path = tmp_path / "receipt"
    path.write_bytes(b"content")
    path.chmod(0o600)
    identity = file_receipt(path)
    clock = [0.0]
    checked = []

    def acl(actual, *, deadline, checked_acls):
        assert deadline == 5 and checked_acls is None
        if actual == path:
            checked.append(actual)
            if len(checked) == 2:
                clock[0] = 5

    monkeypatch.setattr(runtime.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(runtime, "_identity_acl", acl)
    with pytest.raises(ProcessTimeout):
        runtime.check_identity(identity)
    assert checked == [path, path]


def test_receipt_post_hash_acl_permission_race_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "receipt"
    path.write_bytes(b"content")
    path.chmod(0o600)
    identity = file_receipt(path)
    checked = []

    def acl(actual, **_kwargs):
        if actual == path:
            checked.append(actual)
            if len(checked) == 2:
                path.chmod(0o400)

    monkeypatch.setattr(runtime, "_identity_acl", acl)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.check_identity(identity)
    assert checked == [path, path]


def native_acl(path, entries="", *, suffix="+", mode="drwx------"):
    return (f"{mode}{suffix} 2 example staff 64 Oct  5 10:20 {path}\n" + entries).encode("ascii")


@pytest.mark.parametrize(
    "entry",
    [
        " 0: group:everyone deny delete\n",
        " 0: group:everyone inherited deny delete\n",
        " 0: user:service_account deny delete,writeattr,file_inherit,directory_inherit\n",
        " 0: 00000000-0000-0000-0000-000000000001 deny delete\n",
        " 0: group:everyone deny delete\n 1: user:example inherited deny readsecurity\n",
    ],
)
def test_runtime_acl_accepts_only_native_closed_denials(tmp_path, entry):
    runtime._deny_only_acl(native_acl(tmp_path, entry), tmp_path)


@pytest.mark.parametrize("suffix", ["", "@"])
def test_runtime_acl_accepts_complete_no_acl_header(tmp_path, suffix):
    runtime._deny_only_acl(native_acl(tmp_path, suffix=suffix), tmp_path)


def test_runtime_acl_supports_xattr_marker_with_deny_only_acl(tmp_path):
    runtime._deny_only_acl(
        native_acl(tmp_path, " 0: group:everyone deny delete\n", suffix="@"), tmp_path
    )


@pytest.mark.parametrize(
    "entry",
    [
        " 0: group:everyone allow delete\n",
        " 0: group:everyone deny delete\n 1: user:example allow write\n",
        " 0: group:everyone unknown delete\n",
        " 1: group:everyone deny delete\n",
        " 00: group:everyone deny delete\n",
        " 0: group:everyone deny delete\n 2: group:everyone deny delete\n",
        " 0: group:everyone inheriting deny delete\n",
        " 0: group:everyone deny inherited,delete\n",
        " 0: group:everyone inherited inherited deny delete\n",
        " 0: group:everyone deny delete,unknown_inherit\n",
        " 0: group:everyone deny delete,delete\n",
        " 0: group:everyone deny writeattr,delete\n",
        " 0: user:name with spaces deny delete\n",
        " 0: group: deny delete\n",
        " 0: everyone deny delete\n",
        " 0: group:everyone deny file_inherit\n",
        " 0: group:everyone deny \n",
        " 0: group:everyone deny delete\n\n",
        "\t0: group:everyone deny delete\n",
        " 0: group:everyone deny delete\r\n",
    ],
)
def test_runtime_acl_refuses_grants_and_unknown_or_ambiguous_denials(tmp_path, entry):
    with pytest.raises(runtime.RuntimeReadError):
        runtime._deny_only_acl(native_acl(tmp_path, entry), tmp_path)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"looks fine\n",
        b"ls: permission denied\n",
        b"drwx------ 2 example staff 64 Oct 5 10:20 /wrong/path\n",
        b"drwx------+ 2 example staff 64 Oct 5 10:20 /example\n",
        b"drwx------% 2 example staff 64 Oct 5 10:20 /example\n",
        b"drwx------ 2 example staff 64 Oct 5 10:20 /example",
        b"drwx------ 2 example staff 64 Oct 5 29:20 /example\n",
        b"drwx------ 2 example staff 64 Oct 5 10:20 /example\n\xff\n",
        b"x" * 65_537,
    ],
)
def test_runtime_acl_refuses_incomplete_native_header(raw):
    with pytest.raises(runtime.RuntimeReadError):
        runtime._deny_only_acl(raw, Path("/example"))


def test_runtime_acl_does_not_allow_directory_rights_on_file(tmp_path):
    with pytest.raises(runtime.RuntimeReadError):
        runtime._deny_only_acl(
            native_acl(
                tmp_path, " 0: group:everyone deny delete,file_inherit\n", mode="-rw-------"
            ),
            tmp_path,
        )


def test_runtime_acl_native_argv_deadline_and_bounds_are_fixed(tmp_path, monkeypatch):
    calls = []

    def command(argv, **kwargs):
        calls.append((argv, kwargs))
        return Result(0, native_acl(tmp_path, " 0: group:everyone deny delete\n"), b"")

    monkeypatch.setattr(runtime.sys, "platform", "darwin")
    monkeypatch.setattr(runtime, "run", command)
    runtime.reject_acl(tmp_path, timeout=0.5)
    assert calls == [(["/bin/ls", "-lde", str(tmp_path)], {"timeout": 0.5, "max_output": 65_536})]


@pytest.mark.parametrize("code,stderr", [(1, b""), (0, b"denied")])
def test_runtime_acl_native_refusal_is_unknown(tmp_path, monkeypatch, code, stderr):
    monkeypatch.setattr(runtime.sys, "platform", "darwin")
    monkeypatch.setattr(
        runtime, "run", lambda *_args, **_kwargs: Result(code, native_acl(tmp_path), stderr)
    )
    with pytest.raises(runtime.RuntimeReadError):
        runtime.reject_acl(tmp_path)


def test_acl_cache_uses_fresh_ctime_and_is_scoped_to_reader(tmp_path, monkeypatch):
    path = (tmp_path / "protected-receipt").resolve()
    path.write_bytes(b"first")
    path.chmod(0o600)
    cache = set()
    calls = []

    def acl(actual, *, timeout):
        assert actual == path and 0 < timeout <= 2
        calls.append(actual)
        if len(calls) > 1:
            raise RuntimeError("new ACL refused")

    monkeypatch.setattr(runtime, "reject_acl", acl)
    runtime._identity_acl(path, checked_acls=cache)
    runtime._identity_acl(path, checked_acls=cache)
    assert len(calls) == 1
    original = path.stat()
    path.write_bytes(b"new-content-with-same-inode")
    assert path.stat().st_ino == original.st_ino
    assert path.stat().st_ctime_ns != original.st_ctime_ns
    with pytest.raises(runtime.RuntimeReadError):
        runtime._identity_acl(path, checked_acls=cache)
    assert len(calls) == 2


def test_acl_cache_cannot_skip_expired_shared_deadline(tmp_path, monkeypatch):
    path = (tmp_path / "receipt").resolve()
    path.write_bytes(b"content")
    cache = set()
    clock = [0.0]
    calls = []
    monkeypatch.setattr(runtime.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        runtime, "reject_acl", lambda actual, **kwargs: calls.append(kwargs["timeout"])
    )
    runtime._identity_acl(path, deadline=0.5, checked_acls=cache)
    assert calls == [0.5]
    clock[0] = 0.5
    with pytest.raises(ProcessTimeout):
        runtime._identity_acl(path, deadline=0.5, checked_acls=cache)
    assert calls == [0.5]


def test_acl_cache_rejects_metadata_swap_during_native_read(tmp_path, monkeypatch):
    path = (tmp_path / "receipt").resolve()
    path.write_bytes(b"content")
    path.chmod(0o600)
    cache = set()
    monkeypatch.setattr(runtime, "reject_acl", lambda actual, **_kwargs: actual.chmod(0o400))
    with pytest.raises(runtime.RuntimeReadError):
        runtime._identity_acl(path, checked_acls=cache)
    assert not cache


def test_acl_native_timeout_is_not_cached_or_mislabeled(tmp_path, monkeypatch):
    path = (tmp_path / "receipt").resolve()
    path.write_bytes(b"content")
    cache = set()

    def expired(_actual, **_kwargs):
        raise ProcessTimeout("native ACL timed out")

    monkeypatch.setattr(runtime, "reject_acl", expired)
    with pytest.raises(ProcessTimeout):
        runtime._identity_acl(path, checked_acls=cache)
    assert not cache


def test_recovery_only_starts_twice_proven_stopped_guest(enrolled):
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    runner.items["example-camera"]["status"]["state"] = "stopped"
    result = runtime.recover_service(config, settings, "camera", runner)
    assert result.services["camera"].state == "present"
    assert sum(call[0][1:2] == ["start"] for call in runner.calls) == 1


@pytest.mark.parametrize("state", ["running", "stopping", "unknown", "paused", "damaged"])
def test_recovery_never_starts_unknown_running_or_paused_guest(enrolled, state):
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    runner.items["example-camera"]["status"]["state"] = (
        "stopped" if state in {"paused", "damaged"} else state
    )
    if state in {"paused", "damaged"}:
        Path(settings.intent).write_bytes(
            canonical_bytes(
                intent_to_dict(
                    Intent(operator_paused=state == "paused", damaged=state == "damaged")
                )
            )
        )
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert not any(call[0][1:2] == ["start"] for call in runner.calls)


def test_owner_observe_protocol_claims_only_own_services_and_publications(enrolled):
    config, settings, items = enrolled
    response = runtime.handle_request(
        config,
        settings,
        {
            "protocol_version": 1,
            "operation": "observe",
            "owner": settings.owner,
            "config": to_dict(config),
        },
        FakeRunner(settings, items),
    )
    assert set(response["result"]["services"]) == {
        s.id for s in config.services if s.owner == settings.owner
    }
    assert set(response["result"]["profiles"]) == {
        p.id
        for p in config.profiles
        if p.kind == "publication" and config.profile_owner(p).id == settings.owner
    }


def test_runtime_publication_reconcile_never_recreates_workload(enrolled):
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    observed = runtime.observe_runtime(config, settings, runner)
    p = config.profile("camera-web")
    request = {
        "protocol_version": 1,
        "operation": "reconcile",
        "owner": settings.owner,
        "policy_digest": config_digest(config),
        "profile_digest": profile_digest(config, p),
        "profile": p.id,
        "action": "activate",
        "target_ipv4": observed.services[p.service].data["ipv4"],
        "target_generation": observed.services[p.service].generation,
    }
    assert runtime.handle_request(config, settings, request, runner)["result"]["state"] == "present"
    for operation in ("withdraw", "drain"):
        with pytest.raises(runtime.RuntimeReadError):
            runtime.handle_request(config, settings, {**request, "action": operation}, runner)
    assert not any(
        call[0][1:2] in [["start"], ["stop"], ["run"], ["delete"]] for call in runner.calls
    )


@pytest.mark.parametrize(
    "fault",
    [
        "version",
        "native-exit",
        "tool-exit",
        "boot",
        "helper-state",
        "helper-program",
        "helper-uid",
        "helper-command",
        "network-subnet",
        "network-mode",
        "interface-ip",
    ],
)
def test_platform_inspection_contracts_are_exact(enrolled, fault):
    config, settings, items = enrolled
    base = FakeRunner(settings, items)

    def runner(argv, **kwargs):
        result = base(argv, **kwargs)
        if fault == "version" and argv[1:] == ["--version"]:
            return replace(result, stdout=b"container CLI version 9.9.9\n")
        if fault == "native-exit" and argv[0] == settings.executable:
            return replace(result, returncode=1)
        if fault == "tool-exit" and argv[0] != settings.executable:
            return replace(result, returncode=1)
        if fault == "boot" and argv[0] == "/usr/sbin/sysctl":
            return replace(result, stdout=b"bad\n")
        if fault.startswith("helper-") and argv[0] == "/bin/launchctl":
            if fault == "helper-state":
                return replace(result, stdout=result.stdout.replace(b"running", b"waiting"))
            if fault == "helper-program":
                return replace(
                    result, stdout=result.stdout.replace(b"example-network", b"wrong-network")
                )
        if fault.startswith("helper-") and argv[0] == "/bin/ps":
            if fault == "helper-uid":
                return replace(
                    result, stdout=b"0 Mon Oct  5 08:00:00 2026 /usr/libexec/example-network\n"
                )
            if fault == "helper-command":
                return replace(result, stdout=b"malformed process\n")
        if fault.startswith("network-") and argv[1:3] == ["network", "inspect"]:
            if fault == "network-subnet":
                return replace(
                    result, stdout=result.stdout.replace(b"198.51.100.0", b"203.0.113.0")
                )
            if fault == "network-mode":
                return replace(result, stdout=result.stdout.replace(b'"nat"', b'"bridge"'))
        if fault == "interface-ip" and argv[0] == "/sbin/ifconfig":
            return replace(result, stdout=result.stdout.replace(b"192.0.2.10", b"192.0.2.11"))
        return result

    observed = runtime.observe_runtime(config, settings, runner)
    assert all(item.state == "unknown" for item in observed.services.values())
    assert observed.network_generation is None


def test_read_pass_deadline_bounds_entire_native_inventory(enrolled, monkeypatch):
    _config, settings, items = enrolled
    clock = [0]
    monkeypatch.setattr(runtime.time, "monotonic", lambda: clock[0])
    reader = runtime.Reader(settings, FakeRunner(settings, items))
    clock[0] = 9
    with pytest.raises(ProcessTimeout):
        reader.native(["--version"])


@pytest.mark.parametrize("operation", ["observe", "activate", "withdraw", "drain", "shell"])
def test_owner_request_rejects_wrong_identity_or_operations(enrolled, operation):
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    request = {
        "protocol_version": 1,
        "operation": operation,
        "owner": "foreign",
        "config": to_dict(config),
    }
    with pytest.raises(ValueError):
        runtime.handle_request(config, settings, request, runner)
    assert not runner.calls


@pytest.mark.parametrize(
    "change",
    [
        "profile-digest",
        "target",
        "generation",
        "admission",
        "pause",
        "unknown-action",
        "not-publication",
    ],
)
def test_publication_activation_requires_exact_authored_and_observed_contract(enrolled, change):
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    observed = runtime.observe_runtime(config, settings, runner)
    p = config.profile("camera-web")
    request = {
        "protocol_version": 1,
        "operation": "reconcile",
        "owner": settings.owner,
        "policy_digest": config_digest(config),
        "profile_digest": profile_digest(config, p),
        "profile": p.id,
        "action": "activate",
        "target_ipv4": observed.services[p.service].data["ipv4"],
        "target_generation": observed.services[p.service].generation,
    }
    if change == "profile-digest":
        request["profile_digest"] = "0" * 64
    elif change == "target":
        request["target_ipv4"] = "198.51.100.99"
    elif change == "generation":
        request["target_generation"] = "old"
    elif change == "admission":
        Path(settings.admissions).write_bytes(canonical_bytes(admissions_to_dict({})))
    elif change == "pause":
        Path(settings.intent).write_bytes(
            canonical_bytes(intent_to_dict(Intent(operator_paused=True)))
        )
    elif change == "unknown-action":
        request["action"] = "recreate"
    else:
        request["profile"] = "media-udp"
    with pytest.raises((ValueError, runtime.RuntimeReadError)):
        runtime.handle_request(config, settings, request, runner)
    assert not any(
        call[0][1:2] in [["start"], ["stop"], ["run"], ["delete"]] for call in runner.calls
    )


@pytest.mark.parametrize(
    "state,exit_code",
    [("present", 0), ("absent", 42), ("unknown", 69), ("paused", 69), ("damaged", 69)],
)
def test_monit_42_means_only_proven_stopped_and_unblocked(enrolled, monkeypatch, state, exit_code):
    config, settings, items = enrolled
    full = runtime.observe_runtime(config, settings, FakeRunner(settings, items))
    if state in {"paused", "damaged"}:
        Path(settings.intent).write_bytes(
            canonical_bytes(
                intent_to_dict(
                    Intent(operator_paused=state == "paused", damaged=state == "damaged")
                )
            )
        )
    elif state != "present":
        services = dict(full.services)
        services["camera"] = Observation(
            state, "confirmed-absent" if state == "absent" else "unobserved", full.observed_at, None
        )
        full = replace(full, services=services)
    monkeypatch.setattr(runtime, "load_settings", lambda _path: settings)
    monkeypatch.setattr(runtime, "observe_runtime", lambda *_args: full)
    assert (
        runtime.main(["--settings", "/unused/settings.json", "probe", "--service", "camera"])
        == exit_code
    )


@pytest.mark.usefixtures("legacy_cli_conformance")
def test_runtime_cli_observe_enroll_and_recovery_do_not_publish_secrets(
    enrolled, monkeypatch, capsys, tmp_path
):
    config, settings, items = enrolled
    full = runtime.observe_runtime(config, settings, FakeRunner(settings, items))
    monkeypatch.setattr(runtime, "load_settings", lambda _path: settings)
    monkeypatch.setattr(runtime, "observe_runtime", lambda *_args: full)
    monkeypatch.setattr(runtime, "capture_enrollment", lambda _settings: settings)
    monkeypatch.setattr(runtime, "recover_service", lambda *_args: full)
    assert runtime.main(["--settings", "/unused", "observe"]) == 0
    assert runtime.main(["--settings", "/unused", "start", "--service", "camera"]) == 0
    output = tmp_path / "enrolled.json"
    assert runtime.main(["--settings", "/unused", "enroll", "--output", str(output)]) == 0
    assert output.stat().st_mode & 0o777 == 0o600
    assert runtime.main(["--settings", "/unused", "enroll", "--output", str(output)]) == 69
    captured = capsys.readouterr()
    assert '"admitted":false' in captured.out
    assert "runtime-evidence-or-authority-incomplete" in captured.err


def test_runtime_cli_request_forwards_fixed_protocol_only(enrolled, monkeypatch):
    config, settings, _items = enrolled
    monkeypatch.setattr(runtime, "load_settings", lambda _path: settings)
    request = {
        "protocol_version": 1,
        "operation": "observe",
        "owner": settings.owner,
        "config": to_dict(config),
    }
    monkeypatch.setattr(
        runtime.sys, "stdin", io.TextIOWrapper(io.BytesIO(canonical_bytes(request)))
    )

    def handle(actual_config, actual_settings, actual_request):
        assert actual_config == config and actual_settings == settings and actual_request == request
        return {"verified": True}

    monkeypatch.setattr(runtime, "handle_request", handle)
    assert runtime.main(["--settings", "/unused", "request"]) == 0


def test_derived_policy_updates_only_generated_enrollment_contracts(enrolled):
    config, settings, _items = enrolled
    original = replace(
        config, services=tuple(replace(item, contract_sha256="0" * 64) for item in config.services)
    )
    derived = runtime.derive_policy(original, settings)
    assert derived == config
    assert derived.profiles == original.profiles
    assert derived.scopes == original.scopes
    assert derived.discovery == original.discovery
    assert original.services[0].contract_sha256 == "0" * 64
    with pytest.raises(ValueError, match="services and enrollment differ"):
        runtime.derive_policy(original, replace(settings, contracts=settings.contracts[:-1]))


def test_derive_policy_cli_captures_private_content_without_replacing_source(
    enrolled, monkeypatch, tmp_path, capsys
):
    config, settings, _items = enrolled
    original = replace(
        config, services=tuple(replace(item, contract_sha256="0" * 64) for item in config.services)
    )
    source = tmp_path / "source.json"
    source.write_bytes(canonical_bytes(to_dict(original)))
    output = tmp_path / "generated-policy.json"
    monkeypatch.setattr(runtime, "load_settings", lambda _path: settings)
    monkeypatch.setattr(
        runtime, "observe_runtime", lambda *_args: pytest.fail("unexpected native inspection")
    )
    args = [
        "--settings",
        "/unused",
        "derive-policy",
        "--source",
        str(source),
        "--output",
        str(output),
    ]
    assert runtime.main(args) == 0
    assert output.stat().st_mode & 0o777 == 0o600
    assert load_config(output) == config
    assert load_config(source) == original
    assert runtime.main(args) == 69
    assert '"admitted":false' in capsys.readouterr().out


@pytest.fixture
def legacy_cli_conformance(monkeypatch):
    """Explicit CI-only seam for preserved owner internals; never qualification."""
    monkeypatch.setattr(runtime, "require_mutation_qualified", lambda _capability: None)

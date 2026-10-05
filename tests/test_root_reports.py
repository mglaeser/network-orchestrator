"""Protected root reports can inform readiness but never grant root authority."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from netorch import owners
from netorch.codec import canonical_bytes
from netorch.config import load_config, profile_digest
from netorch.mock import initial_snapshot, mock_admissions
from netorch.owners import (
    ExternalOwnerRequired,
    OwnerFailure,
    RootReportOwner,
    SnapshotFileOwner,
    effective_admissions,
    load_bindings,
)
from netorch.planner import Action
from netorch.process import Result
from netorch.state import Observation, Snapshot, snapshot_to_dict


@pytest.fixture
def config():
    return load_config(Path(__file__).resolve().parents[1] / "examples/network.json")


def root_profile(config):
    return next(p for p in config.profiles if config.profile_owner(p).privilege == "external-root")


def root_proof(config, **changes):
    profile = root_profile(config)
    observation = Observation(
        "present",
        "verified",
        1000,
        "guest-present-1",
        {
            "admitted": True,
            "root_ready": True,
            "admission_digest": "a" * 64,
            "policy_digest": profile_digest(config, profile),
            "network_generation": "network-present-1",
        },
    )
    observation = replace(observation, **changes)
    return Snapshot(1000, "network-present-1", {}, {profile.id: observation})


@pytest.fixture
def protected_report(config, tmp_path, monkeypatch):
    """A disposable file with simulated root metadata; no chown or native tools.

    Actual syscall descriptors, NOFOLLOW, hard links and inode replacement still
    run. Only root UID/ancestor protection and read-only ACL enumeration are
    simulated so the same tests run unprivileged on GitHub CI.
    """
    path = tmp_path.resolve() / "root-report.json"
    path.write_bytes(canonical_bytes(snapshot_to_dict(root_proof(config))))
    path.chmod(0o644)
    changes = {}
    real_lstat = Path.lstat
    real_fstat = os.fstat

    def metadata(info, alterations=None):
        fields = {
            key: getattr(info, key)
            for key in (
                "st_mode",
                "st_uid",
                "st_gid",
                "st_dev",
                "st_ino",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
        }
        fields["st_uid"] = 0
        fields.update(alterations or {})
        return SimpleNamespace(**fields)

    def lstat(item, *args, **kwargs):
        info = real_lstat(item, *args, **kwargs)
        alterations = {"st_mode": stat.S_IFDIR | 0o755} if item in path.parents else {}
        alterations.update(changes.get(str(item), {}))
        return metadata(info, alterations)

    def fstat(fd):
        return metadata(real_fstat(fd), changes.get(str(path)))

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(owners.os, "fstat", fstat)

    def acl_reader(argv, **kwargs):
        assert argv[:2] == ["/bin/ls", "-lde"]
        assert kwargs["timeout"] <= 2
        return Result(0, b"root-owned protected path\n", b"")

    monkeypatch.setattr("netorch.pf_owner.run", acl_reader)
    return path, changes


def test_protected_report_read_is_complete_and_read_only(config, protected_report):
    path, _ = protected_report
    profile = root_profile(config)
    client = RootReportOwner(config, config.profile_owner(profile).id, path)
    assert client.observe() == root_proof(config)
    before = path.read_bytes()
    with pytest.raises(ExternalOwnerRequired):
        client.apply(Action(profile.id, client.owner, "withdraw", "paused"))
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("st_uid", 1000),
        ("st_nlink", 2),
        ("st_mode", stat.S_IFREG | 0o666),
        ("st_mode", stat.S_IFDIR | 0o755),
    ],
)
def test_root_report_unsafe_file_metadata_is_unknown(config, protected_report, field, value):
    path, changes = protected_report
    changes[str(path)] = {field: value}
    client = RootReportOwner(config, config.profile_owner(root_profile(config)).id, path)
    snapshot = client.observe()
    assert snapshot.network_generation is None
    assert snapshot.profiles[root_profile(config).id].state == "unknown"
    assert snapshot.profiles[root_profile(config).id].reason == "inaccessible"


@pytest.mark.parametrize(
    "field,value",
    [
        ("st_uid", 1000),
        ("st_mode", stat.S_IFDIR | 0o777),
        ("st_mode", stat.S_IFLNK | 0o755),
    ],
)
def test_root_report_unsafe_ancestor_is_unknown(config, protected_report, field, value):
    path, changes = protected_report
    changes[str(path.parent)] = {field: value}
    client = RootReportOwner(config, config.profile_owner(root_profile(config)).id, path)
    assert client.observe().profiles[root_profile(config).id].state == "unknown"


@pytest.mark.parametrize("where", ["file", "ancestor"])
def test_acl_cannot_turn_protected_report_into_user_authored_proof(
    config, protected_report, monkeypatch, where
):
    path, _ = protected_report
    target = path if where == "file" else path.parent

    def acl_reader(argv, **kwargs):
        if Path(argv[-1]) == target:
            return Result(0, b"protected mode\n 0: user:operator allow write\n", b"")
        return Result(0, b"protected mode\n", b"")

    # Check the owner's platform-neutral refusal seam without native commands.
    from netorch.pf_owner import UnsafeState

    def refuse_acl(item):
        if item == target:
            raise UnsafeState("ACL-bearing trust boundary")

    monkeypatch.setattr(owners, "reject_acl", refuse_acl)
    client = RootReportOwner(config, config.profile_owner(root_profile(config)).id, path)
    assert client.observe().profiles[root_profile(config).id].state == "unknown"


@pytest.mark.parametrize(
    "payload", [b"not-json", b"{}", b'{"private":"' + b"x" * 1_048_576 + b'"}']
)
def test_malformed_or_oversized_report_never_proves_root_readiness(
    config, protected_report, payload
):
    path, _ = protected_report
    path.write_bytes(payload)
    client = RootReportOwner(config, config.profile_owner(root_profile(config)).id, path)
    assert client.observe().network_generation is None


def test_symlink_report_is_never_followed(config, protected_report):
    path, _ = protected_report
    alias = path.with_name("alias.json")
    alias.symlink_to(path)
    client = RootReportOwner(config, config.profile_owner(root_profile(config)).id, alias)
    assert client.observe().network_generation is None


def test_report_replaced_during_read_never_yields_presence(config, protected_report, monkeypatch):
    path, _ = protected_report
    real_fdopen = os.fdopen

    class ReplaceAfterRead:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, count):
            data = self.stream.read(count)
            replacement = path.with_name("replacement.json")
            replacement.write_bytes(data)
            os.replace(replacement, path)
            return data

    monkeypatch.setattr(
        owners.os, "fdopen", lambda *args, **kwargs: ReplaceAfterRead(real_fdopen(*args, **kwargs))
    )
    client = RootReportOwner(config, config.profile_owner(root_profile(config)).id, path)
    assert client.observe().network_generation is None


@pytest.mark.parametrize(
    "field,value", [("st_uid", 1000), ("st_nlink", 2), ("st_mode", stat.S_IFREG | 0o666)]
)
def test_report_losing_protection_during_capture_never_yields_presence(
    config, protected_report, monkeypatch, field, value
):
    path, changes = protected_report
    real_fdopen = os.fdopen

    class ChangeAfterRead:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, count):
            data = self.stream.read(count)
            changes[str(path)] = {field: value}
            return data

    monkeypatch.setattr(
        owners.os, "fdopen", lambda *args, **kwargs: ChangeAfterRead(real_fdopen(*args, **kwargs))
    )
    client = RootReportOwner(config, config.profile_owner(root_profile(config)).id, path)
    assert client.observe().network_generation is None


def test_root_report_acl_probe_failure_is_unknown(config, protected_report, monkeypatch):
    path, _ = protected_report

    def unavailable(path):
        raise PermissionError("ACL metadata unavailable")

    monkeypatch.setattr(owners, "reject_acl", unavailable)
    client = RootReportOwner(config, config.profile_owner(root_profile(config)).id, path)
    assert client.observe().network_generation is None


def test_same_inode_same_size_content_change_during_capture_is_unknown(
    config, protected_report, monkeypatch
):
    path, _ = protected_report
    original = path.read_bytes()
    before = path.stat()
    real_fdopen = os.fdopen

    class ChangeAfterRead:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, count):
            data = self.stream.read(count)
            changed = data.replace(b"network-present-1", b"network-present-2")
            assert changed != data and len(changed) == len(data)
            path.write_bytes(changed)
            return data

    monkeypatch.setattr(
        owners.os, "fdopen", lambda *args, **kwargs: ChangeAfterRead(real_fdopen(*args, **kwargs))
    )
    client = RootReportOwner(config, config.profile_owner(root_profile(config)).id, path)
    assert client.observe().network_generation is None
    after = path.stat()
    assert (before.st_dev, before.st_ino, before.st_size) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
    )
    assert path.read_bytes() != original


def test_root_report_descriptor_is_closed_after_parse_failure(protected_report, monkeypatch):
    path, _ = protected_report
    path.write_bytes(b"private malformed contents")
    opened = []
    real_open = os.open

    def record_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    monkeypatch.setattr(owners.os, "open", record_open)
    with pytest.raises(ValueError):
        owners._root_report(path)
    for fd in opened:
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF


def test_actual_user_owned_report_cannot_confer_root_trust(config, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("this regression exercises the real unprivileged UID boundary")
    path = tmp_path / "forged.json"
    path.write_bytes(canonical_bytes(snapshot_to_dict(root_proof(config))))
    profile = root_profile(config)
    client = RootReportOwner(config, config.profile_owner(profile).id, path)
    assert client.observe().profiles[profile.id].state == "unknown"


def test_only_external_root_owner_can_bind_protected_report(config, tmp_path):
    profile = root_profile(config)
    root_id = config.profile_owner(profile).id
    path = tmp_path / "bindings.json"
    path.write_bytes(
        canonical_bytes(
            {
                "schema_version": 1,
                "owners": [
                    {"id": root_id, "kind": "root-report", "path": "/protected/report.json"}
                ],
            }
        )
    )
    path.chmod(0o600)
    assert isinstance(load_bindings(config, path)[root_id], RootReportOwner)
    user = next(owner.id for owner in config.owners if owner.privilege == "user")
    for entry in [
        {"id": user, "kind": "root-report", "path": "/protected/report.json"},
        {"id": root_id, "kind": "root-report", "path": "relative.json"},
        {"id": root_id, "kind": "root-report", "path": 1},
    ]:
        path.write_bytes(canonical_bytes({"schema_version": 1, "owners": [entry]}))
        with pytest.raises(OwnerFailure):
            load_bindings(config, path)


def test_independent_fresh_root_proof_is_readiness_not_an_admin_command(config, tmp_path):
    profile = root_profile(config)
    owner = config.profile_owner(profile).id
    client = RootReportOwner(config, owner, tmp_path / "report.json")
    result = effective_admissions(config, {owner: client}, root_proof(config), {}, 1000)
    assert result[profile.id].digest == profile_digest(config, profile)
    assert result[profile.id].approved_by == "independent-root:" + owner
    assert result[profile.id].risk_acknowledged is True
    assert not (tmp_path / "report.json").exists()


@pytest.mark.parametrize(
    "fault",
    [
        "stale",
        "future",
        "unknown",
        "absent",
        "missing",
        "no-client",
        "user-file",
        "not-admitted",
        "truthy-admission",
        "not-ready",
        "truthy-ready",
        "missing-proof",
        "invalid-proof",
        "wrong-policy",
        "no-generation",
        "different-generation",
    ],
)
def test_incomplete_root_proof_and_user_authored_admission_never_ready(config, tmp_path, fault):
    profile = root_profile(config)
    owner = config.profile_owner(profile).id
    clients = {owner: RootReportOwner(config, owner, tmp_path / "report.json")}
    snapshot = root_proof(config)
    evidence = snapshot.profiles[profile.id]
    data = dict(evidence.data)
    if fault == "stale":
        evidence = replace(evidence, observed_at=1000 - profile.safety.max_age_seconds - 1)
    elif fault == "future":
        evidence = replace(evidence, observed_at=1001)
    elif fault in {"unknown", "absent"}:
        evidence = replace(
            evidence,
            state=fault,
            reason="inaccessible" if fault == "unknown" else "confirmed-absent",
        )
    elif fault == "missing":
        snapshot = replace(snapshot, profiles={})
    elif fault == "no-client":
        clients = {}
    elif fault == "user-file":
        clients = {owner: SnapshotFileOwner(config, owner, tmp_path / "report.json")}
    elif fault in {"not-admitted", "truthy-admission"}:
        data["admitted"] = False if fault == "not-admitted" else 1
    elif fault in {"not-ready", "truthy-ready"}:
        data["root_ready"] = False if fault == "not-ready" else 1
    elif fault == "missing-proof":
        data.pop("admission_digest")
    elif fault == "invalid-proof":
        data["admission_digest"] = "a" * 63
    elif fault == "wrong-policy":
        data["policy_digest"] = "b" * 64
    elif fault == "no-generation":
        snapshot = replace(snapshot, network_generation=None)
    elif fault == "different-generation":
        data["network_generation"] = "network-other-1"
    if fault != "missing":
        snapshot = replace(snapshot, profiles={profile.id: replace(evidence, data=data)})
    user_authored = mock_admissions(config)
    result = effective_admissions(config, clients, snapshot, user_authored, 1000)
    assert profile.id not in result
    assert all(config.profile_owner(key).privilege == "user" for key in result)


def test_root_proof_does_not_erase_independent_user_admissions(config, tmp_path):
    snapshot = root_proof(config)
    profile = root_profile(config)
    owner = config.profile_owner(profile).id
    authored = mock_admissions(config)
    before = dict(authored)
    result = effective_admissions(
        config,
        {owner: RootReportOwner(config, owner, tmp_path / "report.json")},
        snapshot,
        authored,
        1000,
    )
    for key, value in authored.items():
        if config.profile_owner(key).privilege == "user":
            assert result[key] is value
    assert authored == before
    assert profile.id in result


def test_cross_owner_snapshot_claims_do_not_become_root_evidence(config):
    initial = initial_snapshot(config)
    profile = root_profile(config)
    root_id = config.profile_owner(profile).id

    class CrossOwner:
        simulation = False

        def observe(self):
            return replace(root_proof(config), services=initial.services)

    observed = owners.observe(config, {root_id: CrossOwner()})
    assert observed.profiles[profile.id].reason == "identity-mismatch"
    assert observed.network_generation is None

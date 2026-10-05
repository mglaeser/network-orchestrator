"""Admission, ownership, immutability and source-swap regressions."""

from __future__ import annotations

import copy
import hashlib
import os
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch.codec import canonical_bytes, digest
from netorch.deployment import install_bundle, recover_install, rollback_install, validate_bundle
from netorch.deployment_config import DeploymentError, parse_deployment
from netorch.deployment_model import Job
from netorch.process import run
from netorch.storage import Store, UnsafeState
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest

__all__ = ["config", "fake_platform", "manifest"]
NATIVE_PLATFORM_GUARD = implementation._require_platform


def test_direct_model_cannot_escape_closed_schema(manifest: dict[str, Any]) -> None:
    deployment = parse_deployment(canonical_bytes(manifest))
    bad: Job = replace(deployment.jobs[0], label="../../unowned")
    with pytest.raises(DeploymentError):
        implementation.validate_deployment(replace(deployment, jobs=(bad, *deployment.jobs[1:])))


@pytest.mark.parametrize("destination", ["data/network.json", "data/pf-backend.sh"])
def test_generated_names_cannot_be_shadowed(
    tmp_path: Path, manifest: dict[str, Any], config: Any, destination: str
) -> None:
    manifest["artifacts"][0]["destination"] = destination
    with pytest.raises(DeploymentError):
        make_bundle(tmp_path, manifest, config)


def test_render_site_backend_and_existing_output(
    tmp_path: Path, manifest: dict[str, Any], config: Any
) -> None:
    different = copy.deepcopy(manifest)
    different["site"] = "other-site"
    with pytest.raises(DeploymentError, match="sites"):
        make_bundle(tmp_path, different, config)
    different = copy.deepcopy(manifest)
    different["forwarding"]["backend_sha256"] = "0" * 64
    with pytest.raises(DeploymentError, match="backend"):
        make_bundle(tmp_path, different, config)
    bundle, _ = make_bundle(tmp_path, manifest, config)
    with pytest.raises(DeploymentError, match="exists"):
        make_bundle(tmp_path, manifest, config)
    with pytest.raises(DeploymentError, match="exists"):
        implementation.prepare_root_bundle(bundle, bundle)


def test_input_root_ownership_is_checked(tmp_path: Path, fake_platform: None) -> None:
    # Model protected shared ancestry so this test reaches the distinct leaf
    # ownership check. Writable shared ancestry has its own refusal
    # regression; fixture-local ownership and permissions remain real.
    if os.geteuid() == 0:
        pytest.skip("root CI cannot create a differently owned file without modifying ownership")
    path = tmp_path / "data"
    path.write_bytes(b"data")
    path.chmod(0o600)
    with pytest.raises(DeploymentError, match="root"):
        implementation._read_file(path, root_owned=True)
    with pytest.raises(DeploymentError, match="root-owned"):
        implementation._protected_executable(path)


@pytest.mark.parametrize("corruption", ["backend", "monit", "policy"])
def test_rehashed_control_content_still_checked(
    tmp_path: Path, manifest: dict[str, Any], config: Any, corruption: str
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    names = {
        "backend": "root/data/pf-backend.sh",
        "monit": "user/monit/monitrc",
        "policy": "root/data/network.json",
    }
    name = names[corruption]
    path = bundle / name
    path.write_bytes(path.read_bytes() + b"\n")
    record = next(item for item in metadata["files"] if item["path"] == name)
    record.update(
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=len(path.read_bytes())
    )
    metadata["bundle_digest"] = digest(
        {field: item for field, item in metadata.items() if field != "bundle_digest"}
    )
    (bundle / "manifest.json").write_bytes(canonical_bytes(metadata))
    with pytest.raises(DeploymentError):
        validate_bundle(bundle)


def test_recovery_modified_previous_is_inhibited(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    first, old = make_bundle(tmp_path, manifest, config, "old")
    tools = FakeTools()
    install_bundle(first, "user", expected_digest=old["bundle_digest"], runner=tools)
    changed = copy.deepcopy(manifest)
    changed["jobs"][0]["interval_seconds"] = 15
    second, new = make_bundle(tmp_path, changed, config, "new")
    tools.fail = "bootstrap"
    with pytest.raises(DeploymentError):
        install_bundle(second, "user", expected_digest=new["bundle_digest"], runner=tools)
    release = Path(manifest["user"]["directory"]) / "releases" / old["release_id"]
    (release / "data/network.json").write_bytes(b"corruption")
    tools.fail = None
    before = len(tools.calls)
    with pytest.raises(DeploymentError, match="modified"):
        recover_install(
            Path(manifest["user"]["state_directory"]),
            "user",
            expected_failed_digest=new["bundle_digest"],
            runner=tools,
        )
    assert len(tools.calls) == before


def test_root_upgrade_boundary_cannot_move_before_quiescence(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    first, old = make_bundle(tmp_path, manifest, config, "old")
    tools = FakeTools()
    install_bundle(first, "root", expected_digest=old["bundle_digest"], runner=tools)
    changed = copy.deepcopy(manifest)
    changed["forwarding"]["directory"] += "-new"
    changed["jobs"][1]["argv"][-1] = changed["forwarding"]["directory"]
    second, new = make_bundle(tmp_path, changed, config, "new")
    before = len(tools.calls)
    with pytest.raises(DeploymentError, match="boundaries"):
        install_bundle(second, "root", expected_digest=new["bundle_digest"], runner=tools)
    assert len(tools.calls) == before


@pytest.mark.parametrize("record", [{}, {"schema_version": 2}, {"schema_version": True}])
def test_corrupt_receipt_cannot_authorize_install(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    record: dict[str, Any],
) -> None:
    store = Store(Path(manifest["user"]["state_directory"]))
    store.write("installation-receipt.json", record)
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    tools = FakeTools()
    with pytest.raises(DeploymentError, match="receipt"):
        install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"], runner=tools)
    assert not tools.calls


def test_write_no_progress_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(implementation.os, "write", lambda fd, value: 0)
    with pytest.raises(DeploymentError, match="progress"):
        implementation._write_new(tmp_path / "file", b"data")


def test_atomic_replacement_refuses_unfinished_temporary(tmp_path: Path) -> None:
    target = tmp_path / "job.plist"
    temporary = tmp_path / ".job.plist.netorch-new"
    temporary.write_bytes(b"unfinished")
    temporary.chmod(0o600)
    with pytest.raises(DeploymentError, match="unfinished"):
        implementation._atomic_record(target, b"data", os.geteuid())


def test_invalid_scope_never_selects_root(manifest: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        parse_deployment(canonical_bytes(manifest)).installation("all")


def test_native_monit_syntax_only_in_disposable_state(
    tmp_path: Path, manifest: dict[str, Any], config: Any
) -> None:
    executable = shutil.which("monit")
    if executable is None:
        pytest.skip("optional native Monit grammar check; fake CI contracts always run")
    state = tmp_path / "state with spaces"
    state.mkdir(mode=0o700)
    manifest["user"]["state_directory"] = str(state)
    for item in manifest["monitors"]:
        item["check_argv"] = ["/usr/bin/true", "argument with spaces"]
        if item["recovery_argv"] is not None:
            item["recovery_argv"] = ["/usr/bin/true", "argument with spaces"]
    bundle, _ = make_bundle(tmp_path, manifest, config)
    result = run([executable, "-t", "-c", str(bundle / "user/monit/monitrc")], timeout=10)
    assert result.returncode == 0
    assert b"Control file syntax OK" in result.stdout
    assert (state / "monit.id").is_file()


def refuse_acl(monkeypatch: pytest.MonkeyPatch, selected: Path) -> list[Path]:
    calls: list[Path] = []

    def check(path: Path, **kwargs: Any) -> None:
        calls.append(path)
        if path == selected:
            raise UnsafeState("ACL-bearing privileged trust boundary")

    monkeypatch.setattr(implementation, "reject_acl", check)
    return calls


@pytest.mark.parametrize("target", ["install", "state", "jobs", "logs", "journal", "artifact"])
def test_root_scope_acl_guard_is_active_under_synthetic_operator_uid(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    release = Path(manifest["root"]["directory"]) / "releases" / metadata["release_id"]
    targets = {
        "install": Path(manifest["root"]["directory"]),
        "state": Path(manifest["root"]["state_directory"]),
        "jobs": Path(manifest["root"]["launchd_directory"]),
        "logs": Path(manifest["jobs"][1]["log_directory"]),
        "journal": Path(manifest["root"]["state_directory"]) / "installation-journal.json",
        "artifact": release / "data/pf-backend.sh",
    }
    calls = refuse_acl(monkeypatch, targets[target])
    tools = FakeTools()
    with pytest.raises(DeploymentError, match="ACL"):
        install_bundle(bundle, "root", expected_digest=metadata["bundle_digest"], runner=tools)
    assert targets[target] in calls
    assert not any("bootstrap" in argv for argv in tools.calls)


def test_user_scope_deny_only_acl_provider_is_not_promoted_to_root_rules(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)

    def root_only(path: Path, **kwargs: Any) -> None:
        raise AssertionError("user scope must not apply privileged blanket ACL refusal")

    monkeypatch.setattr(implementation, "reject_acl", root_only)
    result = install_bundle(
        bundle, "user", expected_digest=metadata["bundle_digest"], runner=FakeTools()
    )
    assert result["phase"] == "committed"


@pytest.mark.parametrize("operation", ["rollback", "recover"])
@pytest.mark.parametrize("target", ["state", "receipt", "old-artifact", "current-job"])
def test_root_restore_acl_denial_never_bootstraps_reviewed_or_unreviewed_code(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    target: str,
) -> None:
    first, original = make_bundle(tmp_path, manifest, config, "first")
    tools = FakeTools()
    install_bundle(first, "root", expected_digest=original["bundle_digest"], runner=tools)
    newer = copy.deepcopy(manifest)
    newer["jobs"][1]["log_directory"] += "-v2"
    second, changed = make_bundle(tmp_path, newer, config, "second")
    if operation == "recover":
        tools.fail = "bootstrap"
        with pytest.raises(DeploymentError):
            install_bundle(second, "root", expected_digest=changed["bundle_digest"], runner=tools)
        tools.fail = None
    else:
        install_bundle(second, "root", expected_digest=changed["bundle_digest"], runner=tools)
    state = Path(manifest["root"]["state_directory"])
    targets = {
        "state": state,
        "receipt": state
        / ("installation-journal.json" if operation == "recover" else "installation-receipt.json"),
        "old-artifact": Path(manifest["root"]["directory"])
        / "releases"
        / original["release_id"]
        / "data/pf-backend.sh",
        "current-job": Path(manifest["root"]["launchd_directory"]) / "org.example.netorch-pf.plist",
    }
    calls = refuse_acl(monkeypatch, targets[target])
    tools.calls.clear()
    with pytest.raises(DeploymentError, match="ACL"):
        if operation == "rollback":
            rollback_install(
                state, "root", expected_current_digest=changed["bundle_digest"], runner=tools
            )
        else:
            recover_install(
                state, "root", expected_failed_digest=changed["bundle_digest"], runner=tools
            )
    assert targets[target] in calls
    assert not any("bootstrap" in argv for argv in tools.calls)


@pytest.mark.parametrize("operation", ["install", "rollback", "recover"])
def test_root_job_content_is_fenced_again_immediately_before_bootstrap(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    first, original = make_bundle(tmp_path, manifest, config, "first")
    tools = FakeTools()
    if operation != "install":
        install_bundle(first, "root", expected_digest=original["bundle_digest"], runner=tools)
    newer = copy.deepcopy(manifest)
    newer["jobs"][1]["log_directory"] += "-v2"
    second, changed = make_bundle(tmp_path, newer, config, "second")
    if operation == "recover":
        tools.fail = "bootstrap"
        with pytest.raises(DeploymentError):
            install_bundle(second, "root", expected_digest=changed["bundle_digest"], runner=tools)
        tools.fail = None
    elif operation == "rollback":
        install_bundle(second, "root", expected_digest=changed["bundle_digest"], runner=tools)
    atomic = implementation._atomic_record

    def mutate_after_publish(path: Path, payload: bytes, uid: int, **kwargs: Any) -> None:
        atomic(path, payload, uid, **kwargs)
        path.write_bytes(b"unreviewed root plist")

    monkeypatch.setattr(implementation, "_atomic_record", mutate_after_publish)
    tools.calls.clear()
    with pytest.raises(DeploymentError, match="before native bootstrap"):
        if operation == "install":
            install_bundle(first, "root", expected_digest=original["bundle_digest"], runner=tools)
        elif operation == "rollback":
            rollback_install(
                Path(manifest["root"]["state_directory"]),
                "root",
                expected_current_digest=changed["bundle_digest"],
                runner=tools,
            )
        else:
            recover_install(
                Path(manifest["root"]["state_directory"]),
                "root",
                expected_failed_digest=changed["bundle_digest"],
                runner=tools,
            )
    assert not any("bootstrap" in argv for argv in tools.calls)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "writable", "acl", "foreign-owner"])
def test_existing_root_log_leaf_cannot_be_an_unsafe_launchd_write_target(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    directory = Path(manifest["jobs"][1]["log_directory"])
    directory.mkdir(mode=0o700)
    log = directory / "org.example.netorch-pf.out.log"
    sensitive = tmp_path / "unrelated-private-file"
    sensitive.write_bytes(b"keep this exact content")
    sensitive.chmod(0o600)
    if kind == "symlink":
        log.symlink_to(sensitive)
    elif kind == "hardlink":
        os.link(sensitive, log)
    else:
        log.write_bytes(b"old log")
        log.chmod(0o666 if kind == "writable" else 0o600)
    if kind == "acl":
        refuse_acl(monkeypatch, log)
    elif kind == "foreign-owner":
        selected = log.lstat()
        native_fstat = os.fstat

        def foreign_owner(fd: int) -> os.stat_result:
            info = native_fstat(fd)
            if (info.st_dev, info.st_ino) == (selected.st_dev, selected.st_ino):
                values = list(info)
                values[4] = os.geteuid() + 1
                return os.stat_result(values)
            return info

        monkeypatch.setattr(os, "fstat", foreign_owner)
    tools = FakeTools()
    with pytest.raises((DeploymentError, OSError)):
        install_bundle(bundle, "root", expected_digest=metadata["bundle_digest"], runner=tools)
    assert sensitive.read_bytes() == b"keep this exact content"
    assert not any("bootstrap" in argv for argv in tools.calls)


def test_large_protected_existing_log_is_allowed_without_treating_it_as_a_bundle(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    directory = Path(manifest["jobs"][1]["log_directory"])
    directory.mkdir(mode=0o700)
    log = directory / "org.example.netorch-pf.out.log"
    log.write_bytes(b"x" * 2_097_152)
    log.chmod(0o600)
    assert (
        install_bundle(
            bundle, "root", expected_digest=metadata["bundle_digest"], runner=FakeTools()
        )["phase"]
        == "committed"
    )
    assert log.stat().st_size == 2_097_152


def test_root_captured_release_bytes_are_fenced_before_privileged_owner_install(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    backend = (
        Path(manifest["root"]["directory"])
        / "releases"
        / metadata["release_id"]
        / "data/pf-backend.sh"
    )

    def replace_after_staging(*args: Any) -> bool:
        backend.write_bytes(b"unreviewed privileged backend")
        return False

    monkeypatch.setattr(implementation, "_root_hold", replace_after_staging)
    tools = FakeTools()
    with pytest.raises(DeploymentError, match="installed release differs"):
        install_bundle(bundle, "root", expected_digest=metadata["bundle_digest"], runner=tools)
    assert not any("install" in argv or "bootstrap" in argv for argv in tools.calls)


def test_root_operational_record_replacement_during_capture_blocks_rollback(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    tools = FakeTools()
    install_bundle(bundle, "root", expected_digest=metadata["bundle_digest"], runner=tools)
    state = Path(manifest["root"]["state_directory"])
    read = Store.read

    def mutate_record_after_read(store: Store, name: str) -> Any:
        value = read(store, name)
        if store.directory == state and name == "installation-receipt.json":
            changed = copy.deepcopy(value)
            changed["bundle_digest"] = "b" * 64
            (state / name).write_bytes(canonical_bytes(changed) + b"\n")
        return value

    monkeypatch.setattr(Store, "read", mutate_record_after_read)
    tools.calls.clear()
    with pytest.raises(DeploymentError, match="operational record changed during capture"):
        rollback_install(
            state, "root", expected_current_digest=metadata["bundle_digest"], runner=tools
        )
    assert tools.calls == []


@pytest.mark.parametrize("fault", ["writable", "replaced-symlink", "acl"])
def test_root_rollback_revalidates_predecessor_interpreter_before_transition(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    predecessor = tmp_path / "predecessor-python"
    predecessor.write_bytes(b"previous managed interpreter")
    predecessor.chmod(0o700)
    manifest["jobs"][1]["argv"][0] = str(predecessor)
    first, original = make_bundle(tmp_path, manifest, config, "first")
    tools = FakeTools()
    install_bundle(first, "root", expected_digest=original["bundle_digest"], runner=tools)
    newer = copy.deepcopy(manifest)
    newer["jobs"][1]["argv"][0] = str(tmp_path / "current-python")
    second, changed = make_bundle(tmp_path, newer, config, "second")
    install_bundle(second, "root", expected_digest=changed["bundle_digest"], runner=tools)
    state = Path(manifest["root"]["state_directory"])
    before = {
        name: (state / name).read_bytes()
        for name in ("installation-receipt.json", "installation-journal.json")
    }
    forwarding = Path(manifest["forwarding"]["directory"])
    intent = {"schema_version": 1, "operator_paused": True, "suspensions": {"other": "retain"}}
    Store(forwarding).write("operator-intent.json", intent)
    if fault == "writable":
        predecessor.chmod(0o777)
    elif fault == "replaced-symlink":
        predecessor.unlink()
        predecessor.symlink_to(tmp_path / "foreign-python")
    else:
        refuse_acl(monkeypatch, predecessor)
    leaf_guard = implementation._protected_executable
    native_fstat = os.fstat
    checked: list[Path] = []

    def synthetic_root_leaf(fd: int) -> os.stat_result:
        info = native_fstat(fd)
        fields = list(info)
        fields[4] = 0
        return os.stat_result(fields)

    def interpreter_guard(path: Path) -> None:
        if path == predecessor:
            checked.append(path)
            leaf_guard(path)

    def platform(scope: str, value: Any) -> int:
        job = next(item for item in value.jobs if item.scope == "root")
        if job.argv[0] == str(predecessor):
            # Invoke the real predecessor platform contract. Only the lab's
            # native OS/current-code ancestry and root UID are modelled; the
            # selected predecessor leaf executes the actual ACL/O_NOFOLLOW/
            # metadata guard. These are test seams, never installer options.
            with monkeypatch.context() as probe:
                probe.setattr(implementation.sys, "platform", "darwin")
                probe.setattr(implementation.sys, "executable", str(predecessor))
                probe.setattr(os, "geteuid", lambda: 0)
                probe.setattr(os, "fstat", synthetic_root_leaf)
                probe.setattr(implementation, "_check_tree", lambda *args, **kwargs: None)
                probe.setattr(implementation, "_protected_executable", interpreter_guard)
                return NATIVE_PLATFORM_GUARD(scope, value)
        return os.geteuid()

    monkeypatch.setattr(implementation, "_require_platform", platform)
    tools.calls.clear()
    with pytest.raises((DeploymentError, OSError)):
        rollback_install(
            state, "root", expected_current_digest=changed["bundle_digest"], runner=tools
        )
    assert checked == [predecessor]
    assert tools.calls == []
    assert {name: (state / name).read_bytes() for name in before} == before
    assert Store(forwarding).read("operator-intent.json") == intent

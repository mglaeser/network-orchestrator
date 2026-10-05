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
from netorch.deployment import install_bundle, recover_install, validate_bundle
from netorch.deployment_config import DeploymentError, parse_deployment
from netorch.deployment_model import Job
from netorch.process import run
from netorch.storage import Store
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest

__all__ = ["config", "fake_platform", "manifest"]


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


def test_input_root_ownership_is_checked(tmp_path: Path) -> None:
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

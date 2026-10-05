"""Phase-aware deployment failures, readback fencing and protected-path checks."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch.codec import canonical_bytes, digest
from netorch.deployment import (
    install_bundle,
    recover_install,
    rollback_install,
    validate_bundle,
)
from netorch.deployment_config import DeploymentError, parse_deployment
from netorch.process import Result
from netorch.state import Intent, intent_from_dict, intent_to_dict
from netorch.storage import Store
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest

__all__ = ["config", "fake_platform", "manifest"]


@pytest.mark.parametrize("failure", ["-t", "bootout", "bootstrap", "print"])
def test_failed_first_install_recovery(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None, failure: str
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    with pytest.raises(DeploymentError):
        install_bundle(
            bundle, "user", expected_digest=metadata["bundle_digest"], runner=FakeTools(failure)
        )
    state_dir = Path(manifest["user"]["state_directory"])
    result = recover_install(
        state_dir, "user", expected_failed_digest=metadata["bundle_digest"], runner=FakeTools()
    )
    assert result["phase"] == "rolled-back"
    store = Store(state_dir)
    intent = intent_from_dict(store.read("intent.json"))
    assert intent.operator_paused and not intent.suspensions
    assert not (Path(manifest["user"]["launchd_directory"]) / "org.example.netorch.plist").exists()
    assert (Path(manifest["user"]["directory"]) / "releases" / metadata["release_id"]).exists()


@pytest.mark.parametrize("scope", ["user", "root"])
def test_failed_upgrade_recovers_previous_release(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None, scope: str
) -> None:
    first, old = make_bundle(tmp_path, manifest, config, "first")
    tools = FakeTools()
    install_bundle(first, scope, expected_digest=old["bundle_digest"], runner=tools)
    newer = copy.deepcopy(manifest)
    if scope == "user":
        newer["jobs"][0]["interval_seconds"] = 15
    else:
        newer["jobs"][1]["log_directory"] += "-v2"
    second, new = make_bundle(tmp_path, newer, config, "second")
    tools.fail = "bootstrap"
    with pytest.raises(DeploymentError):
        install_bundle(second, scope, expected_digest=new["bundle_digest"], runner=tools)
    tools.fail = None
    state_dir = Path(manifest[scope]["state_directory"])
    result = recover_install(
        state_dir, scope, expected_failed_digest=new["bundle_digest"], runner=tools
    )
    assert result["release_id"] == old["release_id"]
    store = Store(state_dir)
    assert store.read("installation-receipt.json")["bundle_digest"] == old["bundle_digest"]
    if scope == "user":
        assert intent_from_dict(store.read("intent.json")).operator_paused
    assert not any("admit" in argv or "resume" in argv for argv in tools.calls)


@pytest.mark.parametrize("scope", ["user", "root"])
def test_explicit_rollback_failure_is_not_replayed(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None, scope: str
) -> None:
    first, old = make_bundle(tmp_path, manifest, config, "first")
    tools = FakeTools()
    install_bundle(first, scope, expected_digest=old["bundle_digest"], runner=tools)
    newer = copy.deepcopy(manifest)
    if scope == "user":
        newer["jobs"][0]["interval_seconds"] = 15
    else:
        newer["jobs"][1]["log_directory"] += "-v2"
    second, new = make_bundle(tmp_path, newer, config, "second")
    install_bundle(second, scope, expected_digest=new["bundle_digest"], runner=tools)
    tools.fail = "bootstrap"
    state_dir = Path(manifest[scope]["state_directory"])
    with pytest.raises(DeploymentError):
        rollback_install(
            state_dir, scope, expected_current_digest=new["bundle_digest"], runner=tools
        )
    store = Store(state_dir)
    assert store.read("installation-journal.json")["phase"] == "failed"
    assert store.read("installation-receipt.json")["bundle_digest"] == new["bundle_digest"]


def test_live_label_without_owned_file_not_stopped(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    tools = FakeTools()
    tools.loaded.add("org.example.netorch")
    with pytest.raises(DeploymentError, match="label"):
        install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"], runner=tools)
    assert not any(argv[1] == "bootout" for argv in tools.calls)


def test_bundle_swap_after_validation_is_never_promoted(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    original = implementation.validate_bundle

    def swapped(path: Path, expected_digest: str | None = None) -> dict[str, Any]:
        value = original(path, expected_digest)
        (path / "root/data/forwarding.json").write_bytes(b'{"changed":true}')
        return value

    monkeypatch.setattr(implementation, "validate_bundle", swapped)
    with pytest.raises(DeploymentError, match="between"):
        install_bundle(
            bundle, "root", expected_digest=metadata["bundle_digest"], runner=FakeTools()
        )
    assert not Path(manifest["root"]["directory"]).exists()


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("release_id", "../escape"),
        ("files", []),
        ("policy_digest", "0" * 64),
    ],
)
def test_manifest_tamper_is_closed(
    tmp_path: Path, manifest: dict[str, Any], config: Any, key: str, value: Any
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    metadata[key] = value
    metadata["bundle_digest"] = digest(
        {field: item for field, item in metadata.items() if field != "bundle_digest"}
    )
    (bundle / "manifest.json").write_bytes(canonical_bytes(metadata))
    with pytest.raises((DeploymentError, FileNotFoundError)):
        validate_bundle(bundle)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data["files"][0].update(path="../escape"),
        lambda data: data["files"][0].update(mode=True),
        lambda data: data["files"][0].update(bytes=True),
        lambda data: data["files"][0].update(extra=True),
        lambda data: data["files"].append(data["files"][0].copy()),
    ],
)
def test_inventory_tamper_is_closed(
    tmp_path: Path, manifest: dict[str, Any], config: Any, mutation: Any
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    mutation(metadata)
    metadata["bundle_digest"] = digest(
        {field: item for field, item in metadata.items() if field != "bundle_digest"}
    )
    (bundle / "manifest.json").write_bytes(canonical_bytes(metadata))
    with pytest.raises(DeploymentError):
        validate_bundle(bundle)


def test_protected_directory_and_input_guards(tmp_path: Path) -> None:
    value = tmp_path / "private"
    value.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(value, target_is_directory=True)
    with pytest.raises(DeploymentError):
        implementation._check_tree(link, os.geteuid())
    value.chmod(0o777)
    with pytest.raises(DeploymentError):
        implementation._check_tree(value, os.geteuid())
    value.chmod(0o700)
    path = value / "data"
    path.write_bytes(b"data")
    path.chmod(0o666)
    with pytest.raises(DeploymentError):
        implementation._read_file(path)
    path.chmod(0o644)
    with pytest.raises(DeploymentError):
        implementation._read_file(path, private=True)
    path.chmod(0o600)
    twin = value / "hardlink"
    os.link(path, twin)
    with pytest.raises(DeploymentError):
        implementation._read_file(path)


def test_size_and_final_inode_bounds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "data"
    path.write_bytes(b"x" * (implementation.MAX_ARTIFACT_BYTES + 1))
    path.chmod(0o600)
    with pytest.raises(DeploymentError, match="size"):
        implementation._read_file(path)
    path.write_bytes(b"data")
    original = Path.lstat

    def different_inode(self: Path) -> os.stat_result:
        result = original(self)
        if self == path:
            values = list(result)
            values[1] += 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(Path, "lstat", different_inode)
    with pytest.raises(DeploymentError, match="changed"):
        implementation._read_file(path)


def test_live_owner_identity_gate(
    manifest: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    deployment = parse_deployment(canonical_bytes(manifest))
    monkeypatch.setattr(implementation.sys, "platform", "darwin")
    monkeypatch.setattr(implementation.os, "geteuid", lambda: 502)
    with pytest.raises(DeploymentError, match="owner"):
        implementation._require_platform("user", deployment)
    with pytest.raises(DeploymentError, match="owner"):
        implementation._require_platform("root", deployment)


def test_root_context_requires_root_protected_package(
    manifest: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    deployment = parse_deployment(canonical_bytes(manifest))
    monkeypatch.setattr(implementation.sys, "platform", "darwin")
    monkeypatch.setattr(implementation.os, "geteuid", lambda: 0)
    monkeypatch.setattr(implementation.sys, "executable", deployment.jobs[1].argv[0])
    checked: list[Path] = []
    monkeypatch.setattr(implementation, "_check_tree", lambda path, uid: checked.append(path))
    monkeypatch.setattr(implementation, "_protected_executable", lambda path: checked.append(path))
    assert implementation._require_platform("root", deployment) == 0
    assert len(checked) == 6


def test_unknown_bootout_return_never_continues() -> None:
    with pytest.raises(DeploymentError):
        implementation._tool(
            lambda argv: Result(75, b"", b""), ("/tool", "bootout"), absent_ok=True
        )
    implementation._tool(lambda argv: Result(113, b"", b""), ("/tool", "bootout"), absent_ok=True)


def test_unchanged_install_still_reads_files(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    tools = FakeTools()
    install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"], runner=tools)
    path = Path(manifest["user"]["launchd_directory"]) / "org.example.netorch.plist"
    path.write_bytes(b"corruption")
    with pytest.raises(DeploymentError, match="changed"):
        install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"], runner=tools)


def test_first_install_rollback_is_not_restore(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"], runner=FakeTools())
    with pytest.raises(DeploymentError, match="no prior"):
        rollback_install(
            Path(manifest["user"]["state_directory"]),
            "user",
            expected_current_digest=metadata["bundle_digest"],
            runner=FakeTools(),
        )


def test_recovery_exact_failure_digest(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    with pytest.raises(DeploymentError):
        install_bundle(
            bundle, "user", expected_digest=metadata["bundle_digest"], runner=FakeTools("bootstrap")
        )
    with pytest.raises(DeploymentError, match="match"):
        recover_install(
            Path(manifest["user"]["state_directory"]),
            "user",
            expected_failed_digest="0" * 64,
            runner=FakeTools(),
        )


def test_damaged_intent_blocks_install(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    store = Store(Path(manifest["user"]["state_directory"]))
    store.write("intent.json", {"schema_version": 999})
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    with pytest.raises(DeploymentError, match="damaged"):
        install_bundle(
            bundle, "user", expected_digest=metadata["bundle_digest"], runner=FakeTools()
        )


def test_rollback_never_clears_other_suspension(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    first, old = make_bundle(tmp_path, manifest, config, "first")
    tools = FakeTools()
    install_bundle(first, "user", expected_digest=old["bundle_digest"], runner=tools)
    newer = copy.deepcopy(manifest)
    newer["jobs"][0]["interval_seconds"] = 15
    second, new = make_bundle(tmp_path, newer, config, "second")
    install_bundle(second, "user", expected_digest=new["bundle_digest"], runner=tools)
    store = Store(Path(manifest["user"]["state_directory"]))
    store.write(
        "intent.json", intent_to_dict(Intent().pause().suspend("database-restore", "operator"))
    )
    rollback_install(
        store.directory, "user", expected_current_digest=new["bundle_digest"], runner=tools
    )
    assert intent_from_dict(store.read("intent.json")).suspensions == {
        "database-restore": "operator"
    }

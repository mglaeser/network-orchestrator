"""Portable installation lab: no launchd, root command or production change."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import plistlib
import stat
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch.codec import canonical_bytes, digest
from netorch.config import load_config
from netorch.deployment import (
    install_bundle,
    plan_install,
    prepare_root_bundle,
    render_bundle,
    rollback_install,
    validate_bundle,
)
from netorch.deployment_config import DeploymentError, parse_deployment
from netorch.process import Result
from netorch.state import Intent, intent_from_dict, intent_to_dict
from netorch.storage import Store


@pytest.fixture
def manifest(tmp_path: Path) -> dict[str, Any]:
    settings = tmp_path / "settings.json"
    backend = tmp_path / "backend.sh"
    backend.write_bytes(b"#!/bin/sh\nexit 0\n")
    backend.chmod(0o600)
    settings.write_bytes(
        canonical_bytes(
            {
                "schema_version": 1,
                "owner": "site-forwarding",
                "anchor": "com.apple/netorch.site-forwarding",
                "observer": {"schema_version": 1, "account": "example"},
                "backend_sha256": hashlib.sha256(backend.read_bytes()).hexdigest(),
                "report_path": str(tmp_path / "reports" / "root.json"),
                "intent_path": None,
                "interval_seconds": 10,
                "allow_apple_dns_coexistence": False,
            }
        )
    )
    settings.chmod(0o600)
    return {
        "schema_version": 1,
        "site": "example-site",
        "user_uid": 501,
        "user": {
            "directory": str(tmp_path / "user-install"),
            "state_directory": str(tmp_path / "user-state"),
            "launchd_directory": str(tmp_path / "agents"),
            "domain": "gui/501",
        },
        "root": {
            "directory": str(tmp_path / "root-install"),
            "state_directory": str(tmp_path / "root-state"),
            "launchd_directory": str(tmp_path / "daemons"),
            "domain": "system",
        },
        "forwarding": {
            "directory": str(tmp_path / "pf-owner"),
            "settings_artifact": "forwarding-settings",
            "backend_source": str(backend),
            "backend_sha256": hashlib.sha256(backend.read_bytes()).hexdigest(),
        },
        "artifacts": [
            {
                "id": "forwarding-settings",
                "scope": "root",
                "source": str(settings),
                "destination": "data/forwarding.json",
                "sha256": hashlib.sha256(settings.read_bytes()).hexdigest(),
            }
        ],
        "jobs": [
            {
                "label": "org.example.netorch",
                "scope": "user",
                "role": "coordinator",
                "argv": [
                    "/protected/python",
                    "-m",
                    "netorch",
                    "reconcile",
                    "--config",
                    "{release}/data/network.json",
                    "--state-dir",
                    "{state}",
                ],
                "interval_seconds": 10,
                "keep_alive": False,
                "working_directory": "{release}",
                "log_directory": str(tmp_path / "logs"),
            },
            {
                "label": "org.example.netorch-pf",
                "scope": "root",
                "role": "forwarding",
                "argv": [
                    "/protected/root/python",
                    "-I",
                    "-m",
                    "netorch.pf_owner",
                    "reconcile",
                    "--root-dir",
                    str(tmp_path / "pf-owner"),
                ],
                "interval_seconds": 10,
                "keep_alive": False,
                "working_directory": "{release}",
                "log_directory": str(tmp_path / "root-logs"),
            },
        ],
        "monitors": [
            {
                "id": "workload",
                "role": "workload",
                "check_argv": ["/protected/manager", "probe", "--service", "camera"],
                "recovery_argv": ["/protected/manager", "start", "--service", "camera"],
                "timeout_seconds": 5,
                "cycles": 2,
                "recovery_code": 42,
            },
            {
                "id": "pf",
                "role": "forwarding",
                "check_argv": ["/protected/check", "pf"],
                "recovery_argv": None,
                "timeout_seconds": 5,
                "cycles": 2,
                "recovery_code": 42,
            },
        ],
        "monit_interval_seconds": 10,
        "launchctl": "/bin/launchctl",
        "monit": "/protected/monit",
    }


@pytest.fixture
def config() -> Any:
    return load_config(Path(__file__).resolve().parents[1] / "examples/network.json")


def make_bundle(
    tmp_path: Path, manifest: dict[str, Any], config: Any, name: str = "bundle"
) -> tuple[Path, dict[str, Any]]:
    bundle = tmp_path / name
    result = render_bundle(parse_deployment(canonical_bytes(manifest)), config, bundle)
    return bundle, result


class FakeTools:
    def __init__(self, fail: str | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fail = fail
        self.loaded: set[str] = set()

    def __call__(self, argv: tuple[str, ...]) -> Result:
        self.calls.append(argv)
        if self.fail is not None and self.fail in argv:
            return Result(1, b"", b"")
        if len(argv) > 1 and argv[1] == "bootstrap":
            self.loaded.add(Path(argv[-1]).stem)
        if len(argv) > 1 and argv[1] == "bootout":
            self.loaded.discard(argv[-1].split("/")[-1])
        if len(argv) > 1 and argv[1] == "print":
            return Result(0 if argv[-1].split("/")[-1] in self.loaded else 113, b"", b"")
        return Result(0, b"", b"")


@pytest.fixture
def fake_platform(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Unit-test adapter boundaries; never exposed as live CLI bypasses. The
    # disposable namespace models protected root ancestry even on Linux, where
    # pytest's real /tmp parent is correctly refused by the production helper.
    monkeypatch.setattr(implementation, "_require_platform", lambda scope, value: os.geteuid())
    native_prepare = implementation._prepare_report_directory
    native_lstat = Path.lstat
    namespace = tmp_path.resolve()
    shared_ancestors = set(namespace.parents)

    def protected_shared_ancestor(path: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        info = native_lstat(path, *args, **kwargs)
        if path in shared_ancestors and stat.S_ISDIR(info.st_mode):
            fields = list(info)
            fields[0] = stat.S_IFDIR | 0o755
            fields[4] = 0
            return os.stat_result(
                fields,
                {
                    key: getattr(info, key)
                    for key in ("st_atime_ns", "st_mtime_ns", "st_ctime_ns", "st_flags")
                    if hasattr(info, key)
                },
            )
        return info

    monkeypatch.setattr(Path, "lstat", protected_shared_ancestor)
    # Only the unprivileged lab's ACL provider is replaced. Production root
    # checks still execute for root scope under the synthetic current UID.
    monkeypatch.setattr(implementation, "reject_acl", lambda path, **kwargs: None)

    def prepare_report(directory: Path, uid: int) -> None:
        if not directory.is_relative_to(namespace):
            raise AssertionError("fake report preparation must remain in its disposable namespace")
        # Fixture-local state and reports retain their actual permissions,
        # ownership and inode identity; shared metadata is synthetic throughout
        # this protected root lab, not a production bypass.
        with monkeypatch.context() as scoped:
            scoped.setattr(Path, "lstat", protected_shared_ancestor)
            native_prepare(directory, uid)

    monkeypatch.setattr(implementation, "_prepare_report_directory", prepare_report)


def test_writable_report_ancestor_is_refused_without_permission_changes(
    tmp_path: Path, fake_platform: None
) -> None:
    shared = tmp_path / "writable-shared-parent"
    shared.mkdir(mode=0o777)
    shared.chmod(0o1777)
    before = shared.lstat()
    with pytest.raises(DeploymentError, match="ancestor is replaceable"):
        implementation._prepare_report_directory(shared / "reports", os.geteuid())
    after = shared.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
    )
    assert not (shared / "reports").exists()


def test_production_report_reader_refuses_shared_tmp_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real helper must reject Linux's /tmp1777 rather than relax it.

    Model that standard metadata portably, so macOS CI also covers this Linux
    trust boundary. The refused parent already exists; no file is created.
    """
    native_lstat = Path.lstat

    def shared_tmp(path: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        info = native_lstat(path, *args, **kwargs)
        if path == Path("/tmp"):
            fields = list(info)
            fields[0] = stat.S_IFDIR | 0o1777
            fields[4] = 0
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(Path, "lstat", shared_tmp)
    with pytest.raises(DeploymentError, match="ancestor is replaceable"):
        implementation._prepare_report_directory(Path("/tmp/netorch-unused-report-fixture"), 0)


def test_production_privileged_tree_refuses_shared_tmp_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native_lstat = Path.lstat

    def shared_tmp(path: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        info = native_lstat(path, *args, **kwargs)
        if path == Path("/tmp"):
            values = list(info)
            values[0] = stat.S_IFDIR | 0o1777
            values[4] = 0
            return os.stat_result(values)
        return info

    monkeypatch.setattr(Path, "lstat", shared_tmp)
    with pytest.raises(DeploymentError, match="ancestor permits other writers"):
        implementation._check_tree(Path("/tmp"), os.geteuid(), privileged=True)


def test_deterministic_bundle(tmp_path: Path, manifest: dict[str, Any], config: Any) -> None:
    first, metadata = make_bundle(tmp_path, manifest, config, "first")
    second, other = make_bundle(tmp_path, manifest, config, "second")
    assert metadata == other
    assert validate_bundle(first) == validate_bundle(second)
    for record in metadata["files"]:
        assert (first / record["path"]).read_bytes() == (second / record["path"]).read_bytes()
        assert (first / record["path"]).stat().st_mode & 0o777 == 0o600
    plist = plistlib.loads((first / "user/launchd/org.example.netorch.plist").read_bytes())
    assert "StartInterval" in plist and "KeepAlive" not in plist
    assert "{release}" not in str(plist)
    assert metadata["release_id"] in str(plist)


def test_monit_recovers_only_reserved_status(
    tmp_path: Path, manifest: dict[str, Any], config: Any
) -> None:
    bundle, _ = make_bundle(tmp_path, manifest, config)
    text = (bundle / "user/monit/monitrc").read_text()
    assert "if status = 42 for 2 cycles then exec" in text
    assert text.count("then exec") == 1
    assert text.count("if status != 0 then alert") == 2
    assert "restart" not in text


@pytest.mark.parametrize("field", ["new", "__proto__", "command"])
def test_manifest_closed(manifest: dict[str, Any], field: str) -> None:
    manifest[field] = True
    with pytest.raises(DeploymentError):
        parse_deployment(canonical_bytes(manifest))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.update(schema_version=2),
        lambda data: data.update(user_uid=0),
        lambda data: data["user"].update(domain="system"),
        lambda data: data["root"].update(domain="gui/501"),
        lambda data: data["user"].update(
            state_directory=data["user"]["directory"] + "/releases/old/state"
        ),
        lambda data: data["root"].update(directory=data["user"]["directory"] + "/root"),
        lambda data: data["artifacts"][0].update(destination="data/../escape.json"),
        lambda data: data["jobs"][0].update(keep_alive=True),
        lambda data: data["jobs"][0].update(argv=["/usr/bin/sudo", "echo"]),
        lambda data: data["jobs"][0].update(role="forwarding"),
        lambda data: data["jobs"][1].update(role="coordinator"),
        lambda data: data["jobs"][1].update(
            argv=["/usr/bin/python", "-m", "netorch.pf_owner", "reconcile"]
        ),
        lambda data: data["monitors"][1].update(recovery_argv=["/manager", "start"]),
        lambda data: data["monitors"][0].update(recovery_code=1),
        lambda data: data["forwarding"].update(settings_artifact="missing"),
        lambda data: data["artifacts"].append(data["artifacts"][0].copy()),
        lambda data: data["jobs"].append(data["jobs"][0].copy()),
        lambda data: data["monitors"].append(data["monitors"][0].copy()),
    ],
)
def test_semantic_guards(manifest: dict[str, Any], mutation: Any) -> None:
    mutation(manifest)
    with pytest.raises(DeploymentError):
        parse_deployment(canonical_bytes(manifest))


def test_artifact_hash_and_source_symlink(
    tmp_path: Path, manifest: dict[str, Any], config: Any
) -> None:
    source = Path(manifest["artifacts"][0]["source"])
    source.write_bytes(b"{}")
    with pytest.raises(DeploymentError, match="hash"):
        make_bundle(tmp_path, manifest, config)
    source.unlink()
    source.symlink_to(Path(manifest["forwarding"]["backend_source"]))
    with pytest.raises(OSError):
        make_bundle(tmp_path, manifest, config)


@pytest.mark.parametrize("name", ["intent.json", "admissions.json", "journal.json", "receipt.json"])
def test_mutable_authority_not_artifact(
    tmp_path: Path, manifest: dict[str, Any], config: Any, name: str
) -> None:
    manifest["artifacts"][0]["destination"] = f"data/{name}"
    with pytest.raises(DeploymentError, match="mutable"):
        make_bundle(tmp_path, manifest, config)


def test_bundle_tampering(tmp_path: Path, manifest: dict[str, Any], config: Any) -> None:
    bundle, _ = make_bundle(tmp_path, manifest, config)
    path = bundle / "user/data/network.json"
    path.write_bytes(b"{}")
    with pytest.raises(DeploymentError, match="content"):
        validate_bundle(bundle)


def test_unreviewed_bundle_extra(tmp_path: Path, manifest: dict[str, Any], config: Any) -> None:
    bundle, _ = make_bundle(tmp_path, manifest, config)
    (bundle / "unreviewed").write_text("extra")
    with pytest.raises(DeploymentError, match="unreviewed"):
        validate_bundle(bundle)


def test_readonly_plan_prepare(tmp_path: Path, manifest: dict[str, Any], config: Any) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    plan = plan_install(bundle, "root")
    assert plan["container_recreation"] is False and plan["runtime_upgrade"] is False
    assert plan["jobs"] == ["org.example.netorch-pf"]
    prepared = tmp_path / "prepared"
    assert prepare_root_bundle(bundle, prepared)["expected_digest"] == metadata["bundle_digest"]
    assert validate_bundle(prepared) == validate_bundle(bundle)
    assert not Path(manifest["root"]["directory"]).exists()


def test_live_platform_gate(
    tmp_path: Path, manifest: dict[str, Any], config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    monkeypatch.setattr(implementation.sys, "platform", "linux")
    with pytest.raises(DeploymentError, match="macOS"):
        install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"])
    assert not Path(manifest["user"]["directory"]).exists()


def test_user_install_preserves_pause_and_definitions(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    baseline = tmp_path / "application-config"
    baseline.write_bytes(b"existing image/mount/kernel/resource definitions")
    state = Store(Path(manifest["user"]["state_directory"]))
    state.write("intent.json", intent_to_dict(Intent().pause().suspend("backup", "other-holder")))
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    tools = FakeTools()
    result = install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"], runner=tools)
    assert result["phase"] == "committed"
    intent = intent_from_dict(state.read("intent.json"))
    assert intent.operator_paused and intent.suspensions == {"backup": "other-holder"}
    assert baseline.read_bytes() == b"existing image/mount/kernel/resource definitions"
    assert not Path(manifest["root"]["directory"]).exists()
    assert not any("netorch.pf_owner" in argv for argv in tools.calls)
    assert any(argv[1] == "-t" for argv in tools.calls)
    assert tools.calls[-1][1] == "print"
    assert (
        install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"], runner=tools)[
            "phase"
        ]
        == "unchanged"
    )


@pytest.mark.parametrize("failure", ["-t", "bootout", "bootstrap", "print"])
def test_partial_failure_keeps_journal_and_gate(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None, failure: str
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    tools = FakeTools(failure)
    with pytest.raises(DeploymentError):
        install_bundle(bundle, "user", expected_digest=metadata["bundle_digest"], runner=tools)
    state = Store(Path(manifest["user"]["state_directory"]))
    assert state.read("installation-journal.json")["phase"] == "failed"
    intent = intent_from_dict(state.read("intent.json"))
    assert intent.operator_paused and "installation" in intent.suspensions
    with pytest.raises(DeploymentError, match="unfinished"):
        install_bundle(
            bundle, "user", expected_digest=metadata["bundle_digest"], runner=FakeTools()
        )


def test_foreign_launchd_file_not_overwritten(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    agents = Path(manifest["user"]["launchd_directory"])
    agents.mkdir(mode=0o700)
    existing = agents / "org.example.netorch.plist"
    existing.write_bytes(b"foreign")
    existing.chmod(0o600)
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    with pytest.raises(DeploymentError, match="owned"):
        install_bundle(
            bundle, "user", expected_digest=metadata["bundle_digest"], runner=FakeTools()
        )
    assert existing.read_bytes() == b"foreign"


def test_root_install_is_independent(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    tools = FakeTools()
    result = install_bundle(bundle, "root", expected_digest=metadata["bundle_digest"], runner=tools)
    assert result["phase"] == "committed"
    assert any(argv[1:5] == ("-I", "-m", "netorch.pf_owner", "install") for argv in tools.calls)
    assert not any("admit" in argv or "resume" in argv for argv in tools.calls)
    assert not Path(manifest["user"]["directory"]).exists()


def test_upgrade_and_explicit_rollback_preserves_current_pause(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    first, old = make_bundle(tmp_path, manifest, config, "old")
    tools = FakeTools()
    install_bundle(first, "user", expected_digest=old["bundle_digest"], runner=tools)
    changed = copy.deepcopy(manifest)
    changed["jobs"][0]["interval_seconds"] = 15
    second, new = make_bundle(tmp_path, changed, config, "new")
    install_bundle(second, "user", expected_digest=new["bundle_digest"], runner=tools)
    state_dir = Path(manifest["user"]["state_directory"])
    state = Store(state_dir)
    state.write("intent.json", intent_to_dict(Intent().pause().suspend("maintenance", "holder")))
    result = rollback_install(
        state_dir, "user", expected_current_digest=new["bundle_digest"], runner=tools
    )
    assert result["release_id"] == old["release_id"]
    intent = intent_from_dict(state.read("intent.json"))
    assert intent.operator_paused and intent.suspensions == {"maintenance": "holder"}
    assert state.read("installation-journal.json")["phase"] == "rolled-back"


def test_digest_admission_blocks_install(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    bundle, _ = make_bundle(tmp_path, manifest, config)
    with pytest.raises(DeploymentError, match="admitted"):
        install_bundle(bundle, "user", expected_digest="0" * 64, runner=FakeTools())
    assert not Path(manifest["user"]["directory"]).exists()


def test_recomputed_manifest_cannot_inject_job(
    tmp_path: Path, manifest: dict[str, Any], config: Any
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    target = bundle / "root/launchd/org.example.netorch-pf.plist"
    plist = plistlib.loads(target.read_bytes())
    plist["ProgramArguments"] = ["/usr/bin/evil"]
    target.write_bytes(plistlib.dumps(plist))
    record = next(
        item for item in metadata["files"] if item["path"].endswith("org.example.netorch-pf.plist")
    )
    record.update(
        sha256=hashlib.sha256(target.read_bytes()).hexdigest(), bytes=len(target.read_bytes())
    )
    metadata["bundle_digest"] = digest(
        {key: value for key, value in metadata.items() if key != "bundle_digest"}
    )
    (bundle / "manifest.json").write_bytes(canonical_bytes(metadata))
    with pytest.raises(DeploymentError, match="renderer"):
        validate_bundle(bundle)


def test_schema_rejects_duplicate_keys(manifest: dict[str, Any]) -> None:
    raw = json.dumps(manifest).replace(
        '"schema_version": 1', '"schema_version": 1, "schema_version": 1'
    )
    with pytest.raises(ValueError):
        parse_deployment(raw)

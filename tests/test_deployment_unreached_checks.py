"""Checks of the deployment modules that no other test executes.

Each test reaches one refusal that the coverage report of the deployment test
modules showed as never taken, and states what the refusal protects. The
refusals of rollback and recovery are also required to come before any tool
call and before any change to the journal, the receipt or durable intent.
"""

from __future__ import annotations

import copy
import hashlib
import os
import plistlib
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch.codec import canonical_bytes, digest, strict_loads
from netorch.deployment import install_bundle, recover_install, rollback_install, validate_bundle
from netorch.deployment_config import DeploymentError, parse_deployment
from netorch.process import Result
from netorch.state import Intent, intent_from_dict, intent_to_dict
from netorch.storage import Store
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest
from tests.test_full_deployment import IntegratedTools, setup_forwarding

__all__ = ["config", "fake_platform", "manifest"]

NATIVE_REPORT_DIRECTORY = implementation._prepare_report_directory
JOURNAL = "installation-journal.json"
RECEIPT = "installation-receipt.json"
Runner = Callable[[tuple[str, ...]], Result]


def write_settings(manifest: dict[str, Any], **changes: Any) -> None:
    """Change the captured forwarding settings and bind their new hash."""
    source = Path(manifest["artifacts"][0]["source"])
    source.write_bytes(canonical_bytes({**strict_loads(source.read_bytes()), **changes}))
    manifest["artifacts"][0]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()


def extra(bundle: Path, metadata: dict[str, Any]) -> None:
    """An inventoried file that the resolved deployment does not produce."""
    payload = b"{}"
    (bundle / "user/data/extra.json").write_bytes(payload)
    (bundle / "user/data/extra.json").chmod(0o600)
    metadata["files"].append(
        {
            "path": "user/data/extra.json",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
            "mode": 0o600,
        }
    )


def rebind(metadata: dict[str, Any]) -> dict[str, Any]:
    metadata["bundle_digest"] = digest(
        {key: value for key, value in metadata.items() if key != "bundle_digest"}
    )
    return metadata


def failing(tools: FakeTools, verb: str) -> Runner:
    """Fail every launchctl or owner call of this verb; every other call stays real."""

    def runner(argv: tuple[str, ...]) -> Result:
        if verb in argv:
            tools.calls.append(argv)
            return Result(1, b"", b"")
        return tools(argv)

    return runner


def newer(manifest: dict[str, Any], scope: str) -> dict[str, Any]:
    value = copy.deepcopy(manifest)
    if scope == "user":
        value["jobs"][0]["interval_seconds"] = 15
    else:
        value["jobs"][1]["log_directory"] += "-v2"
    return value


class Lab:
    """One or two releases of one scope, and everything a refusal must leave alone."""

    def __init__(self, tmp_path: Path, manifest: dict[str, Any], config: Any, scope: str) -> None:
        self.scope = scope
        self.manifest = manifest
        self.state_dir = Path(manifest[scope]["state_directory"])
        self.jobs = Path(manifest[scope]["launchd_directory"])
        self.releases = Path(manifest[scope]["directory"]) / "releases"
        self.first, self.old = make_bundle(tmp_path, manifest, config, "first")
        self.second, self.new = make_bundle(tmp_path, newer(manifest, scope), config, "second")
        self.tools = FakeTools()

    def install(self, which: str, runner: Runner | None = None) -> dict[str, Any]:
        bundle, metadata = (self.first, self.old) if which == "old" else (self.second, self.new)
        return install_bundle(
            bundle,
            self.scope,
            expected_digest=metadata["bundle_digest"],
            runner=self.tools if runner is None else runner,
        )

    def fail_install(self, which: str, verb: str = "bootstrap") -> None:
        with pytest.raises(DeploymentError):
            self.install(which, failing(self.tools, verb))

    def recover(self, expected: str | None = None) -> dict[str, Any]:
        return recover_install(
            self.state_dir,
            self.scope,
            expected_failed_digest=self.new["bundle_digest"] if expected is None else expected,
            runner=self.tools,
        )

    def rollback(self, expected: str | None = None) -> dict[str, Any]:
        return rollback_install(
            self.state_dir,
            self.scope,
            expected_current_digest=self.new["bundle_digest"] if expected is None else expected,
            runner=self.tools,
        )

    def read(self, name: str) -> Any:
        return Store(self.state_dir).read(name)

    def write(self, name: str, value: Any) -> None:
        Store(self.state_dir).write(name, value)

    def release(self, metadata: dict[str, Any]) -> Path:
        return self.releases / metadata["release_id"]

    def job(self, index: int = 0) -> Path:
        return sorted(self.jobs.glob("*.plist"))[index]

    def records(self) -> dict[str, Any]:
        return {
            "state": {
                path.name: path.read_bytes()
                for path in sorted(self.state_dir.iterdir())
                if path.name != "owner.lock"
            },
            "jobs": {path.name: path.read_bytes() for path in sorted(self.jobs.iterdir())},
            "loaded": set(self.tools.loaded),
        }

    def refused(self, call: Callable[[], Any], message: str) -> None:
        """The call is refused with this message before any tool call or any write."""
        before = self.records()
        self.tools.calls.clear()
        with pytest.raises(DeploymentError, match=message):
            call()
        assert self.tools.calls == []
        assert self.records() == before


@pytest.fixture
def user(tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None) -> Lab:
    return Lab(tmp_path, manifest, config, "user")


@pytest.fixture
def root(tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None) -> Lab:
    return Lab(tmp_path, manifest, config, "root")


# Rendering: the captured forwarding settings must agree with manifest and policy.


@pytest.mark.parametrize(
    "message,change",
    [
        ("backend hashes differ", lambda data: write_settings(data, backend_sha256="0" * 64)),
        (
            "one authoritative polling interval",
            lambda data: write_settings(data, interval_seconds=20),
        ),
        (
            "outside private root",
            lambda data: write_settings(
                data, report_path=data["root"]["directory"] + "/reports/root.json"
            ),
        ),
        (
            "outside private root",
            lambda data: write_settings(
                data, report_path=data["root"]["state_directory"] + "/root.json"
            ),
        ),
        (
            "outside private root",
            lambda data: write_settings(
                data, report_path=data["forwarding"]["directory"] + "/root.json"
            ),
        ),
        (
            "independently privileged owner",
            lambda data: write_settings(
                data, owner="camera-manager", anchor="com.apple/netorch.camera-manager"
            ),
        ),
        (
            "observation age bound",
            lambda data: (
                write_settings(data, interval_seconds=40),
                data["jobs"][1].update(interval_seconds=40),
            ),
        ),
    ],
)
def test_forwarding_settings_must_agree_with_the_manifest_and_the_policy(
    tmp_path: Path, manifest: dict[str, Any], config: Any, message: str, change: Any
) -> None:
    change(manifest)
    with pytest.raises(DeploymentError, match=message):
        make_bundle(tmp_path, manifest, config)
    assert not (tmp_path / "bundle").exists()


def test_keep_alive_job_is_rendered_as_a_daemon_without_an_interval(
    tmp_path: Path, manifest: dict[str, Any], config: Any
) -> None:
    daemon = dict(manifest["jobs"][0])
    daemon.update(
        label=daemon["label"] + "-daemon",
        role="existing-manager",
        argv=["/protected/tool", "serve"],
        interval_seconds=None,
        keep_alive=True,
    )
    manifest["jobs"].append(daemon)
    bundle, _ = make_bundle(tmp_path, manifest, config)
    rendered = plistlib.loads((bundle / "user/launchd" / f"{daemon['label']}.plist").read_bytes())
    assert rendered["KeepAlive"] is True and "StartInterval" not in rendered
    periodic = plistlib.loads(
        (bundle / "user/launchd" / f"{manifest['jobs'][0]['label']}.plist").read_bytes()
    )
    assert periodic["StartInterval"] == 10 and "KeepAlive" not in periodic


def test_default_tool_runner_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []
    result = Result(0, b"", b"")

    def run(argv: list[str], **bounds: Any) -> Result:
        seen.append((argv, bounds))
        return result

    monkeypatch.setattr(implementation, "run", run)
    assert implementation.run_tool(("/bin/launchctl", "print", "system/label")) is result
    assert seen == [
        (["/bin/launchctl", "print", "system/label"], {"timeout": 30, "max_output": 65_536})
    ]


# The manifest of a bundle is closed: inventory, release identity, captured inputs.


@pytest.mark.parametrize(
    "message,change",
    [
        ("invalid bundle inventory", lambda bundle, data: data.update(files={"path": "x"})),
        ("invalid bundle inventory", lambda bundle, data: data.update(files=data["files"] * 86)),
        ("release identity does not bind", lambda bundle, data: data.update(release_id="0" * 64)),
        (
            "inventory differs from the resolved deployment",
            lambda bundle, data: (
                (bundle / "user/monit/monitrc").unlink(),
                data.update(
                    files=[item for item in data["files"] if item["path"] != "user/monit/monitrc"]
                ),
            ),
        ),
        (
            "inventory differs from the resolved deployment",
            lambda bundle, data: extra(bundle, data),
        ),
    ],
)
def test_rebound_bundle_manifest_is_still_refused(
    tmp_path: Path, manifest: dict[str, Any], config: Any, message: str, change: Any
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    change(bundle, metadata)
    (bundle / "manifest.json").write_bytes(canonical_bytes(rebind(metadata)))
    with pytest.raises(DeploymentError, match=message):
        validate_bundle(bundle)


def test_rebound_captured_input_must_keep_its_declared_source_hash(
    tmp_path: Path, manifest: dict[str, Any], config: Any
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    name = "root/" + manifest["artifacts"][0]["destination"]
    payload = (bundle / name).read_bytes() + b" "
    (bundle / name).write_bytes(payload)
    record = next(item for item in metadata["files"] if item["path"] == name)
    record.update(sha256=hashlib.sha256(payload).hexdigest(), bytes=len(payload))
    (bundle / "manifest.json").write_bytes(canonical_bytes(rebind(metadata)))
    with pytest.raises(DeploymentError, match="declared source hash"):
        validate_bundle(bundle)


@pytest.mark.parametrize(
    "message,change",
    [
        ("canonical absolute", lambda data: data["user"].update(directory="/operator/../other")),
        ("canonical absolute", lambda data: data["jobs"][0].update(log_directory="/logs/{state}")),
        (
            "one author",
            lambda data: data["artifacts"].append({**data["artifacts"][0], "id": "second-author"}),
        ),
        (
            "cannot escape the release",
            lambda data: data["artifacts"][0].update(destination="data/a/../../escape.json"),
        ),
        (
            "outside releases",
            lambda data: data["forwarding"].update(
                directory=data["root"]["directory"] + "/releases/pf-owner"
            ),
        ),
    ],
)
def test_manifest_paths_authors_and_owner_state_are_guarded(
    manifest: dict[str, Any], message: str, change: Any
) -> None:
    change(manifest)
    with pytest.raises(DeploymentError, match=message):
        parse_deployment(canonical_bytes(manifest))


# The platform gate of a live installation.


def test_root_gate_requires_the_running_interpreter_and_the_native_launchctl(
    manifest: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    deployment = parse_deployment(canonical_bytes(manifest))
    monkeypatch.setattr(implementation.sys, "platform", "darwin")
    monkeypatch.setattr(implementation.os, "geteuid", lambda: 0)
    monkeypatch.setattr(implementation, "_check_tree", lambda path, uid: None)
    monkeypatch.setattr(implementation, "_protected_executable", lambda path: None)
    monkeypatch.setattr(implementation.sys, "executable", "/protected/other/python")
    with pytest.raises(DeploymentError, match="already trusted interpreter"):
        implementation._require_platform("root", deployment)
    monkeypatch.setattr(implementation.sys, "executable", deployment.jobs[1].argv[0])
    assert implementation._require_platform("root", deployment) == 0
    relocated = parse_deployment(canonical_bytes({**manifest, "launchctl": "/opt/bin/launchctl"}))
    with pytest.raises(DeploymentError, match="native launchctl only"):
        implementation._require_platform("root", relocated)


def test_user_gate_admits_the_declared_user_without_any_root_check(
    manifest: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    deployment = parse_deployment(canonical_bytes(manifest))

    def unexpected(*arguments: Any, **options: Any) -> None:
        raise AssertionError("user scope must not apply the root package checks")

    monkeypatch.setattr(implementation.sys, "platform", "darwin")
    monkeypatch.setattr(implementation.os, "geteuid", lambda: deployment.user_uid)
    monkeypatch.setattr(implementation, "_check_tree", unexpected)
    monkeypatch.setattr(implementation, "_protected_executable", unexpected)
    assert implementation._require_platform("user", deployment) == deployment.user_uid


def test_protected_executable_accepts_only_a_root_owned_unwritable_file(
    tmp_path: Path, fake_platform: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "python"
    path.write_bytes(b"interpreter")
    path.chmod(0o755)
    native = os.fstat

    def root_owned(descriptor: int) -> os.stat_result:
        fields = list(native(descriptor))
        fields[4] = 0
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", root_owned)
    implementation._protected_executable(path)
    path.chmod(0o775)
    with pytest.raises(DeploymentError, match="root-owned and protected"):
        implementation._protected_executable(path)


# Directory ownership and readback fences.


def root_owned_tree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Model a root-owned tree: uid 0 everywhere, protected ancestors above the namespace."""
    native = Path.lstat
    above = set(tmp_path.resolve().parents)

    def lstat(path: Path, *arguments: Any, **options: Any) -> os.stat_result:
        fields = list(native(path, *arguments, **options))
        fields[4] = 0
        if path in above:
            fields[0] = stat.S_IFDIR | 0o755
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(implementation, "reject_acl", lambda path, **options: None)


def test_root_report_directory_must_be_traversable_by_the_coordinator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root_owned_tree(monkeypatch, tmp_path)
    tmp_path.chmod(0o755)
    NATIVE_REPORT_DIRECTORY(tmp_path / "reports", 0)
    assert stat.S_IMODE(os.lstat(tmp_path / "reports").st_mode) == 0o755
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    with pytest.raises(DeploymentError, match="publicly traversable"):
        NATIVE_REPORT_DIRECTORY(private / "reports", 0)
    assert not (private / "reports").exists()
    assert stat.S_IMODE(os.lstat(private).st_mode) == 0o700


def test_installation_tree_must_exist_and_belong_to_the_installing_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(DeploymentError, match="directory is unavailable"):
        implementation._check_tree(tmp_path / "missing", os.geteuid())
    assert not (tmp_path / "missing").exists()
    root_owned_tree(monkeypatch, tmp_path)
    with pytest.raises(DeploymentError, match="wrong owner"):
        implementation._check_tree(tmp_path, 501)


def test_privileged_artifact_is_read_back_after_it_is_written(
    tmp_path: Path, fake_platform: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "release" / "data.json"
    native = os.fsync

    def replaced(descriptor: int) -> None:
        native(descriptor)
        target.write_bytes(b"other bytes")

    monkeypatch.setattr(os, "fsync", replaced)
    with pytest.raises(DeploymentError, match="generated privileged artifact differs"):
        implementation._write_new(target, b"reviewed", privileged=True)


def test_privileged_record_is_read_back_after_it_is_written(
    tmp_path: Path, fake_platform: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "state").mkdir(mode=0o700)
    store = implementation._PrivilegedStore(tmp_path / "state")
    native = Store.write
    monkeypatch.setattr(
        Store, "write", lambda self, name, value: native(self, name, {"phase": "other"})
    )
    with pytest.raises(DeploymentError, match="privileged operational write differs"):
        store.write(JOURNAL, {"phase": "staging"})


def test_installed_job_is_read_back_after_the_atomic_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = os.replace

    def replaced(source: Any, target: Any, **options: Any) -> None:
        native(source, target, **options)
        Path(target).write_bytes(b"other bytes")

    monkeypatch.setattr(os, "replace", replaced)
    with pytest.raises(DeploymentError, match="installed job differs"):
        implementation._atomic_record(tmp_path / "job.plist", b"reviewed", os.geteuid())


def test_root_log_target_replaced_during_inspection_blocks_bootstrap(
    tmp_path: Path, manifest: dict[str, Any], fake_platform: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    job = parse_deployment(canonical_bytes(manifest)).jobs[1]
    daemons = Path(manifest["root"]["launchd_directory"])
    daemons.mkdir(mode=0o700)
    installed = daemons / f"{job.label}.plist"
    installed.write_bytes(b"reviewed job")
    installed.chmod(0o600)
    logs = Path(job.log_directory)
    logs.mkdir(mode=0o700)
    log = logs / f"{job.label}.out.log"
    log.write_bytes(b"earlier output")
    log.chmod(0o600)
    implementation._fence_job(installed, b"reviewed job", job, os.geteuid())
    current = Path.lstat

    def another_file(path: Path, *arguments: Any, **options: Any) -> os.stat_result:
        info = current(path, *arguments, **options)
        if path != log:
            return info
        fields = list(info)
        fields[1] += 1
        return os.stat_result(fields)

    # The path now names another file than the descriptor that was inspected.
    monkeypatch.setattr(Path, "lstat", another_file)
    with pytest.raises(DeploymentError, match="log target changed"):
        implementation._fence_job(installed, b"reviewed job", job, os.geteuid())


# A receipt is operational data, not authority: its shape is closed.


@pytest.mark.parametrize(
    "message,fault",
    [
        ("invalid receipt identity", lambda receipt: receipt.update(release_id="../../escape")),
        ("invalid receipt identity", lambda receipt: receipt.update(bundle_digest=7)),
        ("invalid receipt job inventory", lambda receipt: receipt.update(jobs={})),
        (
            "invalid receipt job inventory",
            lambda receipt: receipt.update(jobs=receipt["jobs"] * 33),
        ),
        ("invalid receipt job record", lambda receipt: receipt["jobs"][0].update(label="../x")),
        ("invalid receipt job record", lambda receipt: receipt["jobs"][0].update(sha256="short")),
        ("invalid receipt job record", lambda receipt: receipt["jobs"].append("label")),
        ("invalid receipt job record", lambda receipt: receipt["jobs"][0].update(extra=True)),
    ],
)
def test_receipt_with_an_invalid_identity_or_job_record_authorizes_nothing(
    user: Lab, message: str, fault: Any
) -> None:
    user.install("old")
    user.install("new")
    receipt = user.read(RECEIPT)
    fault(receipt)
    user.write(RECEIPT, receipt)
    user.refused(user.rollback, message)
    user.refused(lambda: user.install("new"), message)


# Rollback: every refusal comes before the first tool call and the first write.


def forge_predecessor(lab: Lab, change: Callable[[dict[str, Any]], None]) -> None:
    """Rewrite the predecessor's manifest and make the receipt name the new digest."""
    path = lab.release(lab.old) / "bundle-manifest.json"
    metadata = strict_loads(path.read_bytes())
    change(metadata)
    path.write_bytes(canonical_bytes(rebind(metadata)) + b"\n")
    receipt = lab.read(RECEIPT)
    receipt["previous"]["bundle_digest"] = metadata["bundle_digest"]
    lab.write(RECEIPT, receipt)


def outside(lab: Lab) -> Callable[[dict[str, Any]], None]:
    """A record that names an existing private file two levels above the release."""
    payload = b"not part of any release"
    path = lab.releases.parent / "outside.json"
    path.write_bytes(payload)
    path.chmod(0o600)
    record = {
        "path": "user/../../outside.json",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "mode": 0o600,
    }
    return lambda metadata: metadata["files"].append(record)


def change_receipt(lab: Lab, change: Callable[[dict[str, Any]], None]) -> None:
    receipt = lab.read(RECEIPT)
    change(receipt)
    lab.write(RECEIPT, receipt)


@pytest.mark.parametrize(
    "message,arrange,digest_of",
    [
        ("does not match the current installed release", lambda lab: None, "old"),
        (
            "readable durable intent",
            lambda lab: lab.write("intent.json", {"schema_version": 999}),
            "new",
        ),
        ("escapes its boundary", lambda lab: forge_predecessor(lab, outside(lab)), "new"),
        (
            "rollback cannot change installation boundaries",
            lambda lab: change_receipt(
                lab,
                lambda receipt: receipt["previous"]["deployment"]["user"].update(
                    directory=receipt["deployment"]["user"]["directory"] + "-moved"
                ),
            ),
            "new",
        ),
        (
            "previous release was modified",
            lambda lab: change_receipt(
                lab, lambda receipt: receipt["previous"]["jobs"][0].update(sha256="0" * 64)
            ),
            "new",
        ),
    ],
)
def test_rollback_refuses_before_any_effect(
    user: Lab, message: str, arrange: Any, digest_of: str
) -> None:
    user.install("old")
    user.install("new")
    arrange(user)
    expected = (user.old if digest_of == "old" else user.new)["bundle_digest"]
    user.refused(lambda: user.rollback(expected), message)


def test_rollback_does_not_stop_a_job_whose_installed_file_changed(user: Lab) -> None:
    user.install("old")
    user.install("new")
    user.job().write_bytes(b"not the committed job")
    receipt, loaded = user.read(RECEIPT), set(user.tools.loaded)
    user.tools.calls.clear()
    with pytest.raises(DeploymentError, match="current managed file changed"):
        user.rollback()
    assert user.tools.calls == []
    assert user.tools.loaded == loaded
    assert user.job().read_bytes() == b"not the committed job"
    assert user.read(RECEIPT) == receipt


# Recovery: every refusal comes before the first tool call and the first write.


def forge_failed_release(lab: Lab, change: Callable[[dict[str, Any]], None]) -> str:
    """Rewrite the failed release's manifest and make the journal name its new digest."""
    path = lab.release(lab.new) / "bundle-manifest.json"
    metadata = strict_loads(path.read_bytes())
    change(metadata)
    path.write_bytes(canonical_bytes(rebind(metadata)) + b"\n")
    journal = lab.read(JOURNAL)
    journal["bundle_digest"] = metadata["bundle_digest"]
    lab.write(JOURNAL, journal)
    return str(metadata["bundle_digest"])


def stale_manifest(lab: Lab) -> None:
    path = lab.release(lab.new) / "bundle-manifest.json"
    metadata = strict_loads(path.read_bytes())
    metadata["policy_digest"] = "0" * 64
    path.write_bytes(canonical_bytes(metadata) + b"\n")


RECOVERY_FAULTS: list[tuple[str, str, Callable[[Lab], Any]]] = [
    (
        "first",
        "lacks a valid release identity",
        lambda lab: lab.write(JOURNAL, {**lab.read(JOURNAL), "release_id": "../../escape"}),
    ),
    ("first", "first-release evidence was modified", stale_manifest),
    (
        "first",
        "failed first-install job has foreign content",
        lambda lab: lab.job().write_bytes(b"not a generated job"),
    ),
    (
        "first",
        "requires its original suspension",
        lambda lab: lab.write("intent.json", {"schema_version": 999}),
    ),
    (
        "first",
        "requires its original suspension",
        lambda lab: lab.write(
            "intent.json", intent_to_dict(Intent().pause().suspend("installation", "holder-a"))
        ),
    ),
    ("upgrade", "failed release manifest changed", stale_manifest),
    (
        "upgrade",
        "failed-install job has foreign content",
        lambda lab: lab.job().write_bytes(b"not a job of either release"),
    ),
    (
        "upgrade",
        "requires the original installation suspension",
        lambda lab: lab.write("intent.json", {"schema_version": 999}),
    ),
    (
        "upgrade",
        "requires the original installation suspension",
        lambda lab: lab.write(
            "intent.json", intent_to_dict(Intent().pause().suspend("installation", "holder-a"))
        ),
    ),
]


@pytest.mark.parametrize("scenario,message,arrange", RECOVERY_FAULTS)
def test_recovery_refuses_before_any_effect(
    user: Lab, scenario: str, message: str, arrange: Any
) -> None:
    if scenario == "upgrade":
        user.install("old")
    user.fail_install("new")
    arrange(user)
    user.refused(user.recover, message)


@pytest.mark.parametrize("scope", ["user", "root"])
def test_recovery_cannot_move_a_boundary_even_when_journal_and_manifest_agree(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None, scope: str
) -> None:
    lab = Lab(tmp_path, manifest, config, scope)
    lab.install("old")
    lab.fail_install("new")

    def move(metadata: dict[str, Any]) -> None:
        deployment = metadata["deployment"]
        if scope == "user":
            deployment["user"]["directory"] += "-moved"
        else:
            deployment["forwarding"]["directory"] += "-moved"
            deployment["jobs"][1]["argv"][-1] = deployment["forwarding"]["directory"]

    forged = forge_failed_release(lab, move)
    message = "installation boundaries" if scope == "user" else "forwarding ownership boundaries"
    lab.refused(lambda: lab.recover(forged), f"recovery cannot change {message}")


def test_first_install_recovery_keeps_a_receipt_of_another_bundle(user: Lab) -> None:
    user.fail_install("new")
    unrelated = {
        "schema_version": 1,
        "release_id": user.old["release_id"],
        "bundle_digest": user.old["bundle_digest"],
        "scope": "user",
        "jobs": [],
        "previous": None,
        "deployment": user.old["deployment"],
    }
    user.write(RECEIPT, unrelated)
    receipt = (user.state_dir / RECEIPT).read_bytes()
    journal = (user.state_dir / JOURNAL).read_bytes()
    with pytest.raises(DeploymentError, match="unrelated receipt"):
        user.recover()
    assert (user.state_dir / RECEIPT).read_bytes() == receipt
    assert (user.state_dir / JOURNAL).read_bytes() == journal
    assert intent_from_dict(user.read("intent.json")).suspensions == {
        "installation": user.new["bundle_digest"]
    }


# Root scope with the real owner functions behind the runner.


@pytest.fixture
def owned(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> Lab:
    setup_forwarding(manifest, monkeypatch)
    lab = Lab(tmp_path, manifest, config, "root")
    lab.tools = IntegratedTools()
    return lab


def owner_intent(lab: Lab) -> Intent:
    return intent_from_dict(
        Store(Path(lab.manifest["forwarding"]["directory"])).read("operator-intent.json")
    )


def test_root_upgrade_recovery_releases_its_own_hold_and_no_other(owned: Lab) -> None:
    owned.install("old")
    owner = Store(Path(owned.manifest["forwarding"]["directory"]))
    # The administrator resumed; another operation of the owner is suspended.
    owner.write("operator-intent.json", intent_to_dict(Intent().suspend("backup", "holder-a")))
    owned.fail_install("new")
    assert owner_intent(owned).suspensions == {
        "backup": "holder-a",
        "installation": owned.new["bundle_digest"],
    }
    assert owned.recover()["release_id"] == owned.old["release_id"]
    after = owner_intent(owned)
    assert after.suspensions == {"backup": "holder-a"}
    assert after.operator_paused is False
    assert owned.read(RECEIPT)["bundle_digest"] == owned.old["bundle_digest"]
    assert owned.tools.loaded == {owned.manifest["jobs"][1]["label"]}


def test_first_root_installation_failed_at_its_release_is_recovered_without_its_receipt(
    owned: Lab,
) -> None:
    owned.fail_install("old", "release")
    assert owned.read(JOURNAL)["failed_phase"] == "starting-jobs"
    assert owned.read(RECEIPT)["bundle_digest"] == owned.old["bundle_digest"]
    assert owner_intent(owned).suspensions == {"installation": owned.old["bundle_digest"]}
    recovered = owned.recover(owned.old["bundle_digest"])
    assert recovered["root_gate_retained"] is False
    assert not (owned.state_dir / RECEIPT).exists()
    assert owned.read(JOURNAL)["phase"] == "rolled-back"
    after = owner_intent(owned)
    assert after.operator_paused and not after.suspensions
    assert owned.tools.loaded == set() and list(owned.jobs.iterdir()) == []


def test_first_root_installation_failed_before_the_owner_exists_is_recovered(root: Lab) -> None:
    root.fail_install("old", "print")
    assert root.read(JOURNAL)["failed_phase"] == "preflight-jobs"
    recovered = root.recover(root.old["bundle_digest"])
    assert recovered["phase"] == "rolled-back" and recovered["root_gate_retained"] is False
    assert root.read(JOURNAL)["phase"] == "rolled-back"
    assert not Path(root.manifest["forwarding"]["directory"]).exists()
    assert not any("netorch.pf_owner" in argv for argv in root.tools.calls)

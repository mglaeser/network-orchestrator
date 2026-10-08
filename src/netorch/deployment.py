"""Deterministic macOS bundles and separate, journalled user/root installation.

No command in this module escalates privilege, modifies a container definition,
installs a runtime, or clears operator intent. Root installation is an explicit
administrator invocation using a previously trusted root-owned Python package.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import plistlib
import re
import shlex
import stat
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any

from .codec import MAX_JSON_BYTES, CodecError, canonical_bytes, digest, strict_loads
from .config import config_digest, parse_config, to_dict
from .deployment_config import (
    DeploymentError,
    deployment_to_dict,
    parse_deployment,
    validate_deployment,
)
from .deployment_model import Deployment, Job
from .model import Config
from .pf_owner import Installation as ForwardingSettings
from .pf_owner import reject_acl
from .process import ProcessError, Result, run
from .state import Intent, intent_from_dict, intent_to_dict
from .storage import Store

ToolRunner = Callable[[tuple[str, ...]], Result]
MAX_ARTIFACT_BYTES = 1_048_576
# Phases install_bundle journals before the effects they name. A journal still
# in one of them was not closed by its installer: no handler ran (kill, lost
# power) or the handler could not write.
_OPEN_INSTALL_PHASES = frozenset(
    {
        "staging",
        "preflight-jobs",
        "quiescing-forwarding-owner",
        "installing-forwarding-owner",
        "stopping-jobs",
        "installing-jobs",
        "starting-jobs",
    }
)
# The widest form an installation journal takes after its first write: recovery
# of an installer that was stopped records the phase it stopped in, and closes
# the journal with the longest of the phases that can stand beside one.
_WIDEST_JOURNAL_PHASES = {
    "failed_phase": max(_OPEN_INSTALL_PHASES, key=len),
    "phase": "rolled-back",
}
# The forwarding owner exits 75 when it could not take its own lock; it has then
# done nothing. Its scheduled pass holds that lock, and the job an installation
# loads starts such a pass at once. Half of the 10-second example schedule is
# long enough for one pass to end and too short to wait across two.
OWNER_BUSY = 75
OWNER_BUSY_WAIT_SECONDS = 5.0
OWNER_BUSY_RETRY_SECONDS = 0.5


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _privileged_acl(path: Path, *, content: bool = True) -> None:
    """Reuse the independent owner's strict root ACL trust boundary."""
    try:
        before = path.lstat()
        reject_acl(path)
        after = path.lstat()
        identity = _metadata if content else _trust_metadata
        if identity(after) != identity(before):
            raise DeploymentError("privileged path changed during ACL verification")
    except FileNotFoundError:
        raise
    except (OSError, RuntimeError) as exc:
        raise DeploymentError("privileged path has an ACL or incomplete protection") from exc


def _metadata(info: os.stat_result) -> tuple[int, ...]:
    # Access times may change through a read; trust/content metadata must not.
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        getattr(info, "st_flags", 0),
    )


def _trust_metadata(info: os.stat_result) -> tuple[int, ...]:
    # Append-only logs may grow during inspection; ownership, flags and identity
    # must remain unchanged even when their content metadata legitimately moves.
    return (*_metadata(info)[:6], getattr(info, "st_flags", 0))


def _forwarding_settings(deployment: Deployment, captures: dict[str, bytes]) -> ForwardingSettings:
    artifact = next(
        item for item in deployment.artifacts if item.id == deployment.forwarding.settings_artifact
    )
    settings = ForwardingSettings.from_dict(strict_loads(captures[f"root/{artifact.destination}"]))
    if settings.backend_sha256 != deployment.forwarding.backend_sha256:
        raise DeploymentError("forwarding settings and captured backend hashes differ")
    root_job = next(item for item in deployment.jobs if item.scope == "root")
    if root_job.interval_seconds != settings.interval_seconds:
        raise DeploymentError("forwarding owner has one authoritative polling interval")
    report = Path(settings.report_path)
    for private in (
        deployment.root.directory,
        deployment.root.state_directory,
        deployment.forwarding.directory,
    ):
        if report.is_relative_to(private):
            raise DeploymentError("root report must be outside private root release/state trees")
    return settings


def _prepare_report_directory(directory: Path, uid: int) -> None:
    """Root-owned read-only report visibility is distinct from private root state."""
    current = Path(directory.anchor)
    for part in directory.parts[1:]:
        current /= part
        if not current.exists() and not current.is_symlink():
            current.mkdir(mode=0o755)
            current.chmod(0o755)
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, uid} or info.st_mode & 0o022:
            raise DeploymentError("root report ancestor is replaceable")
        if uid == 0 and (info.st_uid != 0 or not info.st_mode & 0o001):
            raise DeploymentError("root report must have root-owned publicly traversable ancestors")
        _privileged_acl(current)


def _read_file(
    path: Path,
    *,
    private: bool = False,
    root_owned: bool = False,
    allow_other_owner: bool = False,
    privileged: bool = False,
) -> bytes:
    if privileged or root_owned:
        _check_tree(path.parent, os.geteuid(), privileged=True)
        _privileged_acl(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise DeploymentError("bundle input must be a single-link regular file")
        if (not allow_other_owner and info.st_uid not in {0, os.geteuid()}) or stat.S_IMODE(
            info.st_mode
        ) & 0o022:
            raise DeploymentError("bundle input must be protected against other writers")
        if private and stat.S_IMODE(info.st_mode) != 0o600:
            raise DeploymentError("bundle record must have private mode 0600")
        if root_owned and info.st_uid != 0:
            raise DeploymentError("privileged installation must be owned by root")
        with os.fdopen(os.dup(fd), "rb") as stream:
            value = stream.read(MAX_ARTIFACT_BYTES + 1)
        if len(value) > MAX_ARTIFACT_BYTES:
            raise DeploymentError("bundle input exceeds its size bound")
        final = path.lstat()
        if _metadata(final) != _metadata(info) or _metadata(os.fstat(fd)) != _metadata(info):
            raise DeploymentError("bundle input changed during capture")
        if privileged or root_owned:
            _privileged_acl(path)
        return value
    finally:
        os.close(fd)


def _check_tree(path: Path, uid: int, *, create: bool = False, privileged: bool = False) -> None:
    """Check every pathname ancestor; do not follow links or replace foreign trees."""
    path = path.absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if not create:
                raise DeploymentError("installation directory is unavailable") from None
            current.mkdir(mode=0o700)
            info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, uid}:
            raise DeploymentError("installation ancestor is not an owned directory")
        writable = stat.S_IMODE(info.st_mode) & 0o022
        sticky_root = (
            not privileged and uid != 0 and info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        )
        if writable and not sticky_root:
            raise DeploymentError("installation ancestor permits other writers")
        if uid == 0 and info.st_uid != 0:
            raise DeploymentError("privileged installation has a user-owned ancestor")
        if privileged or uid == 0:
            _privileged_acl(current)
    if path.lstat().st_uid != uid:
        raise DeploymentError("installation directory has the wrong owner")


def _write_new(path: Path, payload: bytes, mode: int = 0o600, *, privileged: bool = False) -> None:
    # mkdir(parents=True) gives its mode to the last directory only; every
    # directory created here is private.
    for directory in reversed((path.parent, *path.parent.parents)):
        if not directory.is_dir():
            directory.mkdir(mode=0o700, exist_ok=True)
    if privileged:
        _check_tree(path.parent, os.geteuid(), privileged=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        remaining = memoryview(payload)
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                raise DeploymentError("bundle write made no progress")
            remaining = remaining[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if privileged and _read_file(path, private=True, privileged=True) != payload:
        raise DeploymentError("generated privileged artifact differs from its reviewed bytes")


class _PrivilegedStore(Store):
    """Deployment-only guard for root journals/receipts; user Store is unchanged."""

    def __init__(self, directory: Path) -> None:
        _check_tree(directory, os.geteuid(), privileged=True)
        super().__init__(directory)

    def _check_current_directory(self, fd: int) -> None:
        super()._check_current_directory(fd)
        _check_tree(self.directory, os.geteuid(), privileged=True)

    def read(self, name: str) -> Any:
        path = self._path(name)
        before = strict_loads(_read_file(path, private=True, privileged=True))
        value = super().read(name)
        after = strict_loads(_read_file(path, private=True, privileged=True))
        if value != before or value != after:
            raise DeploymentError("privileged operational record changed during capture")
        return value

    def write(self, name: str, value: Any) -> None:
        _check_tree(self.directory, os.geteuid(), privileged=True)
        path = self._path(name)
        if path.exists() or path.is_symlink():
            _read_file(path, private=True, privileged=True)
        super().write(name, value)
        if _read_file(path, private=True, privileged=True) != canonical_bytes(value) + b"\n":
            raise DeploymentError("privileged operational write differs from its reviewed bytes")

    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        _check_tree(self.directory, os.geteuid(), privileged=True)
        path = self._path("owner.lock")
        if path.exists() or path.is_symlink():
            _read_file(path, private=True, privileged=True)
        with super().lock():
            _read_file(path, private=True, privileged=True)
            yield


def _deployment_store(directory: Path, scope: str) -> Store:
    return _PrivilegedStore(directory) if scope == "root" else Store(directory)


def _fence_files(release: Path, files: dict[str, bytes], *, privileged: bool) -> None:
    for name, expected in files.items():
        if _read_file(release / name, private=True, privileged=privileged) != expected:
            raise DeploymentError("installed release differs from its reviewed bytes")


def _resolve(value: str, release: Path, state: str) -> str:
    return value.replace("{release}", str(release)).replace("{state}", state)


# The manifest's closed `process_type` values and the launchd `ProcessType`
# each one renders. No other class can be rendered.
_PROCESS_TYPES = {"background": "Background", "standard": "Standard"}


def _launchd(job: Job, release: Path, state: str) -> bytes:
    value: dict[str, Any] = {
        "Label": job.label,
        "ProgramArguments": [_resolve(argument, release, state) for argument in job.argv],
        "WorkingDirectory": _resolve(job.working_directory, release, state),
        "RunAtLoad": True,
        "ProcessType": _PROCESS_TYPES[job.process_type],
        "Umask": 0o077,
        "ThrottleInterval": 10,
        "StandardOutPath": f"{job.log_directory}/{job.label}.out.log",
        "StandardErrorPath": f"{job.log_directory}/{job.label}.err.log",
        "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"},
    }
    if job.interval_seconds is not None:
        value["StartInterval"] = job.interval_seconds
    if job.keep_alive:
        value["KeepAlive"] = True
    return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)


def _monit_command(argv: tuple[str, ...], release: Path, state: str) -> str:
    command = shlex.join([_resolve(item, release, state) for item in argv])
    return '"' + command.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _monit(deployment: Deployment, release: Path) -> bytes:
    state = deployment.user.state_directory
    lines = [
        "# Generated from one reviewed deployment manifest. No wildcard recovery.",
        f"set daemon {deployment.monit_interval_seconds}",
        f'set pidfile "{state}/monit.pid"',
        f'set statefile "{state}/monit.state"',
        f'set idfile "{state}/monit.id"',
        "set init",
        "set log syslog",
    ]
    for monitor in deployment.monitors:
        lines.extend(
            [
                "",
                f'check program "{monitor.id}" with path '
                + _monit_command(monitor.check_argv, release, state),
                f"  timeout {monitor.timeout_seconds} seconds",
                "  if status != 0 then alert",
            ]
        )
        if monitor.recovery_argv is not None:
            rule = f"  if status = 42 for {monitor.cycles} cycles then exec " + _monit_command(
                monitor.recovery_argv, release, state
            )
            if monitor.recovery_repeat_cycles is not None:
                # Without this Monit runs the command once per failure episode.
                rule += f" repeat every {monitor.recovery_repeat_cycles} cycles"
            lines.append(rule)
    return ("\n".join(lines) + "\n").encode()


def render_bundle(deployment: Deployment, config: Config, output: Path) -> dict[str, Any]:
    """Capture all inputs once, validate data and create an immutable hash inventory."""
    validate_deployment(deployment)
    if deployment.site != config.site:
        raise DeploymentError("deployment and network policy sites differ")
    if output.exists() or output.is_symlink():
        raise DeploymentError("bundle output already exists")
    captures: dict[str, bytes] = {}
    for artifact in deployment.artifacts:
        payload = _read_file(Path(artifact.source))
        if _sha(payload) != artifact.sha256:
            raise DeploymentError("artifact content differs from its reviewed hash")
        strict_loads(payload)
        if any(
            word in PurePosixPath(artifact.destination).name
            for word in ("intent", "admission", "journal", "receipt")
        ):
            raise DeploymentError("mutable state and admissions cannot be release artifacts")
        captures[f"{artifact.scope}/{artifact.destination}"] = payload
    if any(
        name in captures
        for name in ("user/data/network.json", "root/data/network.json", "root/data/pf-backend.sh")
    ):
        raise DeploymentError("generated policy and backend names are reserved")
    backend = _read_file(Path(deployment.forwarding.backend_source))
    if _sha(backend) != deployment.forwarding.backend_sha256:
        raise DeploymentError("forwarding backend differs from its reviewed hash")
    captures["root/data/pf-backend.sh"] = backend
    settings = _forwarding_settings(deployment, captures)
    if config.owner(settings.owner).privilege != "external-root":
        raise DeploymentError("forwarding settings must name the independently privileged owner")
    if any(
        profile.safety.max_age_seconds < settings.interval_seconds
        for profile in config.profiles
        if config.profile_owner(profile).id == settings.owner
    ):
        raise DeploymentError("forwarding schedule cannot exceed its observation age bound")
    release_id = digest({"deployment": deployment_to_dict(deployment), "policy": to_dict(config)})
    for scope in ("user", "root"):
        captures[f"{scope}/data/network.json"] = canonical_bytes(to_dict(config)) + b"\n"
        release = Path(deployment.installation(scope).directory) / "releases" / release_id
        for job in deployment.jobs:
            if job.scope == scope:
                captures[f"{scope}/launchd/{job.label}.plist"] = _launchd(
                    job, release, deployment.installation(scope).state_directory
                )
        if scope == "user":
            captures["user/monit/monitrc"] = _monit(deployment, release)
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "release_id": release_id,
        "policy_digest": config_digest(config),
        "deployment": deployment_to_dict(deployment),
        "files": [
            {"path": name, "sha256": _sha(payload), "bytes": len(payload), "mode": 0o600}
            for name, payload in sorted(captures.items())
        ],
    }
    manifest["bundle_digest"] = digest(manifest)
    _check_tree(output.parent, os.geteuid())
    output.mkdir(mode=0o700)
    for name, payload in captures.items():
        _write_new(output / name, payload)
    _write_new(output / "manifest.json", canonical_bytes(manifest) + b"\n")
    return manifest


def validate_bundle(bundle: Path, expected_digest: str | None = None) -> dict[str, Any]:
    manifest = strict_loads(
        _read_file(bundle / "manifest.json", private=True, allow_other_owner=os.geteuid() == 0)
    )
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {"schema_version", "release_id", "policy_digest", "deployment", "files", "bundle_digest"}
        or type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
    ):
        raise DeploymentError("unsupported bundle manifest")
    checked = {key: value for key, value in manifest.items() if key != "bundle_digest"}
    if digest(checked) != manifest["bundle_digest"] or (
        expected_digest is not None and expected_digest != manifest["bundle_digest"]
    ):
        raise DeploymentError("bundle content was not admitted by this installation request")
    deployment = parse_deployment(canonical_bytes(manifest["deployment"]))
    if (
        not isinstance(manifest["release_id"], str)
        or re.fullmatch(r"[0-9a-f]{64}", manifest["release_id"]) is None
    ):
        raise DeploymentError("invalid release identity")
    if not isinstance(manifest["files"], list) or len(manifest["files"]) > 256:
        raise DeploymentError("invalid bundle inventory")
    seen: set[str] = set()
    for record in manifest["files"]:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes", "mode"}:
            raise DeploymentError("invalid bundle file record")
        name = record["path"]
        if (
            not isinstance(name, str)
            or PurePosixPath(name).is_absolute()
            or ".." in PurePosixPath(name).parts
            or name in seen
            or not name.startswith(("user/", "root/"))
        ):
            raise DeploymentError("bundle inventory escapes or duplicates a scope")
        seen.add(name)
        payload = _read_file(bundle / name, private=True, allow_other_owner=os.geteuid() == 0)
        if (
            _sha(payload) != record["sha256"]
            or type(record["bytes"]) is not int
            or len(payload) != record["bytes"]
            or type(record["mode"]) is not int
            or record["mode"] != 0o600
        ):
            raise DeploymentError("bundle file content changed")
    actual = {
        str(path.relative_to(bundle))
        for path in bundle.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual != seen | {"manifest.json"}:
        raise DeploymentError("bundle contains unreviewed files")
    policy = parse_config(
        _read_file(
            bundle / "user/data/network.json", private=True, allow_other_owner=os.geteuid() == 0
        )
    )
    if config_digest(policy) != manifest["policy_digest"] or policy.site != deployment.site:
        raise DeploymentError("bundle network policy does not match its manifest")
    if (
        digest({"deployment": deployment_to_dict(deployment), "policy": to_dict(policy)})
        != manifest["release_id"]
    ):
        raise DeploymentError("release identity does not bind its complete inputs")
    expected_files = {
        "user/data/network.json",
        "root/data/network.json",
        "root/data/pf-backend.sh",
        "user/monit/monitrc",
    }
    expected_files.update(f"{item.scope}/{item.destination}" for item in deployment.artifacts)
    expected_files.update(f"{job.scope}/launchd/{job.label}.plist" for job in deployment.jobs)
    if expected_files != seen:
        raise DeploymentError("bundle inventory differs from the resolved deployment")
    captured_inputs: dict[str, bytes] = {}
    for artifact in deployment.artifacts:
        name = f"{artifact.scope}/{artifact.destination}"
        payload = _read_file(bundle / name, private=True, allow_other_owner=os.geteuid() == 0)
        if _sha(payload) != artifact.sha256:
            raise DeploymentError("captured input differs from its declared source hash")
        strict_loads(payload)
        captured_inputs[name] = payload
    _forwarding_settings(deployment, captured_inputs)
    if (
        _read_file(
            bundle / "root/data/network.json", private=True, allow_other_owner=os.geteuid() == 0
        )
        != canonical_bytes(to_dict(policy)) + b"\n"
    ):
        raise DeploymentError("user and root captured policy differ")
    backend = _read_file(
        bundle / "root/data/pf-backend.sh", private=True, allow_other_owner=os.geteuid() == 0
    )
    if _sha(backend) != deployment.forwarding.backend_sha256:
        raise DeploymentError("captured backend differs from its reviewed implementation")
    user_release = Path(deployment.user.directory) / "releases" / manifest["release_id"]
    if _read_file(
        bundle / "user/monit/monitrc", private=True, allow_other_owner=os.geteuid() == 0
    ) != _monit(deployment, user_release):
        raise DeploymentError("Monit definition differs from the reviewed renderer")
    for job in deployment.jobs:
        install = deployment.installation(job.scope)
        release = Path(install.directory) / "releases" / manifest["release_id"]
        expected = _launchd(job, release, install.state_directory)
        if (
            _read_file(
                bundle / job.scope / "launchd" / f"{job.label}.plist",
                private=True,
                allow_other_owner=os.geteuid() == 0,
            )
            != expected
        ):
            raise DeploymentError("launchd definition differs from the reviewed renderer")
    return manifest


def run_tool(argv: tuple[str, ...]) -> Result:
    return run(list(argv), timeout=30, max_output=65_536)


# launchctl's two statuses for a label that is not loaded in the named domain.
# The label preflight, every `bootout` and the wait after a `bootout` read
# "absent" this one way.
_JOB_ABSENT = frozenset({3, 113})


def _require_platform(scope: str, deployment: Deployment) -> int:
    if sys.platform != "darwin":
        raise DeploymentError("live installation requires macOS; bundle rendering is portable")
    uid = 0 if scope == "root" else deployment.user_uid
    if os.geteuid() != uid:
        raise DeploymentError("installation must run directly as its declared owner")
    if scope == "root":
        # The administrator invokes the trusted installed package, never a user venv.
        for value in (Path(sys.executable).resolve(), Path(__file__).resolve()):
            _check_tree(value.parent, 0)
            _protected_executable(value)
        for job in deployment.jobs:
            if job.scope == "root":
                if job.argv[1:5] != ("-I", "-m", "netorch.pf_owner", "reconcile"):
                    raise DeploymentError("root job must independently pull forwarding policy")
                _check_tree(Path(job.argv[0]).parent, 0)
                _protected_executable(Path(job.argv[0]))
                if Path(job.argv[0]).resolve() != Path(sys.executable).resolve():
                    raise DeploymentError(
                        "root scheduler must use this already trusted interpreter"
                    )
        if deployment.launchctl != "/bin/launchctl":
            raise DeploymentError("root installation uses the native launchctl only")
    return uid


def _protected_executable(path: Path) -> None:
    _privileged_acl(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise DeploymentError("privileged executable must be root-owned and protected")
    finally:
        os.close(descriptor)


def _owner_busy_retry(
    runner: ToolRunner, clock: Callable[[], float], sleep: Callable[[float], None]
) -> ToolRunner:
    """Repeat a forwarding-owner command that reports its lock busy, for a bounded time.

    Only the owner's own commands are repeated, and only on exit 75. Every
    other command and every other status passes through once, unchanged.
    """

    def repeated(argv: tuple[str, ...]) -> Result:
        result = runner(argv)
        if argv[1:4] != ("-I", "-m", "netorch.pf_owner"):
            return result
        deadline = clock() + OWNER_BUSY_WAIT_SECONDS
        while result.returncode == OWNER_BUSY and clock() < deadline:
            sleep(OWNER_BUSY_RETRY_SECONDS)
            result = runner(argv)
        return result

    return repeated


def _tool(runner: ToolRunner, argv: tuple[str, ...], *, absent_ok: bool = False) -> None:
    result = runner(argv)
    if result.returncode != 0 and not (absent_ok and result.returncode in _JOB_ABSENT):
        raise DeploymentError("managed tool operation failed; inspect installation journal")


# `launchctl bootout` can return before launchd has removed the job, and a
# `bootstrap` of the same label can fail until it has. A job that is about to be
# loaded again is therefore read after its `bootout` until launchd reports it
# absent: at most this long for one job, at this interval.
BOOTOUT_WAIT_SECONDS = 20.0
BOOTOUT_POLL_SECONDS = 0.25


def _bootout(
    runner: ToolRunner,
    launchctl: str,
    target: str,
    *,
    reloaded: bool,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
) -> None:
    """Unload one managed job; if its label is loaded again, let launchd finish first.

    The wait can only help. It ends with the first read that reports the job
    absent. When its time is used up the caller goes on exactly as it did before
    the wait existed, and the following `bootstrap` succeeds or fails by itself.
    """
    result = runner((launchctl, "bootout", target))
    if result.returncode in _JOB_ABSENT:
        return  # Nothing was loaded, so there is no removal to wait for.
    if result.returncode != 0:
        raise DeploymentError("managed tool operation failed; inspect installation journal")
    if not reloaded:
        return
    deadline = clock() + BOOTOUT_WAIT_SECONDS
    while not _removed(runner, (launchctl, "print", target)):
        if clock() >= deadline:
            return
        sleep(BOOTOUT_POLL_SECONDS)


def _removed(runner: ToolRunner, argv: tuple[str, ...]) -> bool:
    try:
        return runner(argv).returncode in _JOB_ABSENT
    except (OSError, ProcessError):
        # A read that could not complete proves nothing and fails nothing.
        return False


def plan_install(bundle: Path, scope: str) -> dict[str, Any]:
    manifest = validate_bundle(bundle)
    deployment = parse_deployment(canonical_bytes(manifest["deployment"]))
    installation = deployment.installation(scope)
    return {
        "scope": scope,
        "bundle_digest": manifest["bundle_digest"],
        "release_id": manifest["release_id"],
        "directory": installation.directory,
        "domain": installation.domain,
        "files": [
            item["path"] for item in manifest["files"] if item["path"].startswith(f"{scope}/")
        ],
        "jobs": [job.label for job in deployment.jobs if job.scope == scope],
        "preserves_intent": True,
        "container_recreation": False,
        "runtime_upgrade": False,
        "admission_changes": "none; changed policy remains pending",
    }


def _atomic_record(path: Path, payload: bytes, uid: int, *, privileged: bool = False) -> None:
    _check_tree(path.parent, uid, privileged=privileged)
    temporary = path.parent / f".{path.name}.netorch-new"
    if temporary.exists() or temporary.is_symlink():
        raise DeploymentError("unfinished file replacement needs inspection")
    if path.exists() or path.is_symlink():
        _read_file(path, privileged=privileged)
    _write_new(temporary, payload, privileged=privileged)
    _check_tree(path.parent, uid, privileged=privileged)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    if _read_file(path, private=True, privileged=privileged) != payload:
        raise DeploymentError("installed job differs from its reviewed bytes")


def _fence_job(installed: Path, payload: bytes, job: Job, uid: int) -> None:
    privileged = job.scope == "root"
    _check_tree(installed.parent, uid, privileged=privileged)
    if _read_file(installed, private=True, privileged=privileged) != payload:
        raise DeploymentError("job changed before native bootstrap")
    if privileged:
        directory = Path(job.log_directory)
        _check_tree(directory, uid, privileged=True)
        for suffix in ("out.log", "err.log"):
            path = directory / f"{job.label}.{suffix}"
            if not path.exists() and not path.is_symlink():
                continue
            _privileged_acl(path, content=False)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != uid
                    or info.st_nlink != 1
                    or info.st_mode & 0o022
                ):
                    raise DeploymentError("privileged launchd log target is unsafe")
                final = path.lstat()
                if _trust_metadata(info) != _trust_metadata(final):
                    raise DeploymentError("privileged launchd log target changed")
                _privileged_acl(path, content=False)
            finally:
                os.close(fd)


def _receipt(value: Any, scope: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "release_id",
            "bundle_digest",
            "scope",
            "jobs",
            "previous",
            "deployment",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["scope"] != scope
    ):
        raise DeploymentError("unsupported installation receipt")
    for field in ("release_id", "bundle_digest"):
        if not isinstance(value[field], str) or re.fullmatch(r"[0-9a-f]{64}", value[field]) is None:
            raise DeploymentError("invalid receipt identity")
    if not isinstance(value["jobs"], list) or len(value["jobs"]) > 32:
        raise DeploymentError("invalid receipt job inventory")
    for item in value["jobs"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"label", "sha256"}
            or not isinstance(item["label"], str)
            or re.fullmatch(r"[a-z][a-z0-9.-]{0,127}", item["label"]) is None
            or not isinstance(item["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
        ):
            raise DeploymentError("invalid receipt job record")
    parse_deployment(canonical_bytes(value["deployment"]))
    return value


def _verified_release(receipt: dict[str, Any], scope: str) -> tuple[Path, dict[str, bytes]]:
    deployment = parse_deployment(canonical_bytes(receipt["deployment"]))
    release = Path(deployment.installation(scope).directory) / "releases" / receipt["release_id"]
    metadata = strict_loads(
        _read_file(release / "bundle-manifest.json", private=True, privileged=scope == "root")
    )
    if (
        not isinstance(metadata, dict)
        or metadata.get("bundle_digest") != receipt["bundle_digest"]
        or digest({key: value for key, value in metadata.items() if key != "bundle_digest"})
        != receipt["bundle_digest"]
    ):
        raise DeploymentError("retained release manifest was modified")
    captured: dict[str, bytes] = {}
    for record in metadata["files"]:
        name = record["path"]
        if name.startswith(f"{scope}/"):
            relative = name.removeprefix(f"{scope}/")
            if PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts:
                raise DeploymentError("retained release escapes its boundary")
            payload = _read_file(release / relative, private=True, privileged=scope == "root")
            if _sha(payload) != record["sha256"]:
                raise DeploymentError("retained release file was modified")
            captured[relative] = payload
    return release, captured


def _root_command(
    deployment: Deployment, operation: str, holder: str | None = None
) -> tuple[str, ...]:
    job = next(item for item in deployment.jobs if item.scope == "root")
    argv = (
        job.argv[0],
        "-I",
        "-m",
        "netorch.pf_owner",
        operation,
        "--root-dir",
        deployment.forwarding.directory,
    )
    return argv if holder is None else (*argv, "--operation", "installation", "--holder", holder)


def _root_hold(deployment: Deployment, holder: str, runner: ToolRunner) -> bool:
    if not (Path(deployment.forwarding.directory) / "installation.json").exists():
        return False
    _tool(runner, _root_command(deployment, "suspend", holder))
    _tool(runner, _root_command(deployment, "withdraw", holder))
    return True


def _journal_fits(journal: dict[str, Any]) -> bool:
    """Whether the state store writes this installation journal in every form it takes."""
    try:
        widest = canonical_bytes({**journal, **_WIDEST_JOURNAL_PHASES})
    except CodecError:
        return False
    # The store writes the canonical form and one line end.
    return len(widest) < MAX_JSON_BYTES


def install_bundle(
    bundle: Path,
    scope: str,
    *,
    expected_digest: str,
    runner: ToolRunner = run_tool,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Install the explicitly named scope; an unexpected failure never auto-rolls back."""
    runner = _owner_busy_retry(runner, clock, sleep)
    manifest = validate_bundle(bundle, expected_digest)
    deployment = parse_deployment(canonical_bytes(manifest["deployment"]))
    uid = _require_platform(scope, deployment)
    # Capture again and bind every byte before creating files or stopping jobs.
    # A source swapped between initial validation and use is never promoted.
    captured: dict[str, bytes] = {}
    for record in manifest["files"]:
        payload = _read_file(bundle / record["path"], private=True, allow_other_owner=uid == 0)
        if _sha(payload) != record["sha256"]:
            raise DeploymentError("bundle changed between validation and installation")
        captured[record["path"]] = payload
    forwarding_settings = _forwarding_settings(deployment, captured)
    installation = deployment.installation(scope)
    target = Path(installation.directory)
    state_dir = Path(installation.state_directory)
    privileged = scope == "root"
    _check_tree(target, uid, create=True, privileged=privileged)
    _check_tree(state_dir, uid, create=True, privileged=privileged)
    _check_tree(Path(installation.launchd_directory), uid, create=True, privileged=privileged)
    store = _deployment_store(state_dir, scope)
    with store.lock():
        with contextlib.suppress(FileNotFoundError):
            previous_journal = store.read("installation-journal.json")
            if previous_journal.get("phase") not in {"committed", "rolled-back"}:
                raise DeploymentError("unfinished installation needs phase-aware recovery")
        previous: dict[str, Any] | None = None
        with contextlib.suppress(FileNotFoundError):
            previous = _receipt(store.read("installation-receipt.json"), scope)
        if previous is not None and previous.get("release_id") == manifest["release_id"]:
            _, unchanged_files = _verified_release(previous, scope)
            for item in previous["jobs"]:
                installed = Path(installation.launchd_directory) / f"{item['label']}.plist"
                if _sha(_read_file(installed, privileged=privileged)) != item["sha256"]:
                    raise DeploymentError("installed job changed since the matching release")
                job = next(job for job in deployment.jobs if job.label == item["label"])
                _fence_job(installed, unchanged_files[f"launchd/{job.label}.plist"], job, uid)
                _tool(
                    runner,
                    (deployment.launchctl, "print", f"{installation.domain}/{item['label']}"),
                )
            return {"phase": "unchanged", "release_id": manifest["release_id"]}
        # The journal keeps the receipt this installation replaces as it is now,
        # its own predecessor included: recovery writes exactly that back, so a
        # recovered release keeps the rollback target it had.
        replaced = previous
        if previous is not None:
            previous_deployment = parse_deployment(canonical_bytes(previous["deployment"]))
            if previous_deployment.installation(scope) != installation or (
                scope == "root"
                and previous_deployment.forwarding.directory != deployment.forwarding.directory
            ):
                raise DeploymentError(
                    "upgrade cannot change installation or forwarding ownership boundaries"
                )
            # A new receipt keeps one explicit predecessor, not an ever-growing
            # nested history.
            previous = {**previous, "previous": None}
        jobs = [job for job in deployment.jobs if job.scope == scope]
        old_jobs = [] if previous is None else previous["jobs"]
        labels = sorted({job.label for job in jobs} | {item["label"] for item in old_jobs})
        old_inventory = {} if previous is None else {item["label"]: item for item in old_jobs}
        for label in labels:
            installed = Path(installation.launchd_directory) / f"{label}.plist"
            if installed.exists() or installed.is_symlink():
                old_record = old_inventory.get(label)
                if (
                    old_record is None
                    or _sha(_read_file(installed, privileged=privileged)) != old_record["sha256"]
                ):
                    raise DeploymentError(
                        "existing launchd file is not an unchanged owned artifact"
                    )
        retained = target / "releases" / manifest["release_id"]
        if retained.exists() or retained.is_symlink():
            # A retained release is never overwritten. Refuse before the hold is
            # taken and a journal is opened, so that the refusal needs no recovery.
            raise DeploymentError("release already exists without matching committed receipt")
        journal: dict[str, Any] = {
            "schema_version": 1,
            "phase": "staging",
            "scope": scope,
            "release_id": manifest["release_id"],
            "bundle_digest": expected_digest,
            "previous": replaced,
            "deployment": deployment_to_dict(deployment),
        }
        if not _journal_fits(journal):
            # The journal holds this release's record, the replaced receipt and
            # that receipt's predecessor. Refuse like a retained release: before
            # the hold is taken and the journal is opened.
            raise DeploymentError("installation journal would exceed its size bound")
        if scope == "user":
            try:
                intent = intent_from_dict(store.read("intent.json"))
            except FileNotFoundError:
                intent = Intent().pause()
            if intent.damaged:
                raise DeploymentError("damaged intent must be inspected before installation")
            intent = intent.suspend("installation", manifest["bundle_digest"])
            store.write("intent.json", intent_to_dict(intent))
        store.write("installation-journal.json", journal)
        root_held = False
        try:
            release = target / "releases" / manifest["release_id"]
            _check_tree(release.parent, uid, create=True, privileged=privileged)
            if release.exists() or release.is_symlink():
                raise DeploymentError("release already exists without matching committed receipt")
            release.mkdir(mode=0o700)
            for record in manifest["files"]:
                name = record["path"]
                if name.startswith(f"{scope}/"):
                    _write_new(
                        release / name.removeprefix(f"{scope}/"),
                        captured[name],
                        privileged=privileged,
                    )
            _write_new(
                release / "bundle-manifest.json",
                canonical_bytes(manifest) + b"\n",
                privileged=privileged,
            )
            journal["phase"] = "preflight-jobs"
            store.write("installation-journal.json", journal)
            for label in labels:
                if label not in old_inventory:
                    result = runner(
                        (deployment.launchctl, "print", f"{installation.domain}/{label}")
                    )
                    if result.returncode not in _JOB_ABSENT:
                        raise DeploymentError(
                            "launchd label is present or unknown "
                            "without owned installation evidence"
                        )
            if scope == "root":
                journal["phase"] = "quiescing-forwarding-owner"
                store.write("installation-journal.json", journal)
                root_held = _root_hold(deployment, expected_digest, runner)
                _prepare_report_directory(Path(forwarding_settings.report_path).parent, uid)
                settings = next(
                    item
                    for item in deployment.artifacts
                    if item.id == deployment.forwarding.settings_artifact
                )
                root_job = next(job for job in deployment.jobs if job.scope == "root")
                _fence_files(
                    release,
                    {
                        name[5:]: payload
                        for name, payload in captured.items()
                        if name.startswith("root/")
                    },
                    privileged=True,
                )
                journal["phase"] = "installing-forwarding-owner"
                store.write("installation-journal.json", journal)
                _tool(
                    runner,
                    (
                        root_job.argv[0],
                        "-I",
                        "-m",
                        "netorch.pf_owner",
                        "install",
                        "--root-dir",
                        deployment.forwarding.directory,
                        "--policy",
                        str(release / "data/network.json"),
                        "--settings",
                        str(release / settings.destination),
                        "--backend",
                        str(release / "data/pf-backend.sh"),
                    ),
                )
                if not root_held:
                    root_held = _root_hold(deployment, expected_digest, runner)
            if scope == "user" and deployment.monitors:
                _tool(runner, (deployment.monit, "-t", "-c", str(release / "monit/monitrc")))
            journal["phase"] = "stopping-jobs"
            store.write("installation-journal.json", journal)
            for label in labels:
                _bootout(
                    runner,
                    deployment.launchctl,
                    f"{installation.domain}/{label}",
                    reloaded=any(job.label == label for job in jobs),
                    clock=clock,
                    sleep=sleep,
                )
            journal["phase"] = "installing-jobs"
            store.write("installation-journal.json", journal)
            installed_jobs: list[dict[str, Any]] = []
            for job in jobs:
                _check_tree(Path(job.log_directory), uid, create=True, privileged=privileged)
                payload = _read_file(
                    release / "launchd" / f"{job.label}.plist", private=True, privileged=privileged
                )
                installed = Path(installation.launchd_directory) / f"{job.label}.plist"
                _atomic_record(installed, payload, uid, privileged=privileged)
                installed_jobs.append({"label": job.label, "sha256": _sha(payload)})
            new_labels = {job.label for job in jobs}
            for label in set(old_inventory) - new_labels:
                (Path(installation.launchd_directory) / f"{label}.plist").unlink()
            journal["phase"] = "starting-jobs"
            store.write("installation-journal.json", journal)
            for job in jobs:
                installed = Path(installation.launchd_directory) / f"{job.label}.plist"
                _fence_job(installed, captured[f"{scope}/launchd/{job.label}.plist"], job, uid)
                _tool(
                    runner, (deployment.launchctl, "bootstrap", installation.domain, str(installed))
                )
                _tool(runner, (deployment.launchctl, "print", f"{installation.domain}/{job.label}"))
            receipt = {
                "schema_version": 1,
                "release_id": manifest["release_id"],
                "bundle_digest": expected_digest,
                "scope": scope,
                "jobs": installed_jobs,
                "previous": previous,
                "deployment": deployment_to_dict(deployment),
            }
            store.write("installation-receipt.json", receipt)
            if scope == "user":
                current = intent_from_dict(store.read("intent.json"))
                store.write(
                    "intent.json", intent_to_dict(current.release("installation", expected_digest))
                )
            elif root_held:
                _tool(runner, _root_command(deployment, "release", expected_digest))
            journal["phase"] = "committed"
            store.write("installation-journal.json", journal)
            return {
                "phase": "committed",
                "release_id": manifest["release_id"],
                "bundle_digest": expected_digest,
                "jobs_loaded": [job.label for job in jobs],
                "runtime_acceptance": "not established by installation",
            }
        except BaseException:
            # An interrupt is a failure too: record the phase it stopped in.
            journal["failed_phase"] = journal["phase"]
            journal["phase"] = "failed"
            store.write("installation-journal.json", journal)
            raise


def prepare_root_bundle(bundle: Path, output: Path) -> dict[str, Any]:
    """Copy the captured root scope, without executing an installer or escalating."""
    manifest = validate_bundle(bundle)
    if output.exists() or output.is_symlink():
        raise DeploymentError("prepared bundle output already exists")
    _check_tree(output.parent, os.geteuid())
    output.mkdir(mode=0o700)
    # Preserve the entire signed inventory so an administrator verifies the exact
    # same bundle, rather than implicitly admitting a different filtered document.
    for record in manifest["files"]:
        _write_new(output / record["path"], _read_file(bundle / record["path"], private=True))
    _write_new(output / "manifest.json", canonical_bytes(manifest) + b"\n")
    return {
        "bundle": str(output),
        "expected_digest": manifest["bundle_digest"],
        "command": (
            "Invoke root-owned netorch deploy install-root with this digest locally; "
            "no root process was started"
        ),
    }


def rollback_install(
    directory: Path,
    scope: str,
    *,
    expected_current_digest: str,
    runner: ToolRunner = run_tool,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Explicit reversal of a committed file/job release; preserve current intent.

    A rollback that failed or was stopped is repeated with the same digest. Any
    other unfinished journal belongs to `recover` and is left untouched.
    """
    runner = _owner_busy_retry(runner, clock, sleep)
    store = _deployment_store(directory, scope)
    with store.lock():
        unfinished: Any = None
        with contextlib.suppress(FileNotFoundError):
            unfinished = store.read("installation-journal.json")
        resumed = _resumable_rollback(unfinished, scope, expected_current_digest)
        if (
            unfinished is not None
            and not resumed
            and not (
                isinstance(unfinished, dict)
                and unfinished.get("phase") in {"committed", "rolled-back"}
            )
        ):
            # The rule install_bundle applies: never write over an open journal.
            raise DeploymentError("unfinished installation needs phase-aware recovery")
        receipt = _receipt(store.read("installation-receipt.json"), scope)
        if resumed and receipt["bundle_digest"] == unfinished.get("to_bundle_digest"):
            return _finish_rollback(store, scope, unfinished, receipt, runner)
        if receipt["scope"] != scope or receipt["bundle_digest"] != expected_current_digest:
            raise DeploymentError("rollback does not match the current installed release")
        previous = receipt.get("previous")
        if previous is None:
            raise DeploymentError("first installation has no prior release to restore")
        previous = _receipt(previous, scope)
        if resumed and previous["bundle_digest"] != unfinished.get("to_bundle_digest"):
            raise DeploymentError("unfinished installation needs phase-aware recovery")
        deployment = parse_deployment(canonical_bytes(receipt["deployment"]))
        uid = _require_platform(scope, deployment)
        old_deployment = parse_deployment(canonical_bytes(previous["deployment"]))
        # A retained receipt proves past completion, not current executable
        # trust. Validate the restored scheduler before any transition effect,
        # just as failed-install recovery validates its predecessor.
        _require_platform(scope, old_deployment)
        installation = deployment.installation(scope)
        old_installation = old_deployment.installation(scope)
        if installation != old_installation or (
            scope == "root"
            and deployment.forwarding.directory != old_deployment.forwarding.directory
        ):
            raise DeploymentError("rollback cannot change installation boundaries")
        privileged = scope == "root"
        _check_tree(Path(installation.directory), uid, privileged=privileged)
        _check_tree(Path(installation.launchd_directory), uid, privileged=privileged)
        release, old_files = _verified_release(previous, scope)
        for record in previous["jobs"]:
            if (
                _sha(
                    _read_file(
                        release / "launchd" / f"{record['label']}.plist",
                        private=True,
                        privileged=privileged,
                    )
                )
                != record["sha256"]
            ):
                raise DeploymentError("previous release was modified; rollback unavailable")
        if scope == "user":
            intent = intent_from_dict(store.read("intent.json"))
            if intent.damaged:
                raise DeploymentError("rollback requires readable durable intent")
            store.write(
                "intent.json",
                intent_to_dict(intent.suspend("installation", expected_current_digest)),
            )
        journal: dict[str, Any] = {
            "schema_version": 1,
            "phase": "rolling-back",
            "scope": scope,
            "from": receipt["release_id"],
            "to": previous["release_id"],
            "from_bundle_digest": receipt["bundle_digest"],
            "to_bundle_digest": previous["bundle_digest"],
        }
        store.write("installation-journal.json", journal)
        root_held = False
        try:
            if scope == "root":
                root_held = _root_hold(deployment, expected_current_digest, runner)
            old_hashes = {item["label"]: item["sha256"] for item in previous["jobs"]}
            old_labels = set(old_hashes)
            for record in receipt["jobs"]:
                installed = Path(installation.launchd_directory) / f"{record['label']}.plist"
                accepted = {record["sha256"]}
                removed = False
                if resumed:
                    # The earlier attempt may already have restored this job, or
                    # removed one the predecessor does not have.
                    accepted.add(old_hashes.get(record["label"], record["sha256"]))
                    removed = record["label"] not in old_labels and not (
                        installed.exists() or installed.is_symlink()
                    )
                if (
                    not removed
                    and _sha(_read_file(installed, privileged=privileged)) not in accepted
                ):
                    raise DeploymentError("current managed file changed; inspect before rollback")
                _bootout(
                    runner,
                    deployment.launchctl,
                    f"{installation.domain}/{record['label']}",
                    reloaded=any(item["label"] == record["label"] for item in previous["jobs"]),
                    clock=clock,
                    sleep=sleep,
                )
            if resumed:
                # A job only the predecessor has may have been loaded again already.
                for label in sorted(old_labels - {record["label"] for record in receipt["jobs"]}):
                    _bootout(
                        runner,
                        deployment.launchctl,
                        f"{installation.domain}/{label}",
                        reloaded=True,
                        clock=clock,
                        sleep=sleep,
                    )
            if scope == "root":
                settings = next(
                    item
                    for item in old_deployment.artifacts
                    if item.id == old_deployment.forwarding.settings_artifact
                )
                root_job = next(job for job in old_deployment.jobs if job.scope == "root")
                _fence_files(release, old_files, privileged=True)
                _tool(
                    runner,
                    (
                        root_job.argv[0],
                        "-I",
                        "-m",
                        "netorch.pf_owner",
                        "install",
                        "--root-dir",
                        old_deployment.forwarding.directory,
                        "--policy",
                        str(release / "data/network.json"),
                        "--settings",
                        str(release / settings.destination),
                        "--backend",
                        str(release / "data/pf-backend.sh"),
                    ),
                )
            for record in receipt["jobs"]:
                if record["label"] not in old_labels:
                    (Path(installation.launchd_directory) / f"{record['label']}.plist").unlink(
                        missing_ok=True
                    )
            for record in previous["jobs"]:
                installed = Path(installation.launchd_directory) / f"{record['label']}.plist"
                _atomic_record(
                    installed,
                    old_files[f"launchd/{record['label']}.plist"],
                    uid,
                    privileged=privileged,
                )
                job = next(job for job in old_deployment.jobs if job.label == record["label"])
                _fence_job(installed, old_files[f"launchd/{record['label']}.plist"], job, uid)
                _tool(
                    runner,
                    (old_deployment.launchctl, "bootstrap", installation.domain, str(installed)),
                )
                _tool(
                    runner,
                    (old_deployment.launchctl, "print", f"{installation.domain}/{record['label']}"),
                )
            store.write("installation-receipt.json", previous)
            if scope == "user":
                current = intent_from_dict(store.read("intent.json"))
                store.write(
                    "intent.json",
                    intent_to_dict(current.release("installation", expected_current_digest)),
                )
            elif root_held:
                _tool(runner, _root_command(deployment, "release", expected_current_digest))
            journal["phase"] = "rolled-back"
            store.write("installation-journal.json", journal)
            return {
                "phase": "rolled-back",
                "release_id": previous["release_id"],
                "preserved_intent": True,
            }
        except BaseException:
            # An interrupt is a failure too; the journal names the exact pair, so
            # the same rollback can be repeated.
            journal["failed_phase"] = journal["phase"]
            journal["phase"] = "failed"
            store.write("installation-journal.json", journal)
            raise


def _resumable_rollback(journal: Any, scope: str, current_digest: str) -> bool:
    """A rollback of exactly this release that failed, or stopped without recording it.

    The second case is sound because the journal is read under the lock every
    rollback holds for its whole run: whoever left the open phase is gone.
    """
    return (
        isinstance(journal, dict)
        and (
            journal.get("phase") == "rolling-back"
            or (journal.get("phase") == "failed" and journal.get("failed_phase") == "rolling-back")
        )
        and journal.get("scope") == scope
        and journal.get("from_bundle_digest") == current_digest
    )


def _finish_rollback(
    store: Store, scope: str, journal: dict[str, Any], receipt: dict[str, Any], runner: ToolRunner
) -> dict[str, Any]:
    """Close a rollback that stopped after it had restored the predecessor's receipt.

    The receipt is written only after every restored job was loaded and read
    back. What can be missing is the release of this rollback's own hold and
    the closing journal entry.
    """
    if receipt["release_id"] != journal.get("to"):
        raise DeploymentError("unfinished installation needs phase-aware recovery")
    holder = journal["from_bundle_digest"]
    deployment = parse_deployment(canonical_bytes(receipt["deployment"]))
    _require_platform(scope, deployment)
    if scope == "user":
        intent = intent_from_dict(store.read("intent.json"))
        if intent.damaged:
            raise DeploymentError("rollback requires readable durable intent")
        if intent.suspensions.get("installation") == holder:
            store.write("intent.json", intent_to_dict(intent.release("installation", holder)))
    elif (Path(deployment.forwarding.directory) / "installation.json").exists():
        owner_intent = intent_from_dict(
            _deployment_store(Path(deployment.forwarding.directory), "root").read(
                "operator-intent.json"
            )
        )
        if owner_intent.suspensions.get("installation") == holder:
            _tool(runner, _root_command(deployment, "release", holder))
    store.write("installation-journal.json", {**journal, "phase": "rolled-back"})
    return {
        "phase": "rolled-back",
        "release_id": receipt["release_id"],
        "preserved_intent": True,
    }


def recover_install(
    directory: Path,
    scope: str,
    *,
    expected_failed_digest: str,
    runner: ToolRunner = run_tool,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Recover an inspected failed upgrade, without replaying the failed operation.

    A failed first install retains its gated root snapshot and private release as
    evidence, removes only verified generated user jobs, and never deletes data.
    The next install must use a new bundle/release or explicit evidence cleanup.

    "Failed" includes an installation or recovery that was stopped: its journal
    is then still in an in-progress phase, or was never written.
    """
    runner = _owner_busy_retry(runner, clock, sleep)
    store = _deployment_store(directory, scope)
    with store.lock():
        try:
            journal = store.read("installation-journal.json")
        except FileNotFoundError:
            journal = None
        if journal is None or (
            isinstance(journal, dict) and journal.get("phase") in {"committed", "rolled-back"}
        ):
            return _release_unjournalled_hold(store, scope, expected_failed_digest)
        if (
            not isinstance(journal, dict)
            or journal.get("phase") not in {"failed", "recovering", *_OPEN_INSTALL_PHASES}
            or journal.get("bundle_digest") != expected_failed_digest
            or journal.get("scope") != scope
        ):
            raise DeploymentError("recovery does not match a failed installation journal")
        if journal["phase"] in _OPEN_INSTALL_PHASES:
            # The installer holds this same lock from its first read to its last
            # write, so an open phase read under it was left by an installer that
            # is gone. The phase it stopped in is the failed phase.
            journal["failed_phase"] = journal["phase"]
        release_id = journal.get("release_id")
        if not isinstance(release_id, str) or re.fullmatch(r"[0-9a-f]{64}", release_id) is None:
            raise DeploymentError("failed journal lacks a valid release identity")
        previous = journal.get("previous")
        if previous is None:
            return _recover_first(store, journal, scope, expected_failed_digest, runner)
        previous = _receipt(previous, scope)
        deployment = parse_deployment(canonical_bytes(previous["deployment"]))
        uid = _require_platform(scope, deployment)
        installation = deployment.installation(scope)
        privileged = scope == "root"
        _check_tree(Path(installation.directory), uid, privileged=privileged)
        _check_tree(Path(installation.launchd_directory), uid, privileged=privileged)
        release, old_files = _verified_release(previous, scope)
        failed_release = Path(installation.directory) / "releases" / release_id
        failed_manifest: Any
        if journal.get("failed_phase") == "staging":
            # Staging writes only the new release, which may be incomplete: it is
            # no evidence yet and none of its jobs can be installed. The journal's
            # own deployment record gives the boundaries to compare.
            failed_manifest = {"deployment": journal.get("deployment"), "files": []}
        else:
            failed_manifest = strict_loads(
                _read_file(
                    failed_release / "bundle-manifest.json", private=True, privileged=privileged
                )
            )
            if (
                failed_manifest.get("bundle_digest") != expected_failed_digest
                or digest(
                    {key: value for key, value in failed_manifest.items() if key != "bundle_digest"}
                )
                != expected_failed_digest
            ):
                raise DeploymentError("failed release manifest changed; no speculative recovery")
        failed_deployment = parse_deployment(canonical_bytes(failed_manifest["deployment"]))
        if failed_deployment.installation(scope) != installation:
            raise DeploymentError("recovery cannot change installation boundaries")
        if (
            scope == "root"
            and failed_deployment.forwarding.directory != deployment.forwarding.directory
        ):
            raise DeploymentError("recovery cannot change forwarding ownership boundaries")
        old_labels = {item["label"] for item in previous["jobs"]}
        old_hashes = {item["label"]: item["sha256"] for item in previous["jobs"]}
        failed_hashes = {
            PurePosixPath(item["path"]).stem: item["sha256"]
            for item in failed_manifest["files"]
            if item["path"].startswith(f"{scope}/launchd/")
        }
        labels = sorted(old_labels | set(failed_hashes))
        for label in labels:
            installed = Path(installation.launchd_directory) / f"{label}.plist"
            if (installed.exists() or installed.is_symlink()) and _sha(
                _read_file(installed, privileged=privileged)
            ) not in {
                old_hashes.get(label),
                failed_hashes.get(label),
            }:
                raise DeploymentError("failed-install job has foreign content; recovery inhibited")
        if scope == "user":
            intent = intent_from_dict(store.read("intent.json"))
            held = intent.suspensions.get("installation")
            if intent.damaged or held not in {None, expected_failed_digest}:
                raise DeploymentError("recovery requires the original installation suspension")
            if held is None:
                _retake_hold(store, intent, expected_failed_digest)
        journal["phase"] = "recovering"
        store.write("installation-journal.json", journal)
        root_held = False
        try:
            if scope == "root":
                root_held = _root_hold(deployment, expected_failed_digest, runner)
            for label in labels:
                _bootout(
                    runner,
                    deployment.launchctl,
                    f"{installation.domain}/{label}",
                    reloaded=label in old_labels,
                    clock=clock,
                    sleep=sleep,
                )
            if scope == "root":
                settings = next(
                    item
                    for item in deployment.artifacts
                    if item.id == deployment.forwarding.settings_artifact
                )
                root_job = next(job for job in deployment.jobs if job.scope == "root")
                _fence_files(release, old_files, privileged=True)
                _tool(
                    runner,
                    (
                        root_job.argv[0],
                        "-I",
                        "-m",
                        "netorch.pf_owner",
                        "install",
                        "--root-dir",
                        deployment.forwarding.directory,
                        "--policy",
                        str(release / "data/network.json"),
                        "--settings",
                        str(release / settings.destination),
                        "--backend",
                        str(release / "data/pf-backend.sh"),
                    ),
                )
            for label in set(failed_hashes) - old_labels:
                installed = Path(installation.launchd_directory) / f"{label}.plist"
                if installed.exists():
                    installed.unlink()
            for label in old_labels:
                installed = Path(installation.launchd_directory) / f"{label}.plist"
                _atomic_record(
                    installed, old_files[f"launchd/{label}.plist"], uid, privileged=privileged
                )
                job = next(job for job in deployment.jobs if job.label == label)
                _fence_job(installed, old_files[f"launchd/{label}.plist"], job, uid)
                _tool(
                    runner, (deployment.launchctl, "bootstrap", installation.domain, str(installed))
                )
                _tool(runner, (deployment.launchctl, "print", f"{installation.domain}/{label}"))
            # The receipt as the failed installation found it. A journal of a
            # release that did not yet keep it whole names no predecessor in it.
            store.write("installation-receipt.json", previous)
            if scope == "user":
                current = intent_from_dict(store.read("intent.json"))
                store.write(
                    "intent.json",
                    intent_to_dict(current.release("installation", expected_failed_digest)),
                )
            elif root_held:
                _tool(runner, _root_command(deployment, "release", expected_failed_digest))
            journal["phase"] = "rolled-back"
            store.write("installation-journal.json", journal)
            return {
                "phase": "rolled-back",
                "release_id": previous["release_id"],
                "retained_failed_release": release_id,
                "preserved_intent": True,
            }
        except BaseException:
            journal["phase"] = "failed"
            store.write("installation-journal.json", journal)
            raise


def _release_unjournalled_hold(store: Store, scope: str, holder: str) -> dict[str, Any]:
    """Release a user hold whose installer stopped before its first journal write.

    The user installer writes its suspension, then its journal, then everything
    else, and closes the journal only after releasing the suspension. With no
    journal, or only a closed one, a hold by exactly this digest therefore
    proves that nothing else of that installation exists.
    """
    intent = Intent(damaged=True)
    if scope == "user":
        with contextlib.suppress(FileNotFoundError):
            intent = intent_from_dict(store.read("intent.json"))
    if intent.damaged or intent.suspensions.get("installation") != holder:
        raise DeploymentError("recovery does not match a failed installation journal")
    store.write("intent.json", intent_to_dict(intent.release("installation", holder)))
    return {
        "phase": "hold-released",
        "installation_changes": "none; the installer stopped before its first journal write",
        "preserved_intent": True,
    }


def _retake_hold(store: Store, intent: Intent, holder: str) -> None:
    """Recovery works under the failed installation's own hold, as root does via its owner.

    The installer releases that hold one write before it closes its journal. A
    kill between the two leaves an open journal and no holder at all.
    """
    store.write("intent.json", intent_to_dict(intent.suspend("installation", holder)))


def _recover_first(
    store: Store,
    journal: dict[str, Any],
    scope: str,
    failed_digest: str,
    runner: ToolRunner,
) -> dict[str, Any]:
    deployment = parse_deployment(canonical_bytes(journal["deployment"]))
    uid = _require_platform(scope, deployment)
    installation = deployment.installation(scope)
    release = Path(installation.directory) / "releases" / journal["release_id"]
    privileged = scope == "root"
    _check_tree(Path(installation.directory), uid, privileged=privileged)
    _check_tree(Path(installation.launchd_directory), uid, privileged=privileged)
    expected: dict[str, bytes] = {}
    if journal.get("failed_phase") not in {"staging", "preflight-jobs"}:
        metadata = strict_loads(
            _read_file(release / "bundle-manifest.json", private=True, privileged=privileged)
        )
        if (
            metadata["bundle_digest"] != failed_digest
            or digest({key: value for key, value in metadata.items() if key != "bundle_digest"})
            != failed_digest
        ):
            raise DeploymentError("failed first-release evidence was modified")
        for job in deployment.jobs:
            if job.scope == scope:
                payload = _read_file(
                    release / "launchd" / f"{job.label}.plist", private=True, privileged=privileged
                )
                expected[job.label] = payload
                installed = Path(installation.launchd_directory) / f"{job.label}.plist"
                if (installed.exists() or installed.is_symlink()) and _read_file(
                    installed,
                    privileged=privileged,
                ) != payload:
                    raise DeploymentError("failed first-install job has foreign content")
    if scope == "user":
        intent = intent_from_dict(store.read("intent.json"))
        held = intent.suspensions.get("installation")
        if intent.damaged or held not in {None, failed_digest}:
            raise DeploymentError("first-install recovery requires its original suspension")
        if held is None:
            _retake_hold(store, intent, failed_digest)
    journal["phase"] = "recovering"
    store.write("installation-journal.json", journal)
    root_held = False
    root_gate_retained = False
    try:
        if scope == "root":
            root_held = _root_hold(deployment, failed_digest, runner)
        for label in expected:
            _tool(
                runner,
                (deployment.launchctl, "bootout", f"{installation.domain}/{label}"),
                absent_ok=True,
            )
            installed = Path(installation.launchd_directory) / f"{label}.plist"
            if installed.exists():
                installed.unlink()
        # A receipt can have been written immediately before a failed intent
        # write. Remove only a receipt belonging to this exact failed bundle.
        with contextlib.suppress(FileNotFoundError):
            receipt = _receipt(store.read("installation-receipt.json"), scope)
            if receipt["bundle_digest"] != failed_digest:
                raise DeploymentError("first-install recovery found an unrelated receipt")
            (store.directory / "installation-receipt.json").unlink()
        if scope == "user":
            current = intent_from_dict(store.read("intent.json"))
            store.write(
                "intent.json", intent_to_dict(current.release("installation", failed_digest))
            )
        elif root_held:
            root_intent = intent_from_dict(
                _deployment_store(Path(deployment.forwarding.directory), "root").read(
                    "operator-intent.json"
                )
            )
            if root_intent.damaged or not root_intent.operator_paused:
                # No predecessor means no verified scheduler to restore. Keep
                # the operation gate if no independent operator pause protects
                # this pre-existing owner from reapplying after retirement.
                root_gate_retained = True
            else:
                _tool(runner, _root_command(deployment, "release", failed_digest))
        journal["phase"] = "rolled-back"
        store.write("installation-journal.json", journal)
        return {
            "phase": "rolled-back",
            "retained_failed_release": journal["release_id"],
            "preserved_intent": True,
            "root_gate_retained": root_gate_retained,
            "root_owner": "retained with existing admission and operator intent unchanged",
        }
    except BaseException:
        journal["phase"] = "failed"
        store.write("installation-journal.json", journal)
        raise

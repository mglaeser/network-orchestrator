"""The supervisor may start the vendor runtime itself, where the settings opt in.

Without `fleet_start.runtime_start` nothing changes. With it there are two
commands. `runtime-probe` answers 0 for the declared running API job, 42 where a
start is permitted and 69 otherwise. `runtime-start` runs the vendor's own start
command once, and only where three things hold: the reviewed launch file is
already exactly what that command writes for the declared roots, both roots are
given to the call, and the service manager itself says the job is not loaded.

Everything native is faked. The fake `system start` does what the vendor's
source does with its options and environment (apple/container `SystemStart.run`,
the same at tags 1.2.0, 1.4.1 and 1.5.0): it copies the account's configuration
file, if there is one, writes the launch file anew and loads the job from it.
The last tests are contract checks of the real service manager and of `plutil`;
they run only on a hosted macOS runner.
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch import apple_runtime as runtime
from netorch import process
from netorch.codec import canonical_bytes, digest, strict_loads
from netorch.config import load_config, to_dict
from netorch.deployment_config import (
    DeploymentError,
    deployment_to_dict,
    load_deployment,
    parse_deployment,
)
from netorch.process import ProcessTimeout, Result
from netorch.runtime_settings import RuntimeAccount, parse_settings, settings_to_dict
from netorch.state import Intent, intent_to_dict
from netorch.storage import Busy, Store
from netorch.workflow_gate import NOT_QUALIFIED
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_monit_recovery_repeat import DIGEST_BEFORE, MONITRC_BEFORE, RELEASE, fixed
from tests.test_runtime_settings import authored

__all__ = ["enrolled"]

ROOT = Path(__file__).resolve().parents[1]
# The vendor's own public names, as its start command writes them.
LABEL = "com.apple.container.apiserver"
PREFIX = "com.apple.container."
APP, INSTALL = "CONTAINER_APP_ROOT", "CONTAINER_INSTALL_ROOT"
STARTED = "Mon Oct  5 08:00:00 2026"
FLEET_ONLY = {
    "api_label": LABEL,
    "api_executable": "/opt/example/libexec/container-apiserver",
    "runtime_label_prefix": PREFIX,
}
ROOTS = {"app_root": "/opt/example/application data", "install_root": "/opt/example"}
# Taken from the tree before the declaration existed: the same inputs must keep them.
AUTHORED_SETTINGS_DIGEST = "6dd79016779aa6e1ef2a82ce99dd40e315faffbd13cb71c1f65ae2df72d1bde9"
FLEET_ONLY_SETTINGS_DIGEST = "caa7735c69a9fc662b7d0a2bc1d7e1f3f8d7de28290de562be4e284fd9fcb224"
EXAMPLE_MANIFEST_DIGEST = "9908b141addbe7f3b1a3f7b6190b3af5caa4cb70e2e81e92bdd9b4551ef5c1bb"
EXAMPLE_RELEASE_ID = "bc62f8f981f9ce4e8024f3c5099ac381f85c32f41d1742936c10d29d761e7269"
EXAMPLE_MONITRC_SHA256 = "149de03a391f6a39524ee720d8bba5c014bc1dc0099f74934f582e59723b4c18"
NOT_LOADED = Result(113, b"", b"Bad request.\nCould not find service\n")
DISABLED_LIST = (
    b"disabled services = {\n"
    b'\t"com.apple.example-one" => disabled\n'
    b'\t"com.apple.example-two" => enabled\n'
    b"}\n"
    b"login item associations = {\n"
    b"}\n"
)
REFUSED = (ValueError, OSError, runtime.RuntimeReadError, ProcessTimeout)


@pytest.fixture(autouse=True)
def only_the_enrolled_home(monkeypatch: Any) -> None:
    """The user database of the machine that runs the tests is no part of them."""
    monkeypatch.setattr(runtime, "_listed_home", lambda _uid: None, raising=False)


def job_print(domain: str, job: dict[str, Any]) -> bytes:
    """A synthetic service print in the shape the reader assumes; no capture backs it."""
    lines = [
        f"{domain}/{LABEL} = {{",
        "\tactive count = 1",
        f"\tpath = {job['path']}",
        "\ttype = LaunchAgent",
        f"\tstate = {job['state']}",
        "",
        f"\tprogram = {job['program']}",
        "\targuments = {",
        *[f"\t\t{argument}" for argument in job["arguments"]],
        "\t}",
        "",
        "\tdefault environment = {",
        "\t\tPATH => /usr/bin:/bin:/usr/sbin:/sbin",
        "\t}",
        "",
        "\tenvironment = {",
        *[f"\t\t{name} => {value}" for name, value in job["environment"].items()],
        f"\t\tXPC_SERVICE_NAME => {LABEL}",
        "\t}",
        "",
        f"\tdomain = {domain} [100003]",
        "\truns = 1",
        *([] if job["pid"] is None else [f"\tpid = {job['pid']}"]),
        "",
        "\tendpoints = {",
        f'\t\t"{LABEL}" = {{',
        "\t\t\tport = 0x1b03",
        "\t\t\tactive = 1",
        "\t\t}",
        "\t}",
        "}",
    ]
    return ("\n".join(lines) + "\n").encode()


def lock_is_held(settings: Any) -> bool:
    try:
        with Store(Path(settings.state_dir)).lock():
            return False
    except Busy:
        return True


def declared_job(world: World, **changes: Any) -> dict[str, Any]:
    """The job as the vendor's start command loads it for the declared roots."""
    return {
        "path": str(world.launch),
        "program": str(world.program),
        "arguments": [str(world.program), "start"],
        "environment": {APP: str(world.app), INSTALL: str(world.install)},
        "state": "running",
        "pid": 222,
        **changes,
    }


IDLE = {"state": "not running", "pid": None}


class VendorRunner(FakeRunner):
    """The shared fake, the service manager's view of the API job and the vendor's two commands."""

    def __init__(self, world: World, items: dict[str, Any]) -> None:
        super().__init__(world.settings, items)
        self.world = world
        uid = world.settings.account.uid
        self.gui, self.user = f"gui/{uid}", f"user/{uid}"
        self.job: dict[str, Any] | None = None
        self.job_answer: Result | None = None
        self.other_domain = NOT_LOADED
        self.domain = Result(0, f"{self.gui} = {{\n\tservices = {{\n\t}}\n}}\n".encode(), b"")
        self.session = Result(0, b"Aqua\n", b"")
        self.disabled = Result(0, DISABLED_LIST, b"")
        self.version: bytes | None = None
        self.start_answer = Result(0, b"", b"Launching container-apiserver...\n")
        self.after_start: Callable[[], None] | None = None
        self.lock_held: list[bool] = []

    def load(self, **changes: Any) -> None:
        self.job = declared_job(self.world, **changes)

    def __call__(self, argv: list[str], **kwargs: Any) -> Result:
        if argv[0] == "/bin/launchctl":
            self.calls.append((argv, kwargs))
            assert set(kwargs) == {"timeout", "max_output"} and 0 < kwargs["timeout"] <= 3
            if argv[1:] == ["print", f"{self.gui}/{LABEL}"]:
                if self.job_answer is not None:
                    return self.job_answer
                return (
                    NOT_LOADED
                    if self.job is None
                    else Result(0, job_print(self.gui, self.job), b"")
                )
            if argv[1:] == ["print", f"{self.user}/{LABEL}"]:
                return self.other_domain
            if argv[1:] == ["print", self.gui]:
                # The listing of a whole domain is long; only this read may take that much.
                assert kwargs["max_output"] == 4_194_304
                return self.domain
            if argv[1:] == ["managername"]:
                return self.session
            if argv[1:] == ["print-disabled", self.gui]:
                return self.disabled
            raise AssertionError(argv)
        if argv[0] == "/bin/ps" and self.job is not None and argv[2] == str(self.job["pid"]):
            self.calls.append((argv, kwargs))
            line = f"{self.settings.account.uid} {STARTED} {self.job['program']}\n"
            return Result(0, line.encode(), b"")
        if argv[0] == self.settings.executable and argv[1:] == ["--version"] and self.version:
            self.calls.append((argv, kwargs))
            return Result(0, self.version, b"")
        if argv[0] == self.settings.executable and argv[1:2] == ["system"]:
            self.calls.append((argv, kwargs))
            return self.system(argv, kwargs)
        return super().__call__(argv, **kwargs)

    def system(self, argv: list[str], kwargs: dict[str, Any]) -> Result:
        account = self.settings.account
        assert (kwargs["run_uid"], kwargs["run_gid"]) == (account.uid, account.gid)
        assert kwargs["account_home"] == account.home
        self.lock_held.append(lock_is_held(self.settings))
        if argv[2:] == ["status"]:
            if self.job is None:
                return Result(1, b"apiserver is not running and not registered with launchd\n", b"")
            # The service manager runs a loaded job on the first request to its service.
            self.job.update(state="running", pid=222)
            return Result(0, b"FIELD   VALUE\nstatus  running\n", b"")
        assert argv[2] == "start" and argv[7:] == ["--disable-kernel-install"], argv
        options = dict(zip(argv[3:7:2], argv[4:7:2], strict=True))
        # `ConfigurationLoader.copyConfigurationToReadOnly`, the command's first step: the
        # account's own file, if there is one, replaces the copy below the application root.
        own = Path(kwargs["account_home"]) / ".config/container/config.toml"
        if own.exists():
            copy = Path(options["--app-root"]) / "config/config.toml"
            copy.parent.mkdir(exist_ok=True)
            copy.write_bytes(own.read_bytes())
        # `PluginLoader.filterEnvironment`, then both roots from the options.
        environment = {
            name: value
            for name, value in kwargs["environment"].items()
            if name.startswith("CONTAINER_")
        }
        environment.update({APP: options["--app-root"], INSTALL: options["--install-root"]})
        program = os.path.realpath(Path(argv[0]).with_name("container-apiserver"))
        launch = Path(options["--app-root"]) / "apiserver/apiserver.plist"
        # Written in place, as the vendor's `Data.write(to:)` does.
        launch.write_bytes(
            plistlib.dumps(
                {
                    "Label": LABEL,
                    "ProgramArguments": [program, "start"],
                    "EnvironmentVariables": environment,
                    "LimitLoadToSessionType": ["Aqua", "Background", "System"],
                    "RunAtLoad": True,
                    "MachServices": {LABEL: True},
                }
            )
        )
        self.load(
            path=str(launch),
            program=program,
            arguments=[program, "start"],
            environment=environment,
        )
        if self.after_start is not None:
            self.after_start()
        return self.start_answer


class World:
    """One enrolled account with a vendor installation, its launch file and a fake manager."""

    def __init__(self, enrolled: Any, tmp_path: Path, **start: Any) -> None:
        _config, settings, items = enrolled
        base = (tmp_path / "vendor").resolve()
        # A space in the application root, as in the vendor's own default.
        self.install, self.app = base / "install", base / "application data"
        for directory in (self.install / "bin", self.install / "libexec", self.app / "apiserver"):
            directory.mkdir(parents=True)
        for directory in (base, self.install, self.app, *base.glob("*/*")):
            directory.chmod(0o755)
        self.cli = self.install / "bin/container"
        self.program = self.install / "libexec/container-apiserver"
        self.cli.write_bytes(b"")
        self.program.write_bytes(b"")
        self.sibling = self.install / "bin/container-apiserver"
        self.sibling.symlink_to("../libexec/container-apiserver")
        self.launch = self.app / "apiserver/apiserver.plist"
        declaration = {
            "api_label": LABEL,
            "api_executable": str(self.program),
            "runtime_label_prefix": PREFIX,
            "runtime_start": {
                "app_root": str(self.app),
                "install_root": str(self.install),
                **start,
            },
        }
        raw = settings_to_dict(replace(settings, executable=str(self.cli)))
        self.settings = parse_settings({**raw, "fleet_start": declaration})
        self.expected: dict[str, Any] = {
            "Label": LABEL,
            "ProgramArguments": [str(self.program), "start"],
            "EnvironmentVariables": {APP: str(self.app), INSTALL: str(self.install)},
            "LimitLoadToSessionType": ["Aqua", "Background", "System"],
            "RunAtLoad": True,
            "MachServices": {LABEL: True},
        }
        self.write(self.expected)
        self.runner = VendorRunner(self, items)

    def write(self, value: Any, mode: int = 0o644, **options: Any) -> None:
        self.launch.write_bytes(plistlib.dumps(value, **options))
        self.launch.chmod(mode)

    def changed(self, **members: Any) -> dict[str, Any]:
        return {**self.expected, **members}

    def reader(self) -> Any:
        return runtime.Reader(self.settings, self.runner)

    def check_launch_file(self, settings: Any = None) -> None:
        settings = settings or self.settings
        fleet = settings.fleet_start
        runtime.check_launch_file(settings, fleet, fleet.runtime_start, self.reader())

    def vendor_calls(self) -> list[list[str]]:
        return [
            argv[1:]
            for argv, _ in self.runner.calls
            if argv[0] == self.settings.executable and argv[1:2] == ["system"]
        ]

    def pause(self) -> None:
        Path(self.settings.intent).write_bytes(canonical_bytes(intent_to_dict(Intent().pause())))

    def start_arguments(self) -> list[str]:
        return [
            "system",
            "start",
            "--app-root",
            str(self.app),
            "--install-root",
            str(self.install),
            "--disable-kernel-install",
        ]


def state(world: World) -> str:
    return str(runtime.runtime_state(world.settings, world.runner))


def start(world: World) -> str:
    return str(runtime.start_runtime(world.settings, world.runner))


def command(monkeypatch: Any, world: World, name: str) -> int:
    """The real entry point with the fake tools; the release gate is lifted for the test only."""
    real_state, real_start = runtime.runtime_state, runtime.start_runtime
    with monkeypatch.context() as patch:
        patch.setattr(runtime, "require_mutation_qualified", lambda _capability: None)
        patch.setattr(runtime, "load_settings", lambda _path: world.settings)
        patch.setattr(runtime, "runtime_state", lambda s, _r=None: real_state(s, world.runner))
        patch.setattr(runtime, "start_runtime", lambda s: real_start(s, world.runner))
        return int(runtime.main(["--settings", "/unused", name]))


def refuses_to_start(monkeypatch: Any, world: World) -> None:
    """Unknown for the probe, and the start makes no vendor call at all."""
    assert command(monkeypatch, world, "runtime-probe") == runtime.UNKNOWN
    with pytest.raises(REFUSED):
        start(world)
    assert command(monkeypatch, world, "runtime-start") == runtime.UNKNOWN
    assert world.vendor_calls() == []


# The decision, and what it leaves untouched.


def test_settings_without_the_declaration_keep_their_bytes_and_digests() -> None:
    plain = parse_settings(authored())
    assert digest(settings_to_dict(plain)) == AUTHORED_SETTINGS_DIGEST
    fleet = parse_settings({**authored(), "fleet_start": dict(FLEET_ONLY)})
    assert settings_to_dict(fleet)["fleet_start"] == FLEET_ONLY
    assert digest(settings_to_dict(fleet)) == FLEET_ONLY_SETTINGS_DIGEST
    # Read with getattr: the member does not exist before this change.
    assert getattr(fleet.fleet_start, "runtime_start", "missing") is None
    declared = parse_settings(
        {**authored(), "fleet_start": {**FLEET_ONLY, "runtime_start": dict(ROOTS)}}
    )
    assert settings_to_dict(declared) == {
        **settings_to_dict(fleet),
        "fleet_start": {**FLEET_ONLY, "runtime_start": ROOTS},
    }
    assert parse_settings(settings_to_dict(declared)) == declared
    assert declared.fleet_start.runtime_start.timeout_seconds is None
    bounded = {**FLEET_ONLY, "runtime_start": {**ROOTS, "timeout_seconds": 45}}
    parsed = parse_settings({**authored(), "fleet_start": bounded})
    assert settings_to_dict(parsed)["fleet_start"] == bounded
    assert digest(settings_to_dict(parsed)) != digest(settings_to_dict(declared))


def test_without_the_declaration_both_commands_refuse(enrolled: Any, monkeypatch: Any) -> None:
    _config, settings, items = enrolled
    for undeclared in (
        settings,
        parse_settings({**settings_to_dict(settings), "fleet_start": dict(FLEET_ONLY)}),
    ):
        runner = FakeRunner(undeclared, items)
        for refused in (
            lambda s=undeclared, r=runner: runtime.runtime_state(s, r),
            lambda s=undeclared, r=runner: runtime.start_runtime(s, r),
        ):
            with pytest.raises(ValueError, match="declare no start"):
                refused()
        monkeypatch.setattr(runtime, "load_settings", lambda _path, s=undeclared: s)
        monkeypatch.setattr(runtime, "run", runner)
        assert runtime.main(["--settings", "/unused", "runtime-probe"]) == runtime.UNKNOWN
        assert runner.calls == []


REFUSED_DECLARATIONS: dict[str, Any] = {
    "null": None,
    "a-list": [ROOTS],
    "no-install-root": {"app_root": ROOTS["app_root"]},
    "no-app-root": {"install_root": ROOTS["install_root"]},
    "unknown-member": {**ROOTS, "log_root": "/opt/example/log"},
    "timeout-null": {**ROOTS, "timeout_seconds": None},
    "timeout-too-short": {**ROOTS, "timeout_seconds": 4},
    "timeout-too-long": {**ROOTS, "timeout_seconds": 121},
    "timeout-not-whole": {**ROOTS, "timeout_seconds": 20.0},
    "timeout-text": {**ROOTS, "timeout_seconds": "20"},
    "timeout-boolean": {**ROOTS, "timeout_seconds": True},
    "root-relative": {**ROOTS, "app_root": "opt/example"},
    "root-null": {**ROOTS, "install_root": None},
    "root-with-a-parent-step": {**ROOTS, "app_root": "/opt/example/../other"},
    "root-with-an-empty-component": {**ROOTS, "app_root": "/opt//example"},
    "root-with-a-final-slash": {**ROOTS, "install_root": "/opt/example/"},
    "root-is-the-root": {**ROOTS, "install_root": "/"},
    "root-with-a-line-break": {**ROOTS, "app_root": "/opt/example\n/other"},
    "root-with-a-final-space": {**ROOTS, "app_root": "/opt/example "},
}


@pytest.mark.parametrize("case", sorted(REFUSED_DECLARATIONS))
def test_the_declaration_is_closed_and_strict(case: str) -> None:
    declaration = {**FLEET_ONLY, "runtime_start": REFUSED_DECLARATIONS[case]}
    with pytest.raises(ValueError):
        parse_settings({**authored(), "fleet_start": declaration})


def test_the_declaration_accepts_its_bounds() -> None:
    for seconds in (5, 120):
        declaration = {**FLEET_ONLY, "runtime_start": {**ROOTS, "timeout_seconds": seconds}}
        parsed = parse_settings({**authored(), "fleet_start": declaration})
        assert parsed.fleet_start.runtime_start.timeout_seconds == seconds


def test_the_declaration_needs_the_vendor_label_the_own_domain_and_a_printable_program() -> None:
    declared = {**FLEET_ONLY, "runtime_start": dict(ROOTS)}
    assert parse_settings({**authored(), "fleet_start": declared}).fleet_start is not None
    # The vendor's start command loads one job only: absence of another label proves nothing.
    other = {**declared, "api_label": ".".join(["org", "example", "vendor-api"])}
    with pytest.raises(ValueError, match="vendor's API label"):
        parse_settings({**authored(), "fleet_start": other})
    undeclared = {key: value for key, value in other.items() if key != "runtime_start"}
    assert parse_settings({**authored(), "fleet_start": undeclared}).fleet_start is not None
    system = authored()
    system["networks"][0]["helper_domain"] = "system"
    assert parse_settings({**system, "fleet_start": dict(FLEET_ONLY)}).fleet_start is not None
    with pytest.raises(ValueError, match="own domain"):
        parse_settings({**system, "fleet_start": declared})
    with pytest.raises(ValueError, match="one spelling"):
        parse_settings(
            {**authored(), "fleet_start": {**declared, "api_executable": "/opt/example/api\n"}}
        )


# The probe's three answers.


def test_the_probe_answers_running_startable_and_unknown(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    assert state(world) == "absent"
    assert command(monkeypatch, world, "runtime-probe") == runtime.STOPPED
    world.runner.load(**IDLE)
    assert state(world) == "idle"
    assert command(monkeypatch, world, "runtime-probe") == runtime.STOPPED
    world.runner.load()
    assert state(world) == "running"
    assert command(monkeypatch, world, "runtime-probe") == 0
    world.runner.load(program="/usr/libexec/another")
    assert command(monkeypatch, world, "runtime-probe") == runtime.UNKNOWN
    # A probe starts nothing and takes no lock.
    assert world.vendor_calls() == []
    with Store(Path(world.settings.state_dir)).lock():
        world.runner.load()
        assert command(monkeypatch, world, "runtime-probe") == 0


def test_a_running_declared_job_needs_no_launch_file_and_no_vendor_call(
    enrolled: Any, tmp_path: Path
) -> None:
    world = World(enrolled, tmp_path)
    world.runner.load()
    world.launch.unlink()
    assert state(world) == "running"
    assert [argv[:2] for argv, _ in world.runner.calls] == [
        ["/bin/launchctl", "print"],
        ["/bin/launchctl", "print"],
        ["/bin/ps", "-p"],
    ]


@pytest.mark.parametrize("job", ["absent", "idle", "running"])
def test_the_probe_is_unknown_whenever_the_intent_blocks(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, job: str
) -> None:
    world = World(enrolled, tmp_path)
    if job != "absent":
        world.runner.load(**({} if job == "running" else IDLE))
    assert state(world) == job
    world.pause()
    assert command(monkeypatch, world, "runtime-probe") == runtime.UNKNOWN
    Path(world.settings.intent).write_bytes(b"not an intent")
    assert command(monkeypatch, world, "runtime-probe") == runtime.UNKNOWN
    with pytest.raises(runtime.RuntimeReadError):
        start(world)
    assert world.vendor_calls() == []


def test_a_hold_on_one_workload_does_not_keep_the_runtime_down(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    intent = Path(world.settings.intent)
    held = Intent().hold("camera", "maintenance", "operator")
    intent.write_bytes(canonical_bytes(intent_to_dict(held)))
    # The runtime serves every workload: a hold on one of them is not a stop of it.
    assert command(monkeypatch, world, "runtime-probe") == runtime.STOPPED
    # A hold nobody here can place inhibits everything, the runtime included.
    stray = held.hold("unknown-service", "maintenance", "operator")
    intent.write_bytes(canonical_bytes(intent_to_dict(stray)))
    refuses_to_start(monkeypatch, world)
    for suspended in (Intent().suspend("upgrade", "operator"), Intent().pause()):
        intent.write_bytes(canonical_bytes(intent_to_dict(suspended)))
        refuses_to_start(monkeypatch, world)
    intent.write_bytes(canonical_bytes(intent_to_dict(held)))
    assert start(world) == "started"


# The one start.


def test_a_proven_absence_gets_one_start_with_both_roots_pinned(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    world = World(enrolled, tmp_path)
    before = world.launch.read_bytes()
    assert command(monkeypatch, world, "runtime-start") == 0
    assert strict_loads(capsys.readouterr().out) == {"runtime": "started"}
    assert world.vendor_calls() == [world.start_arguments()]
    ((argv, kwargs),) = [call for call in world.runner.calls if call[0][1:2] == ["system"]]
    account = world.settings.account
    # Exactly the declared roots, as options and as environment, and nothing else new.
    assert argv[0] == world.settings.executable
    assert kwargs == {
        "timeout": 20,
        "run_uid": account.uid,
        "run_gid": account.gid,
        "account_home": account.home,
        "environment": {APP: str(world.app), INSTALL: str(world.install)},
    }
    # The launch file was written again with the bytes it had; the job now runs.
    assert world.launch.read_bytes() == before
    assert command(monkeypatch, world, "runtime-probe") == 0
    # No workload was started and nothing was unloaded or stopped.
    vendor = [argv[1:3] for argv, _ in world.runner.calls if argv[0] == world.settings.executable]
    assert {tuple(arguments) for arguments in vendor} == {
        ("--version",),
        ("system", "start"),
        ("list", "--all"),
    }
    managed = [argv[1] for argv, _ in world.runner.calls if argv[0] == "/bin/launchctl"]
    assert set(managed) == {"print", "managername", "print-disabled"}


def test_the_declared_bound_is_the_bound_of_the_call(enrolled: Any, tmp_path: Path) -> None:
    world = World(enrolled, tmp_path, timeout_seconds=45)
    assert start(world) == "started"
    (kwargs,) = [kwargs for argv, kwargs in world.runner.calls if argv[1:2] == ["system"]]
    assert kwargs["timeout"] == 45
    assert runtime.RUNTIME_START_TIMEOUT_SECONDS == 20


def test_a_loaded_idle_job_gets_the_status_request_and_no_start(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    world = World(enrolled, tmp_path)
    world.runner.load(**IDLE)
    before = world.launch.stat()
    assert command(monkeypatch, world, "runtime-start") == 0
    assert strict_loads(capsys.readouterr().out) == {"runtime": "activated"}
    assert world.vendor_calls() == [["system", "status"]]
    (kwargs,) = [kwargs for argv, kwargs in world.runner.calls if argv[1:2] == ["system"]]
    assert kwargs["environment"] == {APP: str(world.app), INSTALL: str(world.install)}
    assert set(kwargs) == {"timeout", "run_uid", "run_gid", "account_home", "environment"}
    after = world.launch.stat()
    assert (after.st_ino, after.st_mtime_ns, after.st_size) == (
        before.st_ino,
        before.st_mtime_ns,
        before.st_size,
    )
    assert state(world) == "running"


def test_a_running_runtime_is_not_started_again(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    world.runner.load()
    with pytest.raises(runtime.RuntimeReadError) as refused:
        start(world)
    assert refused.value.reason == "incomplete"
    assert command(monkeypatch, world, "runtime-start") == runtime.UNKNOWN
    assert world.vendor_calls() == []


def test_the_operation_lock_is_held_for_the_call_and_a_held_lock_is_busy(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    world = World(enrolled, tmp_path)
    assert start(world) == "started"
    assert world.runner.lock_held == [True]
    assert not lock_is_held(world.settings)

    monkeypatch.setattr(runtime, "START_LOCK_WAIT_SECONDS", 0.0)
    world.runner.job, calls = None, len(world.runner.calls)
    capsys.readouterr()
    with Store(Path(world.settings.state_dir)).lock():
        assert command(monkeypatch, world, "runtime-start") == runtime.BUSY
    assert capsys.readouterr().err == '{"error":"busy"}\n'
    # Nothing was read and nothing was started while another operation held the lock.
    assert len(world.runner.calls) == calls


def test_the_gate_refuses_the_start_in_this_release(
    monkeypatch: Any, tmp_path: Path, capsys: Any
) -> None:
    def must_not_call(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("the gate comes first")

    for name in ("load_settings", "runtime_state", "start_runtime", "run"):
        monkeypatch.setattr(runtime, name, must_not_call, raising=False)
    target = tmp_path / "missing"
    assert runtime.main(["--settings", str(target), "runtime-start"]) == NOT_QUALIFIED
    assert strict_loads(capsys.readouterr().err)["capability"] == "runtime-start"
    assert not list(tmp_path.iterdir())


def test_only_the_enrolled_account_asks_and_starts(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    account = world.settings.account
    for other in (0, account.uid + 1):
        with monkeypatch.context() as patch:
            patch.setattr(runtime.os, "geteuid", lambda other=other: other)
            for refused in (state, start):
                with pytest.raises(PermissionError):
                    refused(world)
    # The loader refuses a privileged account; settings built without it are refused again.
    privileged = replace(world.settings, account=RuntimeAccount(0, 0, account.home))
    with monkeypatch.context() as patch:
        patch.setattr(runtime.os, "geteuid", lambda: 0)
        with pytest.raises(PermissionError):
            runtime.runtime_state(privileged, world.runner)
    with pytest.raises(PermissionError):
        runtime.start_runtime(replace(world.settings, state_dir=None), world.runner)
    # Settings built without the loader are refused again for another domain.
    system = replace(world.settings.networks[0], helper_domain="system")
    with pytest.raises(runtime.RuntimeReadError):
        runtime.runtime_state(replace(world.settings, networks=(system,)), world.runner)
    assert world.runner.calls == []


# Rule 1: the reviewed launch file is already exactly the expected one.


def test_the_expected_launch_file_is_read_in_both_forms_and_modes(
    enrolled: Any, tmp_path: Path
) -> None:
    world = World(enrolled, tmp_path)
    world.check_launch_file()
    world.write(world.expected, mode=0o600)
    world.check_launch_file()
    world.write(world.expected, fmt=plistlib.FMT_BINARY)
    assert world.launch.read_bytes().startswith(b"bplist00")
    world.check_launch_file()
    # A dictionary has no order.
    world.write(dict(reversed(list(world.expected.items()))), sort_keys=False)
    world.check_launch_file()
    assert state(world) == "absent"


def linked(world: World) -> None:
    real = world.launch.with_name("real.plist")
    world.launch.rename(real)
    world.launch.symlink_to(real)


def padded(world: World) -> None:
    world.launch.write_bytes(world.launch.read_bytes() + b"<!--" + b"x" * 70_000 + b"-->\n")


FILE_FAULTS: dict[str, Callable[[World], Any]] = {
    "absent": lambda w: w.launch.unlink(),
    "a-symbolic-link": linked,
    "a-second-link": lambda w: os.link(w.launch, w.launch.with_name("second.plist")),
    "mode-0666": lambda w: w.launch.chmod(0o666),
    "mode-0640": lambda w: w.launch.chmod(0o640),
    "mode-0755": lambda w: w.launch.chmod(0o755),
    "directory-open-to-others": lambda w: w.launch.parent.chmod(0o777),
    "not-a-property-list": lambda w: w.launch.write_bytes(b"not a property list\n"),
    "empty": lambda w: w.launch.write_bytes(b""),
    "too-large": padded,
    "not-a-dictionary": lambda w: w.write([w.expected]),
    "one-member-different": lambda w: w.write(w.changed(RunAtLoad=False)),
    "one-member-of-another-type": lambda w: w.write(w.changed(RunAtLoad=1)),
    "one-member-extra": lambda w: w.write(w.changed(KeepAlive=True)),
    "one-member-missing": lambda w: w.write(
        {key: value for key, value in w.expected.items() if key != "MachServices"}
    ),
    "session-types-in-another-order": lambda w: w.write(
        w.changed(LimitLoadToSessionType=["Background", "Aqua", "System"])
    ),
    "another-program": lambda w: w.write(
        w.changed(ProgramArguments=["/usr/libexec/another", "start"])
    ),
    "a-third-argument": lambda w: w.write(
        w.changed(ProgramArguments=[str(w.program), "start", "--debug"])
    ),
    "another-root": lambda w: w.write(
        w.changed(EnvironmentVariables={APP: "/opt/other", INSTALL: str(w.install)})
    ),
    "a-third-variable": lambda w: w.write(
        w.changed(
            EnvironmentVariables={**w.expected["EnvironmentVariables"], "HTTPS_PROXY": "proxy"}
        )
    ),
    "another-label": lambda w: w.write(w.changed(Label="com.apple.container.other")),
    "another-service": lambda w: w.write(w.changed(MachServices={LABEL: True, "other": True})),
    "the-command-would-write-another-program": lambda w: (
        w.sibling.unlink(),
        w.sibling.symlink_to(w.cli),
    ),
    "the-command-has-no-such-program": lambda w: w.sibling.unlink(),
}


@pytest.mark.parametrize("fault", sorted(FILE_FAULTS))
def test_a_launch_file_that_is_not_the_expected_one_starts_nothing(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, fault: str
) -> None:
    world = World(enrolled, tmp_path)
    assert state(world) == "absent"
    FILE_FAULTS[fault](world)
    with pytest.raises(runtime.RuntimeReadError) as refused:
        world.check_launch_file()
    assert refused.value.reason == "identity-mismatch"
    refuses_to_start(monkeypatch, world)
    # The same file stops the activation of an idle job.
    world.runner.load(**IDLE)
    refuses_to_start(monkeypatch, world)


def test_a_launch_file_with_an_acl_or_of_another_owner_starts_nothing(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    account = world.settings.account
    stranger = replace(
        world.settings, account=RuntimeAccount(account.uid + 1, account.gid, account.home)
    )
    with pytest.raises(runtime.RuntimeReadError):
        world.check_launch_file(stranger)
    world.check_launch_file()

    def acl(path: Path, **_kwargs: Any) -> None:
        if path == world.launch:
            raise RuntimeError("a grant")

    monkeypatch.setattr(runtime, "reject_acl", acl)
    with pytest.raises(runtime.RuntimeReadError):
        world.check_launch_file()
    refuses_to_start(monkeypatch, world)


def test_a_launch_file_replaced_while_it_is_read_is_not_the_expected_one(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    real = os.read

    def replacing(fd: int, count: int) -> bytes:
        data = real(fd, count)
        if data:
            os.utime(world.launch, ns=(1, 1))
        return data

    def growing(fd: int, count: int) -> bytes:
        return real(fd, count) + b" "

    for changed in (replacing, growing):
        with monkeypatch.context() as patch, pytest.raises(runtime.RuntimeReadError):
            patch.setattr(runtime.os, "read", changed)
            world.check_launch_file()
    world.write(world.expected)
    world.check_launch_file()


# Rule 3: only a proven absence starts anything.


def printed(world: World, **changes: Any) -> bytes:
    return job_print(world.runner.gui, declared_job(world, **changes))


def set_on(name: str, value: Callable[[World], Any]) -> Callable[[World], None]:
    return lambda world: setattr(world.runner, name, value(world))


def reprinted(change: Callable[[bytes], bytes], **job: Any) -> Callable[[World], None]:
    """The declared job stays loaded with its process; only its print is changed."""

    def apply(world: World) -> None:
        world.runner.load(**job)
        world.runner.job_answer = Result(0, change(printed(world, **job)), b"")

    return apply


def listing(*entries: str, head: str = "disabled services = {", tail: str = "}") -> Result:
    return Result(0, "\n".join([head, *entries, tail, ""]).encode(), b"")


STATE_FAULTS: dict[str, Callable[[World], None]] = {
    "loaded-as-another-program": lambda w: w.runner.load(
        program="/usr/libexec/another", arguments=["/usr/libexec/another", "start"]
    ),
    "loaded-under-another-first-argument": lambda w: w.runner.load(
        arguments=["/usr/libexec/another", "start"]
    ),
    "loaded-with-a-third-argument": lambda w: w.runner.load(
        arguments=[str(w.program), "start", "--debug"]
    ),
    "loaded-with-another-app-root": lambda w: w.runner.load(
        environment={APP: "/opt/other", INSTALL: str(w.install)}
    ),
    "loaded-with-another-install-root": lambda w: w.runner.load(
        environment={APP: str(w.app), INSTALL: "/opt/other"}
    ),
    "loaded-without-a-root": lambda w: w.runner.load(environment={APP: str(w.app)}),
    "loaded-with-a-root-twice": reprinted(
        lambda text: text.replace(
            f"\t\t{APP} =>".encode(), f"\t\t{APP} => /opt/other\n\t\t{APP} =>".encode()
        )
    ),
    "loaded-from-another-file": lambda w: w.runner.load(path="/opt/other/apiserver.plist"),
    "loaded-with-two-path-lines": reprinted(
        lambda text: text.replace(b"\ttype = ", b"\tpath = /x\n\ttype = ")
    ),
    "loaded-without-an-arguments-block": reprinted(
        lambda text: text.replace(b"\targuments = {", b"\targs = {")
    ),
    "loaded-with-two-arguments-blocks": reprinted(
        lambda text: text.replace(b"\tdomain = ", b"\targuments = {\n\t\tx\n\t}\n\tdomain = ")
    ),
    "loaded-with-two-environment-blocks": reprinted(
        lambda text: text.replace(
            b"\tdomain = ", b"\tenvironment = {\n\t\tA => b\n\t}\n\tdomain = "
        )
    ),
    "loaded-with-an-unfamiliar-variable-line": reprinted(
        lambda text: text.replace(b"XPC_SERVICE_NAME => ", b"XPC = ")
    ),
    "loaded-with-an-unclosed-block": reprinted(
        lambda text: text.partition(b"\t\tXPC_SERVICE_NAME")[0] + b"\tpid = 222\n"
    ),
    "loaded-in-an-unfamiliar-state": lambda w: w.runner.load(state="spawn scheduled", pid=None),
    "loaded-idle-as-another-program": lambda w: w.runner.load(
        **IDLE, program="/usr/libexec/another"
    ),
    "loaded-with-both-states": reprinted(
        lambda text: text.replace(b"\truns = 1\n", b"\truns = 1\n\tstate = running\n"), **IDLE
    ),
    "loaded-idle-but-with-a-process": lambda w: w.runner.load(state="not running"),
    "loaded-running-without-a-process": lambda w: w.runner.load(pid=None),
    "job-print-with-an-error": set_on("job_answer", lambda w: Result(0, printed(w), b"warning\n")),
    "job-read-fails": set_on("job_answer", lambda w: Result(1, b"", b"launchctl failed\n")),
    "job-absent-under-another-status": set_on(
        "job_answer", lambda w: Result(3, b"", b"No such process\n")
    ),
    "job-absent-with-output": set_on("job_answer", lambda w: Result(113, b"state = x\n", b"")),
    "loaded-in-the-account-s-other-domain": set_on(
        "other_domain", lambda w: Result(0, printed(w), b"")
    ),
    "other-domain-unreadable": set_on("other_domain", lambda w: Result(1, b"", b"failed\n")),
    "domain-does-not-answer": set_on(
        "domain", lambda w: Result(113, b"", b"Bad request.\nCould not find domain\n")
    ),
    "domain-answers-under-another-status": set_on(
        "domain", lambda w: Result(1, b"x = {\n}\n", b"")
    ),
    "domain-answers-nothing": set_on("domain", lambda w: Result(0, b"", b"")),
    "domain-answers-with-an-error": set_on("domain", lambda w: Result(0, b"x = {\n}\n", b"e\n")),
    "session-is-a-background-session": set_on("session", lambda w: Result(0, b"Background\n", b"")),
    "session-is-the-system": set_on("session", lambda w: Result(0, b"System\n", b"")),
    "session-is-unfamiliar": set_on("session", lambda w: Result(0, b"LoginWindow\n", b"")),
    "session-is-not-named": set_on("session", lambda w: Result(0, b"", b"")),
    "session-is-unreadable": set_on("session", lambda w: Result(1, b"", b"failed\n")),
    "label-disabled": set_on("disabled", lambda w: listing(f'\t"{LABEL}" => disabled')),
    "label-disabled-in-the-older-wording": set_on(
        "disabled", lambda w: listing(f'\t"{LABEL}" => true')
    ),
    "disabled-list-unreadable": set_on("disabled", lambda w: Result(1, b"", b"failed\n")),
    "disabled-list-with-an-error": set_on(
        "disabled", lambda w: Result(0, DISABLED_LIST, b"warning\n")
    ),
    "disabled-list-with-an-unfamiliar-entry": set_on(
        "disabled", lambda w: listing(f"\t{LABEL} => disabled")
    ),
    "disabled-list-with-an-unfamiliar-word": set_on(
        "disabled", lambda w: listing('\t"com.apple.example-one" => off')
    ),
    "disabled-list-without-its-block": set_on("disabled", lambda w: listing(head="services = {")),
    "disabled-list-with-two-blocks": set_on(
        "disabled", lambda w: Result(0, DISABLED_LIST * 2, b"")
    ),
    "disabled-list-unclosed": set_on(
        "disabled",
        lambda w: Result(0, b'disabled services = {\n\t"com.apple.example-two" => enabled\n', b""),
    ),
    "disabled-list-names-the-label-twice": set_on(
        "disabled", lambda w: listing(f'\t"{LABEL}" => enabled', f'\t"{LABEL}" => enabled')
    ),
    "disabled-list-empty": set_on("disabled", lambda w: Result(0, b"", b"")),
    "command-of-another-release": set_on("version", lambda w: b"container CLI version 9.9.9\n"),
    "operator-pause": lambda w: w.pause(),
}


@pytest.mark.parametrize("fault", sorted(STATE_FAULTS))
def test_any_state_but_a_proven_absence_starts_nothing(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, fault: str
) -> None:
    world = World(enrolled, tmp_path)
    assert state(world) == "absent"
    STATE_FAULTS[fault](world)
    refuses_to_start(monkeypatch, world)


@pytest.mark.parametrize(
    "fault",
    sorted(
        name
        for name in STATE_FAULTS
        if name.startswith(("session-", "label-", "disabled-", "command-", "operator-", "other-"))
        or name == "loaded-in-the-account-s-other-domain"
    ),
)
def test_the_same_conditions_stop_the_activation_of_an_idle_job(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, fault: str
) -> None:
    world = World(enrolled, tmp_path)
    world.runner.load(**IDLE)
    idle = world.runner.job
    assert state(world) == "idle"
    STATE_FAULTS[fault](world)
    world.runner.job = idle
    refuses_to_start(monkeypatch, world)


def test_an_idle_job_needs_no_listing_of_its_domain(enrolled: Any, tmp_path: Path) -> None:
    world = World(enrolled, tmp_path)
    world.runner.load(**IDLE)
    world.runner.domain = Result(113, b"", b"Bad request.\n")
    # The job's own print shows that the domain answers.
    assert state(world) == "idle"
    assert ["/bin/launchctl", "print", world.runner.gui] not in [
        argv for argv, _ in world.runner.calls
    ]


def between_the_reads(monkeypatch: Any, change: Callable[[], Any]) -> None:
    """Run `change` after the first complete read of the state and before the second."""
    real, reads = runtime.runtime_state, []

    def counting(settings: Any, runner: Any) -> str:
        reads.append(settings)
        if len(reads) == 2:
            change()
        return str(real(settings, runner))

    monkeypatch.setattr(runtime, "runtime_state", counting)


CHANGES_BETWEEN: dict[str, Callable[[World], Any]] = {
    "the-job-is-loaded-and-runs": lambda w: w.runner.load(),
    "the-job-is-loaded-idle": lambda w: w.runner.load(**IDLE),
    "the-job-is-loaded-as-another-program": lambda w: w.runner.load(program="/usr/libexec/x"),
    "the-intent-is-paused": lambda w: w.pause(),
    "the-launch-file-changes": lambda w: w.write(w.changed(RunAtLoad=False)),
    "the-label-is-disabled": lambda w: setattr(
        w.runner, "disabled", listing(f'\t"{LABEL}" => disabled')
    ),
    "the-domain-stops-answering": lambda w: setattr(
        w.runner, "domain", Result(113, b"", b"Bad request.\n")
    ),
}


@pytest.mark.parametrize("change", sorted(CHANGES_BETWEEN))
def test_absence_on_one_of_the_two_reads_only_starts_nothing(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, change: str
) -> None:
    world = World(enrolled, tmp_path)
    between_the_reads(monkeypatch, lambda: CHANGES_BETWEEN[change](world))
    with pytest.raises(runtime.RuntimeReadError):
        start(world)
    assert world.vendor_calls() == []


def test_a_pause_at_the_first_read_refuses_whatever_the_second_read_would_say(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    world.pause()
    # Were the intent read only once, at the end, this resume would let the start through.
    resumed = canonical_bytes(intent_to_dict(Intent().pause().resume()))
    between_the_reads(monkeypatch, lambda: Path(world.settings.intent).write_bytes(resumed))
    with pytest.raises(runtime.RuntimeReadError) as refused:
        start(world)
    assert refused.value.reason == "incomplete"
    assert world.vendor_calls() == []


def test_an_idle_job_that_starts_by_itself_between_the_reads_gets_no_request(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    world.runner.load(**IDLE)
    between_the_reads(monkeypatch, world.runner.load)
    with pytest.raises(runtime.RuntimeReadError) as refused:
        start(world)
    assert refused.value.reason == "generation-mismatch"
    assert world.vendor_calls() == []


# After the call: the file, the job and one inventory, or the result is unknown.


def cut_off(world: World) -> None:
    raise ProcessTimeout("bounded")


AFTER_START: dict[str, Callable[[World], Any]] = {
    "the-job-is-never-loaded": lambda w: setattr(w.runner, "job", None),
    "the-job-never-runs": lambda w: w.runner.load(**IDLE),
    "the-job-runs-as-another-program": lambda w: w.runner.load(
        program="/usr/libexec/another", arguments=["/usr/libexec/another", "start"]
    ),
    "the-job-runs-with-another-root": lambda w: w.runner.load(
        environment={APP: str(w.app), INSTALL: "/opt/other"}
    ),
    "the-job-runs-from-another-file": lambda w: w.runner.load(path="/opt/other/apiserver.plist"),
    "the-program-is-moved-away": lambda w: w.program.rename(w.program.with_name("moved")),
    "the-launch-file-differs": lambda w: w.write(w.changed(KeepAlive=True)),
    "the-launch-file-is-gone": lambda w: w.launch.unlink(),
    "the-inventory-is-unreadable": lambda w: setattr(w.runner, "failure", "duplicate"),
    "the-call-fails": lambda w: setattr(w.runner, "start_answer", Result(1, b"", b"failed\n")),
    "the-call-is-cut-off": cut_off,
}


@pytest.mark.parametrize("fault", sorted(AFTER_START))
def test_a_start_whose_readback_does_not_hold_is_unknown_and_is_not_repeated(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, fault: str
) -> None:
    world = World(enrolled, tmp_path)
    world.runner.after_start = lambda: AFTER_START[fault](world)
    assert command(monkeypatch, world, "runtime-start") == runtime.UNKNOWN
    # One call, no second attempt, and nothing unloaded, stopped or repaired.
    assert world.vendor_calls() == [world.start_arguments()]
    assert world.runner.lock_held == [True] and not lock_is_held(world.settings)
    managed = {argv[1] for argv, _ in world.runner.calls if argv[0] == "/bin/launchctl"}
    assert managed == {"print", "managername", "print-disabled"}


def test_a_status_request_that_wakes_nothing_is_unknown(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    world.runner.load(**IDLE)
    idle = dict(world.runner.job or {})
    real = world.runner.system

    def asleep(argv: list[str], kwargs: dict[str, Any]) -> Result:
        answer = real(argv, kwargs)
        world.runner.job = dict(idle)
        return answer

    monkeypatch.setattr(world.runner, "system", asleep)
    with pytest.raises(runtime.RuntimeReadError) as refused:
        start(world)
    assert refused.value.reason == "incomplete"
    assert world.vendor_calls() == [["system", "status"]]


# The pure readers.

DISABLED_READS: dict[str, tuple[bytes, bool | None]] = {
    "not-listed": (DISABLED_LIST, False),
    "listed-enabled": (listing(f'\t"{LABEL}" => enabled').stdout, False),
    "listed-false": (listing(f'\t"{LABEL}" => false').stdout, False),
    "listed-disabled": (listing(f'\t"{LABEL}" => disabled').stdout, True),
    "listed-true": (listing(f'\t"{LABEL}" => true').stdout, True),
    "empty-block": (listing().stdout, False),
    "other-indentation": (listing(f'    "{LABEL}" => disabled  ').stdout, True),
    "a-longer-label-is-another-label": (listing(f'\t"{LABEL}.other" => disabled').stdout, False),
    "unfamiliar-state": (listing(f'\t"{LABEL}" => maybe').stdout, None),
    "no-block": (b"", None),
}


@pytest.mark.parametrize("sample", sorted(DISABLED_READS))
def test_the_disabled_list_is_read_strictly(sample: str) -> None:
    text, outcome = DISABLED_READS[sample]
    if outcome is None:
        with pytest.raises(runtime.RuntimeReadError):
            runtime._label_disabled(text.decode(), LABEL)
    else:
        assert runtime._label_disabled(text.decode(), LABEL) is outcome


def test_members_are_compared_with_their_types() -> None:
    same = runtime._same_members
    expected = {"a": True, "b": ["x", "y"], "c": {"d": "e"}}
    assert same({"c": {"d": "e"}, "b": ["x", "y"], "a": True}, expected)
    for other in (
        {**expected, "a": 1},
        {**expected, "b": ["y", "x"]},
        {**expected, "b": ["x"]},
        {**expected, "b": ("x", "y")},
        {**expected, "c": {"d": "e", "f": "g"}},
        {**expected, "c": {}},
        {**expected, "g": None},
        {key: value for key, value in expected.items() if key != "a"},
        [expected],
        None,
    ):
        assert not same(other, expected)
    for data in (b"", b"bplist00", b"<plist><dict><key>a</key></dict>", b"<plist>&x;</plist>"):
        with pytest.raises(runtime.RuntimeReadError):
            runtime._decoded_launch_file(data)


# The runner's closed environment.


def test_the_runner_adds_only_the_named_variables(monkeypatch: Any) -> None:
    monkeypatch.setenv(APP, "/inherited")
    monkeypatch.setenv("UNRELATED_FOR_TEST", "never-propagate")
    captured: dict[str, Any] = {}
    original = subprocess.Popen

    def spawn(argv: Any, **kwargs: Any) -> Any:
        captured.update(kwargs)
        return original(argv, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", spawn)
    script = "import os; print(os.environ.get('UNRELATED_FOR_TEST')); print(os.environ['A_ROOT'])"
    added = {"A_ROOT": "/opt/example/application data", "B_ROOT": "/opt/example"}
    result = process.run([sys.executable, "-c", script], environment=added)
    assert result.stdout.decode().splitlines() == ["None", added["A_ROOT"]]
    assert captured["env"] == {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C",
        "HOME": os.path.expanduser("~"),
        **added,
    }
    # Without the argument the environment is the four it always was.
    process.run([sys.executable, "-c", "pass"])
    assert set(captured["env"]) == {"PATH", "LANG", "LC_ALL", "HOME"}


@pytest.mark.parametrize(
    "environment",
    [
        {"PATH": "/opt/other/bin"},
        {"HOME": "/opt/other"},
        {"LC_ALL": "x"},
        {"lower": "x"},
        {"WITH-HYPHEN": "x"},
        {"": "x"},
        {"A_ROOT": 7},
        {"A_ROOT": None},
        {"A_ROOT": "a\0b"},
        {7: "x"},
        [("A_ROOT", "x")],
        {f"V{index}": "x" for index in range(9)},
    ],
)
def test_the_runner_refuses_any_other_addition(environment: Any) -> None:
    with pytest.raises(ValueError, match="invalid bounded command"):
        process.run([sys.executable, "-c", "pass"], environment=environment)


# The supervisor's one monitor of the runtime.


def with_runtime_monitor(**changes: Any) -> dict[str, Any]:
    value = fixed()
    value["monitors"].append(
        {
            "id": "runtime",
            "role": "runtime",
            "check_argv": ["/operator/tools/manager", "runtime-probe"],
            "recovery_argv": ["/operator/tools/manager", "runtime-start"],
            "timeout_seconds": 10,
            "cycles": 2,
            "recovery_code": 42,
            **changes,
        }
    )
    return value


def test_manifests_without_a_runtime_monitor_keep_their_bytes_and_release() -> None:
    value = fixed()
    canonical = deployment_to_dict(parse_deployment(canonical_bytes(value)))
    assert canonical_bytes(canonical) == canonical_bytes(value)
    assert digest(canonical) == DIGEST_BEFORE
    assert implementation._monit(parse_deployment(canonical_bytes(value)), RELEASE).decode() == (
        MONITRC_BEFORE
    )
    deployment = load_deployment(ROOT / "examples/deployment.json")
    policy = to_dict(load_config(ROOT / "examples/network.json"))
    assert digest(deployment_to_dict(deployment)) == EXAMPLE_MANIFEST_DIGEST
    release = digest({"deployment": deployment_to_dict(deployment), "policy": policy})
    assert release == EXAMPLE_RELEASE_ID
    rendered = implementation._monit(deployment, RELEASE)
    assert hashlib.sha256(rendered).hexdigest() == EXAMPLE_MONITRC_SHA256


def test_a_deployment_may_give_the_runtime_one_monitor_with_a_recovery_command() -> None:
    value = with_runtime_monitor()
    deployment = parse_deployment(canonical_bytes(value))
    assert canonical_bytes(deployment_to_dict(deployment)) == canonical_bytes(value)
    assert digest(deployment_to_dict(deployment)) != DIGEST_BEFORE
    text = implementation._monit(deployment, RELEASE).decode()
    assert text.startswith(MONITRC_BEFORE)
    assert text.removeprefix(MONITRC_BEFORE) == (
        "\n"
        'check program "runtime" with path "/operator/tools/manager runtime-probe"\n'
        "  timeout 10 seconds\n"
        "  if status != 0 then alert\n"
        '  if status = 42 for 2 cycles then exec "/operator/tools/manager runtime-start"\n'
    )
    # It may also only alert, and it may repeat like a workload monitor.
    assert parse_deployment(canonical_bytes(with_runtime_monitor(recovery_argv=None)))
    repeating = parse_deployment(canonical_bytes(with_runtime_monitor(recovery_repeat_cycles=6)))
    assert " repeat every 6 cycles\n" in implementation._monit(repeating, RELEASE).decode()


def test_a_deployment_has_at_most_one_runtime_monitor_and_networking_starts_nothing() -> None:
    value = with_runtime_monitor()
    value["monitors"].append({**value["monitors"][-1], "id": "runtime-again"})
    with pytest.raises(DeploymentError, match="at most one monitor of the vendor runtime"):
        parse_deployment(canonical_bytes(value))
    value["monitors"][-1]["recovery_argv"] = None
    with pytest.raises(DeploymentError, match="at most one monitor of the vendor runtime"):
        parse_deployment(canonical_bytes(value))
    for role in ("forwarding", "discovery"):
        with pytest.raises(DeploymentError, match="networking failure must not initiate"):
            parse_deployment(canonical_bytes(with_runtime_monitor(role=role)))
    with pytest.raises(DeploymentError, match="closed schema"):
        parse_deployment(canonical_bytes(with_runtime_monitor(role="vendor")))
    with pytest.raises(DeploymentError, match="privilege escalation"):
        parse_deployment(
            canonical_bytes(with_runtime_monitor(recovery_argv=["/usr/bin/sudo", "start"]))
        )


# Hosted macOS userspace contract: what the real tools answer. Evidence for the
# recorded runner image only; nothing here loads, starts or changes a job.

GUI = pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true", reason="a remote shell may have no gui domain"
)
DOMAINS = ["user", pytest.param("gui", marks=GUI)]


def recorded(capsys: Any, title: str, seen: str) -> None:
    """On the hosted runner, keep what the tool answered as a warning of the job.

    A warning, not a notice: the runner shows at most ten notices of one step,
    and the hosted tests of earlier changes use all ten.
    """
    if os.environ.get("GITHUB_ACTIONS") == "true":
        text = seen.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        # Capture is lifted for one line of its own: the runner reads commands at line starts.
        with capsys.disabled():
            print(f"\n::warning title={title}::{text}")


def tool(*argv: str) -> tuple[int, str, str]:
    done = subprocess.run(list(argv), capture_output=True, timeout=10, check=False)
    return (
        done.returncode,
        done.stdout.decode("utf-8", "replace"),
        done.stderr.decode("utf-8", "replace"),
    )


def forms(text: str) -> str:
    """The distinct line forms of a listing, with every label and identifier masked."""
    masks = (
        (r'"[^"]*"', '"<label>"'),
        (r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", "<id>"),
        # A label that is not quoted would otherwise be shown as it is.
        (r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2,}", "<name>"),
    )
    masked = set()
    for line in text.splitlines():
        form = line.strip()
        for pattern, mask in masks:
            form = re.sub(pattern, mask, form)
        masked.add(form)
    return " | ".join(sorted(masked)[:12])[:600]


def listed_services(listing_text: str) -> list[tuple[str, str]]:
    """First column and label of every row in a domain print's `services` block."""
    rows, inside = [], False
    for line in listing_text.splitlines():
        if not inside:
            inside = line.strip() == "services = {"
        elif line.strip() == "}":
            break
        elif len(line.split()) >= 2:
            rows.append((line.split()[0], line.split()[-1]))
    return rows


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
@pytest.mark.parametrize("kind", DOMAINS)
def test_hosted_disabled_list_is_in_the_form_the_reader_accepts(kind: str, capsys: Any) -> None:
    status, out, err = tool("/bin/launchctl", "print-disabled", f"{kind}/{os.getuid()}")
    recorded(
        capsys,
        f"disabled list of {kind}",
        f"status {status}, {len(out.splitlines())} lines, err {err[:160]!r}, forms {forms(out)}",
    )
    assert status == 0 and not err
    # Every entry line has a known form, and a label that is not listed is not disabled.
    missing = ".".join(["org", "example", "netorch", "contract", "no-such-job"])
    assert runtime._label_disabled(out, missing) is False


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
def test_hosted_running_job_prints_the_identity_the_start_reads(capsys: Any) -> None:
    """Among the oldest running jobs there is one whose launch file, arguments and
    environment the production expressions read."""
    domain = f"user/{os.getuid()}"
    status, out, err = tool("/bin/launchctl", "print", domain)
    running = sorted(
        (int(first), label)
        for first, label in listed_services(out)
        if first.isdigit() and int(first)
    )
    seen: list[str] = []
    read: list[str] = []
    blocks = 0
    for _pid, label in running[:8]:
        _status, report, _err = tool("/bin/launchctl", "print", f"{domain}/{label}")
        paths = runtime._JOB_PATH.findall(report)
        programs = runtime._JOB_PROGRAMS.findall(report)
        arguments = runtime._job_block(report, "arguments")
        environment = runtime._job_block(report, "environment")
        variables: dict[str, str] | None = None
        if environment is not None:
            blocks += 1
            found = [runtime._JOB_VARIABLE.fullmatch(line) for line in environment]
            if all(item is not None for item in found):
                variables = {item[1]: item[2] or "" for item in found if item is not None}
        # The reader compares exactly: a printer that pads a value would never match.
        padded = any(
            value != value.strip()
            for value in (*paths, *programs, *(arguments or []), *(variables or {}).values())
        )
        seen.append(
            f"paths {len(paths)}, programs {len(programs)}, "
            f"arguments {None if arguments is None else len(arguments)}, "
            f"variables {None if variables is None else sorted(variables)}, "
            f"first argument is the program "
            f"{bool(arguments and len(programs) == 1 and arguments[0] == programs[0])}, "
            f"service name is the label "
            f"{bool(variables and variables.get('XPC_SERVICE_NAME') == label)}, "
            f"a value begins or ends in white space {padded}"
        )
        if (
            len(paths) == 1
            and len(programs) == 1
            and paths[0].startswith("/")
            and arguments
            and variables
            and not padded
        ):
            read.append(label)
    # The record comes before every assertion, so a failing run still shows the answer.
    recorded(
        capsys,
        "identity of running jobs",
        f"listing status {status}, err {err[:160]!r}, {len(running)} running, "
        f"{blocks} of {len(seen)} with an environment block, "
        f"{len(read)} read whole; " + "; ".join(seen[:4]),
    )
    assert status == 0, (status, err)
    assert blocks, "none of the eight oldest running jobs prints an environment block"
    assert read, seen


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
def test_hosted_plutil_writes_what_the_launch_file_decoder_reads(
    tmp_path: Path, capsys: Any
) -> None:
    expected = {
        "Label": LABEL,
        "ProgramArguments": ["/opt/example/libexec/container-apiserver", "start"],
        "EnvironmentVariables": {APP: ROOTS["app_root"], INSTALL: ROOTS["install_root"]},
        "LimitLoadToSessionType": ["Aqua", "Background", "System"],
        "RunAtLoad": True,
        "MachServices": {LABEL: True},
    }
    source = tmp_path / "launch.json"
    source.write_text(json.dumps(expected))
    written: dict[str, tuple[int, bytes]] = {}
    for form in ("xml1", "binary1"):
        target = tmp_path / f"launch-{form}.plist"
        status, _out, _err = tool(
            "/usr/bin/plutil", "-convert", form, "-o", str(target), str(source)
        )
        written[form] = (status, target.read_bytes() if target.exists() else b"")
    recorded(
        capsys,
        "launch file written by plutil",
        "; ".join(
            f"{form} status {status}, {len(data)} bytes, begins {data[:8]!r}"
            for form, (status, data) in written.items()
        ),
    )
    for form, (status, data) in written.items():
        assert status == 0, form
        assert runtime._same_members(runtime._decoded_launch_file(data), expected), form


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
def test_hosted_loaded_job_without_a_process_prints_the_idle_state(capsys: Any) -> None:
    domain = f"user/{os.getuid()}"
    status, out, err = tool("/bin/launchctl", "print", domain)
    idle = [label for first, label in listed_services(out) if not (first.isdigit() and int(first))]
    states: set[str] = set()
    accepted = 0
    for label in idle[:8]:
        _status, report, _err = tool("/bin/launchctl", "print", f"{domain}/{label}")
        # Only the indentation is removed, as the reader does: white space at an end stays.
        states.update(
            line.lstrip("\t ")
            for line in report.split("\n")
            if line.lstrip("\t ").startswith("state = ")
        )
        accepted += (
            runtime._JOB_IDLE.search(report) is not None
            and runtime._JOB_RUNNING.search(report) is None
            and runtime._JOB_PROCESS.search(report) is None
        )
    # The record comes before every assertion, so a failing run still shows the answer.
    recorded(
        capsys,
        "state of jobs without a process",
        f"listing status {status}, err {err[:160]!r}, {len(idle)} listed without a process, "
        f"{accepted} of {len(idle[:8])} read as idle, state lines {sorted(states)[:6]}",
    )
    assert status == 0, (status, err)
    if not idle:
        pytest.skip("this runner lists no loaded job without a process")
    assert accepted, sorted(states)


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
def test_hosted_session_name_is_one_word(capsys: Any) -> None:
    status, out, err = tool("/bin/launchctl", "managername")
    recorded(capsys, "session name", f"status {status}, out {out!r}, err {err[:160]!r}")
    assert status == 0 and not err
    # Which session a runner has differs; the reader needs one word on one line.
    assert re.fullmatch(r"[A-Za-z]+", out.strip()), out

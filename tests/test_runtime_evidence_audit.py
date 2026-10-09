"""Independent counterexamples found during the runtime evidence audit.

These are synthetic fault injections, not native qualification or deployment.
Recorded parser replays live in a separate module and retain their provenance.
"""

import errno
import os
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from netorch import macos_preflight, observer_child, process
from netorch.apple_runtime import Reader, RuntimeReadError
from netorch.process import Result
from netorch.runtime_settings import FleetStart
from netorch.state import intent_from_dict
from netorch.workloads import provision_digest, provision_workloads
from tests.test_apple_runtime import enrolled
from tests.test_runtime_start_vendor_runtime import IDLE, World, printed
from tests.test_workloads import fleet

__all__ = ["enrolled"]


@pytest.mark.parametrize("timeout", [10**1000, -(10**1000)], ids=["too-large", "too-negative"])
def test_timeout_integer_outside_float_range_is_refused_before_spawn(monkeypatch, timeout):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid timeout reached process creation")

    monkeypatch.setattr(process.subprocess, "Popen", unexpected)
    with pytest.raises(ValueError, match="invalid bounded command"):
        process.run([sys.executable, "-c", "pass"], timeout=timeout)


@pytest.mark.parametrize("kind", ["helper", "api"])
@pytest.mark.parametrize(
    "extra",
    ["state = not running\n", "pid = 101\n", "pid = invalid\n", "program = /other\n"],
)
def test_job_identity_rejects_contradictory_or_duplicate_fields(tmp_path, kind, extra):
    _, settings, _, _, _ = fleet(tmp_path)
    executable = settings.networks[0].helper_executable
    report = "state = running\npid = 100\nprogram = " + executable + "\n" + extra
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "/bin/launchctl":
            return Result(0, report.encode(), b"")
        return Result(0, f"{os.geteuid()} Mon Jan  1 00:00:00 2000 {executable}\n".encode(), b"")

    reader = Reader(settings, runner)
    with pytest.raises(RuntimeReadError, match="incomplete or disagrees"):
        if kind == "helper":
            reader.helper(replace(settings.networks[0], helper_uid=os.geteuid()))
        else:
            reader.api_process(
                FleetStart("com.apple.container.apiserver", executable, "com.apple.container."),
                report,
            )
    assert not any(call[0] == "/bin/ps" for call in calls)


@pytest.mark.parametrize("action", ["create-stopped", "start-existing"])
def test_initial_start_refuses_live_guest_job_despite_stopped_api_row(tmp_path, action):
    config, settings, fake, workloads, _ = fleet(tmp_path)
    name = settings.contracts[0].name
    if action == "start-existing":
        fake.existing[name] = fake.snapshot(name, "stopped")

    def surviving_job(argv, **kwargs):
        if argv[:2] == ["/bin/launchctl", "print"] and argv[2].endswith(
            ".container-runtime-linux." + name
        ):
            fake.calls.append((argv, kwargs))
            # Even a loaded idle native job conflicts with a stopped API row.
            return Result(0, b"state = not running\n", b"")
        return fake(argv, **kwargs)

    with pytest.raises(RuntimeReadError):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=provision_digest(config, settings, workloads, start_initial=True),
            start_initial=True,
            runner=surviving_job,
        )
    assert not any(argv[1:2] == ["start"] for argv, _ in fake.calls)


@pytest.mark.parametrize("extra", ["not running", "waiting", "stopped"])
def test_idle_runtime_job_refuses_duplicate_or_contradictory_top_level_state(
    enrolled, tmp_path, extra
):
    world = World(enrolled, tmp_path)
    world.runner.load(**IDLE)
    report = printed(world, **IDLE).replace(
        b"\tstate = not running\n",
        f"\tstate = not running\n\tstate = {extra}\n".encode(),
    )

    def runner(argv, **kwargs):
        if argv[:2] == ["/bin/launchctl", "print"]:
            return Result(0, report, b"")
        pytest.fail("ambiguous job must not reach process or vendor command")

    item = world.settings.fleet_start
    with pytest.raises(RuntimeReadError):
        Reader(world.settings, runner).runtime_job(item, item.runtime_start, "gui/1001")


@pytest.mark.parametrize("appearance", ["historical-handler", "final-fence"])
def test_initial_start_requires_complete_fresh_historical_job_absence(tmp_path, appearance):
    config, settings, fake, workloads, store = fleet(tmp_path)
    name = settings.contracts[0].name
    domain_reads = 0

    def changed_domain(argv, **kwargs):
        nonlocal domain_reads
        result = fake(argv, **kwargs)
        if argv == ["/bin/launchctl", "print", "system"]:
            domain_reads += 1
            if appearance == "historical-handler" or domain_reads == 2:
                report = result.stdout.replace(b"service count = 0", b"service count = 1")
                report = report.replace(
                    b"services = {\n",
                    f"services = {{\n\t\t0 - com.apple.container.old-handler.{name}\n".encode(),
                )
                return Result(0, report, b"")
        return result

    with pytest.raises(RuntimeReadError):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=provision_digest(config, settings, workloads, start_initial=True),
            start_initial=True,
            runner=changed_domain,
        )
    assert not any(argv[1:2] == ["start"] for argv, _ in fake.calls)
    assert store.read("workload-journal.json")["phase"] == "failed"
    assert intent_from_dict(store.read("intent.json")).operator_paused
    if appearance == "final-fence":
        assert domain_reads == 2


def test_initial_start_refuses_guest_that_became_running_before_effect(tmp_path):
    config, settings, fake, workloads, _ = fleet(tmp_path)
    name = settings.contracts[0].name
    inspections = 0

    def racing_state(argv, **kwargs):
        nonlocal inspections
        if argv == [settings.executable, "inspect", name]:
            inspections += 1
            if inspections == 2:
                fake.existing[name] = fake.snapshot(name, "running")
        return fake(argv, **kwargs)

    with pytest.raises(RuntimeReadError):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=provision_digest(config, settings, workloads, start_initial=True),
            start_initial=True,
            runner=racing_state,
        )
    assert inspections == 2
    assert not any(argv[1:2] == ["start"] for argv, _ in fake.calls)


def test_detached_descendant_is_outside_process_group_cleanup(tmp_path):
    """Prove the limit explicitly; the self-terminating child touches only tmp_path."""
    marker = tmp_path / "detached-child-finished"
    script = (
        "import os,time,pathlib; child=os.fork(); "
        "os._exit(0) if child else None; os.setsid(); time.sleep(0.8); "
        f"pathlib.Path({str(marker)!r}).write_text('finished')"
    )
    started = time.monotonic()
    with pytest.raises((process.ProcessTimeout, PermissionError)) as stopped:
        process.run([sys.executable, "-c", script], timeout=0.5)
    # Darwin can report EPERM when killing the original, now empty group. That
    # remains a closed failure, never proof that the detached process was killed.
    if isinstance(stopped.value, PermissionError):
        assert stopped.value.errno == errno.EPERM
    assert time.monotonic() - started < 2
    deadline = time.monotonic() + 3
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert marker.read_text() == "finished"


@pytest.mark.parametrize("failure", ["groups", "gid", "uid", "readback", "cwd", "umask", "exec"])
def test_observer_drop_failure_stops_before_later_privileged_steps(monkeypatch, capsys, failure):
    """Every drop/readback boundary is simulated; this test changes no credentials."""
    calls = []
    credentials = {"uid": 0, "gid": 0}

    def step(name, *args):
        calls.append(name)
        if name == failure:
            raise OSError("private diagnostic must not escape")
        if name in {"uid", "gid"}:
            credentials[name] = args[0]

    monkeypatch.setattr(
        observer_child, "sys", SimpleNamespace(platform="darwin", stderr=sys.stderr)
    )
    monkeypatch.setattr(
        observer_child,
        "os",
        SimpleNamespace(
            path=os.path,
            geteuid=lambda: 0 if failure == "readback" else credentials["uid"],
            getuid=lambda: credentials["uid"],
            getgid=lambda: credentials["gid"],
            getegid=lambda: credentials["gid"],
            setgroups=lambda value: step("groups", value),
            setgid=lambda value: step("gid", value),
            setuid=lambda value: step("uid", value),
            chdir=lambda value: step("cwd", value),
            umask=lambda value: step("umask", value),
            execve=lambda *args: step("exec", *args),
        ),
    )
    assert (
        observer_child.main(["1001", "20", "/example/home", "/example/container", "--version"])
        == 69
    )
    order = ["groups", "gid", "uid", "cwd", "umask", "exec"]
    expected = order[:3] if failure == "readback" else order[: order.index(failure) + 1]
    assert calls == expected
    assert capsys.readouterr().err == '{"error":"observer-bootstrap-or-credentials-unavailable"}\n'


def test_default_preflight_runner_keeps_partial_timeout_output_out_of_facts(monkeypatch):
    calls = []
    monkeypatch.setattr(macos_preflight.sys, "platform", "darwin")
    monkeypatch.setattr(macos_preflight.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(Path, "is_file", lambda _path: False)

    def unavailable(_path):
        raise OSError("unavailable baseline")

    def timed_out(argv, **kwargs):
        calls.append(argv)
        assert kwargs == {"timeout": 3.0, "max_output": macos_preflight.MAX_OUTPUT}
        raise process.ProcessTimeout("bounded", stdout=b"private partial output", stderr=b"secret")

    monkeypatch.setattr(macos_preflight, "_file_digest", unavailable)
    monkeypatch.setattr(macos_preflight, "run", timed_out)
    # Exercise collect_preflight's actual default adapter, not a substitute
    # high-level runner; only the final subprocess primitive is simulated.
    result = macos_preflight.collect_preflight(clock=lambda: 1.0, monotonic=lambda: 0.0)
    assert calls == [list(argv) for argv in macos_preflight.COMMANDS.values()]
    assert all(fact["state"] == "unknown" for fact in result["facts"])
    assert "private partial output" not in str(result) and "secret" not in str(result)

"""Proofs for documented runtime properties that no other test would miss.

Each test fails when the check it is named for is removed: the second half of
recovery, standard error with exit status zero, duplicate publications, flags a
recipe must not supply, the process-group kill and the probe's exit codes from
a real observation.
"""

from __future__ import annotations

import copy
import sys
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.codec import canonical_bytes, digest
from netorch.config import config_digest, profile_digest
from netorch.mock import mock_admissions
from netorch.process import OutputLimit, ProcessError, ProcessTimeout, Result, run
from netorch.runtime_settings import contract_digest, load_settings, settings_to_dict
from netorch.state import Intent, admissions_to_dict, intent_to_dict
from netorch.workloads import parse_workloads
from tests.test_apple_runtime import FakeRunner, enrolled

__all__ = ["enrolled"]

PIN = "example.invalid/service@sha256:" + "1" * 64
RESTARTED_HELPER = Result(
    0, b"state = running\npid = 222\nprogram = /usr/libexec/example-network\n", b""
)


class Scripted:
    """The shared fake runner with a hook at the start of each observation pass."""

    def __init__(
        self,
        inner: FakeRunner,
        *,
        at_pass: Callable[[int], None] | None = None,
        answer: Callable[[list[str], int], Result | None] | None = None,
    ) -> None:
        self.inner, self.at_pass, self.answer = inner, at_pass, answer
        self.passes = 0

    def __call__(self, argv: list[str], **kwargs: Any) -> Result:
        # Every observation pass begins with exactly one version read.
        if argv[1:] == ["--version"]:
            self.passes += 1
            if self.at_pass is not None:
                self.at_pass(self.passes)
        reply = self.answer(argv, self.passes) if self.answer is not None else None
        if reply is not None:
            self.inner.calls.append((argv, kwargs))
            return reply
        result: Result = self.inner(argv, **kwargs)
        return result

    def starts(self) -> list[list[str]]:
        return [argv for argv, _ in self.inner.calls if argv[1:2] == ["start"]]


def stopped() -> dict[str, Any]:
    return {"state": "stopped", "networks": []}


def stopped_camera(enrolled: Any) -> tuple[Any, Any, FakeRunner]:
    config, settings, items = enrolled
    inner = FakeRunner(settings, items)
    inner.items["example-camera"]["status"] = stopped()
    return config, settings, inner


def with_configuration(config: Any, settings: Any, service: str, value: Any) -> tuple[Any, Any]:
    """Enroll `value` as the service's native configuration and derive its policy hash."""
    contract = replace(settings.contract(service), configuration_sha256=digest(value))
    settings = replace(
        settings,
        contracts=tuple(contract if c.service == service else c for c in settings.contracts),
    )
    config = replace(
        config,
        services=tuple(
            replace(s, contract_sha256=contract_digest(contract)) if s.id == service else s
            for s in config.services
        ),
    )
    return config, settings


@pytest.mark.parametrize("second", ["running", "stopping"])
def test_recovery_needs_a_second_observation_that_still_proves_stopped(
    enrolled: Any, second: str
) -> None:
    config, settings, inner = stopped_camera(enrolled)

    def changed_before_second_pass(number: int) -> None:
        if number == 2:
            status = inner.items["example-camera"]["status"]
            status["state"] = second
            if second == "running":
                status["startedDate"] = "2026-01-01T00:00:09Z"
                status["networks"] = [
                    {
                        "network": "example-network",
                        "ipv4Address": "198.51.100.99/24",
                        "ipv4Gateway": "198.51.100.1",
                    }
                ]

    runner = Scripted(inner, at_pass=changed_before_second_pass)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert runner.passes == 2 and not runner.starts()


def test_recovery_needs_both_observations_in_one_network_generation(enrolled: Any) -> None:
    config, settings, inner = stopped_camera(enrolled)
    # The helper restarts between the passes. Each pass is complete and agrees
    # with itself, and the guest is stopped in both: only the generation differs.
    runner = Scripted(
        inner,
        answer=lambda argv, number: (
            RESTARTED_HELPER if argv[0] == "/bin/launchctl" and number >= 2 else None
        ),
    )
    first = runtime.observe_runtime(config, settings, inner)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert runner.passes == 2 and not runner.starts()
    second = runtime.observe_runtime(config, settings, runner)
    assert first.services["camera"].state == second.services["camera"].state == "absent"
    assert None not in {first.network_generation, second.network_generation}
    assert first.network_generation != second.network_generation


@pytest.mark.parametrize("hold", ["operator-pause", "suspension", "damaged"])
def test_recovery_rereads_intent_after_the_second_observation(enrolled: Any, hold: str) -> None:
    config, settings, inner = stopped_camera(enrolled)

    def held_before_second_pass(number: int) -> None:
        if number == 2:
            if hold == "damaged":
                Path(settings.intent).write_bytes(b"{")
                return
            intent = (
                Intent(operator_paused=True)
                if hold == "operator-pause"
                else Intent().suspend("backup", "backup-owner")
            )
            Path(settings.intent).write_bytes(canonical_bytes(intent_to_dict(intent)))

    runner = Scripted(inner, at_pass=held_before_second_pass)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert runner.passes == 2 and not runner.starts()


def test_recovery_needs_a_running_readback_after_the_start(enrolled: Any) -> None:
    config, settings, inner = stopped_camera(enrolled)
    # The vendor's `start` exits zero and the guest stays stopped.
    runner = Scripted(
        inner,
        answer=lambda argv, _number: Result(0, b"started", b"") if argv[1:2] == ["start"] else None,
    )
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert runner.starts() == [[settings.executable, "start", "example-camera"]]
    assert runner.passes == 3
    assert inner.items["example-camera"]["status"]["state"] == "stopped"


@pytest.mark.parametrize(
    "command,unknown",
    [
        (["--version"], None),
        (["list", "--all", "--format", "json"], None),
        (["network", "inspect", "example-network"], None),
        (["inspect", "example-camera"], {"camera"}),
        (["exec"], {"media-controller"}),
    ],
)
def test_native_standard_error_with_exit_zero_is_not_evidence(
    enrolled: Any, command: list[str], unknown: set[str] | None
) -> None:
    config, settings, items = enrolled
    inner = FakeRunner(settings, items)

    def noisy(argv: list[str], **kwargs: Any) -> Result:
        result: Result = inner(argv, **kwargs)
        if argv[0] == settings.executable and argv[1 : 1 + len(command)] == command:
            return replace(result, stderr=b"warning: partial result\n")
        return result

    result = runtime.observe_runtime(config, settings, noisy, clock=lambda: 1000)
    affected = set(result.services) if unknown is None else unknown
    assert {key for key, item in result.services.items() if item.state == "unknown"} == affected
    assert {result.services[key].reason for key in affected} == {"unavailable"}
    assert (result.network_generation is None) == (unknown is None)
    assert {item.state for key, item in result.services.items() if key not in affected} <= {
        "present"
    }


@pytest.mark.parametrize(
    "tool", ["/usr/sbin/sysctl", "/bin/launchctl", "/bin/ps", "/sbin/ifconfig"]
)
def test_platform_tool_standard_error_with_exit_zero_is_not_evidence(
    enrolled: Any, tool: str
) -> None:
    config, settings, items = enrolled
    inner = FakeRunner(settings, items)

    def noisy(argv: list[str], **kwargs: Any) -> Result:
        result: Result = inner(argv, **kwargs)
        return replace(result, stderr=b"warning\n") if argv[0] == tool else result

    result = runtime.observe_runtime(config, settings, noisy, clock=lambda: 1000)
    assert result.network_generation is None
    assert {(item.state, item.reason) for item in result.services.values()} == {
        ("unknown", "unavailable")
    }


def test_a_duplicate_native_publication_is_not_a_verified_publication(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    configuration = runner.items["example-camera"]["configuration"]
    configuration["publishedPorts"].append(copy.deepcopy(configuration["publishedPorts"][0]))
    config, settings = with_configuration(config, settings, "camera", configuration)
    # The enrollment changed with the configuration; admit the profiles again so
    # that only the publication itself can refuse the activation below.
    Path(settings.admissions).write_bytes(
        canonical_bytes(admissions_to_dict(mock_admissions(config)))
    )
    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert observed.services["camera"].state == "present"
    assert observed.profiles["camera-web"].state != "present"
    assert observed.profiles["camera-web"].generation is None
    profile = config.profile("camera-web")
    request = {
        "protocol_version": 1,
        "operation": "reconcile",
        "owner": settings.owner,
        "policy_digest": config_digest(config),
        "profile_digest": profile_digest(config, profile),
        "profile": profile.id,
        "action": "activate",
        "target_ipv4": observed.services["camera"].data["ipv4"],
        "target_generation": observed.services["camera"].generation,
    }
    with pytest.raises(runtime.RuntimeReadError) as refusal:
        runtime.handle_request(config, settings, request, runner)
    # Refused for the publication itself, not for a missing or stale admission.
    assert (
        isinstance(refusal.value, runtime.NativePublicationMaintenance)
        or refusal.value.reason != "incomplete"
    )


@pytest.mark.parametrize(
    "flag,value",
    [
        # Generated from enrollment and policy; a recipe states none of them.
        ("--name", "another-name"),
        ("--network", "another-network"),
        ("--platform", "linux/amd64"),
        ("--arch", "amd64"),
        ("--os", "linux"),
        ("--publish", "192.0.2.10:8080:80/tcp"),
        ("-p", "192.0.2.10:8080:80/tcp"),
        # Lifecycle: provisioning creates a definition and never removes one.
        ("--rm", None),
        ("--remove", None),
        ("--detach", None),
        # Writes the container id to a host path that no enrollment names.
        ("--cidfile", "/operator/run/container.id"),
    ],
)
def test_a_recipe_cannot_supply_a_generated_or_lifecycle_flag(flag: str, value: str | None) -> None:
    recipe = {
        "schema_version": 1,
        "workloads": [
            {
                "service": "example",
                "image": PIN,
                "options": [{"flag": flag, "value": value}],
                "arguments": [],
            }
        ],
    }
    with pytest.raises(ValueError, match="unsupported workload option"):
        parse_workloads(recipe)


DESCENDANT = """
import os, sys, time
if os.fork():
    os._exit(0)
path, flood = sys.argv[1], sys.argv[2] == "output"
for beat in range(250):
    with open(path + ".next", "w") as stream:
        stream.write(str(beat))
    os.replace(path + ".next", path)
    if flood and beat == 0:
        os.write(1, b"x" * 4096)
    time.sleep(0.02)
"""


@pytest.mark.parametrize(
    "bound,refusal,timeout", [("deadline", ProcessTimeout, 1.5), ("output", OutputLimit, 10)]
)
def test_a_bounded_command_leaves_no_descendant_running(
    tmp_path: Path, bound: str, refusal: type[ProcessError], timeout: float
) -> None:
    # The direct child exits at once; its descendant keeps the pipes and writes
    # a counter. Killing only the direct child would leave it counting.
    beat = tmp_path / "beat"
    with pytest.raises(refusal):
        run([sys.executable, "-c", DESCENDANT, str(beat), bound], timeout=timeout, max_output=1024)
    time.sleep(0.2)
    assert beat.exists(), "the descendant never started, so nothing was proven"
    first = beat.read_text()
    for _ in range(10):
        time.sleep(0.05)
        assert beat.read_text() == first


def test_probe_exit_codes_follow_real_observations(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    path = tmp_path / "runtime-settings.json"
    path.write_bytes(canonical_bytes(settings_to_dict(settings)))
    assert load_settings(path) == settings
    observe = runtime.observe_runtime
    monkeypatch.setattr(
        runtime, "observe_runtime", lambda config, settings: observe(config, settings, runner)
    )

    def probe(service: str) -> int:
        return runtime.main(["--settings", str(path), "probe", "--service", service])

    def intent(value: Intent) -> None:
        Path(settings.intent).write_bytes(canonical_bytes(intent_to_dict(value)))

    assert {probe(service.id) for service in config.services} == {0}
    runner.items["example-camera"]["status"] = stopped()
    assert probe("camera") == 42
    assert probe("resolver") == 0
    # A hold makes the same proven stop an inhibited recovery, for every service.
    intent(Intent(operator_paused=True))
    assert probe("camera") == probe("resolver") == 69
    intent(Intent())
    assert probe("camera") == 42
    # No tool answers within its bound: nothing is known, so nothing is stopped.
    runner.failure = "timeout"
    assert probe("camera") == 69
    runner.failure = None
    # A name missing from the inventory is not a stopped container.
    camera = runner.items.pop("example-camera")
    assert probe("camera") == 69
    assert probe("resolver") == 0
    runner.items["example-camera"] = camera
    # Every definition stopped looks like a restarted API service.
    for item in runner.items.values():
        item["status"] = stopped()
    assert {probe(service.id) for service in config.services} == {69}
    runner.items.clear()
    assert probe("camera") == 69
    assert probe("no-such-service") == 69
    assert not any(argv[1:2] == ["start"] for argv, _ in runner.calls)

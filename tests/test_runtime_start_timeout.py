"""Recovery can give the vendor `start` call its own bound.

Every vendor call is cut off after four seconds. A workload whose start takes
longer is cut off as a client while the vendor service may still finish. The
optional setting `start_timeout_seconds` bounds that one call; everything read
before and after it keeps the bounds it has, and settings without the key keep
their bytes. Fake runner and injected clock only; nothing waits.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.codec import canonical_bytes
from netorch.config import load_config
from netorch.process import ProcessTimeout, Result
from netorch.runtime_settings import load_settings, parse_settings, settings_to_dict
from netorch.workloads import parse_workloads, provision_digest, provision_workloads
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_workloads import fleet

__all__ = ["enrolled"]

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
START = 1000.0


class Recorded:
    """The shared fake runner; the clock can move while the `start` call runs."""

    def __init__(self, inner: FakeRunner, clock: list[float], start_takes: float = 0.0) -> None:
        self.inner, self.clock, self.start_takes = inner, clock, start_takes
        self.answer: Result | Exception | None = None

    def __call__(self, argv: list[str], **kwargs: Any) -> Result:
        if argv[1:2] == ["start"]:
            self.clock[0] += self.start_takes
            if self.answer is not None:
                self.inner.calls.append((argv, kwargs))
                if isinstance(self.answer, Exception):
                    raise self.answer
                return self.answer
        return self.inner(argv, **kwargs)

    def bounds(self, executable: str) -> tuple[list[float], list[float], list[float]]:
        """The bounds given to the start call, to other vendor calls and to system tools."""
        start, vendor, tools = [], [], []
        for argv, kwargs in self.inner.calls:
            if argv[0] != executable:
                tools.append(kwargs["timeout"])
            elif argv[1] == "start":
                start.append(kwargs["timeout"])
            else:
                vendor.append(kwargs["timeout"])
        return start, vendor, tools


def stopped_camera(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, seconds: int | None, start_takes: float = 0.0
) -> tuple[Any, Any, Recorded, list[float]]:
    config, settings, items = enrolled
    if seconds is not None:
        settings = replace(settings, start_timeout_seconds=seconds)
    clock = [START]
    monkeypatch.setattr(runtime.time, "monotonic", lambda: clock[0])
    inner = FakeRunner(settings, items)
    inner.items["example-camera"]["status"]["state"] = "stopped"
    return config, settings, Recorded(inner, clock, start_takes), clock


def test_start_deadline_default_is_four_seconds(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Settings as they are today, without the key: this holds before the change too.
    config, settings, runner, _clock = stopped_camera(enrolled, monkeypatch, None)
    result = runtime.recover_service(config, settings, "camera", runner)
    assert result.services["camera"].state == "present"
    start, vendor, tools = runner.bounds(settings.executable)
    assert start == [4]
    assert set(vendor) == {4} and set(tools) == {3}


def test_start_deadline_bounds_the_start_call_only(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The start takes 14 of its 15 seconds. That is longer than a whole read pass.
    config, settings, runner, clock = stopped_camera(enrolled, monkeypatch, 15, start_takes=14.0)
    result = runtime.recover_service(config, settings, "camera", runner)
    assert result.services["camera"].state == "present"
    assert clock[0] == START + 14.0
    start, vendor, tools = runner.bounds(settings.executable)
    assert start == [15]
    # Two observations before the start and the readback after it: every vendor
    # read keeps four seconds and every system tool three.
    assert set(vendor) == {4} and set(tools) == {3}
    assert sum(argv[1:] == ["--version"] for argv, _ in runner.inner.calls) == 3
    # The same call as before, with only the bound replaced.
    argv, kwargs = next(call for call in runner.inner.calls if call[0][1:2] == ["start"])
    assert argv == [settings.executable, "start", "example-camera"]
    assert kwargs == {
        "timeout": 15,
        "run_uid": settings.account.uid,
        "run_gid": settings.account.gid,
        "account_home": settings.account.home,
    }
    # A read pass is still eight seconds, whatever the setting says.
    reader = runtime.Reader(settings, runner)
    assert reader.deadline == clock[0] + 8
    clock[0] += 7.5
    reader.native(["--version"])
    assert runner.inner.calls[-1][1]["timeout"] == 0.5
    clock[0] += 0.5
    with pytest.raises(ProcessTimeout):
        reader.native(["--version"])
    with pytest.raises(ProcessTimeout):
        reader.tool(["/usr/sbin/sysctl", "-n", "kern.boottime"])


def test_start_deadline_reaches_no_other_command(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, settings, runner, _clock = stopped_camera(enrolled, monkeypatch, 120)
    runner.inner.items["example-camera"]["status"]["state"] = "running"
    assert runtime.observe_runtime(config, settings, runner).services["camera"].state == "present"
    assert runtime.capture_enrollment(settings, runner).start_timeout_seconds == 120
    start, vendor, tools = runner.bounds(settings.executable)
    assert not start and set(vendor) == {4} and set(tools) == {3}
    # Initial provisioning is another operation with another approval; its own
    # start call does not read the recovery setting.
    (tmp_path / "fleet").mkdir()
    policy, fleet_settings, fake, workloads, _store = fleet(tmp_path / "fleet")
    slow = replace(fleet_settings, start_timeout_seconds=120)
    fake.settings = slow
    approved = provision_digest(policy, slow, workloads, start_initial=True)
    # The setting is part of the settings an approval hashes.
    assert approved != provision_digest(policy, fleet_settings, workloads, start_initial=True)
    provision_workloads(
        policy, slow, workloads, expected_digest=approved, start_initial=True, runner=fake
    )
    started = [kwargs["timeout"] for argv, kwargs in fake.calls if argv[1:2] == ["start"]]
    assert len(started) == len(workloads) and set(started) == {4}


@pytest.mark.parametrize("outcome", ["cut off", "standard error", "exit status", "not running"])
def test_a_longer_bound_does_not_weaken_the_result_check(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    config, settings, runner, _clock = stopped_camera(enrolled, monkeypatch, 60)
    expected: type[Exception] = runtime.RuntimeReadError
    if outcome == "cut off":
        runner.answer, expected = ProcessTimeout("bounded"), ProcessTimeout
    elif outcome == "standard error":
        runner.answer = Result(0, b"started", b"warning")
    elif outcome == "exit status":
        runner.answer = Result(1, b"", b"")
    else:
        # The client reports success and the workload is still stopped.
        runner.answer = Result(0, b"started", b"")
    with pytest.raises(expected):
        runtime.recover_service(config, settings, "camera", runner)
    calls = runner.inner.calls
    index = next(i for i, call in enumerate(calls) if call[0][1:2] == ["start"])
    assert calls[index][1]["timeout"] == 60
    # A failed call is the end; only a call that reported success is read back,
    # and then the readback decides.
    assert (len(calls) > index + 1) == (outcome == "not running")


def _authored() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "owner": "camera-manager",
        "executable": "/usr/bin/example-container",
        "accepted_version": "1.5.0",
        "account": {"uid": 1001, "gid": 1001, "home": "/private/operator"},
        "networks": [
            {
                "scope": "wired-lan",
                "name": "test-network",
                "gateway": "198.51.100.1",
                "helper_domain": "gui/1001",
                "helper_label": ".".join(["org", "example", "network"]),
                "helper_executable": "/usr/libexec/example-network",
                "helper_uid": 1001,
            }
        ],
        "contracts": [
            {
                "service": "camera",
                "name": "example-camera",
                "scope": "wired-lan",
                "configuration_sha256": "a" * 64,
                "mounts": [
                    {
                        "path": "/private/volumes/camera",
                        "kind": "directory",
                        "uid": 1001,
                        "device": 1,
                        "inode": 2,
                    },
                    {"path": "/private/runtime/api.sock", "kind": "socket", "uid": 1001},
                ],
                "receipts": [
                    {
                        "path": "/private/receipts/camera.json",
                        "kind": "file",
                        "uid": 1001,
                        "device": 1,
                        "inode": 3,
                        "sha256": "b" * 64,
                    }
                ],
            }
        ],
        "policy": "/private/network.json",
        "admissions": "/private/admissions.json",
        "intent": "/private/state/intent.json",
        "state_dir": "/private/state/runtime",
    }


def test_settings_without_start_deadline_keep_their_bytes() -> None:
    """Every literal below was computed with the tree this change is based on."""
    settings = parse_settings(_authored())
    stored = canonical_bytes(settings_to_dict(settings))
    assert b"start_timeout_seconds" not in stored
    assert (
        hashlib.sha256(stored).hexdigest()
        == "756bc5a72017441d664b0ae0ee5992e97e1cea4f49e9716e225b42ecc2aee218"
    )
    shipped = load_settings(EXAMPLES / "runtime-settings.json")
    assert (
        hashlib.sha256(canonical_bytes(settings_to_dict(shipped))).hexdigest()
        == "d1307ffc7cb45fb28b71c4cd190e57a4f8548b76b28a66fad9c4eec52cc28ab8"
    )
    # The stored settings are hashed whole into every approved initial provision.
    recipe = parse_workloads(
        {
            "schema_version": 1,
            "workloads": [
                {
                    "service": item.service,
                    "image": f"example.invalid/containers/{item.service}@sha256:" + "0" * 64,
                    "options": [{"flag": "--volume", "value": f"{item.mounts[0].path}:/config:rw"}],
                    "arguments": [],
                }
                for item in shipped.contracts
            ],
        }
    )
    policy = load_config(EXAMPLES / "network.json")
    assert (
        provision_digest(policy, shipped, recipe)
        == "e1cc07334052affe353a6e2c1bf457c02330fe322c3c242c4c959d4f10a265ac"
    )
    assert (
        provision_digest(policy, shipped, recipe, start_initial=True)
        == "d160cf33f2d57008921105f33e80cd83501c630bed9760c98a490bceca99178d"
    )


def test_settings_with_start_deadline_store_it_as_one_number() -> None:
    settings = parse_settings(_authored())
    assert settings.start_timeout_seconds is None
    document = _authored()
    document["start_timeout_seconds"] = 15
    bounded = parse_settings(document)
    assert bounded == replace(settings, start_timeout_seconds=15)
    assert settings_to_dict(bounded) == {**settings_to_dict(settings), "start_timeout_seconds": 15}
    assert parse_settings(settings_to_dict(bounded)) == bounded


@pytest.mark.parametrize("seconds", [1, 4, 15, 120])
def test_start_deadline_accepts_whole_seconds_from_1_to_120(seconds: int) -> None:
    document = _authored()
    document["start_timeout_seconds"] = seconds
    assert parse_settings(document).start_timeout_seconds == seconds


@pytest.mark.parametrize(
    "value",
    [0, 121, -1, 10**6, True, False, None, "15", 15.0, 1.5, [15], {"seconds": 15}],
    ids=repr,
)
def test_start_deadline_refuses_everything_else(value: Any) -> None:
    document = _authored()
    document["start_timeout_seconds"] = value
    with pytest.raises(ValueError):
        parse_settings(document)

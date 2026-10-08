"""A workload's contract can state its own bound for the vendor `start` call.

The runtime settings bound that call once for the installation. A site whose
workloads need different times had to give every workload the longest one, and
each start that hangs then holds the operation lock that long. The optional
member `start_timeout_seconds` of one service contract bounds the start of that
workload alone: recovery uses the contract's value, else the installation's,
else the reader's four seconds. Nothing else of recovery moves, and a contract
without the member keeps its bytes and its digest. Fake runner and injected
clock only; nothing waits.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch import instance as instance_module
from netorch.codec import canonical_bytes, digest
from netorch.config import load_config
from netorch.model import Config
from netorch.process import ProcessTimeout, Result
from netorch.runtime_settings import (
    RuntimeSettings,
    contract_digest,
    load_settings,
    parse_settings,
    settings_to_dict,
)
from netorch.workloads import parse_workloads, provision_digest, provision_workloads
from tests.test_apple_runtime import enrolled
from tests.test_report_truthfulness import parsed
from tests.test_runtime_start_timeout import START, Recorded, stopped_camera
from tests.test_workloads import fleet

__all__ = ["enrolled"]

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
MEDIA = "media-controller"


def stated(
    config: Config, settings: RuntimeSettings, bounds: dict[str, int]
) -> tuple[Config, RuntimeSettings]:
    """The enrollment with a start bound in the named contracts, and its derived policy."""
    contracts = tuple(
        replace(item, start_timeout_seconds=bounds[item.service])
        if item.service in bounds
        else item
        for item in settings.contracts
    )
    settings = replace(settings, contracts=contracts)
    # A stated bound is part of the contract, so the policy carries another hash.
    return runtime.derive_policy(config, settings), settings


def start_calls(runner: Recorded) -> list[tuple[str, float]]:
    return [
        (argv[2], kwargs["timeout"])
        for argv, kwargs in runner.inner.calls
        if argv[1:2] == ["start"]
    ]


@pytest.mark.parametrize(
    ("own", "installation", "expected"),
    [
        (None, None, 4),
        (None, 15, 15),
        (40, None, 40),
        (40, 15, 40),
        # The contract's value wins in both directions, not only when it is longer.
        (2, 15, 2),
    ],
)
def test_the_contract_bound_precedes_the_installation_bound_and_the_reader(
    enrolled: Any,
    monkeypatch: pytest.MonkeyPatch,
    own: int | None,
    installation: int | None,
    expected: int,
) -> None:
    config, settings, runner, _clock = stopped_camera(enrolled, monkeypatch, installation)
    if own is not None:
        config, settings = stated(config, settings, {"camera": own})
    result = runtime.recover_service(config, settings, "camera", runner)
    assert result.services["camera"].state == "present"
    assert start_calls(runner) == [("example-camera", expected)]
    start, vendor, tools = runner.bounds(settings.executable)
    assert start == [expected]
    assert set(vendor) == {4} and set(tools) == {3}


@pytest.mark.parametrize(("installation", "other"), [(None, 4), (15, 15)])
def test_only_the_start_of_that_workload_gets_its_bound(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, installation: int | None, other: int
) -> None:
    config, settings, runner, clock = stopped_camera(
        enrolled, monkeypatch, installation, start_takes=39.0
    )
    config, settings = stated(config, settings, {"camera": 40})
    runner.inner.items["example-" + MEDIA]["status"]["state"] = "stopped"
    # The start takes 39 of its 40 seconds: far longer than a whole read pass.
    first = runtime.recover_service(config, settings, "camera", runner)
    assert first.services["camera"].state == "present"
    assert clock[0] == START + 39.0
    # The same call as before, with only the bound replaced.
    argv, kwargs = next(call for call in runner.inner.calls if call[0][1:2] == ["start"])
    assert argv == [settings.executable, "start", "example-camera"]
    assert kwargs == {
        "timeout": 40,
        "run_uid": settings.account.uid,
        "run_gid": settings.account.gid,
        "account_home": settings.account.home,
    }
    # Another workload of the same installation does not inherit that bound.
    runner.start_takes = 0.0
    second = runtime.recover_service(config, settings, MEDIA, runner)
    assert second.services[MEDIA].state == "present"
    assert start_calls(runner) == [("example-camera", 40), ("example-" + MEDIA, other)]
    # Two observations before each start and the readback after it: every vendor
    # read keeps four seconds and every system tool three.
    _start, vendor, tools = runner.bounds(settings.executable)
    assert set(vendor) == {4} and set(tools) == {3}
    assert sum(argv[1:] == ["--version"] for argv, _ in runner.inner.calls) == 6
    # A read pass is still eight seconds, whatever a contract says.
    reader = runtime.Reader(settings, runner)
    assert reader.deadline == clock[0] + 8
    clock[0] += 8
    with pytest.raises(ProcessTimeout):
        reader.native(["--version"])


def test_a_contract_bound_reaches_no_other_command(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, settings, runner, _clock = stopped_camera(enrolled, monkeypatch, None)
    config, settings = stated(config, settings, {"camera": 120})
    runner.inner.items["example-camera"]["status"]["state"] = "running"
    assert runtime.observe_runtime(config, settings, runner).services["camera"].state == "present"
    # Enrollment keeps the authored bound and makes no call with it.
    captured = runtime.capture_enrollment(settings, runner)
    assert captured.contract("camera").start_timeout_seconds == 120
    assert captured.contract(MEDIA).start_timeout_seconds is None
    start, vendor, tools = runner.bounds(settings.executable)
    assert not start and set(vendor) == {4} and set(tools) == {3}
    # Initial provisioning is another operation with another approval; its own
    # start call reads neither the installation's bound nor a contract's.
    (tmp_path / "fleet").mkdir()
    policy, fleet_settings, fake, workloads, _store = fleet(tmp_path / "fleet")
    slow = replace(
        fleet_settings,
        contracts=tuple(
            replace(item, start_timeout_seconds=120) for item in fleet_settings.contracts
        ),
    )
    fake.settings = slow
    approved = provision_digest(policy, slow, workloads, start_initial=True)
    # The contracts are part of the settings an approval hashes.
    assert approved != provision_digest(policy, fleet_settings, workloads, start_initial=True)
    provision_workloads(
        policy, slow, workloads, expected_digest=approved, start_initial=True, runner=fake
    )
    started = [kwargs["timeout"] for argv, kwargs in fake.calls if argv[1:2] == ["start"]]
    assert len(started) == len(workloads) and set(started) == {4}


@pytest.mark.parametrize("outcome", ["cut off", "standard error", "exit status", "not running"])
def test_a_longer_contract_bound_does_not_weaken_the_result_check(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    config, settings, runner, _clock = stopped_camera(enrolled, monkeypatch, 15)
    config, settings = stated(config, settings, {"camera": 60})
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
    # A failed call is the end; only a call that reported success is read back.
    assert (len(calls) > index + 1) == (outcome == "not running")


def test_a_stated_bound_does_not_change_what_recovery_requires(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, settings, runner, _clock = stopped_camera(enrolled, monkeypatch, None)
    config, settings = stated(config, settings, {"camera": 90})
    # A running workload is not started, however long its start may take.
    runner.inner.items["example-camera"]["status"]["state"] = "running"
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert not start_calls(runner)
    # A policy derived before the bound was stated does not cover the contract.
    runner.inner.items["example-camera"]["status"]["state"] = "stopped"
    earlier = enrolled[0]
    snapshot = runtime.observe_runtime(earlier, settings, runner)
    assert (snapshot.services["camera"].state, snapshot.services["camera"].reason) == (
        "unknown",
        "identity-mismatch",
    )
    assert snapshot.services[MEDIA].state == "present"
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(earlier, settings, "camera", runner)
    assert not start_calls(runner)


def _authored() -> dict[str, Any]:
    """Every member that could be written before this one, in both enrollment forms."""
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
            },
            {
                "service": MEDIA,
                "name": "example-media",
                "scope": "wired-lan",
                "configuration_sha256": "c" * 64,
                "mounts": [
                    {
                        "path": "/private/volumes/media",
                        "kind": "directory",
                        "uid": 1001,
                        "inode": 5,
                        "volume_uuid": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
                    }
                ],
                "tolerated_stopped_peers": ["example-media-test"],
            },
        ],
        "policy": "/private/network.json",
        "admissions": "/private/admissions.json",
        "intent": "/private/state/intent.json",
        "state_dir": "/private/state/runtime",
        "start_timeout_seconds": 15,
    }


def test_contracts_without_a_start_bound_keep_their_bytes_and_digests() -> None:
    """Every literal below was computed with the tree this change is based on."""
    settings = parse_settings(_authored())
    stored = canonical_bytes(settings_to_dict(settings))
    # The installation's bound is the only one in these bytes.
    assert stored.count(b"start_timeout_seconds") == 1
    assert (
        hashlib.sha256(stored).hexdigest()
        == "6be7e2b72d1036327da1af38c6f409f0f01294892142fef9915959d272ffc9a5"
    )
    assert {item.service: contract_digest(item) for item in settings.contracts} == {
        "camera": "6aebeced64e17d06b35bd73f3a0b616850c5b49168545bbadf30207ecfeb345d",
        MEDIA: "ec32075c9cb15f66ab94a8f15d78d39089ab80c3d74fd6662fb5e6f91e6db41c",
    }
    shipped = load_settings(EXAMPLES / "runtime-settings.json")
    assert (
        hashlib.sha256(canonical_bytes(settings_to_dict(shipped))).hexdigest()
        == "d1307ffc7cb45fb28b71c4cd190e57a4f8548b76b28a66fad9c4eec52cc28ab8"
    )
    assert {item.service: contract_digest(item) for item in shipped.contracts} == {
        "resolver": "738717b976875cab43dc7235150aebbaa3b894a4904c86334dcd9d63250ee153",
        "web-proxy": "afcfdc49c1a7fd7b435a54f1cb75b32fb48fb3ea1865f3e31b4b854081bb5508",
        MEDIA: "0067741a703af180b7fac6e0be8d1880699e1db21517ff09d047cfa83d479d19",
        "camera": "07b9fec3b2403f238c5b4689d80815a7bdb0913a1e887c5fb4228a7fc8cc3f45",
    }
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


def test_a_stated_bound_is_one_more_member_of_the_same_enrollment_form() -> None:
    plain = parse_settings(_authored())
    document = _authored()
    document["contracts"][0]["start_timeout_seconds"] = 40
    document["contracts"][1]["start_timeout_seconds"] = 90
    bounded = parse_settings(document)
    assert bounded.start_timeout_seconds == plain.start_timeout_seconds == 15
    assert [item.start_timeout_seconds for item in plain.contracts] == [None, None]
    assert [item.start_timeout_seconds for item in bounded.contracts] == [40, 90]
    # One number in the contract that states it; the stored form reads back equal.
    assert settings_to_dict(bounded)["contracts"] == [
        {**settings_to_dict(plain)["contracts"][0], "start_timeout_seconds": 40},
        {**settings_to_dict(plain)["contracts"][1], "start_timeout_seconds": 90},
    ]
    assert parse_settings(settings_to_dict(bounded)) == bounded
    assert all("start_timeout_seconds" not in item for item in settings_to_dict(plain)["contracts"])
    # The complete digest input. A bound is no other way to verify an enrollment:
    # each contract keeps the strategy of its identity binding, and the member
    # alone keeps the digest apart from that of the contract without it.
    assert contract_digest(bounded.contract("camera")) == digest(
        {
            "strategy": "apple-runtime-enrollment-v1",
            "contract": {
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
                        "sha256": None,
                    },
                    {
                        "path": "/private/runtime/api.sock",
                        "kind": "socket",
                        "uid": 1001,
                        "device": None,
                        "inode": None,
                        "sha256": None,
                    },
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
                "start_timeout_seconds": 40,
            },
        }
    )
    assert contract_digest(bounded.contract(MEDIA)) == digest(
        {
            "strategy": "apple-runtime-enrollment-v2",
            "contract": {
                "service": MEDIA,
                "name": "example-media",
                "scope": "wired-lan",
                "configuration_sha256": "c" * 64,
                "mounts": [
                    {
                        "path": "/private/volumes/media",
                        "kind": "directory",
                        "uid": 1001,
                        "device": None,
                        "inode": 5,
                        "sha256": None,
                        "volume_uuid": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
                    }
                ],
                "receipts": [],
                "tolerated_stopped_peers": ["example-media-test"],
                "start_timeout_seconds": 90,
            },
        }
    )
    # Stating, changing and removing the bound each give another contract.
    document["contracts"][0]["start_timeout_seconds"] = 41
    changed = parse_settings(document)
    digests = {contract_digest(item.contract("camera")) for item in (plain, bounded, changed)}
    assert len(digests) == 3
    assert contract_digest(changed.contract(MEDIA)) == contract_digest(bounded.contract(MEDIA))


def test_a_stated_bound_equal_to_the_readers_own_is_stated_all_the_same() -> None:
    """Four seconds written down is a member: it is stored and it is hashed."""
    plain = parse_settings(_authored())
    document = _authored()
    document["contracts"][0]["start_timeout_seconds"] = 4
    four = parse_settings(document)
    assert four.contract("camera").start_timeout_seconds == 4
    stored = settings_to_dict(four)
    assert stored["contracts"][0] == {
        **settings_to_dict(plain)["contracts"][0],
        "start_timeout_seconds": 4,
    }
    assert parse_settings(stored) == four
    # Computed with this change. It is not the digest of the contract without
    # the member, whose literal the test of the unchanged bytes pins.
    assert (
        contract_digest(four.contract("camera"))
        == "63f54700c99a9230e6158c566354075ada7b749a3dd864177200619a17f3fdbf"
    )
    assert contract_digest(four.contract("camera")) != contract_digest(plain.contract("camera"))
    # No value is another spelling of "not stated": each is stored and hashed.
    digests = {contract_digest(plain.contract("camera"))}
    for seconds in range(1, 121):
        document["contracts"][0]["start_timeout_seconds"] = seconds
        settings = parse_settings(document)
        assert settings_to_dict(settings)["contracts"][0]["start_timeout_seconds"] == seconds
        digests.add(contract_digest(settings.contract("camera")))
    assert len(digests) == 121


def test_a_stated_bound_changes_the_derived_policy_of_that_service_only(enrolled: Any) -> None:
    config, settings, _items = enrolled
    derived, bounded = stated(config, settings, {"camera": 40})
    before = {item.id: item.contract_sha256 for item in config.services}
    after = {item.id: item.contract_sha256 for item in derived.services}
    assert {key for key in before if before[key] != after[key]} == {"camera"}
    assert after["camera"] == contract_digest(bounded.contract("camera"))
    # The installation's bound is no part of any contract.
    assert runtime.derive_policy(config, replace(settings, start_timeout_seconds=40)) == config


@pytest.mark.parametrize("seconds", [1, 4, 15, 120])
def test_a_contract_accepts_whole_seconds_from_1_to_120(seconds: int) -> None:
    document = _authored()
    document["contracts"][0]["start_timeout_seconds"] = seconds
    settings = parse_settings(document)
    assert settings.contract("camera").start_timeout_seconds == seconds
    assert type(settings.contract("camera").start_timeout_seconds) is int
    # Neither place speaks for the other.
    assert settings.start_timeout_seconds == 15
    assert settings.contract(MEDIA).start_timeout_seconds is None
    del document["start_timeout_seconds"]
    alone = parse_settings(document)
    assert alone.start_timeout_seconds is None
    assert alone.contract("camera").start_timeout_seconds == seconds


@pytest.mark.parametrize(
    "value",
    [0, 121, -1, 10**6, True, False, None, "15", 15.0, 1.5, [15], {"seconds": 15}],
    ids=repr,
)
def test_a_contract_refuses_every_other_start_bound(value: Any) -> None:
    document = _authored()
    document["contracts"][1]["start_timeout_seconds"] = value
    with pytest.raises(ValueError):
        parse_settings(document)
    # The other contract and the installation are not what was refused.
    del document["contracts"][1]["start_timeout_seconds"]
    document["contracts"][0]["start_timeout_seconds"] = 15
    assert parse_settings(document).contract("camera").start_timeout_seconds == 15


@pytest.fixture
def data() -> dict[str, Any]:
    return json.loads((EXAMPLES / "instance.json").read_bytes())


@pytest.mark.parametrize(
    ("site", "own", "expected"),
    [
        # A workload's own deadline is honoured whether or not the site states one.
        (None, 1, ()),
        (None, 120, ()),
        (30, 90, ()),
        (120, 1, ()),
        (30, 30, ()),
        # Only what no start bound can say remains.
        (None, 121, ("/workloads/0/deadlines/action_seconds",)),
        (120, 300, ("/workloads/0/deadlines/action_seconds",)),
        (121, 40, ("/supervision/action_timeout_seconds",)),
    ],
)
def test_a_workloads_own_action_deadline_within_the_bound_is_no_gap(
    data: dict[str, Any], site: int | None, own: int, expected: tuple[str, ...]
) -> None:
    changed = copy.deepcopy(data)
    if site is not None:
        changed["supervision"]["action_timeout_seconds"] = site
    changed["workloads"][0]["deadlines"] = {"action_seconds": own}
    assert tuple(instance_module.retained_supervision_gaps(parsed(changed))) == expected


def test_the_instance_bound_is_the_bound_of_a_contract() -> None:
    """What the gaps function calls honoured is what a contract can be told."""
    maximum = instance_module.RETAINED_ACTION_DEADLINE_MAXIMUM
    assert maximum == 120
    document = _authored()
    document["contracts"][0]["start_timeout_seconds"] = maximum
    assert parse_settings(document).contract("camera").start_timeout_seconds == maximum
    document["contracts"][0]["start_timeout_seconds"] = maximum + 1
    with pytest.raises(ValueError, match="start timeout"):
        parse_settings(document)

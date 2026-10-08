"""One complete read of the fleet has a stated bound instead of a fixed eight seconds.

A read of the runtime is a few dozen short processes, and every reader gave the
whole of it eight seconds. A read that ran out of time was unknown: the probe
started nothing and the root owner retired every rule. The optional setting
`read_timeout_seconds` states the bound of one read; without it every call, bound
and outcome is what it was, and the stored settings keep their bytes. A single
call keeps its own bound either way, and the owner endpoint keeps eight seconds
because its clients wait ten.

Fake runner and an injected clock only: a call "takes time" by moving the clock,
and a call that would take as long as its bound is cut off there. Nothing waits.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch import owners
from netorch import pf_owner as owner
from netorch import runtime_settings as loader
from netorch.codec import canonical_bytes, digest, strict_loads
from netorch.config import config_digest, load_config, to_dict
from netorch.model import Service
from netorch.pf_owner import STRATEGY, Installation, admit, reconcile
from netorch.process import ProcessTimeout, Result
from netorch.runtime_settings import (
    FileIdentity,
    RuntimeContract,
    RuntimeSettings,
    contract_digest,
    load_settings,
    parse_settings,
    settings_to_dict,
)
from netorch.safety_contract import assess_bounded_safety
from netorch.state import Intent, Snapshot, intent_to_dict
from netorch.storage import Store
from netorch.workloads import (
    parse_workloads,
    plan_workloads,
    provision_digest,
    provision_workloads,
)
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_pf_owner import FakeBackend
from tests.test_runtime_fleet_start import declared
from tests.test_workloads import fleet

__all__ = ["enrolled"]

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
# Not a whole second, and every step below is a binary fraction: sums are exact.
START = 1000.25
# Invented workloads beside the four of the example policy.
EXTRA = ("archive", "console", "ledger", "relay")
# The least and the greatest bound that can be stated; the least is today's.
LEAST, GREATEST = 8, 118
# In a parameter list: every workload of the fleet.
ALL = ("*",)


def named(argv: list[str], executable: str) -> str:
    """One call without what differs between machines: the tool and its verb."""
    if argv[0] == executable:
        return "vendor " + argv[1]
    return argv[0].rsplit("/", 1)[1]


class Paced:
    """A fake runner whose calls take time on the injected clock.

    Each call moves the clock by `step`. One that would take as long as its bound
    is cut off at the bound and answers nothing, as the real runner does. ACL
    reads, which are `ls` processes on macOS, are recorded the same way and take
    `acl_step`.
    """

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        inner: Any,
        *,
        step: float = 0.0,
        acl_step: float = 0.0,
        clock: list[float] | None = None,
    ) -> None:
        self.inner, self.step, self.acl_step = inner, step, acl_step
        self.clock = [START] if clock is None else clock
        self.calls: list[tuple[str, float]] = []
        self.acl: list[tuple[str, float]] = []
        monkeypatch.setattr(runtime.time, "monotonic", lambda: self.clock[0])
        monkeypatch.setattr(runtime, "reject_acl", self._acl)

    def _spend(self, step: float, bound: float) -> None:
        if step >= bound:
            self.clock[0] += bound
            raise ProcessTimeout("cut off at its bound")
        self.clock[0] += step

    def _acl(self, path: Path, *, timeout: float) -> None:
        self.acl.append((str(path), timeout))
        self._spend(self.acl_step, timeout)

    def __call__(self, argv: list[str], **kwargs: Any) -> Result:
        self.calls.append((named(argv, self.inner.settings.executable), kwargs["timeout"]))
        self._spend(self.step, kwargs["timeout"])
        result: Result = self.inner(argv, **kwargs)
        return result

    @property
    def elapsed(self) -> float:
        return self.clock[0] - START

    def bounds(self, *names: str) -> list[float]:
        return [bound for name, bound in self.calls if name in names]


def with_bound(settings: RuntimeSettings, seconds: int | None) -> RuntimeSettings:
    """The settings as the closed loader reads them with the member stated."""
    document = settings_to_dict(settings)
    if seconds is not None:
        document["read_timeout_seconds"] = seconds
    return parse_settings(document)


def acl_paths(paced: Paced) -> int:
    """The number of different paths whose ACL a pass read."""
    return len({path for path, _ in paced.acl})


def states(snapshot: Any) -> set[tuple[str, str]]:
    return {(item.state, item.reason) for item in snapshot.services.values()}


def sized(enrolled: Any, count: int) -> tuple[Any, Any, dict[str, Any]]:
    """The enrolled fixture with one, four or eight workloads, one mount each."""
    config, settings, items = enrolled
    if count == 4:
        return config, settings, items
    if count == 1:
        keep = {"camera"}
        contracts = tuple(item for item in settings.contracts if item.service in keep)
        return (
            replace(
                config,
                services=tuple(item for item in config.services if item.id in keep),
                profiles=tuple(item for item in config.profiles if item.service in keep),
                discovery=tuple(item for item in config.discovery if item.service in keep),
            ),
            replace(settings, contracts=contracts),
            {contract.name: items[contract.name] for contract in contracts},
        )
    assert count == 8
    home = Path(settings.account.home)
    contracts, services, grown = list(settings.contracts), list(config.services), dict(items)
    for index, name in enumerate(EXTRA):
        directory = (home / name).resolve()
        directory.mkdir(mode=0o700)
        meta = directory.stat()
        configuration = {
            "id": "example-" + name,
            "runtimeHandler": "container-runtime-linux",
            "mounts": [{"source": str(directory), "options": ["rw"]}],
            "publishedPorts": [],
            "cpus": 2,
            "memory": 1024,
        }
        contract = RuntimeContract(
            name,
            "example-" + name,
            "wired-lan",
            digest(configuration),
            (
                FileIdentity(
                    str(directory), "directory", settings.account.uid, meta.st_dev, meta.st_ino
                ),
            ),
        )
        contracts.append(contract)
        services.append(Service(name, settings.owner, contract_digest(contract)))
        grown[contract.name] = {
            "id": contract.name,
            "configuration": configuration,
            "status": {
                "state": "running",
                "startedDate": "2026-01-01T00:00:00Z",
                "networks": [
                    {
                        "network": "example-network",
                        "ipv4Address": f"198.51.100.{index + 20}/24",
                        "ipv4Gateway": "198.51.100.1",
                    }
                ],
            },
        }
    return (
        replace(config, services=tuple(services)),
        replace(settings, contracts=tuple(contracts)),
        grown,
    )


# --- What one read costs ------------------------------------------------------


@pytest.mark.parametrize(
    "count,stopped,calls",
    [
        # Everything runs: 11 calls for the pass itself, one inspection for each
        # workload, one more for the workload with an automatic port range.
        (1, (), 12),
        (4, (), 16),
        (8, (), 20),
        # A stopped row needs three independent guest-job reads, less the
        # port-range read where it is the stopped one.
        (4, ("example-camera",), 19),
        (4, ("example-media-controller",), 18),
        (8, ("example-relay",), 23),
        # Every workload is stopped: the all-stopped guard ends the pass after
        # the inventory, whatever the size of the fleet.
        (1, ("example-camera",), 7),
        (4, ALL, 7),
        (8, ALL, 7),
    ],
)
def test_one_read_makes_this_many_calls(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, count: int, stopped: tuple[str, ...], calls: int
) -> None:
    """A measured pass, including mandatory independent stopped-job evidence."""
    config, settings, items = sized(enrolled, count)
    inner = FakeRunner(settings, items)
    stopped = tuple(inner.items) if stopped is ALL else stopped
    for name in stopped:
        inner.items[name]["status"]["state"] = "stopped"
    paced = Paced(monkeypatch, inner)
    observed = runtime.observe_runtime(config, settings, paced)
    assert len(paced.calls) == calls
    if count == len(stopped):
        assert states(observed) == {("unknown", "incomplete")}
        assert not paced.acl
        return
    assert sorted(item.state for item in observed.services.values()) == sorted(
        ["absent"] * len(stopped) + ["present"] * (count - len(stopped))
    )
    # Every directory on the way to a mount is read once per pass, and each
    # mount once: on macOS each of these is one more process. (Paths are
    # counted: a directory that something else changes during the pass is read
    # again, which is what the cache is for.)
    assert acl_paths(paced) == len(Path(settings.contracts[0].mounts[0].path).parents) + count
    vendor = [name for name, _ in paced.calls if name.startswith("vendor ")]
    # Version, the network twice, the inventory, then the per-workload reads.
    assert len(vendor) == calls - 7 - 3 * len(stopped)


@pytest.mark.parametrize(
    "count,stopped,calls",
    [(1, False, 16), (4, False, 20), (8, False, 24), (1, True, 19), (4, True, 31), (8, True, 47)],
)
def test_one_read_with_the_fleet_start_evidence(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, count: int, stopped: bool, calls: int
) -> None:
    """Four more calls for the API job, and three for each guest listed as stopped."""
    config, settings, inner = declared(sized(enrolled, count))
    if stopped:
        inner.stop_everything()
    paced = Paced(monkeypatch, inner)
    observed = runtime.observe_runtime(config, settings, paced)
    expected = ("absent", "confirmed-absent") if stopped else ("present", "verified")
    assert states(observed) == {expected}
    assert len(paced.calls) == calls
    assert acl_paths(paced) == len(Path(settings.contracts[0].mounts[0].path).parents) + count


# --- Without the member nothing moves ----------------------------------------

# One read of the four example workloads in which every call takes 0.4375
# seconds, on the tree this change is based on: each call with the bound it was
# given. From the eleventh call on the pass has less left than a call's own cap.
BASE_READ = [
    ("vendor --version", 4),
    ("sysctl", 3),
    ("launchctl", 3),
    ("ps", 3),
    ("vendor network", 4),
    ("ifconfig", 3),
    ("vendor list", 4),
    ("vendor inspect", 4),
    ("vendor inspect", 4),
    ("vendor inspect", 4),
    ("vendor exec", 3.625),
    ("vendor inspect", 3.1875),
    ("launchctl", 2.75),
    ("ps", 2.3125),
    ("vendor network", 1.875),
    ("ifconfig", 1.4375),
]
# The same for a whole recovery of one stopped workload, 0.125 seconds a call:
# SHA-256 of the list of calls and bounds, taken on that tree.
BASE_RECOVERY = "1955c134e0d5e1bbdf5ed6ae442e5899db2e0e9dfe65d943164365c285ec9337"


def test_without_the_member_a_read_is_the_read_it_was(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, settings, items = enrolled
    assert "read_timeout_seconds" not in settings_to_dict(settings)
    paced = Paced(monkeypatch, FakeRunner(settings, items), step=0.4375)
    observed = runtime.observe_runtime(config, settings, paced)
    assert paced.calls == BASE_READ
    assert paced.elapsed == 7.0 and states(observed) == {("present", "verified")}
    # Each ACL read has two seconds or what is left of the pass, as before.
    assert {bound for _, bound in paced.acl} == {2.0}
    # One call more, and the pass no longer fits into eight seconds.
    slower = Paced(monkeypatch, FakeRunner(settings, items), step=0.5)
    assert states(runtime.observe_runtime(config, settings, slower)) == {("unknown", "timed-out")}
    assert slower.calls[-1] == ("ifconfig", 0.5) and slower.elapsed == 8.0


def test_default_recovery_includes_independent_stopped_job_reads(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, settings, items = enrolled
    inner = FakeRunner(settings, items)
    inner.items["example-camera"]["status"]["state"] = "stopped"
    paced = Paced(monkeypatch, inner, step=0.125)
    result = runtime.recover_service(config, settings, "camera", paced)
    assert result.services["camera"].state == "present"
    assert len(paced.calls) == 2 * 19 + 16 + 1
    assert hashlib.sha256(repr(paced.calls).encode()).hexdigest() == BASE_RECOVERY


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
        "start_timeout_seconds": 15,
    }


def _recipe(settings: RuntimeSettings) -> Any:
    return parse_workloads(
        {
            "schema_version": 1,
            "workloads": [
                {
                    "service": item.service,
                    "image": f"example.invalid/containers/{item.service}@sha256:" + "0" * 64,
                    "options": [{"flag": "--volume", "value": f"{item.mounts[0].path}:/config:rw"}],
                    "arguments": [],
                }
                for item in settings.contracts
            ],
        }
    )


def test_settings_without_the_member_keep_their_bytes_and_digests() -> None:
    """Every literal below was computed with the tree this change is based on."""
    settings = parse_settings(_authored())
    stored = canonical_bytes(settings_to_dict(settings))
    assert b"read_timeout_seconds" not in stored
    assert (
        hashlib.sha256(stored).hexdigest()
        == "30d4b744460673486374c7bf47f898a621e1e49f0f897f88f14290e428c5c884"
    )
    shipped = load_settings(EXAMPLES / "runtime-settings.json")
    assert hashlib.sha256(canonical_bytes(settings_to_dict(shipped))).hexdigest() == (
        "d1307ffc7cb45fb28b71c4cd190e57a4f8548b76b28a66fad9c4eec52cc28ab8"
    )
    assert [contract_digest(item) for item in shipped.contracts] == [
        "738717b976875cab43dc7235150aebbaa3b894a4904c86334dcd9d63250ee153",
        "afcfdc49c1a7fd7b435a54f1cb75b32fb48fb3ea1865f3e31b4b854081bb5508",
        "0067741a703af180b7fac6e0be8d1880699e1db21517ff09d047cfa83d479d19",
        "07b9fec3b2403f238c5b4689d80815a7bdb0913a1e887c5fb4228a7fc8cc3f45",
    ]
    policy = load_config(EXAMPLES / "network.json")
    assert config_digest(runtime.derive_policy(policy, shipped)) == (
        "4c4086a6ab0e2b92901ca6e76562ba87b5aa700beb41509e12f1cba41300ee3e"
    )
    # The stored settings are hashed whole into every approved initial provision.
    assert provision_digest(policy, shipped, _recipe(shipped)) == (
        "e1cc07334052affe353a6e2c1bf457c02330fe322c3c242c4c959d4f10a265ac"
    )
    assert provision_digest(policy, shipped, _recipe(shipped), start_initial=True) == (
        "d160cf33f2d57008921105f33e80cd83501c630bed9760c98a490bceca99178d"
    )
    # The root owner binds its observer object as it was written, and reads it
    # with the same loader as the user's settings.
    installation = Installation.from_dict(
        strict_loads((EXAMPLES / "forwarding-settings.json").read_bytes())
    )
    assert digest(dict(installation.observer)) == (
        "83bcd6e774cf6c3675d1aaf8692e728903b14555896eaa6393ef17320f43683e"
    )
    assert settings_to_dict(parse_settings(dict(installation.observer))) == settings_to_dict(
        shipped
    )


def test_the_member_is_stored_as_one_number_and_touches_no_contract() -> None:
    settings = parse_settings(_authored())
    bounded = parse_settings({**_authored(), "read_timeout_seconds": 20})
    assert bounded == replace(settings, read_timeout_seconds=20)
    assert settings_to_dict(bounded) == {**settings_to_dict(settings), "read_timeout_seconds": 20}
    assert parse_settings(settings_to_dict(bounded)) == bounded
    # The bound is the installation's: no contract, and so no policy, changes.
    assert [contract_digest(item) for item in bounded.contracts] == [
        contract_digest(item) for item in settings.contracts
    ]
    # Stating today's eight seconds is a statement and is stored like any other.
    least = parse_settings({**_authored(), "read_timeout_seconds": LEAST})
    assert settings_to_dict(least)["read_timeout_seconds"] == 8
    assert least != settings and settings_to_dict(least) != settings_to_dict(settings)
    # Every value has a stored form of its own.
    forms = {
        canonical_bytes(settings_to_dict(replace(settings, read_timeout_seconds=seconds)))
        for seconds in (None, *range(LEAST, GREATEST + 1))
    }
    assert len(forms) == 1 + 111
    # The neighbouring bound is neither needed nor touched.
    alone = {key: value for key, value in _authored().items() if key != "start_timeout_seconds"}
    assert settings_to_dict(parse_settings({**alone, "read_timeout_seconds": 20})) == {
        **settings_to_dict(parse_settings(alone)),
        "read_timeout_seconds": 20,
    }


def _settings_of_stored_size(size: int) -> RuntimeSettings:
    """Settings without either optional object whose stored form has exactly `size` bytes."""
    document = _authored()
    document["contracts"][0]["receipts"] = []

    def padded(first: int) -> RuntimeSettings:
        document["contracts"][0]["mounts"] = [
            {
                "path": "/" + "m" * (first if index == 0 else 61_000) + f"/{index}",
                "kind": "directory",
                "uid": 1001,
                "device": 1,
                "inode": index,
            }
            for index in range(18)
        ]
        return parse_settings(document)

    start = len(canonical_bytes(settings_to_dict(padded(1_000))))
    return padded(1_000 + size - start)


def test_an_unset_member_costs_no_byte_at_the_size_limit() -> None:
    """The largest settings that could be stored before can still be stored."""
    # Nothing unset is serialised before the bytes are taken, so the stored form
    # itself may have 1,048,576 bytes.
    largest = 1_048_576
    settings = _settings_of_stored_size(largest)
    assert len(canonical_bytes(settings_to_dict(settings))) == largest
    with pytest.raises(ValueError, match="byte limit"):
        settings_to_dict(_settings_of_stored_size(largest + 1))


def test_a_stated_bound_renews_what_hashes_the_settings_whole() -> None:
    shipped = load_settings(EXAMPLES / "runtime-settings.json")
    bounded = replace(shipped, read_timeout_seconds=20)
    policy = load_config(EXAMPLES / "network.json")
    assert provision_digest(policy, bounded, _recipe(shipped)) != provision_digest(
        policy, shipped, _recipe(shipped)
    )
    assert runtime.derive_policy(policy, bounded) == runtime.derive_policy(policy, shipped)
    # The root owner's observer is part of every root admission.
    raw = strict_loads((EXAMPLES / "forwarding-settings.json").read_bytes())
    plain = Installation.from_dict(raw)
    stated = Installation.from_dict(
        {**raw, "observer": {**raw["observer"], "read_timeout_seconds": 20}}
    )
    profile = policy.profile("dns-udp")
    assert owner.admitted_digest(policy, profile, stated) != owner.admitted_digest(
        policy, profile, plain
    )


# --- The loader ---------------------------------------------------------------


@pytest.mark.parametrize("seconds", [8, 9, 20, 30, 117, 118])
def test_the_loader_accepts_whole_seconds_from_8_to_118(seconds: int) -> None:
    settings = parse_settings({**_authored(), "read_timeout_seconds": seconds})
    assert settings.read_timeout_seconds == seconds and type(settings.read_timeout_seconds) is int


@pytest.mark.parametrize(
    "value",
    [7, 119, 0, 1, -8, 120, 10**6, True, False, None, "20", 20.0, 8.5, [20], {"seconds": 20}],
    ids=repr,
)
def test_the_loader_refuses_every_other_value(value: Any) -> None:
    with pytest.raises(ValueError, match="read timeout must be a whole number of seconds"):
        parse_settings({**_authored(), "read_timeout_seconds": value})


def test_the_greatest_bound_is_two_seconds_below_what_a_monitor_can_wait(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bounds are derived: this ties them to the two figures they come from."""
    assert (loader.READ_TIMEOUT_DEFAULT, loader.READ_TIMEOUT_MAXIMUM) == (LEAST, GREATEST)
    schema = strict_loads((ROOT / "schemas/deployment.schema.json").read_bytes())
    longest_check = schema["$defs"]["monitor"]["properties"]["timeout_seconds"]["maximum"]
    # What the clients of the owner endpoint wait for a read of eight seconds.
    config, settings, _items = enrolled
    waited: list[float] = []

    def cut_off(argv: list[str], **kwargs: Any) -> Result:
        waited.append(kwargs["timeout"])
        raise ProcessTimeout("cut off at its bound")

    monkeypatch.setattr(owners, "run", cut_off)
    client = owners.ProcessOwner(config, settings.owner, ["/usr/bin/example-endpoint"])
    assert states(client.observe()) == {("unknown", "timed-out")}
    assert waited == [10]
    # That difference is the margin, under the one name it has in this code.
    margin = waited[0] - LEAST
    assert margin == loader.READ_TIMEOUT_MARGIN == 2
    assert GREATEST + margin == longest_check == 120
    # The shipped example leaves its probe the same margin.
    manifest = strict_loads((EXAMPLES / "deployment.json").read_bytes())
    probe = next(item for item in manifest["monitors"] if item["role"] == "workload")
    assert probe["timeout_seconds"] - LEAST == margin


def test_a_stated_bound_is_the_read_term_of_the_bounded_window() -> None:
    """The safety contract already has a name and a place for this figure."""

    def reasons(read: int) -> tuple[str, ...]:
        return assess_bounded_safety(
            30,
            1,
            "Shared guest addresses can be reused.",
            None,
            None,
            interval_seconds=10,
            read_timeout_seconds=read,
            apply_timeout_seconds=0,
            scheduler_slack_seconds=0,
        ).reasons

    # An interval of ten and a read of twenty are the whole of an age of thirty.
    assert "withdrawal-bound-exceeds-age" not in reasons(LEAST)
    assert "withdrawal-bound-exceeds-age" not in reasons(20)
    assert "withdrawal-bound-exceeds-age" in reasons(21)
    assert "withdrawal-bound-exceeds-age" in reasons(GREATEST)


# --- The bound reaches the reader --------------------------------------------


@pytest.mark.parametrize("seconds", [None, 8, 9, 20, 118])
def test_each_accepted_value_is_the_deadline_of_a_reader(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, seconds: int | None
) -> None:
    _config, plain, items = enrolled
    settings = with_bound(plain, seconds)
    paced = Paced(monkeypatch, FakeRunner(settings, items))
    bound = 8 if seconds is None else seconds
    reader = runtime.Reader(settings, paced)
    assert reader.deadline == START + bound
    # A call never gets more than its own cap, however much of the pass is left.
    assert (reader.remaining(4), reader.remaining(3)) == (4, 3)
    reader.native(["--version"])
    reader.tool(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"])
    assert paced.calls == [("vendor --version", 4), ("sysctl", 3)]
    # Near the end a call gets what is left, and at the end nothing is called.
    paced.clock[0] = START + bound - 0.5
    assert reader.remaining(4) == 0.5
    reader.native(["--version"])
    assert paced.calls[-1] == ("vendor --version", 0.5)
    paced.clock[0] = START + bound
    for call in (lambda: reader.remaining(4), lambda: reader.native(["--version"])):
        with pytest.raises(ProcessTimeout):
            call()
    with pytest.raises(ProcessTimeout):
        reader.tool(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"])
    with pytest.raises(ProcessTimeout):
        reader.job_absent("gui/1", ".".join(["org", "example", "job"]))
    assert len(paced.calls) == 3


def test_every_accepted_value_reaches_a_reader_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    paced = Paced(monkeypatch, None)
    for seconds in range(LEAST, GREATEST + 1):
        settings = parse_settings({**_authored(), "read_timeout_seconds": seconds})
        paced.clock[0] = START + seconds / 4
        assert runtime.Reader(settings, paced).deadline == START + seconds / 4 + seconds


@pytest.mark.parametrize(
    "seconds,outcome",
    [
        (None, ("unknown", "timed-out")),
        (8, ("unknown", "timed-out")),
        # The read takes exactly twelve seconds: a bound of twelve is not enough.
        (12, ("unknown", "timed-out")),
        (13, ("present", "verified")),
        (20, ("present", "verified")),
        (118, ("present", "verified")),
    ],
)
def test_a_read_longer_than_eight_seconds_needs_a_stated_bound(
    enrolled: Any,
    monkeypatch: pytest.MonkeyPatch,
    seconds: int | None,
    outcome: tuple[str, str],
) -> None:
    config, plain, items = enrolled
    settings = with_bound(plain, seconds)
    paced = Paced(monkeypatch, FakeRunner(settings, items), step=0.75)
    observed = runtime.observe_runtime(config, settings, paced)
    assert states(observed) == {outcome}
    assert (observed.network_generation is None) == (outcome[0] == "unknown")
    if outcome[0] == "present":
        assert paced.elapsed == 12.0 and len(paced.calls) == 16
    # Whatever the pass may take, no call got more than its own cap.
    assert max(paced.bounds("vendor --version", "vendor list", "vendor inspect")) == 4
    assert max(paced.bounds("sysctl", "launchctl", "ps", "ifconfig")) == 3
    assert max(bound for _, bound in paced.acl) == 2.0


def test_a_stopped_fleet_under_load_is_proven_stopped_only_with_the_member(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The two optional members together: after a boot, with every read slow."""
    config, declared_settings, inner = declared(enrolled)
    inner.stop_everything()
    for seconds, outcome in (
        (None, ("unknown", "timed-out")),
        (20, ("absent", "confirmed-absent")),
    ):
        settings = with_bound(declared_settings, seconds)
        assert "fleet_start" in settings_to_dict(settings)
        # 31 calls of 0.4375 seconds: includes all three runtime domains.
        paced = Paced(monkeypatch, inner, step=0.4375)
        observed = runtime.observe_runtime(config, settings, paced)
        assert states(observed) == {outcome}
        if seconds is not None:
            assert paced.elapsed == 31 * 0.4375
            # The service manager's answers are single calls with their own cap.
            assert max(paced.bounds("launchctl", "ps")) == 3


def test_a_call_that_hangs_is_still_cut_off_after_its_own_four_seconds(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bound of a pass is not the bound of a call."""
    config, plain, items = enrolled
    settings = with_bound(plain, 118)
    paced = Paced(monkeypatch, FakeRunner(settings, items), step=4.0)
    observed = runtime.observe_runtime(config, settings, paced)
    assert states(observed) == {("unknown", "timed-out")}
    assert paced.calls == [("vendor --version", 4)] and paced.elapsed == 4.0


def test_the_file_checks_of_a_read_count_against_the_same_bound(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, plain, items = enrolled
    # One ACL read for every directory above the mounts and one for each mount.
    reads = len(Path(plain.contracts[0].mounts[0].path).parents) + 4
    assert reads >= 8
    for seconds, outcome in ((None, ("unknown", "timed-out")), (20, ("present", "verified"))):
        settings = with_bound(plain, seconds)
        # The calls alone take seven seconds; the ACL reads take the pass over eight.
        paced = Paced(monkeypatch, FakeRunner(settings, items), step=0.4375, acl_step=0.125)
        observed = runtime.observe_runtime(config, settings, paced)
        assert states(observed) == {outcome}
        assert acl_paths(paced) == reads
        if seconds is not None:
            assert paced.elapsed == 7.0 + 0.125 * len(paced.acl)


def test_the_member_is_in_no_generation(enrolled: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two settings objects that state different bounds still agree on what they read."""
    config, plain, items = enrolled
    seen = []
    for seconds in (None, 8, 60):
        settings = with_bound(plain, seconds)
        paced = Paced(monkeypatch, FakeRunner(settings, items))
        observed = runtime.observe_runtime(config, settings, paced, clock=lambda: 1000)
        seen.append(observed)
    assert seen[0] == seen[1] == seen[2]
    assert seen[0].network_generation is not None


# --- Every reader -------------------------------------------------------------


def _probe(monkeypatch: pytest.MonkeyPatch, config: Any, settings: Any, paced: Paced) -> int:
    """The supervisor's check, from a real observation to its exit status."""
    real = runtime.observe_runtime
    with monkeypatch.context() as patch:
        patch.setattr(runtime, "load_settings", lambda _path: settings)
        patch.setattr(runtime, "observe_runtime", lambda c, s: real(c, s, paced))
        return runtime.main(["--settings", "/unused", "probe", "--service", "camera"])


@pytest.mark.parametrize("state,status", [("running", 0), ("stopped", runtime.STOPPED)])
def test_the_probe_answers_for_a_slow_fleet_only_with_the_member(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, state: str, status: int
) -> None:
    config, plain, items = enrolled
    for seconds, expected in ((None, runtime.UNKNOWN), (20, status)):
        settings = with_bound(plain, seconds)
        inner = FakeRunner(settings, items)
        inner.items["example-camera"]["status"]["state"] = state
        paced = Paced(monkeypatch, inner, step=0.75)
        assert _probe(monkeypatch, config, settings, paced) == expected


def test_each_read_of_a_recovery_has_the_whole_bound(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, plain, items = enrolled
    settings = with_bound(plain, 20)
    inner = FakeRunner(settings, items)
    inner.items["example-camera"]["status"]["state"] = "stopped"
    paced = Paced(monkeypatch, inner, step=0.75)
    result = runtime.recover_service(config, settings, "camera", paced)
    assert result.services["camera"].state == "present"
    # Two stopped reads include job absence; the final running read does not.
    # One bound shared by all three would run out in the second read.
    assert paced.elapsed == (2 * 19 + 16 + 1) * 0.75
    assert paced.bounds("vendor --version") == [4, 4, 4]
    # The start call is one call and keeps its own bound.
    assert paced.bounds("vendor start") == [4]
    # The neighbouring setting still bounds that one call and nothing else.
    both = replace(settings, start_timeout_seconds=90)
    inner = FakeRunner(both, items)
    inner.items["example-camera"]["status"]["state"] = "stopped"
    paced = Paced(monkeypatch, inner, step=0.75)
    runtime.recover_service(config, both, "camera", paced)
    assert paced.bounds("vendor start") == [90] and max(paced.bounds("vendor inspect")) == 4


def test_a_recovery_of_a_slow_fleet_starts_nothing_without_the_member(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, settings, items = enrolled
    inner = FakeRunner(settings, items)
    inner.items["example-camera"]["status"]["state"] = "stopped"
    paced = Paced(monkeypatch, inner, step=0.75)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", paced)
    assert not paced.bounds("vendor start")


def _observe_request(config: Any, settings: Any) -> dict[str, Any]:
    return {
        "protocol_version": 1,
        "operation": "observe",
        "owner": settings.owner,
        "config": to_dict(config),
    }


def test_the_owner_endpoint_keeps_eight_seconds(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its clients wait ten seconds, so a longer read would be cut off from outside."""
    config, plain, items = enrolled
    transcripts = []
    for seconds in (None, 118):
        settings = with_bound(plain, seconds)
        paced = Paced(monkeypatch, FakeRunner(settings, items), step=0.75)
        answer = runtime.handle_request(config, settings, _observe_request(config, settings), paced)
        assert {
            (item["state"], item["reason"]) for item in answer["result"]["services"].values()
        } == {("unknown", "timed-out")}
        # It ended by itself, inside the eight seconds.
        assert paced.elapsed == 8.0
        transcripts.append(paced.calls)
    assert transcripts[0] == transcripts[1]
    # A fleet that answers in time is read as before.
    settings = with_bound(plain, 118)
    paced = Paced(monkeypatch, FakeRunner(settings, items), step=0.4375)
    answer = runtime.handle_request(config, settings, _observe_request(config, settings), paced)
    assert {item["state"] for item in answer["result"]["services"].values()} == {"present"}
    assert paced.calls == BASE_READ


def test_the_endpoint_s_verification_of_a_publication_keeps_eight_seconds(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, plain, items = enrolled
    settings = with_bound(plain, 118)
    fast = Paced(monkeypatch, FakeRunner(settings, items))
    observed = runtime.observe_runtime(config, settings, fast)
    profile = config.profile("camera-web")
    request = {
        "protocol_version": 1,
        "operation": "reconcile",
        "owner": settings.owner,
        "policy_digest": config_digest(config),
        "profile_digest": runtime.profile_digest(config, profile),
        "profile": profile.id,
        "action": "activate",
        "target_ipv4": observed.services[profile.service].data["ipv4"],
        "target_generation": observed.services[profile.service].generation,
    }
    assert runtime.handle_request(config, settings, request, fast)["result"]["state"] == "present"
    slow = Paced(monkeypatch, FakeRunner(settings, items), step=0.75)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.handle_request(config, settings, request, slow)
    assert slow.elapsed == 8.0


def test_enrollment_is_a_read_and_takes_the_bound(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config, plain, items = enrolled
    # Version, inventory and four inspections, 1.5 seconds each: nine seconds.
    paced = Paced(monkeypatch, FakeRunner(plain, items), step=1.5)
    with pytest.raises(ProcessTimeout):
        runtime.capture_enrollment(plain, paced)
    settings = with_bound(plain, 20)
    paced = Paced(monkeypatch, FakeRunner(settings, items), step=1.5)
    captured = runtime.capture_enrollment(settings, paced)
    assert paced.elapsed == 9.0 and len(paced.calls) == 6
    # The authored bound is kept, and nothing else of the enrollment depends on it.
    assert captured.read_timeout_seconds == 20
    assert replace(captured, read_timeout_seconds=None) == runtime.capture_enrollment(
        plain, Paced(monkeypatch, FakeRunner(plain, items))
    )


def test_the_passes_of_initial_provisioning_take_the_bound_and_its_calls_do_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy, plain, fake, workloads, _store = fleet(tmp_path)
    paced = Paced(monkeypatch, fake, step=0.75)
    # Thirteen calls for the plan of seven workloads: 9.75 seconds.
    with pytest.raises(ProcessTimeout):
        plan_workloads(policy, plain, workloads, paced)
    settings = replace(plain, read_timeout_seconds=20)
    fake.settings = settings
    paced = Paced(monkeypatch, fake, step=0.75)
    assert len(plan_workloads(policy, settings, workloads, paced)["steps"]) == 7
    assert paced.elapsed == 9.75
    approved = provision_digest(policy, settings, workloads, start_initial=True)
    paced = Paced(monkeypatch, fake, step=0.75)
    # Each workload's own pass grows with the fleet: the last one reads version,
    # helper, network, inventory and six earlier definitions, nine seconds, which
    # only the stated bound allows.
    result = provision_workloads(
        policy, settings, workloads, expected_digest=approved, start_initial=True, runner=paced
    )
    assert result["provisioned"] and result["started_initial"]
    assert paced.bounds("vendor create") == [4] * 7 and paced.bounds("vendor start") == [4] * 7
    assert max(bound for _, bound in paced.calls) == 4


# --- The root owner ----------------------------------------------------------


def _routed(settings: Any, paced: Paced) -> Any:
    """The root owner's runner: the fixed wrapper that drops to the enrolled account."""

    def run(arguments: list[str], **kwargs: Any) -> Result:
        if arguments[:2] == ["/bin/launchctl", "asuser"]:
            account = settings.account
            return paced(
                arguments[10:],
                run_uid=account.uid,
                run_gid=account.gid,
                account_home=account.home,
                **kwargs,
            )
        return paced(arguments, **kwargs)

    return run


@pytest.mark.parametrize(
    "seconds,outcome", [(None, ("unknown", "timed-out")), (20, ("present", "verified"))]
)
def test_the_root_owner_reads_with_the_bound_its_own_observer_states(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, seconds: int | None, outcome: tuple[str, str]
) -> None:
    config, plain, items = enrolled
    settings = with_bound(plain, seconds)
    # The observer is the stored document; the root owner parses it itself.
    raw = settings_to_dict(settings)
    assert ("read_timeout_seconds" in raw) == (seconds is not None)
    paced = Paced(monkeypatch, FakeRunner(settings, items), step=0.75)
    monkeypatch.setattr(owner, "protected_native_code", lambda paths: None)
    monkeypatch.setattr(owner, "run", _routed(settings, paced))
    observed = owner._runtime_observer(config, raw)
    assert states(observed) == {outcome}


@pytest.mark.parametrize("value", [7, 119, None, "20", 20.0])
def test_a_refused_value_is_refused_before_anything_is_read(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: Any
) -> None:
    """A wrong value never becomes a default: both sides read nothing and answer unknown."""
    config, plain, _items = enrolled
    document = {**settings_to_dict(plain), "read_timeout_seconds": value}
    reads: list[Any] = []

    def read(*args: Any) -> Snapshot:
        reads.append(args)
        return Snapshot(1000, None, {}, {})

    monkeypatch.setattr(owner, "protected_native_code", reads.append)
    monkeypatch.setattr(runtime, "observe_runtime", read)
    # The root owner's observer: the error its pass reads as an unavailable observation.
    with pytest.raises(ValueError, match="read timeout must be a whole number of seconds"):
        owner._runtime_observer(config, document)
    # The user's commands: the probe's own status for unknown.
    path = tmp_path / "refused-settings.json"
    path.write_bytes(canonical_bytes(document))
    path.chmod(0o600)
    for command in (["observe"], ["probe", "--service", "camera"]):
        assert runtime.main(["--settings", str(path), *command]) == runtime.UNKNOWN
    assert not reads
    # The same document with an accepted value is read.
    path.write_bytes(canonical_bytes({**document, "read_timeout_seconds": 20}))
    runtime.main(["--settings", str(path), "probe", "--service", "camera"])
    assert len(reads) == 1 and reads[0][1].read_timeout_seconds == 20


def _installed(tmp_path: Path, config: Any, settings: Any) -> tuple[Store, Installation]:
    installation = Installation(
        "site-forwarding",
        "com.apple/netorch.site-forwarding",
        settings_to_dict(settings),
        hashlib.sha256(b"backend").hexdigest(),
        str(tmp_path / "report.json"),
    )
    root = Store(tmp_path / "root")
    root.write("installation.json", installation.to_dict())
    root.write("policy.json", to_dict(config))
    root.write("admissions.json", {"schema_version": 1, "strategy": STRATEGY, "profiles": {}})
    root.write("operator-intent.json", intent_to_dict(Intent()))
    for profile in config.profiles:
        if config.profile_owner(profile).id == installation.owner:
            admit(root, profile.id, acknowledge_bounded_risk=True, now=START - 1)
    return root, installation


@pytest.mark.parametrize("seconds", [None, 20])
def test_a_slow_read_retires_the_root_owner_s_rules_only_without_the_member(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, seconds: int | None
) -> None:
    config, plain, items = enrolled
    settings = with_bound(plain, seconds)
    root, _installation = _installed(tmp_path, config, settings)
    backend = FakeBackend()
    monkeypatch.setattr(owner, "protected_native_code", lambda paths: None)

    def root_pass(step: float) -> dict[str, Any]:
        paced = Paced(monkeypatch, FakeRunner(settings, items), step=step)
        monkeypatch.setattr(owner, "run", _routed(settings, paced))
        # The owner's own observer, as its scheduled command passes it.
        return reconcile(
            root,
            owner._runtime_observer,
            lambda store, record: backend,
            report=lambda record, snapshot: None,
        )

    loaded = root_pass(0.0)
    assert loaded["changed"] and all(item.endswith(":activate") for item in loaded["changed"])
    rules = backend.rules
    assert rules
    # The same fleet, read under load: every read of the pass takes twelve seconds.
    slow = root_pass(0.75)
    if seconds is None:
        # Every rule is withdrawn (and the states of the guest targets drained).
        assert {item for item in slow["changed"] if item.endswith(":withdraw")} == {
            item.replace(":activate", ":withdraw") for item in loaded["changed"]
        }
        assert not backend.rules
    else:
        assert slow["changed"] == [] and slow["phase"] == "committed"
        assert backend.rules == rules


def test_evidence_older_than_a_profile_accepts_is_stale_whatever_the_bound(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The bound says how long a read may take, not how old its evidence may be."""
    config, plain, items = enrolled
    assert {profile.safety.max_age_seconds for profile in config.profiles} == {30}
    settings = with_bound(plain, 40)
    root, _installation = _installed(tmp_path, config, settings)
    backend = FakeBackend()
    wall = [START]

    def root_pass(step: float) -> dict[str, Any]:
        # One clock for the read's own time and for the age of what it read.
        paced = Paced(monkeypatch, FakeRunner(settings, items), step=step, clock=wall)

        def observer(policy: Any, raw: Any) -> Any:
            return runtime.observe_runtime(
                policy, RuntimeSettings.from_dict(dict(raw)), paced, clock=lambda: wall[0]
            )

        return reconcile(
            root,
            observer,
            lambda store, record: backend,
            now=lambda: wall[0],
            report=lambda record, snapshot: None,
        )

    loaded = root_pass(0.0)["changed"]
    assert loaded and all(item.endswith(":activate") for item in loaded)
    assert backend.rules
    # A read of 28 seconds is inside the bound and inside the 30 seconds of age.
    assert root_pass(1.75)["changed"] == [] and backend.rules
    # A read of 32 seconds is inside the bound of 40 and was complete, yet every
    # profile calls its evidence stale and is retired.
    retired = root_pass(2.0)["changed"]
    assert {item for item in retired if item.endswith(":withdraw")} == {
        item.replace(":activate", ":withdraw") for item in loaded
    }
    assert not backend.rules
    assert {
        action["reason"]
        for action in root.read("journal.json")["actions"]
        if action["operation"] == "withdraw"
    } == {"snapshot-stale"}

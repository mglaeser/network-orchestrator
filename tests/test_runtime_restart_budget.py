"""Recovery can stop starting a workload that keeps stopping.

Without a budget the guarded start issues one `start` every time the
supervisor's rule fires, for ever. With `restart_budget` in the runtime settings
it counts the starts it issues for each service in a private record of the
state store. A start that would exceed the budget is not issued: the service is
held in the durable intent, with the operation `restart-budget` and the holder
`supervisor`, and an operator releases it with `unhold`. Fake runner and an
injected calendar clock only; nothing waits and nothing reads the real time.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch import cli, runtime_settings
from netorch import instance as instance_module
from netorch.codec import canonical_bytes
from netorch.config import load_config
from netorch.mock import mock_admissions
from netorch.planner import plan
from netorch.process import ProcessTimeout, Result
from netorch.runtime_settings import (
    contract_digest,
    load_settings,
    parse_settings,
    settings_to_dict,
)
from netorch.state import Intent, attribute_holds, intent_from_dict, intent_to_dict
from netorch.storage import Busy, Store
from netorch.workflow_gate import NOT_QUALIFIED
from netorch.workloads import parse_workloads, provision_digest
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_bonjour_owner import snapshot as verified_snapshot
from tests.test_report_truthfulness import parsed
from tests.test_service_holds import V1_OPEN, inventory_reads, probe, reasons, starts

__all__ = ["enrolled"]

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
RECORD = "recovery-starts.json"
HOLD = {"restart-budget": "supervisor"}
# The record of a workload whose budget is spent while its hold could not be
# stored: inside every window and enough for every budget.
NOT_HELD = [2**53 - 1] * 10
# A second of the calendar clock. Every test names its own time.
T0 = 1_800_000_000
OTHERS = ("media-controller", "resolver", "web-proxy")


class Site:
    """An enrolled installation whose intent file lies in its state directory."""

    def __init__(self, enrolled: Any, starts: int = 3, window: int = 600) -> None:
        self.config, settings, items = enrolled
        self.store = Store(Path(settings.state_dir))
        self.store.write("intent.json", intent_to_dict(Intent()))
        self.settings = replace(
            settings,
            intent=str(self.store.directory / "intent.json"),
            # Reached through its module: on a tree without the setting this
            # file still collects and each test fails on its own.
            restart_budget=runtime_settings.RestartBudget(starts, window),
        )
        self.runner: Any = FakeRunner(self.settings, items)
        self.inner: FakeRunner = self.runner
        self.now: Any = T0

    def recover(self, service: str = "camera", at: Any = ...) -> Any:
        """One firing of the supervisor's rule for a workload that has stopped."""
        if at is not ...:
            self.now = at
        self.inner.items["example-" + service]["status"]["state"] = "stopped"
        return runtime.recover_service(
            self.config, self.settings, service, self.runner, wall=lambda: self.now
        )

    def refused(self, service: str = "camera", at: Any = ...) -> runtime.RuntimeReadError:
        with pytest.raises(runtime.RuntimeReadError) as refusal:
            self.recover(service, at)
        return refusal.value

    def record(self) -> Any:
        return self.store.read(RECORD)["services"]

    def intent(self) -> Intent:
        return intent_from_dict(self.store.read("intent.json"))

    def spend(self, service: str = "camera", start: int = T0) -> None:
        """Use the whole budget of one workload, one start every ten seconds."""
        budget = self.settings.restart_budget
        for index in range(budget.starts):
            assert self.recover(service, start + 10 * index).services[service].state == "present"

    def unhold(self, monkeypatch: pytest.MonkeyPatch, service: str = "camera") -> int:
        """The operator's release, through the command and behind its gate."""
        arguments = ["unhold", "--state-dir", str(self.store.directory), "--service", service]
        arguments += ["--operation", "restart-budget", "--holder", "supervisor"]
        with monkeypatch.context() as qualified:
            qualified.setattr(cli, "require_mutation_qualified", lambda _capability: None)
            return cli.main(arguments)


def test_without_the_setting_nothing_is_recorded_and_nothing_changes(enrolled: Any) -> None:
    # Settings as they are today. This holds before the change too.
    config, settings, items = enrolled
    store = Store(Path(settings.state_dir))
    store.write("intent.json", intent_to_dict(Intent()))
    settings = replace(settings, intent=str(store.directory / "intent.json"))
    assert getattr(settings, "restart_budget", None) is None
    runner = FakeRunner(settings, items)

    def stopped_again() -> None:
        runner.items["example-camera"]["status"]["state"] = "stopped"
        recovered = runtime.recover_service(config, settings, "camera", runner)
        assert recovered.services["camera"].state == "present"

    for _ in range(12):
        stopped_again()
    assert starts(runner) == ["example-camera"] * 12
    assert sorted(os.listdir(store.directory)) == ["intent.json", "owner.lock"]
    assert (store.directory / "intent.json").read_bytes() == V1_OPEN + b"\n"
    # A record that an earlier budget left behind is neither read nor rewritten.
    store.write(RECORD, {"left": "behind"})
    left = (store.directory / RECORD).read_bytes()
    stopped_again()
    assert starts(runner) == ["example-camera"] * 13
    assert (store.directory / RECORD).read_bytes() == left
    assert (store.directory / "intent.json").read_bytes() == V1_OPEN + b"\n"


def test_the_start_beyond_the_budget_places_a_hold_and_starts_nothing(enrolled: Any) -> None:
    site = Site(enrolled)
    for index in range(3):
        recovered = site.recover(at=T0 + 100 * index)
        assert recovered.services["camera"].state == "present"
        assert site.store.read(RECORD) == {
            "schema_version": 1,
            "services": {"camera": [T0 + 100 * item for item in range(index + 1)]},
        }
    assert starts(site.inner) == ["example-camera"] * 3
    # Three starts inside the budget touched nothing but the record.
    assert (site.store.directory / "intent.json").read_bytes() == V1_OPEN + b"\n"
    reads = len(inventory_reads(site.inner))
    refusal = site.refused(at=T0 + 300)
    # The same outcome as a start that a hold refuses.
    assert refusal.reason == "incomplete"
    # Decided where the start would have been issued: after both observations.
    assert len(inventory_reads(site.inner)) == reads + 2
    assert starts(site.inner) == ["example-camera"] * 3
    assert site.store.read("intent.json") == {
        "schema_version": 2,
        "revision": 1,
        "operator_paused": False,
        "suspensions": {},
        "damaged": False,
        "holds": {"camera": HOLD},
    }
    # The record of that service went with the hold.
    assert site.store.read(RECORD) == {"schema_version": 1, "services": {}}
    # Held: the next firing is refused at the first read of the intent.
    reads = len(inventory_reads(site.inner))
    before = (site.store.directory / "intent.json").read_bytes()
    assert site.refused(at=T0 + 315).reason == "incomplete"
    assert len(inventory_reads(site.inner)) == reads + 1
    assert starts(site.inner) == ["example-camera"] * 3
    assert site.record() == {}
    assert (site.store.directory / "intent.json").read_bytes() == before


@pytest.mark.parametrize(("starts_allowed", "window"), [(1, 60), (2, 3600), (10, 86400)])
def test_the_budget_is_exactly_the_stated_number_of_starts(
    enrolled: Any, starts_allowed: int, window: int
) -> None:
    site = Site(enrolled, starts_allowed, window)
    site.spend()
    assert starts(site.inner) == ["example-camera"] * starts_allowed
    assert not site.intent().holds
    site.refused(at=T0 + 10 * starts_allowed)
    assert starts(site.inner) == ["example-camera"] * starts_allowed
    assert site.intent().holds == {"camera": HOLD}


@pytest.mark.parametrize(("elapsed", "held"), [(599, True), (600, False), (86400, False)])
def test_starts_older_than_the_window_do_not_count(enrolled: Any, elapsed: int, held: bool) -> None:
    site = Site(enrolled, 3, 600)
    for index in range(3):
        site.recover(at=T0 + 100 * index)
    if held:
        # The first start is 599 seconds old: still one of three.
        site.refused(at=T0 + elapsed)
        assert site.intent().holds == {"camera": HOLD}
        assert starts(site.inner) == ["example-camera"] * 3
        return
    recovered = site.recover(at=T0 + elapsed)
    assert recovered.services["camera"].state == "present"
    assert not site.intent().holds
    assert starts(site.inner) == ["example-camera"] * 4
    # What has left the window has left the record: it never grows past the budget.
    kept = [T0 + 100, T0 + 200] if elapsed == 600 else []
    assert site.record() == {"camera": [*kept, T0 + elapsed]}
    if elapsed == 600:
        site.refused(at=T0 + 650)
        assert site.intent().holds == {"camera": HOLD}


class Failing:
    """The shared fake runner with a `start` call that ends as told."""

    def __init__(self, site: Site, answer: Result | Exception) -> None:
        self.site, self.answer = site, answer
        self.on_record: list[Any] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> Result:
        if argv[1:2] != ["start"]:
            return self.site.inner(argv, **kwargs)
        self.site.inner.calls.append((argv, kwargs))
        # What the record says at the moment the vendor call is made.
        self.on_record.append(copy.deepcopy(self.site.record()))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


@pytest.mark.parametrize(
    ("outcome", "error"),
    [
        (ProcessTimeout("bounded"), ProcessTimeout),
        (Result(1, b"", b""), runtime.RuntimeReadError),
        (Result(0, b"started", b"warning"), runtime.RuntimeReadError),
        # The client reports success and the workload is still stopped.
        (Result(0, b"started", b""), runtime.RuntimeReadError),
    ],
    ids=["cut off", "exit status", "standard error", "not confirmed"],
)
def test_an_issued_start_counts_whatever_becomes_of_it(
    enrolled: Any, outcome: Result | Exception, error: type[Exception]
) -> None:
    site = Site(enrolled)
    site.runner = failing = Failing(site, outcome)
    for index in range(3):
        with pytest.raises(error):
            site.recover(at=T0 + 20 * index)
    assert starts(site.inner) == ["example-camera"] * 3
    # Each entry was on record before its call was made.
    assert failing.on_record == [
        {"camera": [T0 + 20 * item for item in range(index + 1)]} for index in range(3)
    ]
    assert not site.intent().holds
    assert site.refused(at=T0 + 60).reason == "incomplete"
    assert starts(site.inner) == ["example-camera"] * 3
    assert site.intent().holds == {"camera": HOLD}


def test_a_start_that_is_read_back_as_running_does_not_clear_the_record(enrolled: Any) -> None:
    site = Site(enrolled)
    site.spend()
    # Every start succeeded and the workload ran in between; the budget is
    # about starts within a period.
    assert site.record() == {"camera": [T0, T0 + 10, T0 + 20]}
    snapshot = runtime.observe_runtime(site.config, site.settings, site.inner)
    assert snapshot.services["camera"].state == "present"
    assert site.record() == {"camera": [T0, T0 + 10, T0 + 20]}


def test_a_refused_recovery_counts_nothing(enrolled: Any) -> None:
    site = Site(enrolled)
    # Running: not proven stopped, so no start is issued and none is recorded.
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(site.config, site.settings, "camera", site.runner, wall=lambda: T0)
    # Paused: refused at the first read of the intent.
    site.store.write("intent.json", intent_to_dict(Intent().pause()))
    site.refused()
    assert not (site.store.directory / RECORD).exists()
    assert starts(site.inner) == []
    assert site.intent() == Intent().pause()


def test_each_workload_has_its_own_count(enrolled: Any) -> None:
    site = Site(enrolled)
    site.spend("camera")
    site.recover("resolver", T0 + 40)
    assert site.record() == {"camera": [T0, T0 + 10, T0 + 20], "resolver": [T0 + 40]}
    site.refused("camera", T0 + 50)
    assert site.intent().holds == {"camera": HOLD}
    # Clearing one workload's record leaves the other's count as it is.
    assert site.record() == {"resolver": [T0 + 40]}
    site.recover("resolver", T0 + 60)
    site.recover("resolver", T0 + 70)
    assert starts(site.inner) == ["example-camera"] * 3 + ["example-resolver"] * 3
    site.refused("resolver", T0 + 80)
    assert site.intent().holds == {"camera": HOLD, "resolver": HOLD}
    assert site.record() == {}
    assert starts(site.inner) == ["example-camera"] * 3 + ["example-resolver"] * 3


def spent_for_one_period(now: int = T0, count: int = 3) -> dict[str, list[int]]:
    return {service: [now] * count for service in OTHERS}


UNFAMILIAR: dict[str, Any] = {
    "not json": b"{",
    "empty file": b"",
    "a list": b"[]",
    "null": b"null",
    "another version": {"schema_version": 2, "services": {}},
    "a boolean version": {"schema_version": True, "services": {}},
    "no services": {"schema_version": 1},
    "no version": {"services": {}},
    "one more member": {"schema_version": 1, "services": {}, "window_seconds": 600},
    "services as a list": {"schema_version": 1, "services": []},
    "no entry": {"schema_version": 1, "services": {"camera": []}},
    "eleven entries": {"schema_version": 1, "services": {"camera": [T0] * 11}},
    "one number": {"schema_version": 1, "services": {"camera": T0}},
    "a fraction": {"schema_version": 1, "services": {"camera": [float(T0)]}},
    "a boolean": {"schema_version": 1, "services": {"camera": [True]}},
    "before the epoch": {"schema_version": 1, "services": {"camera": [-1]}},
    "beyond exact seconds": {"schema_version": 1, "services": {"camera": [2**53]}},
    "a string": {"schema_version": 1, "services": {"camera": [str(T0)]}},
    "no service name": {"schema_version": 1, "services": {"Camera": [T0]}},
    # Unfamiliar in the entry of another workload: the record as a whole says nothing.
    "another workload": {"schema_version": 1, "services": {"resolver": [T0, None]}},
    "too many services": {
        "schema_version": 1,
        "services": {f"service-{index}": [T0] for index in range(257)},
    },
}


@pytest.mark.parametrize("name", list(UNFAMILIAR))
def test_a_record_that_says_nothing_counts_as_a_spent_budget(enrolled: Any, name: str) -> None:
    site = Site(enrolled)
    document = UNFAMILIAR[name]
    raw = document if isinstance(document, bytes) else canonical_bytes(document)
    path = site.store.directory / RECORD
    path.write_bytes(raw)
    path.chmod(0o600)
    assert site.refused(at=T0).reason == "incomplete"
    assert starts(site.inner) == []
    assert site.intent().holds == {"camera": HOLD}
    # The workload that was held gets a whole budget with its release. For every
    # other workload the lost record counts as spent for one period, never as unused.
    assert site.store.read(RECORD) == {"schema_version": 1, "services": spent_for_one_period()}
    site.refused("resolver", T0 + 599)
    assert site.intent().holds == {"camera": HOLD, "resolver": HOLD}
    recovered = site.recover("web-proxy", T0 + 600)
    assert recovered.services["web-proxy"].state == "present"
    assert starts(site.inner) == ["example-web-proxy"]
    assert site.record() == {"media-controller": [T0] * 3, "web-proxy": [T0 + 600]}


@pytest.mark.parametrize("unsafe", ["mode", "link", "symlink", "directory"])
def test_a_record_that_the_store_refuses_keeps_the_brake_engaged(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, unsafe: str
) -> None:
    site = Site(enrolled)
    path = site.store.directory / RECORD
    good = canonical_bytes({"schema_version": 1, "services": {}})
    if unsafe == "directory":
        path.mkdir(mode=0o700)
    elif unsafe == "symlink":
        target = site.store.directory / "elsewhere.json"
        target.write_bytes(good)
        target.chmod(0o600)
        path.symlink_to(target)
    else:
        path.write_bytes(good)
        path.chmod(0o644 if unsafe == "mode" else 0o600)
        if unsafe == "link":
            os.link(path, site.store.directory / "second-name.json")
    # An empty record in a file the store does not accept is not an empty record.
    site.refused(at=T0)
    assert starts(site.inner) == []
    if unsafe == "symlink":
        # A symbolic link is not opened at all: a read error, which is no
        # content. Every firing starts nothing, holds nothing and leaves the
        # link as it is.
        assert not site.intent().holds
        site.refused(at=T0 + 5)
        assert starts(site.inner) == []
        assert not site.intent().holds
        assert path.is_symlink() and target.read_bytes() == good
        return
    assert site.intent().holds == {"camera": HOLD}
    # The store replaces no such file either, so the release alone gives no start.
    assert site.unhold(monkeypatch) == 0
    site.refused(at=T0 + 5)
    assert starts(site.inner) == []
    assert site.intent().holds == {"camera": HOLD}


@pytest.mark.parametrize(
    ("entries", "started"),
    [
        ([T0 + 1, T0 + 5000, T0 + 86400 * 365], False),
        ([T0 + 86400 * 365] * 3, False),
        # Two starts in the future are two of three: one more is inside the budget.
        ([T0 + 5000, T0 + 9000], True),
    ],
)
def test_a_start_recorded_in_the_future_is_inside_the_window(
    enrolled: Any, entries: list[int], started: bool
) -> None:
    site = Site(enrolled)
    site.store.write(
        RECORD, {"schema_version": 1, "services": {"camera": entries, "resolver": [T0 - 30]}}
    )
    if started:
        assert site.recover(at=T0).services["camera"].state == "present"
        assert site.record() == {"camera": [*entries, T0], "resolver": [T0 - 30]}
        assert not site.intent().holds
    site.refused(at=T0 + 1)
    assert starts(site.inner) == ["example-camera"] * started
    assert site.intent().holds == {"camera": HOLD}
    # A readable record keeps what it says about the other workloads.
    assert site.record() == {"resolver": [T0 - 30]}


@pytest.mark.parametrize(
    "now",
    [math.nan, math.inf, -math.inf, -1, -0.5, 2**53, True, None, "1800000000"],
    ids=repr,
)
@pytest.mark.parametrize("readable", [True, False])
def test_a_clock_that_gives_no_usable_time_counts_as_a_spent_budget(
    enrolled: Any, now: Any, readable: bool
) -> None:
    site = Site(enrolled)
    path = site.store.directory / RECORD
    if readable:
        site.store.write(RECORD, {"schema_version": 1, "services": {"resolver": [T0]}})
    else:
        path.write_bytes(b"{")
        path.chmod(0o600)
    site.refused(at=now)
    assert starts(site.inner) == []
    assert site.intent().holds == {"camera": HOLD}
    if readable:
        assert site.record() == {"resolver": [T0]}
    else:
        # Neither a record nor a time to write one with: it stays as it is.
        assert path.read_bytes() == b"{"


def test_after_the_release_the_whole_budget_is_there_again(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    site = Site(enrolled)
    site.spend()
    site.refused(at=T0 + 30)
    assert site.intent().holds == {"camera": HOLD}
    # With the real gate the release is refused in this stage, like every release.
    arguments = ["unhold", "--state-dir", str(site.store.directory), "--service", "camera"]
    arguments += ["--operation", "restart-budget", "--holder", "supervisor"]
    assert cli.main(arguments) == NOT_QUALIFIED
    assert site.intent().holds == {"camera": HOLD}
    assert site.unhold(monkeypatch) == 0
    capsys.readouterr()
    # Version 1 again, two revisions later.
    assert (site.store.directory / "intent.json").read_bytes() == (
        V1_OPEN.replace(b'"revision":0', b'"revision":2') + b"\n"
    )
    # Three more starts, all still inside the period of the first three.
    site.spend(start=T0 + 40)
    assert starts(site.inner) == ["example-camera"] * 6
    assert site.record() == {"camera": [T0 + 40, T0 + 50, T0 + 60]}
    assert not site.intent().holds
    site.refused(at=T0 + 70)
    assert starts(site.inner) == ["example-camera"] * 6
    assert site.store.read("intent.json")["revision"] == 3
    assert site.intent().holds == {"camera": HOLD}


def test_the_hold_is_visible_to_the_probe_the_planner_and_the_intent(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = Site(enrolled)
    site.spend()
    site.inner.items["example-resolver"]["status"]["state"] = "stopped"
    site.refused(at=T0 + 30)
    full = runtime.observe_runtime(site.config, site.settings, site.inner)
    assert full.services["camera"].state == full.services["resolver"].state == "absent"
    # The probe: unknown for the held workload, so the start rule no longer fires.
    assert probe(monkeypatch, site.settings, full, "camera") == runtime.UNKNOWN == 69
    assert probe(monkeypatch, site.settings, full, "resolver") == runtime.STOPPED == 42
    assert probe(monkeypatch, site.settings, full, "web-proxy") == 0
    # The intent every reader of the installation is given.
    intent = runtime._intent(site.settings)
    assert intent == site.intent() and not intent.damaged
    assert intent.blocks("camera") and not intent.blocked
    assert not any(intent.blocks(service) for service in OTHERS)
    # The planner of the coordinator: that service is held, the others are served.
    policy = load_config(EXAMPLES / "network.json")
    services = {item.id for item in policy.services}
    assert attribute_holds(intent, services) == intent
    result = plan(policy, verified_snapshot(policy), mock_admissions(policy), intent, 1000.0)
    for profile in policy.profiles:
        expected = (
            [("withdraw", "held"), ("drain", "held"), ("blocked", "held")]
            if profile.service == "camera"
            else [("noop", "verified")]
        )
        assert reasons(result, profile.id) == expected
    assert result.intent_revision == 1


def test_the_pause_and_other_holds_are_untouched(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    site = Site(enrolled)
    maintenance = Intent().hold("resolver", "maintenance", "manager")
    site.store.write("intent.json", intent_to_dict(maintenance))
    site.spend()
    assert site.intent() == maintenance
    site.refused(at=T0 + 30)
    placed = site.intent()
    assert placed.holds == {"resolver": {"maintenance": "manager"}, "camera": HOLD}
    assert (placed.operator_paused, dict(placed.suspensions), placed.damaged) == (False, {}, False)
    assert placed.revision == maintenance.revision + 1
    # The operator pauses the site and then releases the budget's hold.
    state = ["--state-dir", str(site.store.directory)]
    assert cli.main(["pause", *state]) == 0
    monkeypatch.setattr(cli, "require_mutation_qualified", lambda _capability: None)
    another = ["unhold", *state, "--service", "camera", "--operation", "restart-budget"]
    # Only its holder releases it.
    assert cli.main([*another, "--holder", "manager"]) == 65
    assert site.intent().holds == placed.holds
    assert site.unhold(monkeypatch) == 0
    capsys.readouterr()
    released = site.intent()
    assert released.operator_paused and not released.suspensions and not released.damaged
    assert released.holds == {"resolver": {"maintenance": "manager"}}


def test_the_hold_is_added_to_the_intent_as_it_is_stored_at_that_moment(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = Site(enrolled)
    site.spend()
    # Written without the lock after recovery last read the intent: a pause
    # and a manager's hold on another service.
    arrived = Intent().pause().hold("resolver", "maintenance", "manager")
    read, write = Store.read, Store.write

    def racing(store: Store, name: str) -> Any:
        if name == RECORD:
            write(store, "intent.json", intent_to_dict(arrived))
        return read(store, name)

    with monkeypatch.context() as patched:
        patched.setattr(Store, "read", racing)
        site.refused(at=T0 + 30)
    placed = site.intent()
    assert placed.operator_paused and not placed.suspensions and not placed.damaged
    assert placed.holds == {"resolver": {"maintenance": "manager"}, "camera": HOLD}
    assert placed.revision == arrived.revision + 1
    assert starts(site.inner) == ["example-camera"] * 3


def test_two_recoveries_cannot_both_take_the_last_start(enrolled: Any) -> None:
    site = Site(enrolled, starts=1, window=600)
    second: list[Exception] = []

    def runner(argv: list[str], **kwargs: Any) -> Result:
        if argv[1:2] == ["start"]:
            # A second recovery arrives while the first one makes its call. The
            # clock of its bounded wait only moves when it sleeps.
            waited = [0.0]
            try:
                runtime.recover_service(
                    site.config,
                    site.settings,
                    "camera",
                    site.inner,
                    clock=lambda: waited[0],
                    sleep=lambda seconds: waited.__setitem__(0, waited[0] + seconds),
                    wall=lambda: T0 + 1,
                )
            except Exception as error:
                second.append(error)
        return site.inner(argv, **kwargs)

    site.runner = runner
    assert site.recover(at=T0).services["camera"].state == "present"
    # It found the lock held for its whole wait, read nothing and started nothing.
    assert len(second) == 1 and isinstance(second[0], Busy)
    assert starts(site.inner) == ["example-camera"]
    assert site.record() == {"camera": [T0]}
    assert not site.intent().holds
    # Once it gets the lock, it reads the record the first one wrote.
    site.runner = site.inner
    site.refused(at=T0 + 2)
    assert starts(site.inner) == ["example-camera"]
    assert site.intent().holds == {"camera": HOLD}


def test_a_spent_budget_starts_nothing_while_the_hold_cannot_be_stored(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = Site(enrolled)
    site.spend()
    write = Store.write

    def unwritable(store: Store, name: str, value: Any) -> None:
        if name == "intent.json":
            raise OSError("no space left on device")
        write(store, name, value)

    with monkeypatch.context() as full:
        full.setattr(Store, "write", unwritable)
        assert site.refused(at=T0 + 30).reason == "incomplete"
        assert site.refused(at=T0 + 40).reason == "incomplete"
    assert starts(site.inner) == ["example-camera"] * 3
    assert not site.intent().holds
    # The budget is still spent, in a form that does not age, so the next
    # firing holds the service after all.
    assert site.record() == {"camera": NOT_HELD}
    site.refused(at=T0 + 50)
    assert site.intent().holds == {"camera": HOLD}
    assert starts(site.inner) == ["example-camera"] * 3


def test_a_hold_that_another_holder_owns_is_not_replaced(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = Site(enrolled)
    site.spend()
    # Written without the lock, after the last read of the intent: the same
    # operation on the same service, in another holder's name.
    foreign = Intent().hold("camera", "restart-budget", "someone-else")
    read, write = Store.read, Store.write

    def racing(store: Store, name: str) -> Any:
        if name == RECORD:
            write(store, "intent.json", intent_to_dict(foreign))
        return read(store, name)

    with monkeypatch.context() as patched:
        patched.setattr(Store, "read", racing)
        assert site.refused(at=T0 + 30).reason == "incomplete"
    assert starts(site.inner) == ["example-camera"] * 3
    assert site.intent() == foreign
    assert site.record() == {"camera": NOT_HELD}


def test_no_start_is_issued_when_it_cannot_be_recorded(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = Site(enrolled)
    site.recover(at=T0)
    write = Store.write

    def unwritable(store: Store, name: str, value: Any) -> None:
        if name == RECORD:
            raise OSError("no space left on device")
        write(store, name, value)

    with monkeypatch.context() as full:
        full.setattr(Store, "write", unwritable)
        assert site.refused(at=T0 + 10).reason == "incomplete"
    assert starts(site.inner) == ["example-camera"]
    assert site.record() == {"camera": [T0]}
    # Inside the budget and not recorded: no hold either.
    assert not site.intent().holds


def test_a_crash_between_the_hold_and_the_record_leaves_the_brake_engaged(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    site = Site(enrolled)
    site.spend()
    write = Store.write

    class Crash(BaseException):
        """The process ends here; nothing after it runs."""

    def interrupted(store: Store, name: str, value: Any) -> None:
        if name == RECORD:
            raise Crash
        write(store, name, value)

    with monkeypatch.context() as crash, pytest.raises(Crash):
        crash.setattr(Store, "write", interrupted)
        site.recover(at=T0 + 30)
    # The hold was stored first. The record still says that the budget is spent.
    assert site.intent().holds == {"camera": HOLD}
    assert site.record() == {"camera": [T0, T0 + 10, T0 + 20]}
    assert starts(site.inner) == ["example-camera"] * 3
    # The price is one more hold after the release; then the budget is whole.
    assert site.unhold(monkeypatch) == 0
    site.refused(at=T0 + 40)
    assert site.intent().holds == {"camera": HOLD}
    assert site.record() == {}
    assert site.unhold(monkeypatch) == 0
    capsys.readouterr()
    assert site.recover(at=T0 + 50).services["camera"].state == "present"
    assert starts(site.inner) == ["example-camera"] * 4


def test_a_lowered_budget_and_a_retired_service_are_read_without_surprise(enrolled: Any) -> None:
    site = Site(enrolled, starts=2)
    # Written under a budget of five; one service is no longer enrolled.
    site.store.write(
        RECORD,
        {
            "schema_version": 1,
            "services": {"camera": [T0 + index for index in range(5)], "retired": [T0]},
        },
    )
    site.recover("resolver", T0 + 10)
    # What is written is bounded by the enrollment.
    assert site.record() == {"camera": [T0 + index for index in range(5)], "resolver": [T0 + 10]}
    site.refused("camera", T0 + 20)
    assert site.intent().holds == {"camera": HOLD}
    assert starts(site.inner) == ["example-resolver"]


def test_recovery_refuses_a_budget_whose_hold_it_could_not_write(enrolled: Any) -> None:
    config, settings, items = enrolled
    # Deliberately move intent outside the operation lock's authoritative store.
    other = Path(settings.state_dir).parent / "other-intent.json"
    other.write_bytes(Path(settings.intent).read_bytes())
    other.chmod(0o600)
    settings = replace(settings, intent=str(other))
    budgeted = replace(settings, restart_budget=runtime_settings.RestartBudget(3, 600))
    runner = FakeRunner(budgeted, items)
    runner.items["example-camera"]["status"]["state"] = "stopped"
    with pytest.raises(ValueError, match="restart budget"):
        runtime.recover_service(config, budgeted, "camera", runner, wall=lambda: T0)
    assert runner.calls == []
    assert not (Path(settings.state_dir) / "restart-budget.json").exists()
    # Omitting the budget cannot bypass the same operator pause authority.
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert not starts(runner)


def test_the_start_command_ends_like_a_start_that_a_hold_refuses(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    site = Site(enrolled)
    site.spend()
    recover = runtime.recover_service

    def supervised(config: Any, settings: Any, service: str) -> Any:
        site.inner.items["example-" + service]["status"]["state"] = "stopped"
        return recover(config, settings, service, site.inner, wall=lambda: T0 + 30)

    monkeypatch.setattr(runtime, "load_settings", lambda _path: site.settings)
    monkeypatch.setattr(runtime, "load_config", lambda _path: site.config)
    monkeypatch.setattr(runtime, "recover_service", supervised)
    arguments = ["--settings", "/unused/settings.json", "start", "--service", "camera"]
    # The real gate: in this stage nothing is started, counted or held.
    assert runtime.main(arguments) == NOT_QUALIFIED
    assert not site.intent().holds and site.record() == {"camera": [T0, T0 + 10, T0 + 20]}
    capsys.readouterr()
    monkeypatch.setattr(runtime, "require_mutation_qualified", lambda _capability: None)
    # The firing that places the hold, and the one after it that the hold refuses.
    outcomes = []
    for _ in range(2):
        status = runtime.main(arguments)
        captured = capsys.readouterr()
        outcomes.append((status, captured.out, captured.err))
    assert site.intent().holds == {"camera": HOLD}
    assert outcomes[0] == outcomes[1]
    assert outcomes[0] == (69, "", '{"error":"runtime-evidence-or-authority-incomplete"}\n')
    assert starts(site.inner) == ["example-camera"] * 3


def _authored() -> dict[str, Any]:
    """Every installation member that could be written before this one."""
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
                    }
                ],
            }
        ],
        "policy": "/private/network.json",
        "admissions": "/private/state/admissions.json",
        "intent": "/private/state/intent.json",
        "state_dir": "/private/state",
        "start_timeout_seconds": 15,
        "fleet_start": {
            "api_label": "com.apple.container.apiserver",
            "api_executable": "/Library/ExampleVendor/libexec/api-server",
            "runtime_label_prefix": "com.apple.container.",
        },
    }


def test_settings_without_a_budget_keep_their_bytes() -> None:
    """Vendor identity fixture changed; undeclared shipped bytes remain pinned."""
    settings = parse_settings(_authored())
    stored = canonical_bytes(settings_to_dict(settings))
    assert b"restart_budget" not in stored
    assert (
        hashlib.sha256(stored).hexdigest()
        == "0a04e844aa59161821368f48993b4ce44f5c65204241e008c351a52ec7ecf692"
    )
    assert (
        contract_digest(settings.contract("camera"))
        == "2d53d782e19e5f6f94fe55555a42db5195dd6e0df0af7bfd9ceca6d3a615d364"
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


def test_settings_with_a_budget_store_it_as_one_object() -> None:
    plain = parse_settings(_authored())
    assert plain.restart_budget is None
    document = _authored()
    document["restart_budget"] = {"starts": 3, "window_seconds": 600}
    budgeted = parse_settings(document)
    assert budgeted == replace(plain, restart_budget=runtime_settings.RestartBudget(3, 600))
    assert settings_to_dict(budgeted) == {
        **settings_to_dict(plain),
        "restart_budget": {"starts": 3, "window_seconds": 600},
    }
    assert parse_settings(settings_to_dict(budgeted)) == budgeted
    # The budget is a setting of recovery. It is part of no contract, so no
    # derived policy and no admission of a profile changes with it.
    assert contract_digest(budgeted.contract("camera")) == contract_digest(plain.contract("camera"))
    # The shipped example has the layout a budget needs.
    shipped = json.loads((EXAMPLES / "runtime-settings.json").read_bytes())
    shipped["restart_budget"] = {"starts": 3, "window_seconds": 600}
    assert parse_settings(shipped).restart_budget == runtime_settings.RestartBudget(3, 600)


@pytest.mark.parametrize(
    "budget",
    [
        {"starts": 1, "window_seconds": 60},
        {"starts": 10, "window_seconds": 86400},
        {"starts": 3, "window_seconds": 600},
    ],
    ids=lambda value: canonical_bytes(value).decode(),
)
def test_a_budget_within_its_bounds_is_accepted(budget: dict[str, int]) -> None:
    document = _authored()
    document["restart_budget"] = budget
    stated = parse_settings(document).restart_budget
    assert (stated.starts, stated.window_seconds) == (budget["starts"], budget["window_seconds"])
    assert type(stated.starts) is int and type(stated.window_seconds) is int


@pytest.mark.parametrize(
    "budget",
    [
        None,
        {},
        [],
        3,
        "3 in 600",
        {"starts": 3},
        {"window_seconds": 600},
        {"starts": 3, "window_seconds": 600, "cycles": 40},
        {"starts": 0, "window_seconds": 600},
        {"starts": 11, "window_seconds": 600},
        {"starts": -1, "window_seconds": 600},
        {"starts": True, "window_seconds": 600},
        {"starts": 3.0, "window_seconds": 600},
        {"starts": "3", "window_seconds": 600},
        {"starts": None, "window_seconds": 600},
        {"starts": 3, "window_seconds": 59},
        {"starts": 3, "window_seconds": 86401},
        {"starts": 3, "window_seconds": True},
        {"starts": 3, "window_seconds": 600.0},
        {"starts": 3, "window_seconds": "600"},
        {"starts": 3, "window_seconds": None},
    ],
    ids=lambda value: canonical_bytes(value).decode(),
)
def test_every_other_spelling_of_a_budget_is_refused(budget: Any) -> None:
    document = _authored()
    document["restart_budget"] = budget
    with pytest.raises(ValueError):
        parse_settings(document)


@pytest.mark.parametrize(
    "change",
    [
        {"state_dir": None},
        {"intent": None},
        {"intent": None, "state_dir": None},
        {"intent": "/private/intent.json"},
        {"intent": "/private/state/runtime/intent.json"},
        {"intent": "/private/state/operator-intent.json"},
        {"intent": "/private/state//intent.json"},
        {"state_dir": "/private/state/runtime"},
    ],
    ids=lambda value: canonical_bytes(value).decode(),
)
def test_a_budget_needs_the_intent_file_of_the_state_directory(change: dict[str, Any]) -> None:
    document = _authored()
    for key, value in change.items():
        if value is None:
            del document[key]
        else:
            document[key] = value
    # Without a budget these are settings like any other.
    assert parse_settings(document).restart_budget is None
    document["restart_budget"] = {"starts": 3, "window_seconds": 600}
    with pytest.raises(ValueError, match="restart budget"):
        parse_settings(document)


@pytest.fixture
def data() -> dict[str, Any]:
    return json.loads((EXAMPLES / "instance.json").read_bytes())


@pytest.mark.parametrize(
    "budget",
    [
        {"starts": 1, "window_seconds": 60},
        {"starts": 10, "window_seconds": 86400},
        {"starts": 4, "window_seconds": 1200},
    ],
    ids=lambda value: canonical_bytes(value).decode(),
)
def test_the_retained_supervisor_honours_every_budget_an_instance_can_state(
    data: dict[str, Any], budget: dict[str, int]
) -> None:
    data["supervision"]["restart_budget"] = budget
    instance = parsed(data)
    assert instance.supervision.restart_budget is not None
    assert tuple(instance_module.retained_supervision_gaps(instance)) == ()
    # What the instance states is what the runtime settings take.
    document = _authored()
    document["restart_budget"] = budget
    stated = parse_settings(document).restart_budget
    assert (stated.starts, stated.window_seconds) == (
        instance.supervision.restart_budget.starts,
        instance.supervision.restart_budget.window_seconds,
    )


@pytest.mark.parametrize(
    "budget",
    [
        {"starts": 0, "window_seconds": 60},
        {"starts": 11, "window_seconds": 86400},
        {"starts": 1, "window_seconds": 59},
        {"starts": 10, "window_seconds": 86401},
    ],
    ids=lambda value: canonical_bytes(value).decode(),
)
def test_both_vocabularies_end_at_the_same_bounds(
    data: dict[str, Any], budget: dict[str, int]
) -> None:
    data["supervision"]["restart_budget"] = budget
    with pytest.raises(instance_module.InstanceError):
        parsed(data)
    document = _authored()
    document["restart_budget"] = budget
    with pytest.raises(ValueError, match="restart budget"):
        parse_settings(document)

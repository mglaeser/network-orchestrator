"""The restart budget where something cannot be stored, read or timed.

A spent budget must not come back by itself. Where the hold cannot be stored,
the record of that workload is stored as spent in a form that does not age,
and no start follows until the hold could be stored. A record that could not
be read at all is no content: that firing starts nothing and changes nothing.
A start is recorded with its time rounded up to a whole second, so a window
never ends early. Fake runner only; nothing waits, and one test reads the real
calendar clock because it is the default it has to prove.
"""

from __future__ import annotations

import errno
import inspect
import math
import os
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch import runtime_settings
from netorch.codec import digest
from netorch.model import Service
from netorch.runtime_settings import (
    FileIdentity,
    RuntimeContract,
    contract_digest,
    parse_settings,
    settings_to_dict,
)
from netorch.state import MAX_HELD_SERVICES, Intent, intent_to_dict
from netorch.storage import Store
from tests.test_apple_runtime import enrolled
from tests.test_runtime_restart_budget import HOLD, NOT_HELD, RECORD, T0, Site, _authored
from tests.test_service_holds import starts

__all__ = ["enrolled"]

# `NOT_HELD` is what recovery stores for a workload whose budget is spent while
# its hold cannot be stored: the latest second an entry can name, as often as
# the largest budget. It is inside every window and spends every budget.
# Firings after the budget was spent at T0, T0 + 10 and T0 + 20 with a window
# of 600 seconds: inside it, at the second each start would have left it, and
# long after.
LATER = (30, 300, 599, 600, 610, 620, 1200, 86400, 365 * 86400)
YEARS = 365 * 86400


def holds_of(site: Site) -> dict[str, dict[str, str]]:
    """The holds as recovery and the probe read them, also in a file the store refuses."""
    intent = runtime._intent(site.settings)
    return {service: dict(records) for service, records in intent.holds.items()}


def stays_spent(site: Site) -> None:
    """Spent, and the hold cannot be stored: no later firing starts anything."""
    issued = starts(site.inner)
    assert issued == ["example-camera"] * 3
    for later in LATER:
        assert site.refused(at=T0 + later).reason == "incomplete"
        assert starts(site.inner) == issued
        assert "camera" not in holds_of(site)
        assert site.record()["camera"] == NOT_HELD
    # A larger budget does not make it unspent either.
    stated = site.settings
    site.settings = replace(stated, restart_budget=runtime_settings.RestartBudget(10, 600))
    assert site.refused(at=T0 + YEARS + 1).reason == "incomplete"
    assert starts(site.inner) == issued
    site.settings = stated


def held_once_the_hold_can_be_stored(site: Site, monkeypatch: pytest.MonkeyPatch) -> None:
    issued = starts(site.inner)
    assert site.refused(at=T0 + 2 * YEARS).reason == "incomplete"
    assert holds_of(site)["camera"] == HOLD
    # The hold cleared the record, so the release gives the whole budget again.
    assert "camera" not in site.record()
    assert starts(site.inner) == issued
    assert site.unhold(monkeypatch) == 0
    site.spend(start=T0 + 3 * YEARS)
    assert starts(site.inner) == [*issued, *["example-camera"] * 3]
    assert site.record()["camera"] == [T0 + 3 * YEARS + 10 * index for index in range(3)]


def test_a_spent_budget_stays_spent_while_the_store_refuses_the_intent_file(
    enrolled: Any,
) -> None:
    site = Site(enrolled, 3, 600)
    site.spend()
    intent = site.store.directory / "intent.json"
    # Not private to the account. Recovery and the probe read the intent by the
    # state store's own rule, so they read damage, which blocks every workload
    # before a budget is consulted: nothing starts and the record is kept.
    intent.chmod(0o644)
    assert runtime._intent(site.settings).damaged
    issued, recorded = starts(site.inner), site.record()
    for later in LATER:
        assert site.refused(at=T0 + later).reason == "incomplete"
        assert starts(site.inner) == issued
        assert site.record() == recorded
    intent.chmod(0o600)
    # Readable again inside the window: the budget is spent and the hold is stored.
    assert site.refused(at=T0 + LATER[0]).reason == "incomplete"
    assert holds_of(site)["camera"] == HOLD
    assert "camera" not in site.record()
    assert starts(site.inner) == issued


def enlarged(enrolled: Any, tmp_path: Path, extra: int) -> tuple[Any, Any, Any]:
    """The enrolled installation with `extra` more workloads, all of them running."""
    config, settings, items = enrolled
    owner = config.services[0].owner
    contracts, services = list(settings.contracts), list(config.services)
    for index in range(extra):
        name = f"extra-{index}"
        directory = (tmp_path / name).resolve()
        directory.mkdir(mode=0o700)
        meta = directory.stat()
        configuration = {
            "mounts": [{"source": str(directory), "options": ["rw"]}],
            "publishedPorts": [],
            "cpus": 1,
            "memory": 512,
        }
        contract = RuntimeContract(
            name,
            "example-" + name,
            "wired-lan",
            digest(configuration),
            (FileIdentity(str(directory), "directory", os.geteuid(), meta.st_dev, meta.st_ino),),
        )
        contracts.append(contract)
        services.append(Service(name, owner, contract_digest(contract)))
        items[contract.name] = {
            "id": contract.name,
            "configuration": configuration,
            "status": {
                "state": "running",
                "startedDate": "2026-01-01T00:00:00Z",
                "networks": [
                    {
                        "network": "example-network",
                        "ipv4Address": f"198.51.100.{index + 100}/24",
                        "ipv4Gateway": "198.51.100.1",
                    }
                ],
            },
        }
    return (
        replace(config, services=tuple(services)),
        replace(settings, contracts=tuple(contracts)),
        items,
    )


def test_a_spent_budget_stays_spent_while_the_intent_file_holds_no_further_service(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = Site(enlarged(enrolled, tmp_path, MAX_HELD_SERVICES), 3, 600)
    full = Intent()
    for index in range(MAX_HELD_SERVICES):
        full = full.hold(f"extra-{index}", "maintenance", "manager")
    site.store.write("intent.json", intent_to_dict(full))
    assert len(holds_of(site)) == MAX_HELD_SERVICES == 64
    assert not runtime._intent(site.settings).blocks("camera")
    site.spend()
    stays_spent(site)
    # One of the other holds is released: there is room for this one now.
    site.store.write(
        "intent.json", intent_to_dict(full.unhold("extra-0", "maintenance", "manager"))
    )
    held_once_the_hold_can_be_stored(site, monkeypatch)
    assert len(holds_of(site)) == MAX_HELD_SERVICES - 1


def test_a_spent_budget_stays_spent_while_the_hold_cannot_be_written(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = Site(enrolled, 3, 600)
    site.spend()
    # A workload that is no longer enrolled is on record as well.
    site.store.write(
        RECORD,
        {"schema_version": 1, "services": {**site.record(), "retired": [T0], "resolver": [T0]}},
    )
    write = Store.write

    def unwritable(store: Store, name: str, value: Any) -> None:
        if name == "intent.json":
            raise OSError(errno.EACCES, "permission denied")
        write(store, name, value)

    with monkeypatch.context() as failing:
        failing.setattr(Store, "write", unwritable)
        stays_spent(site)
        # What is stored instead names enrolled workloads only and leaves the
        # count of every other workload as it was.
        assert site.record() == {"camera": NOT_HELD, "resolver": [T0]}
    held_once_the_hold_can_be_stored(site, monkeypatch)
    assert site.record()["resolver"] == [T0]


def test_nothing_is_started_while_neither_the_hold_nor_the_record_can_be_written(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = Site(enrolled, 3, 600)
    site.spend()
    record = (site.store.directory / RECORD).read_bytes()
    intent = (site.store.directory / "intent.json").read_bytes()

    def unwritable(store: Store, name: str, value: Any) -> None:
        raise OSError(errno.ENOSPC, "no space left on device")

    with monkeypatch.context() as full:
        full.setattr(Store, "write", unwritable)
        # Also after the window: a start cannot be recorded, so none is issued.
        for later in LATER:
            assert site.refused(at=T0 + later).reason == "incomplete"
            assert starts(site.inner) == ["example-camera"] * 3
    assert (site.store.directory / RECORD).read_bytes() == record
    assert (site.store.directory / "intent.json").read_bytes() == intent


def test_a_lost_record_and_a_hold_that_cannot_be_stored_start_nothing(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = Site(enrolled, 3, 600)
    path = site.store.directory / RECORD
    path.write_bytes(b"{")
    path.chmod(0o600)
    write = Store.write

    def unwritable(store: Store, name: str, value: Any) -> None:
        if name == "intent.json":
            raise OSError(errno.EACCES, "permission denied")
        write(store, name, value)

    with monkeypatch.context() as failing:
        failing.setattr(Store, "write", unwritable)
        for later in (0, 599, 600, 86400):
            assert site.refused(at=T0 + later).reason == "incomplete"
        # No hold and nothing known: the record stays as unreadable as it is,
        # which counts as spent at every later firing too.
        assert path.read_bytes() == b"{"
        assert not holds_of(site)
    assert starts(site.inner) == []
    site.refused(at=T0 + 86401)
    assert holds_of(site) == {"camera": HOLD}


def test_an_unusable_clock_and_a_hold_that_cannot_be_stored_leave_the_budget_spent(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = Site(enrolled, 3, 600)
    write = Store.write

    def unwritable(store: Store, name: str, value: Any) -> None:
        if name == "intent.json":
            raise OSError(errno.EACCES, "permission denied")
        write(store, name, value)

    with monkeypatch.context() as failing:
        failing.setattr(Store, "write", unwritable)
        # No start is on record yet. The clock gives no time, which counts as a
        # spent budget; not held, that must not become an unused one later.
        assert site.refused(at=math.nan).reason == "incomplete"
        assert site.record() == {"camera": NOT_HELD}
        assert site.refused(at=T0).reason == "incomplete"
        assert not holds_of(site)
    assert starts(site.inner) == []
    site.refused(at=T0 + 1)
    assert holds_of(site) == {"camera": HOLD}
    assert site.record() == {}


@pytest.mark.parametrize("error", [errno.EIO, errno.ENFILE, errno.EACCES])
def test_a_record_that_could_not_be_read_is_not_content(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, error: int
) -> None:
    site = Site(enrolled, 3, 600)
    site.recover("resolver", T0)
    site.recover("camera", T0 + 1)
    record = (site.store.directory / RECORD).read_bytes()
    intent = (site.store.directory / "intent.json").read_bytes()
    read = Store.read
    failed: list[str] = []

    def once(store: Store, name: str) -> Any:
        if name == RECORD and not failed:
            failed.append(name)
            raise OSError(error, os.strerror(error))
        return read(store, name)

    monkeypatch.setattr(Store, "read", once)
    # The file is intact; one read of it fails.
    assert site.refused("camera", T0 + 5).reason == "incomplete"
    assert failed == [RECORD]
    # Nothing was started on that firing, nothing was held and nothing rewritten.
    assert starts(site.inner) == ["example-resolver", "example-camera"]
    assert (site.store.directory / RECORD).read_bytes() == record
    assert (site.store.directory / "intent.json").read_bytes() == intent
    # The next firing behaves as if nothing had happened, for this workload
    # and for every other one.
    site.recover("camera", T0 + 10)
    site.recover("web-proxy", T0 + 20)
    assert not site.intent().holds
    assert site.record() == {
        "resolver": [T0],
        "camera": [T0 + 1, T0 + 10],
        "web-proxy": [T0 + 20],
    }
    site.recover("camera", T0 + 30)
    site.refused("camera", T0 + 40)
    assert site.intent().holds == {"camera": HOLD}


@pytest.mark.parametrize(
    ("begun", "fired", "started"),
    [
        # Seconds after T0 of the start and of the next firing; the window is 60.
        (0.25, 59.25, False),
        # 59.75 seconds after the start: inside the window.
        (0.25, 60.0, False),
        # 59.5 seconds after a start late in its second, early in the firing's.
        (0.75, 60.25, False),
        # The entry is the next whole second after the start, so the window
        # can end up to one second late: here 60.5 seconds after the start.
        (0.25, 60.75, False),
        (0.25, 61.0, True),
        (0.75, 61.0, True),
        (0.25, 61.25, True),
    ],
)
def test_a_window_never_ends_early_and_at_most_one_second_late(
    enrolled: Any, begun: float, fired: float, started: bool
) -> None:
    site = Site(enrolled, 1, 60)
    # A clock with fractions, as the calendar clock gives it.
    assert site.recover(at=T0 + begun).services["camera"].state == "present"
    assert site.record() == {"camera": [T0 + 1]}
    assert type(site.record()["camera"][0]) is int
    if started:
        assert site.recover(at=T0 + fired).services["camera"].state == "present"
        assert starts(site.inner) == ["example-camera"] * 2
        assert site.record() == {"camera": [math.ceil(T0 + fired)]}
        assert not site.intent().holds
    else:
        site.refused(at=T0 + fired)
        assert starts(site.inner) == ["example-camera"]
        assert site.intent().holds == {"camera": HOLD}


def test_a_start_on_a_whole_second_is_recorded_as_that_second(enrolled: Any) -> None:
    site = Site(enrolled, 1, 60)
    site.recover(at=float(T0))
    assert site.record() == {"camera": [T0]}
    assert site.recover(at=T0 + 60.0).services["camera"].state == "present"
    assert site.record() == {"camera": [T0 + 60]}


def test_a_lost_record_counts_as_spent_from_the_next_whole_second(enrolled: Any) -> None:
    site = Site(enrolled, 3, 600)
    path = site.store.directory / RECORD
    path.write_bytes(b"{")
    path.chmod(0o600)
    site.refused(at=T0 + 0.25)
    assert site.intent().holds == {"camera": HOLD}
    assert site.record() == {
        service: [T0 + 1] * 3 for service in ("media-controller", "resolver", "web-proxy")
    }
    # One period by the clock, never less.
    site.refused("resolver", T0 + 600.75)
    assert site.recover("web-proxy", T0 + 601.0).services["web-proxy"].state == "present"


@pytest.mark.parametrize(
    "now", [10**400, -(10**400)], ids=["beyond every float", "below every float"]
)
def test_an_integer_that_no_float_holds_is_no_usable_time(enrolled: Any, now: int) -> None:
    site = Site(enrolled)
    site.store.write(RECORD, {"schema_version": 1, "services": {"resolver": [T0]}})
    # As for every clock that gives no usable time: a spent budget, no error.
    assert site.refused(at=now).reason == "incomplete"
    assert starts(site.inner) == []
    assert site.intent().holds == {"camera": HOLD}
    assert site.record() == {"resolver": [T0]}


@pytest.mark.parametrize("now", [0, 0.0, 2**31, 2**31 + 0.5, 2**40, 2**53 - 1], ids=repr)
def test_every_time_an_entry_can_name_is_usable(enrolled: Any, now: float) -> None:
    site = Site(enrolled, 2, 600)
    stamp = math.ceil(now)
    assert site.recover(at=now).services["camera"].state == "present"
    assert site.record() == {"camera": [stamp]}
    # The entry is read back as a record: the second start is counted beside it.
    assert site.recover(at=now).services["camera"].state == "present"
    assert site.record() == {"camera": [stamp, stamp]}
    site.refused(at=now)
    assert starts(site.inner) == ["example-camera"] * 2
    assert site.intent().holds == {"camera": HOLD}
    assert site.record() == {}


def test_the_default_clock_is_the_calendar_clock(enrolled: Any) -> None:
    """The record has to outlive a boot, which the monotonic clock does not."""
    assert inspect.signature(runtime.recover_service).parameters["wall"].default is time.time
    site = Site(enrolled, 2, 600)
    site.inner.items["example-camera"]["status"]["state"] = "stopped"
    before = time.time()
    # No clock is passed: this is what the `start` command runs.
    recovered = runtime.recover_service(site.config, site.settings, "camera", site.runner)
    after = time.time()
    assert recovered.services["camera"].state == "present"
    (entry,) = site.record()["camera"]
    assert type(entry) is int
    # A minute of slack for a clock that is being adjusted; the monotonic
    # clock counts from another origin altogether.
    assert before - 60 <= entry <= after + 60
    assert not site.intent().holds


def test_a_record_of_the_largest_budget_is_read_as_a_record(enrolled: Any) -> None:
    site = Site(enrolled, 10, 86400)
    site.recover("resolver", T0)
    site.spend()
    assert site.record() == {
        "resolver": [T0],
        "camera": [T0 + 10 * index for index in range(10)],
    }
    site.refused(at=T0 + 100)
    assert starts(site.inner) == ["example-resolver", *["example-camera"] * 10]
    assert site.intent().holds == {"camera": HOLD}
    # Held because the budget is spent, not because ten entries said nothing:
    # the other workload keeps exactly its own count.
    assert site.record() == {"resolver": [T0]}


def test_a_record_of_256_services_is_read_as_a_record(enrolled: Any) -> None:
    site = Site(enrolled)
    retired = {f"retired-{index}": [T0] for index in range(255)}
    site.store.write(RECORD, {"schema_version": 1, "services": {**retired, "resolver": [T0 - 5]}})
    assert len(site.record()) == 256
    assert site.recover(at=T0 + 1).services["camera"].state == "present"
    # What is written names enrolled workloads only.
    assert site.record() == {"resolver": [T0 - 5], "camera": [T0 + 1]}


def test_the_record_written_with_the_hold_names_enrolled_workloads_only(enrolled: Any) -> None:
    site = Site(enrolled, 1, 600)
    site.store.write(
        RECORD,
        {"schema_version": 1, "services": {"camera": [T0], "retired": [T0], "resolver": [T0]}},
    )
    site.refused(at=T0 + 10)
    assert starts(site.inner) == []
    assert site.intent().holds == {"camera": HOLD}
    assert site.record() == {"resolver": [T0]}


def test_every_budget_is_stored_as_it_was_stated() -> None:
    for count in range(1, 11):
        for window in (60, 61, 600, 86399, 86400):
            document = _authored()
            document["restart_budget"] = {"starts": count, "window_seconds": window}
            settings = parse_settings(document)
            stored = settings_to_dict(settings)
            assert stored["restart_budget"] == {"starts": count, "window_seconds": window}
            assert parse_settings(stored) == settings

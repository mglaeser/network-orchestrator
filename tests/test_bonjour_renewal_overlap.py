"""`renewal_overlap_seconds`: a registration is renewed beside the client it replaces.

Every registration client carries its own lifetime (``dns-sd -t``, 120 seconds
at most). Without the setting the publisher starts a replacement only after
that client has ended, so each record leaves the network for a moment at least
every two minutes. With it the replacement is started that many seconds before
the running client's lifetime ends, and the running client ends on its own
timer.

The fake client below honours its lifetime on an injected clock and ends by
itself, as Apple's client does (``Clients/dns-sd.c`` lines 1315-1320 at
``mDNSResponder-2881.120.11``). ``BASE_SEQUENCE`` was recorded on the tree
before the setting existed, so the test that uses it passes there too: without
the setting nothing changes. Names are invented, addresses are RFC 5737, and
nothing here talks to a daemon.
"""

from __future__ import annotations

import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, ClassVar

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.config import to_dict
from netorch.discovery import Record
from netorch.model import Config, Discovery
from netorch.state import Intent
from netorch.storage import Store
from tests.test_bonjour_miss_tolerance import leased, observed, settings_file
from tests.test_bonjour_owner import (
    config,
    expected_settings,
    policy,
    settings,
    write_private,
)
from tests.test_bonjour_record_expiry import FAKE_CLIENT, READY, lease, two_records

__all__ = ["config", "settings"]

IMPORT = "media-import"
WALL = 1_000_000.0  # the wall clock when the injected clock starts
OVERLAP = 10
# Without the setting, on the tree before it existed: one source from the start
# and a second one from 30 seconds on, both seen again by every pass, ticks of
# five seconds for 400 seconds, leases of 300 seconds.
BASE_SEQUENCE = [
    "0 start Example speaker 1 -t 120",
    "0 confirmed True renewing 0",
    "30 start Second speaker 1 -t 120",
    "30 confirmed True renewing 0",
    "120 close Example speaker 1 ended",
    "120 start Example speaker 2 -t 120",
    "120 confirmed False renewing 1",
    "125 confirmed True renewing 0",
    "150 close Second speaker 1 ended",
    "150 start Second speaker 2 -t 120",
    "150 confirmed False renewing 1",
    "155 confirmed True renewing 0",
    "240 close Example speaker 2 ended",
    "240 start Example speaker 3 -t 120",
    "240 confirmed False renewing 1",
    "245 confirmed True renewing 0",
    "270 close Second speaker 2 ended",
    "270 start Second speaker 3 -t 120",
    "270 confirmed False renewing 1",
    "275 confirmed True renewing 0",
    "360 close Example speaker 3 ended",
    "360 start Example speaker 4 -t 120",
    "360 confirmed False renewing 1",
    "365 confirmed True renewing 0",
    "390 close Second speaker 3 ended",
    "390 start Second speaker 4 -t 120",
    "390 confirmed False renewing 1",
    "395 confirmed True renewing 0",
]


class Clock:
    """The publisher's clock: the wall clock runs at a fixed offset from the monotonic one."""

    def __init__(self) -> None:
        self.elapsed = 0.0

    def monotonic(self) -> float:
        return 500.0 + self.elapsed

    def time(self) -> float:
        return WALL + self.elapsed


class Client:
    """Stands in for Registration and, like the native client, ends by itself.

    Its lifetime runs on the injected clock from its start; ``late`` is how much
    later than that its own timer fires. From then on poll() reports the timer
    as Registration.poll does. close() notes whether the client had ended by
    then or was still running, which is what a signal would have met.
    """

    made: ClassVar[list[Client]] = []
    events: ClassVar[list[str]] = []
    clock: ClassVar[Clock]
    confirm_after: ClassVar[float] = 0.0

    def __init__(self, record: Record, index: int, lifetime_seconds: int = 120) -> None:
        self.record = record
        self.index = index
        self.lifetime_seconds = lifetime_seconds
        self.spawned = Client.clock.monotonic()
        self.confirms_at = self.spawned + Client.confirm_after
        self.late = 0.0
        self.active = False
        self.closed = False
        self.failure: native.DiscoveryFailure | None = None
        number = 1 + sum(item.record.name == record.name for item in Client.made)
        self.label = f"{record.name} {number}"
        Client.made.append(self)
        Client.events.append(f"{Client.clock.elapsed:g} start {self.label} -t {lifetime_seconds}")

    @property
    def ended(self) -> bool:
        return Client.clock.monotonic() - self.spawned >= self.lifetime_seconds + self.late

    @property
    def running(self) -> bool:
        return not self.closed and not self.ended

    def poll(self) -> bool:
        if self.closed:
            raise native.DiscoveryFailure("unavailable")
        if self.failure is not None:
            raise self.failure
        if self.ended:
            raise native.RegistrationExpired()
        self.active = Client.clock.monotonic() >= self.confirms_at
        return self.active

    def close(self) -> None:
        if not self.closed:
            state = "ended" if self.ended else "running"
            Client.events.append(f"{Client.clock.elapsed:g} close {self.label} {state}")
        self.closed = True


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    Client.clock = Clock()
    Client.made = []
    Client.events = []
    Client.confirm_after = 0.0
    monkeypatch.setattr(owner, "time", Client.clock)
    return Client.clock


def publisher(overlap: int | None = None) -> owner.Publisher:
    if overlap is None:
        return owner.Publisher(Client)  # type: ignore[arg-type]
    return owner.Publisher(Client, renewal_overlap=overlap)  # type: ignore[arg-type]


def named(name: str) -> list[Client]:
    return [item for item in Client.made if item.record.name == name]


def running(name: str) -> list[Client]:
    return [item for item in named(name) if item.running]


def started() -> list[str]:
    return [event for event in Client.events if " start " in event]


def tick(
    manager: owner.Publisher,
    item: Discovery,
    clock: Clock,
    *,
    seen: float | None = None,
    sources: int = 1,
) -> bool:
    """One turn of the publisher's loop; the source was last seen now unless told when."""
    manager.expire(clock.monotonic())
    seen_at = clock.time() if seen is None else WALL + seen
    return manager.reconcile(item, two_records(seen_at)[:sources], 7, clock.time())


def run(
    manager: owner.Publisher,
    item: Discovery,
    clock: Clock,
    until: float,
    *,
    step: float = 1.0,
    seen: float | None = None,
    sources: int = 1,
) -> list[tuple[bool, int]]:
    """Tick until the clock reads ``until``; what each tick reported."""
    reported = []
    while clock.elapsed < until:
        confirmed = tick(manager, item, clock, seen=seen, sources=sources)
        reported.append((confirmed, manager.renewals(item)))
        clock.elapsed += step
    return reported


def long_lease(config: Config, seconds: int = 300) -> Discovery:
    """The import policy with a lease that lets a client live its full 120 seconds."""
    found: Discovery = policy(leased(config, seconds))
    return found


# Without the setting


def test_without_the_setting_the_sequence_of_calls_is_that_of_the_base(
    config: Config, clock: Clock
) -> None:
    manager = publisher()
    item = long_lease(config)
    while clock.elapsed < 400:
        before = (len(Client.events), manager.renewals(item))
        confirmed = tick(manager, item, clock, sources=2 if clock.elapsed >= 30 else 1)
        if (len(Client.events), manager.renewals(item)) != before:
            Client.events.append(
                f"{clock.elapsed:g} confirmed {confirmed} renewing {manager.renewals(item)}"
            )
        clock.elapsed += 5
    assert Client.events == BASE_SEQUENCE
    # No client ever ran beside another one of its record.
    assert all(" ended" in event for event in Client.events if " close " in event)


def test_settings_without_the_key_load_as_before(
    settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    loaded = owner.load_settings(
        write_private(tmp_path / "bonjour.json", expected_settings(settings))
    )
    assert loaded == settings
    assert loaded.renewal_overlap_seconds is None


def constructed(
    monkeypatch: pytest.MonkeyPatch, config: Config, settings: owner.BonjourSettings
) -> list[tuple[tuple[Any, ...], dict[str, Any]]]:
    """How the publisher process constructs its Publisher for these settings."""
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    made = owner.Publisher

    def construct(*arguments: Any, **keywords: Any) -> owner.Publisher:
        calls.append((arguments, keywords))
        return made(*arguments, **keywords)

    monkeypatch.setattr(owner, "Publisher", construct)
    monkeypatch.setattr(owner, "_signal_stop", lambda _function: None)
    monkeypatch.setattr(owner.os, "getppid", lambda: 1)
    owner.publisher_loop(config, settings, Store(settings.state_dir), parent_pid=4242)
    return calls


@pytest.mark.parametrize(
    ("overlap", "keywords"), [(None, {}), (OVERLAP, {"renewal_overlap": OVERLAP})]
)
def test_publisher_process_takes_the_overlap_from_its_settings(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    overlap: int | None,
    keywords: dict[str, int],
) -> None:
    # Without the setting the publisher is constructed exactly as before.
    own = settings if overlap is None else replace(settings, renewal_overlap_seconds=overlap)
    assert constructed(monkeypatch, config, own) == [((), keywords)]


# The overlap


def test_replacement_starts_the_overlap_before_the_running_client_ends(
    config: Config, clock: Clock
) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config)
    run(manager, item, clock, 110)
    (first,) = Client.made
    assert first.lifetime_seconds == 120 and clock.elapsed == 110
    assert tick(manager, item, clock)
    # At its lifetime minus the overlap, with the lease that is left (120 at most).
    first, second = Client.made
    assert second.spawned - first.spawned == 120 - OVERLAP and second.lifetime_seconds == 120
    assert second.record.name == first.record.name and second.index == first.index
    assert not first.closed and running("Example speaker") == [first, second]
    clock.elapsed += 1
    assert set(run(manager, item, clock, 120)) == {(True, 0)}
    # The running client is never signalled to make room: one second before its
    # own timer it has not been touched.
    clock.elapsed = 119
    assert not first.closed and running("Example speaker") == [first, second]
    assert Client.events == [
        "0 start Example speaker 1 -t 120",
        "110 start Example speaker 2 -t 120",
    ]
    clock.elapsed = 120
    assert tick(manager, item, clock)
    # It has ended by itself; only then is it reaped, and its replacement holds the record.
    assert Client.events[2:] == ["120 close Example speaker 1 ended"]
    assert list(manager.children.values()) == [second] and manager.successors == {}
    clock.elapsed += 1
    run(manager, item, clock, 400)
    assert started() == [
        "0 start Example speaker 1 -t 120",
        "110 start Example speaker 2 -t 120",
        "220 start Example speaker 3 -t 120",
        "330 start Example speaker 4 -t 120",
    ]


def test_record_is_confirmed_without_interruption_and_counted_once(
    config: Config, clock: Clock
) -> None:
    item = long_lease(config)
    reported = run(publisher(OVERLAP), item, clock, 1000, sources=2)
    # Confirmed at every tick, and never between two clients.
    assert set(reported) == {(True, 0)}
    assert len(named("Example speaker")) == len(named("Second speaker")) == 10
    # The same sources without the setting: each renewal is a moment between two clients.
    Client.clock.elapsed = 0.0
    Client.made, Client.events = [], []
    plain = run(publisher(), item, clock, 1000, sources=2)
    assert set(plain) == {(True, 0), (False, 2)}


def test_old_client_is_never_closed_before_its_own_end(config: Config, clock: Clock) -> None:
    manager = publisher(OVERLAP)
    run(manager, long_lease(config), clock, 1000, sources=2)
    closes = [event for event in Client.events if " close " in event]
    assert len(closes) == 2 * 8 and all(event.endswith(" ended") for event in closes)
    # Each replaced client was closed in the tick in which its own lifetime was over.
    for item in Client.made:
        if item.closed:
            assert f"{item.spawned - 500.0 + 120:g} close {item.label} ended" in closes


def test_never_more_than_two_clients_for_a_record_and_two_only_during_the_overlap(
    config: Config, clock: Clock
) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config)
    while clock.elapsed < 1000:
        assert tick(manager, item, clock, sources=2)
        # Two for the overlap's ten seconds of every 110, one for the other hundred.
        overlapping = clock.elapsed >= 110 and clock.elapsed % 110 < OVERLAP
        for name in ("Example speaker", "Second speaker"):
            assert len(running(name)) == (2 if overlapping else 1)
        assert len(manager.children) == 2
        assert len(manager.successors) == (2 if overlapping else 0)
        clock.elapsed += 1
    assert len(Client.made) == 2 * 10


def test_slow_replacement_does_not_show_while_the_running_client_confirms(
    config: Config, clock: Clock
) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config)
    run(manager, item, clock, 110)
    Client.confirm_after = 4.0
    # During the overlap the record is confirmed by its running client: it is
    # neither reported unconfirmed nor counted out while its replacement confirms.
    assert run(manager, item, clock, 114) == [(True, 0)] * 4
    replacement = Client.made[1]
    assert not replacement.active and manager.successors
    assert run(manager, item, clock, 120) == [(True, 0)] * 6
    assert replacement.active


def test_client_that_has_not_confirmed_gets_no_replacement_beside_it(
    config: Config, clock: Clock
) -> None:
    manager = publisher(29)
    item = long_lease(config, 30)
    Client.confirm_after = 3.0
    # From its second second on it is inside the overlap, but it holds nothing yet.
    assert run(manager, item, clock, 3) == [(False, 0)] * 3
    assert len(Client.made) == 1
    assert run(manager, item, clock, 5) == [(True, 0)] * 2
    assert started() == ["0 start Example speaker 1 -t 30", "3 start Example speaker 2 -t 30"]


def test_replacement_that_has_not_confirmed_when_its_predecessor_ends_is_between_two_clients(
    config: Config, clock: Clock
) -> None:
    manager = publisher(2)
    item = long_lease(config)
    run(manager, item, clock, 118)
    Client.confirm_after = 4.0
    assert run(manager, item, clock, 120) == [(True, 0)] * 2
    # The first client has ended and the second has not confirmed yet: the
    # policy becomes unknown until that new client confirms.
    assert run(manager, item, clock, 122) == [(False, 1)] * 2
    assert run(manager, item, clock, 125) == [(True, 0)] * 3
    assert len(Client.made) == 2


@pytest.mark.parametrize(
    "reason", ["timed-out", "identity-mismatch", "unavailable", "local-network-denied"]
)
def test_failed_replacement_during_the_overlap_is_a_failure_as_today(
    config: Config, clock: Clock, reason: str
) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config)
    run(manager, item, clock, 111, sources=2)
    first, second, replacement, _other = Client.made
    assert replacement.record.name == first.record.name and len(manager.successors) == 2
    replacement.failure = native.DiscoveryFailure(reason)
    with pytest.raises(native.DiscoveryFailure) as caught:
        tick(manager, item, clock, sources=2)
    assert caught.value.reason == reason
    assert not isinstance(caught.value, native.RegistrationExpired)
    # Nothing of that record is left, neither its running client nor a replacement.
    assert first.closed and replacement.closed
    assert list(manager.children.values()) == [second]
    assert manager.deadlines.keys() == manager.children.keys()
    # The publisher then withdraws the policy, as for every failed client.
    manager.reconcile(item, (), 1, clock.time())
    assert all(client.closed for client in Client.made)
    assert not manager.children and not manager.successors and not manager.deadlines


def test_failing_running_client_takes_its_replacement_with_it(config: Config, clock: Clock) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config)
    run(manager, item, clock, 111)
    first, replacement = Client.made
    first.failure = native.DiscoveryFailure("unavailable")
    with pytest.raises(native.DiscoveryFailure, match="unavailable"):
        tick(manager, item, clock)
    assert first.closed and replacement.closed
    assert not manager.children and not manager.successors and not manager.renewing


def test_policy_reads_present_with_every_record_counted_across_renewals(
    config: Config, settings: owner.BonjourSettings, clock: Clock
) -> None:
    store = Store(settings.state_dir)

    def facts(manager: owner.Publisher, until: float) -> set[tuple[str, str, int]]:
        seen = set()
        while clock.elapsed < until:
            now = clock.time()
            current = observed(config, now)
            requests, candidates = lease(config, settings, current, two_records(now), now)
            store.write("requests.json", requests)
            store.write("candidates.json", candidates)
            proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
            manager.expire(clock.monotonic())
            fact = owner.publisher_tick(config, settings, store, manager, proof, 0, now).profiles[
                IMPORT
            ]
            seen.add((fact.state, fact.reason, fact.data["record_count"]))
            clock.elapsed += 5
        return seen

    assert facts(publisher(OVERLAP), 250) == {("present", "verified", 2)}
    assert len(Client.made) == 2 * 3
    # Without the setting the same 250 seconds show the count of records between two clients.
    clock.elapsed = 0.0
    assert facts(publisher(), 250) == {("present", "verified", 2), ("unknown", "unobserved", 0)}


def test_failed_replacement_withdraws_the_policy_through_the_publisher_tick(
    config: Config, settings: owner.BonjourSettings, clock: Clock
) -> None:
    store = Store(settings.state_dir)
    manager = publisher(OVERLAP)

    def fact() -> tuple[str, str, int]:
        now = clock.time()
        current = observed(config, now)
        requests, candidates = lease(config, settings, current, two_records(now), now)
        store.write("requests.json", requests)
        store.write("candidates.json", candidates)
        proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
        found = owner.publisher_tick(config, settings, store, manager, proof, 0, now).profiles[
            IMPORT
        ]
        return found.state, found.reason, found.data["record_count"]

    while clock.elapsed < 111:
        assert fact() == ("present", "verified", 2)
        clock.elapsed += 5
    assert len(Client.made) == 4 and len(manager.successors) == 2
    Client.made[2].failure = native.DiscoveryFailure("timed-out")
    assert fact() == ("unknown", "timed-out", 0)
    assert all(client.closed for client in Client.made)
    assert not manager.children and not manager.successors


# The lease


def test_replacement_gets_the_lease_that_is_left_and_the_deadline_does_not_move(
    config: Config, clock: Clock
) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config, 300)
    # Seen once, at the start, and never again: 300 seconds of lease in all.
    reported = run(manager, item, clock, 300, seen=0)
    deadline = 500.0 + 300
    assert started() == [
        "0 start Example speaker 1 -t 120",
        "110 start Example speaker 2 -t 120",
        # 80 seconds of the lease are left: the replacement gets no more.
        "220 start Example speaker 3 -t 80",
    ]
    # Ten seconds before that last client ends the lease has ten seconds left: a
    # replacement would renew nothing, so none is started.
    assert set(reported) == {(True, 0)} and len(Client.made) == 3
    assert list(manager.children.values()) == [Client.made[2]] and manager.successors == {}
    # The deadline is the one the only sight gave it; no replacement moved it.
    assert manager.deadlines == {next(iter(manager.children)): deadline}
    # No client's own lifetime reaches past the lease it was started under.
    assert all(item.spawned + item.lifetime_seconds <= deadline for item in Client.made)
    manager.expire(clock.monotonic())
    assert not manager.children and not manager.successors and not manager.deadlines
    assert all(item.closed for item in Client.made)


def test_without_fresh_evidence_the_record_ends_with_its_lease(
    config: Config, clock: Clock
) -> None:
    manager = publisher(OVERLAP)
    item = policy(config)
    assert item.max_age_seconds == 120
    # The lease has exactly the running client's time left: nothing to renew.
    assert set(run(manager, item, clock, 120, seen=0)) == {(True, 0)}
    assert len(Client.made) == 1
    manager.expire(clock.monotonic())
    assert not manager.children and Client.made[0].closed


def test_overlap_closes_both_clients_at_the_lease_deadline(config: Config, clock: Clock) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config, 125)
    run(manager, item, clock, 115, seen=0)
    first, replacement = Client.made
    # Fifteen seconds were left when it started: more than the running client's ten.
    assert replacement.lifetime_seconds == 15 and manager.successors
    first.late = 30.0  # its timer has not fired when the lease ends
    clock.elapsed = 125.0
    manager.expire(clock.monotonic())
    assert first.closed and replacement.closed
    assert not manager.children and not manager.successors


def test_publisher_that_dies_leaves_only_clients_that_end_by_themselves(
    config: Config, clock: Clock
) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config, 200)
    run(manager, item, clock, 115, seen=0, sources=2)
    # Killed in the middle of an overlap: nothing is closed, nobody is signalled.
    del manager
    orphans = [client for client in Client.made if client.running]
    assert len(orphans) == 4 and not any(client.closed for client in Client.made)
    # Each was started with a lifetime of its own, inside the lease that was left.
    lease_end = 500.0 + 200
    assert [client.lifetime_seconds for client in Client.made] == [120, 120, 90, 90]
    assert all(client.spawned + client.lifetime_seconds <= lease_end for client in Client.made)
    clock.elapsed = 200.0
    assert all(client.ended and not client.closed for client in Client.made)


# Corners


def test_client_that_lives_no_longer_than_the_overlap_is_replaced_after_its_end(
    config: Config, clock: Clock
) -> None:
    item = long_lease(config, 30)
    assert set(run(publisher(30), item, clock, 100)) == {(True, 0), (False, 1)}
    overlapping = list(Client.events)
    assert overlapping[:3] == [
        "0 start Example speaker 1 -t 30",
        "30 close Example speaker 1 ended",
        "30 start Example speaker 2 -t 30",
    ]
    clock.elapsed = 0.0
    Client.made, Client.events = [], []
    run(publisher(), item, clock, 100)
    assert Client.events == overlapping
    # One second more of lifetime than the overlap, and the replacement runs beside it.
    clock.elapsed = 0.0
    Client.made, Client.events = [], []
    assert set(run(publisher(29), item, clock, 100)) == {(True, 0)}
    assert Client.events[:3] == [
        "0 start Example speaker 1 -t 30",
        "1 start Example speaker 2 -t 30",
        "30 close Example speaker 1 ended",
    ]


def test_replacement_that_ends_first_is_dropped_and_the_running_client_keeps_the_record(
    config: Config, clock: Clock
) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config, 125)
    assert set(run(manager, item, clock, 118, seen=0)) == {(True, 0)}
    first, short = Client.made
    assert short.lifetime_seconds == 15
    first.late = 10.0  # its own timer fires at 130
    # The source is seen again at 118; the short replacement ends at 125.
    assert set(run(manager, item, clock, 130, seen=118)) == {(True, 0)}
    assert Client.events[2:] == [
        "125 close Example speaker 2 ended",
        "125 start Example speaker 3 -t 118",
    ]
    clock.elapsed = 129
    assert not first.closed and running("Example speaker") == [first, Client.made[2]]
    clock.elapsed = 130
    assert set(run(manager, item, clock, 140, seen=118)) == {(True, 0)}
    assert Client.events[4:] == ["130 close Example speaker 1 ended"]
    assert list(manager.children.values()) == [Client.made[2]] and manager.successors == {}


def test_both_clients_ended_while_the_publisher_stalled(config: Config, clock: Clock) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config)
    run(manager, item, clock, 112)
    assert len(Client.made) == 2
    clock.elapsed = 240.0
    # Neither is running any more: one new client, as without the setting.
    assert not tick(manager, item, clock) and manager.renewals(item) == 1
    assert Client.events[2:] == [
        "240 close Example speaker 2 ended",
        "240 close Example speaker 1 ended",
        "240 start Example speaker 3 -t 120",
    ]
    clock.elapsed += 1
    assert tick(manager, item, clock) and manager.renewals(item) == 0
    assert list(manager.children.values()) == [Client.made[2]] and manager.successors == {}


@pytest.mark.parametrize("how", ["withdrawn", "closed"])
def test_record_that_goes_during_an_overlap_takes_both_clients(
    config: Config, clock: Clock, how: str
) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config)
    run(manager, item, clock, 112, sources=2)
    assert len(Client.made) == 4 and len(manager.successors) == 2
    if how == "withdrawn":
        manager.expire(clock.monotonic())
        assert manager.reconcile(item, two_records(clock.time())[1:], 7, clock.time())
        gone = named("Example speaker")
        assert [client.closed for client in named("Second speaker")] == [False, False]
        assert len(manager.children) == len(manager.successors) == 1
    else:
        manager.close()
        gone = Client.made
        assert not manager.children and not manager.successors and not manager.deadlines
    assert all(client.closed for client in gone)


# The setting


@pytest.mark.parametrize("value", [1, 10, 30])
def test_overlap_from_one_to_thirty_seconds_is_accepted(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path, value: int
) -> None:
    path = settings_file(tmp_path, config, settings, renewal_overlap_seconds=value)
    assert owner.load_settings(path) == replace(settings, renewal_overlap_seconds=value)


@pytest.mark.parametrize("value", [0, 31, -1, True, 10.0, "10", None, [10]])
def test_overlap_outside_its_range_or_type_is_refused(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path, value: Any
) -> None:
    assert owner.load_settings(settings_file(tmp_path, config, settings, renewal_overlap_seconds=5))
    with pytest.raises(ValueError, match="renewal overlap must be bounded"):
        owner.load_settings(
            settings_file(tmp_path, config, settings, renewal_overlap_seconds=value)
        )


def test_overlap_is_refused_where_no_owned_client_could_live_longer(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    def load(policy_config: Config, overlap: int) -> owner.BonjourSettings:
        return owner.load_settings(
            settings_file(tmp_path, policy_config, settings, renewal_overlap_seconds=overlap)
        )

    # A client lives for its record's lease, 120 seconds at most.
    assert load(config, 30)
    assert load(leased(config, 21), 20)
    with pytest.raises(ValueError, match="needs a lease that is longer"):
        load(leased(config, 20), 20)
    # One owned lease that is longer is enough; the others renew as without the setting.
    assert load(leased(leased(config, 20), 21, only=IMPORT), 20)


# With the real client object and a fake native client


def test_records_are_renewed_beside_their_predecessors_and_orphans_end_by_themselves(
    config: Config,
    settings: owner.BonjourSettings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifetime, overlap = 4, 2  # seconds; a 120-second lease gives the same cycle, slower
    config = replace(
        config,
        discovery=tuple(
            replace(item, max_age_seconds=lifetime) if item.id == IMPORT else item
            for item in config.discovery
        ),
    )
    write_private(settings.config, to_dict(config))
    fake = tmp_path / "fake-dns-sd"
    fake.write_text(FAKE_CLIENT.replace("{python}", sys.executable))
    fake.chmod(0o700)
    monkeypatch.setattr(native, "DNS_SD", str(fake))

    made: dict[str, list[native.Registration]] = {}
    beside: list[str] = []
    most_alive = 0

    def factory(record: Record, index: int, seconds: int) -> native.Registration:
        earlier = made.setdefault(record.name, [])
        if any(item.process.poll() is None for item in earlier):
            beside.append(record.name)
        earlier.append(native.Registration(record, index, seconds))
        return earlier[-1]

    manager = owner.Publisher(factory, renewal_overlap=overlap)
    store = Store(settings.state_dir)
    begin = time.monotonic()
    steady: list[str] = []
    try:
        while time.monotonic() - begin < 40:
            now = time.time()
            current = observed(config, now)
            requests, candidates = lease(config, settings, current, two_records(now), now)
            store.write("requests.json", requests)
            store.write("candidates.json", candidates)
            proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
            manager.expire(time.monotonic())
            fact = owner.publisher_tick(config, settings, store, manager, proof, 0, now).profiles[
                IMPORT
            ]
            if steady or (fact.state == "present" and fact.data["record_count"] == 2):
                steady.append(fact.state)
            for clients in made.values():
                most_alive = max(most_alive, sum(item.process.poll() is None for item in clients))
            if all(len(made.get(item.name, ())) >= 3 for item in two_records()):
                break
            time.sleep(0.05)
        # The publisher dies here: nothing is closed and no client is signalled.
        clients = [item for items in made.values() for item in items]
        deadline = time.monotonic() + lifetime + 20
        while time.monotonic() < deadline and any(item.process.poll() is None for item in clients):
            time.sleep(0.05)
        statuses = [item.process.poll() for item in clients]
    finally:
        manager.close()

    # Every record was renewed twice, by a client started beside its predecessor ...
    assert all(len(made.get(item.name, ())) >= 3 for item in two_records())
    assert sorted(set(beside)) == sorted(item.name for item in two_records())
    # ... never by more than two clients for one record ...
    assert most_alive == 2
    # ... and the policy never read unknown while its sources were seen.
    assert steady and set(steady) == {"present"}
    # Every client ended on its own timer, the orphans of the dead publisher
    # included: status 0, never a signal, and a lifetime within the lease.
    assert set(statuses) == {0}
    assert {item.lifetime_seconds for item in clients} <= set(range(1, lifetime + 1))

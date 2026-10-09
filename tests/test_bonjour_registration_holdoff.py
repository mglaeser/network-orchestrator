"""A record whose registration client failed is held back before it is registered again.

Readiness finding R-D2. ``Publisher.reconcile`` starts one ``dns-sd -P`` client
for each record. When a client fails (the daemon renamed its service after a
name conflict, a denial, an exit), the publisher closes it and the failure
withdraws the policy in the same turn, as before. The next turn of the loop, a
quarter of a second later, then registered every record of the policy again,
so a record whose name another advertiser still held was started again for as
long as the conflict lasted: Apple's client leaves automatic renaming on
(``Clients/dns-sd.c`` lines 1529-1533 at the revision the Bonjour guide cites),
and each client announced the renamed service until it was stopped. Now no
client is started for that record before its hold-off ends: 1 second after
its first failure, twice the last hold-off after each further failure, at
most 300 seconds. A confirmation ends the record's history, and so does a
fresh activation request of its policy: the coordinator's endpoint waits seven
seconds for an activation to be confirmed.

``Native`` prints what the client prints and the shipped ``Registration.poll``
judges it. The long runs drive ``Publisher.reconcile`` at the loop's cadence
and withdraw the policy after a failure with the one call ``publisher_tick``
makes (``turn``); the tests through ``publisher_tick`` show that the tick does
that and what it reports, and ``Coordinated`` adds the owner's endpoint. The
clock is injected and nothing sleeps. Names are invented, addresses are RFC
5737, and nothing here talks to a daemon.
"""

from __future__ import annotations

from dataclasses import replace
from itertools import pairwise
from pathlib import Path
from typing import Any, ClassVar

import pytest
from hypothesis import given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.config import config_digest, load_config, to_dict
from netorch.discovery import Record
from netorch.discovery_plan import discovery_digest
from netorch.model import Config, Discovery
from netorch.state import Intent, Observation, intent_to_dict
from netorch.storage import Store
from tests.test_bonjour_miss_tolerance import observed
from tests.test_bonjour_owner import config, media_record, policy, settings, write_private
from tests.test_bonjour_record_expiry import READY, Idle, Running, lease, two_records
from tests.test_bonjour_renewal_overlap import (
    OVERLAP,
    WALL,
    Client,
    Clock,
    long_lease,
    run,
    tick,
)
from tests.test_bonjour_renewal_overlap import publisher as client_publisher

__all__ = ["config", "settings"]

IMPORT = "media-import"
TURN = 0.25  # publisher_loop sleeps this long between two turns
EXAMPLE, SECOND = (item.name for item in two_records())
# What the observation of a policy has carried before; a hold-off adds nothing.
OBSERVED = {
    "policy_digest",
    "interface_confirmed",
    "service_generation",
    "network_generation",
    "states",
    "record_count",
    "skipped_count",
}


def service_reply(service: str, text: str) -> bytes:
    """A reply of the daemon for the service (``Clients/dns-sd.c`` lines 918-923 and 940)."""
    return f"22:03:18.100  Got a reply for service {service}: {text}\n".encode()


class Native(native.Registration):
    """Registration.poll as shipped; the test decides what the client prints.

    Every client prints the interface, the echo of its record, the date and
    start lines and its address record's confirmation at once. Its service
    follows the next course listed for its name, or else the lasting course of
    its name, ``confirm`` where there is neither:

    - ``confirm``: the service is registered under its name at once;
    - ``slow``: registered under its name one second after the start;
    - ``rename``: one second after the start the service is registered under
      the name the daemon gave it after a name conflict;
    - ``conflict``: registered under its name at once, renamed ten seconds later;
    - ``deny``: the reply ends in error -65570 at once.
    """

    clock: ClassVar[Clock]
    courses: ClassVar[dict[str, list[str]]] = {}
    lasting: ClassVar[dict[str, str]] = {}
    made: ClassVar[list[Native]] = []

    def __init__(self, record: Record, index: int, lifetime_seconds: int = 120) -> None:
        self.record = record
        self.index = index
        self.lifetime_seconds = lifetime_seconds
        self.closed = False
        self.active = False
        # Registration.poll's five-second limit reads the real clock: no test reaches it.
        self.started = self.spawned = native.time.monotonic()
        self.process = Running()  # type: ignore[assignment]
        self.selector = Idle()  # type: ignore[assignment]
        listed = Native.courses.setdefault(record.name, [])
        self.course = listed.pop(0) if listed else Native.lasting.get(record.name, "confirm")
        self.at = Native.clock.elapsed
        self.late = False
        self.output = bytearray(
            f"Using interface {index}\n".encode()
            + native._echo_line(record)
            + b"\nDATE: ---Mon 05 Oct 2026---\n22:03:17.123  ...STARTING...\n"
            + f"22:03:17.900  Got a reply for record {record.hostname}: ".encode()
            + b"Name now registered and active\n"
        )
        own = f"{record.name}.{record.service_type}.local."
        if self.course in {"confirm", "conflict"}:
            self.output += service_reply(own, "Name now registered and active")
        elif self.course == "deny":
            self.output += service_reply(own, "Error -65570")
        Native.made.append(self)

    def poll(self) -> bool:
        after = {"slow": 1.0, "rename": 1.0, "conflict": 10.0}.get(self.course)
        if after is not None and not self.late and Native.clock.elapsed - self.at >= after:
            self.late = True
            name = self.record.name if self.course == "slow" else f"{self.record.name} (2)"
            service = f"{name}.{self.record.service_type}.local."
            self.output += service_reply(service, "Name now registered and active")
        return super().poll()

    def close(self) -> None:
        self.closed = True


def starts(name: str) -> list[float]:
    """When a client was started for the record of that name."""
    return [client.at for client in Native.made if client.record.name == name]


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    current = Clock()
    Native.clock = Client.clock = current
    Native.courses, Native.lasting, Native.made = {}, {}, []
    Client.made, Client.events, Client.confirm_after = [], [], 0.0
    monkeypatch.setattr(owner, "time", current)
    return current


def turn(
    manager: owner.Publisher, item: Discovery, clock: Clock, records: tuple[Record, ...]
) -> str | None:
    """One turn of the publisher's loop for one policy, as publisher_tick takes it.

    A failure withdraws the policy with the call publisher_tick makes for it;
    the failure's reason is returned.
    """
    manager.expire(clock.monotonic())
    try:
        manager.reconcile(item, records, 9, clock.time())
    except native.DiscoveryFailure as failure:
        manager.reconcile(item, (), 1, clock.time())
        return failure.reason
    return None


class Turns:
    """publisher_tick over the import policy, its sources seen by a scanner pass every 5 seconds.

    The request is written once, at the first turn, as the coordinator's
    endpoint writes it, and again only when a test asks for one.
    """

    def __init__(
        self,
        config: Config,
        settings: owner.BonjourSettings,
        clock: Clock,
        manager: owner.Publisher,
        sources: int = 2,
    ) -> None:
        self.config = config
        self.settings = settings
        self.clock = clock
        self.manager = manager
        self.sources = sources
        self.store = Store(settings.state_dir)
        self.requested: dict[str, Any] | None = None
        self.passed: float | None = None
        self.proof: Any = None

    def request(self, active: bool = True) -> None:
        """A request of the coordinator, with the time it is written as its ``requested_at``."""
        now = self.clock.time()
        self.requested, _ = lease(self.config, self.settings, observed(self.config, now), (), now)
        self.requested["policies"][IMPORT]["active"] = active
        self.store.write("requests.json", self.requested)

    def turn(self) -> Observation:
        now = self.clock.time()
        if self.requested is None:
            self.request()
        if self.passed is None or self.clock.elapsed - self.passed >= 5:
            self.passed = self.clock.elapsed
            current = observed(self.config, now)
            _, candidates = lease(
                self.config, self.settings, current, two_records(now)[: self.sources], now
            )
            self.store.write("candidates.json", candidates)
            self.proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
        self.manager.expire(self.clock.monotonic())
        age = self.clock.elapsed - self.passed
        result = owner.publisher_tick(
            self.config, self.settings, self.store, self.manager, self.proof, age, now
        )
        return result.profiles[IMPORT]

    def until(self, end: float) -> dict[float, tuple[str, str, int]]:
        """Turn every quarter of a second until the clock reads ``end``; what each turn reported."""
        reported = {}
        while self.clock.elapsed < end:
            fact = self.turn()
            reported[self.clock.elapsed] = (fact.state, fact.reason, fact.data["record_count"])
            self.clock.elapsed += TURN
        return reported


class Coordinated:
    """The owner's endpoint, the publisher's loop and a scanner pass every 5 s on one clock.

    It stands in for the module ``time`` of the owner: each wait of the
    endpoint advances the injected clock, and every quarter of a second of it
    is a turn of the publisher's loop. Until ``conflict_until`` another
    advertiser holds the first record's name, so each of its clients is renamed
    one second after its start; every other client follows ``after``.
    """

    def __init__(
        self, config: Config, settings: owner.BonjourSettings, clock: Clock, after: str
    ) -> None:
        self.config = config
        self.settings = settings
        self.clock = clock
        self.after = after
        self.conflict_until = 0.0
        self.store = Store(settings.state_dir)
        self.manager = owner.Publisher(Native)  # type: ignore[arg-type]
        self.next_turn = clock.elapsed
        self.passed: float | None = None
        self.proof: Any = None

    def monotonic(self) -> float:
        return self.clock.monotonic()

    def time(self) -> float:
        return self.clock.time()

    def sleep(self, seconds: float) -> None:
        end = self.clock.elapsed + seconds
        while self.next_turn <= end + 1e-9:
            self.clock.elapsed = self.next_turn
            self.turn()
            self.next_turn += TURN
        self.clock.elapsed = max(end, self.clock.elapsed)

    def turn(self) -> None:
        conflict = self.clock.elapsed < self.conflict_until
        Native.lasting = {EXAMPLE: "rename" if conflict else self.after, SECOND: self.after}
        now = self.clock.time()
        if self.passed is None or self.clock.elapsed - self.passed >= 5:
            self.passed = self.clock.elapsed
            current = observed(self.config, now)
            _, candidates = lease(self.config, self.settings, current, two_records(now), now)
            self.store.write("candidates.json", candidates)
            self.proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
        self.manager.expire(self.clock.monotonic())
        age = self.clock.elapsed - self.passed
        owner.publisher_tick(
            self.config, self.settings, self.store, self.manager, self.proof, age, now
        )

    def reconcile(self, active: bool) -> tuple[str, str]:
        """The coordinator's fixed request through the endpoint, which waits up to 7 s."""
        if self.proof is None:
            self.sleep(0)
        item = policy(self.config)
        request = {
            "protocol_version": 1,
            "operation": "reconcile-discovery",
            "owner": self.settings.owner,
            "policy_digest": config_digest(self.config),
            "discovery_digest": discovery_digest(self.config, item),
            "discovery": item.id,
            "active": active,
            "config": to_dict(self.config),
            "service_generation": self.proof[0].services[item.service].generation,
            "network_generation": self.proof[0].network_generation,
        }
        result = owner.endpoint(self.config, self.settings, self.store, request)["result"]
        return result["state"], result["reason"]


# The record that the daemon keeps renaming


def test_renamed_record_is_started_five_times_in_twenty_seconds(
    config: Config, settings: owner.BonjourSettings, clock: Clock
) -> None:
    # Another advertiser holds the name for the whole run.
    Native.lasting = {EXAMPLE: "rename"}
    turns = Turns(config, settings, clock, owner.Publisher(Native), sources=1)  # type: ignore[arg-type]
    # Twenty seconds, and the turn at their end that reads the fifth client's rename.
    reported = turns.until(20.25)
    started = [at for at in starts(EXAMPLE) if at < 20]
    # Before the hold-off: a client every 1.25 seconds, 16 in these 20 seconds.
    assert len(started) <= 5, f"{len(started)} clients for one record in 20 s: {started}"
    # Each client fails one second after its start; then 1, 2, 4 and 8 seconds.
    assert started == [0, 2, 5, 10, 19]
    # Each client announced the renamed service only until the turn that read the
    # rename, and none was started at that last turn.
    assert len(Native.made) == 5 and all(client.closed for client in Native.made)
    # The failure's turn and every turn of a hold-off report the failure ...
    assert {reported[at] for at in (1.0, 1.75, 3.0, 4.75, 6.0, 9.75, 11.0, 18.75)} == {
        ("unknown", "identity-mismatch", 0)
    }
    # ... and a turn whose new client has not confirmed yet reports that.
    assert {reported[at] for at in (0.0, 0.75, 2.0, 5.0, 10.0, 19.0)} == {
        ("unknown", "unobserved", 0)
    }


def test_renamed_record_is_started_ten_times_in_ten_minutes(config: Config, clock: Clock) -> None:
    Native.lasting = {EXAMPLE: "rename"}
    manager = owner.Publisher(Native)  # type: ignore[arg-type]
    item = policy(config)
    reasons = set()
    while clock.elapsed < 600:
        # The scanner sees the record again and again: a newer sighting is the same record.
        reasons.add(turn(manager, item, clock, two_records(clock.time())[:1]))
        clock.elapsed += TURN
    started = starts(EXAMPLE)
    assert len(started) <= 10, f"{len(started)} clients for one record in 600 s, from {started[:5]}"
    assert started == [0, 2, 5, 10, 19, 36, 69, 134, 263, 520]
    assert reasons == {None, "identity-mismatch"}


def test_hold_off_doubles_up_to_three_hundred_seconds(config: Config, clock: Clock) -> None:
    Native.lasting = {EXAMPLE: "rename"}
    manager = owner.Publisher(Native)  # type: ignore[arg-type]
    item = policy(config)
    # Every start, failure and end of a hold-off falls on a whole second: a turn
    # each second meets the same ones as a turn each quarter.
    while clock.elapsed < 1200:
        turn(manager, item, clock, two_records(clock.time())[:1])
        clock.elapsed += 1
    started = starts(EXAMPLE)
    # From each failure, one second after its start, to the next start.
    held = [later - earlier - 1 for earlier, later in pairwise(started)]
    assert held == [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300]


# Its siblings, and what the policy reports


def test_sibling_is_registered_while_the_failed_record_is_held_back(
    config: Config, settings: owner.BonjourSettings, clock: Clock
) -> None:
    Native.courses = {EXAMPLE: ["rename", "rename", "confirm"]}
    turns = Turns(config, settings, clock, owner.Publisher(Native))  # type: ignore[arg-type]
    reported = turns.until(6)
    # The turn after each failure registers the sibling again, and not the failed record ...
    assert starts(SECOND) == [0, 1.25, 3.25]
    # ... which is tried again 1 second after the first failure and 2 after the second.
    assert starts(EXAMPLE) == [0, 2, 5]
    # The failure withdraws the policy in its own turn, its sibling's client too.
    assert reported[1.0] == reported[3.0] == ("unknown", "identity-mismatch", 0)
    assert [client.closed for client in Native.made if client.record.name == SECOND] == [
        True,
        True,
        False,
    ]
    # While the record is held back the policy is not present, although its sibling is.
    assert {reported[at] for at in (1.25, 1.75, 3.25, 4.75)} == {
        ("unknown", "identity-mismatch", 0)
    }
    assert reported[5.0] == ("present", "verified", 2)


def test_policy_reports_the_failure_until_the_held_record_confirms(
    config: Config, settings: owner.BonjourSettings, clock: Clock
) -> None:
    Native.courses = {SECOND: ["deny", "confirm"]}
    turns = Turns(config, settings, clock, owner.Publisher(Native))  # type: ignore[arg-type]
    facts = {}
    while clock.elapsed < 1.5:
        facts[clock.elapsed] = turns.turn()
        clock.elapsed += TURN
    reported = {
        at: (item.state, item.reason, item.data["record_count"]) for at, item in facts.items()
    }
    # The denial withdraws the policy at once, the client registered beside it included.
    assert reported[0.0] == ("unknown", "local-network-denied", 0)
    assert all(client.closed for client in Native.made[:2])
    # The record is held back for a second; its sibling is registered again at once.
    assert starts(SECOND) == [0, 1] and starts(EXAMPLE) == [0, 0.25]
    assert {reported[at] for at in (0.25, 0.5, 0.75)} == {("unknown", "local-network-denied", 0)}
    assert reported[1.0] == ("present", "verified", 2)
    # The reason is one the observation always had, and nothing is added to it.
    assert all(set(item.data) == OBSERVED for item in facts.values())


def test_policy_reports_the_latest_failure_among_the_records_it_holds_back(
    config: Config, settings: owner.BonjourSettings, clock: Clock
) -> None:
    Native.courses = {EXAMPLE: ["rename", "rename"], SECOND: ["deny", "rename", "deny"]}
    turns = Turns(config, settings, clock, owner.Publisher(Native))  # type: ignore[arg-type]
    reported = turns.until(4)
    # The second record is denied at 0, the first renamed at 1.25 and held back
    # until 2.25, the second denied again at 1.5 and held back until 3.5.
    assert starts(EXAMPLE) == [0, 0.25, 2.25] and starts(SECOND) == [0, 1, 1.5, 3.5]
    assert reported[1.25] == ("unknown", "identity-mismatch", 0)
    # With both held back the policy reports the later failure: the second
    # record's denial, though that record failed first of the two.
    assert reported[1.75] == reported[2.0] == ("unknown", "local-network-denied", 0)
    assert reported[3.5] == ("present", "verified", 2)


# The history


def test_confirmation_ends_the_history(config: Config, clock: Clock) -> None:
    Native.courses = {EXAMPLE: ["rename", "conflict", "rename", "rename"]}
    manager = owner.Publisher(Native)  # type: ignore[arg-type]
    item = policy(config)
    while clock.elapsed < 20:
        turn(manager, item, clock, two_records(clock.time())[:1])
        clock.elapsed += TURN
    # The second client confirmed at 2 and was renamed at 12: that failure is a
    # first one again and holds the record back 1 second, not 2. The next two
    # follow without a confirmation: 2, then 4.
    assert starts(EXAMPLE) == [0, 2, 13, 16]


@pytest.mark.parametrize(
    "change",
    [
        {"name": "Example lounge"},
        {"port": 7001},
        {"txt": (b"model=AudioAccessory5,1", b"binary=\0\xff", b"flags=0x4")},
        {"ipv4": "192.0.2.84"},
        {"hostname": "lounge.local."},
    ],
    ids=["name", "port", "txt", "address", "host"],
)
def test_changed_record_has_no_history(
    config: Config, clock: Clock, change: dict[str, Any]
) -> None:
    Native.courses = {EXAMPLE: ["rename"]}
    manager = owner.Publisher(Native)  # type: ignore[arg-type]
    item = policy(config)
    while clock.elapsed < 1.25:
        turn(manager, item, clock, two_records(clock.time())[:1])
        clock.elapsed += TURN
    assert starts(EXAMPLE) == [0]
    # Another record, not the one that failed: registered at the next turn.
    assert turn(manager, item, clock, (replace(two_records(clock.time())[0], **change),)) is None
    assert len(Native.made) == 2 and Native.made[1].at == 1.25 and Native.made[1].active


def test_client_that_ends_on_its_own_timer_starts_no_hold_off(config: Config, clock: Clock) -> None:
    manager = client_publisher()
    item = long_lease(config)
    run(manager, item, clock, 121)
    # It ended on its timer and was replaced in that turn, as before.
    assert [event for event in Client.events if " start " in event] == [
        "0 start Example speaker 1 -t 120",
        "120 start Example speaker 2 -t 120",
    ]
    # The replacement then fails: a first failure, held back 1 second, not 2.
    Client.made[1].failure = native.DiscoveryFailure("identity-mismatch")
    with pytest.raises(native.DiscoveryFailure, match="identity-mismatch"):
        tick(manager, item, clock)
    manager.reconcile(item, (), 1, clock.time())
    clock.elapsed += TURN
    run(manager, item, clock, 122.25, step=TURN)
    assert [event for event in Client.events if " start " in event][2:] == [
        "122 start Example speaker 3 -t 120"
    ]


def test_failed_replacement_beside_its_predecessor_holds_the_record_back(
    config: Config, clock: Clock
) -> None:
    manager = client_publisher(OVERLAP)
    item = long_lease(config)
    run(manager, item, clock, 111, sources=2)
    first, _second, replacement, _other = Client.made
    assert replacement.record.name == first.record.name == EXAMPLE
    replacement.failure = native.DiscoveryFailure("identity-mismatch")
    with pytest.raises(native.DiscoveryFailure, match="identity-mismatch"):
        tick(manager, item, clock, sources=2)
    manager.reconcile(item, (), 1, clock.time())
    clock.elapsed += TURN
    run(manager, item, clock, 112.25, step=TURN, sources=2)
    # The sibling is registered again at the next turn; the record a second after the failure.
    assert [event for event in Client.events if " start " in event][4:] == [
        "111.25 start Second speaker 3 -t 120",
        "112 start Example speaker 3 -t 120",
    ]


@pytest.mark.parametrize("start", ["first", "replacement"])
def test_client_that_cannot_be_started_holds_the_record_back(
    config: Config, clock: Clock, start: str
) -> None:
    attempts: list[float] = []
    # The first start, or the replacement after the first client's own timer, is refused twice.
    refusals = [2]

    def factory(record: Record, index: int, lifetime_seconds: int) -> Client:
        attempts.append(clock.elapsed)
        if refusals[0] and (start == "first" or attempts[1:]):
            refusals[0] -= 1
            raise native.DiscoveryFailure("incomplete")
        return Client(record, index, lifetime_seconds)

    manager = owner.Publisher(factory)  # type: ignore[arg-type]
    item = long_lease(config)
    begin = 0 if start == "first" else 120
    while clock.elapsed < begin + 5:
        assert turn(manager, item, clock, two_records(clock.time())[:1]) in {None, "incomplete"}
        clock.elapsed += TURN
    # Refused, 1 second, refused again, 2 seconds, then started.
    assert attempts[-3:] == [begin, begin + 1, begin + 3]
    assert manager.reconcile(item, two_records(clock.time())[:1], 9, clock.time())


def test_history_survives_a_pause(
    config: Config, settings: owner.BonjourSettings, clock: Clock
) -> None:
    Native.courses = {EXAMPLE: ["rename", "rename", "confirm"]}
    turns = Turns(config, settings, clock, owner.Publisher(Native), sources=1)  # type: ignore[arg-type]
    # Failures at 1 and 3; the record is held back until 5.
    assert turns.until(3.25)[3.0] == ("unknown", "identity-mismatch", 0)
    write_private(settings.intent, intent_to_dict(Intent(operator_paused=True)))
    assert set(turns.until(4).values()) == {("absent", "confirmed-absent", 0)}
    # Resumed inside the hold-off under the same request: the record still waits for its end.
    write_private(settings.intent, intent_to_dict(Intent()))
    assert set(turns.until(5).values()) == {("unknown", "identity-mismatch", 0)}
    assert turns.until(5.25) == {5.0: ("present", "verified", 1)}
    assert starts(EXAMPLE) == [0, 2, 5]


@pytest.mark.parametrize("attempt", ["inactive-then-active", "active-again"])
def test_fresh_activation_request_ends_the_history(
    config: Config, settings: owner.BonjourSettings, clock: Clock, attempt: str
) -> None:
    Native.courses = {EXAMPLE: ["rename", "rename", "confirm"]}
    turns = Turns(config, settings, clock, owner.Publisher(Native), sources=1)  # type: ignore[arg-type]
    # Failures at 1 and 3; the record is held back until 5 under the first request.
    reported = turns.until(3.5)
    assert reported[3.25] == ("unknown", "identity-mismatch", 0)
    if attempt == "inactive-then-active":
        # The coordinator withdraws the policy and requests it again.
        turns.request(active=False)
        assert set(turns.until(4).values()) == {("absent", "confirmed-absent", 0)}
    # A new active request is a new attempt: the record is registered at once.
    turns.request()
    again = clock.elapsed
    assert turns.until(again + TURN) == {again: ("present", "verified", 1)}
    assert starts(EXAMPLE) == [0, 2, again]


def test_fresh_activation_request_ends_the_history_of_its_own_policy_only(
    config: Config, settings: owner.BonjourSettings, clock: Clock
) -> None:
    camera = policy(config, "camera-export")
    store = Store(settings.state_dir)
    manager = owner.Publisher(Native)  # type: ignore[arg-type]
    Native.courses = {name: ["rename", "rename", "confirm"] for name in (EXAMPLE, "Camera")}
    requested = {IMPORT: 0.0, camera.id: 0.0}

    def turn_both() -> dict[str, tuple[str, str]]:
        """A turn over both owned policies, each with its own request; what each reports."""
        now = clock.time()
        current = observed(config, now)
        requests, candidates = lease(config, settings, current, two_records(now)[:1], now)
        source = media_record(
            name="Camera",
            service_type="_hap._tcp",
            hostname="camera.local.",
            ipv4="198.51.100.13",
            interface="bridge-test",
            port=9443,
            seen_at=now,
        )
        records = owner.project_records(
            config, camera, (source,), current, frozenset({"camera-web"}), settings, now
        )
        common = {
            "policy_digest": discovery_digest(config, camera),
            "service_generation": current.services[camera.service].generation,
            "network_generation": current.network_generation,
        }
        requests["policies"][camera.id] = {**common, "active": True}
        candidates["policies"][camera.id] = {
            **common,
            "records": [owner.record_to_dict(item) for item in records],
            "interface_confirmed": True,
            "observed_at": now,
        }
        for identifier, written in requested.items():
            requests["policies"][identifier]["requested_at"] = WALL + written
        store.write("requests.json", requests)
        store.write("candidates.json", candidates)
        proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
        manager.expire(clock.monotonic())
        found = owner.publisher_tick(config, settings, store, manager, proof, 0, now).profiles
        return {key: (value.state, value.reason) for key, value in found.items()}

    reported = {}
    while clock.elapsed < 6:
        if clock.elapsed == 3.25:
            # The coordinator's new attempt for the media import alone.
            requested[IMPORT] = clock.elapsed
        reported[clock.elapsed] = turn_both()
        clock.elapsed += TURN
    # Both records failed at 1 and 3. The fresh request registers the import's
    # record at once; the export's waits for the end of its hold-off at 5.
    assert starts(EXAMPLE) == [0, 2, 3.25] and starts("Camera") == [0, 2, 5]
    assert reported[3.25] == {
        IMPORT: ("present", "verified"),
        camera.id: ("unknown", "identity-mismatch"),
    }
    assert reported[5.0][camera.id] == ("present", "verified")


@pytest.mark.parametrize(("length", "after"), [(3.0, "slow"), (5.0, "confirm"), (5.0, "slow")])
def test_activation_that_meets_a_conflict_of_up_to_five_seconds_is_confirmed_in_time(
    config: Config,
    settings: owner.BonjourSettings,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
    length: float,
    after: str,
) -> None:
    harness = Coordinated(config, settings, clock, after)
    monkeypatch.setattr(owner, "time", harness)
    # A first activation meets a conflict of nine seconds: failures at 1.25,
    # 3.25 and 6.25 leave the record held back until 10.25, and the endpoint
    # answers with what it has after its seven seconds.
    harness.conflict_until = 9.0
    assert harness.reconcile(True)[0] == "unknown"
    # The coordinator withdraws the policy, as the planner does for an unknown.
    harness.sleep(10 - clock.elapsed)
    assert harness.reconcile(False) == ("absent", "confirmed-absent")
    # Its next activation meets a conflict of ``length`` seconds. It starts
    # without the earlier hold-offs: after failures 1.25 and 3.25 seconds into
    # it the record waits 1 and 2 seconds, not 8, and its client started 5.25
    # seconds after the request is confirmed inside the endpoint's wait.
    harness.sleep(20 - clock.elapsed)
    harness.conflict_until = clock.elapsed + length
    assert harness.reconcile(True) == ("present", "verified")


@pytest.mark.parametrize(("back", "hold_off"), [(301.75, 2), (302.0, 1)])
def test_history_of_a_record_that_stays_away_is_forgotten(
    config: Config, clock: Clock, back: float, hold_off: int
) -> None:
    Native.courses = {EXAMPLE: ["rename"] * 3}
    manager = owner.Publisher(Native)  # type: ignore[arg-type]
    item = policy(config)
    while clock.elapsed < back + hold_off + 2:
        # It failed at 1 and its hold-off ended at 2. The scanner then stops
        # seeing it until ``back``; its history is kept until 300 seconds
        # after that end, 302, and forgotten from then on.
        seen = clock.elapsed < 1.25 or clock.elapsed >= back
        turn(manager, item, clock, two_records(clock.time())[:1] if seen else ())
        clock.elapsed += TURN
    assert starts(EXAMPLE) == [0, back, back + 1 + hold_off]


# Where the history ends


def test_publisher_that_closes_registers_at_once(config: Config, clock: Clock) -> None:
    Native.courses = {EXAMPLE: ["rename"]}
    manager = owner.Publisher(Native)  # type: ignore[arg-type]
    item = policy(config)
    while clock.elapsed < 1.25:
        turn(manager, item, clock, two_records(clock.time())[:1])
        clock.elapsed += TURN
    # The loop ends, or its turn failed as a whole: the history is not kept.
    manager.close()
    turn(manager, item, clock, two_records(clock.time())[:1])
    assert starts(EXAMPLE) == [0, 1.25]


def test_turn_that_fails_as_a_whole_drops_the_history(
    config: Config, settings: owner.BonjourSettings, clock: Clock
) -> None:
    Native.courses = {EXAMPLE: ["rename"]}
    turns = Turns(config, settings, clock, owner.Publisher(Native), sources=1)  # type: ignore[arg-type]
    assert turns.until(1.25)[1.0] == ("unknown", "identity-mismatch", 0)
    # A damaged request file fails the turn as a whole, which closes the publisher.
    turns.store.write("requests.json", {"schema_version": 1})
    assert turns.until(1.5) == {1.25: ("unknown", "malformed", 0)}
    # The same request as before, inside what was the hold-off: registered at once.
    turns.store.write("requests.json", turns.requested)
    turns.until(1.75)
    assert starts(EXAMPLE) == [0, 1.5]


def test_clock_that_reads_earlier_than_the_failure_ends_the_hold_off(
    config: Config, clock: Clock
) -> None:
    Native.courses = {EXAMPLE: ["rename"]}
    manager = owner.Publisher(Native)  # type: ignore[arg-type]
    item = policy(config)
    while clock.elapsed < 1.25:
        turn(manager, item, clock, two_records(clock.time())[:1])
        clock.elapsed += TURN
    # Registering again is what the publisher did before hold-offs: the safe direction.
    clock.elapsed = 0.5
    turn(manager, item, clock, two_records(clock.time())[:1])
    assert starts(EXAMPLE) == [0, 0.5]


# Any course of any record at any turn


class Drawn:
    """Stands in for Registration: each start takes the next drawn course.

    ``confirm`` confirms after its waiting polls; ``rename`` and ``deny`` fail
    after them. ``expire`` and ``conflict`` are confirmed for that many polls
    (not at all where there are none); then ``expire`` ends on its own timer
    and ``conflict`` is renamed. ``refuse`` is a start that fails before any
    client runs.
    """

    clock: ClassVar[Clock]
    courses: ClassVar[list[tuple[str, int]]] = []
    events: ClassVar[list[tuple[str, str]]] = []

    def __init__(self, record: Record, index: int, lifetime_seconds: int = 120) -> None:
        self.course, self.waiting = Drawn.courses.pop(0) if Drawn.courses else ("confirm", 0)
        Drawn.events.append(("start", record.name))
        if self.course == "refuse":
            Drawn.events.append(("fail", record.name))
            raise native.DiscoveryFailure("incomplete")
        self.record = record
        self.lifetime_seconds = lifetime_seconds
        self.spawned = Drawn.clock.monotonic()
        self.active = False
        self.closed = False

    def poll(self) -> bool:
        assert not self.closed
        if self.waiting:
            self.waiting -= 1
            self.active = self.course in {"expire", "conflict"}
        elif self.course == "expire":
            raise native.RegistrationExpired()
        elif self.course in {"rename", "deny", "conflict"}:
            Drawn.events.append(("fail", self.record.name))
            reason = "local-network-denied" if self.course == "deny" else "identity-mismatch"
            raise native.DiscoveryFailure(reason)
        else:
            self.active = True
        if self.active:
            Drawn.events.append(("confirm", self.record.name))
        return self.active

    def close(self) -> None:
        self.closed = True


# Turns a quarter of a second apart, as the loop's, a few seconds apart, as a
# slow turn's, and minutes apart, as a stalled publisher's; more of them on the
# scale of the first hold-offs.
GAP = st.one_of(
    st.sampled_from([0.0, 0.25, 0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 5.0, 10.0, 300.0]),
    st.integers(min_value=0, max_value=16).map(lambda quarters: quarters / 4),
    st.integers(min_value=0, max_value=80).map(lambda quarters: quarters / 4),
    st.integers(min_value=0, max_value=1600).map(lambda quarters: quarters / 4),
)
COURSE = st.tuples(
    st.sampled_from(["confirm", "rename", "deny", "expire", "conflict", "refuse"]),
    st.integers(min_value=0, max_value=3),
)


@hypothesis_settings(max_examples=500, deadline=None)
@given(gaps=st.lists(GAP, min_size=1, max_size=80), courses=st.lists(COURSE, max_size=60))
def test_no_record_is_started_inside_its_hold_off(
    gaps: list[float], courses: list[tuple[str, int]]
) -> None:
    item = policy(load_config(Path(__file__).resolve().parents[1] / "examples/network.json"))
    current = Clock()
    Drawn.clock, Drawn.courses, Drawn.events = current, list(courses), []
    # The model: by record name, when its last failure was and how long it holds the record.
    history: dict[str, tuple[float, int]] = {}
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(owner, "time", current)
        manager = owner.Publisher(Drawn)  # type: ignore[arg-type]
        for gap in gaps:
            now = current.monotonic()
            manager.expire(now)
            running = {child.record.name for child in manager.children.values()}
            # Forgotten: no client, and the hold-off ended 300 seconds ago or more.
            for name, (failed_at, seconds) in tuple(history.items()):
                if name not in running and not failed_at <= now < failed_at + seconds + 300:
                    del history[name]
            held = {
                name
                for name, (failed_at, seconds) in history.items()
                if failed_at <= now < failed_at + seconds
            }
            begin = len(Drawn.events)
            turn(manager, item, current, two_records(current.time()))
            events = Drawn.events[begin:]
            for kind, name in events:
                # No record is started before its hold-off has ended.
                assert kind != "start" or name not in held, (
                    f"{name} started at {now} inside the hold-off of {history[name][1]} s"
                    f" of its failure at {history[name][0]}"
                )
                if kind == "confirm":
                    # A confirmation ends the history: the next failure holds 1 second.
                    history.pop(name, None)
                elif kind == "fail":
                    seconds = 1 if name not in history else min(300, 2 * history[name][1])
                    history[name] = (now, seconds)
            failed = [name for kind, name in events if kind == "fail"]
            running = {child.record.name for child in manager.children.values()}
            if failed:
                # One failure per turn; nothing is started after it, and its policy is withdrawn.
                (name,) = failed
                after = events[events.index(("fail", name)) + 1 :]
                assert all(kind != "start" for kind, _name in after)
                assert not running
            else:
                # Every record has a client unless it is held back, and none that is.
                for name in (EXAMPLE, SECOND):
                    assert (name in running) is (name not in held), (
                        f"{name} at {now}: client {name in running}, failures {history}"
                    )
            current.elapsed += gap

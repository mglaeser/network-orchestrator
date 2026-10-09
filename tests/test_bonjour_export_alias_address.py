"""An export reads its guest's record by the guest address, also where an alias answers first.

Readiness finding R-D1. The scan reads an instance's address with
`dns-sd -m -G v4 <host>`, and with -m Apple's client leaves after its first reply
that is not marked as followed by more (`Clients/dns-sd.c` 1287-1290 at the
revision the Bonjour guide cites, `mDNSResponder-2881.120.11`; the line numbers
in the comments are that file's). A guest that holds the inspected guest address
and a further address, an alias, can therefore show the alias alone. The record
then carried the alias, the projection dropped it, and nothing counted it.

An export now reads such a host once more without -m, for an instance that the
projection could export (its port is the guest port of a verified publication)
and only inside the scan's time and the scanner's wait for the scan. The fake
clients answer in the formats of Apple's client: an address read with -m shows
what a test gives as its first reply, a read without -m every row of the host,
as the client that runs to its -t timer does (1315-1320). Names, hosts and
addresses are synthetic (RFC 5737), the clocks are fakes, and nothing here is a
capture from a host.
"""

from __future__ import annotations

import inspect
import ipaddress
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.discovery import Record
from netorch.model import Config, PortRange
from netorch.process import OutputLimit, ProcessError, Result
from tests.test_bonjour_failed_pass_as_miss import (
    Link,
    call_failed,
    call_failed_with,
    counting,
    daemon_stopped,
    stopped,
    stopped_after,
    stopped_in_the_loop,
)
from tests.test_bonjour_miss_tolerance import EXPORT, leased, tolerant
from tests.test_bonjour_owner import FakeRegistration, config, policy, publisher, settings, snapshot
from tests.test_bonjour_record_isolation import (
    AIRPLAY,
    GUEST,
    GUEST_INDEX,
    KITCHEN,
    LAN_INDEX,
    READY,
    STAMP,
    Client,
    Device,
    camera,
    flooded,
    networks,
    scan_pass,
    tick,
    with_interface_line_twice,
    with_line,
    with_suffix,
    without_interface_line,
    without_start_line,
)
from tests.test_bonjour_starting_banner import starting

__all__ = ["config", "settings"]

Failure = Callable[[Result], Result]
HOST = "camera.local."
# A LAN address that the application inside the guest also binds: outside the
# example's guest network (198.51.100.0/24), and not the address the verified
# publication gives the record (the scope's host address, 192.0.2.10).
ALIAS = "192.0.2.64"
# Another guest of the same guest network; the runtime gives each guest one
# address of it (apple_runtime reads exactly one attachment in that subnet).
NEIGHBOUR = "198.51.100.77"
INTERFACES = {"wired-lan": (LAN_INDEX, GUEST_INDEX)}


def rows(host: str, *events: tuple[str, str], index: int = GUEST_INDEX) -> str:
    """The date and start lines, then what addrinfo_reply prints for these replies.

    Its heading comes with the first reply (1253), then one row for each reply
    (1276): `Add` for an added address, `Rmv` for a removed one.
    """
    if not events:
        return starting()
    out = starting() + (
        f"Timestamp     {'A/R':>3}  {'Flags':<11}  {'IF':>3}  "
        f"{'Hostname':<38} {'Address':<44} TTL\n"
    )
    for op, address in events:
        # kDNSServiceFlagsAdd (0x2) is set for an address that was added only.
        flags = 0x40000002 if op == "Add" else 0x40000000
        out += STAMP + f"{op:<3}  {flags:<9X} {' '}  {index:3d}  "
        out += f"{host:<38} {address:<44} 120\n"
    return out


Events = tuple[tuple[str, str], ...]


class Guests(Client):
    """A guest network whose address answer depends on whether the client leaves early.

    With -m the client leaves after its first reply that is not marked as
    followed by more (1287-1290): ``first`` gives what it has shown by then for
    a host. Without -m it runs to its -t timer (1315-1320) and shows every
    reply: ``every`` for a host. Unless given, both are every address of the
    device. ``second`` is applied to the answer of an address read without -m
    alone; ``clock`` and ``costs`` let the commands take time.
    """

    def __init__(
        self,
        *devices: Device,
        first: dict[str, Events] | None = None,
        every: dict[str, Events] | None = None,
        second: Failure | None = None,
        index: int = GUEST_INDEX,
    ) -> None:
        super().__init__(*devices, index=index)
        self.first = first or {}
        self.every = every or {}
        self.second = second
        self.commands: list[tuple[list[str], float]] = []
        self.started: list[float] = []
        self.every_reply = False
        self.clock: Clock | None = None
        self.costs: Callable[[list[str]], float] = lambda _argv: 0.0
        self.hooks: list[Callable[[list[str]], None]] = []

    def __call__(self, argv: list[str], timeout: float) -> Result:
        self.commands.append((list(argv), timeout))
        self.every_reply = "-G" in argv and "-m" not in argv
        if self.clock is not None:
            self.started.append(self.clock.now)
            self.clock.now += self.costs(argv)
        answer = super().__call__(argv, timeout)
        for hook in self.hooks:
            hook(argv)
        if self.every_reply and self.second is not None:
            return self.second(answer)
        return answer

    def address(self, _protocol: str, host: str) -> str:
        device = next(item for item in self.devices if item.host == host)
        given = (self.every if self.every_reply else self.first).get(host)
        events = given if given is not None else tuple(("Add", item) for item in device.addresses)
        return rows(host, *events, index=self.index)

    def reads(self, host: str = HOST) -> list[list[str]]:
        """The address commands made for one host, in order."""
        return [argv for argv, _limit in self.commands if "-G" in argv and argv[-1] == host]

    def asked_for(self, operation: str, subject: str) -> bool:
        return (operation, subject) in self.asked


class Clock:
    """The reader's own clock, against which a scan counts its 45 seconds."""

    def __init__(self) -> None:
        self.now = 100.0

    def monotonic(self) -> float:
        return self.now


def other(number: int, address: str = NEIGHBOUR) -> Device:
    """Another guest's instance of the exported type, on the same guest network."""
    return replace(camera(address), name=f"Bridge {number}", host=f"bridge-{number}.local.")


def foreign(number: int, port: int = 9443) -> Device:
    """A registration on the guest network whose host shows one LAN address alone.

    No projection of this owner: neither its name nor its host has a reserved
    prefix. Port 9443 is the guest port of the example's verified publication.
    """
    return replace(
        camera(f"192.0.2.{100 + number}"),
        name=f"Accessory {number}",
        host=f"accessory-{number}.local.",
        port=port,
    )


def exported(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    guests: Client,
    lan: Client | None = None,
) -> tuple[tuple[Record, ...], int]:
    """One scan of the export policy through the owner: its projection and the count left out."""
    networks(config, monkeypatch, lan or Client(), guests)
    return owner.scan_policy(
        config, settings, policy(config, EXPORT), snapshot(config), READY, INTERFACES, 1000
    )


def published(records: tuple[Record, ...]) -> list[tuple[str, str, int]]:
    return [(item.name, item.ipv4, item.port) for item in records]


def without_m(argv: list[str]) -> bool:
    return "-m" not in argv


# The defect: an alias that answers first.


def test_r_d1_alias_answered_first_is_read_again_and_exported_by_the_guest_address(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    guests = Guests(camera(GUEST, ALIAS), first={HOST: (("Add", ALIAS),)})
    records, skipped = exported(config, settings, monkeypatch, guests)
    # The verified publication gives the address and port, never the answer.
    assert published(records) == [("Camera", config.scope("wired-lan").host_ipv4, 9443)]
    assert skipped == 0
    # One read with -m, then one of every reply for the command's own time limit.
    assert guests.reads() == [
        [native.DNS_SD, "-t", "2", "-i", "bridge-test", "-m", "-G", "v4", HOST],
        [native.DNS_SD, "-t", "2", "-i", "bridge-test", "-G", "v4", HOST],
    ]
    limits = [limit for argv, limit in guests.commands if "-G" in argv]
    assert limits == [3.0, 3.0]


def test_r_d1_alias_answered_first_is_leased_and_shown_present(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    guests = Guests(camera(GUEST, ALIAS), first={HOST: (("Add", ALIAS),)})
    candidate = scan_pass(config, settings, monkeypatch, Client(), guests)[EXPORT]
    assert "reason" not in candidate and "skipped" not in candidate
    records = candidate["records"]
    assert [(item["name"], item["ipv4"], item["port"]) for item in records] == [
        ("Camera", config.scope("wired-lan").host_ipv4, 9443)
    ]
    assert records[0]["hostname"].startswith(config.discovery_names.export_prefix)
    observed = tick(config, settings)[EXPORT]
    assert (observed.state, observed.reason) == ("present", "verified")
    assert (observed.data["record_count"], observed.data["skipped_count"]) == (1, 0)
    assert [child.record.name for child in FakeRegistration.made] == ["Camera"]


@pytest.mark.parametrize(
    "every",
    [
        (("Add", ALIAS), ("Add", GUEST)),
        (("Add", GUEST), ("Add", ALIAS)),
        (("Add", ALIAS), ("Add", GUEST), ("Rmv", ALIAS)),
        (("Add", "203.0.113.40"), ("Add", ALIAS), ("Add", GUEST)),
    ],
    ids=["alias-then-guest", "guest-then-alias", "alias-removed", "two-aliases"],
)
def test_r_d1_second_read_that_holds_the_guest_address_exports_it(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    every: Events,
) -> None:
    guests = Guests(camera(GUEST, ALIAS), first={HOST: (("Add", ALIAS),)}, every={HOST: every})
    records, skipped = exported(config, settings, monkeypatch, guests)
    assert published(records) == [("Camera", config.scope("wired-lan").host_ipv4, 9443)]
    assert skipped == 0


# Never silent: neither read holds the guest address.


def test_r_d1_alias_in_both_reads_is_left_out_and_counted(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Another guest's instance is read beside it, so the pass completes.
    guests = Guests(other(1), camera(ALIAS))
    records, skipped = exported(config, settings, monkeypatch, guests)
    assert records == () and skipped == 1
    assert [without_m(argv) for argv in guests.reads()] == [False, True]
    # Left out at the address: its TXT is not asked for.
    assert not guests.asked_for("-Q", camera(ALIAS).fullname)


@pytest.mark.parametrize(
    "every",
    [
        (),
        (("Add", ALIAS), ("Add", GUEST), ("Rmv", GUEST)),
        (("Add", GUEST), ("Rmv", GUEST)),
        (("Add", ALIAS), ("Add", "203.0.113.40")),
    ],
    ids=["no-row", "guest-address-removed", "guest-address-gone-and-nothing-left", "two-aliases"],
)
def test_r_d1_second_read_without_the_guest_address_leaves_the_instance_out(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    every: Events,
) -> None:
    guests = Guests(other(1), camera(GUEST, ALIAS), first={HOST: (("Add", ALIAS),)})
    guests.every = {HOST: every}
    records, skipped = exported(config, settings, monkeypatch, guests)
    assert records == () and skipped == 1


def test_r_d1_alias_in_both_reads_alone_withdraws_the_policy(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    kept = publisher()
    scan_pass(config, settings, monkeypatch, Client(), Guests(camera(GUEST)))
    assert tick(config, settings, kept)[EXPORT].data["record_count"] == 1
    # The guest now shows its alias alone: nothing of the policy is read, so
    # the pass fails for it, as for every instance left out with nothing read.
    candidate = scan_pass(config, settings, monkeypatch, Client(), Guests(camera(ALIAS)))[EXPORT]
    assert candidate["records"] == [] and candidate.get("reason") == "incomplete"
    observed = tick(config, settings, kept)[EXPORT]
    assert (observed.state, observed.reason) == ("unknown", "unobserved")
    assert [child.closed for child in FakeRegistration.made] == [True]


def test_r_d1_alias_in_both_reads_alone_is_no_read_that_did_not_complete(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The instance answered, with an address that is not the guest's: the failed
    # pass is never counted as a miss (failed_pass), unlike a pass that read nothing.
    with pytest.raises(native.DiscoveryFailure) as caught:
        exported(config, settings, monkeypatch, Guests(camera(ALIAS)))
    failure = caught.value
    assert type(failure) is native.DiscoveryFailure and failure.reason == "incomplete"
    assert (failure.unfinished, failure.unanswered) == (False, False)
    assert not owner.counts_as_miss(failure)


def test_r_d1_record_of_the_previous_pass_is_not_carried_past_an_alias_in_both_reads(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), tolerant(settings, 3))
    link.requested()
    link.guests = Guests(other(1), camera(GUEST, ALIAS))
    assert [item["name"] for item in link.run()[EXPORT]["records"]] == ["Camera"]
    assert link.tick()[EXPORT].data["record_count"] == 1
    # An alias first: read again and exported, a fresh sighting.
    link.guests = Guests(other(1), camera(GUEST, ALIAS), first={HOST: (("Add", ALIAS),)})
    candidate = link.run()[EXPORT]
    assert [(item["name"], item["seen_at"]) for item in candidate["records"]] == [
        ("Camera", link.clock.now)
    ]
    assert link.counts(EXPORT) == {"Camera _hap._tcp": 0}
    # The alias in both reads: left out, which is an answer that cannot be used.
    # The tolerance of three passes does not keep it; it is withdrawn at once.
    link.guests = Guests(other(1), camera(ALIAS))
    candidate = link.run()[EXPORT]
    assert candidate["records"] == [] and candidate["skipped"] == 1
    assert link.counts(EXPORT) == {}
    observed = link.tick()[EXPORT]
    assert (observed.state, observed.reason) == ("present", "verified")
    assert (observed.data["record_count"], observed.data["skipped_count"]) == (0, 1)
    assert [child.closed for child in FakeRegistration.made] == [True]


@pytest.mark.parametrize(
    ("failure", "carried", "reason"),
    [
        (daemon_stopped, True, "malformed"),
        (stopped, True, "malformed"),
        (call_failed_with(b"-65570"), False, "local-network-denied"),
        (with_line("unexpected line"), False, "malformed"),
    ],
    ids=["daemon-stopped", "stopped-at-the-time-limit", "denied", "line-that-is-no-reply"],
)
def test_r_d1_failed_second_read_counts_as_a_miss_where_a_first_read_would(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    failure: Failure,
    carried: bool,
    reason: str,
) -> None:
    # With failed_pass "miss", a second read that did not complete keeps the
    # record of the previous pass, and every other failure withdraws at once.
    link = Link(monkeypatch, leased(config), counting(settings, 3))
    link.requested()
    link.guests = Guests(other(1), camera(GUEST, ALIAS))
    assert [item["name"] for item in link.run()[EXPORT]["records"]] == ["Camera"]
    link.guests = Guests(
        other(1), camera(GUEST, ALIAS), first={HOST: (("Add", ALIAS),)}, second=failure
    )
    candidate = link.run()[EXPORT]
    if carried:
        assert [item["name"] for item in candidate["records"]] == ["Camera"]
        assert (candidate.get("tolerated_failure"), candidate.get("reason")) == (reason, None)
    else:
        assert candidate["records"] == []
        assert (candidate.get("tolerated_failure"), candidate.get("reason")) == (None, reason)


# What makes no second command: the fast path, an import, no row, another guest.


@pytest.mark.parametrize(
    "first",
    [(("Add", GUEST),), (("Add", GUEST), ("Add", ALIAS)), (("Add", ALIAS), ("Add", GUEST))],
    ids=["guest-address", "guest-address-and-alias", "alias-and-guest-address"],
)
def test_r_d1_first_answer_that_holds_the_guest_address_makes_no_second_command(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    first: Events,
) -> None:
    guests = Guests(camera(GUEST, ALIAS), first={HOST: first})
    records, skipped = exported(config, settings, monkeypatch, guests)
    assert published(records) == [("Camera", config.scope("wired-lan").host_ipv4, 9443)]
    assert skipped == 0
    assert [without_m(argv) for argv in guests.reads()] == [False]


def test_r_d1_import_with_two_addresses_is_left_out_as_before(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    double = replace(KITCHEN, name="Double", host="double.local.", addresses=(ALIAS, "192.0.2.84"))
    lan = Guests(KITCHEN, double, index=LAN_INDEX)
    networks(config, monkeypatch, lan, Client(index=GUEST_INDEX))
    records, skipped = owner.scan_policy(
        config, settings, policy(config), snapshot(config), READY, INTERFACES, 1000
    )
    assert [item.name for item in records] == [KITCHEN.name] and skipped == 1
    assert all(not without_m(argv) for argv, _limit in lan.commands if "-G" in argv)


def test_r_d1_answer_without_a_row_is_left_out_as_before(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    guests = Guests(other(1), camera())
    records, skipped = exported(config, settings, monkeypatch, guests)
    assert records == () and skipped == 1
    assert [without_m(argv) for argv in guests.reads()] == [False]


def test_r_d1_other_guests_on_the_guest_network_make_no_second_command(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Five other guests announce the exported type; each holds its own address of
    # the guest network. They are read and not published, and nothing is counted.
    neighbours = [other(number, f"198.51.100.{20 + number}") for number in range(1, 6)]
    guests = Guests(*neighbours, camera(GUEST, ALIAS))
    records, skipped = exported(config, settings, monkeypatch, guests)
    assert published(records) == [("Camera", config.scope("wired-lan").host_ipv4, 9443)]
    assert skipped == 0
    assert not [argv for argv, _limit in guests.commands if "-G" in argv and without_m(argv)]


def test_r_d1_own_projection_in_the_guest_network_makes_no_second_command(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A LAN device that this owner projects into the guest network, under its
    # import prefix, as an import of the same type would register it there.
    host = config.discovery_names.import_prefix + "0123456789abcdef.local."
    projected = replace(camera("192.0.2.81"), name="Kitchen speaker", host=host)
    guests = Guests(projected, camera(GUEST))
    records, skipped = exported(config, settings, monkeypatch, guests)
    assert [item.name for item in records] == ["Camera"] and skipped == 0
    assert [without_m(argv) for argv in guests.reads(host)] == [False]


def test_r_d1_second_read_that_names_another_guest_reads_the_first_answer_as_before(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Another guest whose alias answered first: its every reply shows its own
    # address of the guest network, so it is read and not published, as before.
    shared = replace(other(1, NEIGHBOUR), addresses=(NEIGHBOUR, ALIAS))
    guests = Guests(shared, camera(GUEST), first={shared.host: (("Add", ALIAS),)})
    records, skipped = exported(config, settings, monkeypatch, guests)
    assert [item.name for item in records] == ["Camera"] and skipped == 0
    assert [without_m(argv) for argv in guests.reads(shared.host)] == [False, True]


# Only an instance that the projection could export is read a second time.


@pytest.mark.parametrize("count", [1, 5])
def test_r_d1_registrations_on_other_ports_are_read_as_before(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch, count: int
) -> None:
    # LAN addresses alone, on ports that no verified publication exports: read
    # and not published, nothing counted, no second command.
    guests = Guests(*[foreign(n, 52000 + n) for n in range(1, count + 1)], camera(GUEST))
    records, skipped = exported(config, settings, monkeypatch, guests)
    assert published(records) == [("Camera", config.scope("wired-lan").host_ipv4, 9443)]
    assert skipped == 0
    assert not [argv for argv, _limit in guests.commands if "-G" in argv and without_m(argv)]


def test_r_d1_registration_on_another_port_keeps_the_miss_tolerance(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), tolerant(settings, 3))
    link.requested()
    link.guests = Guests(foreign(1, 21064), camera(GUEST))
    assert [item["name"] for item in link.run()[EXPORT]["records"]] == ["Camera"]
    # The browse misses the guest's own instance; the registration is read, so
    # the pass completes and carries the record, as before.
    link.guests = Guests(foreign(1, 21064))
    candidate = link.run()[EXPORT]
    assert [item["name"] for item in candidate["records"]] == ["Camera"]
    assert "reason" not in candidate and "skipped" not in candidate
    observed = link.tick()[EXPORT]
    assert (observed.state, observed.reason, observed.data["record_count"]) == (
        "present",
        "verified",
        1,
    )


def test_r_d1_registration_on_a_published_port_is_read_again_and_counted(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On the published port the reader cannot tell it from the guest's own
    # alias: it is read again, holds no address of the guest network, and is
    # left out and counted beside the exported guest.
    guests = Guests(foreign(1), camera(GUEST))
    records, skipped = exported(config, settings, monkeypatch, guests)
    assert published(records) == [("Camera", config.scope("wired-lan").host_ipv4, 9443)]
    assert skipped == 1
    assert [without_m(argv) for argv in guests.reads(foreign(1).host)] == [False, True]
    # With five of them the fifth instance left out fails the scan.
    with pytest.raises(native.DiscoveryFailure) as caught:
        exported(config, settings, monkeypatch, Guests(*map(foreign, range(1, 6)), camera(GUEST)))
    assert type(caught.value) is native.DiscoveryFailure and caught.value.reason == "incomplete"


def test_r_d1_port_of_two_publications_makes_no_second_command(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The projection exports a port only through exactly one publication.
    copy = replace(
        config.profile("camera-web"), id="camera-web-copy", ports=PortRange(19443, 19443)
    )
    doubled = replace(config, profiles=(*config.profiles, copy))
    guests = Guests(other(1), camera(ALIAS))
    networks(doubled, monkeypatch, Client(), guests)
    records, skipped = owner.scan_policy(
        doubled,
        settings,
        policy(doubled, EXPORT),
        snapshot(doubled),
        READY | {copy.id},
        INTERFACES,
        1000,
    )
    assert records == () and skipped == 0
    assert [without_m(argv) for argv in guests.reads()] == [False]


def test_r_d1_projected_name_on_a_plain_host_makes_no_second_command(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The loop exclusion refuses a reserved prefix in the instance name as well
    # as in the host name: such an instance is never exported, and read as before.
    named = replace(camera(ALIAS), name=config.discovery_names.export_prefix + "copy")
    guests = Guests(named)
    records, skipped = exported(config, settings, monkeypatch, guests)
    assert records == () and skipped == 0
    assert [without_m(argv) for argv in guests.reads()] == [False]


# Every pair of answers, against the rule of the guide (docs/bonjour-owner.md, export).
SECOND_ALIAS = "203.0.113.40"
ADDRESSES = (GUEST, ALIAS, SECOND_ALIAS, NEIGHBOUR)


def subsets() -> list[tuple[str, ...]]:
    return [
        tuple(item for bit, item in enumerate(ADDRESSES) if mask >> bit & 1)
        for mask in range(1 << len(ADDRESSES))
    ]


def by_the_guide(first: tuple[str, ...], every: tuple[str, ...]) -> tuple[bool, int, int]:
    """Whether the record is exported, how many are left out, and how many reads are made."""

    def as_it_stands(answer: tuple[str, ...]) -> tuple[bool, int]:
        # The guest address among several; one other address is read and not
        # published; none, or several without the guest address, are left out.
        if GUEST in answer:
            return True, 0
        return False, 0 if len(answer) == 1 else 1

    if GUEST in first or not first or NEIGHBOUR in first:
        return (*as_it_stands(first), 1)
    # Outside the guest network alone: read once more for every reply.
    if GUEST in every:
        return True, 0, 2
    if NEIGHBOUR in every:
        return (*as_it_stands(first), 2)
    return False, 1, 2


def test_r_d1_every_pair_of_answers_follows_the_guide(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    differing = []
    for first in subsets():
        for every in subsets():
            guests = Guests(
                other(1, "198.51.100.78"),
                camera(GUEST),
                first={HOST: tuple(("Add", item) for item in first)},
                every={HOST: tuple(("Add", item) for item in every)},
            )
            records, skipped = exported(config, settings, monkeypatch, guests)
            outcome = ([item.name for item in records] == ["Camera"], skipped, len(guests.reads()))
            if outcome != by_the_guide(first, every):
                differing.append((first, every, outcome))
            # What is published is the verified publication's, never an answer's.
            assert all(item.ipv4 == config.scope("wired-lan").host_ipv4 for item in records)
    assert differing == []


# The second read is a reader like the first: every failure fails the scan.


def for_another_interface(answer: Result) -> Result:
    # addrinfo_reply (1276): "%3d" after the flags is the interface of the reply.
    here = f"  {GUEST_INDEX:3d}  {HOST}".encode()
    assert here in answer.stdout
    return replace(
        answer, stdout=answer.stdout.replace(here, f"  {GUEST_INDEX + 1:3d}  {HOST}".encode())
    )


def cut_in_its_last_row(answer: Result) -> Result:
    # Inside the padded address column: the row has no TTL left.
    return replace(answer, stdout=answer.stdout[:-30])


def error_stream_after_a_reply(answer: Result) -> Result:
    # EXIT_IF_LIBDISPATCH_FATAL_ERROR (246) after the replies were shown.
    return replace(answer, stderr=b"Error code -65563\n")


# The failure, the exception and reason the scan raises, and whether it is marked
# as a read that did not complete (None where the runner's own exception is raised).
SECOND_READ_FAILURES: dict[str, tuple[Failure, type[Exception], str | None, bool | None]] = {
    "line-that-is-no-reply": (
        with_line("unexpected line"),
        native.DiscoveryFailure,
        "malformed",
        False,
    ),
    "cut-in-its-last-row": (cut_in_its_last_row, native.DiscoveryFailure, "malformed", False),
    "denial-on-a-row": (
        with_suffix("   Error code -65570"),
        native.DiscoveryFailure,
        "local-network-denied",
        False,
    ),
    "denied-call": (
        call_failed_with(b"-65570"),
        native.DiscoveryFailure,
        "local-network-denied",
        False,
    ),
    "no-such-record": (
        with_suffix("   No Such Record"),
        native.DiscoveryFailure,
        "malformed",
        False,
    ),
    "reply-for-another-interface": (
        for_another_interface,
        native.DiscoveryFailure,
        "malformed",
        False,
    ),
    "exit-status": (
        lambda answer: replace(answer, returncode=1),
        native.DiscoveryFailure,
        "malformed",
        False,
    ),
    "interface-not-acknowledged": (
        without_interface_line,
        native.DiscoveryFailure,
        "malformed",
        False,
    ),
    "interface-acknowledged-twice": (
        with_interface_line_twice,
        native.DiscoveryFailure,
        "malformed",
        False,
    ),
    "error-stream-after-a-reply": (
        error_stream_after_a_reply,
        native.DiscoveryFailure,
        "malformed",
        False,
    ),
    "stopped-after-a-reply": (
        stopped_after(lambda answer: answer.stdout),
        native.DiscoveryFailure,
        "malformed",
        False,
    ),
    "output-bound": (flooded, OutputLimit, None, None),
    # The forms of a read that did not complete, as for the first read: the daemon
    # is not running or busy restarting, or the runner stopped the client before
    # it had shown a reply.
    "stopped-at-the-time-limit": (stopped, native.DiscoveryFailure, "malformed", True),
    "stopped-in-the-loop": (stopped_in_the_loop, native.DiscoveryFailure, "malformed", True),
    "daemon-not-running": (call_failed, native.DiscoveryFailure, "malformed", True),
    "daemon-stopped-before-a-reply": (daemon_stopped, native.DiscoveryFailure, "malformed", True),
}


@pytest.mark.parametrize(
    ("failure", "raised", "reason", "unfinished"),
    SECOND_READ_FAILURES.values(),
    ids=SECOND_READ_FAILURES,
)
def test_r_d1_second_read_that_cannot_prove_itself_fails_the_scan(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    failure: Failure,
    raised: type[Exception],
    reason: str | None,
    unfinished: bool | None,
) -> None:
    guests = Guests(other(1), camera(GUEST, ALIAS), first={HOST: (("Add", ALIAS),)}, second=failure)
    with pytest.raises((native.DiscoveryFailure, ProcessError)) as caught:
        exported(config, settings, monkeypatch, guests)
    assert type(caught.value) is raised
    assert getattr(caught.value, "reason", None) == reason
    assert getattr(caught.value, "unfinished", None) is unfinished
    # It was the second read, and the scan ended there.
    assert [without_m(argv) for argv in guests.reads()] == [False, True]
    assert not guests.asked_for("-Q", camera(GUEST).fullname)


def test_r_d1_second_read_that_never_entered_its_event_loop_cannot_leave_the_instance_out(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No row, and no start line: only a client seen to wait can show no answer.
    guests = Guests(
        other(1),
        camera(GUEST, ALIAS),
        first={HOST: (("Add", ALIAS),)},
        every={HOST: ()},
        second=without_start_line,
    )
    with pytest.raises(native.DiscoveryFailure) as caught:
        exported(config, settings, monkeypatch, guests)
    # As for a first read without a row and without the start line (_unusable).
    assert type(caught.value) is native.DiscoveryFailure and caught.value.reason == "incomplete"


# The scan's time stays the scan's.


def timed(
    guests: Guests, monkeypatch: pytest.MonkeyPatch, seconds: int, remaining: float | None = None
) -> Clock:
    """Commands without -m run to their -t timer; with -m a reply ends them at once.

    With ``remaining``, the scan has that many seconds left once the first
    address read of the camera's host has answered.
    """
    clock = Clock()
    start = clock.now
    monkeypatch.setattr(native, "time", clock)
    guests.clock = clock
    guests.costs = lambda argv: float(seconds) if "-m" not in argv else 0.0

    def after(argv: list[str]) -> None:
        if remaining is not None and "-m" in argv and "-G" in argv and argv[-1] == HOST:
            clock.now = start + 45 - remaining

    guests.hooks.append(after)
    return clock


@pytest.mark.parametrize(
    ("remaining", "second"),
    [(30.0, True), (4.0, True), (3.999, False), (0.5, False)],
    ids=["plenty", "exactly-the-limit-and-room", "just-less", "almost-none"],
)
def test_r_d1_second_read_is_made_only_with_room_for_its_whole_limit(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    remaining: float,
    second: bool,
) -> None:
    guests = Guests(other(1), camera(GUEST, ALIAS), first={HOST: (("Add", ALIAS),)})
    timed(guests, monkeypatch, settings.scan_seconds, remaining)
    records, skipped = exported(config, settings, monkeypatch, guests)
    assert [without_m(argv) for argv in guests.reads()] == [False, True][: 1 + second]
    # Without room the instance is left out; the scan does not fail.
    assert (len(records), skipped) == ((1, 0) if second else (0, 1))
    for argv, limit in guests.commands:
        if "-G" in argv and without_m(argv):
            assert limit == settings.scan_seconds + 1.0


def test_r_d1_scan_whose_time_is_used_up_still_fails_as_such(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    guests = Guests(other(1), camera(GUEST, ALIAS), first={HOST: (("Add", ALIAS),)})
    timed(guests, monkeypatch, settings.scan_seconds, 0.0)
    with pytest.raises(native.DiscoveryFailure) as caught:
        exported(config, settings, monkeypatch, guests)
    assert type(caught.value) is native.DiscoveryFailure and caught.value.reason == "timed-out"
    assert caught.value.unfinished is False


@pytest.mark.parametrize(
    ("seconds", "second_reads", "expected"),
    [(1, 12, (12, 0)), (2, 12, (12, 0)), (3, 12, (12, 0)), (4, 9, (9, 3)), (5, 7, None)],
)
def test_r_d1_second_reads_never_take_a_scan_past_its_limit(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    seconds: int,
    second_reads: int,
    expected: tuple[int, int] | None,
) -> None:
    # Twelve instances of the guest's host, each with its alias first. A second
    # read is made while the scan has room for its whole limit; the instances
    # after that are left out, and at the fifth of them the scan fails as before.
    instances = [replace(camera(GUEST, ALIAS), name=f"Camera {n:02d}") for n in range(12)]
    guests = Guests(*instances, first={HOST: (("Add", ALIAS),)})
    clock = timed(guests, monkeypatch, seconds)
    start = clock.now
    try:
        records, skipped = exported(
            config, replace(settings, scan_seconds=seconds), monkeypatch, guests
        )
    except native.DiscoveryFailure as failure:
        assert expected is None
        assert type(failure) is native.DiscoveryFailure and failure.reason == "incomplete"
    else:
        assert (len(records), skipped) == expected
    assert len([argv for argv, _ in guests.commands if without_m(argv) and "-G" in argv]) == (
        second_reads
    )
    deadline = start + 45
    for (argv, limit), began in zip(guests.commands, guests.started, strict=True):
        assert began + limit <= deadline
        if "-G" in argv and without_m(argv):
            # Every second read had its own whole limit and the room beside it.
            assert limit == seconds + 1.0 and deadline - began >= seconds + 2.0
    assert clock.now - start <= 45


def test_r_d1_second_reads_stay_inside_the_scanners_wait(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A 30-second lease: the scanner waits min(45, 30 / 2) = 15 seconds for the
    # scan. Four other guests on the published port answer an alias first, and
    # each second read runs its 5 seconds; the other commands answer at once.
    current = leased(config, 30, EXPORT)
    neighbours = [
        replace(
            other(n, f"198.51.100.{30 + n}"),
            addresses=(f"198.51.100.{30 + n}", f"192.0.2.{110 + n}"),
        )
        for n in range(1, 5)
    ]
    first = {item.host: (("Add", item.addresses[1]),) for item in neighbours}
    guests = Guests(*neighbours, camera(GUEST), first=first)
    clock = timed(guests, monkeypatch, 5)
    guests.costs = lambda argv: 5.0 if "-G" in argv and without_m(argv) else 0.0
    start = clock.now
    records, skipped = exported(current, replace(settings, scan_seconds=5), monkeypatch, guests)
    # Two second reads fit the wait with their limit and one second to spare;
    # they show the neighbours' own addresses. The two after them are left out
    # for want of room, and the guest is exported.
    assert published(records) == [("Camera", current.scope("wired-lan").host_ipv4, 9443)]
    assert skipped == 2
    seconds = [
        (began, limit)
        for (argv, limit), began in zip(guests.commands, guests.started, strict=True)
        if "-G" in argv and without_m(argv)
    ]
    assert len(seconds) == 2
    assert all(began + limit <= start + 15 - 1.0 for began, limit in seconds)
    assert clock.now - start <= 15


def test_r_d1_bound_of_one_scan_and_of_a_pass_is_unchanged(
    config: Config, settings: owner.BonjourSettings
) -> None:
    # The literals of 0.4.2: so no setting that loads there is refused here.
    assert inspect.signature(native.scan).parameters["max_seconds"].default == 45
    assert (owner._SCAN_LIMIT, owner._SCAN_BATCH, owner._PASS_SLACK) == (45, 8, 5)
    assert (native.MAX_LEFT_OUT, native._BUDGET_ROOM) == (4, 1.0)
    assert owner.pass_budget(config, settings) == 119
    assert owner.carry_horizon(config, settings) == 243


def test_r_d1_import_scan_is_unchanged_by_the_guest_network(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The LAN client with -m shows the first of a device's two addresses alone;
    # an import reads that answer as before, with no second command.
    double = replace(KITCHEN, addresses=(KITCHEN.addresses[0], "192.0.2.85"))
    lan = Guests(double, index=LAN_INDEX, first={KITCHEN.host: (("Add", KITCHEN.addresses[0]),)})
    networks(config, monkeypatch, lan, Client(index=GUEST_INDEX))
    records, skipped = owner.scan_policy(
        config, settings, policy(config), snapshot(config), READY, INTERFACES, 1000
    )
    assert [(item.name, item.service_type) for item in records] == [(KITCHEN.name, AIRPLAY)]
    assert skipped == 0
    assert [without_m(argv) for argv, _ in lan.commands if "-G" in argv] == [False]


def test_r_d1_scanner_gives_the_second_read_for_exports_only(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    given: dict[str, dict[str, Any]] = {}

    def scan(
        _interface: str, index: int, kind: str, *_arguments: Any, **keywords: Any
    ) -> tuple[Record, ...]:
        given[kind] = keywords
        return ()

    networks(config, monkeypatch, Client(), Client(index=GUEST_INDEX))
    monkeypatch.setattr(owner, "scan", scan)
    # The export with a type of each protocol; the example publishes TCP only.
    export = replace(policy(config, EXPORT), types=("_hap._tcp", "_example._udp"))
    for item in (policy(config), export):
        owner.scan_policy(config, settings, item, snapshot(config), READY, INTERFACES, 1000)
    assert all(
        set(keywords) == {"guest_ipv4", "second_read", "skipped", "unanswered"}
        for keywords in given.values()
    )
    tcp, udp = given["_hap._tcp"]["second_read"], given["_example._udp"]["second_read"]
    assert (tcp.guest_ipv4, tcp.guest_network, tcp.names) == (
        GUEST,
        ipaddress.IPv4Network(config.scope("wired-lan").guest_cidr),
        config.discovery_names,
    )
    assert (tcp.ports, udp.ports) == (frozenset({9443}), frozenset())
    # The scanner's wait, on the clock the scan reads: at most 45 seconds ahead.
    assert 0 < tcp.scanner_deadline - native.time.monotonic() <= 45
    # An import gets nothing new.
    assert given[AIRPLAY]["guest_ipv4"] is None and given[AIRPLAY]["second_read"] is None

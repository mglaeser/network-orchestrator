"""`renewal_overlap_seconds` on the publisher's own tick.

The publisher's loop sleeps a quarter of a second between two turns, so the
times at which it decides are no whole seconds, while a client's lifetime is a
whole number of seconds, rounded up from the lease that is left. The tests of
``test_bonjour_renewal_overlap.py`` tick once a second. The ones here tick as
the loop does: a replacement is started beside a running client only where the
lease ends later than that client, which without a newer sighting it does not,
whatever the tick. Two corners of the setting follow: the interface index of a
replacement and the policies of another discovery owner.

The fake client, its clock and the helpers are those of that file. Names are
invented, addresses are RFC 5737, and nothing here talks to a daemon.
"""

from __future__ import annotations

import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.config import validate_config
from netorch.discovery import Record
from netorch.model import Config, Owner
from tests.test_bonjour_miss_tolerance import leased, settings_file
from tests.test_bonjour_owner import config, policy, settings
from tests.test_bonjour_record_expiry import FAKE_CLIENT, two_records
from tests.test_bonjour_renewal_overlap import (
    OVERLAP,
    Client,
    Clock,
    clock,
    long_lease,
    publisher,
    run,
    started,
    tick,
)

__all__ = ["clock", "config", "settings"]

IMPORT, EXPORT = "media-import", "camera-export"
TICK = 0.25  # publisher_loop sleeps this long between two turns


# A replacement needs a lease that ends later than the running client


def test_sighting_inside_the_overlap_window_starts_the_replacement_and_leaves_no_gap(
    config: Config, clock: Clock
) -> None:
    manager = publisher(30)
    item = policy(config)
    assert item.max_age_seconds == 120
    # A slow scanner: the source is seen every 95 seconds. The window of a client
    # of 120 seconds opens 90 seconds after its start, five seconds before the
    # next sighting.
    while clock.elapsed < 400:
        assert tick(manager, item, clock, seen=95.0 * (clock.elapsed // 95))
        # Never between two clients: the record stays registered throughout.
        assert manager.renewals(item) == 0
        clock.elapsed += TICK
    # Under the old sighting nothing is started in the window: it would renew
    # nothing and hold the one place a replacement has. The replacement starts
    # with the sighting, runs beside its predecessor and outlives it.
    assert Client.events == [
        "0 start Example speaker 1 -t 120",
        "95 start Example speaker 2 -t 120",
        "120 close Example speaker 1 ended",
        "190 start Example speaker 3 -t 120",
        "215 close Example speaker 2 ended",
        "285 start Example speaker 4 -t 120",
        "310 close Example speaker 3 ended",
        "380 start Example speaker 5 -t 120",
    ]


@pytest.mark.parametrize("age", [0.0, 0.4])
def test_lease_of_one_client_lifetime_seen_once_gets_no_second_client(
    config: Config, clock: Clock, age: float
) -> None:
    manager = publisher(OVERLAP)
    item = policy(config)
    assert item.max_age_seconds == 120
    # One sighting, ``age`` seconds old at the first turn, and no other. The
    # lease ends with the client or a part of a second before it.
    reported = run(manager, item, clock, 119, step=TICK, seen=-age)
    assert set(reported) == {(True, 0)}
    assert started() == ["0 start Example speaker 1 -t 120"]
    assert manager.successors == {}


def test_long_lease_seen_once_gets_no_client_that_would_renew_nothing(
    config: Config, clock: Clock
) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config, 300)
    reported = run(manager, item, clock, 300, step=TICK, seen=0)
    # Two replacements inside the one lease, each started ten seconds before its
    # predecessor ends. Ten seconds before the third client ends, the lease has
    # those ten seconds left and no more: there is no fourth client.
    assert started() == [
        "0 start Example speaker 1 -t 120",
        "110 start Example speaker 2 -t 120",
        "220 start Example speaker 3 -t 80",
    ]
    assert set(reported) == {(True, 0)}
    assert list(manager.children.values()) == [Client.made[2]] and manager.successors == {}
    manager.expire(clock.monotonic())
    assert not manager.children and all(client.closed for client in Client.made)


@pytest.mark.parametrize("step", [TICK, 0.3, 0.7])
def test_replacement_starts_at_the_first_turn_with_at_most_the_overlap_left(
    config: Config, clock: Clock, step: float
) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config)
    assert set(run(manager, item, clock, 130, step=step)) == {(True, 0)}
    first, replacement = Client.made
    assert replacement.lifetime_seconds == 120
    left = first.spawned + first.lifetime_seconds - replacement.spawned
    # Not a turn before the running client has the overlap left, and at the
    # first turn from then on: the two run side by side for the setting less up
    # to one turn of the loop.
    assert OVERLAP - step < left <= OVERLAP


def test_single_sighting_is_published_by_one_native_client(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease, overlap = 6, 2  # seconds; a 120-second lease gives the same course, slower
    item = replace(policy(config), max_age_seconds=lease)
    fake = tmp_path / "fake-dns-sd"
    fake.write_text(FAKE_CLIENT.replace("{python}", sys.executable))
    fake.chmod(0o700)
    monkeypatch.setattr(native, "DNS_SD", str(fake))
    made: list[native.Registration] = []

    def factory(record: Record, index: int, seconds: int) -> native.Registration:
        made.append(native.Registration(record, index, seconds))
        return made[-1]

    manager = owner.Publisher(factory, renewal_overlap=overlap)
    # Seen once, half a second before the publisher's first turn, and not again.
    seen = time.time() - 0.5
    records = two_records(seen)[:1]
    confirmed = []
    try:
        # Until half a second before the lease ends: the client's last two
        # seconds, in which a replacement would be due, lie inside.
        while time.time() < seen + lease - 0.5:
            manager.expire(time.monotonic())
            confirmed.append(manager.reconcile(item, records, 9, time.time()))
            time.sleep(TICK)
        alive = [client.process.poll() is None for client in made]
    finally:
        manager.close()
    assert confirmed and confirmed[-1]
    # One process for the whole lease: in its last two seconds the lease has no
    # more left than the client has, so nothing is started beside it.
    assert [client.lifetime_seconds for client in made] == [lease]
    assert alive == [True]


# Corners


def test_replacement_is_registered_on_the_interface_index_of_its_own_turn(
    config: Config, clock: Clock
) -> None:
    manager = publisher(OVERLAP)
    item = long_lease(config)
    run(manager, item, clock, 110)
    (first,) = Client.made
    assert first.index == 7
    # The interface was set up anew and has another index when the replacement
    # is due: the replacement is started for that index, as a first client is.
    manager.expire(clock.monotonic())
    assert manager.reconcile(item, two_records(clock.time())[:1], 9, clock.time())
    first, replacement = Client.made
    assert (first.index, replacement.index) == (7, 9)
    assert replacement.record.name == first.record.name and not first.closed


def second_owner(config: Config, *identifiers: str) -> Config:
    """The policy with the named discovery entries handed to another discovery owner."""
    other = Owner("other-discovery", "user", ("discovery",))
    return replace(
        config,
        owners=(*config.owners, other),
        discovery=tuple(
            replace(item, owner=other.id) if item.id in identifiers else item
            for item in config.discovery
        ),
    )


def test_lease_rule_of_the_setting_looks_at_the_policies_of_this_owner_only(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    foreign = second_owner(config, EXPORT)
    validate_config(foreign)
    assert [item.owner for item in foreign.discovery] == [settings.owner, "other-discovery"]

    def load(policy_config: Config) -> owner.BonjourSettings:
        return owner.load_settings(
            settings_file(tmp_path, policy_config, settings, renewal_overlap_seconds=20)
        )

    # Another owner's long lease does not stand in for a lease of this owner ...
    with pytest.raises(ValueError, match="needs a lease that is longer"):
        load(leased(foreign, 20, only=IMPORT))
    # ... and another owner's short lease does not refuse this owner's setting.
    assert load(leased(foreign, 20, only=EXPORT)) == replace(settings, renewal_overlap_seconds=20)

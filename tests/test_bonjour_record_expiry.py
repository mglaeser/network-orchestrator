"""A registration client that ends on its own ``-t`` timer is one record's expiry.

With ``-t`` Apple's client arms ``dispatch_after(exitTimeout)`` with ``exit(0)``
when it enters its event loop (``Clients/dns-sd.c`` lines 1315-1320 at the
revision the Bonjour guide cites). Its other ``exit(0)``, for a daemon that has
stopped, first prints ``Error code %d`` on a line of its own (lines 245-246).
The fake client below follows that source and prints the banner and the two
confirmation callbacks in its format. Synthetic names and RFC 5737 addresses
only; nothing here is a capture from a host.
"""

from __future__ import annotations

import os
import selectors
import sys
import time
from dataclasses import replace
from typing import Any, ClassVar

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.config import config_digest, to_dict
from netorch.discovery import Record
from netorch.discovery_plan import discovery_digest
from netorch.model import Config
from netorch.state import Intent, Snapshot
from netorch.storage import Store
from tests.test_bonjour_owner import (
    config,
    media_record,
    policy,
    settings,
    snapshot,
    write_private,
)

__all__ = ["config", "settings"]

READY = frozenset({"media-udp", "camera-web"})
# main(): "Using interface %d\n"; RegisterService: "Registering Service %s.%s%s%s",
# " host %s", " port %s"; then printtimestamp(), "...STARTING...\n" and the two
# callbacks "Got a reply for record %s: " / "Got a reply for service %s.%s%s: ".
CONFIRMED = (
    b"Using interface 7\n"
    b"Registering Service Example speaker._airplay._tcp.local. host speaker.local. port 7000\n"
    b"DATE: ---Mon 05 Oct 2026---\n"
    b"22:03:17.123  ...STARTING...\n"
    b"22:03:17.900  Got a reply for record speaker.local.: Name now registered and active\n"
    b"22:03:18.100  Got a reply for service Example speaker._airplay._tcp.local.: "
    b"Name now registered and active\n"
)


class Ended:
    """The process handle of a client that has already exited."""

    def __init__(self, status: int) -> None:
        self.status = status

    def poll(self) -> int:
        return self.status


class Idle:
    def select(self, _timeout: float) -> tuple[()]:
        return ()


def ended_registration(status: int, age: float, output: bytes) -> native.Registration:
    registration = object.__new__(native.Registration)
    registration.closed = False
    registration.record = media_record()
    registration.index = 7
    registration.lifetime_seconds = 30
    registration.process = Ended(status)  # type: ignore[assignment]
    registration.selector = Idle()  # type: ignore[assignment]
    registration.output = bytearray(output)
    registration.started = registration.spawned = time.monotonic() - age
    registration.active = True
    return registration


@pytest.mark.parametrize(
    ("status", "age", "output", "expired"),
    [
        (0, 30.0, CONFIRMED, True),
        # The banner echoes names and TXT; only a line of its own is the diagnostic.
        (0, 30.0, CONFIRMED.replace(b"port 7000", b"port 7000 TXT note=Error code 7"), True),
        (0, 10.0, CONFIRMED, False),
        (1, 30.0, CONFIRMED, False),
        (255, 30.0, CONFIRMED, False),
        (-15, 30.0, CONFIRMED, False),
        (-9, 30.0, CONFIRMED, False),
        (0, 30.0, CONFIRMED + b"Error code -65563\n", False),
    ],
    ids=[
        "own-timer",
        "own-timer-with-the-words-in-its-banner",
        "status-0-before-the-lifetime",
        "status-1",
        "status-255",
        "terminated",
        "killed",
        "status-0-after-a-daemon-error-line",
    ],
)
def test_only_status_zero_at_or_after_the_lifetime_is_an_expiry(
    status: int, age: float, output: bytes, expired: bool
) -> None:
    with pytest.raises(native.DiscoveryFailure) as caught:
        ended_registration(status, age, output).poll()
    # A caller that does not know the expiry still sees today's child failure.
    assert caught.value.reason == "unavailable"
    assert isinstance(caught.value, native.RegistrationExpired) is expired


def test_last_line_of_an_ended_client_is_read_before_its_exit_is_judged() -> None:
    read_end, write_end = os.pipe()
    os.set_blocking(read_end, False)

    class DaemonStopped:
        """Writes the fatal-error line and exits 0 at the moment it is asked."""

        status: int | None = None

        def poll(self) -> int:
            if self.status is None:
                os.write(write_end, b"Error code -65563\n")
                os.close(write_end)
                self.status = 0
            return self.status

    registration = ended_registration(0, 30.0, CONFIRMED)
    registration.process = DaemonStopped()  # type: ignore[assignment]
    registration.selector = selectors.DefaultSelector()
    registration.selector.register(read_end, selectors.EVENT_READ)
    try:
        with pytest.raises(native.DiscoveryFailure) as caught:
            registration.poll()
    finally:
        registration.selector.close()
        os.close(read_end)
    assert caught.value.reason == "unavailable"
    assert not isinstance(caught.value, native.RegistrationExpired)


class Child:
    """Stands in for Registration; the test decides when and how its client ends."""

    made: ClassVar[list[Child]] = []
    slow: ClassVar[bool] = False

    def __init__(self, record: Record, index: int, lifetime_seconds: int = 120) -> None:
        self.record = record
        self.lifetime_seconds = lifetime_seconds
        self.confirms = not Child.slow
        self.active = False
        self.closed = False
        self.end: native.DiscoveryFailure | None = None
        # No second client may hold a record whose earlier client still runs.
        self.alone = all(item.closed for item in Child.made if item.record.name == record.name)
        Child.made.append(self)

    def poll(self) -> bool:
        if self.end is not None:
            raise self.end
        self.active = self.confirms
        return self.active

    def close(self) -> None:
        self.closed = True


def publisher(*, slow: bool = False) -> owner.Publisher:
    Child.made = []
    Child.slow = slow
    return owner.Publisher(Child)  # type: ignore[arg-type]


def two_records(seen_at: float = 1000) -> tuple[Record, Record]:
    return (
        media_record(seen_at=seen_at),
        media_record(
            name="Second speaker", hostname="second.local.", ipv4="192.0.2.83", seen_at=seen_at
        ),
    )


def test_own_timer_expiry_replaces_only_that_client(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = publisher()
    monotonic = [100.0]
    monkeypatch.setattr(owner.time, "monotonic", lambda: monotonic[0])
    media = policy(config)
    assert manager.reconcile(media, two_records(), 7, 1000)
    first, second = Child.made
    deadlines = dict(manager.deadlines)

    first.end = native.RegistrationExpired()
    monotonic[0] = 130.0
    # The record was confirmed, so the policy keeps its state while it is renewed.
    assert manager.reconcile(media, two_records(), 7, 1030)
    assert len(Child.made) == 3
    replacement = Child.made[2]
    assert replacement.record == first.record
    assert first.closed and replacement.alone and not replacement.closed
    assert not second.closed and second in manager.children.values()
    assert replacement in manager.children.values() and len(manager.children) == 2
    # The replacement lives for the lease that is left; the lease is not extended.
    assert replacement.lifetime_seconds == 90
    assert manager.deadlines == deadlines
    assert manager.renewals(media) == 1

    assert manager.reconcile(media, two_records(), 7, 1030)
    assert manager.renewals(media) == 0 and len(Child.made) == 3


def test_renewal_grace_ends_with_the_replacement(config: Config) -> None:
    manager = publisher()
    media = policy(config)
    manager.reconcile(media, two_records(), 7, 1000)
    Child.made[0].end = native.RegistrationExpired()
    assert manager.reconcile(media, two_records(), 7, 1000)
    replacement = Child.made[2]
    # A replacement that ends on its own timer before it ever confirmed leaves
    # the record unconfirmed: the grace is not handed on to a third client.
    replacement.confirms = False
    assert manager.reconcile(media, two_records(), 7, 1000)
    replacement.end = native.RegistrationExpired()
    assert not manager.reconcile(media, two_records(), 7, 1000)
    assert manager.renewals(media) == 0 and len(Child.made) == 4
    assert replacement.closed and Child.made[3].alone


def test_expiry_of_a_client_that_never_confirmed_keeps_nothing(config: Config) -> None:
    manager = publisher(slow=True)
    media = policy(config)
    assert not manager.reconcile(media, (media_record(),), 7, 1000)
    Child.made[0].end = native.RegistrationExpired()
    # It is replaced alone as well, but there is no confirmed state to keep.
    assert not manager.reconcile(media, (media_record(),), 7, 1000)
    assert manager.renewals(media) == 0 and Child.made[0].closed and len(Child.made) == 2


@pytest.mark.parametrize("reason", ["timed-out", "identity-mismatch", "unavailable"])
def test_failing_replacement_is_a_child_failure_as_before(config: Config, reason: str) -> None:
    manager = publisher()
    media = policy(config)
    manager.reconcile(media, two_records(), 7, 1000)
    Child.made[0].end = native.RegistrationExpired()
    assert manager.reconcile(media, two_records(), 7, 1000)
    Child.made[2].end = native.DiscoveryFailure(reason)
    with pytest.raises(native.DiscoveryFailure) as caught:
        manager.reconcile(media, two_records(), 7, 1000)
    assert caught.value.reason == reason and not isinstance(
        caught.value, native.RegistrationExpired
    )
    assert Child.made[2].closed and manager.renewals(media) == 0
    assert list(manager.children.values()) == [Child.made[1]]
    assert manager.deadlines.keys() == manager.children.keys()


def lease(
    config: Config, settings: owner.BonjourSettings, current: Snapshot, records: Any, now: float
) -> tuple[dict[str, Any], dict[str, Any]]:
    """A current request and a complete candidate for the import policy."""
    media = policy(config)
    projected = owner.project_records(
        config, media, tuple(records), current, frozenset({"media-udp"}), settings, now
    )
    common = {
        "policy_digest": discovery_digest(config, media),
        "service_generation": current.services[media.service].generation,
        "network_generation": current.network_generation,
    }
    request = {**common, "active": True, "requested_at": now}
    candidate = {
        **common,
        "records": [owner.record_to_dict(item) for item in projected],
        "interface_confirmed": True,
        "observed_at": now,
    }
    return (
        {"schema_version": 1, "policies": {media.id: request}},
        {
            "schema_version": 1,
            "config_digest": config_digest(config),
            "observed_at": now,
            "policies": {media.id: candidate},
        },
    )


def test_policy_stays_present_and_counts_confirmed_records_during_a_renewal(
    config: Config, settings: owner.BonjourSettings
) -> None:
    current = snapshot(config)
    store = Store(settings.state_dir)
    requests, candidates = lease(config, settings, current, two_records(), 1000)
    store.write("requests.json", requests)
    store.write("candidates.json", candidates)
    proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
    manager = publisher()

    def tick() -> tuple[str, str, int]:
        fact = owner.publisher_tick(config, settings, store, manager, proof, 0, 1000).profiles[
            "media-import"
        ]
        return fact.state, fact.reason, fact.data["record_count"]

    assert tick() == ("present", "verified", 2)
    first, second = Child.made
    first.end = native.RegistrationExpired()
    # One record is between two clients: the state is kept, the count is honest.
    assert tick() == ("present", "verified", 1)
    assert first.closed and not second.closed and len(Child.made) == 3
    assert tick() == ("present", "verified", 2)

    # Any other end of a client is still a failure of its whole policy.
    Child.made[2].end = native.DiscoveryFailure("unavailable")
    assert tick() == ("unknown", "unavailable", 0)
    assert second.closed and not manager.children


FAKE_CLIENT = r"""#!{python}
import sys, time
argv = sys.argv[1:]
assert argv[0] == "-i" and argv[2] == "-t" and argv[4] == "-P", argv
lifetime = int(argv[3])
name, kind, domain, port, host, address = argv[5:11]
stamp = time.strftime("%H:%M:%S") + ".000  "
if stamp[0] == "0":
    stamp = " " + stamp[1:]
print("Using interface 9")
print("Registering Service %s.%s.%s host %s port %s" % (name, kind, domain, host, port))
print(stamp + "...STARTING...")
print(stamp + "Got a reply for record %s: Name now registered and active" % host)
print(
    stamp + "Got a reply for service %s.%s.%s: Name now registered and active"
    % (name, kind, domain),
    flush=True,
)
time.sleep(lifetime)  # dispatch_after(exitTimeout) ...
sys.exit(0)  # ... exit(0)
"""


def test_second_record_survives_and_policy_stays_present_across_native_expiry(
    config: Config,
    settings: owner.BonjourSettings,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifetime = 2  # seconds; the example lease of 120 gives the same cycle, slower
    config = replace(
        config,
        discovery=tuple(
            replace(item, max_age_seconds=lifetime) if item.id == "media-import" else item
            for item in config.discovery
        ),
    )
    write_private(settings.config, to_dict(config))
    fake = tmp_path / "fake-dns-sd"
    fake.write_text(FAKE_CLIENT.replace("{python}", sys.executable))
    fake.chmod(0o700)
    monkeypatch.setattr(native, "DNS_SD", str(fake))

    made: dict[str, list[native.Registration]] = {}
    overlapping: list[str] = []
    killed_sibling: list[str] = []

    def factory(record: Record, index: int, seconds: int) -> native.Registration:
        earlier = made.setdefault(record.name, [])
        if any(item.process.poll() is None for item in earlier):
            overlapping.append(record.name)
        if earlier:
            # A replacement is being started: every other record's client must
            # still be the one it had, running or ended on its own timer.
            killed_sibling.extend(
                name
                for name, others in made.items()
                if name != record.name and others[-1].process.poll() not in {None, 0}
            )
        earlier.append(native.Registration(record, index, seconds))
        return earlier[-1]

    def fresh(now: float) -> Snapshot:
        base = snapshot(config)
        return replace(
            base,
            observed_at=now,
            services={key: replace(item, observed_at=now) for key, item in base.services.items()},
            profiles={key: replace(item, observed_at=now) for key, item in base.profiles.items()},
        )

    manager = owner.Publisher(factory)
    store = Store(settings.state_dir)
    begin = time.monotonic()
    steady: list[tuple[str, str]] = []
    try:
        while time.monotonic() - begin < 30:
            now = time.time()
            current = fresh(now)
            # The scanner keeps seeing its sources: a complete, fresh candidate each
            # tick. A second genuine device joins one second after the first.
            sources = two_records(now)[: 2 if time.monotonic() - begin >= 1 else 1]
            requests, candidates = lease(config, settings, current, sources, now)
            store.write("requests.json", requests)
            store.write("candidates.json", candidates)
            proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
            manager.expire(time.monotonic())
            fact = owner.publisher_tick(config, settings, store, manager, proof, 0, now).profiles[
                "media-import"
            ]
            if steady or (fact.state == "present" and fact.data["record_count"] == 2):
                steady.append((fact.state, fact.reason))
            if (
                all(len(made.get(item.name, ())) >= 2 for item in two_records())
                and fact.state == "present"
                and fact.data["record_count"] == 2
            ):
                break
            time.sleep(0.05)
        replaced = [item.process.poll() for items in made.values() for item in items[:-1]]
    finally:
        manager.close()

    # Both records were registered again by a replacement of their own ...
    assert all(len(made.get(item.name, ())) >= 2 for item in two_records())
    # ... each time because that one client ended on its own timer (status 0),
    # never by a signal sent when a sibling's timer ran out.
    assert replaced and set(replaced) == {0}
    assert killed_sibling == []
    # No replacement was started beside the client it replaces.
    assert overlapping == []
    # From the first complete confirmation on, the source was seen continuously
    # and the policy never read unknown.
    assert steady and set(steady) == {("present", "verified")}

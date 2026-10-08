"""A registration client that ends on its own ``-t`` timer is one record's expiry.

With ``-t`` Apple's client arms ``dispatch_after(exitTimeout)`` with ``exit(0)``
when it enters its event loop (``Clients/dns-sd.c`` lines 1315-1320 at the
revision the Bonjour guide cites). Its other ``exit(0)``, for a daemon that has
stopped, first prints ``Error code %d`` on a line of its own (lines 245-246).
An unknown interface returns 0 as well, through ``Fail:`` (lines 2104 and
2405-2408), and a callback can arrive after the last poll that saw the client
running. So the end is an expiry only if the complete output is clean.
The fake client below follows that source and prints the banner and the two
confirmation callbacks in its format. Synthetic names and RFC 5737 addresses
only; nothing here is a capture from a host.
"""

from __future__ import annotations

import os
import selectors
import sys
import time
from collections.abc import Callable
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
        # The banner echoes TXT with every space escaped (ShowTXTRecord, line 806),
        # so these words in TXT are not the diagnostic.
        (0, 30.0, CONFIRMED.replace(b"port 7000", rb"port 7000 TXT note=Error\ code\ 7"), True),
        # Unescaped in the banner they fail a running client, and so an ended one:
        # the diagnostic goes to stderr and can follow a banner that stdio cut.
        (0, 30.0, CONFIRMED.replace(b"port 7000", b"port 7000 TXT note=Error code 7"), False),
        (0, 10.0, CONFIRMED, False),
        (1, 30.0, CONFIRMED, False),
        (255, 30.0, CONFIRMED, False),
        (-15, 30.0, CONFIRMED, False),
        (-9, 30.0, CONFIRMED, False),
        (0, 30.0, CONFIRMED + b"Error code -65563\n", False),
    ],
    ids=[
        "own-timer",
        "own-timer-with-the-words-in-its-txt-as-echoed",
        "status-0-with-the-words-unescaped-in-its-banner",
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


SERVICE = b"Example speaker._airplay._tcp.local."
ACTIVE = b": Name now registered and active\n"
# printtimestamp() writes this before the text of every callback line.
LATER = b"22:03:47.250  "
REMOVED = LATER + b"Got a reply for service " + SERVICE + b": Name registration removed\n"
UNSTAMPED = b"Got a reply for service " + SERVICE + ACTIVE
# main(): "Unknown interface %s\n" (line 2104), then Fail: prints the usage and
# returns 0. The first usage line stands for all of them.
UNKNOWN_INTERFACE = (
    b"Unknown interface example0\n"
    b"dns-sd -E                          (Enumerate recommended registration domains)\n"
)
# The client leaves stdio's defaults: stdout to a pipe is written in full blocks,
# stderr at once. Here a block ended inside the banner, the daemon stopped, the
# diagnostic followed the cut and exit(0) flushed the rest. (A real block is longer.)
GLUED_TO_THE_BANNER = (
    b"Using interface 7\n"
    b"Registering Service " + SERVICE + b" host speaker.local. port 7000 TXT model="
    b"Error code -65563\n"
    b"AudioAccessory5,1\n"
    b"DATE: ---Mon 05 Oct 2026---\n"
    b"22:03:17.123  ...STARTING...\n"
)
OVERSIZED = CONFIRMED.replace(b"port 7000", b"port 7000 TXT " + b"x" * native.MAX_OUTPUT)


@pytest.mark.parametrize(
    ("output", "confirmed"),
    [
        (CONFIRMED + REMOVED, True),
        (
            CONFIRMED
            + LATER
            + b"Got a reply for service Example speaker (2)._airplay._tcp.local."
            + ACTIVE,
            True,
        ),
        (CONFIRMED + LATER + b"Got a reply for record other.local." + ACTIVE, True),
        (CONFIRMED + LATER + b"Got a reply for service " + SERVICE + b": Error -65570\n", True),
        (CONFIRMED + b"    No Authorization\n", True),
        (CONFIRMED + b"DNSService call failed -65563\n", True),
        # The loop without libdispatch prints this and main() returns 0 (line 1377).
        (CONFIRMED + LATER + b"DNSServiceProcessResult returned -65563\n", True),
        (UNKNOWN_INTERFACE, False),
        (CONFIRMED + LATER + b"Error code -65563\n", True),
        (GLUED_TO_THE_BANNER, False),
        (CONFIRMED + b"Error code -65563\r\n", True),
        (CONFIRMED + LATER + b"Got a reply for record speaker.local.: Name now regis", True),
        # Every line is as expected; only the last newline is missing.
        (CONFIRMED[:-1], True),
        (CONFIRMED + UNSTAMPED, True),
        (b"", False),
        (OVERSIZED, True),
        # main() prints the requested interface once, before anything else (line 2135).
        (CONFIRMED.replace(b"Using interface 7\n", b""), True),
        (CONFIRMED + b"Using interface 7\n", True),
        (CONFIRMED.replace(b"Using interface 7\n", b"Using interface 8\n"), True),
        (UNKNOWN_INTERFACE.split(b"\n", 1)[1], False),
    ],
    ids=[
        "removal-callback",
        "confirmation-for-another-service-name",
        "confirmation-for-another-host-record",
        "callback-with-error-65570",
        "no-authorization-line",
        "dnsservice-call-failed-line",
        "dnsservice-returned-line",
        "unknown-interface-and-usage",
        "error-code-directly-after-an-unterminated-line",
        "error-code-glued-to-a-cut-banner",
        "error-code-line-ending-in-a-carriage-return",
        "confirmation-cut-in-the-middle",
        "last-line-without-its-newline",
        "callback-without-the-timestamp",
        "nothing-printed",
        "more-output-than-the-bound",
        "no-interface-line",
        "interface-line-twice",
        "line-for-another-interface",
        "usage-text-only",
    ],
)
def test_status_zero_at_the_lifetime_is_no_expiry_unless_the_whole_output_is_clean(
    output: bytes, confirmed: bool
) -> None:
    registration = ended_registration(0, 30.0, output)
    registration.active = confirmed
    with pytest.raises(native.DiscoveryFailure) as caught:
        registration.poll()
    # An ended client keeps the general reason; only the expiry got narrower.
    assert caught.value.reason == "unavailable"
    assert not isinstance(caught.value, native.RegistrationExpired)
    assert registration.active is confirmed


@pytest.mark.parametrize(
    ("output", "confirmed"),
    [
        # A lifetime can be shorter than the confirmation takes.
        (CONFIRMED[: CONFIRMED.index(b"22:03:17.900")], False),
        (CONFIRMED + LATER + b"Got a reply for record speaker.local." + ACTIVE, True),
        # The confirmation arrived after the last poll that saw the client running.
        (CONFIRMED, False),
    ],
    ids=["banner-only", "expected-confirmation-repeated", "confirmed-after-the-last-poll"],
)
def test_clean_end_stays_an_expiry_and_does_not_change_the_confirmed_state(
    output: bytes, confirmed: bool
) -> None:
    registration = ended_registration(0, 30.0, output)
    registration.active = confirmed
    with pytest.raises(native.RegistrationExpired):
        registration.poll()
    # The publisher reads this to decide whether the record keeps the policy's
    # state; judging the end does not change what the last running poll found.
    assert registration.active is confirmed


class Running:
    """The process handle of a client that has not ended."""

    def poll(self) -> None:
        return None


def running_registration(output: bytes) -> native.Registration:
    registration = ended_registration(0, 0.0, output)
    registration.process = Running()  # type: ignore[assignment]
    registration.active = False
    return registration


@pytest.mark.parametrize(
    ("output", "reason"),
    [
        (CONFIRMED + REMOVED, "identity-mismatch"),
        (CONFIRMED + UNSTAMPED, "malformed"),
        (
            CONFIRMED + LATER + b"Got a reply for service " + SERVICE + b": Error -65570\n",
            "local-network-denied",
        ),
        (CONFIRMED + b"    No Authorization\n", "local-network-denied"),
        (CONFIRMED + b"DNSService call failed -65563\n", "malformed"),
        (UNKNOWN_INTERFACE, "malformed"),
        (GLUED_TO_THE_BANNER, "malformed"),
        (CONFIRMED.replace(b"port 7000", b"port 7000 TXT note=Error code 7"), "malformed"),
        (OVERSIZED, "incomplete"),
    ],
    ids=[
        "removal-callback",
        "callback-without-the-timestamp",
        "callback-with-error-65570",
        "no-authorization-line",
        "dnsservice-call-failed-line",
        "unknown-interface-and-usage",
        "error-code-glued-to-a-cut-banner",
        "the-words-unescaped-in-its-banner",
        "more-output-than-the-bound",
    ],
)
def test_running_client_keeps_failing_with_the_specific_reason(output: bytes, reason: str) -> None:
    with pytest.raises(native.DiscoveryFailure) as caught:
        running_registration(output).poll()
    assert caught.value.reason == reason
    assert not isinstance(caught.value, native.RegistrationExpired)


def test_running_client_keeps_a_partial_last_line_until_its_newline() -> None:
    registration = running_registration(CONFIRMED + REMOVED[:-4])
    # The complete lines confirm; the cut callback is not judged yet.
    assert registration.poll() is True
    registration.output.extend(REMOVED[-4:])
    with pytest.raises(native.DiscoveryFailure) as caught:
        registration.poll()
    assert caught.value.reason == "identity-mismatch"


def test_running_client_that_does_not_confirm_times_out_after_five_seconds() -> None:
    registration = running_registration(CONFIRMED[: CONFIRMED.index(b"22:03:17.900")])
    assert registration.poll() is False
    registration.started -= 5.1
    with pytest.raises(native.DiscoveryFailure) as caught:
        registration.poll()
    assert caught.value.reason == "timed-out"


# The line in which the client echoes the record is data, so words of a
# diagnostic in the record's own name or TXT fail nothing. Only the exact echo
# is: a diagnostic on the error stream can follow a stdout line that a full
# block cut, also the echo, and every line that is not the echo is searched.
WORDS = media_record(
    name="Error code display",
    txt=(
        b"note=Error",
        b"code -65563",
        b"No",
        b"Authorization",
        b"serial=A-65570",
        b"DNSServiceRegister",
        b"returned",
        b"Unknown",
        b"interface",
    ),
)
GLUED = media_record(name="Error code display", txt=(b"note=Error", b"code -65563"))


def echoed(record: Record) -> bytes:
    """A clean registration output of ``record``, with the echo the client prints."""
    service = f"Got a reply for service {record.name}.{record.service_type}.local.".encode()
    return b"".join(
        [
            b"Using interface 7\n",
            native._echo_line(record) + b"\n",
            CONFIRMED[CONFIRMED.index(b"DATE: ") : CONFIRMED.index(b"22:03:18.100")],
            LATER + service + ACTIVE,
        ]
    )


def test_echo_line_is_the_line_the_client_prints_for_the_record() -> None:
    # RegisterService (1501-1503, 1524-1527) and ShowTXTRecord (781-813): a space
    # before each non-empty entry, a backslash before a shell character and
    # before NUL, four for a backslash, \\xHH for another byte below the space.
    record = media_record(txt=(b"a b", b"", b"c\\d", b"e\x1f\x7f\xff", b"&$\0"))
    head = b"Registering Service Example speaker._airplay._tcp.local. host speaker.local. port 7000"
    assert native._echo_line(record) == (
        head + rb" TXT a\ b c\\\\d e\\x1F" + b"\x7f\xff" + rb" \&\$\\\x00"
    )
    assert native._echo_line(media_record(txt=(b"",))) == head + b" TXT"
    assert native._echo_line(media_record(txt=())) == head


def test_words_of_the_record_in_its_exact_echo_are_data() -> None:
    running = running_registration(echoed(WORDS))
    running.record = WORDS
    assert running.poll() is True
    ended = ended_registration(0, 30.0, echoed(WORDS))
    ended.record = WORDS
    with pytest.raises(native.RegistrationExpired):
        ended.poll()


@pytest.mark.parametrize(
    ("diagnostic", "reason"),
    [
        (b"Error code -65563", "malformed"),
        (b"DNSServiceRegister failed -65570", "local-network-denied"),
    ],
)
def test_diagnostic_inside_a_cut_echo_is_read_at_every_byte(diagnostic: bytes, reason: str) -> None:
    clean = echoed(GLUED)
    start = clean.index(native._echo_line(GLUED))
    for cut in range(start, start + len(native._echo_line(GLUED)) + 1):
        output = clean[:cut] + diagnostic + b"\n" + clean[cut:]
        running = running_registration(output)
        running.record = GLUED
        with pytest.raises(native.DiscoveryFailure) as caught:
            running.poll()
        assert (cut, caught.value.reason) == (cut, reason)
        ended = ended_registration(0, 30.0, output)
        ended.record = GLUED
        with pytest.raises(native.DiscoveryFailure) as caught:
            ended.poll()
        assert (cut, isinstance(caught.value, native.RegistrationExpired)) == (cut, False)


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


class Scripted(native.Registration):
    """Registration.poll as shipped; the test writes the client's output and its end."""

    made: ClassVar[list[Scripted]] = []

    def __init__(self, record: Record, index: int, lifetime_seconds: int = 120) -> None:
        self.record = record
        self.index = index
        self.lifetime_seconds = lifetime_seconds
        self.closed = False
        self.active = False
        self.started = self.spawned = time.monotonic()
        self.process = Running()  # type: ignore[assignment]
        self.selector = Idle()  # type: ignore[assignment]
        self.service = f"{record.name}.{record.service_type}.local."
        self.output = bytearray(
            (
                f"Using interface {index}\n"
                f"Registering Service {self.service} host {record.hostname} port {record.port}\n"
                "DATE: ---Mon 05 Oct 2026---\n"
                "22:03:17.123  ...STARTING...\n"
                f"22:03:17.900  Got a reply for record {record.hostname}"
                ": Name now registered and active\n"
                f"22:03:18.100  Got a reply for service {self.service}"
                ": Name now registered and active\n"
            ).encode()
        )
        Scripted.made.append(self)

    def end_on_timer(self, final: str = "") -> None:
        """Print ``final`` after the last poll, then exit with status 0 at the lifetime."""
        self.output.extend(final.encode())
        self.process = Ended(0)  # type: ignore[assignment]
        self.spawned = time.monotonic() - self.lifetime_seconds

    def close(self) -> None:
        self.closed = True


def scripted_policy(
    config: Config, settings: owner.BonjourSettings
) -> tuple[owner.Publisher, Callable[[], tuple[str, str, int]]]:
    """The import policy with two leased records, published through Scripted clients."""
    current = snapshot(config)
    store = Store(settings.state_dir)
    requests, candidates = lease(config, settings, current, two_records(), 1000)
    store.write("requests.json", requests)
    store.write("candidates.json", candidates)
    proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
    Scripted.made = []
    manager = owner.Publisher(Scripted)

    def tick() -> tuple[str, str, int]:
        fact = owner.publisher_tick(config, settings, store, manager, proof, 0, 1000).profiles[
            "media-import"
        ]
        return fact.state, fact.reason, fact.data["record_count"]

    return manager, tick


def test_removal_in_the_final_output_of_a_client_ended_at_its_lifetime_withdraws_the_policy(
    config: Config, settings: owner.BonjourSettings
) -> None:
    manager, tick = scripted_policy(config, settings)
    assert tick() == ("present", "verified", 2)
    first, second = Scripted.made
    assert first.active and second.active
    # The daemon reports the name removed after the last poll that saw the client
    # running; then the client's own timer ends it with status 0.
    first.end_on_timer(
        f"22:03:47.250  Got a reply for service {first.service}: Name registration removed\n"
    )
    assert tick() == ("unknown", "unavailable", 0)
    # Every registration of the policy is closed and nothing was started again.
    assert first.closed and second.closed and not manager.children
    assert Scripted.made == [first, second]


def test_clean_final_output_of_a_client_ended_at_its_lifetime_renews_that_record_alone(
    config: Config, settings: owner.BonjourSettings
) -> None:
    manager, tick = scripted_policy(config, settings)
    assert tick() == ("present", "verified", 2)
    first, second = Scripted.made
    # The same end with nothing else printed stays the expiry of one record.
    first.end_on_timer()
    assert tick() == ("present", "verified", 1)
    assert first.closed and not second.closed and len(Scripted.made) == 3
    assert Scripted.made[2].record == first.record and second in manager.children.values()
    assert tick() == ("present", "verified", 2)


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

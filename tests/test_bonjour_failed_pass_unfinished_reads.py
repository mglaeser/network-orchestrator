"""What counts as a read that did not complete is a closed list of exact forms.

A failed scan can count as a miss (`failed_pass`, see the neighbouring module)
only where what one client left is exactly a form that the vendor's client
gives for a daemon that is not running, or where the bounded runner stopped the
client at its own time limit before it had shown a reply. Everything else,
every other error code among it, withdraws at once, and so does a scan whose
own time is used up, wherever that is noticed.

The forms are read from Apple's client, `Clients/dns-sd.c` at the revision the
Bonjour guide cites (`mDNSResponder-2881.120.11`); the line numbers in the
comments are that file's. Names, hosts and addresses are synthetic, and nothing
here is a capture from a host. Four cases run a short Python child under the
real bounded runner; no native tool is run.
"""

from __future__ import annotations

import itertools
import selectors
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch import process
from netorch.model import Config
from netorch.process import ProcessTimeout, Result
from tests.test_bonjour_failed_pass_as_miss import (
    CAMERA,
    START_LINE,
    Budget,
    Link,
    call_failed,
    call_failed_with,
    counting,
    daemon_stopped,
    denied_before_the_loop,
    stopped,
    stopped_with,
)
from tests.test_bonjour_miss_tolerance import EXPORT, IMPORT, MONOTONIC, leased
from tests.test_bonjour_owner import config, settings
from tests.test_bonjour_record_isolation import (
    AIRPLAY,
    HAP,
    KITCHEN,
    LAN_INDEX,
    RAOP,
    STAMP,
    STUDY,
    Client,
)

__all__ = ["config", "settings"]

# The operations a scan runs, with the arguments scan gives them, what main
# prints for each before it makes its call (2135, 2157, 2181; nothing more for
# -G and -Q) and how it names that call (2158, 2183, 2314, 2225).
INTERFACE_LINE = b"Using interface 7\n"
COMMANDS: dict[str, tuple[list[str], bytes, bytes]] = {
    "browse": (
        ["-B", AIRPLAY, "local."],
        INTERFACE_LINE + b"Browsing for _airplay._tcp.local.\n",
        b"DNSServiceBrowse",
    ),
    "resolve": (
        ["-L", KITCHEN.name, AIRPLAY, "local."],
        INTERFACE_LINE + b"Lookup Kitchen speaker._airplay._tcp.local.\n",
        b"DNSServiceResolve",
    ),
    "address": (["-G", "v4", KITCHEN.host], INTERFACE_LINE, b"DNSServiceGetAddrInfo"),
    "query": (
        ["-Q", KITCHEN.fullname, "TXT", "IN"],
        INTERFACE_LINE,
        b"DNSServiceQueryRecord",
    ),
}
# main (2392-2393): "%s failed %ld%s\n", with these words for kDNSServiceErr_ServiceNotRunning.
NOT_RUNNING = b" failed -65563 (Service Not Running)\n"
# EXIT_IF_LIBDISPATCH_FATAL_ERROR (246): fprintf(stderr, "Error code %d\n", (E)); exit(0);
STOPPED = b"Error code -65563\n"
DATE_LINE, STARTING_LINE = START_LINE.splitlines(keepends=True)
# browse_reply (763): the heading that comes with the first reply.
HEADING = (
    f"Timestamp     A/R    Flags  if {'Domain':<20} {'Service Type':<20} Instance Name\n"
).encode()
REPLY = (STAMP + f"Add {2:8X} {7:3d} {'local.':<20} {'_airplay._tcp.':<20} Kitchen\n").encode()


def judged(command: str, status: int | None, stdout: bytes, stderr: bytes, index: int = 7) -> bool:
    return native.unfinished_read(COMMANDS[command][0], index, status, stdout, stderr)


# The closed list


@pytest.mark.parametrize("command", COMMANDS)
def test_forms_of_a_read_that_did_not_complete(command: str) -> None:
    _args, head, call = COMMANDS[command]
    # The daemon is not running: the call fails and main returns -1 (2390-2394).
    assert judged(command, 255, head, call + NOT_RUNNING) is True
    # The daemon stopped while the client waited (246): status 0, after the start line.
    assert judged(command, 0, head + START_LINE, STOPPED) is True
    # Stopped by the runner before a reply: nothing was flushed, or these banners.
    assert judged(command, None, b"", b"") is True
    assert judged(command, None, head, b"") is True
    assert judged(command, None, head + START_LINE, b"") is True


# One change to a form each: (command, status, standard output, error stream).
BROWSE, RESOLVE = COMMANDS["browse"][1], COMMANDS["resolve"][1]
FAILED = b"DNSServiceBrowse" + NOT_RUNNING
NOT_ON_THE_LIST: dict[str, tuple[str, int | None, bytes, bytes]] = {
    # Another status with the output of a failed call, or of a daemon that stopped.
    "failed-call-with-status-0": ("browse", 0, BROWSE, FAILED),
    "failed-call-with-status-1": ("browse", 1, BROWSE, FAILED),
    "failed-call-with-status-254": ("browse", 254, BROWSE, FAILED),
    "failed-call-ended-by-a-signal": ("browse", -9, BROWSE, FAILED),
    "failed-call-of-a-stopped-client": ("browse", None, BROWSE, FAILED),
    "stopped-daemon-with-status-255": ("browse", 255, BROWSE + START_LINE, STOPPED),
    "stopped-daemon-with-status-1": ("browse", 1, BROWSE + START_LINE, STOPPED),
    "stopped-daemon-ended-by-a-signal": ("browse", -15, BROWSE + START_LINE, STOPPED),
    "stopped-daemon-of-a-stopped-client": ("browse", None, BROWSE + START_LINE, STOPPED),
    # Another error code: kDNSServiceErr_NoAuth, _PolicyDenied, _NotPermitted,
    # _BadInterfaceIndex, _Refused, _Firewall, _BadParam, _Unknown, _Timeout,
    # _DefunctConnection (dns_sd.h at the same revision).
    **{
        f"failed-call-with-code{code}": (
            "browse",
            255,
            BROWSE,
            f"DNSServiceBrowse failed {code}\n".encode(),
        )
        for code in (
            -65555,
            -65570,
            -65571,
            -65552,
            -65553,
            -65550,
            -65540,
            -65537,
            -65568,
            -65569,
            -65563,
            -6556,
            -655630,
        )
    },
    "failed-call-with-the-words-of-another-code": (
        "browse",
        255,
        BROWSE,
        b"DNSServiceBrowse failed -65555 (Service Not Running)\n",
    ),
    "stopped-daemon-with-another-code": ("browse", 0, BROWSE + START_LINE, b"Error code -65570\n"),
    "stopped-daemon-with-a-longer-code": (
        "browse",
        0,
        BROWSE + START_LINE,
        b"Error code -655630\n",
    ),
    # Anything else on the error stream, before, after or in place of the one line.
    "failed-call-under-the-name-of-another-call": (
        "browse",
        255,
        BROWSE,
        b"DNSServiceResolve" + NOT_RUNNING,
    ),
    "failed-call-under-the-name-of-the-browse": (
        "resolve",
        255,
        RESOLVE,
        b"DNSServiceBrowse" + NOT_RUNNING,
    ),
    "failed-call-under-no-name": ("browse", 255, BROWSE, NOT_RUNNING),
    "failed-call-and-a-line-before": ("browse", 255, BROWSE, b"warning\n" + FAILED),
    "failed-call-and-a-line-after": ("browse", 255, BROWSE, FAILED + b"warning\n"),
    "failed-call-twice": ("browse", 255, BROWSE, FAILED + FAILED),
    "failed-call-without-its-line-end": ("browse", 255, BROWSE, FAILED[:-1]),
    "failed-call-with-a-carriage-return": ("browse", 255, BROWSE, FAILED[:-1] + b"\r\n"),
    "failed-call-with-a-space-before": ("browse", 255, BROWSE, b" " + FAILED),
    "failed-call-in-other-letters": ("browse", 255, BROWSE, FAILED.lower()),
    "failed-call-with-an-empty-error-stream": ("browse", 255, BROWSE, b""),
    "stopped-daemon-and-a-line-after": ("browse", 0, BROWSE + START_LINE, STOPPED + b"x\n"),
    "stopped-daemon-and-a-line-before": ("browse", 0, BROWSE + START_LINE, b"\n" + STOPPED),
    "stopped-daemon-in-other-letters": ("browse", 0, BROWSE + START_LINE, b"error code -65563\n"),
    "stopped-daemon-without-its-line-end": ("browse", 0, BROWSE + START_LINE, STOPPED[:-1]),
    "stopped-daemon-with-an-empty-error-stream": ("browse", 0, BROWSE + START_LINE, b""),
    "unknown-interface-on-the-error-stream": (
        "browse",
        0,
        BROWSE,
        b"Unknown interface example0\n",
    ),
    "failed-call-and-unknown-interface": (
        "browse",
        255,
        BROWSE,
        b"Unknown interface example0\n" + FAILED,
    ),
    # The diagnostic on standard output is no line of the error stream.
    "failed-call-on-standard-output": ("browse", 255, BROWSE + FAILED, b""),
    "stopped-daemon-on-standard-output": ("browse", 0, BROWSE + START_LINE + STOPPED, b""),
    # Standard output that is not exactly the banners of that command at that point.
    "failed-call-without-any-output": ("browse", 255, b"", FAILED),
    "failed-call-without-the-interface-line": (
        "browse",
        255,
        BROWSE.removeprefix(INTERFACE_LINE),
        FAILED,
    ),
    "failed-call-for-another-interface": (
        "browse",
        255,
        BROWSE.replace(b"interface 7", b"interface 8"),
        FAILED,
    ),
    "failed-call-for-an-interface-that-begins-alike": (
        "browse",
        255,
        BROWSE.replace(b"interface 7", b"interface 70"),
        FAILED,
    ),
    "failed-call-with-the-interface-line-twice": ("browse", 255, INTERFACE_LINE + BROWSE, FAILED),
    "failed-call-with-the-interface-line-last": (
        "browse",
        255,
        BROWSE.removeprefix(INTERFACE_LINE) + INTERFACE_LINE,
        FAILED,
    ),
    "failed-call-naming-another-interface-too": (
        "browse",
        255,
        BROWSE + b"Using interface 8\n",
        FAILED,
    ),
    "failed-call-with-an-indented-interface-line": ("browse", 255, b" " + BROWSE, FAILED),
    "failed-call-without-the-line-of-its-operation": ("browse", 255, INTERFACE_LINE, FAILED),
    "failed-call-with-the-line-of-another-type": (
        "browse",
        255,
        BROWSE.replace(b"_airplay", b"_raop"),
        FAILED,
    ),
    "failed-call-with-the-line-of-another-operation": ("browse", 255, RESOLVE, FAILED),
    "failed-resolve-with-the-line-of-another-name": (
        "resolve",
        255,
        RESOLVE.replace(b"Kitchen", b"Study"),
        b"DNSServiceResolve" + NOT_RUNNING,
    ),
    "failed-address-call-with-a-line-of-an-operation": (
        "address",
        255,
        BROWSE,
        b"DNSServiceGetAddrInfo" + NOT_RUNNING,
    ),
    "failed-call-after-the-start-line": ("browse", 255, BROWSE + START_LINE, FAILED),
    "failed-call-with-any-other-line": ("browse", 255, BROWSE + b"No Such Record\n", FAILED),
    "failed-call-with-an-unknown-interface-line": (
        "browse",
        255,
        BROWSE + b"Unknown interface example0\n",
        FAILED,
    ),
    "failed-call-with-an-empty-line": ("browse", 255, BROWSE + b"\n", FAILED),
    "failed-call-with-an-unended-line": ("browse", 255, BROWSE[:-1], FAILED),
    "failed-call-with-carriage-returns": ("browse", 255, BROWSE.replace(b"\n", b"\r\n"), FAILED),
    "stopped-daemon-before-the-start-line": ("browse", 0, BROWSE, STOPPED),
    "stopped-daemon-without-the-date-line": ("browse", 0, BROWSE + STARTING_LINE, STOPPED),
    "stopped-daemon-without-the-start-line": ("browse", 0, BROWSE + DATE_LINE, STOPPED),
    "stopped-daemon-with-the-start-line-first": (
        "browse",
        0,
        BROWSE + STARTING_LINE + DATE_LINE,
        STOPPED,
    ),
    "stopped-daemon-with-two-start-lines": (
        "browse",
        0,
        BROWSE + START_LINE + STARTING_LINE,
        STOPPED,
    ),
    "stopped-daemon-with-two-date-lines": ("browse", 0, BROWSE + DATE_LINE + START_LINE, STOPPED),
    "stopped-daemon-after-a-heading": ("browse", 0, BROWSE + START_LINE + HEADING, STOPPED),
    "stopped-daemon-after-a-reply": ("browse", 0, BROWSE + START_LINE + HEADING + REPLY, STOPPED),
    "stopped-daemon-with-an-unended-start-line": ("browse", 0, (BROWSE + START_LINE)[:-1], STOPPED),
    "stopped-daemon-with-a-date-that-is-none": (
        "browse",
        0,
        BROWSE + b"DATE: ---today---\n" + STARTING_LINE,
        STOPPED,
    ),
    "stopped-daemon-with-a-time-that-is-none": (
        "browse",
        0,
        BROWSE + DATE_LINE + b"24:03:17.123  ...STARTING...\n",
        STOPPED,
    ),
    "stopped-daemon-for-another-interface": (
        "browse",
        0,
        (BROWSE + START_LINE).replace(b"interface 7", b"interface 8"),
        STOPPED,
    ),
    # The line of the operation is compared sign for sign.
    "stopped-daemon-with-a-type-that-looks-alike": (
        "browse",
        0,
        BROWSE.replace(b"_airplay._tcp", b"_airplay-_tcp") + START_LINE,
        STOPPED,
    ),
    "stopped-with-a-type-that-looks-alike": (
        "browse",
        None,
        BROWSE.replace(b"_airplay._tcp", b"_airplay-_tcp") + START_LINE,
        b"",
    ),
    "stopped-daemon-without-the-line-of-its-operation": (
        "resolve",
        0,
        INTERFACE_LINE + START_LINE,
        STOPPED,
    ),
    "stopped-daemon-of-a-query-with-a-line-of-an-operation": (
        "query",
        0,
        BROWSE + START_LINE,
        STOPPED,
    ),
    # A stopped client that had written anything but its banners, or anything
    # at all on the error stream.
    "stopped-with-a-space-on-the-error-stream": ("browse", None, b"", b" "),
    "stopped-with-a-line-end-on-the-error-stream": ("browse", None, BROWSE, b"\n"),
    "stopped-after-a-denial": ("browse", None, BROWSE, b"DNSServiceBrowse failed -65570\n"),
    "stopped-after-its-daemon-stopped": ("browse", None, BROWSE + START_LINE, STOPPED),
    "stopped-naming-another-interface": ("browse", None, b"Using interface 8\n", b""),
    "stopped-with-the-interface-line-alone": ("browse", None, INTERFACE_LINE, b""),
    "stopped-without-the-interface-line": (
        "browse",
        None,
        BROWSE.removeprefix(INTERFACE_LINE),
        b"",
    ),
    "stopped-with-an-unended-line": ("address", None, INTERFACE_LINE[:-1], b""),
    "stopped-with-a-line-end-alone": ("address", None, b"\n", b""),
    "stopped-with-the-date-line-alone": ("browse", None, BROWSE + DATE_LINE, b""),
    "stopped-with-the-start-line-alone": ("browse", None, BROWSE + STARTING_LINE, b""),
    "stopped-after-a-heading": ("browse", None, BROWSE + START_LINE + HEADING, b""),
    "stopped-after-a-reply": ("browse", None, BROWSE + START_LINE + HEADING + REPLY, b""),
    "stopped-after-a-denial-in-place-of-a-row": (
        "browse",
        None,
        BROWSE + START_LINE + HEADING + (STAMP + "Error code -65570\n").encode(),
        b"",
    ),
    "stopped-after-any-other-line": ("address", None, INTERFACE_LINE + b"x\n", b""),
    "stopped-with-the-line-of-another-operation": ("address", None, BROWSE, b""),
}


@pytest.mark.parametrize(
    ("command", "status", "stdout", "stderr"), NOT_ON_THE_LIST.values(), ids=NOT_ON_THE_LIST
)
def test_nothing_else_is_on_the_list(
    command: str, status: int | None, stdout: bytes, stderr: bytes
) -> None:
    assert judged(command, status, stdout, stderr) is False


def test_interface_that_was_not_verified_is_never_on_the_list() -> None:
    for index in (0, -1, True, 7.0, "7", None):
        head = f"Using interface {index}\n".encode()
        for status, stdout, stderr in (
            (255, head, b"DNSServiceGetAddrInfo" + NOT_RUNNING),
            (0, head + START_LINE, STOPPED),
            (None, b"", b""),
        ):
            arguments: Any = (COMMANDS["address"][0], index, status, stdout, stderr)
            assert native.unfinished_read(*arguments) is False
    # The same three with the verified index.
    assert judged("address", 255, INTERFACE_LINE, b"DNSServiceGetAddrInfo" + NOT_RUNNING)
    assert judged("address", 0, INTERFACE_LINE + START_LINE, STOPPED)
    assert judged("address", None, b"", b"")


def test_name_is_compared_sign_for_sign_whatever_signs_it_has() -> None:
    # A browsed name is passed on as it is, and main prints it as it got it (2181).
    name = "Kitchen (1) [a+b]*? ^$ {2}| \\d"
    arguments = ["-L", name, AIRPLAY, "local."]
    head = INTERFACE_LINE + f"Lookup {name}._airplay._tcp.local.\n".encode()
    for status, stdout, stderr in (
        (255, head, b"DNSServiceResolve" + NOT_RUNNING),
        (0, head + START_LINE, STOPPED),
        (None, head, b""),
        (None, head + START_LINE, b""),
    ):
        assert native.unfinished_read(arguments, 7, status, stdout, stderr) is True
        other = stdout.replace(b"[a+b]", b"[aab]")
        assert native.unfinished_read(arguments, 7, status, other, stderr) is False


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["-B"],
        ["-B", AIRPLAY],
        ["-B", AIRPLAY, "local.", "more"],
        ["-L", KITCHEN.name, AIRPLAY],
        ["-G", "v4"],
        ["-Q", KITCHEN.fullname, "TXT"],
        ["-R", "Name", AIRPLAY, "local."],
        ["-P", "v4", KITCHEN.host],
        ["B", AIRPLAY, "local."],
    ],
)
def test_command_that_a_scan_does_not_run_is_never_on_the_list(arguments: list[str]) -> None:
    assert native.unfinished_read(arguments, 7, None, b"", b"") is False
    assert native.unfinished_read(arguments, 7, 0, INTERFACE_LINE + START_LINE, STOPPED) is False


# The authorization code, with and without the setting


def without_authorization(operation: str, subject: str) -> tuple[str, str, Any]:
    # kDNSServiceErr_NoAuth: main reports the failed call like any other (2390-2394).
    return operation, subject, call_failed_with(b"-65555")


@pytest.mark.parametrize(
    ("operation", "subject"),
    [("-B", AIRPLAY), ("-L", STUDY.name), ("-G", STUDY.host), ("-Q", STUDY.fullname)],
)
@pytest.mark.parametrize("counted", [True, False], ids=["with-the-setting", "without-it"])
def test_call_that_fails_without_authorization_withdraws_at_once(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    subject: str,
    counted: bool,
) -> None:
    own = counting(settings) if counted else replace(settings, miss_tolerance=3)
    link = Link(monkeypatch, leased(config), own)
    link.lan.devices, link.guests.devices = (KITCHEN, STUDY), (CAMERA,)
    assert len(link.run()[IMPORT]["records"]) == 2
    # The reader marks nothing ...
    client = Client(KITCHEN, STUDY).fail(*without_authorization(operation, subject))
    with pytest.raises(native.DiscoveryFailure) as caught:
        native.scan("example0", LAN_INDEX, AIRPLAY, 8, 2, 1000.0, client)
    assert (caught.value.reason, caught.value.unfinished) == ("malformed", False)
    assert client.asked[-1] == (operation, subject)
    # ... and the pass withdraws and forgets, whatever the setting says.
    link.lan.fail(*without_authorization(operation, subject))
    failed = link.run()
    assert (failed[IMPORT]["records"], failed[IMPORT]["reason"]) == ([], "malformed")
    assert "tolerated_failure" not in failed[IMPORT] and link.counts() is None
    assert len(failed[EXPORT]["records"]) == 1 and "reason" not in failed[EXPORT]
    link.lan.failing.clear()
    link.lan.devices = ()
    missed = link.run()[IMPORT]
    assert missed["records"] == [] and "reason" not in missed
    # The same call failing for a daemon that is not running is a miss with the setting.
    link.lan.devices = (KITCHEN, STUDY)
    link.run()
    link.lan.fail(operation, subject, call_failed)
    again = link.run()[IMPORT]
    assert (len(again["records"]), again.get("tolerated_failure")) == (
        (2, "malformed") if counted else (0, None)
    )


# A scan whose own time is used up


def scanned(runner: Any, seconds: int, budget: float) -> tuple[Any, ...]:
    return native.scan("example0", LAN_INDEX, AIRPLAY, 8, seconds, 1000.0, runner, budget)


@pytest.mark.parametrize("seconds", [1, 2, 5])
@pytest.mark.parametrize(
    "failure",
    [stopped, call_failed, daemon_stopped],
    ids=["stopped", "call-failed", "daemon-stopped"],
)
def test_command_has_its_own_time_limit_only_with_room_in_the_scan(
    monkeypatch: pytest.MonkeyPatch, seconds: int, failure: Any
) -> None:
    monkeypatch.setattr(native, "time", Budget())
    own = seconds + 1.0
    limits: list[float] = []
    client = Client(KITCHEN).fail("-B", AIRPLAY, failure)

    def runner(argv: list[str], given: float) -> Result:
        limits.append(given)
        return client(argv, given)

    # (the scan's time when the command starts, the limit it gets, whether its failure is marked)
    for budget, limit, marked in (
        (45.0, own, True),
        # Exactly the command's limit and one second more.
        (own + 1.0, own, True),
        (own + 0.75, own, False),
        (own, own, False),
        # Less than the command's own limit: it gets what is left.
        (own - 0.25, own - 0.25, False),
        (0.25, 0.25, False),
    ):
        limits.clear()
        with pytest.raises(native.DiscoveryFailure) as caught:
            scanned(runner, seconds, budget)
        assert (caught.value.reason, caught.value.unfinished) == ("malformed", marked), budget
        assert limits == [limit]


def test_room_is_judged_for_each_command_of_a_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    budget = Budget()
    monkeypatch.setattr(native, "time", budget)
    used = [0.0]

    def answered(answer: Result) -> Result:
        budget.now += used[0]
        return answer

    # The browse takes this much of the 45 seconds; the resolve after it is stopped.
    for used[0], marked in ((41.0, True), (41.25, False)):
        client = Client(KITCHEN).fail("-B", AIRPLAY, answered).fail("-L", KITCHEN.name, stopped)
        with pytest.raises(native.DiscoveryFailure) as caught:
            native.scan("example0", LAN_INDEX, AIRPLAY, 8, 2, 1000.0, client)
        assert client.asked == [("-B", AIRPLAY), ("-L", KITCHEN.name)]
        assert (caught.value.reason, caught.value.unfinished) == ("malformed", marked)


class Impatient:
    """The scanner's clock in a pass whose every wait for a scan is over at once."""

    def __init__(self, link: Link) -> None:
        self.link = link
        self.read = itertools.count()

    def time(self) -> float:
        return self.link.clock.now

    def monotonic(self) -> float:
        # Each reading is later than the scanner waits for a scan (45 seconds).
        return MONOTONIC + 100.0 * next(self.read)

    def sleep(self, seconds: float) -> None:
        self.link.clock.sleep(seconds)


def slowly(answer: Result) -> Result:
    """A client that answers a moment of real time later."""
    time.sleep(0.3)
    return answer


class Outlasting:
    """A client that answers only once the scanner has stopped waiting for its scan.

    The scanner waits for the scans of a policy inside their pool. The client
    is released when the scanner leaves that pool, so however the threads are
    scheduled, its scan has not ended while the scanner still waited.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.left = threading.Event()
        outlasting = self

        class Pool(ThreadPoolExecutor):
            def __init__(self, *arguments: Any, **keywords: Any) -> None:
                self.left = outlasting.left = threading.Event()
                super().__init__(*arguments, **keywords)

            def __exit__(self, *details: Any) -> Any:
                self.left.set()
                return super().__exit__(*details)

        monkeypatch.setattr(owner, "ThreadPoolExecutor", Pool)

    def __call__(self, answer: Result) -> Result:
        # A scanner that never stopped waiting gets its answer after five
        # seconds, and the scan completes: the pass then reads as it must not.
        self.left.wait(5)
        return answer


# How one scan uses up its time, by what notices it, and the reason the pass then carries.
USED_UP = {
    "no-time-left-for-the-next-command": "timed-out",
    "client-stopped-with-what-was-left": "malformed",
    "scanner-no-longer-waiting": "malformed",
}


@pytest.mark.parametrize(
    ("identifier", "kind", "first"),
    [(EXPORT, HAP, "Camera"), (IMPORT, AIRPLAY, KITCHEN.name), (IMPORT, RAOP, KITCHEN.name)],
    ids=["one-type", "four-types-the-first", "four-types-another"],
)
@pytest.mark.parametrize("noticed", USED_UP)
def test_scan_that_uses_up_its_time_is_no_miss_whatever_notices_it(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    identifier: str,
    kind: str,
    first: str,
    noticed: str,
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    related = replace(KITCHEN, kind=RAOP, port=5000)
    link.lan.devices, link.guests.devices = (KITCHEN, related), (CAMERA,)
    seen = link.run()
    assert len(seen[identifier]["records"]) == (1 if identifier == EXPORT else 2)
    client = link.guests if identifier == EXPORT else link.lan

    def almost(answer: Result) -> Result:
        # The browse leaves the scan a quarter of a second less than a command
        # with its own limit needs (scan_seconds + 1 and one second more).
        link.budget.now += 45 - 3.75
        return answer

    if noticed == "no-time-left-for-the-next-command":
        client.fail("-B", kind, link.out_of_time)
    elif noticed == "client-stopped-with-what-was-left":
        client.fail("-B", kind, almost).fail("-L", first, stopped)
    else:
        client.fail("-B", kind, Outlasting(monkeypatch))
        monkeypatch.setattr(owner, "time", Impatient(link))
    failed = link.run()[identifier]
    assert (failed["records"], failed["reason"]) == ([], USED_UP[noticed])
    assert "tolerated_failure" not in failed and link.counts(identifier) is None
    # The same client stopped at its own limit, with room in the scan, is a miss.
    monkeypatch.setattr(owner, "time", link.clock)
    client.failing.clear()
    link.run()
    client.fail("-L", first, stopped)
    carried = link.run()[identifier]
    assert carried["tolerated_failure"] == "malformed" and "reason" not in carried
    assert len(carried["records"]) == len(seen[identifier]["records"])


def test_scan_that_the_scanner_stops_waiting_for_un_marks_a_pass_that_would_count(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN, STUDY)
    seen = link.run()[IMPORT]
    # The first type's browse is stopped at its own limit, and another type's
    # client answers slowly. Within the scanner's wait the pass counts as a miss.
    link.lan.fail("-B", AIRPLAY, stopped).fail("-B", RAOP, slowly)
    carried = link.run()[IMPORT]
    assert carried["records"] == seen["records"] and carried["tolerated_failure"] == "malformed"
    assert link.lan.asked.count(("-B", RAOP)) == 2
    # Once the scanner's wait for a scan is over, the slow scan has used up its
    # time: the pass is no miss, although the scan then completes.
    link.lan.fail("-B", RAOP, Outlasting(monkeypatch))
    monkeypatch.setattr(owner, "time", Impatient(link))
    failed = link.run()[IMPORT]
    assert (failed["records"], failed["reason"]) == ([], "malformed")
    assert "tolerated_failure" not in failed and link.counts() is None
    assert link.lan.asked.count(("-B", RAOP)) == 3


def test_scan_that_ends_later_in_the_same_pass_is_waited_for_and_judged(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied_slowly(answer: Result) -> Result:
        return denied_before_the_loop(slowly(answer))

    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN, STUDY)
    assert len(link.run()[IMPORT]["records"]) == 2
    # The first type's browse is stopped at once; a later type's client is still
    # running then and is denied a moment afterwards.
    link.lan.fail("-B", AIRPLAY, stopped).fail("-B", RAOP, denied_slowly)
    failed = link.run()[IMPORT]
    assert link.lan.asked.count(("-B", RAOP)) == 2
    assert (failed["records"], failed["reason"]) == ([], "malformed")
    assert "tolerated_failure" not in failed and link.counts() is None


# What is not the runner's time limit


@pytest.mark.parametrize(
    "raised",
    [TimeoutError("wait"), TimeoutError(), OSError("spawn"), RuntimeError("limit")],
    ids=["builtin-timeout", "builtin-timeout-bare", "os-error", "runtime-error"],
)
def test_only_the_runner_own_time_limit_becomes_the_reader_failure(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    raised: Exception,
) -> None:
    def failing(_answer: Result) -> Result:
        raise raised

    client = Client(KITCHEN).fail("-B", AIRPLAY, failing)
    with pytest.raises(type(raised)) as caught:
        native.scan("example0", LAN_INDEX, AIRPLAY, 8, 2, 1000.0, client)
    assert caught.value is raised and not owner.counts_as_miss(raised)
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN,)
    link.run()
    failed = link.failed(failing)[IMPORT]
    assert (failed["records"], failed["reason"]) == ([], "malformed")
    assert "tolerated_failure" not in failed and link.counts() is None


def test_time_limit_carries_nothing_unless_its_runner_says_so() -> None:
    bare = ProcessTimeout("command did not complete within its deadline")
    assert (bare.stdout, bare.stderr, bare.args) == (None, None, (str(bare),))
    assert (ProcessTimeout().stdout, ProcessTimeout().stderr, ProcessTimeout().args) == (
        None,
        None,
        (),
    )
    told = stopped_with(b"shown", b"reported")
    assert (told.stdout, told.stderr) == (b"shown", b"reported")  # type: ignore[attr-defined]
    # The message never holds what was captured.
    assert str(told) == str(bare) and told.args == bare.args
    assert "shown" not in repr(told) and "reported" not in repr(told)
    with pytest.raises(TypeError):
        ProcessTimeout("limit", output=b"shown")  # type: ignore[call-arg]
    # One capture alone is no account of what the client had written.
    halves = [ProcessTimeout("limit", stdout=b""), ProcessTimeout("limit", stderr=b"")]

    def failing(_answer: Result) -> Result:
        raise halves[0]

    while halves:
        with pytest.raises(native.DiscoveryFailure) as caught:
            native.scan(
                "example0",
                LAN_INDEX,
                AIRPLAY,
                8,
                2,
                1000.0,
                Client(KITCHEN).fail("-B", AIRPLAY, failing),
            )
        assert (caught.value.reason, caught.value.unfinished) == ("malformed", False)
        assert caught.value.__cause__ is halves.pop(0)


# The bounded runner says what a stopped command had written

CHILD = """
import sys, time
sys.stdout.write(sys.argv[1]); sys.stdout.flush()
sys.stderr.write(sys.argv[2]); sys.stderr.flush()
time.sleep(30)
"""


def child(stdout: str = "", stderr: str = "") -> list[str]:
    """A command that writes this at once and then does not end."""
    return [sys.executable, "-S", "-c", CHILD, stdout, stderr]


def test_runner_time_limit_carries_what_the_command_had_written() -> None:
    with pytest.raises(ProcessTimeout) as caught:
        process.run(child("Using interface 8\n", "DNSServiceBrowse failed -65570\n"), timeout=1.0)
    assert caught.value.stdout == b"Using interface 8\n"
    assert caught.value.stderr == b"DNSServiceBrowse failed -65570\n"
    # The message is the one of before and holds nothing of it.
    assert str(caught.value) == "command did not complete within its deadline"
    assert caught.value.args == ("command did not complete within its deadline",)


class Blind(selectors.DefaultSelector):
    """A selector that never reports the pipes readable before the time limit."""

    def select(self, timeout: float | None = None) -> list[Any]:
        time.sleep(timeout or 0)
        return []


def test_runner_reads_what_is_left_in_the_pipes_of_a_stopped_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Nothing was read while the command ran: all of it is read after the stop.
    monkeypatch.setattr(process.selectors, "DefaultSelector", Blind)
    with pytest.raises(ProcessTimeout) as caught:
        process.run(child("first\nsecond\n", "third\n"), timeout=1.0)
    assert (caught.value.stdout, caught.value.stderr) == (b"first\nsecond\n", b"third\n")
    # Never more than the output bound, which both streams share.
    with pytest.raises(ProcessTimeout) as caught:
        process.run(child("o" * 600, "e" * 3000), timeout=1.0, max_output=1000)
    assert (caught.value.stdout, caught.value.stderr) == (b"o" * 600, b"e" * 400)


@pytest.mark.parametrize(
    ("stdout", "stderr", "marked"),
    [
        # The client's own buffer holds its banners until a reply or its exit.
        ("", "", True),
        # A client that printed a denial and then did not end.
        ("Using interface 7\n", "DNSServiceBrowse failed -65570\n", False),
    ],
    ids=["nothing-written", "denial-written"],
)
def test_client_stopped_by_the_real_runner_is_judged_by_what_it_had_written(
    stdout: str, stderr: str, marked: bool
) -> None:
    asked: list[tuple[list[str], float]] = []

    def runner(argv: list[str], limit: float) -> Result:
        asked.append((argv, limit))
        return process.run(child(stdout, stderr), timeout=limit, max_output=native.MAX_OUTPUT)

    began = time.monotonic()
    with pytest.raises(native.DiscoveryFailure) as caught:
        native.scan("example0", LAN_INDEX, AIRPLAY, 8, 1, 1000.0, runner)
    assert asked == [([native.DNS_SD, "-t", "1", "-i", "example0", "-B", AIRPLAY, "local."], 2.0)]
    assert 2.0 <= time.monotonic() - began < 20
    assert isinstance(caught.value.__cause__, ProcessTimeout)
    assert caught.value.__cause__.stdout == stdout.encode()
    assert caught.value.__cause__.stderr == stderr.encode()
    assert (caught.value.reason, caught.value.unfinished) == ("malformed", marked)
    assert owner.counts_as_miss(caught.value) is marked

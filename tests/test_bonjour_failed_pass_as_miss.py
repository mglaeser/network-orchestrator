"""A scanner pass whose read did not complete can count as a miss.

The owner setting `failed_pass` has one value, `"miss"`, and is absent unless
given. Without it a failed pass withdraws its policy at once, as before: the
values in ``BEFORE`` are fingerprints of what the tree before the setting wrote
for one fixed run of completed, missed and failed passes, so the test that only
uses them passes there too. With it, and for a policy that tolerates misses, a
pass whose read did not complete counts as one miss for every record the
scanner remembers for that policy.

The fake clients answer in the formats of Apple's client, `Clients/dns-sd.c` at
the revision the Bonjour guide cites (`mDNSResponder-2881.120.11`); the line
numbers in the comments are that file's. Names, hosts and addresses are
synthetic, both clocks are fakes, and nothing here is a capture from a host.
"""

from __future__ import annotations

import hashlib
import itertools
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.codec import canonical_bytes, strict_loads
from netorch.config import config_digest, to_dict
from netorch.discovery import Record
from netorch.discovery_plan import discovery_digest
from netorch.model import Config
from netorch.process import OutputLimit, ProcessTimeout, Result
from netorch.state import Intent, Observation, Snapshot
from netorch.storage import Store
from tests.test_bonjour_miss_tolerance import (
    EXPORT,
    IMPORT,
    LEASE,
    MONOTONIC,
    READY,
    START,
    STEP,
    leased,
    names,
    observed,
    regenerated,
    renumbered,
    settings_file,
)
from tests.test_bonjour_miss_tolerance import serve as serving
from tests.test_bonjour_miss_tolerance_per_policy import scanner_memory, second_owner, stating
from tests.test_bonjour_owner import FakeRegistration, config, policy, publisher, settings
from tests.test_bonjour_record_isolation import (
    AIRPLAY,
    GUEST,
    GUEST_INDEX,
    HAP,
    KITCHEN,
    LAN_INDEX,
    RAOP,
    STAMP,
    STUDY,
    Client,
    flooded,
    timed_out,
    with_interface_line_twice,
    with_line,
    without_interface_line,
)
from tests.test_bonjour_record_isolation import camera as guest_camera
from tests.test_bonjour_starting_banner import starting

__all__ = ["config", "settings"]

Failure = Callable[[Result], Result]
Raised = Callable[[], Exception]
CAMERA = guest_camera(GUEST)
# main (2396-2397), after the date line of the first timestamp (515).
START_LINE = starting().encode()


def stopped_with(stdout: bytes = b"", stderr: bytes = b"") -> Exception:
    """The bounded runner's time limit, with what the client had written by then."""
    return ProcessTimeout(
        "command did not complete within its deadline", stdout=stdout, stderr=stderr
    )


def stopped(_answer: Result) -> Result:
    # The client flushes only in a reply callback and at exit (browse_reply 772,
    # resolve_reply 843, qr_reply 1211, addrinfo_reply 1289): stopped before a
    # reply, it has shown nothing.
    raise stopped_with()


class Clock:
    """The scanner's and the publisher's time, set by the test; a sleep moves it."""

    def __init__(self, now: float) -> None:
        self.now = now

    def time(self) -> float:
        return self.now

    def monotonic(self) -> float:
        return MONOTONIC + self.now - START

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class Budget:
    """The reader's own clock, against which a scan counts its 45 seconds."""

    def __init__(self) -> None:
        self.now = 100.0

    def monotonic(self) -> float:
        return self.now


class Link:
    """One scanner and one publisher over two fake links, with the real reader.

    The test says which devices answer, which command of which client fails
    and how, or what a whole scan of one type raises or returns.
    """

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, config: Config, settings: owner.BonjourSettings
    ) -> None:
        self.config = config
        self.settings = settings
        # The memory as the scanner process itself builds it for these inputs.
        self.memory: Any = scanner_memory(monkeypatch, config, settings)
        self.clock = Clock(START - STEP)
        self.budget = Budget()
        self.report: Snapshot | None = None
        self.ready = READY
        self.lan = Client(index=LAN_INDEX)
        self.guests = Client(index=GUEST_INDEX)
        self.raising: dict[str, Raised] = {}
        self.reads: dict[str, tuple[Record, ...]] | None = None
        self.store = Store(settings.state_dir)
        self.manager = publisher()
        monkeypatch.setattr(owner, "time", self.clock)
        monkeypatch.setattr(native, "time", self.budget)
        monkeypatch.setattr(
            owner, "independent_snapshot", lambda *_args: (self.current(), Intent(), self.ready)
        )
        monkeypatch.setattr(
            owner, "_interfaces", lambda *_args: {"wired-lan": (LAN_INDEX, GUEST_INDEX)}
        )
        monkeypatch.setattr(owner, "scan", self.scan)

    def current(self) -> Snapshot:
        return self.report or observed(self.config, self.clock.now)

    def scan(
        self, interface: str, index: int, kind: str, *arguments: Any, **keywords: Any
    ) -> tuple[Record, ...]:
        if kind in self.raising:
            raise self.raising[kind]()
        if self.reads is not None:
            return tuple(
                replace(record, interface=interface, seen_at=arguments[2])
                for record in self.reads.get(kind, ())
            )
        runner = self.lan if index == LAN_INDEX else self.guests
        return native.scan(interface, index, kind, *arguments, runner, **keywords)

    def run(self, at: float | None = None, step: float = STEP) -> dict[str, Any]:
        """One scanner pass, `step` seconds after the last unless told when; its candidates."""
        self.clock.now = self.clock.now + step if at is None else at
        owner.scan_pass(self.config, self.settings, self.store, self.memory)
        policies: dict[str, Any] = self.store.read("candidates.json")["policies"]
        return policies

    def failed(self, failure: Failure = stopped, at: float | None = None) -> dict[str, Any]:
        """One pass in which the browse for the type that anchors an import fails."""
        self.lan.fail("-B", AIRPLAY, failure)
        try:
            return self.run(at)
        finally:
            self.lan.failing.clear()

    def out_of_time(self, answer: Result) -> Result:
        """A command after which the scan has used up its 45 seconds."""
        self.budget.now += 60
        return answer

    def requested(self) -> None:
        """Every policy of this owner is requested, as the coordinator's request leaves it."""
        current = self.current()
        self.store.write(
            "requests.json",
            {
                "schema_version": 1,
                "policies": {
                    item.id: {
                        "active": True,
                        "policy_digest": discovery_digest(self.config, item),
                        "service_generation": current.services[item.service].generation,
                        "network_generation": current.network_generation,
                        "requested_at": START,
                    }
                    for item in self.config.discovery
                    if item.owner == self.settings.owner
                },
            },
        )

    def tick(self) -> dict[str, Observation]:
        """One publisher tick at the clock's time, with fresh proof."""
        proof = (self.current(), Intent(), self.ready, {"wired-lan": (LAN_INDEX, GUEST_INDEX)})
        return dict(
            owner.publisher_tick(
                self.config, self.settings, self.store, self.manager, proof, 0, self.clock.now
            ).profiles
        )

    def counts(self, identifier: str = IMPORT) -> dict[str, int] | None:
        """The miss count of each record the scanner remembers for a policy; None for none."""
        if identifier not in self.memory.listed:
            return None
        return {
            f"{name} {kind}": misses
            for (name, kind), (_record, misses) in self.memory.listed[identifier][1].items()
        }

    def raw(self, name: str) -> bytes:
        return (self.settings.state_dir / name).read_bytes()


def counting(settings: owner.BonjourSettings, tolerance: int = 3) -> owner.BonjourSettings:
    """The owner's settings with a miss tolerance and a failed pass counted as a miss."""
    return replace(settings, miss_tolerance=tolerance, failed_pass="miss")


def unfinished(reason: str = "malformed") -> Exception:
    """What the reader raises for a read that did not complete."""
    return native.DiscoveryFailure(reason, unfinished=True)


def shown(observation: Observation) -> tuple[str, str, Any, Any]:
    return (
        observation.state,
        observation.reason,
        observation.data.get("record_count"),
        observation.data.get("tolerated_failure"),
    )


# What a client that does not complete its read leaves behind.


def before_the_loop(answer: Result) -> bytes:
    """What the client has printed when it makes the operation's call: main (2135, 2157)."""
    return answer.stdout[: answer.stdout.index(START_LINE)]


def in_the_loop(answer: Result) -> bytes:
    """The same and the start line: the client waits for its first reply."""
    return answer.stdout[: answer.stdout.index(START_LINE) + len(START_LINE)]


def called(answer: Result) -> bytes:
    """How main names the call of the operation that gave this answer (2158, 2183, 2225, 2314)."""
    banner = answer.stdout.split(b"\n")[1]
    if banner.startswith(b"Browsing for "):
        return b"DNSServiceBrowse"
    if banner.startswith(b"Lookup "):
        return b"DNSServiceResolve"
    return b"DNSServiceGetAddrInfo" if b" Hostname " in answer.stdout else b"DNSServiceQueryRecord"


def call_failed(answer: Result) -> Result:
    # main (2390-2394): fprintf(stderr, "%s failed %ld%s\n", callName, err, ...); return (-1);
    return Result(
        255, before_the_loop(answer), called(answer) + b" failed -65563 (Service Not Running)\n"
    )


def daemon_stopped(answer: Result) -> Result:
    # EXIT_IF_LIBDISPATCH_FATAL_ERROR (246), before a reply callback prints
    # anything (761, 824, 1111, 1249): fprintf(stderr, "Error code %d\n", (E)); exit(0);
    return Result(0, in_the_loop(answer), b"Error code -65563\n")


def stopped_in_the_loop(answer: Result) -> Result:
    # Where its output was flushed: the banners up to the start line, and no reply.
    raise stopped_with(in_the_loop(answer))


def stopped_in_its_call(answer: Result) -> Result:
    raise stopped_with(before_the_loop(answer))


# Reads that did not complete: the failure, and the reason the pass carries for it.
UNFINISHED: dict[str, tuple[Failure, str]] = {
    "stopped-at-the-time-limit": (stopped, "malformed"),
    "stopped-in-its-call-with-its-banners-flushed": (stopped_in_its_call, "malformed"),
    "stopped-in-the-loop-with-its-banners-flushed": (stopped_in_the_loop, "malformed"),
    "call-failed": (call_failed, "malformed"),
    "daemon-stopped-before-a-reply": (daemon_stopped, "malformed"),
}


def ended_with_a_status(answer: Result) -> Result:
    return Result(1, in_the_loop(answer), b"")


def diagnostic_before_the_loop(answer: Result) -> Result:
    return Result(0, before_the_loop(answer) + b"DNSServiceBrowse failed -65563\n", b"")


def call_failed_with(code: bytes) -> Failure:
    """The call fails with another code than that of a daemon that is not running."""
    return lambda answer: Result(
        255, before_the_loop(answer), called(answer) + b" failed " + code + b"\n"
    )


def call_failed_under_another_name(answer: Result) -> Result:
    failed = call_failed(answer)
    return replace(failed, stderr=failed.stderr.replace(called(answer), b"DNSServiceRegister"))


def stopped_after(stdout: Callable[[Result], bytes], stderr: bytes = b"") -> Failure:
    """The runner stops a client that had written this."""

    def failure(answer: Result) -> Result:
        raise stopped_with(stdout(answer), stderr)

    return failure


def denied_before_the_loop(answer: Result) -> Result:
    return Result(255, before_the_loop(answer), b"DNSServiceBrowse failed -65570\n")


def another_interface_named(answer: Result) -> Result:
    failed = call_failed(answer)
    return replace(failed, stdout=failed.stdout + f"Using interface {LAN_INDEX + 1}\n".encode())


def another_interface_on_the_error_stream(answer: Result) -> Result:
    failed = call_failed(answer)
    return replace(failed, stderr=f"Using interface {LAN_INDEX + 1}\n".encode() + failed.stderr)


# main (2104): fprintf(stderr, "Unknown interface %s\n", argv[2]); goto Fail; and Fail
# (2405-2408) prints the usage text on the error stream (print_usage, 540) and returns 0.
UNKNOWN_INTERFACE = (
    b"Unknown interface example0\n"
    b"dns-sd -E                          (Enumerate recommended registration domains)\n"
)


def unknown_interface(_answer: Result) -> Result:
    return Result(0, b"", UNKNOWN_INTERFACE)


def unknown_interface_after_the_line(answer: Result) -> Result:
    return Result(0, before_the_loop(answer), UNKNOWN_INTERFACE)


def unknown_interface_on_standard_output(answer: Result) -> Result:
    failed = call_failed(answer)
    return replace(failed, stdout=failed.stdout + b"Unknown interface example0\n")


def status_after_a_reply(answer: Result) -> Result:
    return replace(answer, returncode=1)


def daemon_stopped_after_a_reply(answer: Result) -> Result:
    return replace(answer, stderr=b"Error code -65563\n")


def reply_without_the_start_line(answer: Result) -> Result:
    return Result(1, answer.stdout.replace(START_LINE, b""), b"")


def start_line_twice(answer: Result) -> Result:
    return Result(1, in_the_loop(answer) + STAMP.encode() + b"...STARTING...\n", b"")


def heading_without_a_reply(answer: Result) -> Result:
    # browse_reply (763) prints its heading with the first reply only.
    return Result(1, in_the_loop(answer) + b"Timestamp     A/R    Flags  if Domain\n", b"")


def at_its_bound(answer: Result) -> Result:
    failed = call_failed(answer)
    room = native.MAX_OUTPUT - len(failed.stdout) - len(failed.stderr)
    return replace(failed, stderr=failed.stderr + b" " * room)


def reply_for_another_interface(answer: Result) -> Result:
    # browse_reply (768-769): "%s %8X %3d %-20s %-20s %s\n", the third field is the interface.
    here, other = f" {LAN_INDEX:3d} local.", f" {LAN_INDEX + 1:3d} local."
    assert here.encode() in answer.stdout
    return replace(answer, stdout=answer.stdout.replace(here.encode(), other.encode()))


def could_not_start(_answer: Result) -> Result:
    raise OSError("the client could not be started")


def unexpected(_answer: Result) -> Result:
    raise ValueError("unexpected")


# Failures that are no read that did not complete: the failure, the reason the
# candidate carries, and whether the reader raises a DiscoveryFailure for it.
NEVER: dict[str, tuple[Failure, str, bool]] = {
    "denial-before-the-loop": (denied_before_the_loop, "local-network-denied", True),
    # browse_reply (766) prints "Error code %d" in place of a row.
    "denial-in-place-of-a-row": (
        lambda answer: with_line(STAMP + "Error code -65570")(
            replace(answer, stdout=in_the_loop(answer))
        ),
        "local-network-denied",
        True,
    ),
    "interface-not-acknowledged": (
        lambda answer: without_interface_line(call_failed(answer)),
        "malformed",
        True,
    ),
    "interface-acknowledged-twice": (
        lambda answer: with_interface_line_twice(call_failed(answer)),
        "malformed",
        True,
    ),
    "another-interface-named": (another_interface_named, "malformed", True),
    "another-interface-on-the-error-stream": (
        another_interface_on_the_error_stream,
        "malformed",
        True,
    ),
    "unknown-interface": (unknown_interface, "malformed", True),
    "unknown-interface-after-the-line": (unknown_interface_after_the_line, "malformed", True),
    "unknown-interface-on-standard-output": (
        unknown_interface_on_standard_output,
        "malformed",
        True,
    ),
    # A status or a diagnostic that is no form of a daemon that is not running.
    "status-without-a-reply": (ended_with_a_status, "malformed", True),
    "diagnostic-before-the-loop": (diagnostic_before_the_loop, "malformed", True),
    # kDNSServiceErr_NoAuth, _NotPermitted, _BadInterfaceIndex, _BadParam (dns_sd.h).
    "call-failed-without-authorization": (call_failed_with(b"-65555"), "malformed", True),
    "call-failed-not-permitted": (call_failed_with(b"-65571"), "malformed", True),
    "call-failed-for-the-interface-index": (call_failed_with(b"-65552"), "malformed", True),
    "call-failed-for-a-parameter": (call_failed_with(b"-65540"), "malformed", True),
    # The code of a daemon that is not running, without the words main adds to it.
    "call-failed-without-its-words": (call_failed_with(b"-65563"), "malformed", True),
    "call-failed-under-another-name": (call_failed_under_another_name, "malformed", True),
    # Stopped at the time limit after it had written something else than its banners.
    "stopped-without-a-capture": (timed_out, "malformed", True),
    "stopped-after-a-denial": (
        stopped_after(before_the_loop, b"DNSServiceBrowse failed -65570\n"),
        "malformed",
        True,
    ),
    "stopped-after-any-text-on-the-error-stream": (
        stopped_after(in_the_loop, b"\n"),
        "malformed",
        True,
    ),
    "stopped-naming-another-interface": (
        stopped_after(lambda _answer: f"Using interface {LAN_INDEX + 1}\n".encode()),
        "malformed",
        True,
    ),
    "stopped-after-a-reply": (stopped_after(lambda answer: answer.stdout), "malformed", True),
    "status-after-a-reply": (status_after_a_reply, "malformed", True),
    "daemon-stopped-after-a-reply": (daemon_stopped_after_a_reply, "malformed", True),
    "reply-without-the-start-line": (reply_without_the_start_line, "malformed", True),
    "start-line-twice": (start_line_twice, "malformed", True),
    "heading-without-a-reply": (heading_without_a_reply, "malformed", True),
    "output-at-its-bound": (at_its_bound, "malformed", True),
    "line-that-is-no-reply": (with_line("unexpected line"), "malformed", True),
    "reply-for-another-interface": (reply_for_another_interface, "malformed", True),
    "output-over-its-bound": (flooded, "malformed", False),
    "client-that-could-not-start": (could_not_start, "malformed", False),
    "unexpected-error": (unexpected, "malformed", False),
}


# Without the setting nothing changes


def reconcile(link: Link, identifier: str) -> dict[str, Any]:
    """The coordinator's fixed request for one policy, through the owner's endpoint."""
    current = link.current()
    item = policy(link.config, identifier)
    return owner.endpoint(
        link.config,
        link.settings,
        link.store,
        {
            "protocol_version": 1,
            "operation": "reconcile-discovery",
            "owner": link.settings.owner,
            "config": to_dict(link.config),
            "policy_digest": config_digest(link.config),
            "discovery_digest": discovery_digest(link.config, item),
            "discovery": item.id,
            "active": True,
            "service_generation": current.services[item.service].generation,
            "network_generation": current.network_generation,
        },
    )


def run_of_passes(link: Link, *, failing: bool = True) -> list[tuple[bytes, ...]]:
    """A fixed run of completed, missed and failed passes, and what each wrote.

    One entry for each step: the candidates and the readback as the files hold
    them, and for the two steps that go through the endpoint the request file
    and the endpoint's answers. With `failing` false the same passes all
    complete.
    """
    written: list[tuple[bytes, ...]] = []

    def passed(client: Client | None = None, *command: Any) -> None:
        if failing and client is not None:
            client.fail(*command)
        link.run()
        link.tick()
        written.append((link.raw("candidates.json"), link.raw("readback.json")))
        link.lan.failing.clear()
        link.guests.failing.clear()

    link.lan.devices, link.guests.devices = (KITCHEN, STUDY), (CAMERA,)
    passed()
    answers = [reconcile(link, item.id) for item in link.config.discovery]
    written.append((link.raw("requests.json"), canonical_bytes(answers)))
    link.tick()
    written.append((link.raw("readback.json"),))
    # One device does not answer this time.
    link.lan.devices = (KITCHEN,)
    passed()
    # The bounded runner stops the browse of the import's anchoring type.
    passed(link.lan, "-B", AIRPLAY, timed_out)
    link.lan.devices = (KITCHEN, STUDY)
    passed()
    # A resolve command ends with a status, and so does the export's browse call.
    passed(link.lan, "-G", KITCHEN.host, ended_with_a_status)
    passed(link.guests, "-B", HAP, call_failed)
    # A scan has no time left for its next command.
    passed(link.lan, "-B", AIRPLAY, link.out_of_time)
    # A command that does not show its interface, a denial, a line that is no reply.
    passed(link.lan, "-B", AIRPLAY, without_interface_line)
    passed(link.lan, "-B", RAOP, NEVER["denial-in-place-of-a-row"][0])
    passed(link.lan, "-L", STUDY.name, with_line("unexpected line"))
    # Nothing answers on either link, then everything does again.
    link.lan.devices, link.guests.devices = (), ()
    passed()
    link.lan.devices, link.guests.devices = (KITCHEN, STUDY), (CAMERA,)
    passed()
    observation = owner.endpoint(
        link.config,
        link.settings,
        link.store,
        {
            "protocol_version": 1,
            "operation": "observe",
            "owner": link.settings.owner,
            "config": to_dict(link.config),
        },
    )
    written.append((canonical_bytes(observation),))
    return written


def fingerprints(written: list[tuple[bytes, ...]]) -> list[str]:
    return [hashlib.sha256(b"\x00".join(parts)).hexdigest() for parts in written]


# Taken on the tree before the setting, with a miss tolerance of three: the
# SHA-256 of what each step of run_of_passes wrote. The policy digests are part
# of every candidate and readback.
BEFORE = [
    "c5b5d9f0982ed7af14c2b1ce2ebcbaf63ea3e652f8dda1866b1931239aee06f0",
    "6855684ca1314fa588da57074fb2543d62633b145d01abbb08fb189dd1d06575",
    "891977fced0d8d5bac0915288c7534287a610154cdc33dac096289649d7d17e2",
    "f22c048d0024ae32244fd029a1b8c32df73ee107d4758d3786039f0f26aec10f",
    "5204757daff6ed14883d0ee69ae12a6c3b6bf932edb7630c4931c28b856ca83c",
    "4620b70fafcd98ca1c5d8c80d95f5cba9ab45277a5593f756f14c291890de6d6",
    "5dedfa429a5048df2d6f2fde3b4b5c53f146cb57de06aadbee4a7a3e0c1c786c",
    "54d526bb37f41d4b71fb10e4751fd5def10144f0bb614ce14fa63b813a81ce98",
    "a901aebb063650124984ef67097ba0ead195730c83aec91d7ad2be9d91bce501",
    "28e6d3349802e2e2bef8cf6960cfd244f64f53dfcc5abcdd5665f03f6fca59a7",
    "ec24d5a8527d9f1cd78692bcee97be27fb6c46c2827903b5045f7716b1263750",
    "78f83a0e88f00fcf45bbf053cea98213c5e89f5f234aed4e710878c2c5009b76",
    "7786875e943cc377467ae6faa057e0dfa658a6d7df4255ca152677d0aaef49c6",
    "a92169cac849032104252da087f7c26471d404607f383f31a4b71c092db32742",
    "055f2ac044d347d19f911f12e4354bd20b69a8b4f8fc4672b7a62d8f03636b11",
]


def test_without_the_setting_every_pass_writes_the_bytes_of_before(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), replace(settings, miss_tolerance=3))
    written = run_of_passes(link)
    assert fingerprints(written) == BEFORE
    # The run is what it says: the failed passes carry their reason and nothing else.
    reasons = [
        strict_loads(step[0])["policies"][IMPORT].get("reason")
        for step in written
        if len(step) == 2 and step[0].startswith(b'{"config_digest"')
    ]
    assert reasons == [
        None,
        None,
        "malformed",
        None,
        "malformed",
        None,
        "timed-out",
        "malformed",
        "local-network-denied",
        "malformed",
        None,
        None,
    ]
    assert not any(b"tolerated_failure" in part for step in written for part in step)


def test_setting_changes_nothing_while_no_pass_fails(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plain = Link(monkeypatch, leased(config), replace(settings, miss_tolerance=3))
    before = run_of_passes(plain, failing=False)
    counted = Link(
        monkeypatch, leased(config), replace(counting(settings), state_dir=tmp_path / "counted")
    )
    assert run_of_passes(counted, failing=False) == before
    # The run holds completed passes and passes that miss a record, and carries one.
    document = strict_loads(before[3][0])
    carried = document["policies"][IMPORT]
    assert names(carried) == [KITCHEN.name, STUDY.name]
    # The pass follows the endpoint's two bounded waits, so its time is no whole second.
    assert sorted(item["seen_at"] for item in carried["records"]) == [
        START,
        document["observed_at"],
    ]
    assert START + 14 < document["observed_at"] < START + 25 and document["observed_at"] % 1


def test_policy_that_tolerates_no_miss_is_untouched_by_the_setting(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # The import states that it tolerates nothing; the export follows the owner's three.
    stated = stating(leased(config), {IMPORT: 1})
    plain = run_of_passes(Link(monkeypatch, stated, replace(settings, miss_tolerance=3)))
    counted = run_of_passes(
        Link(monkeypatch, stated, replace(counting(settings), state_dir=tmp_path / "counted"))
    )
    assert len(plain) == len(counted) == 15
    differing = []
    for at, (before, after) in enumerate(zip(plain, counted, strict=True)):
        if len(before) != 2 or not before[0].startswith(b'{"config_digest"'):
            assert before == after
            continue
        candidates = [strict_loads(step[0])["policies"] for step in (before, after)]
        readbacks = [strict_loads(step[1])["profiles"] for step in (before, after)]
        # Its candidate and its observation are the same, byte for byte, in every pass.
        assert canonical_bytes(candidates[0][IMPORT]) == canonical_bytes(candidates[1][IMPORT])
        assert canonical_bytes(readbacks[0][IMPORT]) == canonical_bytes(readbacks[1][IMPORT])
        if before != after:
            differing.append(at)
            assert candidates[0][EXPORT].get("reason") == "malformed"
            assert candidates[1][EXPORT]["tolerated_failure"] == "malformed"
    # The one pass in which the export's own read did not complete.
    assert differing == [7]


# The setting


def test_settings_without_the_key_do_not_count_a_failed_pass(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    loaded = owner.load_settings(settings_file(tmp_path, leased(config), settings))
    assert loaded == settings and loaded.failed_pass is None
    assert owner.BonjourSettings.__dataclass_fields__["failed_pass"].default is None


def test_failed_pass_has_the_one_value_miss(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    path = settings_file(tmp_path, leased(config), settings, miss_tolerance=3, failed_pass="miss")
    assert owner.load_settings(path) == counting(settings)
    assert counting(settings).failed_pass == "miss"


@pytest.mark.parametrize(
    "value",
    ["Miss", "miss ", " miss", "", "missed", "withdraw", "forget", True, 1, 1.0, None, ["miss"]],
)
def test_any_other_value_of_failed_pass_is_refused(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path, value: Any
) -> None:
    keys = {"miss_tolerance": 3, "failed_pass": "miss"}
    assert owner.load_settings(settings_file(tmp_path, leased(config), settings, **keys))
    with pytest.raises(ValueError, match="Bonjour failed pass has one value: miss"):
        owner.load_settings(
            settings_file(tmp_path, leased(config), settings, **{**keys, "failed_pass": value})
        )


def test_settings_stay_closed_beside_the_new_key(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    keys = {"miss_tolerance": 3, "failed_pass": "miss"}
    for unknown in ("failed_passes", "failed-pass", "FAILED_PASS", "failed_scan"):
        with pytest.raises(ValueError, match="invalid Bonjour settings"):
            owner.load_settings(
                settings_file(tmp_path, leased(config), settings, **keys, **{unknown: "miss"})
            )


def test_failed_pass_is_refused_where_no_owned_policy_tolerates_a_miss(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    refusal = "Bonjour failed pass needs an owned policy that tolerates a miss"

    def load(policy_config: Config, **keys: Any) -> owner.BonjourSettings:
        return owner.load_settings(
            settings_file(tmp_path, policy_config, settings, failed_pass="miss", **keys)
        )

    roomy = leased(config)
    # The owner tolerates nothing and no entry says otherwise.
    with pytest.raises(ValueError, match=refusal):
        load(roomy)
    with pytest.raises(ValueError, match=refusal):
        load(roomy, miss_tolerance=1)
    # The owner tolerates misses, and every owned entry states that it tolerates none.
    with pytest.raises(ValueError, match=refusal):
        load(stating(roomy, {IMPORT: 1, EXPORT: 1}), miss_tolerance=3)
    # One owned policy that tolerates a miss is enough, by the setting or by its entry.
    assert load(roomy, miss_tolerance=2) == counting(settings, 2)
    assert load(stating(roomy, {IMPORT: 1}), miss_tolerance=2) == counting(settings, 2)
    assert load(stating(roomy, {EXPORT: 2})) == counting(settings, 1)
    assert load(stating(roomy, {EXPORT: 2, IMPORT: 1}), miss_tolerance=1) == counting(settings, 1)


def test_refusal_looks_at_the_policies_of_this_owner_only(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    refusal = "Bonjour failed pass needs an owned policy that tolerates a miss"
    foreign = second_owner(leased(config), EXPORT)
    assert [item.owner for item in foreign.discovery] == [settings.owner, "other-discovery"]

    def load(policy_config: Config, **keys: Any) -> owner.BonjourSettings:
        return owner.load_settings(
            settings_file(tmp_path, policy_config, settings, failed_pass="miss", **keys)
        )

    # Another owner's entry that tolerates misses does not stand in for an owned one.
    with pytest.raises(ValueError, match=refusal):
        load(stating(foreign, {EXPORT: 3}))
    with pytest.raises(ValueError, match=refusal):
        load(stating(foreign, {EXPORT: 3, IMPORT: 1}), miss_tolerance=3)
    assert load(stating(foreign, {IMPORT: 2})) == counting(settings, 1)
    # An owner that owns no policy has nothing a failed pass could count for.
    with pytest.raises(ValueError, match=refusal):
        load(second_owner(leased(config), IMPORT, EXPORT))


# What the reader marks


def scanned(runner: Callable[[list[str], float], Result]) -> tuple[Record, ...]:
    return native.scan("example0", LAN_INDEX, AIRPLAY, 8, 2, 1000.0, runner)


def test_failure_is_not_marked_unless_its_reader_says_so() -> None:
    assert native.DiscoveryFailure().unfinished is False
    assert native.DiscoveryFailure("timed-out").unfinished is False
    assert native.InstanceUnusable().unfinished is False
    assert native.RegistrationExpired().unfinished is False
    marked = native.DiscoveryFailure("timed-out", unfinished=True)
    assert (marked.reason, marked.unfinished, str(marked)) == ("timed-out", True, "timed-out")
    with pytest.raises(TypeError):
        native.DiscoveryFailure("timed-out", True)  # type: ignore[misc]


@pytest.mark.parametrize(
    ("operation", "subject"),
    [("-B", AIRPLAY), ("-L", KITCHEN.name), ("-G", KITCHEN.host), ("-Q", KITCHEN.fullname)],
)
@pytest.mark.parametrize(("failure", "reason"), UNFINISHED.values(), ids=UNFINISHED)
def test_reader_marks_a_read_that_did_not_complete(
    operation: str, subject: str, failure: Failure, reason: str
) -> None:
    client = Client(KITCHEN, STUDY).fail(operation, subject, failure)
    with pytest.raises(native.DiscoveryFailure) as caught:
        scanned(client)
    assert type(caught.value) is native.DiscoveryFailure
    assert (caught.value.reason, caught.value.unfinished) == (reason, True)
    # The scan ended at that command.
    assert client.asked[-1] == (operation, subject)


def test_time_limit_of_the_runner_is_raised_as_the_reader_own_failure() -> None:
    with pytest.raises(native.DiscoveryFailure) as caught:
        scanned(Client(KITCHEN).fail("-B", AIRPLAY, stopped))
    assert isinstance(caught.value.__cause__, ProcessTimeout)
    assert (caught.value.reason, caught.value.unfinished) == ("malformed", True)
    # A time limit that does not say what the client had written is not marked.
    with pytest.raises(native.DiscoveryFailure) as caught:
        scanned(Client(KITCHEN).fail("-B", AIRPLAY, timed_out))
    assert isinstance(caught.value.__cause__, ProcessTimeout)
    assert (caught.value.__cause__.stdout, caught.value.__cause__.stderr) == (None, None)
    assert (caught.value.reason, caught.value.unfinished) == ("malformed", False)
    # The output bound is not a time limit and stays the runner's own failure.
    with pytest.raises(OutputLimit):
        scanned(Client(KITCHEN).fail("-B", AIRPLAY, flooded))


def test_reader_does_not_mark_a_scan_that_has_no_time_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    budget = Budget()
    monkeypatch.setattr(native, "time", budget)

    def late(answer: Result) -> Result:
        budget.now += 45
        return answer

    with pytest.raises(native.DiscoveryFailure) as caught:
        scanned(Client(KITCHEN).fail("-B", AIRPLAY, late))
    assert (caught.value.reason, caught.value.unfinished) == ("timed-out", False)
    # One tick earlier the next command still gets the time that is left.
    budget.now = 100.0
    limits: list[float] = []
    client = Client(KITCHEN)

    def almost(answer: Result) -> Result:
        budget.now += 44.75
        return answer

    def runner(argv: list[str], limit: float) -> Result:
        limits.append(limit)
        return client(argv, limit)

    client.fail("-B", AIRPLAY, almost)
    assert [item.name for item in scanned(runner)] == [KITCHEN.name]
    assert limits == [3.0, 0.25, 0.25, 0.25]


@pytest.mark.parametrize(("failure", "reason", "discovery"), NEVER.values(), ids=NEVER)
def test_reader_marks_nothing_else(failure: Failure, reason: str, discovery: bool) -> None:
    client = Client(KITCHEN, STUDY).fail("-B", AIRPLAY, failure)
    with pytest.raises((native.DiscoveryFailure, OSError, ValueError, OutputLimit)) as caught:
        scanned(client)
    assert isinstance(caught.value, native.DiscoveryFailure) is discovery
    if discovery:
        assert (caught.value.reason, caught.value.unfinished) == (reason, False)
    assert not owner.counts_as_miss(caught.value)


@pytest.mark.parametrize(
    ("result", "reason", "marked"),
    [
        # The call failed for a daemon that is not running (2390-2394), or the
        # daemon stopped before a reply (246): the two forms, for an address command.
        (
            Result(
                255,
                b"Using interface 7\n",
                b"DNSServiceGetAddrInfo failed -65563 (Service Not Running)\n",
            ),
            "malformed",
            1,
        ),
        (Result(0, b"Using interface 7\n" + START_LINE, b"Error code -65563\n"), "malformed", 1),
        # Not those forms: another call's name without the words of that code,
        # a status alone, other text on the error stream, a diagnostic on
        # standard output.
        (Result(255, b"Using interface 7\n", b"DNSServiceBrowse failed -65563\n"), "malformed", 0),
        (Result(1, b"Using interface 7\n", b""), "malformed", 0),
        (Result(0, b"Using interface 7\n", b" "), "malformed", 0),
        (Result(0, b"Using interface 7\nNo Such Record\n", b""), "malformed", 0),
        # Not the verified interface, or more than it.
        (Result(1, b"Using interface 8\n", b""), "malformed", 0),
        (Result(1, b"Using interface 70\n", b""), "malformed", 0),
        (Result(1, b"", b""), "malformed", 0),
        (Result(1, b"Using interface 7\nUsing interface 7\n", b""), "malformed", 0),
        (Result(0, b"Using interface 7\nUsing interface 7\n", b""), "malformed", 0),
        (Result(1, b"Using interface 7\nUsing interface 8\n", b""), "malformed", 0),
        (Result(1, b"Using interface 7\n", b"Using interface 8\n"), "malformed", 0),
        (Result(1, b"Using interface 7\n", b"x\nUsing interface 7\n"), "malformed", 0),
        (Result(1, b"", b"Using interface 7\n"), "malformed", 0),
        (Result(1, b"Browsing for x\n", b"Using interface 7\n"), "malformed", 0),
        (Result(0, b"Using interface 7\n", UNKNOWN_INTERFACE), "malformed", 0),
        (Result(0, b"", UNKNOWN_INTERFACE), "malformed", 0),
        # Anything after the banners but the one start line.
        (Result(1, b"Using interface 7\n" + START_LINE + b"\n", b""), "malformed", 0),
        (Result(1, b"Using interface 7\n" + START_LINE + b"x\n", b""), "malformed", 0),
        (Result(1, b"Using interface 7\n" + STAMP.encode() + b"x\n", b""), "malformed", 0),
        # A denial has its own reason.
        (Result(1, b"Using interface 7\n", b"Error code -65570\n"), "local-network-denied", 0),
        (Result(1, b"Using interface 7\nNo Authorization\n", b""), "local-network-denied", 0),
    ],
)
def test_only_a_client_that_left_a_form_of_a_read_that_did_not_complete_is_marked(
    result: Result, reason: str, marked: int
) -> None:
    # The confirmation raises the failure with its reason, as before, and marks
    # nothing itself: which command ran decides what the forms are, and scan
    # marks its failure by them (unfinished_read).
    with pytest.raises(native.DiscoveryFailure) as caught:
        native.confirmed_output(result, 7)
    assert (caught.value.reason, caught.value.unfinished) == (reason, False)
    judged = native.unfinished_read(
        ["-G", "v4", KITCHEN.host], 7, result.returncode, result.stdout, result.stderr
    )
    assert judged is bool(marked)


def test_output_at_its_bound_is_not_marked_and_neither_is_any_other_padding() -> None:
    head = b"Using interface 7\n"
    failed = b"DNSServiceGetAddrInfo failed -65563 (Service Not Running)\n"
    room = native.MAX_OUTPUT - len(head) - len(failed)
    # The form itself, one byte more, one byte below the bound, the bound.
    for padding, marked in ((0, True), (1, False), (room - 1, False), (room, False)):
        client = Client(KITCHEN).fail(
            "-G", KITCHEN.host, lambda _answer, pad=padding: Result(255, head, failed + b" " * pad)
        )
        with pytest.raises(native.DiscoveryFailure) as caught:
            scanned(client)
        assert client.asked[-1] == ("-G", KITCHEN.host)
        assert (caught.value.reason, caught.value.unfinished) == ("malformed", marked)


def test_confirmation_never_marks_an_interface_that_was_not_verified() -> None:
    for index in (0, -1):
        with pytest.raises(native.DiscoveryFailure) as caught:
            native.confirmed_output(Result(1, f"Using interface {index}\n".encode(), b""), index)
        assert (caught.value.reason, caught.value.unfinished) == ("malformed", False)
        # Nor does the scan, whatever form the client left for that index.
        client = Client(KITCHEN, index=index).fail("-B", AIRPLAY, call_failed)
        with pytest.raises(native.DiscoveryFailure) as caught:
            native.scan("example0", index, AIRPLAY, 8, 2, 1000.0, client)
        assert (caught.value.reason, caught.value.unfinished) == ("malformed", False)
    # The same form for the verified index is marked.
    with pytest.raises(native.DiscoveryFailure) as caught:
        scanned(Client(KITCHEN).fail("-B", AIRPLAY, call_failed))
    assert (caught.value.reason, caught.value.unfinished) == ("malformed", True)


@pytest.mark.parametrize(
    ("reason", "marked", "counts"),
    [
        ("malformed", True, True),
        ("malformed", False, False),
        # A reason that is not on the closed list never counts, marked or not. A
        # scan whose own time is used up carries timed-out and is never marked.
        ("timed-out", True, False),
        ("timed-out", False, False),
        ("incomplete", True, False),
        ("local-network-denied", True, False),
        ("identity-mismatch", True, False),
        ("unavailable", True, False),
        ("unobserved", True, False),
    ],
)
def test_only_a_marked_failure_with_a_reason_on_the_closed_list_counts(
    reason: str, marked: bool, counts: bool
) -> None:
    assert owner.counts_as_miss(native.DiscoveryFailure(reason, unfinished=marked)) is counts


def test_exception_that_is_no_discovery_failure_never_counts() -> None:
    for error in (
        ProcessTimeout("limit"),
        OutputLimit("bound"),
        TimeoutError(),
        OSError(),
        ValueError("timed-out"),
        KeyError("malformed"),
        RecursionError("timed-out"),
    ):
        error.unfinished = True  # type: ignore[attr-defined]
        error.reason = "malformed"  # type: ignore[attr-defined]
        assert not owner.counts_as_miss(error)


# One failed pass


def test_failed_pass_carries_every_record_the_memory_holds(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The tolerance is the policy's own; the owner's setting only says what a failure is.
    link = Link(
        monkeypatch, stating(leased(config), {IMPORT: 3}), replace(settings, failed_pass="miss")
    )
    link.lan.devices = (KITCHEN, STUDY)
    seen = link.run()[IMPORT]
    assert names(seen) == [KITCHEN.name, STUDY.name]
    assert link.counts() == {f"{KITCHEN.name} {AIRPLAY}": 0, f"{STUDY.name} {AIRPLAY}": 0}
    failed = link.failed()[IMPORT]
    # The same records with the time they were seen, as a completed pass that
    # missed them writes them, and the failure beside them.
    assert failed["records"] == seen["records"]
    assert [item["seen_at"] for item in failed["records"]] == [START, START]
    assert failed == {**seen, "observed_at": link.clock.now, "tolerated_failure": "malformed"}
    assert "reason" not in failed and link.clock.now == START + STEP
    # Each record has missed one pass.
    assert link.counts() == {f"{KITCHEN.name} {AIRPLAY}": 1, f"{STUDY.name} {AIRPLAY}": 1}


def test_same_failed_pass_withdraws_at_once_without_the_setting(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, stating(leased(config), {IMPORT: 3}), settings)
    link.lan.devices = (KITCHEN, STUDY)
    assert len(link.run()[IMPORT]["records"]) == 2
    failed = link.failed()[IMPORT]
    assert failed["records"] == [] and failed["reason"] == "malformed"
    assert "tolerated_failure" not in failed and link.counts() is None


@pytest.mark.parametrize(
    ("operation", "subject"),
    [("-B", AIRPLAY), ("-L", STUDY.name), ("-G", STUDY.host), ("-Q", STUDY.fullname)],
)
@pytest.mark.parametrize(("failure", "reason"), UNFINISHED.values(), ids=UNFINISHED)
def test_each_read_that_did_not_complete_counts_as_a_miss(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    subject: str,
    failure: Failure,
    reason: str,
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices, link.guests.devices = (KITCHEN, STUDY), (CAMERA,)
    seen = link.run()
    link.lan.fail(operation, subject, failure)
    failed = link.run()
    assert failed[IMPORT]["records"] == seen[IMPORT]["records"]
    assert failed[IMPORT]["tolerated_failure"] == reason and "reason" not in failed[IMPORT]
    # The sibling policy read its own link again and says nothing of a failure.
    assert set(failed[EXPORT]) == set(seen[EXPORT]) and names(failed[EXPORT]) == ["Camera"]
    assert failed[EXPORT]["records"][0]["seen_at"] == link.clock.now


def test_scan_that_has_no_time_left_is_no_miss(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN, STUDY)
    assert len(link.run()[IMPORT]["records"]) == 2
    failed = link.failed(link.out_of_time)[IMPORT]
    assert (failed["records"], failed["reason"]) == ([], "timed-out")
    assert "tolerated_failure" not in failed and link.counts() is None


@pytest.mark.parametrize(("failure", "reason", "_discovery"), NEVER.values(), ids=NEVER)
def test_every_other_failure_withdraws_at_once(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    failure: Failure,
    reason: str,
    _discovery: bool,
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices, link.guests.devices = (KITCHEN, STUDY), (CAMERA,)
    assert len(link.run()[IMPORT]["records"]) == 2
    failed = link.failed(failure)
    assert failed[IMPORT]["records"] == [] and failed[IMPORT]["reason"] == reason
    assert "tolerated_failure" not in failed[IMPORT]
    assert len(failed[EXPORT]["records"]) == 1 and "reason" not in failed[EXPORT]
    # Nothing is remembered: the next pass, which merely misses them, lists nothing.
    assert link.counts() is None
    link.lan.devices = ()
    missed = link.run()[IMPORT]
    assert missed["records"] == [] and "reason" not in missed


# What a whole scan of one type can raise that is no read that did not complete.
OTHERWISE: dict[str, Raised] = {
    "timed-out-unmarked": lambda: native.DiscoveryFailure("timed-out"),
    "malformed-unmarked": lambda: native.DiscoveryFailure("malformed"),
    "incomplete": lambda: native.DiscoveryFailure("incomplete"),
    "denial": lambda: native.DiscoveryFailure("local-network-denied"),
    "identity-mismatch": lambda: native.DiscoveryFailure("identity-mismatch"),
    "unavailable": lambda: native.DiscoveryFailure("unavailable"),
    # Marked, with a reason that is not on the closed list.
    "timed-out-marked": lambda: unfinished("timed-out"),
    "incomplete-marked": lambda: unfinished("incomplete"),
    "denial-marked": lambda: unfinished("local-network-denied"),
    "identity-mismatch-marked": lambda: unfinished("identity-mismatch"),
    "unavailable-marked": lambda: unfinished("unavailable"),
    "instance-unusable": lambda: native.InstanceUnusable("malformed"),
    # Not a DiscoveryFailure: the runner's limits outside the reader, the wait
    # for a scan that the pool's own limit ends, and anything else.
    "runner-time-limit": lambda: ProcessTimeout("limit"),
    "runner-output-bound": lambda: OutputLimit("bound"),
    "pool-wait": lambda: TimeoutError(),
    "os-error": lambda: OSError("spawn"),
    "recursion-error": lambda: RecursionError("depth"),
    "key-error": lambda: KeyError("unexpected"),
}


@pytest.mark.parametrize("raised", OTHERWISE.values(), ids=OTHERWISE)
def test_scan_failure_that_is_not_marked_or_not_on_the_list_withdraws_at_once(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    raised: Raised,
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN, STUDY)
    assert len(link.run()[IMPORT]["records"]) == 2
    link.raising[AIRPLAY] = raised
    failed = link.run()[IMPORT]
    expected = getattr(raised(), "reason", "malformed")
    assert (failed["records"], failed["reason"]) == ([], expected)
    assert "tolerated_failure" not in failed and link.counts() is None


def test_marked_failure_with_the_reason_on_the_list_is_carried(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN, STUDY)
    seen = link.run()[IMPORT]
    link.raising[AIRPLAY] = lambda: unfinished("malformed")
    failed = link.run()[IMPORT]
    assert failed["records"] == seen["records"] and failed["tolerated_failure"] == "malformed"


# Another scan of the same pass


# How another scan of the pass ends, and whether the pass then counts as a miss.
BESIDE: dict[str, tuple[Raised | None, bool]] = {
    "denied": (OTHERWISE["denial"], False),
    "incomplete": (OTHERWISE["incomplete"], False),
    "malformed": (OTHERWISE["malformed-unmarked"], False),
    "timed-out-unmarked": (OTHERWISE["timed-out-unmarked"], False),
    "denied-marked": (OTHERWISE["denial-marked"], False),
    "output-bound": (OTHERWISE["runner-output-bound"], False),
    "os-error": (OTHERWISE["os-error"], False),
    # Its own time used up, even if someone marked it: never a miss.
    "out-of-time-marked": (lambda: unfinished("timed-out"), False),
    "also-unfinished": (lambda: unfinished("malformed"), True),
    "completed": (None, True),
}


@pytest.mark.parametrize(("other", "carried"), BESIDE.values(), ids=BESIDE)
@pytest.mark.parametrize("kind", [RAOP, "_mediaremotetv._tcp"])
def test_pass_counts_as_a_miss_only_when_no_scan_of_it_failed_otherwise(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    other: Raised | None,
    carried: bool,
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    assert policy(link.config).types.index(AIRPLAY) < policy(link.config).types.index(kind)
    link.lan.devices = (KITCHEN, STUDY)
    seen = link.run()[IMPORT]
    # The scan of the first type does not complete; another type's scan ends as told.
    link.raising[AIRPLAY] = unfinished
    if other is not None:
        link.raising[kind] = other
    failed = link.run()[IMPORT]
    if carried:
        assert failed["records"] == seen["records"]
        assert failed["tolerated_failure"] == "malformed" and "reason" not in failed
    else:
        # The reason is still the one of the first scan that failed, as before.
        assert (failed["records"], failed["reason"]) == ([], "malformed")
        assert "tolerated_failure" not in failed and link.counts() is None


def test_denial_of_an_earlier_type_is_reported_as_before(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN, STUDY)
    link.run()
    link.raising[AIRPLAY] = lambda: native.DiscoveryFailure("local-network-denied")
    link.raising[RAOP] = unfinished
    failed = link.run()[IMPORT]
    assert (failed["records"], failed["reason"]) == ([], "local-network-denied")
    assert "tolerated_failure" not in failed and link.counts() is None


@pytest.mark.parametrize(
    ("beside", "carried"),
    [
        (NEVER["denial-in-place-of-a-row"][0], False),
        (NEVER["denial-before-the-loop"][0], False),
        (NEVER["interface-not-acknowledged"][0], False),
        (NEVER["line-that-is-no-reply"][0], False),
        (flooded, False),
        (call_failed_with(b"-65555"), False),
        (timed_out, False),
        (call_failed, True),
        (stopped, True),
    ],
    ids=[
        "denial-in-place-of-a-row",
        "denial-before-the-loop",
        "interface-not-acknowledged",
        "line-that-is-no-reply",
        "output-over-its-bound",
        "call-failed-without-authorization",
        "stopped-without-a-capture",
        "call-failed",
        "stopped-at-the-time-limit",
    ],
)
def test_client_of_another_type_that_fails_otherwise_is_not_passed_over(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    beside: Failure,
    carried: bool,
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN, STUDY)
    seen = link.run()[IMPORT]
    # The browse of the first type is stopped at its time limit, and the client
    # that browses a later type of the same pass ends as told.
    link.lan.fail("-B", AIRPLAY, stopped).fail("-B", RAOP, beside)
    failed = link.run()[IMPORT]
    if carried:
        assert failed["records"] == seen["records"] and failed["tolerated_failure"] == "malformed"
    else:
        assert (failed["records"], failed["reason"]) == ([], "malformed")
        assert "tolerated_failure" not in failed and link.counts() is None


def test_record_that_another_scan_of_the_failed_pass_read_is_not_refreshed(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    related = replace(KITCHEN, kind=RAOP, port=5000)
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN, related)
    seen = link.run()[IMPORT]
    assert sorted(item["service_type"] for item in seen["records"]) == [AIRPLAY, RAOP]
    asked = len(link.lan.asked)
    failed = link.failed()[IMPORT]
    # The other type's scan read its record again in this pass. A pass that did
    # not complete refreshes nothing: both are carried as they were seen.
    assert ("-Q", related.fullname) in link.lan.asked[asked:]
    assert failed["records"] == seen["records"]
    assert link.counts() == {f"{KITCHEN.name} {AIRPLAY}": 1, f"{KITCHEN.name} {RAOP}": 1}


# Counting


def kept(link: Link, passes: list[str]) -> list[list[str]]:
    """The names each pass lists for the import: `fail`, `miss` or `seen`."""
    listed = []
    for kind in passes:
        if kind == "fail":
            listed.append(names(link.failed()[IMPORT]))
        else:
            link.lan.devices = (KITCHEN, STUDY) if kind == "seen" else ()
            listed.append(names(link.run()[IMPORT]))
    return listed


@pytest.mark.parametrize("tolerance", [2, 3, 4, 5, 6, 7, 8])
@pytest.mark.parametrize("stated", [False, True], ids=["owner", "policy"])
def test_failed_passes_withdraw_at_the_pass_at_which_the_same_number_of_misses_would(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    tolerance: int,
    stated: bool,
) -> None:
    policy_config = stating(leased(config), {IMPORT: tolerance}) if stated else leased(config)
    own = counting(settings, 1 if stated else tolerance)
    both = [KITCHEN.name, STUDY.name]
    expected = [both] * (tolerance - 1) + [[], []]
    missing = Link(monkeypatch, policy_config, own)
    assert kept(missing, ["seen"] + ["miss"] * (tolerance + 1)) == [both, *expected]
    last = missing.store.read("candidates.json")["policies"][IMPORT]
    assert "reason" not in last
    failing = Link(monkeypatch, policy_config, replace(own, state_dir=tmp_path / "failing"))
    assert kept(failing, ["seen"] + ["fail"] * (tolerance - 1)) == [both] * tolerance
    assert failing.counts() == {
        f"{KITCHEN.name} {AIRPLAY}": tolerance - 1,
        f"{STUDY.name} {AIRPLAY}": tolerance - 1,
    }
    # The pass at which the count reaches the tolerance: the failure stands.
    stands = failing.failed()[IMPORT]
    assert (stands["records"], stands["reason"]) == ([], "malformed")
    assert "tolerated_failure" not in stands and failing.counts() is None
    assert failing.failed()[IMPORT]["reason"] == "malformed"


@pytest.mark.parametrize("pattern", list(itertools.product(["fail", "miss"], repeat=3)))
@pytest.mark.parametrize("fourth", ["fail", "miss"])
def test_failed_and_missed_passes_count_together(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    pattern: tuple[str, ...],
    fourth: str,
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings, 4))
    both = [KITCHEN.name, STUDY.name]
    assert kept(link, ["seen"]) == [both]
    for number, kind in enumerate(pattern, start=1):
        assert kept(link, [kind]) == [both]
        assert set((link.counts() or {}).values()) == {number}
        candidate = link.store.read("candidates.json")["policies"][IMPORT]
        # Only a failed pass says so; a missed one is written as it always was.
        assert ("tolerated_failure" in candidate) is (kind == "fail")
        assert [item["seen_at"] for item in candidate["records"]] == [START, START]
    assert kept(link, [fourth]) == [[]]
    candidate = link.store.read("candidates.json")["policies"][IMPORT]
    assert candidate.get("reason") == ("malformed" if fourth == "fail" else None)
    assert link.counts() == (None if fourth == "fail" else {})


def test_completed_pass_that_reads_the_record_starts_a_new_count(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    both = [KITCHEN.name, STUDY.name]
    assert kept(link, ["seen", "fail", "fail", "seen"]) == [both] * 4
    again = link.store.read("candidates.json")["policies"][IMPORT]
    assert [item["seen_at"] for item in again["records"]] == [START + 3 * STEP] * 2
    assert "tolerated_failure" not in again
    assert set((link.counts() or {}).values()) == {0}
    assert kept(link, ["fail", "fail", "fail"]) == [both, both, []]


def test_passes_at_fractions_of_a_second_carry_the_time_of_sight_unchanged(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings, 4))
    link.lan.devices = (KITCHEN,)
    seen = link.run(at=START + 0.125)[IMPORT]
    assert [item["seen_at"] for item in seen["records"]] == [START + 0.125]
    for at in (START + 7.375, START + 7.5, START + 19.0625):
        failed = link.failed(at=at)[IMPORT]
        assert failed["records"] == seen["records"] and failed["observed_at"] == at
    assert link.counts() == {f"{KITCHEN.name} {AIRPLAY}": 3}
    assert link.failed(at=START + 19.125)[IMPORT]["reason"] == "malformed"


def test_record_that_was_read_alone_starts_its_own_count(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN, STUDY)
    link.run()
    link.lan.devices = (KITCHEN,)
    link.run()
    assert link.counts() == {f"{KITCHEN.name} {AIRPLAY}": 0, f"{STUDY.name} {AIRPLAY}": 1}
    assert names(link.failed()[IMPORT]) == [KITCHEN.name, STUDY.name]
    assert link.counts() == {f"{KITCHEN.name} {AIRPLAY}": 1, f"{STUDY.name} {AIRPLAY}": 2}
    # The record that already missed a pass reaches its limit one pass earlier.
    assert names(link.failed()[IMPORT]) == [KITCHEN.name]
    assert link.counts() == {f"{KITCHEN.name} {AIRPLAY}": 2}
    last = link.failed()[IMPORT]
    assert (last["records"], last["reason"]) == ([], "malformed")


# What ends a carried record whatever the count


def test_record_is_carried_through_a_failed_pass_only_inside_its_lease(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_config = leased(config)
    own = counting(settings, 8)
    last = START + LEASE - owner.carry_horizon(policy_config, own)
    link = Link(monkeypatch, policy_config, own)
    link.lan.devices = (KITCHEN,)
    link.run(at=START)
    # A quarter of a second before its lease no longer outlasts the next candidate.
    assert names(link.failed(at=last - 0.25)[IMPORT]) == [KITCHEN.name]
    assert link.counts() == {f"{KITCHEN.name} {AIRPLAY}": 1}
    # Missed twice of eight: the lease decides, and the failure stands.
    stands = link.failed(at=last)[IMPORT]
    assert (stands["records"], stands["reason"]) == ([], "malformed")
    assert "tolerated_failure" not in stands and link.counts() is None


def test_lease_of_a_record_carried_through_failed_passes_is_never_refreshed(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_config = leased(config)
    own = counting(settings, 8)
    link = Link(monkeypatch, policy_config, own)
    link.lan.devices = (KITCHEN,)
    link.requested()
    in_force = link.run(at=START)[IMPORT]
    item = policy(policy_config)
    request = link.store.read("requests.json")["policies"][IMPORT]

    def leased_at(candidate: dict[str, Any], when: float) -> tuple[Record, ...] | None:
        return owner.lease_records(
            policy_config,
            item,
            request,
            candidate,
            observed(policy_config, when),
            Intent(),
            READY,
            when,
        )

    # Every pass fails and takes its whole time budget.
    budget = owner.pass_budget(policy_config, own)
    written = START + budget
    carrying = 0
    while in_force["records"]:
        assert [record["seen_at"] for record in in_force["records"]] == [START]
        begun = written + own.pass_interval
        following = link.failed(at=begun)[IMPORT]
        for when in (written, begun, begun + budget):
            assert leased_at(in_force, when) is not None
        carrying += bool(following["records"])
        in_force, written = following, begun + budget
    # Carried, and for fewer passes than the tolerance alone would allow.
    assert 1 <= carrying < own.miss_tolerance - 1
    assert in_force["reason"] == "malformed" and written <= START + LEASE


def test_changed_fence_carries_nothing_through_a_failed_pass(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    for change in ("guest", "network", "policy", None):
        with monkeypatch.context() as patch:
            own = replace(counting(settings), state_dir=settings.state_dir / str(change))
            link = Link(patch, leased(config), own)
            link.guests.devices = (CAMERA,)
            link.run()
            link.guests.fail("-B", HAP, stopped)
            assert names(link.run()[EXPORT]) == ["Camera"]
            now = link.clock.now + STEP
            report = observed(link.config, now)
            if change == "guest":
                link.report = regenerated(report, link.config, "camera", "mock-camera-2")
            elif change == "network":
                link.report = renumbered(report, "mock-network-2")
            elif change == "policy":
                link.config = replace(
                    link.config,
                    discovery=tuple(
                        replace(item, max_records=item.max_records - 1)
                        for item in link.config.discovery
                    ),
                )
            after = link.run(at=now)[EXPORT]
            if change is None:
                # One miss of three is left, so the same pass without a change carries.
                assert names(after) == ["Camera"] and after["tolerated_failure"] == "malformed"
                continue
            assert (after["records"], after["reason"]) == ([], "malformed")
            assert "tolerated_failure" not in after and link.counts(EXPORT) is None
            assert after["policy_digest"] == discovery_digest(
                link.config, policy(link.config, EXPORT)
            )


def test_carried_source_is_judged_by_the_report_of_the_failed_pass(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.guests.devices = (CAMERA,)
    link.run()
    # The guest now has another address under the same generation: the record
    # read at the old address is no record of this guest any more.
    now = link.clock.now + STEP
    report = observed(link.config, now)
    guest = report.services["camera"]
    link.report = replace(
        report,
        services={
            **report.services,
            "camera": replace(guest, data={**guest.data, "ipv4": "198.51.100.99"}),
        },
        profiles={
            key: replace(item, data={**item.data, "target_ipv4": "198.51.100.99"})
            if key == "camera-web"
            else item
            for key, item in report.profiles.items()
        },
    )
    link.guests.fail("-B", HAP, stopped)
    moved = link.run(at=now)[EXPORT]
    # Nothing of what was remembered is listed, so nothing is carried: the failure stands.
    assert (moved["records"], moved["reason"]) == ([], "malformed")
    assert "tolerated_failure" not in moved and link.counts(EXPORT) is None


def test_projection_that_fails_for_the_carried_records_leaves_the_failure_standing(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices, link.guests.devices = (KITCHEN,), (CAMERA,)
    link.run()
    project = owner.project_records
    projected: list[str] = []

    def refusing(config: Config, item: Any, records: Any, *rest: Any) -> tuple[Record, ...]:
        projected.append(item.id)
        if item.id == IMPORT:
            raise RuntimeError("unexpected")
        return project(config, item, records, *rest)

    monkeypatch.setattr(owner, "project_records", refusing)
    link.raising[AIRPLAY] = unfinished
    failed = link.run()
    # The carry was tried and failed: the scan's own reason stands, the sibling is whole.
    assert projected == [IMPORT, EXPORT]
    assert (failed[IMPORT]["records"], failed[IMPORT]["reason"]) == ([], "malformed")
    assert "tolerated_failure" not in failed[IMPORT] and link.counts() is None
    assert names(failed[EXPORT]) == ["Camera"] and "reason" not in failed[EXPORT]


def test_carried_records_stay_within_the_record_bound(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    bounded = replace(
        leased(config),
        discovery=tuple(replace(item, max_records=2) for item in leased(config).discovery),
    )
    link = Link(monkeypatch, bounded, counting(settings))
    link.lan.devices = (KITCHEN, STUDY)
    link.requested()
    seen = link.run()[IMPORT]
    failed = link.failed()[IMPORT]
    assert failed["records"] == seen["records"] and len(failed["records"]) == 2
    request = link.store.read("requests.json")["policies"][IMPORT]
    arguments = (observed(bounded, link.clock.now), Intent(), READY, link.clock.now)
    assert (
        len(owner.lease_records(bounded, policy(bounded), request, failed, *arguments) or ()) == 2
    )
    # The carry takes the bound from the pass, like a completed pass that read nothing:
    # of three remembered sources two are carried, the fewest misses first.
    item = policy(bounded)
    interface = bounded.scope(item.scope).interface
    model = (b"model=AudioAccessory5,1",)
    sources = {
        (device.name, AIRPLAY): (
            Record(device.name, AIRPLAY, device.host, 7000, address, model, interface, START),
            misses,
        )
        for device, address, misses in (
            (KITCHEN, "192.0.2.81", 1),
            (STUDY, "192.0.2.82", 0),
            (replace(KITCHEN, name="Third speaker", host="third.local."), "192.0.2.83", 1),
        )
    }
    fence = ("digest", "guest", "network")
    memory = owner.MissMemory(3)
    missed = owner.MissedSources(memory, item, fence, sources, START + STEP, 3)
    carried = owner.carried_through(
        bounded, link.settings, item, observed(bounded, START + STEP), READY, START + STEP, missed
    )
    assert sorted(record.name for record in carried) == [KITCHEN.name, STUDY.name]
    assert {key[0]: value[1] for key, value in memory.listed[item.id][1].items()} == {
        KITCHEN.name: 2,
        STUDY.name: 1,
    }


def test_nothing_remembered_means_nothing_carried(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    # The first pass of a scanner fails: there is no memory yet.
    first = link.failed()[IMPORT]
    assert (first["records"], first["reason"]) == ([], "malformed")
    assert "tolerated_failure" not in first
    # A completed pass that lists nothing leaves nothing to carry either.
    empty = link.run()[IMPORT]
    assert empty["records"] == [] and "reason" not in empty and link.counts() == {}
    again = link.failed()[IMPORT]
    assert (again["records"], again["reason"]) == ([], "malformed")
    assert "tolerated_failure" not in again


# What still forgets


def test_skipped_pass_still_forgets(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN,)
    link.run()
    link.ready = frozenset({"camera-web"})
    skipped = link.failed()[IMPORT]
    assert skipped["records"] == [] and "reason" not in skipped
    assert "tolerated_failure" not in skipped and link.counts() is None
    link.ready = READY
    failed = link.failed()[IMPORT]
    assert (failed["records"], failed["reason"]) == ([], "malformed")


def test_pass_that_fails_after_reading_still_withdraws(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN,)
    link.run()
    # Two instances of one name and type: the pass read them and refuses its own result.
    model = (b"model=AudioAccessory5,1",)
    twin = Record(
        KITCHEN.name, AIRPLAY, "twin.local.", 7000, "192.0.2.90", model, "example0", START
    )
    link.reads = {AIRPLAY: (twin, replace(twin, hostname="other.local.", ipv4="192.0.2.91"))}
    refused = link.run()[IMPORT]
    assert (refused["records"], refused["reason"]) == ([], "incomplete")
    assert "tolerated_failure" not in refused and link.counts() is None


@pytest.mark.parametrize(
    "raised",
    [
        lambda: OSError("bindings unreadable"),
        lambda: unfinished("timed-out"),
        lambda: unfinished("malformed"),
    ],
    ids=["unreadable-input", "marked-timed-out", "marked-malformed"],
)
def test_pass_that_fails_as_a_whole_still_forgets(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    raised: Raised,
) -> None:
    policy_config = leased(config)
    own = counting(settings)
    held: list[owner.MissMemory] = []

    def scan_pass(_config: Config, _settings: Any, _store: Store, memory: owner.MissMemory) -> None:
        held.append(memory)
        if len(held) == 1:
            memory.listed[IMPORT] = (("digest", "guest", "network"), {})
            return
        raise raised()

    serving(monkeypatch, policy_config, own, scan_pass, 2)
    assert held[0] is held[1] and held[0].listed == {}
    written = Store(own.state_dir).read("candidates.json")
    assert written["policies"] == {}
    assert written["reason"] == getattr(raised(), "reason", "malformed")


BULKY = (b"model=AudioAccessory5,1", *([b"p" * 255] * 34))


def test_candidate_file_that_does_not_fit_still_empties_its_bulkiest_policy(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    guest = observed(link.config, START).services["camera"].data["ipv4"]
    speakers = tuple(
        Record(
            f"Speaker {number}",
            AIRPLAY,
            f"s{number}.local.",
            7000,
            f"192.0.2.{20 + number}",
            BULKY,
            "example0",
            START,
        )
        for number in range(60)
    )

    def bridges(count: int) -> tuple[Record, ...]:
        return tuple(
            Record(f"Bridge {number}", HAP, "guest.local.", 9443, guest, BULKY, "example0", START)
            for number in range(count)
        )

    link.reads = {AIRPLAY: speakers, HAP: bridges(1)}
    seen = link.run()
    assert len(seen[IMPORT]["records"]) == 60 and len(seen[EXPORT]["records"]) == 1
    # The import's read does not complete: its sixty records are carried, and they fit.
    link.raising[AIRPLAY] = unfinished
    fitting = link.run()[IMPORT]
    assert len(fitting["records"]) == 60 and fitting["tolerated_failure"] == "malformed"
    # The same again while the export has grown: together the carried records
    # and the export's no longer fit the state file.
    link.reads = {HAP: bridges(40)}
    written = link.run()
    assert (written[IMPORT]["records"], written[IMPORT]["reason"]) == ([], "incomplete")
    # Emptied as before: nothing says that a failure was tolerated, and nothing is kept.
    assert "tolerated_failure" not in written[IMPORT] and link.counts() is None
    assert len(written[EXPORT]["records"]) == 40 and "reason" not in written[EXPORT]


# The publisher


def test_publisher_keeps_its_registrations_across_carried_failed_passes(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices, link.guests.devices = (KITCHEN, STUDY), (CAMERA,)
    link.requested()
    link.run()
    assert {key: shown(item) for key, item in link.tick().items()} == {
        IMPORT: ("present", "verified", 2, None),
        EXPORT: ("present", "verified", 1, None),
    }
    clients = list(FakeRegistration.made)
    assert sorted(item.record.name for item in clients) == ["Camera", KITCHEN.name, STUDY.name]
    deadlines = dict(link.manager.deadlines)
    assert set(deadlines.values()) == {MONOTONIC + LEASE}
    for _ in range(2):
        link.failed()
        # Ticks a quarter of a second apart, as the publisher's loop makes them.
        for _tick in range(8):
            assert {key: shown(item) for key, item in link.tick().items()} == {
                IMPORT: ("present", "verified", 2, "malformed"),
                EXPORT: ("present", "verified", 1, None),
            }
            link.clock.now += 0.25
        # No client was closed and none was started: the same three, and the
        # deadline of each carried record is the one of its last sight.
        assert FakeRegistration.made == clients and not any(item.closed for item in clients)
        carried = {key: value for key, value in link.manager.deadlines.items() if IMPORT in key}
        assert carried == {key: value for key, value in deadlines.items() if IMPORT in key}
    # The third failed pass reaches the tolerance: the import is withdrawn.
    link.failed()
    assert {key: shown(item) for key, item in link.tick().items()} == {
        IMPORT: ("unknown", "unobserved", 0, None),
        EXPORT: ("present", "verified", 1, None),
    }
    assert FakeRegistration.made == clients
    assert sorted(item.record.name for item in clients if item.closed) == [
        KITCHEN.name,
        STUDY.name,
    ]


def test_failure_is_visible_while_records_are_carried_and_gone_with_it(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices, link.guests.devices = (KITCHEN,), (CAMERA,)
    link.requested()
    link.run()
    before = link.tick()
    assert all("tolerated_failure" not in item.data for item in before.values())
    link.failed()
    during = link.tick()
    assert during[IMPORT].data["tolerated_failure"] == "malformed"
    assert "tolerated_failure" not in during[EXPORT].data
    # It is all that the failed pass adds to the observation of the pass before.
    assert {**during[IMPORT].data, "tolerated_failure": None} == {
        **before[IMPORT].data,
        "tolerated_failure": None,
    }
    # What the coordinator and an operator read: the owner's own readback.
    readback = owner.readback(link.config, link.settings, link.store, link.clock.now)
    assert shown(readback.profiles[IMPORT]) == ("present", "verified", 1, "malformed")
    answer = owner.endpoint(
        link.config,
        link.settings,
        link.store,
        {
            "protocol_version": 1,
            "operation": "observe",
            "owner": link.settings.owner,
            "config": to_dict(link.config),
        },
    )
    assert answer["result"]["profiles"][IMPORT]["data"]["tolerated_failure"] == "malformed"
    assert "tolerated_failure" not in answer["result"]["profiles"][EXPORT]["data"]
    # The next pass that completes says nothing of it any more.
    link.run()
    after = link.tick()
    assert after[IMPORT].data == {**before[IMPORT].data}
    assert "tolerated_failure" not in link.store.read("candidates.json")["policies"][IMPORT]


def test_tolerated_failure_is_not_shown_for_a_policy_that_is_not_requested(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN,)
    link.run()
    assert link.failed()[IMPORT]["tolerated_failure"] == "malformed"
    # Nothing was requested: nothing is published and no candidate is read.
    assert shown(link.tick()[IMPORT]) == ("absent", "confirmed-absent", 0, None)
    assert FakeRegistration.made == []
    # Requested alone, the import shows it; the export after it, still not
    # requested, shows nothing of its sibling's failure.
    link.requested()
    requests = link.store.read("requests.json")
    del requests["policies"][EXPORT]
    link.store.write("requests.json", requests)
    assert {key: shown(item) for key, item in link.tick().items()} == {
        IMPORT: ("present", "verified", 1, "malformed"),
        EXPORT: ("absent", "confirmed-absent", 0, None),
    }


def leased_candidate(
    link: Link, candidate: dict[str, Any], item_id: str = IMPORT
) -> tuple[Record, ...] | None:
    request = link.store.read("requests.json")["policies"][item_id]
    return owner.lease_records(
        link.config,
        policy(link.config, item_id),
        request,
        candidate,
        link.current(),
        Intent(),
        READY,
        link.clock.now,
    )


def test_candidate_with_a_tolerated_failure_is_leased(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    reason = "malformed"
    link = Link(monkeypatch, leased(config), settings)
    link.lan.devices = (KITCHEN, STUDY)
    link.requested()
    candidate = link.run()[IMPORT]
    plain = leased_candidate(link, candidate)
    assert plain is not None and len(plain) == 2
    assert leased_candidate(link, {**candidate, "tolerated_failure": reason}) == plain
    # Beside the count of instances left out, too.
    assert leased_candidate(link, {**candidate, "tolerated_failure": reason, "skipped": 1}) == plain


@pytest.mark.parametrize(
    "value",
    [
        # The reason of a scan whose own time is used up: no pass writes it here.
        "timed-out",
        "incomplete",
        "local-network-denied",
        "identity-mismatch",
        "unavailable",
        "unobserved",
        "",
        "Malformed",
        "malformed ",
        True,
        False,
        1,
        0,
        1.5,
        None,
        [],
        ["malformed"],
        {},
        {"reason": "malformed"},
    ],
)
def test_candidate_tolerated_failure_is_parsed_strictly(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    link = Link(monkeypatch, leased(config), settings)
    link.lan.devices = (KITCHEN,)
    link.requested()
    candidate = link.run()[IMPORT]
    assert leased_candidate(link, {**candidate, "tolerated_failure": "malformed"}) is not None
    assert leased_candidate(link, {**candidate, "tolerated_failure": value}) is None
    # The publisher withdraws that policy and keeps serving its sibling.
    link.guests.devices = (CAMERA,)
    written = link.run()
    link.store.write(
        "candidates.json",
        {
            **link.store.read("candidates.json"),
            "policies": {**written, IMPORT: {**written[IMPORT], "tolerated_failure": value}},
        },
    )
    assert {key: shown(item) for key, item in link.tick().items()} == {
        IMPORT: ("unknown", "unobserved", 0, None),
        EXPORT: ("present", "verified", 1, None),
    }


def test_candidate_never_carries_a_tolerated_failure_without_a_record(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), settings)
    link.requested()
    empty = link.run()[IMPORT]
    assert empty["records"] == [] and leased_candidate(link, empty) == ()
    # A failure that carried nothing has to stand; it is not read as an empty pass.
    assert leased_candidate(link, {**empty, "tolerated_failure": "malformed"}) is None
    # Nor beside the reason of a failure that stands.
    link.lan.devices = (KITCHEN,)
    listed = link.run()[IMPORT]
    assert leased_candidate(link, {**listed, "tolerated_failure": "malformed"}) is not None
    refused = {**listed, "tolerated_failure": "malformed", "reason": "malformed"}
    assert leased_candidate(link, refused) is None


# A second owner, and one policy beside another


def test_other_discovery_owner_policies_are_not_this_scanner_business(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The export belongs to another discovery owner and states a tolerance of its own.
    foreign = stating(second_owner(leased(config), EXPORT), {EXPORT: 5})
    link = Link(monkeypatch, foreign, counting(settings))
    link.lan.devices, link.guests.devices = (KITCHEN,), (CAMERA,)
    link.requested()
    seen = link.run()
    assert list(seen) == [IMPORT] and list(link.memory.listed) == [IMPORT]
    assert link.guests.asked == []
    failed = link.failed()
    assert list(failed) == [IMPORT] and failed[IMPORT]["tolerated_failure"] == "malformed"
    assert failed[IMPORT]["records"] == seen[IMPORT]["records"]
    assert {key: shown(item) for key, item in link.tick().items()} == {
        IMPORT: ("present", "verified", 1, "malformed")
    }
    assert list(link.store.read("requests.json")["policies"]) == [IMPORT]


def test_each_policy_counts_its_own_failed_passes(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The import states four, the export follows the owner's two.
    link = Link(monkeypatch, stating(leased(config), {IMPORT: 4}), counting(settings, 2))
    link.lan.devices, link.guests.devices = (KITCHEN,), (CAMERA,)
    link.run()
    listed = []
    for _ in range(4):
        link.lan.fail("-B", AIRPLAY, stopped)
        link.guests.fail("-B", HAP, call_failed)
        written = link.run()
        listed.append(
            tuple(
                (
                    names(written[key]),
                    written[key].get("tolerated_failure"),
                    written[key].get("reason"),
                )
                for key in (IMPORT, EXPORT)
            )
        )
    assert listed == [
        (([KITCHEN.name], "malformed", None), (["Camera"], "malformed", None)),
        (([KITCHEN.name], "malformed", None), ([], None, "malformed")),
        (([KITCHEN.name], "malformed", None), ([], None, "malformed")),
        (([], None, "malformed"), ([], None, "malformed")),
    ]


def test_policy_that_states_one_withdraws_at_once_beside_a_policy_that_carries(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, stating(leased(config), {IMPORT: 1}), counting(settings))
    link.lan.devices, link.guests.devices = (KITCHEN,), (CAMERA,)
    seen = link.run()
    link.guests.fail("-B", HAP, stopped)
    failed = link.failed()
    assert (failed[IMPORT]["records"], failed[IMPORT]["reason"]) == ([], "malformed")
    assert "tolerated_failure" not in failed[IMPORT] and list(link.memory.listed) == [EXPORT]
    assert failed[EXPORT]["records"] == seen[EXPORT]["records"]
    assert failed[EXPORT]["tolerated_failure"] == "malformed"

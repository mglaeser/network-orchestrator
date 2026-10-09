"""One instance that cannot be read costs that instance, not its policy.

The fake client answers browse, resolve, address and query commands for a small
network in the formats of Apple's client, `Clients/dns-sd.c` at the revision the
Bonjour guide cites (`mDNSResponder-2881.120.11`); the line numbers in the
comments are that file's. Names, hosts and addresses are synthetic. These are
source-derived contracts, not captures from a host.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.codec import canonical_bytes
from netorch.discovery import Record
from netorch.discovery_plan import discovery_digest
from netorch.model import Config
from netorch.process import OutputLimit, ProcessError, ProcessTimeout, Result
from netorch.state import Intent, Observation, Snapshot
from netorch.storage import Store
from tests.test_bonjour_owner import FakeRegistration, config, policy, publisher, settings, snapshot
from tests.test_bonjour_starting_banner import starting

__all__ = ["config", "settings"]

INTERFACE = "example0"
LAN_INDEX = 7
GUEST_INDEX = 9
AIRPLAY = "_airplay._tcp"
RAOP = "_raop._tcp"
HAP = "_hap._tcp"
STAMP = "22:03:17.123  "  # printtimestamp_F (518): "%2d:%02d:%02d.%03d  "
GUEST = "198.51.100.13"
READY = frozenset({"media-udp", "camera-web"})

Runner = Callable[[list[str], float], Result]
Failure = Callable[[Result], Result]


def rdata(*strings: bytes) -> bytes:
    return b"".join(bytes([len(item)]) + item for item in strings)


MODEL = rdata(b"model=AudioAccessory5,1")


def escaped(label: str) -> str:
    """The daemon's escaped form of a label (mDNSCore/DNSCommon.c:1224-1249, same tag)."""
    out = ""
    for char in label:
        if char in ".\\":
            out += "\\" + char
        elif ord(char) <= 0x20:
            out += f"\\{ord(char):03d}"
        else:
            out += char
    return out


def shown(record: bytes) -> str:
    """ShowTXTRecord (781-813), for the plain strings these tests use."""
    out = ""
    at = 0
    while at < len(record):
        end = at + 1 + record[at]
        if end > len(record):
            # (788): if (end > max) { printf("<< invalid data >>"); break; }
            return out + "<< invalid data >>"
        out += (" " if end > at + 1 else "") + record[at + 1 : end].decode("ascii")
        at = end
    return out


@dataclass(frozen=True)
class Device:
    """One advertised instance and what the daemon currently answers about it."""

    name: str
    host: str
    addresses: tuple[str, ...]
    kind: str = AIRPLAY
    port: int = 7000
    txt: tuple[bytes, ...] = (MODEL,)
    replies: int = 1  # resolve replies; none is a browse entry whose instance is gone

    @property
    def fullname(self) -> str:
        return f"{escaped(self.name)}.{self.kind}.local."


class Client:
    """A fake client for one interface: the devices on it, and commands made to fail."""

    def __init__(
        self, *devices: Device, index: int = LAN_INDEX, waited: list[float] | None = None
    ) -> None:
        self.devices = devices
        self.index = index
        self.failing: dict[tuple[str, str], Failure] = {}
        self.asked: list[tuple[str, str]] = []
        self.waited = waited  # a clock: the seconds spent on commands that got no reply

    def fail(self, operation: str, subject: str, failure: Failure) -> Client:
        self.failing[operation, subject] = failure
        return self

    def __call__(self, argv: list[str], _timeout: float) -> Result:
        operation = next(item for item in ("-B", "-L", "-G", "-Q") if item in argv)
        arguments = argv[argv.index(operation) + 1 :]
        subject = arguments[1] if operation == "-G" else arguments[0]
        self.asked.append((operation, subject))
        body = {"-B": self.browse, "-L": self.resolve, "-G": self.address, "-Q": self.query}[
            operation
        ](*arguments)
        if self.waited is not None and operation != "-B" and STAMP not in body.split(starting())[1]:
            # HandleEvents (1315-1320): without a reply the client leaves through its -t timer.
            self.waited[0] += int(argv[argv.index("-t") + 1])
        # main (2135): printf("Using interface %d\n", opinterface);
        answer = Result(
            0, f"Using interface {self.index}\n{body}".encode("utf-8", "surrogateescape"), b""
        )
        failure = self.failing.get((operation, subject))
        return answer if failure is None else failure(answer)

    def browse(self, kind: str, _domain: str) -> str:
        out = f"Browsing for {kind}.local.\n" + starting()  # main (2157, 2396-2397)
        # browse_reply (763, 768-769): "%s %8X %3d %-20s %-20s %s\n"
        out += f"Timestamp     A/R    Flags  if {'Domain':<20} {'Service Type':<20} Instance Name\n"
        for device in self.devices:
            if device.kind == kind:
                out += STAMP + f"Add {2:8X} {self.index:3d} {'local.':<20} {kind + '.':<20} "
                out += device.name + "\n"
        return out

    def resolve(self, name: str, kind: str, _domain: str) -> str:
        device = next(item for item in self.devices if (item.name, item.kind) == (name, kind))
        out = f"Lookup {name}.{kind}.local.\n" + starting()  # main (2181)
        for reply in range(device.replies):
            # resolve_reply (828, 832): "%s " "can be reached at %s:%u (interface %d)"
            out += STAMP + f"{device.fullname} can be reached at {device.host}:"
            out += f"{device.port + reply} (interface {self.index})\n"
            # resolve_reply (837): the display follows unless the record is one empty string
            if device.txt and len(device.txt[0]) > 1:
                out += shown(device.txt[0]) + "\n"
        return out

    def address(self, _protocol: str, host: str) -> str:
        device = next(item for item in self.devices if item.host == host)
        # addrinfo_reply (1253, 1276): "%-3s  %-9X %c  %3d  %-38s %-44s %d"
        out = starting() + (
            f"Timestamp     {'A/R':>3}  {'Flags':<11}  {'IF':>3}  "
            f"{'Hostname':<38} {'Address':<44} TTL\n"
        )
        for address in device.addresses:
            out += STAMP + f"{'Add':<3}  {0x40000002:<9X} {' '}  {self.index:3d}  "
            out += f"{host:<38} {address:<44} 120\n"
        return out

    def query(self, fullname: str, _rrtype: str, _rrclass: str) -> str:
        device = next(item for item in self.devices if item.fullname == fullname)
        # qr_reply (1115, 1182, 1174, 1188): "%-3s  %-9X %c  %3d  %-29s %-6s %-6s %s", " %02X"
        out = starting() + (
            f"Timestamp     {'A/R':>3}  {'Flags':<11}  {'IF':>3}  "
            f"{'Name':<29} {'Type':<6} {'Class':<6} Rdata\n"
        )
        for record in device.txt:
            out += STAMP + f"{'Add':<3}  {0x40000002:<9X} {' '}  {self.index:3d}  "
            out += f"{fullname:<29} {'TXT':<6} {'IN':<6} {len(record)} bytes:"
            out += "".join(f" {byte:02X}" for byte in record) + "\n"
        return out


KITCHEN = Device("Kitchen speaker", "kitchen.local.", ("192.0.2.81",))
STUDY = Device("Study speaker", "study.local.", ("192.0.2.82",))
ODD = Device("Odd neighbour", "odd.local.", ("192.0.2.83",))

# What one instance's own replies can say that cannot be used. A reply for
# another interface is not among them: it fails the scan (further down).
UNUSABLE = {
    "stale-browse-entry": replace(ODD, replies=0),
    "replies-that-differ": replace(ODD, replies=2),
    "port-zero": replace(ODD, port=0),
    "target-outside-local": replace(ODD, host="odd.home.arpa."),
    "target-not-utf8": replace(ODD, host="odd\udcff.local."),
    "no-address": replace(ODD, addresses=()),
    "two-addresses": replace(ODD, addresses=("192.0.2.83", "192.0.2.84")),
    "no-txt-record": replace(ODD, txt=()),
    "txt-records-that-differ": replace(ODD, txt=(MODEL, rdata(b"model=AudioAccessory6,1"))),
    "txt-shorter-than-declared": replace(ODD, txt=(b"\x05ab",)),
    # An escaped name can be longer than the 255 bytes a record's host name may have.
    "target-longer-than-a-record-allows": replace(
        ODD, host=".".join(["x\\032" * 15] * 5) + ".local."
    ),
}


def scanned(runner: Runner, **keywords: Any) -> tuple[Record, ...]:
    return native.scan(INTERFACE, LAN_INDEX, AIRPLAY, 8, 2, 1000.0, runner, **keywords)


def names(records: tuple[Record, ...]) -> list[str]:
    return [item.name for item in records]


# Confined to one instance: its own replies are well-formed and unusable.


@pytest.mark.parametrize("odd", UNUSABLE.values(), ids=UNUSABLE)
def test_unusable_instance_no_longer_fails_the_healthy_ones(odd: Device) -> None:
    client = Client(KITCHEN, odd, STUDY)
    assert names(scanned(client)) == [KITCHEN.name, STUDY.name]
    # The instances after the odd one were still asked about.
    assert ("-Q", STUDY.fullname) in client.asked
    # The caller is told which instance was left out.
    left_out: list[str] = []
    scanned(Client(KITCHEN, odd, STUDY), skipped=left_out)
    assert left_out == [ODD.name]


def test_scan_that_reads_every_instance_leaves_nothing_out() -> None:
    left_out: list[str] = []
    assert names(scanned(Client(KITCHEN, STUDY), skipped=left_out)) == [KITCHEN.name, STUDY.name]
    assert left_out == []


# At most four instances of one scan are left out; a fifth fails it.


def unusable(count: int, kind: str = AIRPLAY) -> tuple[Device, ...]:
    """Instances of one type, unusable in four ways; a scan asks about them after KITCHEN."""
    label = kind.strip("_").split(".")[0]
    ways: tuple[dict[str, Any], ...] = ({"replies": 0}, {"port": 0}, {"addresses": ()}, {"txt": ()})
    return tuple(
        replace(
            ODD,
            name=f"Odd {label} {number}",
            host=f"odd-{label}-{number}.local.",
            kind=kind,
            **ways[number % len(ways)],
        )
        for number in range(count)
    )


def test_four_unusable_instances_of_one_scan_are_left_out() -> None:
    client = Client(KITCHEN, *unusable(4), STUDY)
    left_out: list[str] = []
    assert names(scanned(client, skipped=left_out)) == [KITCHEN.name, STUDY.name]
    assert left_out == [item.name for item in unusable(4)]


@pytest.mark.parametrize("count", [5, 6])
@pytest.mark.parametrize("listed", [False, True], ids=["plain", "names-asked-for"])
def test_fifth_unusable_instance_fails_the_scan(count: int, listed: bool) -> None:
    # The bound is the scan's own: it holds whether or not the caller asks for the names.
    client = Client(KITCHEN, *unusable(count), STUDY)
    with pytest.raises(native.DiscoveryFailure) as caught:
        scanned(client, **({"skipped": []} if listed else {}))
    assert type(caught.value) is native.DiscoveryFailure and caught.value.reason == "incomplete"
    # The scan ended at the fifth: the names after it were not asked about.
    resolved = [subject for operation, subject in client.asked if operation == "-L"]
    assert resolved == [KITCHEN.name, *(item.name for item in unusable(5))]


def test_invalid_txt_display_of_the_client_is_read_as_display() -> None:
    # ShowTXTRecord (788) prints this for the record that the query then shows to be short.
    reply = STAMP + f"{ODD.fullname} can be reached at {ODD.host}:7000 (interface {LAN_INDEX})\n"
    for display in ("<< invalid data >>", " first=1<< invalid data >>"):
        assert native.resolve_endpoint((reply + display + "\n").encode(), LAN_INDEX)[2] == 7000
    for damaged in ("<< invalid data >>\n" + reply, reply + "<< invalid data >>\nmore\n"):
        with pytest.raises(native.DiscoveryFailure) as caught:
            native.resolve_endpoint(damaged.encode(), LAN_INDEX)
        assert type(caught.value) is native.DiscoveryFailure


def with_line(line: str) -> Failure:
    return lambda answer: replace(answer, stdout=answer.stdout + line.encode() + b"\n")


def without_start_line(answer: Result) -> Result:
    # main (2396-2397): the line the client prints when it enters its event loop
    return replace(answer, stdout=answer.stdout.replace(f"{STAMP}...STARTING...\n".encode(), b""))


def commands(device: Device) -> tuple[tuple[str, str], ...]:
    return (("-L", device.name), ("-G", device.host), ("-Q", device.fullname))


@pytest.mark.parametrize("odd", UNUSABLE.values(), ids=UNUSABLE)
def test_unreadable_line_is_not_passed_over_for_an_unusable_instance(odd: Device) -> None:
    # Every line of an output is read before its instance is left out.
    for operation, subject in commands(odd):
        client = Client(KITCHEN, odd, STUDY).fail(operation, subject, with_line("unexpected line"))
        try:
            scanned(client)
        except native.DiscoveryFailure as failure:
            assert type(failure) is native.DiscoveryFailure
        else:
            # The instance was left out before the scan came to this command.
            assert (operation, subject) not in client.asked


# All but the last case: there each command's own reply is usable.
WITHOUT_REPLY = {
    label: device for label, device in UNUSABLE.items() if not label.startswith("target-longer")
}


@pytest.mark.parametrize("odd", WITHOUT_REPLY.values(), ids=WITHOUT_REPLY)
def test_instance_is_not_left_out_by_a_client_that_never_entered_its_event_loop(
    odd: Device,
) -> None:
    client = Client(KITCHEN, odd, STUDY)
    for operation, subject in commands(odd):
        client.fail(operation, subject, without_start_line)
    with pytest.raises(native.DiscoveryFailure) as caught:
        scanned(client)
    assert type(caught.value) is native.DiscoveryFailure
    # A reply that can be used does not need the line, as before.
    healthy = Client(KITCHEN, STUDY)
    for operation, subject in commands(KITCHEN):
        healthy.fail(operation, subject, without_start_line)
    assert names(scanned(healthy)) == [KITCHEN.name, STUDY.name]


# The scan as a whole: a command that cannot prove itself, or a diagnostic.


def without_interface_line(answer: Result) -> Result:
    return replace(answer, stdout=answer.stdout.split(b"\n", 1)[1])


def with_interface_line_twice(answer: Result) -> Result:
    return replace(answer, stdout=answer.stdout.split(b"\n", 1)[0] + b"\n" + answer.stdout)


def with_suffix(suffix: str) -> Failure:
    # addrinfo_reply (1281, 1283) and qr_reply (1193, 1195) append to the row they print.
    return lambda answer: replace(answer, stdout=answer.stdout[:-1] + suffix.encode() + b"\n")


def timed_out(_answer: Result) -> Result:
    raise ProcessTimeout("command did not complete within its deadline")


def flooded(_answer: Result) -> Result:
    raise OutputLimit("command exceeded its combined output bound")


def for_another_interface(answer: Result) -> Result:
    # The interface a reply names: resolve_reply (832) "(interface %d)", and "%3d" after the
    # flags of addrinfo_reply (1276) and qr_reply (1182).
    stdout = answer.stdout
    for column in ("(interface {})", f"{0x40000002:<9X} {' '}  {{:3d}}  "):
        stdout = stdout.replace(
            column.format(LAN_INDEX).encode(), column.format(LAN_INDEX + 1).encode()
        )
    return replace(answer, stdout=stdout)


COMMAND_FAILURES: dict[str, tuple[Failure, str | None]] = {
    "exit-status": (lambda answer: replace(answer, returncode=1), "malformed"),
    # EXIT_IF_LIBDISPATCH_FATAL_ERROR (246): fprintf(stderr, "Error code %d\n", (E)); exit(0);
    "error-stream": (lambda answer: replace(answer, stderr=b"Error code -65563\n"), "malformed"),
    "interface-not-acknowledged": (without_interface_line, "malformed"),
    "interface-acknowledged-twice": (with_interface_line_twice, "malformed"),
    "line-that-is-no-reply": (with_line("unexpected line"), "malformed"),
    # The scope asked for with -i was not honoured, whichever command shows it.
    "reply-for-another-interface": (for_another_interface, "malformed"),
    # The reader raises the runner's time limit as its own failure, with the
    # reason a scanner pass has always written for it.
    "time-limit": (timed_out, "malformed"),
    "output-bound": (flooded, None),
}
# The diagnostics each command prints for one request.
DIAGNOSTICS: dict[str, dict[str, tuple[Failure, str]]] = {
    "-L": {
        # resolve_reply (830, 831)
        "no-such-record": (with_line(STAMP + ODD.fullname + " No Such Record"), "malformed"),
        "denial": (with_line(STAMP + ODD.fullname + " error code -65570"), "local-network-denied"),
    },
    "-G": {
        "no-such-record": (with_suffix("   No Such Record"), "malformed"),
        "denial": (with_suffix("   Error code -65570"), "local-network-denied"),
    },
    "-Q": {
        "no-such-record": (with_suffix("    No Such Record"), "malformed"),
        "denial": (with_suffix("    No Authorization"), "local-network-denied"),
    },
}
SUBJECT = {"-L": ODD.name, "-G": ODD.host, "-Q": ODD.fullname}
CASES = [
    (operation, failure, reason)
    for operation in ("-L", "-G", "-Q")
    for failure, reason in [*COMMAND_FAILURES.values(), *DIAGNOSTICS[operation].values()]
]
CASE_IDS = [
    f"{operation}-{label}"
    for operation in ("-L", "-G", "-Q")
    for label in [*COMMAND_FAILURES, *DIAGNOSTICS[operation]]
]


@pytest.mark.parametrize("operation,failure,reason", CASES, ids=CASE_IDS)
def test_command_that_cannot_prove_itself_still_fails_the_scan(
    operation: str, failure: Failure, reason: str | None
) -> None:
    client = Client(KITCHEN, ODD, STUDY).fail(operation, SUBJECT[operation], failure)
    with pytest.raises((native.DiscoveryFailure, ProcessError)) as caught:
        scanned(client)
    # Exactly the scan's own failure, not the one that is confined to an instance.
    assert type(caught.value) in {native.DiscoveryFailure, ProcessTimeout, OutputLimit}
    assert getattr(caught.value, "reason", None) == reason
    # The scan ended there: the next instance was not asked about.
    assert ("-L", STUDY.name) not in client.asked


# resolve_reply (832), naming another interface than the one the scan asked for.
ELSEWHERE = STAMP + f"{ODD.fullname} can be reached at {ODD.host}:7000 (interface {LAN_INDEX + 1})"


@pytest.mark.parametrize(
    "devices,failure",
    [
        ((ODD,), for_another_interface),
        ((KITCHEN, ODD, STUDY), with_line(ELSEWHERE)),
        ((KITCHEN, replace(ODD, host="odd\udcff.local."), STUDY), for_another_interface),
        # These two failed the scan before as well, by the line that is missing or added.
        ((KITCHEN, ODD, STUDY), lambda answer: without_start_line(for_another_interface(answer))),
        (
            (KITCHEN, ODD, STUDY),
            lambda answer: with_line("unexpected line")(for_another_interface(answer)),
        ),
    ],
    ids=[
        "on-its-own",
        "beside-a-reply-for-the-scanned-interface",
        "with-names-that-are-not-utf8",
        "without-start-line",
        "with-an-unreadable-line",
    ],
)
def test_resolve_reply_for_another_interface_fails_the_scan_whatever_comes_with_it(
    devices: tuple[Device, ...], failure: Failure
) -> None:
    # Beside healthy instances and nothing else: the case of the table above.
    client = Client(*devices).fail("-L", ODD.name, failure)
    with pytest.raises(native.DiscoveryFailure) as caught:
        scanned(client)
    assert type(caught.value) is native.DiscoveryFailure and caught.value.reason == "malformed"
    # The scan ended with that reply: nothing further was asked.
    assert client.asked[-1] == ("-L", ODD.name)


@pytest.mark.parametrize(
    "client,limit,reason",
    [
        (Client(KITCHEN, ODD, STUDY), 2, "incomplete"),
        (Client(KITCHEN, replace(ODD, name="Odd\tneighbour")), 8, "malformed"),
        # browse_reply (763-766) prints its heading, then "Error code %d" in place of a row.
        (
            Client().fail("-B", AIRPLAY, with_line(STAMP + "Error code -65570")),
            8,
            "local-network-denied",
        ),
        (Client(KITCHEN).fail("-B", AIRPLAY, without_interface_line), 8, "malformed"),
    ],
    ids=["more-names-than-the-bound", "name-that-cannot-be-passed-on", "denial", "interface"],
)
def test_failed_browse_still_fails_the_scan(client: Client, limit: int, reason: str) -> None:
    with pytest.raises(native.DiscoveryFailure) as caught:
        native.scan(INTERFACE, LAN_INDEX, AIRPLAY, limit, 2, 1000.0, client)
    assert type(caught.value) is native.DiscoveryFailure and caught.value.reason == reason
    assert all(operation == "-B" for operation, _subject in client.asked)


def test_used_up_time_budget_still_fails_the_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [100.0]
    monkeypatch.setattr(native.time, "monotonic", lambda: clock[0])
    client = Client(KITCHEN, replace(ODD, replies=0), STUDY)

    def runner(argv: list[str], timeout: float) -> Result:
        answer = client(argv, timeout)
        if "-L" in argv and ODD.name in argv:
            clock[0] += 60  # more than the scan's 45 seconds
        return answer

    with pytest.raises(native.DiscoveryFailure) as caught:
        scanned(runner)
    assert type(caught.value) is native.DiscoveryFailure and caught.value.reason == "timed-out"


# Addresses: an export reads the inspected guest address among several.


def address_rows(host: str, *events: tuple[str, str]) -> bytes:
    out = f"Using interface {GUEST_INDEX}\n" + starting()
    for op, address in events:
        out += STAMP + f"{op:<3}  {0x40000002:<9X} {' '}  {GUEST_INDEX:3d}  "
        out += f"{host:<38} {address:<44} 120\n"
    return out.encode()


def test_export_reads_the_guest_address_among_several() -> None:
    raw = address_rows("camera.local.", ("Add", "192.0.2.10"), ("Add", GUEST))
    assert native.resolve_ipv4(raw, "camera.local.", GUEST_INDEX, GUEST) == GUEST
    # One address that is not the guest's is returned as before; the projection drops it.
    foreign = address_rows("camera.local.", ("Add", "198.51.100.77"))
    assert native.resolve_ipv4(foreign, "camera.local.", GUEST_INDEX, GUEST) == "198.51.100.77"


@pytest.mark.parametrize(
    "events,guest",
    [
        ((("Add", "192.0.2.10"), ("Add", GUEST)), None),
        ((("Add", "192.0.2.10"), ("Add", "198.51.100.77")), GUEST),
        ((("Add", "192.0.2.10"), ("Add", GUEST), ("Rmv", GUEST), ("Add", "198.51.100.77")), GUEST),
        ((), GUEST),
        ((("Add", GUEST), ("Rmv", GUEST)), GUEST),
    ],
    ids=["import", "guest-not-among-them", "guest-address-removed", "none", "none-left"],
)
def test_ambiguous_or_missing_address_is_unusable_for_the_instance(
    events: tuple[tuple[str, str], ...], guest: str | None
) -> None:
    raw = address_rows("camera.local.", *events)
    with pytest.raises(native.DiscoveryFailure) as caught:
        native.resolve_ipv4(raw, "camera.local.", GUEST_INDEX, *([] if guest is None else [guest]))
    assert caught.value.reason == "incomplete"
    assert type(caught.value) is native.InstanceUnusable


# The owner: the healthy records are leased, and the count is shown.


def networks(config: Config, monkeypatch: pytest.MonkeyPatch, lan: Client, guests: Client) -> None:
    """Let the owner's scanner run the real reader against two fake networks."""
    current = snapshot(config)
    clock = type(
        "Clock", (), {"time": staticmethod(lambda: 1000), "monotonic": staticmethod(lambda: 10)}
    )()
    monkeypatch.setattr(owner, "time", clock)
    monkeypatch.setattr(owner, "independent_snapshot", lambda *_args: (current, Intent(), READY))
    monkeypatch.setattr(
        owner, "_interfaces", lambda *_args: {"wired-lan": (LAN_INDEX, GUEST_INDEX)}
    )

    def scan(interface: str, index: int, *arguments: Any, **keywords: Any) -> tuple[Record, ...]:
        runner = lan if index == LAN_INDEX else guests
        return native.scan(interface, index, *arguments, runner, **keywords)

    monkeypatch.setattr(owner, "scan", scan)


def scan_pass(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    lan: Client,
    guests: Client,
) -> dict[str, dict[str, Any]]:
    """One real scanner pass over the two networks; the candidate of each policy."""
    networks(config, monkeypatch, lan, guests)
    store = Store(settings.state_dir)
    owner.scan_pass(config, settings, store)
    candidates: dict[str, dict[str, Any]] = store.read("candidates.json")["policies"]
    return candidates


def tick(
    config: Config, settings: owner.BonjourSettings, kept: owner.Publisher | None = None
) -> dict[str, Observation]:
    """Request every policy and let the publisher lease what the pass wrote.

    ``kept`` is a publisher that still holds the registrations of an earlier pass.
    """
    current = snapshot(config)
    store = Store(settings.state_dir)
    requests = {
        item.id: {
            "active": True,
            "policy_digest": discovery_digest(config, item),
            "service_generation": current.services[item.service].generation,
            "network_generation": current.network_generation,
            "requested_at": 1000,
        }
        for item in config.discovery
    }
    store.write("requests.json", {"schema_version": 1, "policies": requests})
    proof = (current, Intent(), READY, {"wired-lan": (LAN_INDEX, GUEST_INDEX)})
    observed = owner.publisher_tick(config, settings, store, kept or publisher(), proof, 0, 1000)
    return dict(observed.profiles)


def camera(*addresses: str, name: str = "Camera") -> Device:
    return Device(name, "camera.local.", addresses, kind=HAP, port=9443, txt=(rdata(b"c#=1"),))


# Another guest on the same network, itself with two addresses.
OTHER_GUEST = replace(camera("198.51.100.77", "192.0.2.10"), name="Other", host="other.local.")


def test_stale_neighbour_no_longer_withdraws_the_policy(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    lan = Client(KITCHEN, UNUSABLE["stale-browse-entry"], STUDY)
    candidates = scan_pass(config, settings, monkeypatch, lan, Client(index=GUEST_INDEX))
    candidate = candidates["media-import"]
    assert "reason" not in candidate and candidate["skipped"] == 1
    assert [item["name"] for item in candidate["records"]] == [KITCHEN.name, STUDY.name]
    observed = tick(config, settings)
    imported = observed["media-import"]
    assert (imported.state, imported.reason) == ("present", "verified")
    assert (imported.data["record_count"], imported.data["skipped_count"]) == (2, 1)
    assert sorted(child.record.name for child in FakeRegistration.made) == [
        KITCHEN.name,
        STUDY.name,
    ]
    assert not any(child.closed for child in FakeRegistration.made)
    # The other policy read every instance: no count in its candidate, zero shown.
    assert "skipped" not in candidates["camera-export"]
    assert observed["camera-export"].data["skipped_count"] == 0


def test_failed_command_still_withdraws_the_policy(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    lan = Client(KITCHEN, ODD, STUDY).fail("-G", ODD.host, without_interface_line)
    candidate = scan_pass(config, settings, monkeypatch, lan, Client(index=GUEST_INDEX))[
        "media-import"
    ]
    assert candidate["records"] == [] and candidate["reason"] == "malformed"
    assert "skipped" not in candidate
    observed = tick(config, settings)["media-import"]
    assert (observed.state, observed.reason) == ("unknown", "unobserved")
    assert not FakeRegistration.made


# Nothing is left out unless something was read in the same pass.


def test_pass_in_which_no_resolve_is_answered_withdraws_the_policy(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    everyone = (KITCHEN, ODD, STUDY)
    kept = publisher()
    scan_pass(config, settings, monkeypatch, Client(*everyone), Client(index=GUEST_INDEX))
    assert tick(config, settings, kept)["media-import"].data["record_count"] == 3
    # The browse still lists the three names; none of them answers a resolve.
    silent = Client(*(replace(item, replies=0) for item in everyone))
    candidate = scan_pass(config, settings, monkeypatch, silent, Client(index=GUEST_INDEX))[
        "media-import"
    ]
    assert [subject for operation, subject in silent.asked if operation == "-L"] == [
        item.name for item in everyone
    ]
    assert candidate["records"] == [] and candidate.get("reason") == "incomplete"
    assert "skipped" not in candidate
    observed = tick(config, settings, kept)["media-import"]
    assert (observed.state, observed.reason) == ("unknown", "unobserved")
    assert (observed.data["record_count"], observed.data["skipped_count"]) == (0, 0)
    assert [child.closed for child in FakeRegistration.made] == [True, True, True]


def test_instances_are_left_out_beside_one_that_was_read(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    lan = Client(replace(KITCHEN, replies=0), replace(ODD, replies=0), STUDY)
    candidate = scan_pass(config, settings, monkeypatch, lan, Client(index=GUEST_INDEX))[
        "media-import"
    ]
    assert "reason" not in candidate and candidate["skipped"] == 2
    assert [item["name"] for item in candidate["records"]] == [STUDY.name]
    observed = tick(config, settings)["media-import"]
    assert (observed.state, observed.reason) == ("present", "verified")
    assert (observed.data["record_count"], observed.data["skipped_count"]) == (1, 2)


def test_export_whose_own_instance_alone_is_unusable_is_withdrawn(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    kept = publisher()
    scan_pass(config, settings, monkeypatch, Client(), Client(camera(GUEST), index=GUEST_INDEX))
    assert tick(config, settings, kept)["camera-export"].data["record_count"] == 1
    # The guest's own instance is still browsed and no longer answers; no other was read.
    silent = Client(replace(camera(GUEST), replies=0), index=GUEST_INDEX)
    candidate = scan_pass(config, settings, monkeypatch, Client(), silent)["camera-export"]
    assert candidate["records"] == [] and candidate.get("reason") == "incomplete"
    assert "skipped" not in candidate
    observed = tick(config, settings, kept)["camera-export"]
    assert (observed.state, observed.reason) == ("unknown", "unobserved")
    assert [child.closed for child in FakeRegistration.made] == [True]


def test_instance_that_was_read_counts_before_selection_and_for_any_type(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # What was read is counted, not what is then selected: a related record without
    # its AirPlay record, and another guest's instance, are read and not published.
    lan = Client(replace(KITCHEN, replies=0), replace(STUDY, kind=RAOP))
    other = replace(camera("198.51.100.77"), name="Other", host="other.local.")
    guests = Client(replace(camera(GUEST), replies=0), other, index=GUEST_INDEX)
    candidates = scan_pass(config, settings, monkeypatch, lan, guests)
    observed = tick(config, settings)
    for identifier in ("media-import", "camera-export"):
        candidate = candidates[identifier]
        assert candidate["records"] == [] and "reason" not in candidate
        assert candidate["skipped"] == 1
        assert (observed[identifier].state, observed[identifier].reason) == ("present", "verified")
        assert observed[identifier].data["skipped_count"] == 1


def test_pass_that_reads_every_instance_and_selects_none_stays_present(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Not changed: where nothing is left out, nothing has to be selected either.
    lan = Client(replace(KITCHEN, txt=(rdata(b"model=Example1,1"),)))
    guests = Client(camera("198.51.100.77"), index=GUEST_INDEX)
    candidates = scan_pass(config, settings, monkeypatch, lan, guests)
    observed = tick(config, settings)
    for identifier in ("media-import", "camera-export"):
        candidate = candidates[identifier]
        assert candidate["records"] == [] and not {"reason", "skipped"} & set(candidate)
        assert (observed[identifier].state, observed[identifier].reason) == ("present", "verified")
        assert observed[identifier].data["skipped_count"] == 0


# The bound on instances left out, in the owner: for each type of a policy.


@pytest.mark.parametrize(
    "airplay,raop,reason,skipped",
    [(4, 4, None, 8), (5, 3, "incomplete", None)],
    ids=["four-of-each-of-two-types", "five-of-one-type"],
)
def test_instances_left_out_are_bounded_for_each_type_of_a_policy(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    airplay: int,
    raop: int,
    reason: str | None,
    skipped: int | None,
) -> None:
    # Eight instances are unusable in both cases; what differs is how many of one type.
    lan = Client(KITCHEN, *unusable(airplay), *unusable(raop, RAOP))
    candidate = scan_pass(config, settings, monkeypatch, lan, Client(index=GUEST_INDEX))[
        "media-import"
    ]
    assert candidate.get("reason") == reason and candidate.get("skipped") == skipped
    observed = tick(config, settings)["media-import"]
    if reason is None:
        assert [item["name"] for item in candidate["records"]] == [KITCHEN.name]
        assert (observed.state, observed.data["skipped_count"]) == ("present", 8)
    else:
        assert candidate["records"] == []
        assert (observed.state, observed.reason) == ("unknown", "unobserved")


def test_candidate_with_a_count_always_has_an_instance_that_was_read_behind_it(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Every small network of instances that are gone and instances that answer.
    for read in range(3):
        for gone in range(7):
            lan = Client(
                *(
                    replace(ODD, name=f"Gone {n}", host=f"gone-{n}.local.", replies=0)
                    for n in range(gone)
                ),
                *(replace(KITCHEN, name=f"Read {n}", host=f"read-{n}.local.") for n in range(read)),
            )
            candidate = scan_pass(config, settings, monkeypatch, lan, Client(index=GUEST_INDEX))[
                "media-import"
            ]
            failed = gone > 4 or (gone > 0 and read == 0)
            assert candidate.get("reason") == ("incomplete" if failed else None), (read, gone)
            assert candidate.get("skipped") == (gone if gone and not failed else None), (read, gone)
            assert len(candidate["records"]) == (0 if failed else read), (read, gone)


def test_more_records_than_the_policy_bound_still_withdraw_it(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # One record of each of two types, in a policy that may hold one record.
    related = replace(KITCHEN, kind=RAOP)
    networks(config, monkeypatch, Client(KITCHEN, related), Client(index=GUEST_INDEX))
    bounded = replace(policy(config), max_records=1)
    interfaces = {"wired-lan": (LAN_INDEX, GUEST_INDEX)}
    with pytest.raises(native.DiscoveryFailure) as caught:
        owner.scan_policy(config, settings, bounded, snapshot(config), READY, interfaces, 1000)
    assert type(caught.value) is native.DiscoveryFailure and caught.value.reason == "incomplete"


@pytest.mark.parametrize(
    "guests,records,skipped,reason",
    [
        ((camera(GUEST, "192.0.2.10"),), 1, None, None),
        ((camera(GUEST, "192.0.2.10"), OTHER_GUEST), 1, 1, None),
        # Readiness R-D1: an alias alone, also when read for every reply, leaves
        # the instance out, and with nothing else read the policy is withdrawn.
        ((camera("192.0.2.10"),), 0, None, "incomplete"),
        # Unusable, and no other instance was read in the pass: the policy is withdrawn.
        ((camera("192.0.2.10", "198.51.100.77"),), 0, None, "incomplete"),
    ],
    ids=["guest-and-alias", "another-guest-with-two-addresses", "alias-only", "guest-not-among"],
)
def test_guest_with_a_second_address_is_exported_by_its_guest_address(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    guests: tuple[Device, ...],
    records: int,
    skipped: int | None,
    reason: str | None,
) -> None:
    candidate = scan_pass(
        config, settings, monkeypatch, Client(), Client(*guests, index=GUEST_INDEX)
    )["camera-export"]
    assert candidate.get("reason") == reason and candidate.get("skipped") == skipped
    exported = candidate["records"]
    assert isinstance(exported, list) and len(exported) == records
    if records:
        # What is leased is the verified publication's address and port, not the answer's.
        assert (exported[0]["name"], exported[0]["ipv4"], exported[0]["port"]) == (
            "Camera",
            config.scope("wired-lan").host_ipv4,
            9443,
        )
        assert tick(config, settings)["camera-export"].state == "present"


@pytest.mark.parametrize("second", ["192.0.2.84", "consumer"])
def test_import_keeps_exactly_one_address(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch, second: str
) -> None:
    # No address is preferred for an import, the consuming guest's own included.
    if second == "consumer":
        second = snapshot(config).services[policy(config).service].data["ipv4"]
    lan = Client(KITCHEN, replace(ODD, addresses=(ODD.addresses[0], second)))
    candidate = scan_pass(config, settings, monkeypatch, lan, Client(index=GUEST_INDEX))[
        "media-import"
    ]
    assert [item["name"] for item in candidate["records"]] == [KITCHEN.name]
    assert candidate["skipped"] == 1


def test_pass_that_reads_every_instance_writes_the_candidate_of_before(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidates = scan_pass(
        config,
        settings,
        monkeypatch,
        Client(KITCHEN, STUDY),
        Client(camera(GUEST), index=GUEST_INDEX),
    )
    assert all("skipped" not in candidate for candidate in candidates.values())
    # The discovery digest is versioned separately; everything else is compared
    # with the bytes the scanner wrote for this network before the change.
    for candidate in candidates.values():
        candidate["policy_digest"] = "digest"
    assert hashlib.sha256(canonical_bytes(candidates)).hexdigest() == BEFORE


# SHA-256 of the canonical bytes that the unchanged scanner (0.3.2) wrote for the
# two networks of the test above, with the policy digests replaced as there.
BEFORE = "a6110c4b738291002be2aee3036cb6c7f02e4dfa547054f2392823bf51529e08"


# The example policy has four types: four instances left out for each is its bound.
@pytest.mark.parametrize("value", [1, 2, 4 * 4])
def test_candidate_skip_count_within_its_bound_is_leased(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    value: int,
) -> None:
    assert lease(config, settings, monkeypatch, value) is not None


# Refused among them: the bound of before, one for each name a browse may list (128 * 4).
@pytest.mark.parametrize(
    "value", [0, -1, 4 * 4 + 1, 128 * 4, 128 * 4 + 1, True, 1.0, "1", None, [1]]
)
def test_candidate_skip_count_is_parsed_strictly(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    value: object,
) -> None:
    assert lease(config, settings, monkeypatch, value) is None


@pytest.mark.parametrize("value,leased", [(2 * 4, True), (2 * 4 + 1, False)])
def test_candidate_skip_count_never_exceeds_the_names_a_browse_may_list(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    value: int,
    leased: bool,
) -> None:
    # A browse of a policy that may hold two records lists two names at most.
    small = replace(
        config,
        discovery=tuple(
            replace(item, max_records=2) if item.id == "media-import" else item
            for item in config.discovery
        ),
    )
    assert (lease(small, settings, monkeypatch, value) is not None) is leased


def lease(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    skipped: object,
) -> tuple[Record, ...] | None:
    candidate = scan_pass(
        config, settings, monkeypatch, Client(KITCHEN, STUDY), Client(index=GUEST_INDEX)
    )["media-import"]
    current = snapshot(config)
    item = policy(config)
    assert len(item.types) == 4
    request = {
        "active": True,
        "policy_digest": discovery_digest(config, item),
        "service_generation": current.services[item.service].generation,
        "network_generation": current.network_generation,
        "requested_at": 1000,
    }
    return owner.lease_records(
        config, item, request, {**candidate, "skipped": skipped}, current, Intent(), READY, 1000
    )


# Time: what instances that do not answer cost a pass, and the policy beside them.


def fresh(config: Config, now: float) -> Snapshot:
    """The owners' reports as read at that moment, so that only a candidate's age counts."""
    base = snapshot(config)
    return replace(
        base,
        observed_at=now,
        services={key: replace(item, observed_at=now) for key, item in base.services.items()},
        profiles={key: replace(item, observed_at=now) for key, item in base.profiles.items()},
    )


@pytest.mark.parametrize("silent", [4, 5, 14, 22])
def test_instances_that_do_not_answer_delay_a_pass_by_a_bounded_time(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch, silent: int
) -> None:
    """One clock, advanced by ``scan_seconds`` for every command that gets no reply.

    The scanner scans its policies one after another and writes all candidates
    once, stamped with the time the pass began; then it sleeps ``poll_seconds``.
    Until the next pass has ended, the publisher holds the candidates of this one.
    """
    # The policy beside the slow one: its records may be 60 seconds old.
    config = replace(
        config,
        discovery=tuple(
            replace(item, max_age_seconds=60) if item.id == "camera-export" else item
            for item in config.discovery
        ),
    )
    waited = [0.0]
    gone = tuple(
        Device(f"Gone {number:02d}", f"gone-{number}.local.", ("192.0.2.90",), replies=0)
        for number in range(silent)
    )
    lan = Client(*gone, KITCHEN, STUDY, waited=waited)
    networks(config, monkeypatch, lan, Client(camera(GUEST), index=GUEST_INDEX, waited=waited))
    clock = type(
        "Clock",
        (),
        {
            "time": staticmethod(lambda: 1000 + waited[0]),
            "monotonic": staticmethod(lambda: 10 + waited[0]),
        },
    )()
    monkeypatch.setattr(owner, "time", clock)
    monkeypatch.setattr(native, "time", clock)
    monkeypatch.setattr(
        owner, "independent_snapshot", lambda *_args: (fresh(config, clock.time()), Intent(), READY)
    )
    store = Store(settings.state_dir)

    def leased(candidates: dict[str, Any], identifier: str) -> bool:
        now = clock.time()
        current = fresh(config, now)
        item = policy(config, identifier)
        request = {
            "active": True,
            "policy_digest": discovery_digest(config, item),
            "service_generation": current.services[item.service].generation,
            "network_generation": current.network_generation,
            "requested_at": now,
        }
        records = owner.lease_records(
            config, item, request, candidates[identifier], current, Intent(), READY, now
        )
        return records is not None

    owner.scan_pass(config, settings, store)
    first = store.read("candidates.json")["policies"]
    took = waited[0]
    # Each of them costs one wait, and the fifth ends the scan of its type.
    assert took == min(silent, 5) * settings.scan_seconds
    imported = first["media-import"]
    if silent <= 4:
        assert "reason" not in imported and imported["skipped"] == silent
        assert [item["name"] for item in imported["records"]] == [KITCHEN.name, STUDY.name]
    else:
        assert imported.get("reason") == "incomplete" and "skipped" not in imported
        assert imported["records"] == []
    assert leased(first, "media-import") is (silent <= 4)
    assert leased(first, "camera-export")
    # The scanner sleeps and the next pass takes as long again. Just before that pass
    # replaces them, the candidates of the first are as old as the publisher ever holds them.
    waited[0] += settings.poll_seconds
    owner.scan_pass(config, settings, store)
    assert waited[0] == 2 * took + settings.poll_seconds
    assert leased(first, "media-import") is (silent <= 4)
    assert leased(first, "camera-export")

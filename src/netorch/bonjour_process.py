"""Bounded Apple DNS-SD CLI contracts; no raw multicast or foreign process control.

The maintained system client is the transport adapter. TXT is read through
``-Q TXT`` raw hexadecimal output, never by evaluating its shell-friendly text.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import re
import selectors
import signal
import socket
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass

from .discovery import Record, is_projected_name
from .model import DiscoveryNames
from .process import ProcessTimeout, Result, run

DNS_SD = "/usr/bin/dns-sd"
IFCONFIG = "/sbin/ifconfig"
MAX_OUTPUT = 1_048_576
# The most instances one scan (one type on one interface) leaves out; one more
# fails it. Each instance that does not answer costs a wait of the scan's
# seconds, the scanner writes its candidates and its heartbeat only after the
# whole pass, and a scan in which more than a few instances are unusable is
# not one to trust for the others.
MAX_LEFT_OUT = 4
Runner = Callable[[list[str], float], Result]
# Apple's printtimestamp_F uses %2d for the hour: one padding space before
# 00:00-09:59's single-digit hour, and no padding for 10:00-23:59.
_STAMP = r"(?: [0-9]|1[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}"
# Every dns-sd operation prints this one line, after its timestamp, before it
# enters the event loop: printtimestamp(); printf("...STARTING...\n").
_STARTING = rf"{_STAMP}  \.\.\.STARTING\.\.\."


class DiscoveryFailure(RuntimeError):
    def __init__(
        self, reason: str = "malformed", *, unfinished: bool = False, unanswered: bool = False
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        # True only where a scan's read did not complete (unfinished_read):
        # what one client left is exactly a form the vendor's client gives for
        # a daemon that is not running, or it was stopped at its own time limit
        # before it had shown a reply. What a reader refuses in an answer that
        # it read is never marked, and neither is a denial, any other error
        # code or a scan whose own time is used up.
        self.unfinished = unfinished
        # True only where no instance this failure concerns answered at all: an
        # instance left out because its resolve printed no reply line, or a scan
        # that stopped at its fifth such instance before it had read one.
        self.unanswered = unanswered


class RegistrationExpired(DiscoveryFailure):
    """One client ended on its own ``-t`` timer; every other exit is a failure."""

    def __init__(self) -> None:
        super().__init__("unavailable")


def command(argv: list[str], timeout: float) -> Result:
    return run(argv, timeout=timeout, max_output=MAX_OUTPUT)


def interface_index(interface: str, expected_ipv4: str, runner: Runner = command) -> int:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", interface):
        raise DiscoveryFailure("identity-mismatch")
    ipaddress.IPv4Address(expected_ipv4)
    result = runner([IFCONFIG, interface], 2.0)
    if result.returncode or result.stderr:
        raise DiscoveryFailure("unavailable")
    lines = result.stdout.decode("ascii", errors="strict").splitlines()
    if not lines or not lines[0].startswith(interface + ":"):
        raise DiscoveryFailure("identity-mismatch")
    addresses = [line.split()[1] for line in lines if line.strip().startswith("inet ")]
    if addresses.count(expected_ipv4) != 1:
        raise DiscoveryFailure("identity-mismatch")
    try:
        index = socket.if_nametoindex(interface)
    except OSError as exc:
        raise DiscoveryFailure("unavailable") from exc
    if index <= 0:
        raise DiscoveryFailure("identity-mismatch")
    return index


def _lines(raw: bytes) -> list[bytes]:
    """Every format string of the client ends its line with a line feed only.

    A carriage return or any other separator in the output is data: browse
    replies carry the instance label unescaped.
    """
    lines = raw.split(b"\n")
    if not lines[-1]:
        lines.pop()
    return lines


def _refused(line: bytes, denial: bytes) -> DiscoveryFailure:
    """A line that is neither a banner nor a well-formed reply of its operation.

    It is the client's denial only in the form in which that operation prints
    one after a timestamp; anything else is damage. Replies are data and are
    never searched for the words of a diagnostic.
    """
    if re.fullmatch(_STAMP.encode() + b"  " + denial, line) is not None:
        return DiscoveryFailure("local-network-denied")
    return DiscoveryFailure()


def confirmed_output(result: Result, index: int) -> bytes:
    """An exit status alone never proves that the requested interface was used.

    Replies belong to the parser of the operation that was run. Words of a
    diagnostic are searched here only where no reply can be: in the error
    stream and in what the client prints before its event loop, that is before
    the first timestamp. There the two lines that echo the arguments
    ("Browsing for %s%s%s", "Lookup %s.%s.%s") are not searched either.
    """
    lines = _lines(result.stdout)
    replies = next(
        (at for at, line in enumerate(lines) if re.match(_STAMP.encode(), line)), len(lines)
    )
    searched = b"\n".join(
        [line for line in lines[:replies] if not line.startswith((b"Browsing for ", b"Lookup "))]
        + [result.stderr]
    )
    if b"No Authorization" in searched or b"-65570" in searched:
        raise DiscoveryFailure("local-network-denied")
    if (
        result.returncode
        or result.stderr
        or index <= 0
        or len(result.stdout) + 1 + len(result.stderr) > MAX_OUTPUT
        or lines.count(f"Using interface {index}".encode()) != 1
        or re.search(
            rb"(?:DNSService[^\n]*(?:failed|error)|[Ee]rror code|No Such Record|Unknown interface)",
            searched,
        )
    ):
        raise DiscoveryFailure("malformed")
    return result.stdout


# How main() names the call of each operation a scan runs, and how many
# arguments scan() gives that operation: Clients/dns-sd.c lines 2158 (-B), 2183
# (-L), 2314 (-G) and 2225 (-Q) at the tag the owner guide cites
# (mDNSResponder-2881.120.11), as every line number below.
_CALLS = {
    "-B": (b"DNSServiceBrowse", 2),
    "-L": (b"DNSServiceResolve", 3),
    "-G": (b"DNSServiceGetAddrInfo", 2),
    "-Q": (b"DNSServiceQueryRecord", 3),
}
# Seconds of a scan's own time that must be left beyond a command's time limit
# for that limit to be the command's own (scan). The scan's time and the
# scanner's wait for the scan end within moments of each other, and a scan
# whose time is used up is no miss whichever of them notices it: with this
# room no failure that is marked is raised that late.
_BUDGET_ROOM = 1.0
# printtimestamp_F (515): the date line that comes with the first timestamp.
_DATE = (
    rb"DATE: ---(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:0[1-9]|[12][0-9]|3[01]) "
    rb"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4}---"
)


def unfinished_read(
    args: list[str], index: int, status: int | None, stdout: bytes, stderr: bytes
) -> bool:
    """Whether what one client left is a read that did not complete, and nothing else.

    A closed list of forms, each compared exactly with what the vendor's client
    prints. ``args`` is the operation and its arguments as scan() passes them,
    ``status`` the client's exit status, or None for a client that the runner
    stopped at its time limit, with what it had written by then. Any other
    status, error code, text on the error stream or text on standard output is
    not on the list, and neither is an interface that was not verified.
    """
    call, arguments = _CALLS.get(args[0] if args else "", (b"", 0))
    if not call or len(args) != 1 + arguments or type(index) is not int or index <= 0:
        return False
    # main() prints the interface line (2135), then the line of the operation
    # (2157 for -B, 2181 for -L, none for -G and -Q), then makes its call.
    head = f"Using interface {index}\n".encode()
    if args[0] == "-B":
        head += os.fsencode(f"Browsing for {args[1]}.{args[2]}\n")
    elif args[0] == "-L":
        head += os.fsencode(f"Lookup {args[1]}.{args[2]}.{args[3]}\n")
    # Once the call has succeeded it prints the start line with the first
    # timestamp (515, 518, 2396-2397) and waits for replies.
    waiting = (
        re.fullmatch(re.escape(head) + _DATE + b"\n" + _STARTING.encode() + b"\n", stdout)
        is not None
    )
    if status is None:
        # Stopped at its time limit without a reply. The client flushes its
        # standard output only in a reply callback (772, 843, 1211 and 1289
        # for these operations) and at exit, so until then it has shown
        # nothing; where its output was flushed, it is these banners.
        return not stderr and (not stdout or stdout == head or waiting)
    if status == 255:
        # The daemon is not running: the call fails, and main() reports it on
        # the error stream and returns -1 (2390-2394).
        return stdout == head and stderr == call + b" failed -65563 (Service Not Running)\n"
    # The daemon stopped while the client waited: the reply callback ends the
    # client before it prints anything for that reply (245-246, called at 761,
    # 824, 1111 and 1249).
    return status == 0 and waiting and stderr == b"Error code -65563\n"


def browse_names(raw: bytes, service_type: str, index: int, limit: int) -> tuple[str, ...]:
    """Strictly parse current Add/Rmv rows for exactly one type and interface."""
    pattern = re.compile(
        rf"^{_STAMP}  (Add|Rmv) ( {{0,7}}[0-9A-F]{{1,8}}) ( {{0,2}}[0-9]+) "
        rf"{re.escape('local.'.ljust(20))} {re.escape((service_type + '.').ljust(20))} (.+)$"
    )
    active: set[str] = set()
    replied = False  # a reply was read: the client's banners are all behind it
    listed = False  # a row was read: a later line may be the rest of its name
    clock = ""  # the last timestamp read
    dated = False  # a date line after a timestamp: the day has to have changed
    # browse_reply uses fixed-width columns, then an unescaped instance label.
    # Splitting after Unicode decoding would treat valid U+0085/U+2028 labels
    # as new lines; greedy whitespace would merge distinct "Name"/" Name".
    for raw_line in _lines(raw):
        line = raw_line.decode("utf-8", errors="strict")
        stamped = re.match(rf"^{_STAMP}\s", line) is not None
        # printtimestamp_F repeats "DATE: ---%s---" only when the day differs
        # from the one it printed last, directly before that day's timestamp.
        # The width of the timestamp is fixed, so its text orders like the time.
        if dated and not (stamped and line[:12] < clock):
            raise DiscoveryFailure()
        dated = False
        if stamped:
            clock = line[:12]
            if re.fullmatch(_STARTING, line):
                if replied:
                    raise DiscoveryFailure()
                continue
            replied = True
            match = pattern.fullmatch(line)
            if match is None or match[2] != f"{int(match[2], 16):8X}" or match[3] != f"{index:3d}":
                # browse_reply prints "Error code %d" in place of a row. After a
                # row the same bytes can be the rest of a name that holds a line
                # feed, so they are the client's denial only before any row.
                raise DiscoveryFailure() if listed else _refused(raw_line, b"Error code -65570")
            listed = True
            name = match[4]
            # RegisterService reads the name "." as the empty one and registers
            # the computer's own name, so that label can never be passed on.
            if (
                not name
                or name == "."
                or len(name.encode()) > 63
                or any(ord(char) < 32 for char in name)
            ):
                raise DiscoveryFailure()
            if match[1] == "Add":
                active.add(name)
            else:
                active.discard(name)
            if len(active) > limit:
                raise DiscoveryFailure("incomplete")
        elif line.startswith("DATE: ---") and line.endswith("---"):
            dated = bool(clock)
        elif replied or not (
            line == f"Using interface {index}"
            or line == f"Browsing for {service_type}.local."
            or " ".join(line.split()) == "Timestamp A/R Flags if Domain Service Type Instance Name"
        ):
            # main() and the first browse_reply print these before any reply; a
            # line after a row that is no reply is the rest of that row's name.
            raise DiscoveryFailure()
    if dated:
        raise DiscoveryFailure()
    return tuple(sorted(active))


def _banner(line: bytes, index: int, heading: bytes | None = None) -> bool:
    """Only the fixed native interface/date/start/table banners are non-callbacks."""
    return (
        line == f"Using interface {index}".encode()
        or re.fullmatch(_STARTING.encode(), line) is not None
        or re.fullmatch(
            rb"DATE: ---(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
            rb"(?:0[1-9]|[12][0-9]|3[01]) "
            rb"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4}---",
            line,
        )
        is not None
        or (heading is not None and b" ".join(line.split()) == heading)
    )


class InstanceUnusable(DiscoveryFailure):
    """What one instance's own well-formed replies say cannot be used.

    Raised only by a reader whose command has proved itself: its status, error
    stream and interface line were accepted, it is seen to have entered its
    event loop, and every line of its output was a banner or a well-formed
    reply. It is the one failure a scan confines to the instance it concerns;
    every other failure still fails the scan.
    """


def _unusable(
    raw: bytes, reason: str = "malformed", *, unanswered: bool = False
) -> DiscoveryFailure:
    """The failure for replies that were all read and give no usable value.

    Without the start line the client has not shown that it waited for a
    reply, and the command fails as it did before; only an instance that it
    waited for can be one that did not answer.
    """
    if re.search(rb"(?m)^" + _STARTING.encode() + rb"$", raw) is None:
        return DiscoveryFailure(reason)
    return InstanceUnusable(reason, unanswered=unanswered)


def resolve_endpoint(raw: bytes, index: int) -> tuple[str, str, int]:
    """The one endpoint the resolve replies name.

    No reply (a browse entry whose instance is gone), replies that differ and
    a port or target that cannot be published are unusable for that instance.
    A reply for another interface is not confined to it: the command was asked
    for one interface, and it fails, as it does for such an address or TXT row.
    """
    pattern = re.compile(
        rf"^{_STAMP}\s+(.+?) can be reached at ([^\s:]+):(\d+) "
        rf"\(interface (\d+)\)(?: Flags: [0-9A-Fa-f]+)?$".encode()
    )
    unique = set()
    continuation = False
    for line in _lines(raw):
        match = pattern.fullmatch(line)
        if match is not None:
            # A reply for another interface means that the scope asked for was
            # not honoured. That concerns the scan as a whole.
            if int(match[4]) != index:
                raise DiscoveryFailure()
            try:
                unique.add(
                    (
                        match[1].decode("utf-8"),
                        match[2].decode("utf-8"),
                        int(match[3]),
                    )
                )
            except UnicodeError:
                # Names that are not UTF-8: a reply that can never be used. It
                # is kept as one, so that the rest of the output is still read.
                unique.add(("", "", 0))
            continuation = True
        elif _banner(line, index) or re.fullmatch(
            rb"Lookup .+\._[A-Za-z0-9-]+\._(?:tcp|udp)\.local\.", line
        ):
            continuation = False
        elif (
            continuation
            and (not line or line.startswith(b" ") or line == b"<< invalid data >>")
            and all(byte >= 32 for byte in line)
            and re.match(rb"^ *[0-9]{1,2}:", line) is None
        ):
            # ShowTXTRecord emits exactly one optional continuation; printable
            # bytes are not necessarily UTF-8. The authoritative TXT query is
            # -Q's hexadecimal RDATA, not this shell-friendly display. For a
            # record shorter than one of its strings declares, the display is
            # or ends with "<< invalid data >>"; -Q then shows why.
            continuation = False
        else:
            # resolve_reply prints "%s error code %d" in place of the row. An
            # escaped full name holds no space, and an error reply may carry
            # none at all; the TXT display never holds two adjacent spaces.
            raise _refused(line, rb"[^ ]* error code -65570")
    if len(unique) != 1:
        # Without any reply line the instance did not answer its resolve at all.
        raise _unusable(raw, unanswered=not unique)
    fullname, host, port = unique.pop()
    if not 1 <= port <= 65535 or not host.endswith(".local."):
        raise _unusable(raw)
    return fullname, host, port


def _ipv4_rows(raw: bytes, hostname: str, index: int) -> set[str]:
    """The addresses an address answer holds after its last Add or Rmv row."""
    pattern = re.compile(
        rf"^{_STAMP}\s+(Add|Rmv)\s+[0-9A-Fa-f]+\s+(\d+)\s+"
        rf"{re.escape(hostname)}\s+([0-9.]+)\s+\d+$"
    )
    active: set[str] = set()
    for raw_line in _lines(raw):
        if _banner(raw_line, index, b"Timestamp A/R Flags IF Hostname Address TTL"):
            continue
        try:
            line = raw_line.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise DiscoveryFailure() from exc
        match = pattern.fullmatch(line)
        if match is None or int(match[2]) != index:
            # addrinfo_reply appends "   Error code %d" to its row.
            raise _refused(raw_line, rb"(?:Add|Rmv) .*   Error code -65570")
        address = str(ipaddress.IPv4Address(match[3]))
        if match[1] == "Add":
            active.add(address)
        else:
            active.discard(address)
    return active


def resolve_ipv4(raw: bytes, hostname: str, index: int, guest_ipv4: str | None = None) -> str:
    """The host's one current IPv4 address.

    An export passes the announcing service's inspected guest address. A host
    that holds that address among several is read as that address: the record
    is tied to the service by it, and what is published comes from the verified
    publication, never from this answer.
    """
    active = _ipv4_rows(raw, hostname, index)
    if guest_ipv4 is not None and guest_ipv4 in active:
        return guest_ipv4
    if len(active) != 1:
        raise _unusable(raw, "incomplete")
    return active.pop()


def resolve_txt(raw: bytes, fullname: str, index: int) -> tuple[bytes, ...]:
    pattern = re.compile(
        rf"^{_STAMP}\s+(Add|Rmv)\s+[0-9A-Fa-f]+\s+(\d+)\s+"
        rf"{re.escape(fullname)}\s+TXT\s+IN\s+(\d+) bytes:?((?: [0-9A-Fa-f]{{2}})*)$"
    )
    active: set[bytes] = set()
    for raw_line in _lines(raw):
        if _banner(raw_line, index, b"Timestamp A/R Flags IF Name Type Class Rdata"):
            continue
        try:
            line = raw_line.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise DiscoveryFailure() from exc
        match = pattern.fullmatch(line)
        if match is None or int(match[2]) != index:
            # qr_reply appends "    No Authorization" to its row.
            raise _refused(raw_line, rb"(?:Add|Rmv) .*    No Authorization")
        data = bytes.fromhex(match[4])
        if len(data) != int(match[3]) or len(data) > 8900:
            raise DiscoveryFailure()
        if match[1] == "Add":
            active.add(data)
        else:
            active.discard(data)
    if len(active) != 1:
        raise _unusable(raw, "incomplete")
    data = active.pop()
    entries = []
    offset = 0
    while offset < len(data):
        size = data[offset]
        offset += 1
        # The record is shorter than one of its strings declares.
        if offset + size > len(data):
            raise _unusable(raw)
        entries.append(data[offset : offset + size])
        offset += size
    return tuple(entries)


def deadline_after(seconds: float) -> float:
    """The moment ``seconds`` from now on the monotonic clock that a scan reads."""
    return time.monotonic() + seconds


@dataclass(frozen=True, slots=True)
class SecondRead:
    """What an export needs to read a host's address once more (scan).

    ``guest_ipv4`` is the inspected guest address and ``guest_network`` the
    network of which the runtime gives each guest one address. ``ports`` are
    the guest ports that the policy's verified publications can export for the
    scanned type and ``names`` the projection prefixes of the loop exclusion.
    ``scanner_deadline`` is the moment, on the clock the scan reads
    (deadline_after), at which the scanner stops waiting for the scan.
    """

    guest_ipv4: str
    guest_network: ipaddress.IPv4Network
    ports: frozenset[int]
    names: DiscoveryNames
    scanner_deadline: float


def scan(
    interface: str,
    index: int,
    service_type: str,
    limit: int,
    seconds: int,
    now: float,
    runner: Runner = command,
    max_seconds: float = 45,
    *,
    guest_ipv4: str | None = None,
    second_read: SecondRead | None = None,
    skipped: list[str] | None = None,
    unanswered: list[str] | None = None,
) -> tuple[Record, ...]:
    """Browse one type and resolve each instance; a failed command fails the scan.

    Only an instance whose own replies are unusable is left out, and its name
    is added to ``skipped``; also to ``unanswered`` where its resolve printed
    no reply line at all. At most MAX_LEFT_OUT are left out; one more fails
    the scan, marked ``unanswered`` where none of them answered and nothing
    was read before. ``guest_ipv4`` is the export rule of resolve_ipv4; with
    ``second_read`` an export reads an address a second time where its first
    answer may be part of the guest's (read_address()).
    """
    deadline = time.monotonic() + max_seconds

    def room(remaining: float) -> bool:
        # The time limit is the command's own only while the scan's time has
        # room for it and _BUDGET_ROOM more. With less the scan's time is used
        # up, and that is never a read that did not complete: not in a command
        # that ends then, not in query() where no time is left, and not where
        # the scanner stops waiting for the scan.
        return remaining >= seconds + 1.0 + _BUDGET_ROOM

    def query(args: list[str], *, every_reply: bool = False) -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DiscoveryFailure("timed-out")
        # With -m the client leaves after its first reply that is not marked
        # as followed by more (841-844, 1209-1212 and 1287-1290). A browse, and
        # a read of every reply, run until the client's own -t timer (1315-1320).
        options = [] if args[0] == "-B" or every_reply else ["-m"]
        own = room(remaining)
        try:
            result = runner(
                [DNS_SD, "-t", str(seconds), "-i", interface, *options, *args],
                min(seconds + 1.0, remaining),
            )
        except ProcessTimeout as exc:
            # The bounded runner stopped the client at its time limit. The
            # reason is the one a scanner pass has always written for it; the
            # mark needs what the client had written by then.
            raise DiscoveryFailure(
                "malformed",
                unfinished=own
                and exc.stdout is not None
                and exc.stderr is not None
                and unfinished_read(args, index, None, exc.stdout, exc.stderr),
            ) from exc
        try:
            return confirmed_output(result, index)
        except DiscoveryFailure as failure:
            failure.unfinished = own and unfinished_read(
                args, index, result.returncode, result.stdout, result.stderr
            )
            raise

    def read_address(name: str, host: str, port: int) -> str:
        """The instance's address; for an export, the guest address where its host holds it.

        With -m the client can show one of a host's addresses alone. The
        runtime gives each guest one address of the guest network, and the
        guest address is one of them (the planner refuses any other), so an
        export answer that holds an address of that network names a host of it
        and is read as before. One that holds addresses outside it alone, an
        alias for example, may be the first part of the guest's own answer.
        Where the instance could be exported (its port is one of ``ports``, and
        the loop exclusion does not refuse it), the host is read once more for
        every reply, until the command's own time limit and only where that
        read ends before both the scan's time and the scanner's wait, with
        _BUDGET_ROOM to spare. The instance is then read by the guest address
        where that answer holds it, as before where it holds another address of
        the guest network, and left out otherwise. Every other instance is read
        as before.
        """
        raw = query(["-G", "v4", host])
        rule = second_read
        if rule is None:
            return resolve_ipv4(raw, host, index, guest_ipv4)
        first = _ipv4_rows(raw, host, index)
        if (
            port not in rule.ports
            or not first
            or any(ipaddress.IPv4Address(item) in rule.guest_network for item in first)
            or is_projected_name(rule.names, name, host)
        ):
            return resolve_ipv4(raw, host, index, rule.guest_ipv4)
        clock = time.monotonic()
        remaining = deadline - clock
        if not room(min(remaining, rule.scanner_deadline - clock)):
            # The second read never takes time the scan or the scanner does not
            # have: without room for its whole limit the instance is left out.
            # A scan whose own time is used up still fails as such (query()).
            if remaining <= 0:
                raise DiscoveryFailure("timed-out")
            raise _unusable(raw, "incomplete")
        second = query(["-G", "v4", host], every_reply=True)
        held = _ipv4_rows(second, host, index)
        if rule.guest_ipv4 in held:
            return rule.guest_ipv4
        if not any(ipaddress.IPv4Address(item) in rule.guest_network for item in held):
            raise _unusable(second, "incomplete")
        return resolve_ipv4(raw, host, index, rule.guest_ipv4)

    names = browse_names(query(["-B", service_type, "local."]), service_type, index, limit)
    result: list[Record] = []
    left_out = 0
    silent = 0
    for name in names:
        # query() never raises InstanceUnusable: a command that cannot prove
        # itself, a diagnostic and the scan's time budget end the whole scan.
        try:
            fullname, host, port = resolve_endpoint(
                query(["-L", name, service_type, "local."]), index
            )
            address = read_address(name, host, port)
            txt = resolve_txt(query(["-Q", fullname, "TXT", "IN"]), fullname, index)
            try:
                record = Record(name, service_type, host, port, address, txt, interface, now)
            except ValueError as exc:
                raise InstanceUnusable() from exc
        except InstanceUnusable as exc:
            left_out += 1
            silent += exc.unanswered
            if left_out > MAX_LEFT_OUT:
                raise DiscoveryFailure(
                    "incomplete", unanswered=silent == left_out and not result
                ) from exc
            if skipped is not None:
                skipped.append(name)
            if exc.unanswered and unanswered is not None:
                unanswered.append(name)
            continue
        result.append(record)
    return tuple(result)


def registration_argv(record: Record, lifetime_seconds: int = 120) -> list[str]:
    """Escape every TXT byte in Apple's documented CLI grammar, including NUL."""
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 120:
        raise DiscoveryFailure("incomplete")
    if sum(1 + len(item) for item in record.txt) > 8900:
        raise DiscoveryFailure("incomplete")
    if record.name == ".":
        # RegisterService: "." is a synonym for the empty name, which registers
        # the computer's own name instead of this record's.
        raise DiscoveryFailure("identity-mismatch")
    return [
        DNS_SD,
        "-i",
        record.interface,
        "-t",
        str(lifetime_seconds),
        "-P",
        record.name,
        record.service_type,
        "local.",
        str(record.port),
        record.hostname,
        record.ipv4,
        *("".join(f"\\x{byte:02X}" for byte in entry) for entry in record.txt),
    ]


# ShowTXTRecord puts a backslash before each of these bytes and before NUL.
_TXT_ESCAPED = b" &;`'\"|*?~<>^()[]{}$"


def _echo_line(record: Record) -> bytes:
    """The one line in which the client echoes the arguments of ``registration_argv``.

    RegisterService prints the name, type and domain, the host, the port and,
    where TXT was given, the word TXT and its display (``Clients/dns-sd.c``
    lines 1501-1503 and 1524-1527 at the tag the owner guide cites).
    ShowTXTRecord (lines 781-813) begins each non-empty entry with a space,
    puts a backslash before a shell character and before NUL, writes a
    backslash as four and any other byte below the space as ``\\xHH``.
    """
    line = bytearray(
        f"Registering Service {record.name}.{record.service_type}.local."
        f" host {record.hostname} port {record.port}".encode()
    )
    if record.txt:
        line += b" TXT"
        for entry in record.txt:
            if entry:
                line += b" "
            for byte in entry:
                if byte == 0 or byte in _TXT_ESCAPED:
                    line += b"\\"
                if byte == 0x5C:
                    line += b"\\" * 4
                elif byte >= 0x20:
                    line.append(byte)
                else:
                    line += b"\\\\x%02X" % byte
    return bytes(line)


class Registration:
    """Only this object owns and signals its own spawned client process group."""

    def __init__(self, record: Record, index: int, lifetime_seconds: int = 120) -> None:
        if type(index) is not int or index <= 0:
            raise DiscoveryFailure("identity-mismatch")
        # Validate the entire native request before allocating a selector.
        # Rejected names/TXT/lifetimes otherwise leak one descriptor per retry.
        arguments = registration_argv(record, lifetime_seconds)
        self.record = record
        self.index = index
        self.lifetime_seconds = lifetime_seconds
        self.closed = False
        # Read before the spawn: the client arms its own timer later than this,
        # so it cannot end on that timer earlier than its lifetime from here.
        self.spawned = time.monotonic()
        try:
            self.selector = selectors.DefaultSelector()
        except OSError as exc:
            raise DiscoveryFailure("unavailable") from exc
        try:
            self.process = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
            )
        except OSError as exc:
            self.selector.close()
            raise DiscoveryFailure("unavailable") from exc
        except BaseException:
            self.selector.close()
            raise
        try:
            self.output = bytearray()
            assert self.process.stdout is not None
            os.set_blocking(self.process.stdout.fileno(), False)
            self.selector.register(self.process.stdout, selectors.EVENT_READ)
        except OSError as exc:
            # The child exists but Publisher never received this object. Reap
            # only that owned child before handing its failure to the hold-off.
            self.close()
            raise DiscoveryFailure("unavailable") from exc
        self.started = time.monotonic()
        self.active = False

    def poll(self) -> bool:
        try:
            return self._poll()
        except OSError as exc:
            # OS resource/I/O failures have the same bounded retry policy as
            # a client exit. Programming errors still fail the whole turn.
            raise DiscoveryFailure("unavailable") from exc

    def _poll(self) -> bool:
        if self.closed:
            raise DiscoveryFailure("unavailable")
        # Sampled before the read, so the last line of a client that has ended
        # is in the buffer when its exit is judged.
        status = self.process.poll()
        # A stopped client may have more than one pipe read left. Drain that
        # bounded output before classifying its exit: a trailing conflict or
        # removal must not be hidden behind an earlier clean block.
        while ready := self.selector.select(0):
            progress = False
            for key, _events in ready:
                if len(self.output) > MAX_OUTPUT:
                    raise DiscoveryFailure("unavailable" if status is not None else "incomplete")
                try:
                    chunk = os.read(key.fd, min(65536, MAX_OUTPUT + 1 - len(self.output)))
                except BlockingIOError:
                    continue
                if chunk:
                    self.output.extend(chunk)
                    progress = True
                else:
                    self.selector.unregister(key.fileobj)
                if len(self.output) > MAX_OUTPUT:
                    raise DiscoveryFailure("unavailable" if status is not None else "incomplete")
            if status is None or not progress:
                break
        if status is not None:
            # With -t the client arms dispatch_after(exitTimeout) { exit(0); } when
            # it enters its event loop (Clients/dns-sd.c:1315-1320 at the tag the
            # owner guide cites). Its other exit(0), a daemon that stopped, first
            # prints "Error code %d" on a line of its own (dns-sd.c:245-246).
            # That line goes to stderr, so it can follow a cut stdout line. An
            # unknown interface ends with status 0 as well (dns-sd.c:2104,
            # 2405-2408), and a callback can arrive after the last poll that
            # saw the client running. So the end is that timer's only if the
            # complete output is clean.
            if (
                status == 0
                and time.monotonic() - self.spawned >= self.lifetime_seconds
                and self._clean()
            ):
                raise RegistrationExpired()
            raise DiscoveryFailure("unavailable")
        self.active = self._confirmed()
        if not self.active and time.monotonic() - self.started > 5:
            raise DiscoveryFailure("timed-out")
        return self.active

    def _clean(self) -> bool:
        """Whether the complete output of an ended client passes a running one's checks."""
        # exit(0) flushes whole lines, so an unterminated last line is not the
        # timer's end. With the last newline in place every line is complete,
        # and the checks see the whole output.
        if not self.output.endswith(b"\n"):
            return False
        # A registration prints the interface it was asked to use, once, before
        # anything else (dns-sd.c:2135). Output without that line is not one's.
        if bytes(self.output).splitlines().count(f"Using interface {self.index}".encode()) != 1:
            return False
        try:
            self._confirmed()
        except DiscoveryFailure:
            return False
        return True

    def _confirmed(self) -> bool:
        """Check the output read so far; return whether both names are confirmed.

        A running client fails with the reason raised here. An ended client is
        judged by the same checks but keeps the reason ``unavailable``.
        """
        if len(self.output) > MAX_OUTPUT:
            raise DiscoveryFailure("incomplete")
        text = bytes(self.output)
        # Pipe reads can split a native callback anywhere. A partial final
        # line is not a conflicting registration; retain it until its newline.
        lines = _lines(text[: text.rfind(b"\n") + 1])
        interface_lines = [line for line in lines if line.startswith(b"Using interface ")]
        if interface_lines and interface_lines != [f"Using interface {self.index}".encode()]:
            raise DiscoveryFailure("identity-mismatch")
        expected_service = (
            f"Got a reply for service {self.record.name}."
            f"{self.record.service_type}.local.: Name now registered and active"
        ).encode()
        expected_address = (
            f"Got a reply for record {self.record.hostname}: Name now registered and active"
        ).encode()
        echo = _echo_line(self.record)
        callbacks = []
        searched = []
        pattern = re.compile(rf"^{_STAMP}  (Got a reply for (?:service|record) .+)$".encode())
        for line in lines:
            if line == echo:
                # RegisterService echoes the name, host, port and TXT on this one
                # line. Like a reply, it is data and holds no diagnostic. Only the
                # exact echo is: a diagnostic goes to the error stream and can
                # follow a cut stdout line, so a cut echo is searched like any other.
                continue
            if b"Got a reply for service " in line or b"Got a reply for record " in line:
                callback = pattern.fullmatch(line)
                if callback is None:
                    raise DiscoveryFailure("malformed")
                # reg_reply and MyRegisterRecordCallback end the line with
                # "Error %d"; the name is never the end of a reply.
                if callback[1].endswith(b": Error -65570"):
                    raise DiscoveryFailure("local-network-denied")
                callbacks.append(callback[1])
            else:
                searched.append(line)
        diagnostics = b"\n".join(searched)
        if b"-65570" in diagnostics or b"No Authorization" in diagnostics:
            raise DiscoveryFailure("local-network-denied")
        if re.search(
            rb"(?:DNSService[^\n]*(?:returned|failed)|[Ee]rror code|Unknown interface)",
            diagnostics,
        ):
            raise DiscoveryFailure()
        if any(line not in {expected_service, expected_address} for line in callbacks):
            raise DiscoveryFailure("identity-mismatch")
        return (
            lines.count(f"Using interface {self.index}".encode()) == 1
            and expected_service in callbacks
            and expected_address in callbacks
        )

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        # A reaped child's numeric PID may already have been reused. Never
        # signal a dead client or repeat cleanup using its historical PID.
        if self.process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGTERM)
        try:
            self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=1)
        self.selector.close()
        if self.process.stdout:
            self.process.stdout.close()

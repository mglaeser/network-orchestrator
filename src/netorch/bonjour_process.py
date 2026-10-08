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

from .discovery import Record
from .process import Result, run

DNS_SD = "/usr/bin/dns-sd"
IFCONFIG = "/sbin/ifconfig"
MAX_OUTPUT = 1_048_576
Runner = Callable[[list[str], float], Result]
# Apple's printtimestamp_F uses %2d for the hour: one padding space before
# 00:00-09:59's single-digit hour, and no padding for 10:00-23:59.
_STAMP = r"(?: [0-9]|1[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}"
# Every dns-sd operation prints this one line, after its timestamp, before it
# enters the event loop: printtimestamp(); printf("...STARTING...\n").
_STARTING = rf"{_STAMP}  \.\.\.STARTING\.\.\."


class DiscoveryFailure(RuntimeError):
    def __init__(self, reason: str = "malformed") -> None:
        super().__init__(reason)
        self.reason = reason


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


def _unusable(raw: bytes, reason: str = "malformed") -> DiscoveryFailure:
    """The failure for replies that were all read and give no usable value.

    Without the start line the client has not shown that it waited for a
    reply, and the command fails as it did before.
    """
    if re.search(rb"(?m)^" + _STARTING.encode() + rb"$", raw) is None:
        return DiscoveryFailure(reason)
    return InstanceUnusable(reason)


def resolve_endpoint(raw: bytes, index: int) -> tuple[str, str, int]:
    """The one endpoint the resolve replies name.

    No reply (a browse entry whose instance is gone), replies that differ, a
    reply for another interface and a port or target that cannot be published
    are unusable for that instance.
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
            try:
                unique.add(
                    (
                        match[1].decode("utf-8"),
                        match[2].decode("utf-8"),
                        int(match[3]),
                        int(match[4]),
                    )
                )
            except UnicodeError:
                # Names that are not UTF-8: a reply that can never be used. It
                # is kept as one, so that the rest of the output is still read.
                unique.add(("", "", 0, 0))
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
        raise _unusable(raw)
    fullname, host, port, actual = unique.pop()
    if actual != index or not 1 <= port <= 65535 or not host.endswith(".local."):
        raise _unusable(raw)
    return fullname, host, port


def resolve_ipv4(raw: bytes, hostname: str, index: int, guest_ipv4: str | None = None) -> str:
    """The host's one current IPv4 address.

    An export passes the announcing service's inspected guest address. A host
    that holds that address among several is read as that address: the record
    is tied to the service by it, and what is published comes from the verified
    publication, never from this answer.
    """
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
    skipped: list[str] | None = None,
) -> tuple[Record, ...]:
    """Browse one type and resolve each instance; a failed command fails the scan.

    Only an instance whose own replies are unusable is left out, and its name
    is added to ``skipped``. ``guest_ipv4`` is the export rule of resolve_ipv4.
    """
    deadline = time.monotonic() + max_seconds

    def query(args: list[str]) -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DiscoveryFailure("timed-out")
        options = [] if args[0] == "-B" else ["-m"]
        result = runner(
            [DNS_SD, "-t", str(seconds), "-i", interface, *options, *args],
            min(seconds + 1.0, remaining),
        )
        return confirmed_output(result, index)

    names = browse_names(query(["-B", service_type, "local."]), service_type, index, limit)
    result = []
    for name in names:
        # query() never raises InstanceUnusable: a command that cannot prove
        # itself, a diagnostic and the scan's time budget end the whole scan.
        try:
            fullname, host, port = resolve_endpoint(
                query(["-L", name, service_type, "local."]), index
            )
            address = resolve_ipv4(query(["-G", "v4", host]), host, index, guest_ipv4)
            txt = resolve_txt(query(["-Q", fullname, "TXT", "IN"]), fullname, index)
            try:
                record = Record(name, service_type, host, port, address, txt, interface, now)
            except ValueError as exc:
                raise InstanceUnusable() from exc
        except InstanceUnusable:
            if skipped is not None:
                skipped.append(name)
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


class Registration:
    """Only this object owns and signals its own spawned client process group."""

    def __init__(self, record: Record, index: int, lifetime_seconds: int = 120) -> None:
        if type(index) is not int or index <= 0:
            raise DiscoveryFailure("identity-mismatch")
        self.record = record
        self.index = index
        self.lifetime_seconds = lifetime_seconds
        self.closed = False
        # Read before the spawn: the client arms its own timer later than this,
        # so it cannot end on that timer earlier than its lifetime from here.
        self.spawned = time.monotonic()
        self.process = subprocess.Popen(
            registration_argv(record, lifetime_seconds),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
        )
        self.output = bytearray()
        self.selector = selectors.DefaultSelector()
        assert self.process.stdout is not None
        os.set_blocking(self.process.stdout.fileno(), False)
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.started = time.monotonic()
        self.active = False

    def poll(self) -> bool:
        if self.closed:
            raise DiscoveryFailure("unavailable")
        # Sampled before the read, so the last line of a client that has ended
        # is in the buffer when its exit is judged.
        status = self.process.poll()
        for key, _events in self.selector.select(0):
            chunk = os.read(key.fd, 65536)
            if chunk:
                self.output.extend(chunk)
            else:
                self.selector.unregister(key.fileobj)
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
        expected_service = (
            f"Got a reply for service {self.record.name}."
            f"{self.record.service_type}.local.: Name now registered and active"
        ).encode()
        expected_address = (
            f"Got a reply for record {self.record.hostname}: Name now registered and active"
        ).encode()
        callbacks = []
        searched = []
        pattern = re.compile(rf"^{_STAMP}  (Got a reply for (?:service|record) .+)$".encode())
        for line in lines:
            if line.startswith(b"Registering Service "):
                # RegisterService echoes the name, host, port and TXT on this one
                # line. Like a reply, it is data and holds no diagnostic.
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

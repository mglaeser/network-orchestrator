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


def confirmed_output(result: Result, index: int) -> bytes:
    """An exit status alone never proves that the requested interface was used."""
    joined = result.stdout + b"\n" + result.stderr
    if b"No Authorization" in joined or b"-65570" in joined:
        raise DiscoveryFailure("local-network-denied")
    if (
        result.returncode
        or result.stderr
        or index <= 0
        or len(joined) > MAX_OUTPUT
        or result.stdout.splitlines().count(f"Using interface {index}".encode()) != 1
        or re.search(
            rb"(?:DNSService[^\n]*(?:failed|error)|[Ee]rror code|No Such Record|Unknown interface)",
            joined,
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
    # browse_reply uses fixed-width columns, then an unescaped instance label.
    # Splitting after Unicode decoding would treat valid U+0085/U+2028 labels
    # as new lines; greedy whitespace would merge distinct "Name"/" Name".
    for raw_line in raw.splitlines():
        line = raw_line.decode("utf-8", errors="strict")
        if re.fullmatch(_STARTING, line):
            continue
        if re.match(rf"^{_STAMP}\s", line):
            match = pattern.fullmatch(line)
            if match is None or match[2] != f"{int(match[2], 16):8X}" or match[3] != f"{index:3d}":
                raise DiscoveryFailure()
            name = match[4]
            if not name or len(name.encode()) > 63 or any(ord(char) < 32 for char in name):
                raise DiscoveryFailure()
            if match[1] == "Add":
                active.add(name)
            else:
                active.discard(name)
            if len(active) > limit:
                raise DiscoveryFailure("incomplete")
        elif not (
            line == f"Using interface {index}"
            or line == f"Browsing for {service_type}.local."
            or (line.startswith("DATE: ---") and line.endswith("---"))
            or " ".join(line.split()) == "Timestamp A/R Flags if Domain Service Type Instance Name"
        ):
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


def resolve_endpoint(raw: bytes, index: int) -> tuple[str, str, int]:
    pattern = re.compile(
        rf"^{_STAMP}\s+(.+?) can be reached at ([^\s:]+):(\d+) "
        rf"\(interface (\d+)\)(?: Flags: [0-9A-Fa-f]+)?$".encode()
    )
    unique = set()
    continuation = False
    for line in raw.splitlines():
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
            except UnicodeError as exc:
                raise DiscoveryFailure() from exc
            continuation = True
        elif _banner(line, index) or re.fullmatch(
            rb"Lookup .+\._[A-Za-z0-9-]+\._(?:tcp|udp)\.local\.", line
        ):
            continuation = False
        elif (
            continuation
            and (not line or line.startswith(b" "))
            and all(byte >= 32 for byte in line)
            and re.match(rb"^ *[0-9]{1,2}:", line) is None
        ):
            # ShowTXTRecord emits exactly one optional continuation; printable
            # bytes are not necessarily UTF-8. The authoritative TXT query is
            # -Q's hexadecimal RDATA, not this shell-friendly display.
            continuation = False
        else:
            raise DiscoveryFailure()
    if len(unique) != 1:
        raise DiscoveryFailure()
    fullname, host, port, actual = unique.pop()
    if actual != index or not 1 <= port <= 65535 or not host.endswith(".local."):
        raise DiscoveryFailure()
    return fullname, host, port


def resolve_ipv4(raw: bytes, hostname: str, index: int) -> str:
    pattern = re.compile(
        rf"^{_STAMP}\s+(Add|Rmv)\s+[0-9A-Fa-f]+\s+(\d+)\s+"
        rf"{re.escape(hostname)}\s+([0-9.]+)\s+\d+$"
    )
    active: set[str] = set()
    for raw_line in raw.splitlines():
        if _banner(raw_line, index, b"Timestamp A/R Flags IF Hostname Address TTL"):
            continue
        try:
            line = raw_line.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise DiscoveryFailure() from exc
        match = pattern.fullmatch(line)
        if match is None or int(match[2]) != index:
            raise DiscoveryFailure()
        address = str(ipaddress.IPv4Address(match[3]))
        if match[1] == "Add":
            active.add(address)
        else:
            active.discard(address)
    if len(active) != 1:
        raise DiscoveryFailure("incomplete")
    return active.pop()


def resolve_txt(raw: bytes, fullname: str, index: int) -> tuple[bytes, ...]:
    pattern = re.compile(
        rf"^{_STAMP}\s+(Add|Rmv)\s+[0-9A-Fa-f]+\s+(\d+)\s+"
        rf"{re.escape(fullname)}\s+TXT\s+IN\s+(\d+) bytes:?((?: [0-9A-Fa-f]{{2}})*)$"
    )
    active: set[bytes] = set()
    for raw_line in raw.splitlines():
        if _banner(raw_line, index, b"Timestamp A/R Flags IF Name Type Class Rdata"):
            continue
        try:
            line = raw_line.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise DiscoveryFailure() from exc
        match = pattern.fullmatch(line)
        if match is None or int(match[2]) != index:
            raise DiscoveryFailure()
        data = bytes.fromhex(match[4])
        if len(data) != int(match[3]) or len(data) > 8900:
            raise DiscoveryFailure()
        if match[1] == "Add":
            active.add(data)
        else:
            active.discard(data)
    if len(active) != 1:
        raise DiscoveryFailure("incomplete")
    data = active.pop()
    entries = []
    offset = 0
    while offset < len(data):
        size = data[offset]
        offset += 1
        if offset + size > len(data):
            raise DiscoveryFailure()
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
) -> tuple[Record, ...]:
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
        fullname, host, port = resolve_endpoint(query(["-L", name, service_type, "local."]), index)
        address = resolve_ipv4(query(["-G", "v4", host]), host, index)
        txt = resolve_txt(query(["-Q", fullname, "TXT", "IN"]), fullname, index)
        result.append(Record(name, service_type, host, port, address, txt, interface, now))
    return tuple(result)


def registration_argv(record: Record, lifetime_seconds: int = 120) -> list[str]:
    """Escape every TXT byte in Apple's documented CLI grammar, including NUL."""
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 120:
        raise DiscoveryFailure("incomplete")
    if sum(1 + len(item) for item in record.txt) > 8900:
        raise DiscoveryFailure("incomplete")
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
            if (
                status == 0
                and time.monotonic() - self.spawned >= self.lifetime_seconds
                and re.search(rb"(?m)^Error code -?[0-9]+$", self.output) is None
            ):
                raise RegistrationExpired()
            raise DiscoveryFailure("unavailable")
        if len(self.output) > MAX_OUTPUT:
            raise DiscoveryFailure("incomplete")
        text = bytes(self.output)
        if b"-65570" in text or b"No Authorization" in text:
            raise DiscoveryFailure("local-network-denied")
        if re.search(
            rb"(?:DNSService[^\n]*(?:returned|failed)|[Ee]rror code|Unknown interface)",
            text,
        ):
            raise DiscoveryFailure()
        # Pipe reads can split a native callback anywhere. A partial final
        # line is not a conflicting registration; retain it until its newline.
        lines = text[: text.rfind(b"\n") + 1].splitlines()
        expected_service = (
            f"Got a reply for service {self.record.name}."
            f"{self.record.service_type}.local.: Name now registered and active"
        ).encode()
        expected_address = (
            f"Got a reply for record {self.record.hostname}: Name now registered and active"
        ).encode()
        callbacks = []
        pattern = re.compile(rf"^{_STAMP}  (Got a reply for (?:service|record) .+)$".encode())
        for line in lines:
            if b"Got a reply for service " in line or b"Got a reply for record " in line:
                callback = pattern.fullmatch(line)
                if callback is None:
                    raise DiscoveryFailure("malformed")
                callbacks.append(callback[1])
        if any(line not in {expected_service, expected_address} for line in callbacks):
            raise DiscoveryFailure("identity-mismatch")
        self.active = (
            lines.count(f"Using interface {self.index}".encode()) == 1
            and expected_service in callbacks
            and expected_address in callbacks
        )
        if not self.active and time.monotonic() - self.started > 5:
            raise DiscoveryFailure("timed-out")
        return self.active

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

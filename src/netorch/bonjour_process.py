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
_STAMP = r"\d{1,2}:\d{2}:\d{2}\.\d{3}"


class DiscoveryFailure(RuntimeError):
    def __init__(self, reason: str = "malformed") -> None:
        super().__init__(reason)
        self.reason = reason


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
        rf"^{_STAMP}\s+(Add|Rmv)\s+[0-9A-Fa-f]+\s+(\d+)\s+local\.\s+"
        rf"{re.escape(service_type)}\.?\s+(.+)$"
    )
    active: set[str] = set()
    for line in raw.decode("utf-8", errors="strict").splitlines():
        if re.match(rf"^{_STAMP}\s", line):
            match = pattern.fullmatch(line)
            if match is None or int(match[2]) != index:
                raise DiscoveryFailure()
            name = match[3]
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


def resolve_endpoint(raw: bytes, index: int) -> tuple[str, str, int]:
    pattern = re.compile(
        rf"^{_STAMP}\s+(.+?) can be reached at ([^\s:]+):(\d+) "
        rf"\(interface (\d+)\)(?: Flags: [0-9A-Fa-f]+)?$"
    )
    matches = [match for line in raw.decode().splitlines() if (match := pattern.fullmatch(line))]
    unique = {(match[1], match[2], int(match[3]), int(match[4])) for match in matches}
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
    for line in raw.decode().splitlines():
        if not re.match(rf"^{_STAMP}\s", line):
            continue
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
    for line in raw.decode("utf-8", errors="strict").splitlines():
        if not re.match(rf"^{_STAMP}\s", line):
            continue
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
        self.closed = False
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
        for key, _events in self.selector.select(0):
            chunk = os.read(key.fd, 65536)
            if chunk:
                self.output.extend(chunk)
            else:
                self.selector.unregister(key.fileobj)
        if self.process.poll() is not None:
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
        lines = text.splitlines()
        expected_service = (
            f"Got a reply for service {self.record.name}."
            f"{self.record.service_type}.local.: Name now registered and active"
        ).encode()
        expected_address = (
            f"Got a reply for record {self.record.hostname}: Name now registered and active"
        ).encode()
        callbacks = [
            line.split(b"  ")[-1]
            for line in lines
            if b"Got a reply for service " in line or b"Got a reply for record " in line
        ]
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

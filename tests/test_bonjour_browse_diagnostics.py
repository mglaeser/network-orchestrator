"""Replies of the DNS-SD client are data; its diagnostics are read where it prints them.

Every transcript is built from the format strings of Apple's client,
`Clients/dns-sd.c` at the revision the Bonjour guide cites
(`mDNSResponder-2881.120.11`); the line numbers in the comments are that file's.
Names, hosts and addresses are synthetic. These are source-derived contracts,
not captures from a host.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import replace

import pytest

from netorch import bonjour_process as native
from netorch.discovery import Record
from netorch.process import Result
from tests.test_bonjour_starting_banner import starting

INDEX = 7
INTERFACE = "example0"
TYPE = "_airplay._tcp"
HOST = "speaker.local."
ADDRESS = "192.0.2.82"
CLOCK = "22:03:17.123"
MODEL = (b"model=AudioAccessory5,1",)
NEXT_DAY = "DATE: ---Tue 06 Oct 2026---\n"
# browse_reply (763), once before its first reply
HEADING = f"Timestamp     A/R    Flags  if {'Domain':<20} {'Service Type':<20} Instance Name\n"
# Words of the client's diagnostics, here as parts of instance names.
NAMES = [
    "Error code display",
    "error code 7",
    "Unknown interface art",
    "No Such Record shop",
    "Model-65570",
    "No Authorization desk",
    "DNSServiceBrowse failed",
]

Runner = Callable[[list[str], float], Result]


def at(clock: str = CLOCK) -> str:
    # printtimestamp_F (518): "%2d:%02d:%02d.%03d  "
    return clock + "  "


def escaped(label: str) -> str:
    """The daemon's escaped form of one label, as resolve and query replies carry it.

    mDNSCore/DNSCommon.c:1224-1249 at the same tag: a backslash before a dot or a
    backslash, and a decimal escape for every byte up to the space.
    """
    out = ""
    for char in label:
        if char in ".\\":
            out += "\\" + char
        elif ord(char) <= 0x20:
            out += f"\\{ord(char):03d}"
        else:
            out += char
    return out


def fullname(name: str) -> str:
    return f"{escaped(name)}.{TYPE}.local."


def shown(entries: tuple[bytes, ...]) -> bytes:
    """ShowTXTRecord (781-813): the display under a resolve row and in the -P banner."""
    out = bytearray()
    for entry in entries:
        if entry:
            out += b" "
        for byte in entry:
            if byte == 0 or byte in b" &;`'\"|*?~<>^()[]{}$":
                out += b"\\"
            if byte == 0x5C:
                out += b"\\" * 4
            elif byte >= 0x20:
                out.append(byte)
            else:
                out += b"\\\\x%02X" % byte
    return bytes(out)


def rdata(entries: tuple[bytes, ...]) -> bytes:
    return b"".join(bytes([len(entry)]) + entry for entry in entries)


def browse_row(name: str, op: str = "Add", clock: str = CLOCK) -> bytes:
    # browse_reply (768-769): "%s %8X %3d %-20s %-20s %s\n"
    flags = 2 if op == "Add" else 0
    row = at(clock) + f"{op} {flags:8X} {INDEX:3d} {'local.':<20} {TYPE + '.':<20} {name}\n"
    return row.encode()


def browse_output(*replies: bytes) -> bytes:
    out = f"Using interface {INDEX}\n"  # main (2135)
    out += f"Browsing for {TYPE}.local.\n"  # main (2157)
    out += starting()  # printtimestamp_F (515), main (2396-2397)
    return (out + HEADING).encode() + b"".join(replies)


def resolve_output(name: str, host: str = HOST, txt: tuple[bytes, ...] = MODEL) -> bytes:
    out = f"Using interface {INDEX}\n"
    out += f"Lookup {name}.{TYPE}.local.\n"  # main (2181)
    out += starting()
    # resolve_reply (828, 832): "%s " then "can be reached at %s:%u (interface %d)"
    out += at() + f"{fullname(name)} can be reached at {host}:7000 (interface {INDEX})\n"
    # resolve_reply (837): the display follows only when the record is not a single empty string
    display = shown(txt) + b"\n" if len(rdata(txt)) > 1 else b""
    return out.encode() + display


def address_output(host: str = HOST, address: str = ADDRESS, suffix: str = "") -> bytes:
    out = f"Using interface {INDEX}\n" + starting()
    # addrinfo_reply (1253): "Timestamp     %3s  %-11s  %3s  %-38s %-44s %s\n"
    out += (
        f"Timestamp     {'A/R':>3}  {'Flags':<11}  {'IF':>3}  "
        f"{'Hostname':<38} {'Address':<44} TTL\n"
    )
    # addrinfo_reply (1276): "%-3s  %-9X %c  %3d  %-38s %-44s %d"
    out += at() + f"{'Add':<3}  {0x40000002:<9X} {' '}  {INDEX:3d}  {host:<38} {address:<44} 120"
    return (out + suffix + "\n").encode()


def txt_output(name: str, txt: tuple[bytes, ...] = MODEL, suffix: str | None = None) -> bytes:
    out = f"Using interface {INDEX}\n" + starting()
    # qr_reply (1115): "Timestamp     %3s  %-11s  %3s  %-29s %-6s %-6s Rdata\n"
    out += (
        f"Timestamp     {'A/R':>3}  {'Flags':<11}  {'IF':>3}  "
        f"{'Name':<29} {'Type':<6} {'Class':<6} Rdata\n"
    )
    # qr_reply (1182): "%-3s  %-9X %c  %3d  %-29s %-6s %-6s %s"
    out += at() + (
        f"{'Add':<3}  {0x40000002:<9X} {' '}  {INDEX:3d}  "
        f"{fullname(name):<29} {'TXT':<6} {'IN':<6} "
    )
    if suffix is not None:
        # qr_reply (1102, 1130): the data column stays "0.0.0.0" when the reply is an error
        return (out + "0.0.0.0" + suffix + "\n").encode()
    data = rdata(txt)
    # qr_reply (1174, 1188): "%d bytes%s" and " %02X" for each byte
    out += f"{len(data)} bytes:" + "".join(f" {byte:02X}" for byte in data) + "\n"
    return out.encode()


def client(
    name: str = "Example speaker",
    host: str = HOST,
    txt: tuple[bytes, ...] = MODEL,
    **replaced: Result,
) -> Runner:
    """A fake client that answers the four scan operations in the source's formats."""

    def runner(argv: list[str], _timeout: float) -> Result:
        operation = next(item for item in ("-B", "-L", "-G", "-Q") if item in argv)
        if operation[1] in replaced:
            return replaced[operation[1]]
        payload = {
            "-B": lambda: browse_output(browse_row(name)),
            "-L": lambda: resolve_output(name, host, txt),
            "-G": lambda: address_output(host),
            "-Q": lambda: txt_output(name, txt),
        }[operation]()
        return Result(0, payload, b"")

    return runner


def scanned(runner: Runner) -> tuple[Record, ...]:
    return native.scan(INTERFACE, INDEX, TYPE, 8, 2, 1000.0, runner)


def refusal(call: Callable[[], object]) -> str:
    with pytest.raises(native.DiscoveryFailure) as caught:
        call()
    return caught.value.reason


def browsed(*replies: bytes) -> tuple[str, ...]:
    return native.browse_names(browse_output(*replies), TYPE, INDEX, 8)


# Data that reads like a diagnostic is still data.


@pytest.mark.parametrize("name", NAMES)
def test_scan_reads_a_device_whose_name_reads_like_a_diagnostic(name: str) -> None:
    # The name is in the browse row, in the "Lookup" echo and, escaped, in the
    # resolve and query replies.
    assert [(item.name, item.hostname, item.ipv4, item.txt) for item in scanned(client(name))] == [
        (name, HOST, ADDRESS, MODEL)
    ]


@pytest.mark.parametrize(
    "txt",
    [
        (b"serial=A-65570",),
        (b"Error", b"code=7"),
        (b"No", b"Authorization"),
        (b"Unknown", b"interface"),
        (b"No", b"Such", b"Record"),
        (b"DNSServiceResolve", b"failed"),
    ],
    ids=lambda txt: b" ".join(txt).decode(),
)
def test_scan_reads_a_device_whose_txt_reads_like_a_diagnostic(txt: tuple[bytes, ...]) -> None:
    # ShowTXTRecord separates the strings of a record with one space each.
    assert b" ".join(txt) in resolve_output("Example speaker", txt=txt)
    assert [item.txt for item in scanned(client(txt=txt))] == [txt]


def test_scan_reads_a_device_whose_host_name_ends_like_the_denial_code() -> None:
    host = "printer-65570.local."
    assert [item.hostname for item in scanned(client(host=host))] == [host]


def test_interface_proof_does_not_search_replies_or_the_echoed_arguments() -> None:
    for name in NAMES:
        for stdout in (browse_output(browse_row(name)), resolve_output(name)):
            assert native.confirmed_output(Result(0, stdout, b""), INDEX) == stdout
    # A service type is an argument too, and the policy grammar allows this one.
    stdout = (
        f"Using interface {INDEX}\nBrowsing for _unit-65570._tcp.local.\n" + starting()
    ).encode()
    assert native.confirmed_output(Result(0, stdout, b""), INDEX) == stdout


# What the client itself prints as a diagnostic still fails the scan.


@pytest.mark.parametrize(
    "code,reason",
    [(-65570, "local-network-denied"), (-65563, "malformed"), (-65554, "malformed")],
)
def test_browse_error_reply_fails_the_scan(code: int, reason: str) -> None:
    # browse_reply (764-766): printtimestamp(); printf("Error code %d\n", errorCode);
    denied = Result(0, browse_output(f"{at()}Error code {code}\n".encode()), b"")
    assert refusal(lambda: scanned(client(B=denied))) == reason


@pytest.mark.parametrize(
    "text,reason",
    [
        # resolve_reply (831, 839): printf("error code %d\n", errorCode); ... printf("\n");
        ("error code -65570\n", "local-network-denied"),
        ("error code -65563\n", "malformed"),
        # resolve_reply (830)
        ("No Such Record", "malformed"),
        # resolve_reply (834), after either
        ("error code -65570\n Flags: 2", "local-network-denied"),
        ("No Such Record Flags: 2", "malformed"),
    ],
)
@pytest.mark.parametrize("name", [fullname("Example speaker"), ""], ids=["named", "unnamed"])
def test_resolve_error_reply_fails_the_scan(name: str, text: str, reason: str) -> None:
    # An error reply need not name the instance: the daemon's asynchronous error
    # carries an empty name (mDNSShared/uds_daemon.c:4746-4782 at the same tag).
    out = f"Using interface {INDEX}\nLookup Example speaker.{TYPE}.local.\n" + starting()
    out += at() + name + " " + text + "\n"
    assert refusal(lambda: scanned(client(L=Result(0, out.encode(), b"")))) == reason


@pytest.mark.parametrize(
    "suffix,reason",
    [
        # addrinfo_reply (1283): printf("   Error code %d", errorCode);
        ("   Error code -65570", "local-network-denied"),
        ("   Error code -65563", "malformed"),
        # addrinfo_reply (1281)
        ("   No Such Record", "malformed"),
    ],
)
def test_address_error_reply_fails_the_scan(suffix: str, reason: str) -> None:
    failed = Result(0, address_output(address="0.0.0.0", suffix=suffix), b"")
    assert refusal(lambda: scanned(client(G=failed))) == reason


@pytest.mark.parametrize(
    "suffix,status,reason",
    [
        # qr_reply (1195): printf("    No Authorization");
        ("    No Authorization", 0, "local-network-denied"),
        # qr_reply (1193)
        ("    No Such Record", 0, "malformed"),
        # qr_reply (1198-1200): two lines, then exit(1)
        ("    No Such Record\nQuery Timed Out", 1, "malformed"),
        # qr_reply prints no text for any other error
        ("", 0, "malformed"),
    ],
)
def test_query_error_reply_fails_the_scan(suffix: str, status: int, reason: str) -> None:
    failed = Result(status, txt_output("Example speaker", suffix=suffix), b"")
    assert refusal(lambda: scanned(client(Q=failed))) == reason


@pytest.mark.parametrize(
    "status,stdout,stderr,reason",
    [
        # main (2392, 2394): fprintf(stderr, "%s failed %ld%s\n", ...); return (-1);
        (
            255,
            f"Using interface {INDEX}\n",
            "DNSServiceBrowse failed -65570\n",
            "local-network-denied",
        ),
        (
            255,
            f"Using interface {INDEX}\n",
            "DNSServiceBrowse failed -65563 (Service Not Running)\n",
            "malformed",
        ),
        # EXIT_IF_LIBDISPATCH_FATAL_ERROR (246): fprintf(stderr, "Error code %d\n", (E)); exit(0);
        (0, f"Using interface {INDEX}\n" + starting(), "Error code -65563\n", "malformed"),
        # main (2104): fprintf(stderr, "Unknown interface %s\n", argv[2]); then the usage text
        (0, "", f"Unknown interface {INTERFACE}\n", "malformed"),
    ],
)
def test_error_stream_fails_the_scan(status: int, stdout: str, stderr: str, reason: str) -> None:
    failed = Result(status, stdout.encode(), stderr.encode())
    assert refusal(lambda: scanned(client(B=failed))) == reason


def test_diagnostic_before_the_event_loop_keeps_its_reason() -> None:
    # No operation prints these on the output stream; the reader still refuses them there.
    for line, reason in [
        ("Error code -65570", "local-network-denied"),
        ("Error code -1", "malformed"),
    ]:
        out = f"Using interface {INDEX}\n{line}\n".encode()
        assert (
            refusal(lambda out=out: native.confirmed_output(Result(0, out, b""), INDEX)) == reason
        )


# A name is data on every line it reaches.


def test_txt_display_cannot_report_a_denial() -> None:
    # The display starts like a timestamp and ends like resolve_reply's error
    # line, but ShowTXTRecord separates two strings by one space only.
    txt = (b"9:05:03.123", b"x", b"error", b"code", b"-65570")
    resolved = resolve_output("Example speaker", txt=txt)
    assert resolved.endswith(b"\n 9:05:03.123 x error code -65570\n")
    assert refusal(lambda: scanned(client(L=Result(0, resolved, b"")))) == "malformed"


@pytest.mark.parametrize("fragment", [at() + "Error code -65570", "Error code -65570"])
def test_name_with_a_line_feed_cannot_report_a_denial(fragment: str) -> None:
    name = "Attic\n" + fragment
    assert len(name.encode()) <= 63  # a legal label, which browse replies carry unescaped
    browse = Result(0, browse_output(browse_row(name)), b"")
    assert refusal(lambda: scanned(client(B=browse))) == "malformed"


@pytest.mark.parametrize(
    "banner",
    [
        "DATE: ------",
        NEXT_DAY.rstrip("\n"),
        at() + "...STARTING...",
        "Timestamp A/R Flags if Domain Service Type Instance Name",
        f"Browsing for {TYPE}.local.",
    ],
)
@pytest.mark.parametrize("line_end", ["\n", "\r"])
def test_name_cannot_remove_another_device_through_a_banner(line_end: str, banner: str) -> None:
    forged = "Victim" + line_end + banner
    assert len(forged.encode()) <= 63
    refusal(lambda: browsed(browse_row("Victim"), browse_row(forged, "Rmv")))
    # A further reply after the forged one does not make it acceptable either.
    refusal(lambda: browsed(browse_row("Victim"), browse_row(forged, "Rmv"), browse_row("Other")))


def test_a_row_does_not_fit_into_the_rest_of_a_name() -> None:
    # The shortest row the client prints is longer than a label can be, so what
    # follows a line feed inside a name is never read as a row of its own.
    shortest = browse_row("x").rstrip(b"\n")
    assert browsed(shortest + b"\n") == ("x",)
    assert len(shortest) == 74 > 63
    refusal(lambda: browsed(shortest.replace(b"local.  ", b"local. ") + b"\n"))


def test_carriage_return_is_part_of_a_name_not_a_line_end() -> None:
    # Cut at the carriage return, this row would be an instance named "Speaker"
    # that nobody advertised, followed by a date line.
    refusal(lambda: browsed(browse_row("Speaker\rDATE: ------")))


def test_only_a_line_feed_ends_a_line_of_the_client() -> None:
    def crlf(raw: bytes) -> bytes:
        return raw.replace(b"\n", b"\r\n")

    name = "Example speaker"
    refusal(lambda: native.confirmed_output(Result(0, crlf(browse_output()), b""), INDEX))
    refusal(lambda: native.browse_names(crlf(browse_output(browse_row(name))), TYPE, INDEX, 8))
    refusal(lambda: native.resolve_endpoint(crlf(resolve_output(name)), INDEX))
    refusal(lambda: native.resolve_ipv4(crlf(address_output()), HOST, INDEX))
    refusal(lambda: native.resolve_txt(crlf(txt_output(name)), fullname(name), INDEX))


# Banners have the place the source gives them.


def test_date_line_between_replies_is_read_at_midnight() -> None:
    # printtimestamp_F (512-517) prints the date again when the day has changed.
    assert browsed(
        browse_row("Evening", clock="23:59:59.900"),
        NEXT_DAY.encode(),
        browse_row("Morning", clock=" 0:00:00.100"),
    ) == ("Evening", "Morning")


def test_date_line_before_the_first_reply_is_read_at_midnight() -> None:
    out = f"Using interface {INDEX}\nBrowsing for {TYPE}.local.\n"
    out += "DATE: ---Mon 05 Oct 2026---\n" + at("23:59:59.900") + "...STARTING...\n"
    # browse_reply (763-764) prints its heading before the timestamp of the first reply.
    out += HEADING + NEXT_DAY
    raw = out.encode() + browse_row("Morning", clock=" 0:00:00.100")
    assert native.browse_names(raw, TYPE, INDEX, 8) == ("Morning",)


@pytest.mark.parametrize("clock", ["23:59:59.900", "23:59:59.901", None])
def test_date_line_without_an_earlier_time_of_day_is_refused(clock: str | None) -> None:
    following = b"" if clock is None else browse_row("Morning", clock=clock)
    refusal(
        lambda: browsed(browse_row("Evening", clock="23:59:59.900"), NEXT_DAY.encode(), following)
    )


@pytest.mark.parametrize(
    "banner",
    [
        at() + "...STARTING...",
        "Timestamp     A/R    Flags  if Domain               Service Type         Instance Name",
        f"Browsing for {TYPE}.local.",
        f"Using interface {INDEX}",
        "",
    ],
)
def test_banner_after_the_first_reply_is_refused(banner: str) -> None:
    refusal(lambda: browsed(browse_row("Example speaker"), banner.encode() + b"\n"))


# The name the client reads as "no name".


def test_browse_refuses_the_name_the_client_reads_as_empty() -> None:
    # RegisterService (1498): if (nam[0] == '.' && nam[1] == 0) nam = "";
    refusal(lambda: browsed(browse_row(".")))
    assert browsed(browse_row(".."), browse_row(" ."), browse_row(".x")) == (" .", "..", ".x")


def test_registration_never_passes_the_name_the_client_reads_as_empty() -> None:
    record = Record(".", TYPE, HOST, 7000, ADDRESS, MODEL, INTERFACE, 1000.0)
    assert refusal(lambda: native.registration_argv(record)) == "identity-mismatch"
    assert native.registration_argv(replace(record, name=".."))[5:7] == ["-P", ".."]


# The registration reader follows the same rule.


def record_named(name: str, txt: tuple[bytes, ...] = MODEL) -> Record:
    return Record(
        name, TYPE, "netorch-lan-0123456789abcdef.local.", 7000, ADDRESS, txt, INTERFACE, 1000.0
    )


def registration_output(record: Record, *replies: str, service: str | None = None) -> bytes:
    out = f"Using interface {INDEX}\n".encode()
    # RegisterService (1501-1503, 1524-1527): one line with name, host, port and the TXT display
    out += f"Registering Service {record.name}.{record.service_type}.local.".encode()
    out += f" host {record.hostname} port {record.port}".encode()
    out += (b" TXT" + shown(record.txt) if record.txt else b"") + b"\n"
    out += starting().encode()
    # MyRegisterRecordCallback (1435, 1439)
    out += (
        f"{at()}Got a reply for record {record.hostname}: Name now registered and active\n".encode()
    )
    if service is None:
        # reg_reply (918, 922)
        service = "Name now registered and active"
    out += (
        f"{at()}Got a reply for service {record.name}.{record.service_type}.local.: {service}\n"
    ).encode()
    return out + "".join(line + "\n" for line in replies).encode()


def reader(record: Record, output: bytes) -> native.Registration:
    class Live:
        def poll(self) -> None:
            return None

    class Idle:
        def select(self, _timeout: float) -> tuple[()]:
            return ()

    registration = object.__new__(native.Registration)
    registration.closed = False
    registration.record = record
    registration.index = INDEX
    registration.process = Live()
    registration.selector = Idle()
    registration.output = bytearray(output)
    registration.started = time.monotonic()
    return registration


@pytest.mark.parametrize(
    "name", [*NAMES, "DNSServiceRegister returned", "Got a reply for service x"]
)
def test_confirmed_registration_is_not_refused_for_words_in_its_name(name: str) -> None:
    record = record_named(name)
    assert reader(record, registration_output(record)).poll() is True


@pytest.mark.parametrize(
    "txt", [(b"serial=A-65570",), (b"Error", b"code=7"), (b"No", b"Authorization")]
)
def test_confirmed_registration_is_not_refused_for_words_in_its_txt(txt: tuple[bytes, ...]) -> None:
    record = record_named("Example speaker", txt)
    assert reader(record, registration_output(record)).poll() is True


@pytest.mark.parametrize(
    "line,reason",
    [
        # EXIT_IF_LIBDISPATCH_FATAL_ERROR (246), on the error stream that the reader merges
        ("Error code -65563", "malformed"),
        # main (2392)
        ("DNSServiceRegister failed -65570", "local-network-denied"),
        ("DNSServiceRegisterRecord failed -65540", "malformed"),
        # main (2199)
        ("DNSServiceCreateConnection returned -65563", "malformed"),
        # main (2104)
        (f"Unknown interface {INTERFACE}", "malformed"),
    ],
)
def test_registration_diagnostic_on_its_own_line_still_fails(line: str, reason: str) -> None:
    record = record_named("Example speaker")
    assert refusal(reader(record, registration_output(record, line)).poll) == reason


@pytest.mark.parametrize(
    "service,reason",
    [
        # reg_reply (940): printf("Error %d\n", errorCode);
        ("Error -65570", "local-network-denied"),
        ("Error -65563", "identity-mismatch"),
        # reg_reply (923, 936)
        ("Name registration removed", "identity-mismatch"),
        ("Name in use, please choose another", "identity-mismatch"),
    ],
)
def test_registration_reply_that_is_not_the_confirmation_still_fails(
    service: str, reason: str
) -> None:
    record = record_named("Example speaker")
    assert refusal(reader(record, registration_output(record, service=service)).poll) == reason


def test_registration_reader_waits_for_the_end_of_the_echo_line() -> None:
    record = record_named("Error code display")
    complete = registration_output(record)
    registration = reader(record, complete[: complete.index(b"display")])
    assert registration.poll() is False
    registration.output = bytearray(complete)
    assert registration.poll() is True


def test_registration_reader_ends_lines_at_a_line_feed_only() -> None:
    # A carriage return stays in the line: the interface line is not acknowledged
    # and the replies are not the ones that were asked for.
    record = record_named("Example speaker")
    crlf = registration_output(record).replace(b"\n", b"\r\n")
    assert refusal(reader(record, crlf).poll) == "identity-mismatch"

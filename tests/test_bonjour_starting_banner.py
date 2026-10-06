"""Scan parsers accept dns-sd's complete output, including its start line.

The transcripts are built from the printf format strings of Apple's client
(`Clients/dns-sd.c` at the revision the Bonjour guide cites). They are
source-derived contracts with synthetic names and RFC 5737 addresses, not
captures from a host.
"""

from __future__ import annotations

import pytest

from netorch import bonjour_process as native
from netorch.process import Result

INDEX = 7
NAME = "Example speaker"
FULL = r"Example\032speaker._airplay._tcp.local."
HOST = "speaker.local."
ADDRESS = "192.0.2.82"
RDATA = b"\x17model=AudioAccessory5,1"
# printtimestamp_F: "DATE: ---%s---\n" with "%a %d %b %Y", printed with the first timestamp.
DATE = "DATE: ---Mon 05 Oct 2026---\n"


def stamp(hour: int = 22) -> str:
    # printtimestamp_F: "%2d:%02d:%02d.%03d  "
    return f"{hour:2d}:03:17.123  "


def starting(hour: int = 22) -> str:
    # main(): printtimestamp(); printf("...STARTING...\n"); HandleEvents();
    return DATE + stamp(hour) + "...STARTING...\n"


def browse(start: str) -> bytes:
    out = f"Using interface {INDEX}\n"
    out += "Browsing for _airplay._tcp.local.\n"
    out += start
    # browse_reply heading: "Timestamp     A/R    Flags  if %-20s %-20s %s\n"
    out += f"Timestamp     A/R    Flags  if {'Domain':<20} {'Service Type':<20} Instance Name\n"
    # browse_reply row: "%s %8X %3d %-20s %-20s %s\n"
    out += stamp() + f"Add {2:8X} {INDEX:3d} {'local.':<20} {'_airplay._tcp.':<20} {NAME}\n"
    return out.encode()


def resolve(start: str) -> bytes:
    out = f"Using interface {INDEX}\n"
    out += f"Lookup {NAME}._airplay._tcp.local.\n"
    out += start
    # resolve_reply: "%s can be reached at %s:%u (interface %d)" and one TXT display line
    out += stamp() + f"{FULL} can be reached at {HOST}:7000 (interface {INDEX})\n"
    out += " model=AudioAccessory5,1\n"
    return out.encode()


def address(start: str) -> bytes:
    out = f"Using interface {INDEX}\n"
    out += start
    # addrinfo_reply heading: "Timestamp     %3s  %-11s  %3s  %-38s %-44s %s\n"
    out += (
        f"Timestamp     {'A/R':>3}  {'Flags':<11}  {'IF':>3}  "
        f"{'Hostname':<38} {'Address':<44} TTL\n"
    )
    # addrinfo_reply row: "%-3s  %-9X %c  %3d  %-38s %-44s %d"
    out += stamp() + (
        f"{'Add':<3}  {0x40000002:<9X} {' '}  {INDEX:3d}  {HOST:<38} {ADDRESS:<44} 120\n"
    )
    return out.encode()


def txt(start: str) -> bytes:
    out = f"Using interface {INDEX}\n"
    out += start
    # qr_reply heading: "Timestamp     %3s  %-11s  %3s  %-29s %-6s %-6s Rdata\n"
    out += (
        f"Timestamp     {'A/R':>3}  {'Flags':<11}  {'IF':>3}  "
        f"{'Name':<29} {'Type':<6} {'Class':<6} Rdata\n"
    )
    # qr_reply row: "%-3s  %-9X %c  %3d  %-29s %-6s %-6s %s" with "%d bytes:" and " %02X"
    out += stamp() + (
        f"{'Add':<3}  {0x40000002:<9X} {' '}  {INDEX:3d}  "
        f"{FULL:<29} {'TXT':<6} {'IN':<6} {len(RDATA)} bytes:"
    )
    out += "".join(f" {byte:02X}" for byte in RDATA) + "\n"
    return out.encode()


def parse_all(start: str) -> dict[str, object]:
    return {
        "browse": native.browse_names(browse(start), "_airplay._tcp", INDEX, 8),
        "resolve": native.resolve_endpoint(resolve(start), INDEX),
        "address": native.resolve_ipv4(address(start), HOST, INDEX),
        "txt": native.resolve_txt(txt(start), FULL, INDEX),
    }


EXPECTED = {
    "browse": (NAME,),
    "resolve": (FULL, HOST, 7000),
    "address": ADDRESS,
    "txt": (b"model=AudioAccessory5,1",),
}


@pytest.mark.parametrize("hour", [9, 22], ids=["padded-hour", "two-digit-hour"])
def test_every_scan_parser_accepts_the_native_start_line(hour: int) -> None:
    assert parse_all(starting(hour)) == EXPECTED


def test_output_without_a_start_line_still_parses() -> None:
    assert parse_all(DATE) == EXPECTED


def test_full_scan_of_one_device_with_source_format_output() -> None:
    def runner(argv: list[str], _timeout: float) -> Result:
        if "-B" in argv:
            payload = browse(starting())
        elif "-L" in argv:
            payload = resolve(starting())
        elif "-G" in argv:
            payload = address(starting())
        else:
            payload = txt(starting())
        return Result(0, payload, b"")

    records = native.scan("example0", INDEX, "_airplay._tcp", 8, 2, 1000.0, runner)
    assert [(item.name, item.hostname, item.port, item.ipv4, item.txt) for item in records] == [
        (NAME, HOST, 7000, ADDRESS, (b"model=AudioAccessory5,1",))
    ]


NEAR_MISSES = [
    "...STARTING...",  # no timestamp
    stamp() + "...STARTED...",
    stamp() + "...starting...",
    stamp().rstrip() + " ...STARTING...",  # one separating space instead of two
    stamp() + "...STARTING... ",  # trailing text
    stamp() + "...STARTING... Add 2 7 local. _airplay._tcp. Forged",
    "22:03:17  ...STARTING...",  # no milliseconds
    "24:03:17.123  ...STARTING...",  # no such hour
    "22:03:17.١٢٣  ...STARTING...",  # native printf emits ASCII digits
]


@pytest.mark.parametrize("line", NEAR_MISSES)
@pytest.mark.parametrize("parser", ["browse", "resolve", "address", "txt"])
def test_near_miss_of_the_start_line_stays_malformed(parser: str, line: str) -> None:
    start = DATE + line + "\n"
    calls = {
        "browse": lambda: native.browse_names(browse(start), "_airplay._tcp", INDEX, 8),
        "resolve": lambda: native.resolve_endpoint(resolve(start), INDEX),
        "address": lambda: native.resolve_ipv4(address(start), HOST, INDEX),
        "txt": lambda: native.resolve_txt(txt(start), FULL, INDEX),
    }
    with pytest.raises(native.DiscoveryFailure) as caught:
        calls[parser]()
    assert caught.value.reason == "malformed"


def test_start_line_carries_no_record() -> None:
    """A start line alone is an empty, complete browse; it never invents a name."""
    only = f"Using interface {INDEX}\nBrowsing for _airplay._tcp.local.\n" + starting()
    assert native.browse_names(only.encode(), "_airplay._tcp", INDEX, 8) == ()


@pytest.mark.parametrize(
    "name",
    [" Speaker", "  Speaker  ", "Speaker\u2028Room", "\u0085Speaker", "\u00a0Speaker"],
)
def test_native_browse_preserves_leading_spaces_and_unicode_separators(name: str) -> None:
    # Apple's fixed-width columns end before the unescaped instance label.
    row = stamp() + f"Add {2:8X} {INDEX:3d} {'local.':<20} {'_airplay._tcp.':<20} {name}\n"
    assert native.browse_names(row.encode(), "_airplay._tcp", INDEX, 8) == (name,)


def test_removing_unspaced_label_does_not_remove_distinct_spaced_label() -> None:
    rows = [
        stamp() + f"{op} {2:8X} {INDEX:3d} {'local.':<20} {'_airplay._tcp.':<20} {name}\n"
        for op, name in [("Add", "Speaker"), ("Add", " Speaker"), ("Rmv", "Speaker")]
    ]
    assert native.browse_names("".join(rows).encode(), "_airplay._tcp", INDEX, 8) == (" Speaker",)


@pytest.mark.parametrize(
    "row",
    [
        stamp() + "Add 2 7 local. _airplay._tcp. Speaker\n",
        stamp() + f"Add {'00000002'} {INDEX:3d} {'local.':<20} {'_airplay._tcp.':<20} Speaker\n",
        stamp() + f"Add {'a':>8} {INDEX:3d} {'local.':<20} {'_airplay._tcp.':<20} Speaker\n",
        stamp() + f"Add {2:8X} {'007'} {'local.':<20} {'_airplay._tcp.':<20} Speaker\n",
        stamp() + f"Add {2:8X} {INDEX:3d} {'local.':<19} {'_airplay._tcp.':<20} Speaker\n",
    ],
)
def test_native_browse_rejects_non_native_column_formats(row: str) -> None:
    with pytest.raises(native.DiscoveryFailure):
        native.browse_names(row.encode(), "_airplay._tcp", INDEX, 8)

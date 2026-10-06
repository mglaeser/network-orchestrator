"""State rows are read in the display forms of the kernel's lan/gwy/ext state model.

The readable forms are those of a reviewed read-only capture of a macOS state
table. Only the shape of a row is the capture's: every address and port below
is a documentation value (RFC 5737, RFC 3849), a link-local or a multicast
constant. Nothing here ran against a kernel.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from netorch.pf_owner import PFError, ShellBackend, state_addresses
from netorch.state import Intent, intent_to_dict
from tests.test_pf_owner import approve_all, environment, run_pass

__all__ = ["environment"]

# name -> (row, every IPv4 address the row names, in printed order)
CAPTURED: dict[str, tuple[str, tuple[str, ...]]] = {
    "translated outbound": (
        "ALL tcp 198.51.100.12:45002 -> 192.0.2.10:45002 -> 203.0.113.8:443 "
        "ESTABLISHED:ESTABLISHED",
        ("198.51.100.12", "192.0.2.10", "203.0.113.8"),
    ),
    "translated inbound": (
        "ALL udp 192.0.2.82:7000 <- 192.0.2.10:45001 <- 198.51.100.12:45001 MULTIPLE:MULTIPLE",
        ("192.0.2.82", "192.0.2.10", "198.51.100.12"),
    ),
    "translated with a marked endpoint": (
        "ALL udp 198.51.100.12:45127 -> 192.0.2.10:45127 -> ~192.0.2.82:7000 SINGLE:NO_TRAFFIC",
        ("198.51.100.12", "192.0.2.10", "192.0.2.82"),
    ),
    "translated inbound, low port": (
        "ALL udp 192.0.2.1:53 <- 192.0.2.10:53 <- 198.51.100.20:50123 MULTIPLE:MULTIPLE",
        ("192.0.2.1", "192.0.2.10", "198.51.100.20"),
    ),
    "IPv6 tcp": ("ALL tcp 2001:db8::1[443] <- 2001:db8::2[50124] ESTABLISHED:ESTABLISHED", ()),
    "IPv6 udp": ("ALL udp fe80::1[5353] -> fe80::2[5353] SINGLE:NO_TRAFFIC", ()),
    "igmp without ports": (
        "ALL igmp 192.0.2.1 <- 224.0.0.1 NO_TRAFFIC:SINGLE",
        ("192.0.2.1", "224.0.0.1"),
    ),
    "icmp with port zero": ("ALL icmp fe80::1[0] <- fe80::2[0] 0:0", ()),
    "untranslated": (
        "all tcp 192.0.2.10:51000 -> 203.0.113.5:443 ESTABLISHED:ESTABLISHED",
        ("192.0.2.10", "203.0.113.5"),
    ),
}

OUTBOUND = CAPTURED["translated outbound"][0]
INBOUND = CAPTURED["translated inbound"][0]
MARKED = CAPTURED["translated with a marked endpoint"][0]
TCP6 = CAPTURED["IPv6 tcp"][0]
IGMP = CAPTURED["igmp without ports"][0]
ICMP6 = CAPTURED["icmp with port zero"][0]
PLAIN = CAPTURED["untranslated"][0]
# The one-arrow display with a translated endpoint in parentheses, as before.
WRAPPED = "all udp 192.0.2.10:45001 (198.51.100.12:45001) -> 192.0.2.82:80 SINGLE:MULTIPLE"
ESP = "ALL esp 198.51.100.12 -> 192.0.2.10 -> 203.0.113.8 MULTIPLE:MULTIPLE"

# Forms that follow from the same rules without being rows of the capture.
DERIVED: dict[str, tuple[str, tuple[str, ...]]] = {
    "esp without ports, translated": (ESP, ("198.51.100.12", "192.0.2.10", "203.0.113.8")),
    "gre without ports": (
        "ALL gre 192.0.2.10 <- 203.0.113.8 NO_TRAFFIC:SINGLE",
        ("192.0.2.10", "203.0.113.8"),
    ),
    "sctp with ports, translated": (
        "ALL sctp 198.51.100.12:5000 -> 192.0.2.10:5000 -> 203.0.113.8:5000 SINGLE:MULTIPLE",
        ("198.51.100.12", "192.0.2.10", "203.0.113.8"),
    ),
    "protocol number": (
        "ALL 253 192.0.2.10 <- 203.0.113.8 NO_TRAFFIC:SINGLE",
        ("192.0.2.10", "203.0.113.8"),
    ),
    "level without a name": ("ALL igmp 192.0.2.1 <- 224.0.0.1 3:0", ("192.0.2.1", "224.0.0.1")),
    "icmp id as port, translated": (
        "ALL icmp 198.51.100.12:4660 -> 192.0.2.10:4660 -> 203.0.113.8:4660 0:0",
        ("198.51.100.12", "192.0.2.10", "203.0.113.8"),
    ),
    "tcp proxy phase, translated": (
        "ALL tcp 198.51.100.12:45002 -> 192.0.2.10:45002 -> 203.0.113.8:443 PROXY:DST",
        ("198.51.100.12", "192.0.2.10", "203.0.113.8"),
    ),
    "IPv4-mapped endpoints, translated": (
        "ALL udp ::ffff:198.51.100.12[45001] -> ::ffff:192.0.2.10[45001] -> "
        "2001:db8::8[7000] SINGLE:MULTIPLE",
        ("198.51.100.12", "192.0.2.10"),
    ),
    "marker on the first endpoint": (
        "ALL udp ~198.51.100.12:45127 -> 192.0.2.10:45127 -> 192.0.2.82:7000 SINGLE:NO_TRAFFIC",
        ("198.51.100.12", "192.0.2.10", "192.0.2.82"),
    ),
    "marker on the middle endpoint": (
        "ALL udp 198.51.100.12:45127 -> ~192.0.2.10:45127 -> 192.0.2.82:7000 SINGLE:NO_TRAFFIC",
        ("198.51.100.12", "192.0.2.10", "192.0.2.82"),
    ),
    "marker, untranslated": (
        "ALL udp 192.0.2.10:45127 -> ~192.0.2.82:7000 SINGLE:NO_TRAFFIC",
        ("192.0.2.10", "192.0.2.82"),
    ),
    "marker on an address without port": (
        "ALL igmp ~192.0.2.1 <- 224.0.0.1 NO_TRAFFIC:SINGLE",
        ("192.0.2.1", "224.0.0.1"),
    ),
    "port zero in brackets, udp": ("ALL udp fe80::1[0] -> fe80::2[5353] SINGLE:NO_TRAFFIC", ()),
    # The kernel header names the levels of ESP and GRE itself (xnu pfvar.h,
    # PFESPS_NAMES and PFGRE1S_NAMES); the flow levels are read for them too.
    "esp with its own level names": (
        "ALL esp 198.51.100.12 -> 192.0.2.10 -> 203.0.113.8 INITIATING:ESTABLISHED",
        ("198.51.100.12", "192.0.2.10", "203.0.113.8"),
    ),
    "gre with its own level names": (
        "ALL gre 192.0.2.10 <- 203.0.113.8 NO_TRAFFIC:INITIATING",
        ("192.0.2.10", "203.0.113.8"),
    ),
    # The printer of this state model writes flow levels for every protocol
    # except IPv4 icmp; the numeric tail of the IPv6 form is read as before.
    "ipv6-icmp with flow levels": ("ALL ipv6-icmp fe80::1[0] <- fe80::2[0] NO_TRAFFIC:SINGLE", ()),
    "icmp6 with numbers": ("ALL icmp6 fe80::1[135] <- fe80::2[135] 0:0", ()),
}


def edit(row: str, old: str, new: str) -> str:
    """One edit of a readable row; the edited part occurs exactly once."""
    assert row.count(old) == 1, (row, old)
    return row.replace(old, new)


@pytest.mark.parametrize("row,addresses", list(CAPTURED.values()), ids=list(CAPTURED))
def test_captured_form_is_read_with_every_ipv4_address_it_names(
    row: str, addresses: tuple[str, ...]
) -> None:
    assert state_addresses(row) == ((row, addresses),)


@pytest.mark.parametrize("row,addresses", list(DERIVED.values()), ids=list(DERIVED))
def test_form_that_follows_from_the_same_rules_is_read(
    row: str, addresses: tuple[str, ...]
) -> None:
    assert state_addresses(row) == ((row, addresses),)


def test_captured_table_is_read_row_by_row_in_the_printer_spacing() -> None:
    # print_state puts seven spaces between the last endpoint and the status.
    printed = [
        (" ".join(row.split()[:-1]) + " " * 7 + row.split()[-1], addresses)
        for row, addresses in CAPTURED.values()
    ]
    table = "\n".join(row for row, _ in printed) + "\n"

    assert state_addresses(table) == tuple(printed)


@pytest.mark.parametrize(
    "protocol",
    [
        *("igmp", "esp", "ah", "gre", "sctp", "ipv6", "rsvp-e2e-ignore"),
        *("3pc", "tp++", "ax.25", "a/n"),  # every other character of a database name
        *("61", "253", "255"),  # numbers the database has no name for
    ],
)
def test_any_name_of_the_protocol_database_or_a_number_is_a_protocol(protocol: str) -> None:
    row = f"ALL {protocol} 192.0.2.10 <- 203.0.113.8 NO_TRAFFIC:SINGLE"

    assert state_addresses(row) == ((row, ("192.0.2.10", "203.0.113.8")),)


@pytest.mark.parametrize(
    "valid,damaged",
    [
        # The refusals named with the capture.
        pytest.param(OUTBOUND, edit(OUTBOUND, "-> 203", "<- 203"), id="second arrow turns round"),
        pytest.param(
            INBOUND, edit(INBOUND, "<- 192.0.2.10", "-> 192.0.2.10"), id="first arrow turns round"
        ),
        pytest.param(OUTBOUND, edit(OUTBOUND, " 192.0.2.10:45002", ""), id="empty middle endpoint"),
        pytest.param(
            OUTBOUND,
            edit(OUTBOUND, " ESTABLISHED", " -> 203.0.113.9:443 ESTABLISHED"),
            id="third arrow",
        ),
        pytest.param(OUTBOUND, edit(OUTBOUND, ":443", ":65536"), id="port above 65535"),
        pytest.param(TCP6, edit(TCP6, "[50124]", "[65536]"), id="IPv6 port above 65535"),
        pytest.param(OUTBOUND, edit(OUTBOUND, " -> 192", " 192"), id="no arrow after lan"),
        pytest.param(OUTBOUND, edit(OUTBOUND, " -> 203", " 203"), id="no arrow before ext"),
        pytest.param(PLAIN, edit(PLAIN, " -> ", " "), id="no arrow at all"),
        pytest.param(OUTBOUND, edit(OUTBOUND, "12:45002", "12"), id="tcp lan without port"),
        pytest.param(OUTBOUND, edit(OUTBOUND, "10:45002", "10"), id="tcp gwy without port"),
        pytest.param(OUTBOUND, edit(OUTBOUND, ":443", ""), id="tcp ext without port"),
        pytest.param(INBOUND, edit(INBOUND, ":7000", ""), id="udp lan without port"),
        pytest.param(PLAIN, edit(PLAIN, ":51000", ""), id="untranslated tcp without port"),
        pytest.param(TCP6, edit(TCP6, "[443]", ""), id="IPv6 tcp without port"),
        pytest.param(OUTBOUND, OUTBOUND + "\x00", id="trailing NUL"),
        pytest.param(OUTBOUND, edit(OUTBOUND, "-> 203", "->\x1b 203"), id="escape in a row"),
        pytest.param(OUTBOUND, edit(OUTBOUND, "ALL", "ALL\x7f"), id="delete in the label"),
        pytest.param(OUTBOUND, edit(OUTBOUND, "-> 203", "->\x0b203"), id="vertical tab in a row"),
        pytest.param(OUTBOUND, edit(OUTBOUND, "ALL ", "ALL\x1f"), id="unit separator for a space"),
        # Parentheses belong to the one-arrow display and never meet a second arrow.
        pytest.param(
            WRAPPED,
            edit(WRAPPED, " SINGLE", " -> 203.0.113.8:80 SINGLE"),
            id="parentheses and two arrows",
        ),
        pytest.param(
            OUTBOUND,
            edit(OUTBOUND, "192.0.2.10:45002", "(192.0.2.10:45002)"),
            id="parenthesised gwy",
        ),
        pytest.param(
            WRAPPED, edit(WRAPPED, "192.0.2.10:45001 (", "("), id="only a parenthesised endpoint"
        ),
        # The marker is one prefix of one endpoint.
        pytest.param(MARKED, edit(MARKED, "-> 192.0.2.10", "-> ~192.0.2.10"), id="two markers"),
        pytest.param(MARKED, edit(MARKED, "~192", "~~192"), id="doubled marker"),
        pytest.param(MARKED, edit(MARKED, "~192.0.2.82:7000", "~"), id="marker alone"),
        pytest.param(MARKED, edit(MARKED, "~192.0.2.82:", "192.0.2.82~:"), id="marker inside"),
        pytest.param(WRAPPED, edit(WRAPPED, "-> 192", "-> ~192"), id="marker beside parentheses"),
        pytest.param(WRAPPED, edit(WRAPPED, "(198", "(~198"), id="marker in parentheses"),
        # Zero is a port only as the capture prints it.
        pytest.param(
            "ALL icmp 192.0.2.1:8 <- 192.0.2.2:8 0:0",
            "ALL icmp 192.0.2.1:0 <- 192.0.2.2:0 0:0",
            id="IPv4 port zero",
        ),
        pytest.param(ICMP6, edit(ICMP6, "fe80::1[0]", "fe80::1[00]"), id="zero written twice"),
        # The status tail belongs to the protocol.
        pytest.param(INBOUND, edit(INBOUND, "MULTIPLE:MULTIPLE", "0:0"), id="udp numbers"),
        pytest.param(INBOUND, edit(INBOUND, "MULTIPLE:MULTIPLE", "3:0"), id="udp unnamed level"),
        pytest.param(
            INBOUND,
            edit(INBOUND, "MULTIPLE:MULTIPLE", "ESTABLISHED:ESTABLISHED"),
            id="udp with tcp names",
        ),
        pytest.param(
            OUTBOUND,
            edit(OUTBOUND, "ESTABLISHED:ESTABLISHED", "SINGLE:MULTIPLE"),
            id="tcp with flow levels",
        ),
        pytest.param(
            OUTBOUND,
            edit(OUTBOUND, "ESTABLISHED:ESTABLISHED", "<BAD STATE LEVELS 12:12>"),
            id="tcp bad levels",
        ),
        pytest.param(
            OUTBOUND, edit(OUTBOUND, "ESTABLISHED:ESTABLISHED", "11:11"), id="tcp numbers"
        ),
        pytest.param(ICMP6, edit(ICMP6, "0:0", "NO_TRAFFIC:SINGLE"), id="icmp with flow levels"),
        pytest.param(IGMP, edit(IGMP, "NO_TRAFFIC:SINGLE", "0:1"), id="numbers for named levels"),
        pytest.param(IGMP, edit(IGMP, "NO_TRAFFIC:SINGLE", "256:0"), id="level above 255"),
        pytest.param(IGMP, edit(IGMP, "NO_TRAFFIC:SINGLE", "SINGLE"), id="one level"),
        pytest.param(IGMP, edit(IGMP, " NO_TRAFFIC:SINGLE", ""), id="no status tail"),
        # INITIATING and ESTABLISHED are levels of GRE and ESP only.
        pytest.param(
            IGMP, edit(IGMP, "NO_TRAFFIC:SINGLE", "INITIATING:ESTABLISHED"), id="igmp, esp levels"
        ),
        pytest.param(
            INBOUND,
            edit(INBOUND, "MULTIPLE:MULTIPLE", "NO_TRAFFIC:INITIATING"),
            id="udp, gre level",
        ),
        pytest.param(
            ESP, edit(ESP, "MULTIPLE:MULTIPLE", "SYN_SENT:ESTABLISHED"), id="esp with a tcp name"
        ),
        # The protocol is a lower-case database name or a number.
        pytest.param(IGMP, edit(IGMP, "igmp", "IGMP"), id="upper-case protocol"),
        pytest.param(IGMP, edit(IGMP, "igmp", "ig_mp"), id="protocol outside the alphabet"),
        pytest.param(IGMP, edit(IGMP, "igmp", "i" * 33), id="protocol too long"),
        pytest.param(IGMP, edit(IGMP, "igmp ", ""), id="no protocol"),
    ],
)
def test_row_one_edit_away_from_a_readable_row_is_refused(valid: str, damaged: str) -> None:
    assert state_addresses(valid)[0][0] == valid
    with pytest.raises(PFError):
        state_addresses(damaged)


@pytest.mark.parametrize(
    "separator",
    ["\r\n", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"],
    ids=["CRLF", "CR", "VT", "FF", "FS", "GS", "RS", "NEL", "LS", "PS"],
)
def test_only_a_line_feed_ends_a_row(separator: str) -> None:
    assert len(state_addresses(OUTBOUND + "\n" + IGMP + "\n")) == 2
    with pytest.raises(PFError):
        state_addresses(OUTBOUND + separator + IGMP + "\n")


# Never a complete numerical endpoint, whatever the protocol of the row.
BROKEN_ENDPOINTS = [
    "?",  # print_addr writes this when it cannot format an address
    "host.example:443",
    "198.51.100:45002",
    "198.51.100.256:45002",
    "198.51.100.12:",
    "198.51.100.12:65536",
    "198.51.100.12:45002:7",
    "198.51.100.12/32:45002",
    "2001:db8::1[443",
    "2001:db8::1443]",
    "2001:db8:::1[443]",
    "2001:db8::1[65536]",
    "2001:db8::1[]",
    "2001:db8::1%lo0[443]",
    "[443]",
    "~",
]
ENDPOINT_ROWS = {
    "outbound": OUTBOUND,
    "inbound": INBOUND,
    "marked": MARKED,
    "tcp6": TCP6,
    "igmp": IGMP,
    "icmp6": ICMP6,
    "plain": PLAIN,
    "wrapped": WRAPPED,
    "esp": ESP,
}


def endpoint_positions(row: str) -> list[int]:
    return [
        index
        for index, token in enumerate(row.split())
        if 2 <= index < len(row.split()) - 1 and token not in {"->", "<-"}
    ]


def with_endpoint(row: str, index: int, change: Callable[[str], str]) -> str:
    """Change the endpoint inside one token; its marker or parentheses stay."""
    pieces = row.split()
    token = pieces[index]
    if token.startswith("("):
        pieces[index] = f"({change(token[1:-1])})"
    elif token.startswith("~"):
        pieces[index] = f"~{change(token[1:])}"
    else:
        pieces[index] = change(token)
    return " ".join(piece for piece in pieces if piece)


@pytest.mark.parametrize(
    "row,index",
    [
        pytest.param(row, index, id=f"{name}-{position}")
        for name, row in ENDPOINT_ROWS.items()
        for position, index in enumerate(endpoint_positions(row))
    ],
)
def test_row_is_refused_when_any_one_endpoint_is_damaged(row: str, index: int) -> None:
    assert with_endpoint(row, index, lambda endpoint: endpoint) == row
    assert state_addresses(row)[0][0] == row
    damages: list[Callable[[str], str]] = [
        *(lambda _, broken=broken: broken for broken in BROKEN_ENDPOINTS),
        lambda endpoint: endpoint + "x",
        lambda endpoint: "x" + endpoint,
        lambda endpoint: endpoint + ":",
        lambda endpoint: endpoint.replace(".", ",").replace("::", ",,"),
        lambda endpoint: f"({endpoint})",
        lambda endpoint: f"~~{endpoint}",
        lambda endpoint: "",
    ]
    for damage in damages:
        damaged = with_endpoint(row, index, damage)
        assert damaged != row
        with pytest.raises(PFError):
            state_addresses(damaged)
        # One damaged row leaves nothing of a table that is otherwise complete.
        with pytest.raises(PFError):
            state_addresses(f"{IGMP}\n{damaged}\n{PLAIN}")


@pytest.mark.parametrize("row,addresses", list(CAPTURED.values()), ids=list(CAPTURED))
def test_only_the_complete_row_is_read_and_no_truncation_of_it(
    row: str, addresses: tuple[str, ...]
) -> None:
    assert state_addresses(row) == ((row, addresses),)
    for length in range(1, len(row)):
        with pytest.raises(PFError):
            state_addresses(row[:length])
        with pytest.raises(PFError):
            state_addresses(f"{IGMP}\n{row[:length]}")


def address(environment: Any, service: str) -> str:
    return str(environment[4][-1].services[service].data["ipv4"])


def kernel_table(environment: Any) -> str:
    """A translated outbound state of the media guest beside an unrelated IGMP row."""
    assert address(environment, "media-controller") == "198.51.100.12"
    return f"{OUTBOUND}\n{IGMP}"


def test_pass_commits_and_a_pause_drains_beside_translated_and_igmp_rows(
    environment: Any,
) -> None:
    root, _, _, backend, _ = environment
    backend.flow_states = kernel_table(environment)
    approve_all(environment)

    first = run_pass(environment)

    assert first["phase"] == "committed"
    assert sorted(first["changed"]) == [
        "dns-tcp:activate",
        "dns-udp:activate",
        "media-udp:activate",
        "proxy-standard:activate",
    ]
    assert "static-port" in backend.rules
    assert root.read("journal.json")["phase"] == "committed"
    # The table is readable on every pass: a healthy pass changes nothing.
    loads = sum(command[0] == "replace" for command in backend.commands)
    second = run_pass(environment)
    assert second["phase"] == "committed" and second["changed"] == []
    assert sum(command[0] == "replace" for command in backend.commands) == loads

    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    paused = run_pass(environment)

    assert paused["phase"] == "inhibited"
    assert backend.rules == ""
    assert root.read("live.json")["records"] == {}
    assert ("drain", "198.51.100.12") in backend.commands
    # The guest's translated state is gone; the row that names no guest stays.
    assert backend.flow_states == IGMP


def test_damaged_translated_row_still_retires_everything_as_unknown(environment: Any) -> None:
    root, _, _, backend, _ = environment
    backend.flow_states = kernel_table(environment)
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"

    backend.flow_states = f"{edit(OUTBOUND, '-> 203', '<- 203')}\n{IGMP}"
    result = run_pass(environment)

    assert result["phase"] == "failed"
    assert backend.rules == ""
    assert root.read("journal.json")["reason"] == "kernel-state-unknown"
    assert backend.flow_states  # No complete read, so no drain is claimed.


def drain_readback(table: str, ipv4: str) -> None:
    """The owner's own drain against a kernel whose states do not go away."""

    def call(operation: str, *arguments: str) -> str:
        return table if operation == "states" else ""

    shell = object.__new__(ShellBackend)
    shell._call = call  # type: ignore[method-assign]
    shell.drain(ipv4)


@pytest.mark.parametrize("named", CAPTURED["translated outbound"][1])
def test_drain_readback_counts_an_address_at_any_endpoint_of_a_translated_row(named: str) -> None:
    # Only the translated row names these addresses: one as lan, gwy and ext each.
    table = f"{IGMP}\n{OUTBOUND}\n{TCP6}"

    with pytest.raises(PFError, match="scoped PF states remain"):
        drain_readback(table, named)
    # A complete read of the same table shows another address as drained, even
    # one whose text begins a named address.
    drain_readback(table, "198.51.100.1")

"""The public guard reports shared-address-space, IPv6 and hardware addresses."""

from __future__ import annotations

import hashlib
import json

import pytest

from netorch.privacy import PrivacyError, PrivacyException, scan_framework, scan_text


def joined(separator, *parts):
    """Assemble a value at run time so that this file holds nothing the guard reports."""
    return separator.join(parts)


# Invented values. The IPv6 and hardware examples lie in special-purpose blocks
# (6to4 of a documentation address, benchmarking, the registry's own hardware
# prefix), so none of them can belong to a real installation.
SHARED = joined(".", "100", "100", "1", "2")
UNIQUE_LOCAL = joined(":", "fd12", "3456", "789a", "1", "", "10")
GLOBAL = joined(":", "2002", "c000", "204", "", "1")
DEVICE = joined(":", "00", "00", "5e", "00", "52", "a1")


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def reported(text):
    return [(f.kind, f.column, f.value_sha256) for f in scan_text(text, path="docs/example.md")]


def test_findings_name_kind_and_place_without_echoing_the_value():
    text = f"overlay {SHARED}\nguest {UNIQUE_LOCAL}\nadapter {DEVICE}\n"
    findings = scan_text(text, path="docs/example.md")
    assert [(f.kind, f.line, f.column) for f in findings] == [
        ("private-address", 1, 9),
        ("private-address", 2, 7),
        ("hardware-address", 3, 9),
    ]
    assert [f.value_sha256 for f in findings] == [
        digest(SHARED),
        digest(UNIQUE_LOCAL),
        digest(DEVICE),
    ]
    emitted = json.dumps([f.to_dict() for f in findings])
    assert all(value not in emitted for value in (SHARED, UNIQUE_LOCAL, DEVICE))


# Shared address space of carrier-grade NAT


@pytest.mark.parametrize(
    "address",
    [
        joined(".", "100", "64", "0", "0"),
        joined(".", "100", "64", "0", "1"),
        joined(".", "100", "100", "1", "2"),
        joined(".", "100", "127", "255", "255"),
        joined(".", "100", "64", "0", "0") + "/10",
        joined(".", "100", "96", "7", "0") + "/24",
    ],
)
@pytest.mark.parametrize("ending", ["", ".", ". Next sentence", ",", ")", ":8080"])
def test_shared_address_space_is_reported(address, ending):
    assert reported("node " + address + ending) == [("private-address", 6, digest(address))]


@pytest.mark.parametrize("address", ["100.63.255.255", "100.128.0.0", "100.0.0.1", "101.64.0.1"])
def test_addresses_beside_the_shared_space_are_not_reported(address):
    assert reported("node " + address) == []


# IPv6


@pytest.mark.parametrize(
    "address",
    [
        UNIQUE_LOCAL,
        UNIQUE_LOCAL.upper(),
        joined(":", "fc00", "", "1"),
        joined(":", "fd00", "", ""),
        joined(":", "fdff", "ffff", "ffff", "ffff", "ffff", "ffff", "ffff", "ffff"),
        joined(":", "fec0", "", "1"),
        GLOBAL,
        joined(":", "2001", "2", "0", "1", "", "1"),
        joined(":", "3fff", "0", "0", "1", "", "10"),
        joined(":", "2002", "c000", "0204", "0000", "0000", "0000", "0000", "0001"),
        joined(":", "2002", "c000", "204", "", joined(".", "192", "0", "2", "9")),
    ],
)
def test_unicast_ipv6_literal_is_reported(address):
    assert reported("guest " + address) == [("private-address", 7, digest(address))]


@pytest.mark.parametrize(
    "before,after",
    [
        ("", "."),
        ("", ". Next sentence"),
        ("[", "]:443"),
        ("https://[", "]/path"),
        ('"', '"'),
        ("(", ")"),
        ("address=", ","),
        ("", "%example0"),
        ("", "[443]"),
    ],
)
def test_ipv6_literal_is_found_in_its_usual_surroundings(before, after):
    assert reported(before + UNIQUE_LOCAL + after) == [
        ("private-address", len(before) + 1, digest(UNIQUE_LOCAL))
    ]


def test_ipv6_prefix_is_reported_with_its_length():
    prefix = joined(":", "fd12", "3456", "789a", "", "") + "/48"
    assert reported("Route " + prefix + ".") == [("private-address", 7, digest(prefix))]


def test_mapped_form_of_a_private_ipv4_address_is_reported():
    private = joined(".", "10", "25", "36", "47")
    dotted = joined(":", "", "", "ffff", private)
    assert ("private-address", 1, digest(dotted)) in reported(dotted)
    spelled_in_hex = joined(":", "", "", "ffff", "a19", "242f")
    assert reported(spelled_in_hex) == [("private-address", 1, digest(spelled_in_hex))]


@pytest.mark.parametrize(
    "address",
    [
        "2001:db8::1",
        "2001:db8::/32",
        "2001:DB8:0:1::10",
        "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
        "::1",
        "::",
        "fe80::1",
        "fe80::1%example0",
        "febf::1",
        "ff02::1",
        "ff05::1:3",
        "::ffff:192.0.2.10",
        "::ffff:198.51.100.7",
        "::ffff:203.0.113.9",
        "::ffff:127.0.0.1",
        "::ffff:0.0.0.0",
    ],
)
def test_documentation_and_scope_bound_ipv6_addresses_are_not_reported(address):
    assert reported(address) == []
    assert reported("See " + address + ". [" + address + "]:443") == []


@pytest.mark.parametrize(
    "text",
    [
        # Times and dates
        "12:34:56",
        "07:03:21.123456",
        "2026-10-06T07:03:21Z",
        "2026-10-06 07:03:21+02:00",
        "1:02:03",
        "00:00:00",
        "23:59:59:24",
        "20261006-070321",
        "06-10-26-07-03-21",
        "10-06-26-07-03-21",
        # Versions
        "1.2.3",
        "v0.3.1",
        "27.0.1",
        "0.47.0",
        "2881.120.11",
        "1:2.30-1",
        "2:1.0",
        "100.64",
        "100.0.4896.127",
        # Test identifiers
        "tests/test_a.py::test_b",
        "tests/test_a.py::TestCase::test_b[a::b]",
        "a::b",
        "test_a.py::test_b[fd-1]",
        # Scope operators
        "x::y",
        "std::string",
        "ns::fn()",
        "::global",
        "a::b::c",
        "abc::def",
        "cafe::babe",
        "dead::beef",
        "bad::v6",
        "fd::close",
        "Development Status :: 3 - Alpha",
        # Slices
        "x[::2]",
        "x[1::2]",
        "x[::-1]",
        "x[a::b]",
        "x[:]",
        "x[1:2:3]",
        "a[::2, 1::2]",
        "rows[10::5]",
        "the slice `[::2]`",
        # Other colon and hex text
        "1:2:3",
        ":::",
        "1::2::3",
        "12345::1",
        "sha256:" + "ab" * 32,
        "550e8400-e29b-41d4-a716-446655440000",
        "(?::[0-9a-f]{2}){5}",
        "::ffff:0.0.0.0.53",
    ],
)
def test_text_that_only_looks_like_an_address_is_not_reported(text):
    assert reported(text) == []
    assert reported("See " + text + " here.") == []


@pytest.mark.parametrize("glue", ["x{}", "{}x", "{}.5", ":{}", "{}:", "{}:1:2:3:4:5:6:7:8"])
def test_ipv6_literal_inside_a_longer_token_is_not_reported(glue):
    assert reported(glue.format(UNIQUE_LOCAL)) == []


# Hardware addresses


@pytest.mark.parametrize(
    "address",
    [
        DEVICE,
        DEVICE.upper(),
        DEVICE.replace(":", "-"),
        joined(":", "00", "00", "5e", "00", "52", "01"),
        joined(":", "00", "00", "5e", "00", "54", "00"),
        joined(":", "04", "00", "5e", "00", "53", "01"),
        joined(":", "08", "00", "00", "00", "00", "01"),
        joined(":", "0c", "00", "00", "00", "00", "01"),
        joined(":", "00", "00", "5e", "00", "52", "a1", "b2", "c3"),
        joined(":", "00", "00", "5e", "00", "53", "a1", "b2", "c3"),
    ],
)
@pytest.mark.parametrize("ending", ["", ".", ". Next sentence", ",", " on example0 [ethernet]"])
def test_universally_administered_device_address_is_reported(address, ending):
    assert reported("at " + address + ending) == [("hardware-address", 4, digest(address))]


@pytest.mark.parametrize(
    "address",
    [
        "02:00:00:00:00:01",
        "06:00:00:00:00:01",
        "0a:00:00:00:00:01",
        "0E:00:00:00:00:01",
        "a2:b3:c4:d5:e6:f7",
        "fe:ff:ff:ff:ff:ff",
        "02-00-00-00-00-AF",
        "02:00:00:00:00:00:00:01",
        "00:00:5e:00:53:00",
        "00:00:5E:00:53:FF",
        "00-00-5e-00-53-af",
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
        "01:00:5e:00:00:fb",
        "33:33:00:00:00:01",
        "01:00:00:00:00:01",
    ],
)
def test_fixture_group_and_unspecified_hardware_addresses_are_not_reported(address):
    assert reported(address) == []
    assert reported("at " + address + ". Next sentence") == []


@pytest.mark.parametrize(
    "glue",
    [
        "x{}",
        "{}x",
        ":{}",
        "{}:",
        "-{}",
        "{}-",
        "aa:{}",
        "{}:aa",
        "{}:aa:bb:cc:dd:ee:ff:00:11:22:33",
        "{}.pcap",
    ],
)
def test_device_address_inside_a_longer_token_is_not_reported(glue):
    assert reported(glue.format(DEVICE)) == []


def test_other_groupings_are_not_hardware_addresses():
    pairs = DEVICE.split(":")
    for text in (
        ":".join(pairs[:5]),
        ":".join(pairs[:4]),
        ":".join([*pairs, "07"]),
        ":".join(pair.lstrip("0") or "0" for pair in pairs),
        pairs[0] + ":" + "-".join(pairs[1:]),
        ".".join(["0000", "5e00", "52a1"]),
        "".join(pairs),
    ):
        assert reported(text) == [], text


def test_hyphenated_form_needs_a_hexadecimal_letter():
    # Six decimal pairs joined by hyphens are a date and time, not an address.
    pairs = ["00", "11", "22", "33", "44", "55"]
    assert reported("-".join(pairs)) == []
    assert reported(":".join(pairs)) == [("hardware-address", 1, digest(":".join(pairs)))]


# Exceptions and limits


def test_new_kind_takes_an_exact_exception(tmp_path):
    (tmp_path / "fixture.txt").write_text("at " + DEVICE + "\n")
    assert [f.kind for f in scan_framework(tmp_path, files=["fixture.txt"])] == ["hardware-address"]
    exact = PrivacyException("fixture.txt", "hardware-address", "synthetic fixture", digest(DEVICE))
    assert scan_framework(tmp_path, files=["fixture.txt"], exceptions=[exact]) == ()
    other = PrivacyException("fixture.txt", "hardware-address", "another value", "a" * 64)
    assert len(scan_framework(tmp_path, files=["fixture.txt"], exceptions=[other])) == 1


def test_many_addresses_are_still_a_bounded_refusal():
    with pytest.raises(PrivacyError, match="findings"):
        scan_text((DEVICE + " ") * 10001, path="fixture")


def test_local_host_names_and_other_reverse_dns_labels_are_left_to_the_instance_pass():
    # Deliberately not detected: in code the same shapes are attribute access.
    assert reported("host example-host.local label de.example.service") == []
    assert reported("self.local = local.strip(); de.example.run()") == []

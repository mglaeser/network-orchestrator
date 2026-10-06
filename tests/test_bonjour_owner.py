from __future__ import annotations

import copy
import io
import os
import sys
import time
from concurrent.futures import Future
from dataclasses import asdict, replace
from pathlib import Path
from typing import ClassVar

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.codec import canonical_bytes, digest
from netorch.config import config_digest, load_config, profile_digest, to_dict
from netorch.discovery import Record
from netorch.discovery_plan import discovery_digest
from netorch.mock import initial_snapshot, mock_admissions
from netorch.model import PortRange, Profile, Safety
from netorch.owners import RootReportOwner
from netorch.process import Result
from netorch.state import (
    Intent,
    Observation,
    Snapshot,
    admissions_to_dict,
    intent_to_dict,
    snapshot_to_dict,
)
from netorch.storage import Store


@pytest.fixture
def config():
    return load_config(Path(__file__).resolve().parents[1] / "examples/network.json")


def write_private(path, value):
    path.write_bytes(canonical_bytes(value))
    path.chmod(0o600)
    return path


@pytest.fixture
def settings(config, tmp_path):
    return owner.BonjourSettings(
        "bonjour-manager",
        write_private(tmp_path / "network.json", to_dict(config)),
        tmp_path / "bindings.json",
        tmp_path / "admissions.json",
        write_private(tmp_path / "intent.json", intent_to_dict(Intent())),
        tmp_path / "state",
        (owner.GuestInterface("wired-lan", "bridge-test", "198.51.100.1"),),
    )


def snapshot(config):
    base = initial_snapshot(config)
    profiles = {}
    for item in config.profiles:
        endpoint = base.services[item.service]
        target = (
            config.scope(item.scope).host_ipv4
            if item.kind == "host-redirect"
            else endpoint.data["ipv4"]
        )
        profiles[item.id] = Observation(
            "present",
            "verified",
            1000,
            endpoint.generation,
            {
                "policy_digest": profile_digest(config, item),
                "target_ipv4": target,
                "target_generation": endpoint.generation,
                "network_generation": base.network_generation,
                "states": [],
            },
        )
    return replace(base, profiles=profiles)


def policy(config, identifier="media-import"):
    return next(item for item in config.discovery if item.id == identifier)


def media_record(**kwargs):
    return replace(
        Record(
            "Example speaker",
            "_airplay._tcp",
            "speaker.local.",
            7000,
            "192.0.2.82",
            (b"model=AudioAccessory5,1", b"binary=\0\xff"),
            "en0",
            1000,
        ),
        **kwargs,
    )


def expected_settings(settings):
    return {
        "schema_version": 1,
        "owner": settings.owner,
        "config": str(settings.config),
        "bindings": str(settings.bindings),
        "admissions": str(settings.admissions),
        "intent": str(settings.intent),
        "state_dir": str(settings.state_dir),
        "scopes": [
            {"id": "wired-lan", "guest_interface": "bridge-test", "guest_ipv4": "198.51.100.1"}
        ],
    }


def test_settings_are_external_private_data(settings, tmp_path):
    path = write_private(tmp_path / "bonjour.json", expected_settings(settings))
    assert owner.load_settings(path) == settings


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("owner", "site-forwarding"),
        ("config", "relative.json"),
        ("bindings", "relative.json"),
        ("admissions", 42),
        ("intent", "nul\0path"),
        ("state_dir", "."),
        ("scopes", []),
        ("scopes", {}),
        ("scan_seconds", 0),
        ("scan_seconds", 6),
        ("scan_seconds", True),
        ("poll_seconds", 11),
        ("poll_seconds", -1),
        ("poll_seconds", "5"),
        ("eligible_model_prefixes", []),
        ("eligible_model_prefixes", ["AppleTV", "AppleTV"]),
        ("eligible_model_prefixes", ["$()"]),
        ("eligible_model_prefixes", [3]),
        ("unknown", True),
    ],
)
def test_settings_reject_ambiguous_authority(settings, tmp_path, key, value):
    raw = expected_settings(settings)
    raw[key] = value
    path = write_private(tmp_path / "bonjour.json", raw)
    with pytest.raises((ValueError, KeyError)):
        owner.load_settings(path)


@pytest.mark.parametrize(
    "change",
    ["extra", "missing", "duplicate", "guest-outside", "same-interface", "zero", "bad-name"],
)
def test_scope_bindings_are_closed(settings, tmp_path, change):
    raw = expected_settings(settings)
    item = raw["scopes"][0]
    if change == "extra":
        item["command"] = "ignore"
    elif change == "missing":
        del item["guest_ipv4"]
    elif change == "duplicate":
        raw["scopes"].append(item.copy())
    elif change == "guest-outside":
        item["guest_ipv4"] = "203.0.113.1"
    elif change == "same-interface":
        item["guest_interface"] = "en0"
    elif change == "zero":
        item["guest_interface"] = "0"
    else:
        item["guest_interface"] = "bridge;touch"
    with pytest.raises(ValueError):
        owner.load_settings(write_private(tmp_path / "bonjour.json", raw))


@pytest.mark.parametrize("mode", [0o644, 0o666, 0o400])
def test_owner_input_must_have_exact_private_mode(tmp_path, mode):
    path = write_private(tmp_path / "input.json", {})
    path.chmod(mode)
    with pytest.raises(ValueError):
        owner.private_json(path)


def test_owner_input_refuses_symlink_and_hardlink(tmp_path):
    path = write_private(tmp_path / "input.json", {})
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        owner.private_json(alias)
    alias.unlink()
    os.link(path, alias)
    with pytest.raises(ValueError):
        owner.private_json(path)


@given(st.lists(st.binary(max_size=255), max_size=8))
def test_binary_txt_json_and_cli_roundtrip(entries):
    record = media_record(txt=tuple(entries))
    assert owner.record_from_dict(owner.record_to_dict(record)) == record
    arguments = native.registration_argv(record)[12:]
    restored = tuple(bytes.fromhex(argument.replace("\\x", "")) for argument in arguments)
    assert restored == tuple(entries)


def test_browse_parser_preserves_names_and_removes_gone_records():
    raw = (
        b"Using interface 7\nBrowsing for _airplay._tcp.local.\n"
        b"Timestamp A/R Flags if Domain Service Type Instance Name\n"
        b"12:34:56.000  Add        2   7 local.               _airplay._tcp.       "
        b"Living room speaker\n"
        b"12:34:57.000  Add        2   7 local.               _airplay._tcp.       Old speaker\n"
        b"12:34:58.000  Rmv        0   7 local.               _airplay._tcp.       Old speaker\n"
    )
    assert native.browse_names(raw, "_airplay._tcp", 7, 8) == ("Living room speaker",)


@pytest.mark.parametrize("stamp", [" 0:00:00.000", " 9:59:59.999", "10:00:00.000", "23:59:59.999"])
def test_native_source_timestamp_format_in_all_discovery_parsers(stamp):
    # Synthetic values, with spacing from Apple's printtimestamp_F (%2d hour),
    # browse_reply, resolve_reply, addrinfo_reply and qr_reply. Source provenance:
    # mDNSResponder-2881.120.11/Clients/dns-sd.c, not a production capture.
    name = "Example  speaker"
    fullname = name + "._airplay._tcp.local."
    browse = (
        "Using interface 7\nBrowsing for _airplay._tcp.local.\n"
        "Timestamp     A/R    Flags  if Domain               Service Type         Instance Name\n"
        f"{stamp}  Add {2:8X} {7:3d} {'local.':<20} {'_airplay._tcp.':<20} {name}\n"
    ).encode()
    resolved = (
        f"{stamp}  {fullname} can be reached at speaker.local.:7000 (interface 7) Flags: 2\n"
    ).encode()
    address = (
        f"{stamp}  Add  2            7  speaker.local.                         192.0.2.82 120\n"
    ).encode()
    txt = (f"{stamp}  Add  2            7  {fullname} TXT    IN     2 bytes: 01 61\n").encode()
    assert native.browse_names(browse, "_airplay._tcp", 7, 8) == (name,)
    assert native.resolve_endpoint(resolved, 7) == (fullname, "speaker.local.", 7000)
    assert native.resolve_ipv4(address, "speaker.local.", 7) == "192.0.2.82"
    assert native.resolve_txt(txt, fullname, 7) == (b"a",)


@pytest.mark.parametrize(
    "stamp",
    [
        "9:00:00.000",
        "09:00:00.000",
        "  9:00:00.000",
        "24:00:00.000",
        "12:60:00.000",
        "12:00:60.000",
        "12:00:00.00",
    ],
)
def test_discovery_parsers_reject_malformed_native_timestamp(stamp):
    with pytest.raises(native.DiscoveryFailure):
        native.browse_names(
            (
                f"{stamp}  Add        2   7 local.               _airplay._tcp.       "
                "Example speaker\n"
            ).encode(),
            "_airplay._tcp",
            7,
            8,
        )
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_endpoint(
            (
                f"{stamp}  Example speaker._airplay._tcp.local. can be reached at "
                "speaker.local.:7000 (interface 7)\n"
            ).encode(),
            7,
        )
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_ipv4(
            f"{stamp}  Add 2 7 speaker.local. 192.0.2.82 120\n".encode(),
            "speaker.local.",
            7,
        )
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_txt(
            (
                f"{stamp}  Add 2 7 Example speaker._airplay._tcp.local. TXT IN 2 bytes: 01 61\n"
            ).encode(),
            "Example speaker._airplay._tcp.local.",
            7,
        )


@pytest.mark.parametrize(
    "stamp",
    ["9:00:00.000", "09:00:00.000", "  9:00:00.000", "24:00:00.000", "12:60:00.000"],
)
def test_mixed_valid_and_malformed_native_callbacks_never_become_success(stamp):
    good = "12:34:56.000"
    browse = "{stamp}  Add        2   7 local.               _airplay._tcp.       Example speaker\n"
    endpoint = (
        "{stamp}  Example speaker._airplay._tcp.local. can be reached at "
        "speaker.local.:7000 (interface 7)\n"
    )
    address = "{stamp}  Add 2 7 speaker.local. 192.0.2.82 120\n"
    txt = "{stamp}  Add 2 7 Example speaker._airplay._tcp.local. TXT IN 2 bytes: 01 61\n"
    cases = [
        (browse, lambda raw: native.browse_names(raw, "_airplay._tcp", 7, 8)),
        (endpoint, lambda raw: native.resolve_endpoint(raw, 7)),
        (address, lambda raw: native.resolve_ipv4(raw, "speaker.local.", 7)),
        (txt, lambda raw: native.resolve_txt(raw, "Example speaker._airplay._tcp.local.", 7)),
    ]
    for template, parser in cases:
        with pytest.raises(native.DiscoveryFailure):
            parser((template.format(stamp=good) + template.format(stamp=stamp)).encode())


@pytest.mark.parametrize("unknown", [b"unexpected callback\n", b"12:34:56.000  damaged row\n"])
def test_mixed_valid_and_unknown_query_rows_are_refused(unknown):
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_endpoint(
            b"12:34:56.000  Example speaker._airplay._tcp.local. can be reached at "
            b"speaker.local.:7000 (interface 7)\n" + unknown,
            7,
        )
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_ipv4(
            b"12:34:56.000  Add 2 7 speaker.local. 192.0.2.82 120\n" + unknown,
            "speaker.local.",
            7,
        )
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_txt(
            txt_output(b"\x01a") + unknown,
            "Example speaker._airplay._tcp.local.",
            7,
        )


def test_native_srv_banners_and_binary_txt_continuation_are_not_callback_data():
    raw = (
        b"Using interface 7\nLookup Example speaker._airplay._tcp.local.\n"
        b"DATE: ---Mon 05 Oct 2026---\n"
        b" 9:00:00.000  Example\\032speaker._airplay._tcp.local. can be reached at "
        b"speaker.local.:7000 (interface 7)\n bin=\xff\\\\x00\n"
    )
    assert native.resolve_endpoint(raw, 7) == (
        r"Example\032speaker._airplay._tcp.local.",
        "speaker.local.",
        7000,
    )


@pytest.mark.parametrize("continuation", [b"", b" key=value", b" \xff\\x00", b" 12\\:opaque"])
def test_native_srv_allows_only_one_opaque_txt_continuation(continuation):
    callback = (
        b"12:34:56.000  Example speaker._airplay._tcp.local. can be reached at "
        b"speaker.local.:7000 (interface 7)\n"
    )
    assert native.resolve_endpoint(callback + continuation + b"\n", 7)[2] == 7000
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_endpoint(callback + continuation + b"\n unexpected\n", 7)


def test_native_query_banners_are_closed_and_not_arbitrary_rows():
    banners = b"Using interface 7\nDATE: ---Mon 05 Oct 2026---\n"
    assert (
        native.resolve_ipv4(
            banners + b"Timestamp A/R Flags IF Hostname Address TTL\n"
            b" 9:00:00.000  Add 2 7 speaker.local. 192.0.2.82 120\n",
            "speaker.local.",
            7,
        )
        == "192.0.2.82"
    )
    assert native.resolve_txt(
        banners + b"Timestamp A/R Flags IF Name Type Class Rdata\n"
        b" 9:00:00.000  Add 2 7 Example speaker._airplay._tcp.local. TXT IN 2 bytes: 01 61\n",
        "Example speaker._airplay._tcp.local.",
        7,
    ) == (b"a",)


@pytest.mark.parametrize("continuation", [b" key=\x00", b" key=\t", b" \tunknown"])
def test_srv_does_not_accept_raw_controls_as_opaque_native_txt(continuation):
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_endpoint(
            b"12:34:56.000  Example speaker._airplay._tcp.local. can be reached at "
            b"speaker.local.:7000 (interface 7)\n" + continuation + b"\n",
            7,
        )


@pytest.mark.parametrize(
    "fullname", [r"Example\.speaker._airplay._tcp.local.", r"Example\\speaker._airplay._tcp.local."]
)
def test_resolved_fullname_escaping_is_retained_for_txt_query(fullname):
    # Service labels in browse/register replies are unescaped; resolve/query
    # fullnames are native escaped DNS names and must pass through unchanged.
    resolved = (
        f"12:34:56.000  {fullname} can be reached at speaker.local.:7000 (interface 7)\n"
    ).encode()
    actual, _host, _port = native.resolve_endpoint(resolved, 7)
    assert actual == fullname
    assert native.resolve_txt(txt_output(b"\x01a", fullname), actual, 7) == (b"a",)


@pytest.mark.parametrize(
    "row",
    [
        b"12:34:56.000  Add        2   0 local.               _airplay._tcp.       Speaker",
        b"12:34:56.000  Add        2   8 local.               _airplay._tcp.       Speaker",
        b"12:34:56.000  Add        Z   7 local.               _airplay._tcp.       Speaker",
        b"12:34:56.000  Add        2   7 foreign.             _airplay._tcp.       Speaker",
        b"12:34:56.000  Add        2   7 local.               _raop._tcp.          Speaker",
        b"12:34:56.000 Add 2 7 local. _airplay._tcp.",
        b"garbage",
        b"12:34:56.000 Error code -1",
    ],
)
def test_browse_rejects_partial_or_wrong_scope_rows(row):
    with pytest.raises(native.DiscoveryFailure):
        native.browse_names(b"Using interface 7\n" + row, "_airplay._tcp", 7, 8)


def test_browse_flood_is_not_truncated_into_success():
    raw = b"\n".join(
        (
            f"12:34:56.000  Add        2   7 local.               _airplay._tcp.       speaker-{i}"
        ).encode()
        for i in range(3)
    )
    with pytest.raises(native.DiscoveryFailure):
        native.browse_names(raw, "_airplay._tcp", 7, 2)


@pytest.mark.parametrize(
    "result,index",
    [
        (Result(0, b"", b""), 7),
        (Result(0, b"Using interface 0\n", b""), 0),
        (Result(0, b"Using interface 7\nUsing interface 7\n", b""), 7),
        (Result(0, b"Using interface 7\n", b"Unknown interface"), 7),
        (Result(1, b"Using interface 7\n", b""), 7),
    ],
)
def test_exit_zero_does_not_prove_interface(result, index):
    with pytest.raises(native.DiscoveryFailure):
        native.confirmed_output(result, index)


def test_local_network_denial_has_distinct_reason():
    with pytest.raises(native.DiscoveryFailure, match="local-network-denied"):
        native.confirmed_output(Result(0, b"Using interface 7\nError code -65570", b""), 7)


def test_txt_word_error_is_data_not_native_error():
    assert native.confirmed_output(Result(0, b"Using interface 7\n TXT description=error", b""), 7)


def test_resolve_endpoint_exact_interface_and_tuple():
    raw = (
        b"12:34:56.000 Example speaker._airplay._tcp.local. can be reached at "
        b"speaker.local.:7000 (interface 7) Flags: 2\n"
    )
    assert native.resolve_endpoint(raw, 7) == (
        "Example speaker._airplay._tcp.local.",
        "speaker.local.",
        7000,
    )
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_endpoint(raw, 8)
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_endpoint(raw + raw.replace(b"7000", b"7001"), 7)


def test_ipv4_is_unique_current_value():
    raw = (
        b"12:34:56.000 Add 2 7 speaker.local. 192.0.2.81 120\n"
        b"12:34:57.000 Rmv 0 7 speaker.local. 192.0.2.81 0\n"
        b"12:34:58.000 Add 2 7 speaker.local. 192.0.2.82 120\n"
    )
    assert native.resolve_ipv4(raw, "speaker.local.", 7) == "192.0.2.82"
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_ipv4(raw.replace(b"Rmv", b"Add"), "speaker.local.", 7)


def txt_output(data, fullname="Example speaker._airplay._tcp.local."):
    hex_data = " ".join(f"{byte:02X}" for byte in data)
    return f"12:34:56.000 Add 2 7 {fullname} TXT IN {len(data)} bytes: {hex_data}\n".encode()


def test_txt_preserves_empty_and_non_utf8_entries():
    raw = txt_output(b"\x00\x04bin=\x02\0\xff")
    assert native.resolve_txt(raw, "Example speaker._airplay._tcp.local.", 7) == (
        b"",
        b"bin=",
        b"\0\xff",
    )


@pytest.mark.parametrize("raw", [b"\x05abc", b"\x01", b"\x03a"])
def test_truncated_txt_is_unknown(raw):
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_txt(txt_output(raw), "Example speaker._airplay._tcp.local.", 7)


def test_full_native_scan_uses_only_fixed_argv_and_hex_txt():
    calls = []

    def runner(argv, timeout):
        calls.append((argv, timeout))
        if "-B" in argv:
            payload = (
                b"Browsing for _airplay._tcp.local.\n"
                b"12:34:56.000  Add        2   7 local.               _airplay._tcp.       "
                b"Example speaker\n"
            )
        elif "-L" in argv:
            payload = (
                b"12:34:56.000 Example speaker._airplay._tcp.local. can be reached at "
                b"speaker.local.:7000 (interface 7)\n bin=\xff\\\\x00\n"
            )
        elif "-G" in argv:
            payload = b"12:34:56.000 Add 2 7 speaker.local. 192.0.2.82 120\n"
        else:
            payload = txt_output(b"\x17model=AudioAccessory5,1")
        return Result(0, b"Using interface 7\n" + payload, b"")

    records = native.scan("en0", 7, "_airplay._tcp", 8, 2, 1000, runner)
    assert records == (media_record(txt=(b"model=AudioAccessory5,1",)),)
    assert all(argv[:5] == [native.DNS_SD, "-t", "2", "-i", "en0"] for argv, _ in calls)
    assert all("-m" in argv for argv, _ in calls[1:])


@pytest.mark.parametrize(
    "txt,expected",
    [
        ((b"model=AudioAccessory5,1",), True),
        ((b"MODEL=APPLETV6,2",), True),
        ((b"am=AppleTV6,2",), True),
        ((b"model=Unrelated",), False),
        ((b"model=AppleTV6,2", b"Model=AudioAccessory5,1"), False),
        ((b"am=AppleTV6,2", b"am=AppleTV6,2"), False),
        ((), False),
    ],
)
def test_existing_model_and_alternate_model_contract(txt, expected):
    assert owner.apple_eligible(txt, ("AudioAccessory", "AppleTV")) is expected


def test_import_supports_multiple_devices_dhcp_and_related_protocols(config, settings):
    records = (
        media_record(),
        media_record(name="Second speaker", hostname="second.local.", ipv4="192.0.2.83"),
        media_record(
            name="ABC@Example", service_type="_raop._tcp", port=5000, txt=(b"am=HomePod",)
        ),
    )
    result = owner.project_records(
        config, policy(config), records, snapshot(config), frozenset({"media-udp"}), settings, 1000
    )
    assert len(result) == 3
    assert {item.ipv4 for item in result} == {"192.0.2.82", "192.0.2.83"}
    assert {item.interface for item in result} == {"bridge-test"}
    assert len({item.hostname for item in result}) == 3
    assert result[0].txt == records[0].txt
    changed = owner.project_records(
        config,
        policy(config),
        (media_record(ipv4="192.0.2.84"),),
        snapshot(config),
        frozenset({"media-udp"}),
        settings,
        1000,
    )
    assert changed[0].ipv4 == "192.0.2.84"


def test_related_service_on_same_ip_different_host_is_excluded(config, settings):
    records = (
        media_record(),
        media_record(name="Unrelated", hostname="other.local.", service_type="_raop._tcp"),
    )
    assert (
        len(
            owner.project_records(
                config,
                policy(config),
                records,
                snapshot(config),
                frozenset({"media-udp"}),
                settings,
                1000,
            )
        )
        == 1
    )


@pytest.mark.parametrize(
    "source_host,related_host,expected",
    [
        ("Speaker.LOCAL.", "speaker.local.", 2),
        ("Åpeaker.local.", "åpeaker.local.", 1),
        ("Straße.local.", "strasse.local.", 1),
    ],
)
def test_owner_import_associates_only_ascii_equivalent_hostnames(
    config, settings, source_host, related_host, expected
):
    records = (
        media_record(hostname=source_host),
        media_record(name="Related", hostname=related_host, service_type="_raop._tcp"),
    )
    result = owner.project_records(
        config, policy(config), records, snapshot(config), frozenset({"media-udp"}), settings, 1000
    )
    assert len(result) == expected
    assert result[0].name == records[0].name and result[0].txt == records[0].txt


@pytest.mark.parametrize("prefix", ["NeToRcH-CoNtAiNeR-", "NETORCH-LAN-"])
@pytest.mark.parametrize("field", ["name", "hostname"])
def test_owner_import_rejects_own_projection_prefix_in_any_ascii_case(
    config, settings, prefix, field
):
    records = (media_record(**{field: prefix + "previous.local."}),)
    assert (
        owner.project_records(
            config,
            policy(config),
            records,
            snapshot(config),
            frozenset({"media-udp"}),
            settings,
            1000,
        )
        == ()
    )


def old_discovery_digest(config, item, version):
    """Frozen prior envelope: unchanged policy cannot approve new native semantics."""
    service = config.service(item.service)
    return digest(
        {
            "digest_version": version,
            "schema_version": config.schema_version,
            "discovery": asdict(item),
            "scope": asdict(config.scope(item.scope)),
            "service": asdict(service),
            "service_owner": asdict(config.owner(service.owner)),
            "owner": asdict(config.owner(item.owner)),
            "dependencies": {
                identifier: profile_digest(config, config.profile(identifier))
                for identifier in sorted(item.dependencies)
            },
        }
    )


@pytest.mark.parametrize("old_version", [1, 2, 3])
@pytest.mark.parametrize("old_field", ["candidate", "request"])
def test_discovery_owner_refuses_prior_lease_records(config, settings, old_field, old_version):
    current = snapshot(config)
    request, candidate = candidate_request(config, settings, current, media_record())
    assert owner.lease_records(
        config,
        policy(config),
        request,
        candidate,
        current,
        Intent(),
        frozenset({"media-udp"}),
        1000,
    )
    (candidate if old_field == "candidate" else request)["policy_digest"] = old_discovery_digest(
        config, policy(config), old_version
    )
    assert (
        owner.lease_records(
            config,
            policy(config),
            request,
            candidate,
            current,
            Intent(),
            frozenset({"media-udp"}),
            1000,
        )
        is None
    )


@pytest.mark.parametrize("old_version", [1, 2, 3])
@pytest.mark.parametrize("boundary", ["readback", "endpoint"])
def test_discovery_owner_refuses_prior_readback_and_endpoint(
    config, settings, monkeypatch, boundary, old_version
):
    monkeypatch.setattr(owner.time, "time", lambda: 1000)
    current = snapshot(config)
    old_profiles = {
        item.id: Observation(
            "present",
            "verified",
            1000,
            current.services[item.service].generation,
            {
                "policy_digest": old_discovery_digest(config, item, old_version),
                "network_generation": current.network_generation,
                "service_generation": current.services[item.service].generation,
                "interface_confirmed": True,
            },
        )
        for item in config.discovery
    }
    store = Store(settings.state_dir)
    store.write("readback.json", snapshot_to_dict(replace(current, profiles=old_profiles)))
    if boundary == "readback":
        result = owner.readback(config, settings, store, 1000)
        assert all(
            item.state == "unknown" and item.reason == "identity-mismatch"
            for item in result.profiles.values()
        )
    else:
        request = {
            "protocol_version": 1,
            "operation": "reconcile-discovery",
            "owner": settings.owner,
            "policy_digest": config_digest(config),
            "discovery_digest": old_discovery_digest(config, policy(config), old_version),
            "discovery": policy(config).id,
            "active": True,
            "config": to_dict(config),
            "service_generation": current.services[policy(config).service].generation,
            "network_generation": current.network_generation,
        }
        with pytest.raises(ValueError, match="invalid fixed discovery request"):
            owner.endpoint(config, settings, store, request)
        assert not (settings.state_dir / "requests.json").exists()


def test_export_uses_same_service_publication_not_colliding_port(config, settings):
    record = media_record(
        name="Camera",
        service_type="_hap._tcp",
        hostname="camera.local.",
        ipv4="198.51.100.13",
        interface="bridge-test",
        port=9443,
    )
    result = owner.project_records(
        config,
        policy(config, "camera-export"),
        (record,),
        snapshot(config),
        frozenset({"camera-web"}),
        settings,
        1000,
    )
    assert result[0].ipv4 == "192.0.2.10"
    assert result[0].source_service == "camera"
    assert result[0].source_generation == "mock-camera-1"
    assert (
        owner.project_records(
            config,
            policy(config, "camera-export"),
            (replace(record, port=8080),),
            snapshot(config),
            frozenset({"proxy-high"}),
            settings,
            1000,
        )
        == ()
    )


@pytest.mark.parametrize(
    "change",
    [
        "paused",
        "unknown",
        "contract",
        "profile-digest",
        "target",
        "generation",
        "network",
        "states",
        "stale",
        "missing-ready",
    ],
)
def test_publisher_checks_independent_dependency_evidence(config, change):
    current = snapshot(config)
    intent = Intent()
    ready = frozenset({"media-udp"})
    if change == "paused":
        intent = Intent(operator_paused=True)
    elif change == "missing-ready":
        ready = frozenset()
    elif change in {"unknown", "contract"}:
        services = dict(current.services)
        endpoint = services["media-controller"]
        services["media-controller"] = (
            Observation("unknown", "unobserved", 1000, None)
            if change == "unknown"
            else replace(endpoint, data={**endpoint.data, "contract_sha256": "0" * 64})
        )
        current = replace(current, services=services)
    else:
        profiles = dict(current.profiles)
        observed = profiles["media-udp"]
        fields = {
            "profile-digest": "policy_digest",
            "target": "target_ipv4",
            "generation": "target_generation",
            "network": "network_generation",
            "states": "states",
        }
        profiles["media-udp"] = (
            replace(observed, observed_at=0)
            if change == "stale"
            else replace(observed, data={**observed.data, fields[change]: None})
        )
        current = replace(current, profiles=profiles)
    assert not owner.dependencies_ready(config, policy(config), current, intent, ready, 1000)


@pytest.mark.parametrize(
    "change",
    [
        None,
        "missing-ready",
        "backing-unknown",
        "backing-digest",
        "direct-available",
        "missing-fallback",
    ],
)
def test_discovery_dependency_can_use_exact_verified_dns_fallback(config, change):
    original = config.profile("dns-udp")
    native_publication = Profile(
        "dns-native-udp",
        original.service,
        original.scope,
        "publication",
        "udp",
        PortRange(1053, 1053),
        PortRange(53, 53),
        Safety("structural", 30, 1),
        "camera-manager",
    )
    profiles = (
        *(
            replace(item, fallback_publication="dns-native-udp") if item.id == "dns-udp" else item
            for item in config.profiles
        ),
        native_publication,
    )
    config = replace(config, profiles=profiles)
    current = snapshot(config)
    observed = dict(current.profiles)
    observed["dns-udp"] = replace(
        observed["dns-udp"],
        data={
            **observed["dns-udp"].data,
            "target_ipv4": config.scope(original.scope).host_ipv4,
            "effective_strategy": "degraded-fallback",
            "direct_available": False,
        },
    )
    ready = frozenset({"dns-udp", "dns-native-udp"})
    if change == "missing-ready":
        ready = frozenset({"dns-udp"})
    elif change == "backing-unknown":
        observed["dns-native-udp"] = replace(
            observed["dns-native-udp"], state="unknown", reason="unobserved"
        )
    elif change == "backing-digest":
        observed["dns-native-udp"] = replace(
            observed["dns-native-udp"],
            data={**observed["dns-native-udp"].data, "policy_digest": "0" * 64},
        )
    elif change == "direct-available":
        observed["dns-udp"] = replace(
            observed["dns-udp"], data={**observed["dns-udp"].data, "direct_available": True}
        )
    elif change == "missing-fallback":
        config = replace(
            config,
            profiles=tuple(
                replace(item, fallback_publication=None) if item.id == "dns-udp" else item
                for item in config.profiles
            ),
        )
    current = replace(current, profiles=observed)
    discovery = replace(policy(config), service="resolver", dependencies=("dns-udp",))
    assert owner.dependencies_ready(config, discovery, current, Intent(), ready, 1000) is (
        change is None
    )


class FakeRegistration:
    made: ClassVar[list] = []

    def __init__(self, record, index, lifetime_seconds=120):
        self.record = record
        self.index = index
        self.lifetime_seconds = lifetime_seconds
        self.closed = False
        self.failed = False
        self.active = True
        self.made.append(self)

    def poll(self):
        if self.failed:
            raise native.DiscoveryFailure("unavailable")
        return self.active

    def close(self):
        self.closed = True


def publisher():
    FakeRegistration.made = []
    return owner.Publisher(FakeRegistration)


def candidate_request(config, settings, current, record):
    p = policy(config)
    records = owner.project_records(
        config, p, (record,), current, frozenset({"media-udp"}), settings, 1000
    )
    common = {
        "policy_digest": discovery_digest(config, p),
        "service_generation": current.services[p.service].generation,
        "network_generation": current.network_generation,
    }
    request = {**common, "active": True, "requested_at": 1000}
    candidate = {
        **common,
        "records": [owner.record_to_dict(item) for item in records],
        "interface_confirmed": True,
        "observed_at": 1000,
    }
    return request, candidate


def test_initial_absence_can_be_observed_without_bootstrap_request(config, settings):
    store = Store(settings.state_dir)
    proof = (
        snapshot(config),
        Intent(),
        frozenset({"media-udp", "camera-web"}),
        {"wired-lan": (7, 9)},
    )
    result = owner.publisher_tick(config, settings, store, publisher(), proof, 0, 1000)
    assert all(item.state == "absent" for item in result.profiles.values())
    assert all(item.data["interface_confirmed"] for item in result.profiles.values())


@pytest.mark.parametrize("stamp", [" 0:00:00.000", " 9:59:59.999", "12:34:56.000"])
@pytest.mark.parametrize(
    "name", ["Example speaker", "Example  speaker", "Example.speaker", r"Example\speaker"]
)
def test_real_publisher_contract_with_fake_native_client(tmp_path, monkeypatch, stamp, name):
    record = replace(media_record(), name=name)
    fake = tmp_path / "fake-dns-sd"
    service = (
        f"{stamp}  Got a reply for service {name}._airplay._tcp.local.: "
        "Name now registered and active"
    )
    address = f"{stamp}  Got a reply for record speaker.local.: Name now registered and active"
    fake.write_text(
        f"#!{sys.executable}\nimport time\nprint('Using interface 7',flush=True)\n"
        f"print({service!r},flush=True)\n"
        f"print({address!r},flush=True)\ntime.sleep(5)\n"
    )
    fake.chmod(0o700)
    monkeypatch.setattr(native, "DNS_SD", str(fake))
    registration = native.Registration(record, 7)
    try:
        deadline = time.monotonic() + 2
        while not registration.poll() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert registration.active
    finally:
        registration.close()
    assert registration.process.poll() is not None
    registration.close()
    with pytest.raises(native.DiscoveryFailure):
        registration.poll()


@pytest.mark.parametrize(
    "service_callback",
    [
        "9:00:00.000  Got a reply for service Example  speaker._airplay._tcp.local.: "
        "Name now registered and active",
        "  9:00:00.000  Got a reply for service Example  speaker._airplay._tcp.local.: "
        "Name now registered and active",
        " 9:00:00.000 Got a reply for service Example  speaker._airplay._tcp.local.: "
        "Name now registered and active",
        " 9:00:00.000  Got a reply for service Example speaker._airplay._tcp.local.: "
        "Name now registered and active",
        " 9:00:00.000  Got a reply for service Example  speaker (2)._airplay._tcp.local.: "
        "Name now registered and active",
        " 9:00:00.000  Got a reply for service Example  speaker._airplay._tcp.local.: "
        "Name registration removed",
        " 9:00:00.000  Got a reply for service Example  speaker._airplay._tcp.local.: "
        "Name in use, please choose another",
    ],
)
def test_registration_rejects_malformed_timestamp_renaming_and_removal(service_callback):
    class Live:
        def poll(self):
            return None

    class Idle:
        def select(self, _timeout):
            return ()

    registration = object.__new__(native.Registration)
    registration.closed = False
    registration.record = replace(media_record(), name="Example  speaker")
    registration.index = 7
    registration.process = Live()
    registration.selector = Idle()
    registration.output = bytearray(
        (
            "Using interface 7\n" + service_callback + "\n"
            " 9:00:00.000  Got a reply for record speaker.local.: Name now registered and active\n"
        ).encode()
    )
    registration.started = time.monotonic()
    with pytest.raises(native.DiscoveryFailure):
        registration.poll()


@pytest.mark.parametrize("index", [0, -1, True, "7"])
def test_registration_refuses_unknown_interface_before_spawning(index, monkeypatch):
    monkeypatch.setattr(
        native.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("spawned")
    )
    with pytest.raises(native.DiscoveryFailure, match="identity-mismatch"):
        native.Registration(media_record(), index)


def test_reaped_client_never_signals_a_historical_process_group(monkeypatch):
    registration = object.__new__(native.Registration)
    registration.closed = False

    class Completed:
        pid = 123
        stdout = None

        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    class ClosedSelector:
        def close(self):
            pass

    registration.process = Completed()
    registration.selector = ClosedSelector()
    monkeypatch.setattr(native.os, "killpg", lambda *_args: pytest.fail("historical PID signalled"))
    registration.close()
    registration.close()


def test_watchdog_expiry_and_child_exit_withdraw_owned_registration(config, monkeypatch):
    manager = publisher()
    monkeypatch.setattr(owner.time, "monotonic", lambda: 100)
    assert manager.reconcile(policy(config), (media_record(),), 7, 1000)
    child = FakeRegistration.made[0]
    manager.expire(219)
    assert not child.closed
    manager.expire(220)
    assert child.closed and not manager.children
    manager.reconcile(policy(config), (media_record(),), 7, 1000)
    FakeRegistration.made[-1].failed = True
    with pytest.raises(native.DiscoveryFailure):
        manager.reconcile(policy(config), (media_record(),), 7, 1000)
    assert not manager.children


def test_backwards_wall_clock_cannot_extend_existing_record_lease(config, monkeypatch):
    manager = publisher()
    monotonic = [100]
    monkeypatch.setattr(owner.time, "monotonic", lambda: monotonic[0])
    manager.reconcile(policy(config), (media_record(),), 7, 1000)
    initial = next(iter(manager.deadlines.values()))
    monotonic[0] = 110
    manager.reconcile(policy(config), (media_record(),), 7, 990)
    assert next(iter(manager.deadlines.values())) == initial


@pytest.mark.parametrize("value", [0, -1, 121, True, 1.5, "5"])
def test_native_registration_has_closed_self_expiry(value):
    with pytest.raises(native.DiscoveryFailure):
        native.registration_argv(media_record(), value)


def test_registration_self_expiry_uses_remaining_lease_not_new_full_age(config):
    manager = publisher()
    manager.reconcile(policy(config), (media_record(),), 7, 1090)
    assert FakeRegistration.made[0].lifetime_seconds == 30
    assert native.registration_argv(media_record(), 30)[3:5] == ["-t", "30"]


def test_live_tick_withdraws_on_pause_stale_proof_and_generation_change(config, settings):
    current = snapshot(config)
    request, candidate = candidate_request(config, settings, current, media_record())
    store = Store(settings.state_dir)
    store.write("requests.json", {"schema_version": 1, "policies": {"media-import": request}})
    store.write(
        "candidates.json",
        {
            "schema_version": 1,
            "config_digest": config_digest(config),
            "policies": {"media-import": candidate},
        },
    )
    proof = (current, Intent(), frozenset({"media-udp", "camera-web"}), {"wired-lan": (7, 9)})
    manager = publisher()
    assert (
        owner.publisher_tick(config, settings, store, manager, proof, 0, 1000)
        .profiles["media-import"]
        .state
        == "present"
    )
    child = FakeRegistration.made[0]
    write_private(settings.intent, intent_to_dict(Intent(operator_paused=True)))
    assert (
        owner.publisher_tick(config, settings, store, manager, proof, 0, 1000)
        .profiles["media-import"]
        .state
        == "absent"
    )
    assert child.closed
    write_private(settings.intent, intent_to_dict(Intent()))
    assert (
        owner.publisher_tick(config, settings, store, manager, proof, 31, 1000)
        .profiles["media-import"]
        .state
        == "unknown"
    )
    changed = replace(current, network_generation="network-replaced")
    proof = (changed, Intent(), proof[2], proof[3])
    assert (
        owner.publisher_tick(config, settings, store, manager, proof, 0, 1000)
        .profiles["media-import"]
        .state
        == "unknown"
    )
    assert not manager.children


def test_registration_failure_isolated_to_its_policy(config, settings):
    current = snapshot(config)
    request, candidate = candidate_request(config, settings, current, media_record())
    camera = policy(config, "camera-export")
    camera_records = owner.project_records(
        config,
        camera,
        (
            media_record(
                name="Camera",
                service_type="_hap._tcp",
                hostname="camera.local.",
                ipv4="198.51.100.13",
                interface="bridge-test",
                port=9443,
            ),
        ),
        current,
        frozenset({"camera-web"}),
        settings,
        1000,
    )
    camera_common = {
        "policy_digest": discovery_digest(config, camera),
        "service_generation": current.services[camera.service].generation,
        "network_generation": current.network_generation,
    }
    store = Store(settings.state_dir)
    store.write(
        "requests.json",
        {
            "schema_version": 1,
            "policies": {
                "media-import": request,
                "camera-export": {**camera_common, "active": True, "requested_at": 1000},
            },
        },
    )
    store.write(
        "candidates.json",
        {
            "schema_version": 1,
            "config_digest": config_digest(config),
            "policies": {
                "media-import": candidate,
                "camera-export": {
                    **camera_common,
                    "records": [owner.record_to_dict(item) for item in camera_records],
                    "interface_confirmed": True,
                    "observed_at": 1000,
                },
            },
        },
    )
    proof = (current, Intent(), frozenset({"media-udp", "camera-web"}), {"wired-lan": (7, 9)})
    manager = publisher()
    assert all(
        value.state == "present"
        for value in owner.publisher_tick(
            config, settings, store, manager, proof, 0, 1000
        ).profiles.values()
    )
    failed = next(
        child for child in FakeRegistration.made if child.record.service_type == "_airplay._tcp"
    )
    unaffected = next(
        child for child in FakeRegistration.made if child.record.service_type == "_hap._tcp"
    )
    failed.failed = True
    observed = owner.publisher_tick(config, settings, store, manager, proof, 0, 1000)
    assert observed.profiles["media-import"].state == "unknown"
    assert observed.profiles["camera-export"].state == "present"
    assert failed.closed and not unaffected.closed
    assert len(manager.children) == 1


@pytest.mark.parametrize(
    "field",
    [
        "policy_digest",
        "service_generation",
        "network_generation",
        "interface_confirmed",
        "observed_at",
        "records",
    ],
)
def test_candidate_is_data_not_authority(config, settings, field):
    current = snapshot(config)
    request, candidate = candidate_request(config, settings, current, media_record())
    candidate[field] = None
    assert (
        owner.lease_records(
            config,
            policy(config),
            request,
            candidate,
            current,
            Intent(),
            frozenset({"media-udp"}),
            1000,
        )
        is None
    )


def test_endpoint_fixed_observe_request_and_redacted_missing_readback(config, settings):
    result = owner.endpoint(
        config,
        settings,
        Store(settings.state_dir),
        {
            "protocol_version": 1,
            "operation": "observe",
            "owner": settings.owner,
            "config": to_dict(config),
        },
    )
    assert result["owner"] == settings.owner
    assert result["result"]["profiles"]["media-import"]["state"] == "unknown"


@pytest.mark.parametrize("change", ["owner", "protocol", "extra", "operation", "config"])
def test_endpoint_rejects_cross_owner_or_arbitrary_operations(config, settings, change):
    request = {
        "protocol_version": 1,
        "operation": "observe",
        "owner": settings.owner,
        "config": to_dict(config),
    }
    if change == "owner":
        request["owner"] = "camera-manager"
    elif change == "protocol":
        request["protocol_version"] = True
    elif change == "extra":
        request["argv"] = ["ignore"]
    elif change == "operation":
        request["operation"] = "shell"
    else:
        request["config"] = copy.deepcopy(request["config"])
        request["config"]["site"] = "different-site"
    with pytest.raises(ValueError):
        owner.endpoint(config, settings, Store(settings.state_dir), request)


def test_health_requires_both_fresh_independent_process_heartbeats(settings, monkeypatch):
    store = Store(settings.state_dir)
    monkeypatch.setattr(owner.time, "time", lambda: 1000)
    for filename in ("scanner-heartbeat.json", "publisher-heartbeat.json"):
        store.write(filename, {"schema_version": 1, "observed_at": 1000, "pid": 1})
    assert owner.health(settings, store)
    store.write("scanner-heartbeat.json", {"schema_version": 1, "observed_at": 900, "pid": 1})
    assert not owner.health(settings, store)


def test_readback_expires_without_daemon_heartbeat(config, settings):
    store = Store(settings.state_dir)
    p = policy(config)
    fact = owner._observation(
        config, p, "present", "verified", 1000, snapshot(config), interface=True
    )
    store.write(
        "readback.json",
        snapshot_to_dict(Snapshot(1000, "network-1", {}, {p.id: fact, "camera-export": fact})),
    )
    assert owner.readback(config, settings, store, 1011).profiles[p.id].state == "unknown"


@pytest.mark.parametrize(
    "failure",
    [
        "none",
        "command",
        "wrong-header",
        "wrong-address",
        "missing-address",
        "index-zero",
        "index-error",
    ],
)
def test_interface_requires_exact_address_and_nonzero_index(monkeypatch, failure):
    def runner(argv, timeout):
        assert argv == [native.IFCONFIG, "en0"] and timeout == 2
        result = Result(0, b"en0: flags=0\n\tinet 192.0.2.10 netmask 0xffffff00\n", b"")
        if failure == "command":
            return replace(result, returncode=1)
        if failure == "wrong-header":
            return replace(result, stdout=result.stdout.replace(b"en0:", b"en1:"))
        if failure == "wrong-address":
            return replace(result, stdout=result.stdout.replace(b".10", b".11"))
        if failure == "missing-address":
            return replace(result, stdout=b"en0: flags=0\n")
        return result

    def index(_name):
        if failure == "index-error":
            raise OSError("missing")
        return 0 if failure == "index-zero" else 7

    monkeypatch.setattr(native.socket, "if_nametoindex", index)
    if failure == "none":
        assert native.interface_index("en0", "192.0.2.10", runner) == 7
    else:
        with pytest.raises(native.DiscoveryFailure):
            native.interface_index("en0", "192.0.2.10", runner)
    with pytest.raises(native.DiscoveryFailure):
        native.interface_index("0", "192.0.2.10", runner)


def test_interfaces_are_confirmed_on_both_sides(config, settings, monkeypatch):
    calls = []

    def validate(interface, address):
        calls.append((interface, address))
        return 7 if interface == "en0" else 9

    monkeypatch.setattr(owner, "interface_index", validate)
    assert owner._interfaces(config, settings) == {"wired-lan": (7, 9)}
    assert calls == [("en0", "192.0.2.10"), ("bridge-test", "198.51.100.1")]


def test_independent_probe_excludes_itself_and_replans_admission(config, settings, monkeypatch):
    current = snapshot(config)
    profiles = dict(current.profiles)
    profiles["media-udp"] = replace(
        profiles["media-udp"],
        data={
            **profiles["media-udp"].data,
            "admitted": True,
            "root_ready": True,
            "admission_digest": "a" * 64,
        },
    )
    current = replace(current, profiles=profiles)
    clients = {
        "bonjour-manager": object(),
        "camera-manager": object(),
        "site-forwarding": RootReportOwner(
            config, "site-forwarding", settings.state_dir / "root-report.json"
        ),
    }
    monkeypatch.setattr(owner, "load_bindings", lambda _config, _path: dict(clients))

    def observe(_config, available):
        assert "bonjour-manager" not in available
        return current

    monkeypatch.setattr(owner, "observe", observe)
    write_private(settings.admissions, admissions_to_dict(mock_admissions(config)))
    observed, intent, ready = owner.independent_snapshot(config, settings, 1000)
    assert observed is current and not intent.blocked
    assert {"media-udp", "camera-web"} <= ready
    write_private(settings.admissions, admissions_to_dict({}))
    assert owner.independent_snapshot(config, settings, 1000)[2] == frozenset({"media-udp"})
    # A user-provided root approval is not authority without the protected owner.
    clients.pop("site-forwarding")
    write_private(settings.admissions, admissions_to_dict(mock_admissions(config)))
    assert "media-udp" not in owner.independent_snapshot(config, settings, 1000)[2]


def test_scan_pass_uses_live_records_and_refreshes_lease_only_when_complete(
    config, settings, monkeypatch
):
    current = snapshot(config)
    monkeypatch.setattr(
        owner,
        "time",
        type(
            "Clock", (), {"time": staticmethod(lambda: 1000), "monotonic": staticmethod(lambda: 10)}
        )(),
    )
    monkeypatch.setattr(
        owner,
        "independent_snapshot",
        lambda *_args: (current, Intent(), frozenset({"media-udp", "camera-web"})),
    )
    monkeypatch.setattr(owner, "_interfaces", lambda *_args: {"wired-lan": (7, 9)})

    def scan(interface, index, kind, _limit, _seconds, _now, **_keywords):
        if kind == "_airplay._tcp":
            return (media_record(),)
        if kind == "_hap._tcp":
            return (
                media_record(
                    name="Camera",
                    service_type=kind,
                    hostname="camera.local.",
                    port=9443,
                    ipv4="198.51.100.13",
                    interface=interface,
                ),
            )
        return ()

    monkeypatch.setattr(owner, "scan", scan)
    store = Store(settings.state_dir)
    owner.scan_pass(config, settings, store)
    candidates = store.read("candidates.json")
    assert len(candidates["policies"]["media-import"]["records"]) == 1
    assert len(candidates["policies"]["camera-export"]["records"]) == 1

    def fail_media(interface, index, kind, limit, seconds, now, **_keywords):
        if kind == "_airplay._tcp":
            raise native.DiscoveryFailure("local-network-denied")
        return scan(interface, index, kind, limit, seconds, now)

    monkeypatch.setattr(owner, "scan", fail_media)
    owner.scan_pass(config, settings, store)
    refreshed = store.read("candidates.json")["policies"]
    assert refreshed["media-import"]["records"] == []
    assert refreshed["media-import"]["reason"] == "local-network-denied"
    assert len(refreshed["camera-export"]["records"]) == 1


@pytest.mark.parametrize(
    "change",
    [
        "expired",
        "future",
        "request-policy",
        "request-generation",
        "request-network",
        "unknown",
        "inactive",
        "foreign-address",
        "foreign-type",
        "export-provenance",
    ],
)
def test_record_leases_cannot_survive_stale_or_foreign_evidence(config, settings, change):
    current = snapshot(config)
    request, candidate = candidate_request(config, settings, current, media_record())
    if change == "expired":
        candidate["observed_at"] = 1
    elif change == "future":
        candidate["observed_at"] = 1001
    elif change == "request-policy":
        request["policy_digest"] = "0" * 64
    elif change == "request-generation":
        request["service_generation"] = "old"
    elif change == "request-network":
        request["network_generation"] = "old"
    elif change == "unknown":
        request["extra"] = True
    elif change == "inactive":
        request["active"] = False
    elif change == "foreign-address":
        candidate["records"][0]["ipv4"] = "203.0.113.8"
    elif change == "foreign-type":
        candidate["records"][0]["service_type"] = "_http._tcp"
    else:
        p = policy(config, "camera-export")
        candidate["policy_digest"] = request["policy_digest"] = discovery_digest(config, p)
        candidate["service_generation"] = request["service_generation"] = current.services[
            p.service
        ].generation
        candidate["records"][0].update(
            service_type="_hap._tcp", ipv4="192.0.2.10", source_service="other"
        )
        assert (
            owner.lease_records(
                config, p, request, candidate, current, Intent(), frozenset({"camera-web"}), 1000
            )
            is None
        )
        return
    result = owner.lease_records(
        config,
        policy(config),
        request,
        candidate,
        current,
        Intent(),
        frozenset({"media-udp"}),
        1000,
    )
    assert result == () if change == "inactive" else result is None


def test_endpoint_reconcile_is_fixed_intent_and_bounded_verified_readback(
    config, settings, monkeypatch
):
    store = Store(settings.state_dir)
    current = snapshot(config)
    p = policy(config)
    fact = owner._observation(
        config, p, "present", "verified", time.time(), current, interface=True
    )
    store.write(
        "readback.json",
        snapshot_to_dict(
            Snapshot(
                time.time(),
                current.network_generation,
                {},
                {
                    p.id: fact,
                    "camera-export": owner._observation(
                        config,
                        policy(config, "camera-export"),
                        "absent",
                        "confirmed-absent",
                        time.time(),
                        current,
                        interface=True,
                    ),
                },
            )
        ),
    )
    request = {
        "protocol_version": 1,
        "operation": "reconcile-discovery",
        "owner": settings.owner,
        "config": to_dict(config),
        "policy_digest": config_digest(config),
        "discovery_digest": discovery_digest(config, p),
        "discovery": p.id,
        "active": True,
        "service_generation": current.services[p.service].generation,
        "network_generation": current.network_generation,
    }
    result = owner.endpoint(config, settings, store, request)
    assert result["result"]["state"] == "present"
    assert store.read("requests.json")["policies"][p.id]["active"] is True
    with pytest.raises(ValueError):
        owner.endpoint(config, settings, store, {**request, "discovery_digest": "0" * 64})
    monkeypatch.setattr(owner.time, "monotonic", iter((0, 8)).__next__)
    timed_out = owner.endpoint(config, settings, store, {**request, "active": False})
    assert timed_out["result"]["state"] == "present"
    assert store.read("requests.json")["policies"][p.id]["active"] is False


class ImmediatePool:
    def __init__(self, **_kwargs):
        self.closed = False

    def submit(self, function, *args):
        future = Future()
        try:
            future.set_result(function(*args))
        except Exception as exc:
            future.set_exception(exc)
        return future

    def shutdown(self, **_kwargs):
        self.closed = True


@pytest.mark.parametrize("failed", [False, True])
def test_watchdog_loop_remains_responsive_while_probe_is_independent(
    config, settings, monkeypatch, failed
):
    managed = publisher()
    monkeypatch.setattr(owner, "Publisher", lambda: managed)
    monkeypatch.setattr(owner, "ThreadPoolExecutor", ImmediatePool)
    monkeypatch.setattr(owner, "_signal_stop", lambda _function: None)

    def proof(*_args):
        if failed:
            raise OSError("probe")
        return (
            snapshot(config),
            Intent(),
            frozenset({"media-udp", "camera-web"}),
            {"wired-lan": (7, 9)},
        )

    monkeypatch.setattr(owner, "collect_proof", proof)
    monkeypatch.setattr(
        owner.time, "sleep", lambda _delay: (_ for _ in ()).throw(InterruptedError())
    )
    store = Store(settings.state_dir)
    with pytest.raises(InterruptedError):
        owner.publisher_loop(config, settings, store)
    assert not managed.children
    result = store.read("readback.json")
    assert result["profiles"]["media-import"]["state"] == ("unknown" if failed else "absent")


def test_parent_death_stops_watchdog_before_reusing_old_scanner_files(
    config, settings, monkeypatch
):
    managed = publisher()
    managed.reconcile(policy(config), (media_record(),), 7, 1000)
    child = FakeRegistration.made[0]
    monkeypatch.setattr(owner, "Publisher", lambda: managed)
    monkeypatch.setattr(owner, "_signal_stop", lambda _function: None)
    monkeypatch.setattr(owner.os, "getppid", lambda: 1)
    owner.publisher_loop(config, settings, Store(settings.state_dir), parent_pid=4242)
    assert child.closed


@pytest.mark.parametrize("failed", [False, True])
def test_scanner_supervision_records_heartbeat_or_invalidates_candidates(
    config, settings, monkeypatch, failed
):
    class Child:
        calls = 0
        exited = False

        def poll(self):
            self.calls += 1
            return 0 if self.calls > 1 else None

        def terminate(self):
            self.exited = True

        def wait(self, timeout):
            return 0

    child = Child()
    calls = []

    def spawn(argv, **_kwargs):
        calls.append(argv)
        return child

    monkeypatch.setattr(owner.subprocess, "Popen", spawn)
    monkeypatch.setattr(owner, "_signal_stop", lambda _function: None)
    monkeypatch.setattr(owner.time, "sleep", lambda _delay: None)

    def scanner(*_args):
        if failed:
            raise native.DiscoveryFailure()

    monkeypatch.setattr(owner, "scan_pass", scanner)
    owner.serve(config, settings, settings.config)
    assert child.exited and "--parent-pid" in calls[0]
    store = Store(settings.state_dir)
    if failed:
        assert not store.read("candidates.json")["policies"]
    else:
        assert store.read("scanner-heartbeat.json")["schema_version"] == 1


def test_ha_endpoint_url_projection_is_exact_and_preserves_other_txt():
    source = media_record(
        service_type="_home-assistant._tcp",
        ipv4="198.51.100.12",
        hostname="guest.local.",
        txt=(
            b"internal_url=http://198.51.100.12:8123/path",
            b"base_url=https://guest.local.:8123",
            b"external_url=https://example.invalid/",
            b"binary=\0\xff",
            b"internal_url=broken",
        ),
    )
    target = replace(source, ipv4="192.0.2.10", port=8181)
    assert owner.rewrite_endpoint_urls(source, target) == (
        b"internal_url=http://192.0.2.10:8181/path",
        b"base_url=https://192.0.2.10:8181",
        b"external_url=https://example.invalid/",
        b"binary=\0\xff",
        b"internal_url=broken",
    )
    assert (
        owner.rewrite_endpoint_urls(replace(source, service_type="_hap._tcp"), target) == source.txt
    )


@pytest.mark.parametrize("command", ["endpoint", "serve", "publisher", "health"])
@pytest.mark.usefixtures("legacy_cli_conformance")
def test_bonjour_cli_uses_fixed_handlers_without_native_calls(
    config, settings, monkeypatch, command
):
    Store(settings.state_dir)
    monkeypatch.setattr(owner, "load_settings", lambda _path: settings)
    monkeypatch.setattr(owner, "serve", lambda *_args: None)
    monkeypatch.setattr(owner, "publisher_loop", lambda *_args: None)
    monkeypatch.setattr(owner, "health", lambda *_args: True)
    if command == "endpoint":
        request = {
            "protocol_version": 1,
            "operation": "observe",
            "owner": settings.owner,
            "config": to_dict(config),
        }
        monkeypatch.setattr(
            owner.sys, "stdin", io.TextIOWrapper(io.BytesIO(canonical_bytes(request)))
        )
        monkeypatch.setattr(owner.sys, "stdout", io.TextIOWrapper(io.BytesIO()))
    args = ["--settings", "/unused/settings.json", command]
    if command == "publisher":
        args.extend(["--parent-pid", "42"])
    assert owner.main(args) == 0


def test_bonjour_health_failure_never_returns_container_restart_code(settings, monkeypatch):
    Store(settings.state_dir)
    monkeypatch.setattr(owner, "load_settings", lambda _path: settings)
    monkeypatch.setattr(owner, "health", lambda *_args: False)
    assert owner.main(["--settings", "/unused/settings.json", "health"]) == 1


@pytest.mark.parametrize("command", ["endpoint", "publisher", "serve", "health"])
@pytest.mark.usefixtures("legacy_cli_conformance")
def test_bonjour_cli_rejects_root_or_incomplete_settings(settings, monkeypatch, command):
    monkeypatch.setattr(owner.os, "geteuid", lambda: 0)
    assert owner.main(["--settings", "/unused/settings.json", command]) == 65


@pytest.mark.usefixtures("legacy_cli_conformance")
def test_standalone_publisher_without_scanner_parent_is_rejected(settings, monkeypatch):
    Store(settings.state_dir)
    monkeypatch.setattr(owner, "load_settings", lambda _path: settings)
    assert owner.main(["--settings", "/unused/settings.json", "publisher"]) == 65


def test_signal_handler_withdraws_before_exiting(monkeypatch):
    callbacks = []
    closed = []
    monkeypatch.setattr(
        owner.signal, "signal", lambda _number, function: callbacks.append(function)
    )
    owner._signal_stop(lambda: closed.append(True))
    with pytest.raises(SystemExit):
        callbacks[0](15, None)
    assert closed == [True]


def test_damaged_candidate_or_denial_cannot_be_reported_as_healthy(config, settings):
    current = snapshot(config)
    request, _candidate = candidate_request(config, settings, current, media_record())
    store = Store(settings.state_dir)
    store.write("requests.json", {"schema_version": 1, "policies": {"media-import": request}})
    proof = current, Intent(), frozenset({"media-udp"}), {"wired-lan": (7, 9)}
    store.write(
        "candidates.json",
        {
            "schema_version": 1,
            "config_digest": config_digest(config),
            "policies": {},
            "reason": "local-network-denied",
        },
    )
    assert (
        owner.publisher_tick(config, settings, store, publisher(), proof, 0, 1000)
        .profiles["media-import"]
        .reason
        == "local-network-denied"
    )
    store.write(
        "candidates.json",
        {"schema_version": True, "config_digest": config_digest(config), "policies": {}},
    )
    assert (
        owner.publisher_tick(config, settings, store, publisher(), proof, 0, 1000)
        .profiles["media-import"]
        .reason
        == "malformed"
    )


def test_collect_proof_rejects_policy_change_before_observing(config, settings, monkeypatch):
    monkeypatch.setattr(
        owner,
        "independent_snapshot",
        lambda *_args: (snapshot(config), Intent(), frozenset({"media-udp"})),
    )
    monkeypatch.setattr(owner, "_interfaces", lambda *_args: {"wired-lan": (7, 9)})
    assert owner.collect_proof(config, settings, 1000)[3] == {"wired-lan": (7, 9)}
    raw = to_dict(config)
    raw["site"] = "replaced"
    write_private(settings.config, raw)
    with pytest.raises(ValueError):
        owner.collect_proof(config, settings, 1000)


@pytest.fixture
def legacy_cli_conformance(monkeypatch):
    """Explicit CI-only seam for preserved owner internals; never qualification."""
    monkeypatch.setattr(owner, "require_mutation_qualified", lambda _capability: None)


@pytest.mark.parametrize("active", [False, True])
def test_real_owner_readback_preserves_generation_for_discovery_planner(
    config, settings, monkeypatch, active
):
    """Join the owner's actual wire report to the planner, not a hand-made report."""
    from netorch.discovery_plan import plan_discovery
    from netorch.planner import plan
    from netorch.state import snapshot_from_dict

    monkeypatch.setattr(owner.time, "time", lambda: 1000)
    current = snapshot(config)
    store = Store(settings.state_dir)
    if active:
        request, candidate = candidate_request(config, settings, current, media_record())
        store.write("requests.json", {"schema_version": 1, "policies": {"media-import": request}})
        store.write(
            "candidates.json",
            {
                "schema_version": 1,
                "config_digest": config_digest(config),
                "policies": {"media-import": candidate},
            },
        )
    proof = (current, Intent(), frozenset({"media-udp", "camera-web"}), {"wired-lan": (7, 9)})
    manager = publisher()
    try:
        owner.publisher_tick(config, settings, store, manager, proof, 0, 1000)
        response = owner.endpoint(
            config,
            settings,
            store,
            {
                "protocol_version": 1,
                "operation": "observe",
                "owner": settings.owner,
                "config": to_dict(config),
            },
        )
        discovery = snapshot_from_dict(response["result"])
        observed = replace(current, profiles={**current.profiles, **discovery.profiles})
        transport = plan(config, observed, mock_admissions(config), Intent(), 1000)
        actions = {
            item.id: item for item in plan_discovery(config, observed, transport, Intent(), 1000)
        }
        assert actions["media-import"].active
        assert actions["media-import"].reason == ("verified" if active else "ready")
    finally:
        manager.close()


@pytest.mark.parametrize("fragmented_kind", ["service", "record"])
def test_registration_waits_for_complete_callback_line(tmp_path, monkeypatch, fragmented_kind):
    record = media_record()
    service = (
        "12:34:56.000  Got a reply for service Example speaker._airplay._tcp.local.: "
        "Name now registered and active\n"
    )
    address = (
        "12:34:56.000  Got a reply for record speaker.local.: Name now registered and active\n"
    )
    lines = [service, address]
    fragmented = 0 if fragmented_kind == "service" else 1
    chunks = ["Using interface 7\n"]
    for index, line in enumerate(lines):
        chunks.extend([line[:45], line[45:]] if index == fragmented else [line])
    fake = tmp_path / "fragmented-dns-sd"
    fake.write_text(
        f"#!{sys.executable}\nimport os, time\n"
        f"for chunk in {chunks!r}:\n"
        " os.write(1, chunk.encode())\n time.sleep(0.1)\n"
        "time.sleep(5)\n"
    )
    fake.chmod(0o700)
    monkeypatch.setattr(native, "DNS_SD", str(fake))
    registration = native.Registration(record, 7)
    try:
        deadline = time.monotonic() + 3
        while not registration.poll() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert registration.active
    finally:
        registration.close()

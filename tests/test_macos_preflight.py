"""Synthetic local command responses; never run a native probe or LAN operation."""

from __future__ import annotations

import hashlib
import os
import plistlib
from pathlib import Path
from typing import Any

import pytest

from netorch import macos_preflight as preflight
from netorch.process import OutputLimit, ProcessTimeout, Result

VPN_HEADER = "Available network connection services in the current set (*=enabled):"
VPN_ID = "00000000-0000-4000-8000-000000000001"


def vpn_row(status: str = "Disconnected", *, enabled: bool = True, name: str = "Example") -> str:
    return f'{"*" if enabled else " "} ({status}) {VPN_ID} VPN "{name}" [VPN:example]'


SAMPLES = {
    "macos_version": "27.0.1",
    "macos_build": "26A434",
    "architecture": "arm64",
    "hardware_model": "MacExample1,1",
    "filevault": "FileVault is Off.",
    "automatic_login": "example",
    "power_restart": "AC Power:\n autorestart 1\n sleep 0",
    "application_firewall": "Firewall is enabled. (State = 1)",
    "network_extensions": "0 extension(s)",
    "proxies": "<dictionary> {\n HTTPEnable : 0\n}",
    "vpns": VPN_HEADER + "\n" + vpn_row(),
    "internet_sharing": plistlib.dumps({"NAT": {"Enabled": 0}}).decode(),
    "interfaces": (
        "example0: flags=8863<UP> mtu 1500\n ether 02:00:00:00:00:01\n"
        " inet 192.0.2.20 netmask 0xffffff00\n"
    ),
}


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("macos_version", "27.0.1"),
        ("macos_build", "26A434"),
        ("architecture", "apple-silicon"),
        ("hardware_model", "MacExample1,1"),
        ("filevault", "off"),
        ("automatic_login", True),
        ("power_restart", True),
        ("application_firewall", True),
        ("network_extensions", []),
        ("proxies", False),
        ("vpns", False),
        ("internet_sharing", False),
    ],
)
def test_native_fact_parsers(key: str, expected: Any) -> None:
    assert preflight._parse(key, SAMPLES[key]) == expected


@pytest.mark.parametrize("key", [key for key in SAMPLES if key != "interfaces"])
def test_empty_success_is_not_a_fact(key: str) -> None:
    with pytest.raises(ValueError):
        preflight._parse(key, "")


def test_unique_lan_identity_and_expected_address() -> None:
    actual = preflight._interface_facts(SAMPLES["interfaces"], "192.0.2.20")
    assert actual["lan_interface"] == "example0"
    other = (
        SAMPLES["interfaces"].replace("example0", "example1").replace("192.0.2.20", "192.0.2.21")
    )
    with pytest.raises(ValueError):
        preflight._interface_facts(SAMPLES["interfaces"] + other, None)
    assert preflight._interface_facts(SAMPLES["interfaces"] + other, "192.0.2.20") == actual
    assert (
        preflight._expected_address({"host": {"lan": {"address": "192.0.2.20/24"}}}) == "192.0.2.20"
    )
    assert preflight._expected_address({"host": {"lan": {"address": "bad"}}}) is None


def test_collector_uses_only_fixed_local_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight.sys, "platform", "darwin")
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(Path, "is_file", lambda path: False)

    calls: list[tuple[str, ...]] = []
    reverse = {argv: key for key, argv in preflight.COMMANDS.items()}

    def runner(argv: tuple[str, ...], timeout: float) -> Result:
        assert 0 < timeout <= preflight.COMMAND_TIMEOUT
        calls.append(argv)
        return Result(0, SAMPLES[reverse[argv]].encode(), b"")

    monkeypatch.setattr(preflight, "_file_digest", lambda path: "a" * 64)
    monkeypatch.setattr(Path, "iterdir", lambda path: iter(()))
    report = preflight.collect_preflight(runner=runner, clock=lambda: 100.0)
    assert calls == list(preflight.COMMANDS.values())
    assert report["observed_at"] == 100.0
    keys = [item["key"] for item in report["facts"]]
    assert len(keys) == len(set(keys))
    assert "interfaces" not in keys
    fact = {item["key"]: item for item in report["facts"]}
    assert fact["local_network_identity"]["reason"] == "not-checked"
    assert fact["anchor_order"]["state"] == "unknown"
    assert fact["runtime_version"]["state"] == "unknown"
    assert fact["pf_baseline_sha256"]["value"] == "a" * 64


@pytest.mark.parametrize("failure", ["exit", "timeout", "oversize", "malformed", "permission"])
def test_failures_stay_unknown_without_raw_output(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    monkeypatch.setattr(preflight.sys, "platform", "darwin")
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(Path, "is_file", lambda path: False)

    def unavailable(path: Path) -> str:
        raise PermissionError("no platform file in the synthetic lab")

    monkeypatch.setattr(preflight, "_file_digest", unavailable)

    def runner(argv: tuple[str, ...], timeout: float) -> Result:
        if failure == "timeout":
            raise ProcessTimeout("bounded")
        if failure == "oversize":
            raise OutputLimit("bounded")
        if failure == "permission":
            raise PermissionError("private response")
        return Result(1 if failure == "exit" else 0, b"private response", b"private error")

    report = preflight.collect_preflight(runner=runner)
    assert all(item["state"] == "unknown" for item in report["facts"])
    assert "private response" not in str(report)
    assert "private error" not in str(report)


def test_unsupported_host_and_expired_budget_make_no_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(Path, "is_file", lambda path: False)
    monkeypatch.setattr(preflight, "_file_digest", lambda path: "a" * 64)
    monkeypatch.setattr(Path, "iterdir", lambda path: iter(()))

    def forbidden(argv: tuple[str, ...], timeout: float) -> Result:
        raise AssertionError("unexpected operation")

    monkeypatch.setattr(preflight.sys, "platform", "unsupported-test")
    report = preflight.collect_preflight(runner=forbidden)
    assert all(item["state"] == "unknown" for item in report["facts"])
    monkeypatch.setattr(preflight.sys, "platform", "darwin")
    times = iter([0.0, *([preflight.TOTAL_TIMEOUT + 1] * 30)])
    report = preflight.collect_preflight(runner=forbidden, monotonic=lambda: next(times))
    assert report["facts"][0]["reason"] == "timed-out"


def test_root_is_rejected_before_any_native_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(PermissionError, match="unprivileged"):
        preflight.collect_preflight()


def test_digest_refuses_symlink_and_changed_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "baseline"
    path.write_bytes(b"unchanged")
    assert preflight._file_digest(path) == hashlib.sha256(b"unchanged").hexdigest()
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        preflight._file_digest(link)
    original = os.fstat
    count = 0

    def changed(fd: int) -> os.stat_result:
        nonlocal count
        count += 1
        info = original(fd)
        if count == 2:
            path.write_bytes(b"changed")
            return original(fd)
        return info

    monkeypatch.setattr(os, "fstat", changed)
    with pytest.raises(ValueError, match="changed"):
        preflight._file_digest(path)


@pytest.mark.parametrize(
    ("key", "text"),
    [
        ("network_extensions", "2 extension(s)"),
        ("network_extensions", "0 extension(s)\n org.example.driver"),
        ("proxies", "<dictionary> {\n HTTPEnable : unknown\n}"),
        ("proxies", "<dictionary> {\n HTTPEnable : 2\n}"),
    ],
)
def test_incomplete_coexistence_output_never_means_disabled(key: str, text: str) -> None:
    with pytest.raises(ValueError):
        preflight._parse(key, text)


@pytest.mark.parametrize("mode", ["homebrew", "package", "timeout", "malformed", "ambiguous"])
def test_runtime_method_needs_evidence_not_path(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight.sys, "platform", "darwin")
    monkeypatch.setattr(preflight, "_file_digest", lambda path: "a" * 64)
    monkeypatch.setattr(Path, "iterdir", lambda path: iter(()))
    method = "signed-package" if mode == "package" else "homebrew"
    selected = Path(
        "/usr/local/bin/container" if method == "signed-package" else "/opt/homebrew/bin/container"
    )
    monkeypatch.setattr(Path, "is_file", lambda path: mode == "ambiguous" or path == selected)
    monkeypatch.setattr(
        Path,
        "resolve",
        lambda path: (
            Path("/opt/homebrew/Cellar/container/1.5.0/bin/container")
            if mode == "homebrew"
            else path
        ),
    )
    reverse = {argv: key for key, argv in preflight.COMMANDS.items()}

    def runner(argv: tuple[str, ...], timeout: float) -> Result:
        if argv[-1] == "--version":
            if mode == "timeout":
                raise ProcessTimeout("bounded")
            return Result(
                0, b"broken" if mode == "malformed" else b"container CLI version 1.5.0", b""
            )
        return Result(0, SAMPLES[reverse[argv]].encode(), b"")

    report = preflight.collect_preflight(runner=runner, monotonic=lambda: 0)
    facts = {item["key"]: item for item in report["facts"]}
    assert facts["runtime_version"]["state"] == (
        "present" if mode in {"homebrew", "package"} else "unknown"
    )
    assert facts["runtime_install_method"]["state"] == (
        "present" if mode == "homebrew" else "unknown"
    )


def test_baseline_path_replacement_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "baseline"
    path.write_bytes(b"old")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"new")
    original = os.fstat
    count = 0

    def swap(fd: int) -> os.stat_result:
        nonlocal count
        count += 1
        if count == 2:
            replacement.replace(path)
        return original(fd)

    monkeypatch.setattr(os, "fstat", swap)
    with pytest.raises(ValueError, match="changed"):
        preflight._file_digest(path)


def test_baseline_fifo_cannot_block_before_regular_file_check(tmp_path: Path) -> None:
    path = tmp_path / "fifo"
    os.mkfifo(path)
    with pytest.raises(ValueError, match="invalid local baseline"):
        preflight._file_digest(path)


def test_extension_version_numbers_are_not_bundle_identifiers() -> None:
    # Synthetic output shape: vendor version strings are not installed IDs.
    text = (
        "1 extension(s)\n"
        "--- com.apple.system_extension.network_extension\n"
        "enabled active teamID bundleID (version) name [state]\n"
        "* * ABCDE12345 org.example.driver (1.2.3/1.2.3) Example [activated enabled]"
    )
    assert preflight._parse("network_extensions", text) == ["org.example.driver"]


@pytest.mark.parametrize("status", ["Connected", "Connecting", "Disconnecting"])
def test_vpn_active_status_column_including_disconnect_transition(status: str) -> None:
    assert preflight._parse("vpns", VPN_HEADER + "\n" + vpn_row(status)) is True


def test_vpn_service_name_cannot_impersonate_its_status_column() -> None:
    assert preflight._parse("vpns", VPN_HEADER + "\n" + vpn_row(name="(Connected)")) is False
    assert preflight._parse("vpns", VPN_HEADER + "\n" + vpn_row("Invalid", enabled=False)) is False


@pytest.mark.parametrize(
    "text",
    [
        VPN_HEADER,
        VPN_HEADER + "\n* (Connec",
        VPN_HEADER + "\n" + vpn_row("Unknown"),
        VPN_HEADER + "\n" + vpn_row("Invalid"),
        VPN_HEADER + "\n" + vpn_row("Connected", enabled=False),
        VPN_HEADER + "\n" + vpn_row() + "\n" + vpn_row(),
        VPN_HEADER + "\n" + vpn_row() + "\nunparsed row",
        VPN_HEADER + "\n" + vpn_row().replace(VPN_ID, "truncated-id"),
        VPN_HEADER + "\n" + vpn_row().replace('"Example"', '"Example'),
        VPN_HEADER + " truncated",
    ],
)
def test_incomplete_or_unknown_vpn_inventory_cannot_prove_disabled(text: str) -> None:
    with pytest.raises(ValueError):
        preflight._parse("vpns", text)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("<dictionary> {\n}", False),
        ("<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 1\n}", True),
        (
            "<dictionary> {\n  ExceptionsList : <array> {\n"
            "    0 : *.example\n    1 : localhost\n  }\n"
            "  ExcludeSimpleHostnames : 1\n  HTTPEnable : 0\n}",
            False,
        ),
        (
            "<dictionary> {\n  __SCOPED__ : <dictionary> {\n"
            "    example0 : <dictionary> {\n      HTTPEnable : 1\n"
            "      HTTPProxy : proxy.example\n      HTTPPort : 8080\n    }\n  }\n}",
            True,
        ),
        (
            "<dictionary> {\n  __SUPPLEMENTAL__ : <array> {\n"
            "    0 : <dictionary> {\n      ProxyAutoConfigEnable : 1\n"
            "      ProxyAutoConfigURLString : https://proxy.example/config.pac\n    }\n  }\n}",
            True,
        ),
    ],
)
def test_complete_proxy_dictionary_and_nested_native_shapes(text: str, expected: bool) -> None:
    assert preflight._parse("proxies", text) is expected


@pytest.mark.parametrize(
    "text",
    [
        "<dictionary> {\n  HTTPEnable blah\n}",
        "<dictionary> {\n  HTTPEnable :\n}",
        "<dictionary> {\n  HTTPEnable : 0\n  HTTPEnable : 0\n}",
        "<dictionary> {\n  HTTPEnable : 0\n  HTTPEnable : 1\n}",
        "<dictionary> {\n  Scoped : <dictionary> {\n  HTTPEnable : 0\n}",
        "<dictionary> {\n  Scoped : <dictionary> {\n  HTTPEnable : 1\n}",
        "<dictionary> {\n  List : <array> {\n    1 : missing-first-item\n  }\n}",
        "<dictionary> {\n  List : <array> {\n    0 : one\n    0 : repeated\n  }\n}",
        "<dictionary> {\n  Scoped : <dictionary>\n}",
        "<dictionary> {\n  HTTPEnable : <dictionary> {\n  }\n}",
        "<dictionary> {\n}\ntrailing",
        "<dictionary> {\n}\n}",
        "<dictionary> {\n  HTTPEnable : 0\x00\n}",
    ],
)
def test_malformed_proxy_tree_never_becomes_complete(text: str) -> None:
    with pytest.raises(ValueError):
        preflight._parse("proxies", text)


def test_proxy_nesting_is_bounded_without_rejecting_complete_shallow_trees() -> None:
    def nested(depth: int) -> str:
        return "<dictionary> {\n" + "  item : <dictionary> {\n" * depth + "}\n" * (depth + 1)

    assert preflight._parse("proxies", nested(31)) is False
    with pytest.raises(ValueError, match="nesting"):
        preflight._parse("proxies", nested(32))


def test_collector_preserves_unknown_vpn_instead_of_complete_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(preflight.sys, "platform", "darwin")
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(Path, "is_file", lambda path: False)
    monkeypatch.setattr(preflight, "_file_digest", lambda path: "a" * 64)
    monkeypatch.setattr(Path, "iterdir", lambda path: iter(()))
    reverse = {argv: key for key, argv in preflight.COMMANDS.items()}

    def runner(argv: tuple[str, ...], timeout: float) -> Result:
        key = reverse[argv]
        return Result(0, (VPN_HEADER if key == "vpns" else SAMPLES[key]).encode(), b"")

    report = preflight.collect_preflight(runner=runner)
    fact = next(item for item in report["facts"] if item["key"] == "vpns")
    assert fact["state"] == "unknown"
    assert fact["reason"] == "incomplete"
    assert fact["value"] is None


@pytest.mark.parametrize(
    "text",
    [
        "0 extension(s)\nmalformed extension row",
        "0 extension(s) partial response",
        "1 extension(s)\norg.example.driver",
        "1 extension(s)\n--- com.apple.system_extension.network_extension",
        "1 extension(s)\n--- com.apple.system_extension.network_extension\n"
        "enabled active teamID bundleID (version) name [state]",
    ],
)
def test_extension_count_or_id_alone_cannot_prove_complete_inventory(text: str) -> None:
    with pytest.raises(ValueError):
        preflight._parse("network_extensions", text)


def test_complete_multiple_extension_categories_and_duplicate_rejection() -> None:
    columns = "enabled active teamID bundleID (version) name [state]\n"
    group_one = "--- com.apple.system_extension.network_extension\n" + columns
    group_two = (
        "--- com.apple.system_extension.driver_extension (Go to System Settings)\n" + columns
    )
    row_one = "* * ABCDE12345 org.example.driver (1.2.3/1.2.3) Example [activated enabled]"
    row_two = "    ABCDE12345 org.example.other (4.5/4.5) Example [activated waiting for user]"
    text = "2 extension(s)\n" + group_one + row_one + "\n" + group_two + row_two
    assert preflight._parse("network_extensions", text) == [
        "org.example.driver",
        "org.example.other",
    ]
    for broken in (
        text.replace("org.example.other", "org.example.driver"),
        text + "\n" + group_one,
        text.replace("[activated enabled]", "[future state]"),
        text.replace("2 extension(s)", "1 extension(s)"),
    ):
        with pytest.raises(ValueError):
            preflight._parse("network_extensions", broken)


def test_power_inventory_is_sectioned_and_ac_setting_is_explicit() -> None:
    assert (
        preflight._parse(
            "power_restart", "Battery Power:\n sleep 1\nAC Power:\n autorestart 1\n sleep 0"
        )
        is True
    )
    assert preflight._parse("power_restart", "AC Power:\n autorestart 0\n sleep 0") is False


@pytest.mark.parametrize(
    "text",
    [
        "not the pmset inventory\nautorestart 1",
        "AC Power:\n autorestart 1\ntruncated row",
        "AC Power:\n autorestart 1\n autorestart 1",
        "AC Power:\n autorestart 1\n sleep 0\n sleep 0",
        "AC Power:\n autorestart 2",
        "Battery Power:\n autorestart 1",
        "AC Power:\n sleep 0",
        "AC Power:\n autorestart 1\nUPS Power:",
        "AC Power:\nUPS Power:\n autorestart 1",
        "AC Power:\n autorestart 1\nAC Power:\n autorestart 1",
        "Future Power:\n autorestart 1",
    ],
)
def test_power_inventory_incomplete_or_conflicting_is_unknown(text: str) -> None:
    with pytest.raises(ValueError):
        preflight._parse("power_restart", text)


@pytest.mark.parametrize("enabled", [0, 1, False, True])
def test_sharing_reads_only_complete_top_level_nat_flag(enabled: int | bool) -> None:
    data = {"NAT": {"Enabled": enabled, "PrimaryInterface": {"Enabled": 1}}}
    assert preflight._parse("internet_sharing", plistlib.dumps(data).decode()) is bool(enabled)
    assert preflight.COMMANDS["internet_sharing"][1:] == (
        "export",
        "/Library/Preferences/SystemConfiguration/com.apple.nat",
        "-",
    )


@pytest.mark.parametrize(
    "data",
    [{}, {"NAT": {}}, {"NAT": True}, {"NAT": {"Enabled": 2}}, {"NAT": {"Enabled": "1"}}],
)
def test_absent_or_invalid_sharing_flag_is_unknown(data: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        preflight._parse("internet_sharing", plistlib.dumps(data).decode())


@pytest.mark.parametrize(
    "text",
    [
        "broken output\nEnabled = 0;",
        "{\n Enabled = 0;\n}",
        '<?xml version="1.0"?><plist><dict><key>NAT</key><dict><key>Enabled</key>',
        '<?xml version="1.0"?><plist><dict><key>NAT</key><dict><key>Enabled</key>'
        "<integer>0</integer><key>Enabled</key><integer>1</integer></dict></dict></plist>",
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY flag "1">]><plist><dict/></plist>',
    ],
)
def test_malformed_sharing_xml_never_proves_disabled(text: str) -> None:
    with pytest.raises(ValueError):
        preflight._parse("internet_sharing", text)

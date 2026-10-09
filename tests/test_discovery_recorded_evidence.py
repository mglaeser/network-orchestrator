"""Replay sanitized *recorded* CLI bytes; never invoke native networking.

The limited-browse scan below deliberately selects the two captured resolves.
That test transformation is not a claim the original LAN contained two devices.
Malformed variants are test-generated mutations, not additional native captures.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.discovery import Record
from netorch.process import Result
from tests.recorded import load_recording
from tests.test_bonjour_owner import config, policy, settings, snapshot

__all__ = ["config", "settings"]

TYPES = {"airplay": "_airplay._tcp", "raop": "_raop._tcp", "homekit": "_hap._tcp"}
ENDPOINTS = {
    "airplay-00": ("MediaÄ01", "endpoint-01.local.", "192.0.2.10", 7000, 18),
    "airplay-01": ("MediaÄ02", "endpoint-02.local.", "192.0.2.11", 7000, 18),
    "raop-00": ("020000000001@MediaÄ01", "endpoint-02.local.", "192.0.2.11", 7000, 13),
    "raop-01": ("020000000002@MediaÄ02", "endpoint-05.local.", "192.0.2.13", 7000, 13),
    "homekit-00": ("Bridge Unit 01 ABCDEF", "endpoint-03.local.", "192.0.2.12", 21065, 9),
    "homekit-01": ("Bridge Unit 02 ABCDEF", "endpoint-04.local.", "192.0.2.12", 21066, 9),
}


def read(identifier):
    recording = load_recording("discovery", identifier)
    assert recording.status == "exited" and recording.returncode == 0
    return native.confirmed_output(
        Result(recording.returncode, recording.stdout, recording.stderr), 10
    )


def endpoint(identifier):
    kind = identifier.split("-")[0]
    full, host, port = native.resolve_endpoint(read(identifier + "-resolve"), 10)
    address = native.resolve_ipv4(read(identifier + "-address"), host, 10)
    txt = native.resolve_txt(read(identifier + "-txt"), full, 10)
    return Record(ENDPOINTS[identifier][0], TYPES[kind], host, port, address, txt, "en0", 1000)


@pytest.mark.parametrize("kind,count", [("airplay", 5), ("raop", 5), ("homekit", 8)])
def test_recorded_browse_preserves_every_observed_row(kind, count):
    names = native.browse_names(read("browse-" + kind), TYPES[kind], 10, 30)
    assert len(names) == count
    assert {ENDPOINTS[kind + f"-{index:02}"][0] for index in range(2)} <= set(names)
    if kind != "homekit":
        assert any("Ä" in name for name in names)
    with pytest.raises(native.DiscoveryFailure, match="incomplete"):
        native.browse_names(read("browse-" + kind), TYPES[kind], 10, count - 1)


@pytest.mark.parametrize("identifier", ENDPOINTS)
def test_recorded_resolve_address_txt_and_registration_arguments(identifier):
    record = endpoint(identifier)
    name, hostname, address, port, count = ENDPOINTS[identifier]
    assert (record.name, record.hostname, record.ipv4, record.port) == (
        name,
        hostname,
        address,
        port,
    )
    assert len(record.txt) == count
    # The renderer is exercised; no Registration or native process is started.
    argv = native.registration_argv(record, 30)
    assert argv[:6] == [native.DNS_SD, "-i", "en0", "-t", "30", "-P"]
    assert argv[6:12] == [name, record.service_type, "local.", str(port), hostname, address]
    expected = ["".join(f"\\x{byte:02X}" for byte in item) for item in record.txt]
    assert argv[12:] == expected
    if identifier.startswith("homekit"):
        fullname, _, _ = native.resolve_endpoint(read(identifier + "-resolve"), 10)
        assert "\\032" in fullname
        assert any(item.startswith(b"md=") and b" " in item for item in record.txt)


@pytest.mark.parametrize("kind", TYPES)
def test_scanner_runs_all_four_operations_using_recorded_endpoint_subset(kind):
    chosen = [kind + f"-{index:02}" for index in range(2)]
    names = {ENDPOINTS[identifier][0]: identifier for identifier in chosen}
    hosts = {ENDPOINTS[identifier][1]: identifier for identifier in chosen}
    fullnames = {
        native.resolve_endpoint(read(identifier + "-resolve"), 10)[0]: identifier
        for identifier in chosen
    }
    observed_calls = []

    def runner(argv, timeout):
        assert argv[:5] == [native.DNS_SD, "-t", "2", "-i", "en0"]
        assert 0 < timeout <= 3
        operation = argv[6:] if argv[5] == "-m" else argv[5:]
        observed_calls.append(operation[0])
        if operation[0] == "-B":
            assert operation == ["-B", TYPES[kind], "local."]
            # Explicit test-derived subset of a real browse, keeping its exact
            # banners and selected rows. It is NOT a native two-device census.
            raw = read("browse-" + kind)
            rows = raw.splitlines(keepends=True)
            output = b"".join(
                row
                for row in rows
                if b"  Add " not in row
                or any(row.rstrip(b"\n").endswith(name.encode()) for name in names)
            )
        elif operation[0] == "-L":
            assert operation[2:] == [TYPES[kind], "local."]
            output = read(names[operation[1]] + "-resolve")
        elif operation[0] == "-G":
            assert operation[1] == "v4"
            output = read(hosts[operation[2]] + "-address")
        else:
            assert operation[0] == "-Q" and operation[2:] == ["TXT", "IN"]
            output = read(fullnames[operation[1]] + "-txt")
        return Result(0, output, b"")

    records = native.scan("en0", 10, TYPES[kind], 30, 2, 1000, runner)
    assert set(records) == {endpoint(identifier) for identifier in chosen}
    assert observed_calls == ["-B", "-L", "-G", "-Q", "-L", "-G", "-Q"]


def test_recorded_media_import_requires_observed_airplay_anchor(config, settings):
    records = tuple(endpoint(key) for key in ENDPOINTS if not key.startswith("homekit"))
    rule = policy(config)
    projected = owner.project_records(
        config, rule, records, snapshot(config), frozenset(rule.dependencies), settings, 1000
    )
    # Only one captured RAOP record has a matching captured AirPlay host AND IP.
    # The AppleTV RAOP-only sample does not prove an AirPlay anchor was observed.
    assert {item.name for item in projected} == {
        ENDPOINTS[key][0] for key in ("airplay-00", "airplay-01", "raop-00")
    }
    assert all(item.interface == "bridge-test" for item in projected)
    assert len({item.hostname for item in projected}) == 3
    for item in projected:
        original = next(record for record in records if record.name == item.name)
        assert replace(item, hostname=original.hostname, interface="en0") == original
    with pytest.raises(native.DiscoveryFailure):
        owner.project_records(config, rule, records, snapshot(config), frozenset(), settings, 1000)


@pytest.mark.parametrize("identifier", ENDPOINTS)
def test_recorded_txt_mutations_do_not_hide_after_a_valid_callback(identifier):
    full, _, _ = native.resolve_endpoint(read(identifier + "-resolve"), 10)
    raw = read(identifier + "-txt")
    # These are intentional test corruptions, never claimed as captured output.
    for suffix in (b"20:30:00.000  Add garbage\n", b"Error code -65570\n"):
        with pytest.raises(native.DiscoveryFailure):
            native.resolve_txt(raw + suffix, full, 10)
    malformed = re.sub(rb"\d+ bytes:", b"1 bytes:", raw)
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_txt(malformed, full, 10)


@pytest.mark.parametrize("identifier", ENDPOINTS)
def test_recorded_read_refuses_wrong_interface_even_with_success_status(identifier):
    raw = load_recording("discovery", identifier + "-resolve").stdout
    with pytest.raises(native.DiscoveryFailure):
        native.confirmed_output(Result(0, raw, b""), 11)
    with pytest.raises(native.DiscoveryFailure):
        native.resolve_endpoint(raw, 11)


@pytest.mark.parametrize("outcome", ["clean", "stderr", "nonzero-exit"])
def test_default_interface_runner_preserves_real_child_failure_signals(monkeypatch, outcome):
    recording = load_recording("packet", "native-lan-interface")
    assert recording.status == "exited" and recording.returncode == 0
    assert recording.stderr == b""
    assert recording.stdout.startswith(b"en0:")
    assert b"\tinet 192.0.2.10 " in recording.stdout
    index_lookups = []

    def observed_index(name):
        index_lookups.append(name)
        assert name == "en0"
        return 10

    monkeypatch.setattr(native.socket, "if_nametoindex", observed_index)
    with tempfile.TemporaryDirectory(prefix="netorch-ifconfig-replay-", dir="/tmp") as directory:
        work = Path(directory)
        executable = work / "offline interface reader"
        # A no-space temporary interpreter path also works when the checkout
        # and its virtualenv live in a directory containing spaces.
        interpreter = work / "python"
        interpreter.symlink_to(sys.executable)
        (work / "interface.stdout").write_bytes(recording.stdout)
        (work / "interface.stderr").write_bytes(
            b"synthetic child diagnostic\n" if outcome == "stderr" else b""
        )
        code = 7 if outcome == "nonzero-exit" else 0
        # The kernel starts this fixed local Python interpreter. The process
        # runner itself still receives an argv vector, never a shell command.
        executable.write_text(
            f"#!{interpreter}\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "root = Path(__file__).parent\n"
            "assert sys.argv[1:] == ['en0']\n"
            "(root / 'invocation.json').write_text(json.dumps(\n"
            "    {'pid': os.getpid(), 'arguments': sys.argv[1:]}))\n"
            "data = (root / 'interface.stdout').read_bytes()\n"
            "middle = len(data) // 2\n"
            "os.write(1, data[:middle])\n"
            "os.write(1, data[middle:])\n"
            "os.write(2, (root / 'interface.stderr').read_bytes())\n"
            f"raise SystemExit({code})\n"
        )
        executable.chmod(0o700)
        monkeypatch.setattr(native, "IFCONFIG", str(executable))
        # Deliberately omit runner=. This traverses the real default command()
        # adapter and process.run(), including actual stdout/stderr/exit status.
        if outcome == "clean":
            assert native.interface_index("en0", "192.0.2.10") == 10
            assert index_lookups == ["en0"]
        else:
            with pytest.raises(native.DiscoveryFailure, match="unavailable"):
                native.interface_index("en0", "192.0.2.10")
            # Valid-looking stdout cannot authorize an interface lookup when
            # the real child failed or emitted a diagnostic on its error pipe.
            assert index_lookups == []
        invocation = json.loads((work / "invocation.json").read_text())
        assert invocation["arguments"] == ["en0"]
        with pytest.raises(ChildProcessError):
            os.waitpid(invocation["pid"], os.WNOHANG)
    assert not work.exists()

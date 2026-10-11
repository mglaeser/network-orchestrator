"""Paired native recordings replay the extracted selector without native queries.

The positive capture is production data, sanitized without removing records.
Replacement, ambiguity and corruption cases are explicitly synthetic mutations.
Only the pure Perl resolve function is called; native inventory remains untouched.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

from netorch.process import Result, run
from netorch.wired_interface import RESOURCE, selector_path
from tests.recorded import load_recording

ROOT = Path(__file__).resolve().parents[1]
PERL = "/usr/bin/perl"
TARGET = "192.0.2.10"


def inventories() -> tuple[str, str]:
    hardware = load_recording("wired", "hardware-ports")
    interfaces = load_recording("wired", "interfaces")
    assert hardware.returncode == interfaces.returncode == 0
    assert hardware.stderr == interfaces.stderr == b""
    return hardware.stdout.decode(), interfaces.stdout.decode()


def resolve(hardware: str, interfaces: str, address: str = TARGET) -> Result:
    return run(
        [
            PERL,
            "-MJSON::PP",
            "-e",
            "require shift @ARGV; my $v=decode_json(do {local $/;<STDIN>}); "
            "my $r=eval {WiredInterface::resolve(@$v)}; "
            'if ($@) {print STDERR $@; exit 1} print "$r\\n";',
            str(selector_path()),
        ],
        input_data=json.dumps([address, hardware, interfaces]).encode(),
        timeout=3,
    )


def selected_block(interfaces: str) -> str:
    return re.search(r"(?ms)^en108:.*?(?=^\S|\Z)", interfaces)[0]  # type: ignore[index]


def test_recorded_pair_selects_only_current_cabled_address_owner() -> None:
    result = resolve(*inventories())
    assert result == Result(0, b"en108\n", b"")


def test_replacement_renumbers_both_recorded_inventories_without_fixed_en_pin() -> None:
    hardware, interfaces = inventories()
    result = resolve(hardware.replace("en108", "en207"), interfaces.replace("en108", "en207"))
    assert result == Result(0, b"en207\n", b"")


def test_exact_mac_redaction_keeps_independent_hardware_and_link_requirements() -> None:
    hardware, interfaces = inventories()
    block = selected_block(interfaces)
    redacted = re.sub(r"ether (?:[0-9a-f]{2}:){5}[0-9a-f]{2}", "ether 02:00:00:00:00:00", block)
    result = resolve(hardware, interfaces.replace(block, redacted))
    assert result == Result(0, b"en108\n", b"")
    invalid = hardware.replace("02:11:22:33:44:11", "02:00:00:00:00:00")
    assert resolve(invalid, interfaces.replace(block, redacted)).returncode == 1


@pytest.mark.parametrize(
    "case",
    [
        "missing-ip",
        "duplicate-ip",
        "wifi",
        "virtual",
        "missing-hardware",
        "mac-mismatch",
        "link-down",
        "not-running",
        "loopback",
        "no-media",
        "wireless-media",
        "bad-netmask",
        "noncontiguous-mask",
        "duplicate-interface",
        "malformed-header",
        "duplicate-status",
    ],
)
def test_mutated_recordings_cannot_admit_missing_ambiguous_or_malformed_identity(case: str) -> None:
    hardware, interfaces = inventories()
    block = selected_block(interfaces)
    changed = block
    if case == "missing-ip":
        changed = block.replace(TARGET, "192.0.2.20")
    elif case == "duplicate-ip":
        interfaces += block.replace("en108", "en209")
    elif case in {"wifi", "virtual"}:
        hardware = hardware.replace(
            "USB 10/100/1000 LAN", "Wi-Fi" if case == "wifi" else "Virtual Ethernet"
        )
    elif case == "missing-hardware":
        hardware = hardware.replace("Device: en108", "Device: en209")
    elif case == "mac-mismatch":
        changed = block.replace("02:11:22:33:44:11", "02:11:22:33:44:fa")
    elif case == "link-down":
        changed = block.replace("status: active", "status: inactive")
    elif case == "not-running":
        changed = block.replace("RUNNING,", "")
    elif case == "loopback":
        changed = block.replace("<UP,", "<UP,LOOPBACK,")
    elif case in {"no-media", "wireless-media"}:
        changed = re.sub(
            r"media: .*", "media: " + ("autoselect" if case == "no-media" else "IEEE802.11"), block
        )
    elif case in {"bad-netmask", "noncontiguous-mask"}:
        changed = block.replace(
            "0xffffff00", "999.999.999.999" if case == "bad-netmask" else "0xffff00ff"
        )
    elif case == "duplicate-interface":
        interfaces += block
    elif case == "malformed-header":
        interfaces += "unexpected inventory error\n"
    else:
        changed = block + "\tstatus: active\n"
    result = resolve(hardware, interfaces.replace(block, changed))
    assert result.returncode == 1 and result.stdout == b""


@pytest.mark.parametrize("mask", ["0xffffff00", "255.255.255.0", "0xfffffffe"])
def test_valid_mask_formats_do_not_change_identity(mask: str) -> None:
    hardware, interfaces = inventories()
    assert resolve(hardware, interfaces.replace("0xffffff00", mask)).stdout == b"en108\n"


@pytest.mark.parametrize(
    "media",
    [
        "100baseTX",
        "10baseT <half-duplex>",
        "autoselect (2500baseT <full-duplex>)",
        "autoselect (5000baseT <full-duplex,flow-control>)",
        "10Gbase-T <full-duplex>",
        "autoselect (1000baseT <full-duplex,rxpause,txpause>)",
    ],
)
def test_anchored_media_preserves_negotiated_and_fixed_copper_formats(media: str) -> None:
    hardware, interfaces = inventories()
    changed = interfaces.replace("autoselect (1000baseT <full-duplex>)", media)
    assert resolve(hardware, changed) == Result(0, b"en108\n", b"")


@pytest.mark.parametrize(
    "media",
    [
        "none 1000baseT garbage",
        "autoselect (1000baseT",
        "1000baseT)",
        "autoselect (1000baseT <full-duplex>) ignored",
        "autoselect (1000baseT garbage)",
        "autoselect (1000baseT <full-duplex,>)",
        "autoselect (1000baseT <>)",
    ],
)
def test_malformed_media_is_not_an_ethernet_token_search(media: str) -> None:
    hardware, interfaces = inventories()
    changed = interfaces.replace("autoselect (1000baseT <full-duplex>)", media)
    result = resolve(hardware, changed)
    assert result.returncode == 1 and result.stdout == b""


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "0.1.2.3",
        "224.0.0.1",
        "255.255.255.255",
        "192.0.2.010",
        "::1",
    ],
)
def test_pure_selector_rejects_invalid_addresses_from_recorded_inputs(address: str) -> None:
    result = resolve(*inventories(), address=address)
    assert result.returncode == 1 and result.stdout == b""


def test_native_reader_environment_and_error_output_are_bounded() -> None:
    result = run(
        [
            PERL,
            "-e",
            'require shift @ARGV; $ENV{UNTRUSTED_TEST}="not inherited"; '
            'print WiredInterface::command_output("/usr/bin/perl", "-e", '
            'q{print "$ENV{LC_ALL}:";print $ENV{UNTRUSTED_TEST}//"absent"});',
            str(selector_path()),
        ],
        timeout=3,
    )
    assert result == Result(0, b"C:absent", b"")


@pytest.mark.parametrize("body", ['print "x" x 1100000; sleep 30', "sleep 30"])
def test_failed_inventory_child_is_killed_and_reaped_before_return(body: str) -> None:
    result = run(
        [
            PERL,
            "-e",
            "require shift @ARGV; "
            'eval {WiredInterface::command_output("/usr/bin/perl", "-e", shift @ARGV)}; '
            'die "expected failure" unless $@; select undef,undef,undef,0.1; '
            'my $pid=waitpid(-1,1); die "owned child left unreaped" unless $pid == -1; '
            'print "reaped\\n";',
            str(selector_path()),
            body,
        ],
        timeout=8,
    )
    assert result == Result(0, b"reaped\n", b"")


def test_selector_is_in_wheel_and_sdist_resources() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    targets = config["tool"]["hatch"]["build"]["targets"]
    assert targets["wheel"]["force-include"][RESOURCE] == "netorch/" + RESOURCE
    assert "/platform" in targets["sdist"]["include"]
    assert selector_path().is_file()

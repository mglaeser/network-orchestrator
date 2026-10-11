"""Bounded preflight invokes only the packaged selector, never instance commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from netorch import macos_preflight as preflight
from netorch import wired_interface
from netorch.process import OutputLimit, ProcessTimeout, Result
from tests.test_auto_wired_instance import declaration, parsed
from tests.test_macos_preflight import SAMPLES


def setup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight.sys, "platform", "darwin")
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight, "_file_digest", lambda path: "a" * 64)
    monkeypatch.setattr(Path, "iterdir", lambda path: iter(()))
    original = Path.is_file
    monkeypatch.setattr(
        Path,
        "is_file",
        lambda p: False if str(p).endswith("/bin/container") else original(p),
    )


def collect(
    monkeypatch: pytest.MonkeyPatch,
    selector: Any,
    *,
    instance: Any = None,
) -> tuple[dict[str, Any], list[tuple[str, ...]]]:
    setup(monkeypatch)
    expected = ("/usr/bin/perl", str(wired_interface.selector_path()), "198.51.100.10")
    reverse = {argv: key for key, argv in preflight.COMMANDS.items()}
    seen: list[tuple[str, ...]] = []

    def runner(argv: tuple[str, ...], timeout: float) -> Result:
        assert 0 < timeout <= preflight.COMMAND_TIMEOUT
        seen.append(argv)
        if argv == expected:
            if isinstance(selector, Exception):
                raise selector
            return selector
        assert argv != ("/sbin/ifconfig", "auto-wired")
        return Result(0, SAMPLES[reverse[argv]].encode(), b"")

    document = preflight.collect_preflight(
        parsed(declaration()) if instance is None else instance,
        runner=runner,
        clock=lambda: 1000.0,
        monotonic=lambda: 0.0,
    )
    return {row["key"]: row for row in document["facts"]}, seen


def test_auto_preflight_emits_fresh_proof_but_no_mac_from_an_unrelated_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts, seen = collect(monkeypatch, Result(0, b"en108\n", b""))
    assert ("/sbin/ifconfig", "-a") not in seen
    assert seen[-1] == ("/usr/bin/perl", str(wired_interface.selector_path()), "198.51.100.10")
    assert facts["lan_selection"]["value"] == {
        "mode": "auto-wired",
        "interface": "en108",
        "ipv4": "198.51.100.10",
        "selector_sha256": wired_interface.selector_digest(),
    }
    assert facts["lan_interface"]["value"] == "en108"
    assert facts["lan_ipv4"]["value"] == "198.51.100.10"
    assert facts["lan_hardware_id"]["state"] == "unknown"
    assert facts["anchor_order"]["reason"] == "not-checked"


@pytest.mark.parametrize(
    "result,reason",
    [
        (Result(1, b"private topology", b"secret detail"), "malformed"),
        (Result(0, b"en108\n", b"private warning"), "malformed"),
        (Result(0, b"en108\nen109\n", b""), "malformed"),
        (Result(0, b"auto-wired\n", b""), "malformed"),
        (Result(0, b"en108", b""), "malformed"),
        (Result(0, b" en108\n", b""), "malformed"),
        (Result(0, b"en" + b"1" * 100_000 + b"\n", b""), "malformed"),
        (ProcessTimeout("private timeout"), "timed-out"),
        (OutputLimit("private output"), "malformed"),
        (PermissionError("private privilege"), "inaccessible"),
    ],
)
def test_native_selection_failure_never_falls_back_or_leaks_output(
    monkeypatch: pytest.MonkeyPatch,
    result: object,
    reason: str,
) -> None:
    facts, seen = collect(monkeypatch, result)
    for key in ("lan_selection", "lan_interface", "lan_ipv4", "lan_hardware_id"):
        assert facts[key]["state"] == "unknown"
        assert facts[key]["reason"] == reason
    assert "private" not in json.dumps(facts)
    assert "secret" not in json.dumps(facts)
    assert ("/sbin/ifconfig", "-a") not in seen


def test_selector_uses_remaining_total_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    setup(monkeypatch)
    now = [0.0]
    calls: list[tuple[tuple[str, ...], float]] = []
    reverse = {argv: key for key, argv in preflight.COMMANDS.items()}

    def runner(argv: tuple[str, ...], timeout: float) -> Result:
        calls.append((argv, timeout))
        if argv[0] == "/usr/bin/perl":
            return Result(0, b"en108\n", b"")
        if reverse[argv] == "internet_sharing":
            now[0] = preflight.TOTAL_TIMEOUT - 0.25
        return Result(0, SAMPLES[reverse[argv]].encode(), b"")

    preflight.collect_preflight(parsed(declaration()), runner=runner, monotonic=lambda: now[0])
    assert calls[-1][1] == 0.25


def test_expired_total_budget_and_unsupported_host_do_not_run_selector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup(monkeypatch)

    def forbidden(argv: tuple[str, ...], timeout: float) -> Result:
        raise AssertionError("unexpected native command")

    ticks = iter([0.0, *([preflight.TOTAL_TIMEOUT + 1] * 30)])
    document = preflight.collect_preflight(
        parsed(declaration()),
        runner=forbidden,
        monotonic=lambda: next(ticks),
    )
    facts = {f["key"]: f for f in document["facts"]}
    assert facts["lan_selection"]["reason"] == "timed-out"
    monkeypatch.setattr(preflight.sys, "platform", "unsupported-test")
    document = preflight.collect_preflight(parsed(declaration()), runner=forbidden)
    assert (
        next(f for f in document["facts"] if f["key"] == "lan_selection")["reason"] == "unsupported"
    )


def test_observation_refuses_selector_resource_change(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = iter([b"reviewed code", b"different code"])
    monkeypatch.setattr(wired_interface, "read_data", lambda path: next(calls))
    with pytest.raises(ValueError, match="changed"):
        wired_interface.observe(
            "192.0.2.10", runner=lambda argv, timeout: Result(0, b"en1\n", b""), timeout=1
        )


@pytest.mark.parametrize("address", ["0.0.0.0", "127.0.0.1", "224.0.0.1", "192.0.2.010", "bad"])
def test_invalid_selection_address_never_executes_a_command(address: str) -> None:
    def forbidden(argv: tuple[str, ...], timeout: float) -> Result:
        raise AssertionError("unexpected native command")

    with pytest.raises(ValueError, match="canonical"):
        wired_interface.observe(address, runner=forbidden, timeout=1)


def test_packaged_selector_is_preferred_and_missing_resource_is_not_downloaded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    package = tmp_path / "netorch"
    helper = package / wired_interface.RESOURCE
    helper.parent.mkdir(parents=True)
    helper.write_text("# installed fixture")
    monkeypatch.setattr(wired_interface.resources, "files", lambda name: package)
    assert wired_interface.selector_path() == helper
    helper.unlink()
    monkeypatch.setattr(Path, "is_file", lambda path: False)
    with pytest.raises(FileNotFoundError, match="unavailable"):
        wired_interface.selector_path()

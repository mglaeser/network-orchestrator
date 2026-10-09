"""Replay captured native facts through collection and host reports, offline.

The raw macOS replies are recorded; filesystem availability and the example
instance are deliberate test inputs. No replay confers production qualification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from netorch import host_cli
from netorch import macos_preflight as preflight
from netorch.host_report import parse_host_evidence
from netorch.process import Result
from tests.recorded import load_recording

ROOT = Path(__file__).resolve().parents[1]
STAMP = 1_800_000_000.0


@pytest.mark.parametrize(
    "key,expected",
    [
        ("macos_version", "27.0.1"),
        ("macos_build", "26A434"),
        ("architecture", "apple-silicon"),
        ("hardware_model", "MacExample1,1"),
        ("filevault", "off"),
        ("automatic_login", True),
        ("application_firewall", True),
        ("network_extensions", ["example.extension.1", "example.extension.2"]),
        ("proxies", False),
    ],
)
def test_recorded_native_fact_parser(key: str, expected: object) -> None:
    record = load_recording("preflight", key.replace("_", "-"))
    assert record.returncode == 0 and record.stderr == b""
    assert preflight._parse(key, record.stdout.decode().strip()) == expected


@pytest.mark.parametrize("key", ["power_restart", "vpns", "internet_sharing"])
def test_successful_native_command_can_still_leave_a_fact_unproven(key: str) -> None:
    record = load_recording("preflight", key.replace("_", "-"))
    assert record.returncode == 0
    # These successful real replies lack an independently decisive value.
    # Never turn an empty or unavailable preference into a healthy default.
    with pytest.raises(preflight.IncompleteFact):
        preflight._parse(key, record.stdout.decode().strip())


def replay(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    records = {
        argv: load_recording("preflight", key.replace("_", "-"))
        for key, argv in preflight.COMMANDS.items()
        if key != "interfaces"
    }
    # Explicitly a single recorded interface excerpt, not a full host inventory.
    records[preflight.COMMANDS["interfaces"]] = load_recording("packet", "native-lan-interface")
    runtime = ("/usr/local/bin/container", "--version")
    records[runtime] = load_recording("preflight", "container-version")
    seen: list[tuple[str, ...]] = []

    def runner(argv: tuple[str, ...], timeout: float) -> Result:
        assert 0 < timeout <= preflight.COMMAND_TIMEOUT
        seen.append(argv)
        record = records[argv]  # any unexpected command fails the replay
        assert record.returncode is not None
        return Result(record.returncode, record.stdout, record.stderr)

    def unread_disk(path: Path) -> str:
        raise PermissionError("synthetic refusal: no disk baseline was recorded")

    with monkeypatch.context() as patch:
        patch.setattr(preflight.os, "geteuid", lambda: 501)
        patch.setattr(preflight.sys, "platform", "darwin")
        patch.setattr(Path, "is_file", lambda path: path == Path(runtime[0]))
        patch.setattr(preflight, "_file_digest", unread_disk)
        document = preflight.collect_preflight(
            {"host": {"lan": {"address": "192.0.2.10"}}},
            runner=runner,
            clock=lambda: STAMP,
            monotonic=lambda: 0.0,
        )
    assert seen == [*preflight.COMMANDS.values(), runtime]
    return document


@pytest.mark.parametrize("command", ["report", "status", "check", "plan"])
def test_recorded_collection_roundtrip_never_qualifies_an_unaccepted_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    document = replay(monkeypatch)
    parsed = parse_host_evidence(document)
    facts = {fact.key: fact for fact in parsed.facts}
    assert facts["runtime_version"].value == "1.2.0"
    assert facts["network_extensions"].value == ["example.extension.1", "example.extension.2"]
    for key in ("power_restart", "vpns", "internet_sharing"):
        assert facts[key].state == "unknown" and facts[key].reason == "incomplete"
    assert facts["pf_baseline_sha256"].state == "unknown"
    assert facts["anchor_order"].reason == "not-checked"
    assert facts["local_network_identity"].reason == "not-checked"
    # Serialized replay stays a real-parser exercise but cannot become new native evidence.
    saved = tmp_path / "replay.json"
    saved.write_text(json.dumps(document))
    monkeypatch.setattr(host_cli.os, "geteuid", lambda: 501)
    result = host_cli.main(
        [command, "--instance", str(ROOT / "examples/instance.json"), "--evidence", str(saved)],
        now=STAMP + 1,
    )
    assert result == (1 if command == "check" else 0)
    report = json.loads(capsys.readouterr().out)
    assert report["mutation_available"] is False
    if command == "plan":
        assert report["actions"] == []
    else:
        assert report["platform"]["candidate_parser_compatible"] is False
        assert report["platform"]["host_accepted"] is False
        assert report.get("fully_served", report.get("passed")) is False


def test_aged_recorded_facts_are_unknown_in_later_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    document = replay(monkeypatch)
    saved = tmp_path / "replay.json"
    saved.write_text(json.dumps(document))
    monkeypatch.setattr(host_cli.os, "geteuid", lambda: 501)
    assert (
        host_cli.main(
            [
                "report",
                "--instance",
                str(ROOT / "examples/instance.json"),
                "--evidence",
                str(saved),
            ],
            now=STAMP + 301,
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert all(fact["state"] == "unknown" for fact in report["facts"])
    assert report["fully_served"] is False

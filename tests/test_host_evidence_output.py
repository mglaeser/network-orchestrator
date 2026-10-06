"""`preflight --collect-local --emit-evidence` prints the document `--evidence` reads.

Every native read is a synthetic response; no test runs a host command.
"""

from __future__ import annotations

import json
import os
import plistlib
import re
import shlex
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from netorch import host_cli
from netorch import macos_preflight as preflight
from netorch.codec import canonical_json
from netorch.host_report import parse_host_evidence
from netorch.process import Result

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
INSTANCE = str(EXAMPLES / "instance.json")
OBSERVED = 1_800_000_000.0
NOW = OBSERVED + 5.0
EMIT = ["preflight", "--collect-local", "--emit-evidence", "--instance", INSTANCE]
DOCUMENT_KEYS = {"schema_version", "source", "observed_at", "facts", "profiles"}

VPN_HEADER = "Available network connection services in the current set (*=enabled):"
VPN_ROW = '* (Disconnected) 00000000-0000-4000-8000-000000000001 VPN "Example" [VPN:example]'
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
    "vpns": VPN_HEADER + "\n" + VPN_ROW,
    "internet_sharing": plistlib.dumps({"NAT": {"Enabled": 0}}).decode(),
    "interfaces": (
        "example0: flags=8863<UP> mtu 1500\n ether 02:00:00:00:00:01\n"
        " inet 198.51.100.10 netmask 0xffffff00\n"
    ),
}
# What the synthetic responses above amount to as facts of the example host.
PRESENT = {
    "macos_version": "27.0.1",
    "macos_build": "26A434",
    "hardware_class": "apple-silicon",
    "hardware_model": "MacExample1,1",
    "filevault": "off",
    "automatic_login": True,
    "power_restart": True,
    "application_firewall": True,
    "network_extensions": [],
    "proxies": False,
    "vpns": False,
    "internet_sharing": False,
    "lan_interface": "example0",
    "lan_hardware_id": "02:00:00:00:00:01",
    "lan_ipv4": "198.51.100.10",
    "pf_baseline_sha256": "a" * 64,
    "pf_anchors": [],
}

Collector = Callable[[Any], dict[str, Any]]


@pytest.fixture(autouse=True)
def unprivileged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 501)


@pytest.fixture
def collected() -> list[dict[str, Any]]:
    """Every document the simulated collector handed to the command."""
    return []


@pytest.fixture
def collector(monkeypatch: pytest.MonkeyPatch, collected: list[dict[str, Any]]) -> Collector:
    """The bundled collector on a simulated Mac: fixed argv in, synthetic text out."""
    reverse = {argv: key for key, argv in preflight.COMMANDS.items()}

    def runner(argv: tuple[str, ...], timeout: float) -> Result:
        return Result(0, SAMPLES[reverse[argv]].encode(), b"")

    def collect(instance: Any) -> dict[str, Any]:
        with monkeypatch.context() as patch:
            patch.setattr(preflight.sys, "platform", "darwin")
            patch.setattr(Path, "is_file", lambda path: False)
            patch.setattr(Path, "iterdir", lambda path: iter(()))
            patch.setattr(preflight, "_file_digest", lambda path: "a" * 64)
            document = preflight.collect_preflight(instance, runner=runner, clock=lambda: OBSERVED)
        collected.append(document)
        return document

    return collect


def schema_errors(document: Any) -> list[str]:
    schema = json.loads((ROOT / "schemas/host-evidence.schema.json").read_bytes())
    return [error.message for error in Draft202012Validator(schema).iter_errors(document)]


def emit(capsys: Any, collector: Collector | None = None, argv: list[str] | None = None) -> str:
    assert host_cli.main(argv or EMIT, collector=collector, now=NOW) == 0
    return str(capsys.readouterr().out)


def test_emitted_output_is_the_collected_evidence_document(
    capsys: Any, collector: Collector, collected: list[dict[str, Any]]
) -> None:
    output = emit(capsys, collector)
    document = json.loads(output)

    assert set(document) == DOCUMENT_KEYS  # the document, not the report view around it
    assert document == collected[0]
    assert output == canonical_json(collected[0]) + "\n"
    assert schema_errors(document) == []
    assert document["source"] == "local-collector"
    present = {
        item["key"]: item["value"] for item in document["facts"] if item["value"] is not None
    }
    assert present == PRESENT
    assert all(item["observed_at"] == OBSERVED for item in document["facts"])
    # What `--evidence` does with a file: the same parser accepts the printed bytes.
    assert parse_host_evidence(output.encode()) == parse_host_evidence(collected[0])


@pytest.mark.parametrize("command", ["status", "report"])
def test_emitted_document_reads_back_as_the_same_facts(
    command: str, tmp_path: Path, capsys: Any, collector: Collector
) -> None:
    saved = tmp_path / "host-evidence.json"
    saved.write_text(emit(capsys, collector))

    assert host_cli.main([command, "--instance", INSTANCE, "--evidence", str(saved)], now=NOW) == 0
    read_back = capsys.readouterr().out
    result = json.loads(read_back)
    assert result["evidence_source"] == "local-collector"
    facts = {item["key"]: item for item in result["facts"]}
    for key, value in PRESENT.items():
        assert facts[key] == {
            "key": key,
            "state": "present",
            "reason": "complete",
            "age_seconds": NOW - OBSERVED,
            "value": value,
        }
    assert (facts["runtime_version"]["state"], facts["runtime_version"]["reason"]) == (
        "unknown",
        "incomplete",
    )
    # Collecting within the same command gives byte for byte the same report.
    assert (
        host_cli.main(
            [command, "--collect-local", "--instance", INSTANCE], collector=collector, now=NOW
        )
        == 0
    )
    assert capsys.readouterr().out == read_back


def test_emitted_document_is_accepted_by_plan(
    tmp_path: Path, capsys: Any, collector: Collector
) -> None:
    saved = tmp_path / "host-evidence.json"
    saved.write_text(emit(capsys, collector))
    assert host_cli.main(["plan", "--instance", INSTANCE, "--evidence", str(saved)], now=NOW) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["actions"] == [] and result["read_only"] and not result["mutation_available"]

    # The report view of the same collection is still not an evidence document.
    saved.write_text(
        emit(capsys, collector, ["preflight", "--collect-local", "--instance", INSTANCE])
    )
    assert host_cli.main(["plan", "--instance", INSTANCE, "--evidence", str(saved)], now=NOW) == 65


def test_document_collected_off_macos_is_valid_and_all_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(preflight.sys, "platform", "linux")
    assert host_cli.main(EMIT) == 0  # the bundled collector and the real clock
    output = capsys.readouterr().out
    document = json.loads(output)

    assert set(document) == DOCUMENT_KEYS and schema_errors(document) == []
    assert all(item["state"] == "unknown" and item["value"] is None for item in document["facts"])
    reasons = {item["key"]: item["reason"] for item in document["facts"]}
    unsupported = {key for key, reason in reasons.items() if reason == "unsupported"}
    native = (set(preflight.COMMANDS) - {"architecture", "interfaces"}) | {"hardware_class"}
    assert unsupported == native | {
        "lan_interface",
        "lan_hardware_id",
        "lan_ipv4",
        "runtime_version",
        "runtime_install_method",
    }
    assert set(reasons.values()) == {"unsupported", "inaccessible", "not-checked"}

    saved = tmp_path / "host-evidence.json"
    saved.write_text(output)
    later = max(item["observed_at"] for item in document["facts"]) + 1.0
    assert (
        host_cli.main(["status", "--instance", INSTANCE, "--evidence", str(saved)], now=later) == 0
    )
    facts = {item["key"]: item for item in json.loads(capsys.readouterr().out)["facts"]}
    assert {key: facts[key]["reason"] for key in reasons} == reasons
    assert all(facts[key]["state"] == "unknown" for key in reasons)


@pytest.mark.parametrize(
    "argv",
    [
        ["validate", "--emit-evidence"],
        ["status", "--emit-evidence"],
        ["status", "--collect-local", "--emit-evidence"],
        ["plan", "--emit-evidence"],
        ["check", "--emit-evidence"],
        ["report", "--emit-evidence"],
        ["report", "--collect-local", "--emit-evidence"],
        ["preflight", "--emit-evidence"],
        ["preflight", "--collect-local", "--emit-evidence", "--evidence", "unused.json"],
    ],
    ids=" ".join,
)
def test_emit_evidence_is_refused_outside_local_preflight(
    argv: list[str], capsys: Any, collector: Collector, collected: list[dict[str, Any]]
) -> None:
    with pytest.raises(SystemExit) as refused:
        host_cli.main([*argv, "--instance", INSTANCE], collector=collector, now=NOW)
    assert refused.value.code == 2
    assert collected == []
    assert capsys.readouterr().out == ""  # a redirect would hold nothing to mistake for evidence


def test_root_is_refused_before_anything_is_collected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
    collector: Collector,
    collected: list[dict[str, Any]],
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert host_cli.main(EMIT, collector=collector, now=NOW) == 77
    refusal = capsys.readouterr().out
    assert collected == [] and "facts" not in json.loads(refusal)

    # Redirected into the evidence file, the refusal is not read as evidence.
    saved = tmp_path / "host-evidence.json"
    saved.write_text(refusal)
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    assert (
        host_cli.main(["status", "--instance", INSTANCE, "--evidence", str(saved)], now=NOW) == 65
    )


@pytest.mark.parametrize("defect", ["extra-member", "unknown-fact", "valued-unknown"])
def test_a_document_the_parser_refuses_is_never_printed(
    defect: str, capsys: Any, collector: Collector
) -> None:
    def broken(instance: Any) -> dict[str, Any]:
        document = collector(instance)
        if defect == "extra-member":
            document["command"] = "example-private-text"
        elif defect == "unknown-fact":
            document["facts"][0]["key"] = "example-private-text"
        else:
            document["facts"][-1]["value"] = "example-private-text"
        return document

    assert host_cli.main(EMIT, collector=broken, now=NOW) == 65
    output = capsys.readouterr().out
    assert json.loads(output) == {
        "read_only": True,
        "mutation_available": False,
        "error": "invalid-or-unavailable-local-data",
    }
    assert "example-private-text" not in output


def test_emitting_evidence_writes_no_file(
    tmp_path: Path, capsys: Any, collector: Collector
) -> None:
    shutil.copytree(EXAMPLES, tmp_path / "data")

    def snapshot() -> dict[str, tuple[bytes, int]]:
        return {
            str(path.relative_to(tmp_path)): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in tmp_path.rglob("*")
            if path.is_file()
        }

    before = snapshot()
    argv = ["preflight", "--collect-local", "--emit-evidence"]
    emit(capsys, collector, [*argv, "--instance", str(tmp_path / "data/instance.json")])
    assert snapshot() == before
    assert sorted(path.name for path in tmp_path.iterdir()) == ["data"]


def test_documented_command_sequence_runs_as_written(
    tmp_path: Path, capsys: Any, collector: Collector
) -> None:
    """The six lines of the instance guide, with its private paths mapped to a lab."""
    guide = (ROOT / "docs/instances.md").read_text(encoding="utf-8")
    block = re.search(r"## Six commands\n.*?```sh\n(.*?)```", guide, re.DOTALL)
    assert block is not None
    lines = block[1].strip().splitlines()
    assert sorted(shlex.split(line)[1] for line in lines) == sorted(host_cli.COMMANDS)

    def lab(word: str) -> str:
        if word == "/private/instance/instance.json":
            return INSTANCE
        if word.startswith("/private/host-state/"):
            return str(tmp_path / Path(word).name)
        assert not word.startswith("/"), word
        return word

    for line in lines:
        program, *words = shlex.split(line)
        assert program == "netorch-host"
        redirected = None
        if ">" in words:
            *words, operator, redirected = words
            assert operator == ">" and redirected.startswith("/private/host-state/")
        code = host_cli.main([lab(word) for word in words], collector=collector, now=NOW)
        output = capsys.readouterr().out
        assert code == (1 if words[0] == "check" else 0), line
        if redirected is not None:
            Path(lab(redirected)).write_text(output)

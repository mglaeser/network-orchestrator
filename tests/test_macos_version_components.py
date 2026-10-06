"""The declared macOS version uses the grammar the local collector emits."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netorch import host_cli
from netorch import macos_preflight as preflight
from netorch.codec import canonical_bytes
from netorch.host_report import build_report, parse_host_evidence
from netorch.instance import InstanceError, instance_to_dict, load_instance, parse_instance

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
NOW = 1000.0
TWO_OR_THREE = ["27.0", "27.1", "27.10", "27.0.1", "27.10.3", "100.0", "9.9.9"]
OTHER = ["27", "27.", ".1", "27..1", "27.0.", "27.0.1.2", "27.x", "v27.1", "27,1", " 27.1", "27.1 "]
TEMPLATE = instance_to_dict(load_instance(EXAMPLES / "instance.json"))


def instance_bytes(version: str) -> bytes:
    platform = TEMPLATE["host"]["platform"] | {"macos_version": version}
    data = TEMPLATE | {"host": TEMPLATE["host"] | {"platform": platform}}
    return canonical_bytes(data) + b"\n"


def declarable(version: str) -> bool:
    try:
        parse_instance(instance_bytes(version))
    except InstanceError:
        return False
    return True


def observable(version: str) -> bool:
    try:
        return bool(preflight._parse("macos_version", version) == version)
    except ValueError:
        return False


@pytest.mark.parametrize("version", TWO_OR_THREE)
def test_instance_declares_a_two_or_three_component_macos_version(version: str) -> None:
    assert parse_instance(instance_bytes(version)).host.platform.macos_version == version


@pytest.mark.parametrize("version", OTHER)
def test_instance_refuses_any_other_number_of_components(version: str) -> None:
    with pytest.raises(InstanceError):
        parse_instance(instance_bytes(version))


@pytest.mark.parametrize("version", TWO_OR_THREE)
def test_collector_reports_a_two_or_three_component_macos_version(version: str) -> None:
    assert preflight._parse("macos_version", version) == version


@pytest.mark.parametrize("version", [*OTHER, ""])
def test_collector_refuses_any_other_number_of_components(version: str) -> None:
    with pytest.raises(ValueError):
        preflight._parse("macos_version", version)


@given(st.from_regex(r"[0-9]{1,3}(\.[0-9]{0,3}){0,4}", fullmatch=True))
def test_collector_and_instance_share_one_numeric_grammar(version: str) -> None:
    assert declarable(version) == observable(version)
    assert observable(version) == bool(re.fullmatch(r"[0-9]+\.[0-9]+(\.[0-9]+)?", version))


def test_host_command_validates_an_instance_with_a_two_component_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    path = tmp_path / "instance.json"
    path.write_bytes(instance_bytes("27.1"))
    arguments = ["validate", "--instance", str(path), "--data-dir", str(EXAMPLES)]
    code = host_cli.main(arguments, now=NOW)
    result = json.loads(capsys.readouterr().out)
    assert code == 0, result
    assert result["valid"] is True


def test_two_component_version_does_not_widen_platform_acceptance() -> None:
    # Declaring what the system prints must stay possible; it qualifies nothing.
    instance = parse_instance(instance_bytes("27.1"))
    facts: list[dict[str, Any]] = [
        {"key": key, "state": "present", "reason": "complete", "observed_at": NOW, "value": value}
        for key, value in (
            ("macos_version", "27.1"),
            ("macos_build", "26B100"),
            ("runtime_version", "1.5.0"),
            ("hardware_class", "apple-silicon"),
        )
    ]
    evidence = parse_host_evidence(
        {
            "schema_version": 1,
            "source": "local-collector",
            "observed_at": NOW,
            "facts": facts,
            "profiles": [],
        }
    )
    report = build_report(instance, evidence, now=NOW, data_directory=EXAMPLES)
    row = next(item for item in report["requirements"] if item["id"] == "PLATFORM-SUPPORT")
    assert row["status"] == "not-fulfilled"
    assert report["platform"] == {
        "candidate_parser_compatible": False,
        "host_accepted": False,
        "mutation_qualified": False,
    }
    assert report["fully_served"] is False

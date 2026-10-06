"""`check` can pass once the shipped matrix lists the platform; today it never does.

The shipped matrix is empty and stays empty. Each test that expects a pass puts
a matrix in place for that test only, so the positive result is exercised
without declaring any platform supported.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import netorch
from netorch import host_cli, host_report
from netorch.codec import canonical_bytes
from netorch.host_report import build_report, parse_host_evidence
from netorch.instance import (
    instance_contract_digest,
    parse_instance,
    resolved_discovery_digest,
    resolved_profile_digest,
)
from netorch.platform_contract import ACCEPTED_PLATFORMS
from netorch.requirements import REQUIREMENTS

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
NOW = 1_800_000_000.0
RECORDED = "2026-12-01T00:00:00Z"
SERVED = {"fulfilled-verified", "accepted-residual", "not-applicable"}
CONTEXTS = {
    "root-runtime-observer": "root-launchdaemon",
    "local-network-consent": "user-launchagent",
}


def parsed(data: dict[str, Any]) -> Any:
    return parse_instance(canonical_bytes(data) + b"\n")


def triple(data: dict[str, Any]) -> tuple[str, str, str]:
    host = data["host"]
    return (
        host["platform"]["macos_version"],
        host["platform"]["macos_build"],
        host["runtime"]["version"],
    )


def attest(
    data: dict[str, Any],
    records: Path,
    identifier: str,
    profile: str | None = None,
    *,
    context: str | None = None,
    instance: Any = None,
) -> None:
    """Append a ledger entry at the registered method and tier, with its retained record.

    The ledger is outside every digest, so one parsed ``instance`` serves many entries.
    """
    registered = next(item for item in REQUIREMENTS if item.id == identifier)
    method = registered.acceptance_methods[0]
    instance = instance or parsed(data)
    digest = instance_contract_digest(instance)
    if profile is not None:
        transport = next((item for item in instance.transport if item.id == profile), None)
        digest = (
            resolved_profile_digest(instance, transport)
            if transport is not None
            else resolved_discovery_digest(
                instance, next(item for item in instance.discovery if item.id == profile)
            )
        )
    entry = {
        "requirement": identifier,
        "instance_schema_version": 1,
        "profile": profile,
        "method": method,
        "tier": registered.minimum_tier,
        "observed_at": RECORDED,
        "macos_build": instance.host.platform.macos_build,
        "runtime_version": instance.host.runtime.version,
        "framework_sha256": instance.framework.artifact_sha256,
        "contract_sha256": digest,
        "signed_by": "example-reviewer",
    }
    raw = (
        canonical_bytes(
            {
                **entry,
                "schema_version": 1,
                "kind": "native-capture",
                "capture_context": context or CONTEXTS.get(method, "macos-userspace"),
                "result": "passed",
                "source_versions": ["container-" + instance.host.runtime.version],
            }
        )
        + b"\n"
    )
    entry["evidence_sha256"] = hashlib.sha256(raw).hexdigest()
    (records / (entry["evidence_sha256"] + ".json")).write_bytes(raw)
    data["acceptance"].append(entry)


def retract(data: dict[str, Any], identifier: str) -> None:
    data["acceptance"] = [item for item in data["acceptance"] if item["requirement"] != identifier]


def observations(data: dict[str, Any]) -> dict[str, Any]:
    """Owner-reported evidence in which every declared row is current and consistent."""
    instance = parsed(data)
    seen = {
        "state": "present",
        "reason": "complete",
        "observed_at": NOW,
        "generation": "example-generation",
    }
    digests = [
        *((item.id, resolved_profile_digest(instance, item)) for item in instance.transport),
        *((item.id, resolved_discovery_digest(instance, item)) for item in instance.discovery),
    ]
    facts = {
        "macos_version": instance.host.platform.macos_version,
        "macos_build": instance.host.platform.macos_build,
        "runtime_version": instance.host.runtime.version,
        "hardware_class": "apple-silicon",
        "filevault": "off",
        "local_network_identity": "example-identity",
        "lan_hardware_id": instance.host.lan.hardware_id,
        "lan_ipv4": instance.host.lan.ipv4,
    }
    return {
        "schema_version": 1,
        "source": "owner-snapshot",
        "observed_at": NOW,
        "facts": [
            {
                "key": key,
                "state": "present",
                "reason": "complete",
                "observed_at": NOW,
                "value": value,
            }
            for key, value in facts.items()
        ],
        "profiles": [
            {
                "id": identifier,
                "desired_digest": digest,
                "admitted_digest": digest,
                "applied_digest": digest,
                "paused": False,
                "suspensions": [],
                **{
                    key: dict(seen)
                    for key in ("transport", "discovery", "probe", "application", "heard_audio")
                },
            }
            for identifier, digest in digests
        ],
        "workloads": [{"id": item.id, "observation": dict(seen)} for item in instance.workloads],
    }


@pytest.fixture
def host(tmp_path: Path) -> SimpleNamespace:
    """The structural example with a real release pin and every applicable row proven.

    Nothing here says the platform is supported: that is the matrix alone.
    """
    shutil.copytree(EXAMPLES / "contracts", tmp_path / "contracts")
    records = tmp_path / "records"
    records.mkdir()
    artifact = tmp_path / "artifact.whl"
    artifact.write_bytes(b"example immutable wheel")
    lock = tmp_path / "lock.json"
    lock.write_bytes(b"example dependency lock")

    data = json.loads((EXAMPLES / "instance-structural.json").read_bytes())
    data["framework"].update(
        version=netorch.__version__,
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        dependency_lock_sha256=hashlib.sha256(lock.read_bytes()).hexdigest(),
    )
    data["host"]["baseline"]["filevault"] = False
    data["decisions"]["unattended_recovery"] = {"accepted": True, "max_dns_ready_seconds": 120}
    data["decisions"]["lifecycle_control"] = {
        "residual": "The supervisor can start and stop workloads through the container API.",
        "signed_by": "Example Owner",
        "signed_at": "1970-01-01T00:00:01Z",
    }
    data["lifecycle_tools"].append(
        {
            "id": "example-supervisor",
            "kind": "supervisor",
            "container_api_access": True,
            "starts_runtime": True,
            "starts_fleet": True,
            "version": None,
        }
    )

    # Every declared setting above is final before anything is attested against it.
    instance = parsed(data)
    exports = [item.id for item in instance.discovery if item.direction == "export"]
    per_profile = {
        "transport": [item.id for item in instance.transport],
        "discovery": [item.id for item in instance.discovery],
        "exports": exports,
    }
    assert exports == per_profile["discovery"] and len(instance.transport) == 1
    document = observations(data)
    unproven = build_report(
        instance, parse_host_evidence(document), now=NOW, data_directory=tmp_path
    )
    for row in unproven["requirements"]:
        if row["status"] in SERVED:
            continue
        registered = next(item for item in REQUIREMENTS if item.id == row["id"])
        for profile in per_profile.get(registered.applicability, [None]):
            attest(data, records, row["id"], profile, instance=instance)
    return SimpleNamespace(
        data=data,
        document=document,
        directory=tmp_path,
        records=records,
        artifact=artifact,
        lock=lock,
    )


def report(host: SimpleNamespace, *, release_verified: bool = True) -> dict[str, Any]:
    return build_report(
        parsed(host.data),
        parse_host_evidence(host.document),
        now=NOW,
        data_directory=host.directory,
        release_verified=release_verified,
        evidence_directory=host.records,
    )


def open_rows(result: dict[str, Any]) -> list[str]:
    return [row["id"] for row in result["requirements"] if row["status"] not in SERVED]


def list_platform(monkeypatch: pytest.MonkeyPatch, *platforms: tuple[str, str, str]) -> None:
    monkeypatch.setattr(host_report, "ACCEPTED_PLATFORMS", platforms)


def test_shipped_matrix_is_empty_and_only_the_platform_row_stays_open(
    host: SimpleNamespace,
) -> None:
    assert ACCEPTED_PLATFORMS == ()
    result = report(host)
    assert result["current_ready"]
    assert open_rows(result) == ["PLATFORM-SUPPORT"]
    assert result["platform"] == {
        "candidate_parser_compatible": True,
        "host_accepted": False,
        "mutation_qualified": False,
    }
    assert not result["fully_served"]


def test_listed_platform_with_its_host_record_is_fully_served(
    host: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    list_platform(monkeypatch, triple(host.data))
    result = report(host)
    assert open_rows(result) == []
    assert result["fully_served"] and result["current_ready"]
    # Accepted is not qualified for mutation: this release has no such state.
    assert result["platform"] == {
        "candidate_parser_compatible": True,
        "host_accepted": True,
        "mutation_qualified": False,
    }
    assert result["read_only"] and not result["mutation_available"]


@pytest.mark.parametrize(
    "missing",
    [
        "platform-record",
        "root-daemon-context",
        "listed-triple",
        "apple-silicon",
        "deviation",
        "another-record",
        "release",
        "current-profile",
        "owner-evidence",
    ],
)
def test_every_part_of_the_positive_result_is_required(
    host: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    listed = triple(host.data)
    release_verified = True
    accepted = False
    if missing == "platform-record":
        retract(host.data, "PLATFORM-SUPPORT")
    elif missing == "root-daemon-context":
        retract(host.data, "PLATFORM-SUPPORT")
        attest(host.data, host.records, "PLATFORM-SUPPORT", context="macos-userspace")
    elif missing == "listed-triple":
        listed = (listed[0], listed[1], "1.4.0")
    elif missing == "apple-silicon":
        fact = next(item for item in host.document["facts"] if item["key"] == "hardware_class")
        fact["value"] = "intel"
    elif missing == "deviation":
        host.data["deviations"].append(
            {
                "id": "example-deviation",
                "requirement": "PLATFORM-SUPPORT",
                "statement": "Reviewed and signed instead of proven.",
                "accepted_by": "example-reviewer",
                "accepted_at": RECORDED,
            }
        )
    else:
        accepted = True  # the platform itself is accepted; something else is missing
        if missing == "another-record":
            retract(host.data, "RESTORE-REHEARSAL")
        elif missing == "release":
            release_verified = False
        elif missing == "current-profile":
            host.document["profiles"][0]["paused"] = True
        else:
            host.document["source"] = "synthetic"
            accepted = False  # a synthetic source proves no record at all
    list_platform(monkeypatch, listed)
    result = report(host, release_verified=release_verified)
    assert result["platform"]["host_accepted"] is accepted
    assert not result["fully_served"]


def test_check_exits_zero_only_for_a_fully_served_host(
    host: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    instance = host.directory / "instance.json"
    instance.write_bytes(canonical_bytes(host.data) + b"\n")
    evidence = host.directory / "host-evidence.json"
    evidence.write_bytes(canonical_bytes(host.document) + b"\n")
    argv = [
        "check",
        "--instance",
        str(instance),
        "--evidence",
        str(evidence),
        "--evidence-dir",
        str(host.records),
        "--framework-artifact",
        str(host.artifact),
        "--dependency-lock",
        str(host.lock),
    ]
    monkeypatch.setattr(os, "geteuid", lambda: 501)

    assert host_cli.main(argv, now=NOW) == 1  # the shipped matrix
    result = json.loads(capsys.readouterr().out)
    assert not result["passed"] and not result["platform"]["host_accepted"]

    list_platform(monkeypatch, triple(host.data))
    assert host_cli.main(argv, now=NOW) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["passed"] and result["platform"]["host_accepted"]
    assert not result["platform"]["mutation_qualified"] and not result["mutation_available"]
    assert all(row["status"] in SERVED for row in result["requirements"])

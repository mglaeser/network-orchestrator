"""Missing, stale or negative knowledge never improves a requirement row."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from netorch.codec import canonical_bytes
from netorch.host_report import build_report, parse_host_evidence
from netorch.instance import (
    instance_contract_digest,
    parse_instance,
    resolved_discovery_digest,
    resolved_profile_digest,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
NOW = 1000.0
STALE = NOW - 301
FUTURE = NOW + 1
SIGNED = "1970-01-01T00:15:00Z"
LATER = "1970-01-01T01:00:00Z"


@pytest.fixture
def data() -> dict[str, Any]:
    return json.loads((EXAMPLES / "instance.json").read_bytes())


def parsed(data: dict[str, Any]) -> Any:
    return parse_instance(canonical_bytes(data) + b"\n")


def fact(key: str, value: Any, *, state: str = "present", at: float = NOW) -> dict[str, Any]:
    return {"key": key, "state": state, "reason": "complete", "observed_at": at, "value": value}


def platform() -> list[dict[str, Any]]:
    return [fact("macos_build", "26A434"), fact("runtime_version", "1.5.0")]


def report(
    data: dict[str, Any], facts: list[dict[str, Any]] | None = None, **kwargs: Any
) -> dict[str, Any]:
    evidence = parse_host_evidence(
        {
            "schema_version": 1,
            "source": "owner-snapshot",
            "observed_at": NOW,
            "facts": facts or [],
            "profiles": [],
        }
    )
    return build_report(parsed(data), evidence, now=NOW, data_directory=EXAMPLES, **kwargs)


def row(result: dict[str, Any], identifier: str) -> dict[str, Any]:
    return next(item for item in result["requirements"] if item["id"] == identifier)


def status(result: dict[str, Any], identifier: str) -> str:
    return str(row(result, identifier)["status"])


def attest(
    data: dict[str, Any],
    directory: Path,
    requirement: str,
    method: str,
    tier: int,
    profile: str | None = None,
) -> None:
    """Append a ledger entry and write its content-addressed owner attestation."""
    instance = parsed(data)
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
        "requirement": requirement,
        "instance_schema_version": 1,
        "profile": profile,
        "method": method,
        "tier": tier,
        "observed_at": SIGNED,
        "macos_build": "26A434",
        "runtime_version": "1.5.0",
        "framework_sha256": instance.framework.artifact_sha256,
        "contract_sha256": digest,
        "signed_by": "example-reviewer",
    }
    raw = (
        canonical_bytes(
            {
                **entry,
                "schema_version": 1,
                "kind": "owner-attestation",
                "capture_context": "macos-userspace",
                "result": "passed",
                "source_versions": ["container-1.5.0"],
            }
        )
        + b"\n"
    )
    entry["evidence_sha256"] = hashlib.sha256(raw).hexdigest()
    (directory / (entry["evidence_sha256"] + ".json")).write_bytes(raw)
    data["acceptance"].append(entry)


def deviation(
    requirement: str,
    *,
    accepted_by: str | None = "example-reviewer",
    accepted_at: str | None = SIGNED,
    identifier: str = "example-deviation",
) -> dict[str, Any]:
    return {
        "id": identifier,
        "requirement": requirement,
        "statement": "Example statement of a known deviation.",
        "accepted_by": accepted_by,
        "accepted_at": accepted_at,
    }


def accept_unattended_recovery(data: dict[str, Any]) -> None:
    data["decisions"]["unattended_recovery"] = {"accepted": True, "max_dns_ready_seconds": 60}


@pytest.mark.parametrize("observed_at", [NOW, STALE, FUTURE])
def test_reported_filevault_on_blocks_unattended_recovery_at_any_age(
    tmp_path: Path, data: dict[str, Any], observed_at: float
) -> None:
    accept_unattended_recovery(data)
    attest(data, tmp_path, "BOOT-RECOVERY", "unattended-reboot", 4)
    facts = [*platform(), fact("filevault", "on", at=observed_at)]
    result = report(data, facts, evidence_directory=tmp_path)
    assert status(result, "BOOT-RECOVERY") == "not-fulfilled"


def test_unobserved_and_undeclared_filevault_is_not_fulfilled(data: dict[str, Any]) -> None:
    accept_unattended_recovery(data)
    assert data["host"]["baseline"]["filevault"] is None
    assert status(report(data), "BOOT-RECOVERY") == "not-fulfilled"
    stale_off = [fact("filevault", "off", at=STALE)]
    assert status(report(data, stale_off), "BOOT-RECOVERY") == "not-fulfilled"


@pytest.mark.parametrize(
    ("declared", "expected"), [(True, "not-fulfilled"), (False, "fulfilled-unverified")]
)
def test_declared_filevault_baseline_decides_without_a_current_observation(
    data: dict[str, Any], declared: bool, expected: str
) -> None:
    accept_unattended_recovery(data)
    data["host"]["baseline"]["filevault"] = declared
    assert status(report(data), "BOOT-RECOVERY") == expected
    unknown = [fact("filevault", None, state="unknown")]
    assert status(report(data, unknown), "BOOT-RECOVERY") == expected


def test_reported_filevault_on_outranks_a_declared_off_baseline(data: dict[str, Any]) -> None:
    accept_unattended_recovery(data)
    data["host"]["baseline"]["filevault"] = False
    stale_on = [fact("filevault", "on", at=STALE)]
    assert status(report(data, stale_on), "BOOT-RECOVERY") == "not-fulfilled"


def test_current_filevault_off_observation_keeps_the_row_unverified(data: dict[str, Any]) -> None:
    accept_unattended_recovery(data)
    data["host"]["baseline"]["filevault"] = True
    current_off = [fact("filevault", "off")]
    assert status(report(data, current_off), "BOOT-RECOVERY") == "fulfilled-unverified"


NEGATIVE = [
    ("recovery_material", "RESTORE-REHEARSAL"),
    ("owner_conformance", "OWNER-CONFORMANCE"),
    ("names_preserved", "NAMES-PRESERVED"),
    ("instance_literal_check", "HOST-DATA"),
    ("framework_literal_check", "HOST-DATA"),
]


@pytest.mark.parametrize(("key", "requirement"), NEGATIVE)
@pytest.mark.parametrize("variant", ["absent", "stale-absent", "false", "stale-false"])
def test_reported_negative_fact_keeps_its_requirement_not_fulfilled(
    data: dict[str, Any], key: str, requirement: str, variant: str
) -> None:
    observed_at = STALE if variant.startswith("stale") else NOW
    negative = (
        fact(key, None, state="absent", at=observed_at)
        if variant.endswith("absent")
        else fact(key, False, at=observed_at)
    )
    result = report(data, [negative])
    assert status(result, requirement) == "not-fulfilled"
    assert "absent" in row(result, requirement)["reason"]


@pytest.mark.parametrize(("key", "requirement"), NEGATIVE)
def test_positive_or_missing_fact_leaves_the_declared_row_unchanged(
    data: dict[str, Any], key: str, requirement: str
) -> None:
    assert status(report(data), requirement) == "fulfilled-unverified"
    assert status(report(data, [fact(key, True)]), requirement) == "fulfilled-unverified"
    unknown = [fact(key, None, state="unknown")]
    assert status(report(data, unknown), requirement) == "fulfilled-unverified"


def test_acceptance_record_does_not_override_a_negative_fact(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    attest(data, tmp_path, "RESTORE-REHEARSAL", "restore-rehearsal", 4)
    verified = report(data, platform(), evidence_directory=tmp_path)
    assert status(verified, "RESTORE-REHEARSAL") == "fulfilled-verified"
    facts = [*platform(), fact("recovery_material", None, state="absent", at=STALE)]
    blocked = report(data, facts, evidence_directory=tmp_path)
    assert status(blocked, "RESTORE-REHEARSAL") == "not-fulfilled"


@pytest.mark.parametrize("release_verified", [True, False])
@pytest.mark.parametrize("observed_at", [NOW, STALE])
def test_release_pin_is_not_fulfilled_against_a_different_installed_artifact(
    data: dict[str, Any], release_verified: bool, observed_at: float
) -> None:
    other = [fact("installed_framework_sha256", "f" * 64, at=observed_at)]
    result = report(data, other, release_verified=release_verified)
    assert status(result, "FRAMEWORK-PIN") == "not-fulfilled"


def test_release_pin_stays_verified_for_the_pinned_installed_artifact(
    data: dict[str, Any],
) -> None:
    same = [fact("installed_framework_sha256", data["framework"]["artifact_sha256"])]
    assert status(report(data, same, release_verified=True), "FRAMEWORK-PIN") == (
        "fulfilled-verified"
    )
    assert status(report(data, same), "FRAMEWORK-PIN") == "fulfilled-unverified"
    unknown = [fact("installed_framework_sha256", None, state="unknown")]
    assert status(report(data, unknown, release_verified=True), "FRAMEWORK-PIN") == (
        "fulfilled-verified"
    )


def test_instance_wide_record_never_satisfies_a_per_profile_requirement(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    attest(data, tmp_path, "DISCOVERY-IMPORT", "cold-application-scan", 5)
    result = report(data, platform(), evidence_directory=tmp_path)
    assert status(result, "DISCOVERY-IMPORT") == "fulfilled-unverified"
    attest(data, tmp_path, "DISCOVERY-IMPORT", "cold-application-scan", 5, "example-import")
    result = report(data, platform(), evidence_directory=tmp_path)
    assert status(result, "DISCOVERY-IMPORT") == "fulfilled-verified"


def test_instance_wide_record_still_satisfies_an_instance_wide_requirement(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    attest(data, tmp_path, "RESTORE-REHEARSAL", "restore-rehearsal", 4)
    result = report(data, platform(), evidence_directory=tmp_path)
    assert status(result, "RESTORE-REHEARSAL") == "fulfilled-verified"


@pytest.mark.parametrize(
    "record",
    [
        deviation("HEARD-AUDIO", accepted_by=None, accepted_at=None),
        deviation("HEARD-AUDIO", accepted_at=LATER),
        deviation("HEARD-AUDIO", accepted_by=" "),
        deviation("NO-LOCAL-NETWORK", accepted_by=None, accepted_at=None),
    ],
)
def test_unaccepted_deviation_makes_its_row_not_fulfilled(
    data: dict[str, Any], record: dict[str, Any]
) -> None:
    before = status(report(data), record["requirement"])
    assert before in {"fulfilled-unverified", "fulfilled-verified"}
    data["deviations"].append(record)
    result = report(data)
    assert status(result, record["requirement"]) == "not-fulfilled"
    assert "deviation" in row(result, record["requirement"])["reason"]


@pytest.mark.parametrize(
    ("requirement", "expected"),
    [
        ("NAMES-PRESERVED", "accepted-residual"),
        ("HEARD-AUDIO", "not-fulfilled"),
        ("NO-LOCAL-NETWORK", "not-fulfilled"),
    ],
)
def test_accepted_deviation_respects_the_requirement_gate(
    data: dict[str, Any], requirement: str, expected: str
) -> None:
    data["deviations"].append(deviation(requirement))
    result = report(data)
    assert status(result, requirement) == expected
    assert "deviation" in row(result, requirement)["reason"]


def test_accepted_deviation_cannot_replace_the_restore_gate(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    attest(data, tmp_path, "RESTORE-REHEARSAL", "restore-rehearsal", 4)
    verified = report(data, platform(), evidence_directory=tmp_path)
    assert status(verified, "RESTORE-REHEARSAL") == "fulfilled-verified"
    data["deviations"].append(deviation("RESTORE-REHEARSAL"))
    result = report(data, platform(), evidence_directory=tmp_path)
    assert status(result, "RESTORE-REHEARSAL") == "not-fulfilled"


def test_accepted_deviation_does_not_lift_a_row_that_is_not_fulfilled(
    data: dict[str, Any],
) -> None:
    before = row(report(data), "LAN-IDENTITY")
    assert before["status"] == "not-fulfilled"
    data["deviations"].append(deviation("LAN-IDENTITY"))
    assert row(report(data), "LAN-IDENTITY") == before


def test_one_unaccepted_deviation_outweighs_an_accepted_one(data: dict[str, Any]) -> None:
    data["deviations"].append(deviation("NAMES-PRESERVED"))
    data["deviations"].append(
        deviation(
            "NAMES-PRESERVED", accepted_by=None, accepted_at=None, identifier="example-second"
        )
    )
    assert status(report(data), "NAMES-PRESERVED") == "not-fulfilled"


def test_deviation_changes_only_its_own_applicable_row(data: dict[str, Any]) -> None:
    before = {item["id"]: item["status"] for item in report(data)["requirements"]}
    assert before["DNS-CLIENT-IDENTITY"] == "not-applicable"
    changed = copy.deepcopy(data)
    changed["deviations"].append(
        deviation("DNS-CLIENT-IDENTITY", accepted_by=None, accepted_at=None)
    )
    changed["deviations"].append(deviation("NAMES-PRESERVED", identifier="example-second"))
    after = {item["id"]: item["status"] for item in report(changed)["requirements"]}
    assert after == {**before, "NAMES-PRESERVED": "accepted-residual"}


@pytest.mark.parametrize(
    "requirement",
    [
        "BOUNDED-IDENTITY",
        "PLATFORM-SUPPORT",
        "SOURCE-AUTHORSHIP",
        "OWNER-CONFORMANCE",
        "ROOT-ADMISSION",
        "ROOT-HARD-BOUNDS",
        "ROOT-INDEPENDENCE",
        "PAUSE-PRESERVED",
        "UNKNOWN-NO-RECOVERY",
        "RESTORE-REHEARSAL",
        "NO-LOCAL-NETWORK",
        "CURRENT-OBSERVATIONS",
        "DISCOVERY-PUBLICATION",
        "DISCOVERY-IMPORT",
        "DISCOVERY-LEASES",
        "CONSENT-IDENTITY",
        "UDP-FIRST-PACKET",
        "DNS-CLIENT-IDENTITY",
        "HEARD-AUDIO",
        "MULTI-RECEIVER",
        "BOOT-RECOVERY",
        "OWNER-ROLLBACK",
        "PORT-BUDGET",
    ],
)
def test_generic_deviation_cannot_replace_mandatory_qualification_or_provenance(
    data: dict[str, Any], requirement: str
) -> None:
    data["workloads"][0]["application_profile"] = "resolver"
    accept_unattended_recovery(data)
    data["host"]["baseline"]["filevault"] = False
    data["decisions"]["bounded"] = [
        {
            "profile": "example-return",
            "max_age_seconds": 30,
            "unknown_limit": 1,
            "residual": "Example statement of the remaining address-reuse risk.",
            "signed_by": "example-reviewer",
            "signed_at": SIGNED,
        }
    ]
    facts = [
        *platform(),
        fact("macos_version", "27.0.1"),
        fact("hardware_class", "apple-silicon"),
        fact("local_network_identity", "example-identity"),
    ]
    assert status(report(data, facts), requirement) in {
        "fulfilled-unverified",
        "fulfilled-verified",
    }
    data["deviations"].append(deviation(requirement))
    result = report(data, facts)
    assert status(result, requirement) == "not-fulfilled"
    assert not result["fully_served"] and not result["platform"]["host_accepted"]

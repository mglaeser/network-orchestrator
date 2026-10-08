"""All seven host commands are offline/read-only; recorded proof is not live authority."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest

from netorch import host_cli
from netorch.codec import canonical_bytes
from netorch.host_report import (
    Fact,
    HostEvidence,
    Observation,
    build_report,
    empty_evidence,
    evidence_to_dict,
    fact_view,
    observation_view,
    parse_host_evidence,
    verify_contracts,
)
from netorch.instance import (
    InstanceError,
    instance_contract_digest,
    load_instance,
    parse_instance,
    resolved_discovery_digest,
    resolved_profile_digest,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
NOW = 1000.0


@pytest.fixture
def data() -> dict[str, Any]:
    return json.loads((EXAMPLES / "instance.json").read_bytes())


def parsed(data: dict[str, Any]) -> Any:
    return parse_instance(canonical_bytes(data) + b"\n")


def evidence_dict(source: str = "owner-snapshot") -> dict[str, Any]:
    return {"schema_version": 1, "source": source, "observed_at": NOW, "facts": [], "profiles": []}


def platform_evidence(source: str = "owner-snapshot") -> dict[str, Any]:
    data = evidence_dict(source)
    data["facts"] = [
        {"key": key, "state": "present", "reason": "complete", "observed_at": NOW, "value": value}
        for key, value in [
            ("macos_version", "27.0.1"),
            ("macos_build", "26A434"),
            ("runtime_version", "1.5.0"),
            ("hardware_class", "apple-silicon"),
        ]
    ]
    return data


def profile_evidence(
    identifier: str,
    digest: str = "1" * 64,
    *,
    transport: str = "unknown",
    discovery: str = "unknown",
    application: str = "unknown",
) -> dict[str, Any]:
    row = {
        "id": identifier,
        "desired_digest": digest,
        "admitted_digest": digest,
        "applied_digest": digest,
        "paused": False,
        "suspensions": [],
    }
    for key in ("transport", "discovery", "probe", "application", "heard_audio"):
        state = {"transport": transport, "discovery": discovery, "application": application}.get(
            key, "unknown"
        )
        row[key] = {
            "state": state,
            "reason": "complete" if state != "unknown" else "not-checked",
            "observed_at": NOW,
            "generation": "example-generation" if state != "unknown" else None,
        }
    return row


def report(
    data: dict[str, Any], evidence: dict[str, Any] | None = None, **kwargs: Any
) -> dict[str, Any]:
    return build_report(
        parsed(data),
        parse_host_evidence(evidence or evidence_dict()),
        now=NOW,
        data_directory=EXAMPLES,
        **kwargs,
    )


def status(result: dict[str, Any], identifier: str) -> str:
    return next(row["status"] for row in result["requirements"] if row["id"] == identifier)


def proof(
    data: dict[str, Any],
    tmp_path: Path,
    *,
    requirement: str = "DISCOVERY-IMPORT",
    profile: str | None = "example-import",
    method: str = "cold-application-scan",
    tier: int = 5,
    kind: str = "native-capture",
    context: str = "macos-userspace",
    **changes: Any,
) -> Path:
    instance = parsed(data)
    digest = instance_contract_digest(instance)
    if profile is not None:
        selected = next((p for p in instance.transport if p.id == profile), None)
        digest = (
            resolved_profile_digest(instance, selected)
            if selected is not None
            else resolved_discovery_digest(
                instance, next(p for p in instance.discovery if p.id == profile)
            )
        )
    entry = {
        "requirement": requirement,
        "instance_schema_version": 1,
        "profile": profile,
        "method": method,
        "tier": tier,
        "observed_at": "1970-01-01T00:15:00Z",
        "macos_build": "26A434",
        "runtime_version": "1.5.0",
        "framework_sha256": instance.framework.artifact_sha256,
        "contract_sha256": digest,
        "signed_by": "example-reviewer",
    }
    artifact = {
        **entry,
        "schema_version": 1,
        "kind": kind,
        "capture_context": context,
        "result": "passed",
        "source_versions": ["container-1.5.0"],
        **changes,
    }
    raw = canonical_bytes(artifact) + b"\n"
    entry["evidence_sha256"] = hashlib.sha256(raw).hexdigest()
    data["acceptance"].append(entry)
    target = tmp_path / (entry["evidence_sha256"] + ".json")
    target.write_bytes(raw)
    return target


def test_missing_host_facts_remain_unknown(data: dict[str, Any]) -> None:
    result = report(data)
    assert all(fact["state"] == "unknown" for fact in result["facts"])
    assert status(result, "PLATFORM-SUPPORT") == "not-fulfilled"
    assert not result["platform"]["host_accepted"]
    assert not result["mutation_available"]


def test_workload_contract_hash_and_closed_data(tmp_path: Path, data: dict[str, Any]) -> None:
    shutil.copytree(EXAMPLES / "contracts", tmp_path / "contracts")
    instance = parsed(data)
    assert all(row["state"] == "present" for row in verify_contracts(instance, tmp_path))
    target = tmp_path / instance.workloads[0].contract.data_path
    original = json.loads(target.read_bytes())
    for change in ("hash", "raw-env", "network", "traversal", "format"):
        changed = copy.deepcopy(original)
        if change == "hash":
            changed["cpus"] += 1
        elif change == "raw-env":
            changed["environment"] = {"PASSWORD": "example"}
        elif change == "network":
            changed["network"]["name"] = "other-network"
        elif change == "traversal":
            changed["mounts"][0]["source"] = "/example/../outside"
        raw = (
            json.dumps(changed, indent=2).encode()
            if change == "format"
            else canonical_bytes(changed) + b"\n"
        )
        target.write_bytes(raw)
        altered = copy.deepcopy(data)
        if change != "hash":
            altered["workloads"][0]["contract"]["sha256"] = hashlib.sha256(raw).hexdigest()
        assert verify_contracts(parsed(altered), tmp_path)[0]["state"] == "unknown"
    target.unlink()
    assert verify_contracts(instance, tmp_path)[0]["state"] == "unknown"


def test_unsigned_lifecycle_residual_is_not_accepted(data: dict[str, Any]) -> None:
    assert status(report(data), "LIFECYCLE-WRITERS") == "not-fulfilled"
    data["decisions"]["lifecycle_control"] = {
        "residual": "Reviewed vendor API authority remains.",
        "signed_by": "example-reviewer",
        "signed_at": "1970-01-01T00:15:00Z",
    }
    assert status(report(data), "LIFECYCLE-WRITERS") == "accepted-residual"
    data["decisions"]["lifecycle_control"]["signed_at"] = "1970-01-01T01:00:00Z"
    assert status(report(data), "LIFECYCLE-WRITERS") == "not-fulfilled"


@pytest.mark.parametrize("problem", ["unknown", "declined", "unsigned", "blank", "future"])
def test_import_visibility_requires_current_explicit_owner_decision(
    data: dict[str, Any], problem: str
) -> None:
    decision = data["decisions"]["import_visibility"]
    decision.update(accepted=True, signed_by="example-reviewer", signed_at="1970-01-01T00:15:00Z")
    assert status(report(data), "IMPORT-VISIBILITY") == "accepted-residual"
    if problem == "unknown":
        decision["accepted"] = None
    elif problem == "declined":
        decision["accepted"] = False
    elif problem == "unsigned":
        decision.update(signed_by=None, signed_at=None)
    elif problem == "blank":
        decision["signed_by"] = " "
    else:
        decision["signed_at"] = "1970-01-01T01:00:00Z"
    assert status(report(data), "IMPORT-VISIBILITY") == "not-fulfilled"


def test_import_visibility_attestation_does_not_become_verified_authorization(
    data: dict[str, Any], tmp_path: Path
) -> None:
    data["decisions"]["import_visibility"].update(
        accepted=True, signed_by="example-reviewer", signed_at="1970-01-01T00:15:00Z"
    )
    proof(
        data,
        tmp_path,
        requirement="IMPORT-VISIBILITY",
        method="schema-tests",
        tier=1,
        profile=None,
    )
    result = report(data, platform_evidence(), evidence_directory=tmp_path)
    assert status(result, "IMPORT-VISIBILITY") == "accepted-residual"
    data["discovery"] = [item for item in data["discovery"] if item["direction"] != "import"]
    data["acceptance"] = []
    assert status(report(data), "IMPORT-VISIBILITY") == "not-applicable"


def test_no_guessed_withdrawal_bound(data: dict[str, Any]) -> None:
    assert status(report(data), "BOUNDED-IDENTITY") == "not-fulfilled"
    data["decisions"]["bounded"] = [
        {
            "profile": "example-return",
            "max_age_seconds": 30,
            "unknown_limit": 3,
            "residual": "The shared address pool has residual reuse risk.",
            "signed_by": "example-reviewer",
            "signed_at": "1970-01-01T00:15:00Z",
        }
    ]
    result = report(data)
    safety = result["profiles"][1]["safety"]
    assert safety["withdrawal_bound_seconds"] is None
    assert safety["configured_unknown_limit"] == 3 and safety["effective_unknown_limit"] == 1
    assert not safety["zero_misdelivery_guaranteed"]
    assert status(result, "BOUNDED-IDENTITY") == "unverified"
    data["decisions"]["bounded"][0]["signed_at"] = "1970-01-01T01:00:00Z"
    assert status(report(data), "BOUNDED-IDENTITY") == "not-fulfilled"


@pytest.mark.parametrize(
    "state,reason,generation,at,expected",
    [
        ("present", "complete", "g", NOW, "present"),
        ("absent", "complete", "g", NOW, "absent"),
        ("present", "complete", None, NOW, "unknown"),
        ("present", "busy", "g", NOW, "unknown"),
        ("present", "complete", "g", 0, "unknown"),
        ("present", "complete", "g", NOW + 1, "unknown"),
        ("unknown", "timed-out", None, NOW, "unknown"),
    ],
)
def test_unknown_observations_never_become_healthy(
    state: str, reason: str, generation: str | None, at: float, expected: str
) -> None:
    view = observation_view(Observation(state, reason, at, generation), NOW, 30)
    assert view["state"] == expected
    assert observation_view(None, NOW, 30)["state"] == "unknown"


def test_transport_success_does_not_prove_discovery(data: dict[str, Any]) -> None:
    instance = parsed(data)
    evidence = evidence_dict()
    evidence["profiles"] = [
        profile_evidence(
            "example-return",
            resolved_profile_digest(instance, instance.transport[1]),
            transport="present",
        )
    ]
    result = report(data, evidence)
    row = result["profiles"][1]
    assert row["composite"] == "transport-present, discovery-unknown"
    assert not result["current_ready"]
    assert result["discovery_profiles"][1]["observations"]["discovery"]["state"] == "unknown"
    assert result["discovery_profiles"][1]["dependencies"][0]["transport"]["state"] == "present"
    assert status(result, "DISCOVERY-IMPORT") == "unverified"


def test_receipt_never_proves_live_application(data: dict[str, Any]) -> None:
    instance = parsed(data)
    evidence = evidence_dict()
    row = profile_evidence(
        "example-return", resolved_profile_digest(instance, instance.transport[1])
    )
    row["receipt"] = {
        "digest": row["applied_digest"],
        "recorded_at": 1,
        "generation": "old-generation",
        "result": "passed",
    }
    evidence["profiles"] = [row]
    result = report(data, evidence)
    states = result["profiles"][1]["states"]
    assert set(states) == {"desired", "admitted", "observed", "applied", "receipt"}
    assert states["receipt"]["historical"] and not states["receipt"]["current_authority"]
    assert states["observed"]["application"]["state"] == "unknown"
    assert not result["current_ready"]


def test_missing_acceptance_stays_unverified(data: dict[str, Any]) -> None:
    result = report(data, platform_evidence())
    assert result["platform"]["candidate_parser_compatible"]
    assert not result["platform"]["host_accepted"]
    assert not result["fully_served"]
    for key in ("HEARD-AUDIO", "MULTI-RECEIVER", "RESTORE-REHEARSAL", "OWNER-CONFORMANCE"):
        assert status(result, key) == "unverified"


def test_filevault_on_does_not_fulfil_unattended_recovery(data: dict[str, Any]) -> None:
    data["decisions"]["unattended_recovery"] = {"accepted": True, "max_dns_ready_seconds": 60}
    evidence = evidence_dict()
    evidence["facts"] = [
        {
            "key": "filevault",
            "state": "present",
            "reason": "complete",
            "observed_at": NOW,
            "value": "on",
        }
    ]
    assert status(report(data, evidence), "BOOT-RECOVERY") == "not-fulfilled"


@pytest.mark.parametrize("command", host_cli.COMMANDS)
def test_host_commands_do_not_change_state(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    shutil.copytree(EXAMPLES, tmp_path / "data")
    before = {
        str(p.relative_to(tmp_path)): (p.read_bytes(), p.stat().st_mtime_ns)
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    assert host_cli.main(
        [command, "--instance", str(tmp_path / "data/instance.json")], now=NOW
    ) == (1 if command == "check" else 0)
    result = json.loads(capsys.readouterr().out)
    assert result["read_only"] and not result["mutation_available"]
    after = {
        str(p.relative_to(tmp_path)): (p.read_bytes(), p.stat().st_mtime_ns)
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    assert before == after
    if command == "plan":
        assert result["actions"] == []


def test_host_entrypoint_never_contacts_network(
    monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("read-only command attempted process/network/state operation")

    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    for command in host_cli.COMMANDS:
        assert host_cli.main([command, "--instance", str(EXAMPLES / "instance.json")], now=NOW) == (
            1 if command == "check" else 0
        )
        capsys.readouterr()


def test_explicit_collector_is_opt_in(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    calls = []
    monkeypatch.setattr(os, "geteuid", lambda: 501)

    def collector(instance: Any) -> dict[str, Any]:
        calls.append(instance.instance)
        return evidence_dict("local-collector")

    host_cli.main(
        ["preflight", "--instance", str(EXAMPLES / "instance.json")], collector=collector, now=NOW
    )
    assert not calls
    host_cli.main(
        ["preflight", "--collect-local", "--instance", str(EXAMPLES / "instance.json")],
        collector=collector,
        now=NOW,
    )
    assert calls == ["example"]
    assert (
        json.loads(capsys.readouterr().out.splitlines()[-1])["evidence_source"] == "local-collector"
    )
    with pytest.raises(SystemExit):
        host_cli.main(
            ["plan", "--collect-local", "--instance", str(EXAMPLES / "instance.json")],
            collector=collector,
            now=NOW,
        )


def test_root_and_bad_data_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert host_cli.main(["status", "--instance", "/nonexistent/private-secret"], now=NOW) == 77
    assert "private-secret" not in capsys.readouterr().out
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    target = tmp_path / "private-secret"
    target.write_bytes(b'{"secret":"do-not-echo"}')
    assert host_cli.main(["status", "--instance", str(target)], now=NOW) == 65
    output = capsys.readouterr().out
    assert "do-not-echo" not in output and "private-secret" not in output


@pytest.mark.parametrize("variant", ["instance.json", "instance-structural.json"])
def test_synthetic_variants_validate_without_native_support(variant: str) -> None:
    instance = load_instance(EXAMPLES / variant)
    result = build_report(instance, empty_evidence(NOW), now=NOW, data_directory=EXAMPLES)
    assert all(row["state"] == "present" for row in result["contracts"])
    assert not result["platform"]["host_accepted"] and not result["fully_served"]
    if variant == "instance-structural.json":
        assert all(row["gate"] != "bounded" for row in result["profiles"])
        assert status(result, "BOUNDED-IDENTITY") == "not-applicable"
        assert status(result, "HEARD-AUDIO") == "not-applicable"


def test_native_receipt_is_content_bound_but_not_mutation_authority(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    proof(data, tmp_path)
    result = report(data, platform_evidence(), evidence_directory=tmp_path)
    assert status(result, "DISCOVERY-IMPORT") == "fulfilled-verified"
    assert not result["current_ready"] and not result["mutation_available"]
    assert "not independently replayed" in result["acceptance_authority"]
    proof(
        data,
        tmp_path,
        requirement="PLATFORM-SUPPORT",
        profile=None,
        method="root-runtime-observer",
        tier=2,
        context="root-launchdaemon",
    )
    result = report(data, platform_evidence(), evidence_directory=tmp_path)
    assert not result["platform"]["host_accepted"]
    assert status(result, "PLATFORM-SUPPORT") == "unverified"


@pytest.mark.parametrize(
    "failure",
    [
        "synthetic-source",
        "synthetic-proof",
        "offline-context",
        "no-file",
        "changed-file",
        "unknown-platform",
        "different-build",
        "future",
        "wrong-context",
        "wrong-method",
        "incomplete-layer",
    ],
)
def test_invalid_or_synthetic_receipts_never_become_native_verified(
    tmp_path: Path, data: dict[str, Any], failure: str
) -> None:
    context = "host-person" if failure == "wrong-context" else "macos-userspace"
    requirement = "HEARD-AUDIO" if failure == "wrong-context" else "DISCOVERY-IMPORT"
    method = "heard-audio" if failure == "wrong-context" else "cold-application-scan"
    target = proof(data, tmp_path, requirement=requirement, method=method, context=context)
    evidence = platform_evidence()
    if failure == "synthetic-source":
        evidence["source"] = "synthetic"
    elif failure in {"synthetic-proof", "offline-context", "wrong-context", "incomplete-layer"}:
        artifact = json.loads(target.read_bytes())
        if failure == "synthetic-proof":
            artifact["kind"] = "synthetic"
        elif failure == "offline-context":
            artifact["capture_context"] = "offline-fixture"
        elif failure == "wrong-context":
            artifact["capture_context"] = "macos-userspace"
        else:
            artifact["result"] = "unknown"
        raw = canonical_bytes(artifact) + b"\n"
        target.unlink()
        sha = hashlib.sha256(raw).hexdigest()
        (tmp_path / (sha + ".json")).write_bytes(raw)
        data["acceptance"][0]["evidence_sha256"] = sha
    elif failure == "no-file":
        target.unlink()
    elif failure == "changed-file":
        target.write_bytes(b"{}\n")
    elif failure == "unknown-platform":
        evidence["facts"] = []
    elif failure == "different-build":
        data["acceptance"][0]["macos_build"] = "OTHER"
    elif failure == "future":
        data["acceptance"][0]["observed_at"] = "1970-01-01T01:00:00Z"
    else:
        data["acceptance"][0]["method"] = "receiver-change"
    assert status(report(data, evidence, evidence_directory=tmp_path), requirement) == "unverified"


def test_profile_acceptance_requires_every_applicable_selection(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    duplicate = copy.deepcopy(data["discovery"][1])
    duplicate["id"] = "example-import-second"
    data["discovery"].append(duplicate)
    proof(data, tmp_path)
    result = report(data, platform_evidence(), evidence_directory=tmp_path)
    assert status(result, "DISCOVERY-IMPORT") == "unverified"
    proof(data, tmp_path, profile="example-import-second")
    assert (
        status(report(data, platform_evidence(), evidence_directory=tmp_path), "DISCOVERY-IMPORT")
        == "fulfilled-verified"
    )


@pytest.mark.parametrize(
    "problem",
    [
        "paused",
        "suspension",
        "admission",
        "applied",
        "desired",
        "unknown",
        "stale",
        "synthetic",
        "missing-component",
        "generation",
        "workload",
    ],
)
def test_current_readiness_requires_all_states(data: dict[str, Any], problem: str) -> None:
    instance = parsed(data)
    evidence = evidence_dict()
    for item in instance.transport:
        evidence["profiles"].append(
            profile_evidence(item.id, resolved_profile_digest(instance, item), transport="present")
        )
    for item in instance.discovery:
        evidence["profiles"].append(
            profile_evidence(
                item.id,
                resolved_discovery_digest(instance, item),
                discovery="present",
                application="present",
            )
        )
    observation = {
        "state": "present",
        "reason": "complete",
        "observed_at": NOW,
        "generation": "example-generation",
    }
    evidence["workloads"] = [
        {"id": workload.id, "observation": copy.deepcopy(observation)}
        for workload in instance.workloads
    ]
    evidence["components"] = [
        {
            "service": "example-media",
            "id": "example-component",
            "observation": copy.deepcopy(observation),
        }
    ]
    assert report(data, evidence)["current_ready"]
    current = evidence["profiles"][0]
    if problem == "paused":
        current["paused"] = True
    elif problem == "suspension":
        current["suspensions"] = ["other-operation"]
    elif problem == "admission":
        current["admitted_digest"] = "2" * 64
    elif problem == "applied":
        current["applied_digest"] = "2" * 64
    elif problem == "desired":
        current["desired_digest"] = "2" * 64
    elif problem == "unknown":
        current["transport"]["state"] = "unknown"
    elif problem == "stale":
        current["transport"]["observed_at"] = 0
    elif problem == "synthetic":
        evidence["source"] = "synthetic"
    elif problem == "missing-component":
        evidence["components"] = []
    elif problem == "generation":
        evidence["profiles"][2]["discovery"]["generation"] = "different-generation"
    else:
        evidence["workloads"] = []
    assert not report(data, evidence)["current_ready"]


@pytest.mark.parametrize(
    "change",
    [
        "unknown-key",
        "duplicate",
        "null-present",
        "valued-unknown",
        "bool-filevault",
        "wrong-bool",
        "bad-generation",
        "raw-command",
    ],
)
def test_evidence_is_closed_and_typed(change: str) -> None:
    evidence = evidence_dict()
    evidence["facts"] = [
        {
            "key": "filevault",
            "state": "present",
            "reason": "complete",
            "observed_at": NOW,
            "value": "off",
        }
    ]
    if change == "unknown-key":
        evidence["facts"][0]["key"] = "arbitrary"
    elif change == "duplicate":
        evidence["facts"] *= 2
    elif change == "null-present":
        evidence["facts"][0]["value"] = None
    elif change == "valued-unknown":
        evidence["facts"][0]["state"] = "unknown"
    elif change == "bool-filevault":
        evidence["facts"][0]["value"] = True
    elif change == "wrong-bool":
        evidence["facts"][0].update(key="automatic_login", value="yes")
    elif change == "bad-generation":
        evidence["profiles"] = [profile_evidence("example-return")]
        evidence["profiles"][0]["transport"]["generation"] = []
    else:
        evidence["command"] = "sudo anything"
    with pytest.raises(InstanceError):
        parse_host_evidence(evidence)


def test_each_fact_has_its_own_age_reason_and_generation() -> None:
    data = evidence_dict()
    data["facts"] = [
        {
            "key": "filevault",
            "state": "present",
            "reason": "complete",
            "observed_at": 0,
            "value": "off",
        }
    ]
    evidence = parse_host_evidence(data)
    assert fact_view(evidence, "filevault", NOW)["reason"] == "stale"
    assert fact_view(evidence, "runtime_version", NOW)["reason"] == "not-checked"
    assert evidence_to_dict(evidence)["facts"][0]["observed_at"] == 0
    assert (
        fact_view(
            HostEvidence(
                1,
                NOW,
                "owner-snapshot",
                (Fact("filevault", "present", "complete", NOW + 1, "off"),),
                (),
            ),
            "filevault",
            NOW,
        )["reason"]
        == "contradictory"
    )


def test_cli_release_pin_requires_artifact_lock_and_version(
    tmp_path: Path, data: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    shutil.copytree(EXAMPLES / "contracts", tmp_path / "contracts")
    artifact = tmp_path / "artifact.whl"
    artifact.write_bytes(b"example immutable wheel")
    lock = tmp_path / "lock.json"
    lock.write_bytes(b"example dependency lock")
    data["framework"]["artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    data["framework"]["dependency_lock_sha256"] = hashlib.sha256(lock.read_bytes()).hexdigest()
    instance = tmp_path / "instance.json"
    instance.write_bytes(canonical_bytes(data) + b"\n")
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    args = [
        "validate",
        "--instance",
        str(instance),
        "--framework-artifact",
        str(artifact),
        "--dependency-lock",
        str(lock),
    ]
    assert host_cli.main(args, now=NOW) == 0
    assert json.loads(capsys.readouterr().out)["release_verified"]
    lock.write_bytes(b"changed")
    assert host_cli.main(args, now=NOW) == 0
    assert not json.loads(capsys.readouterr().out)["release_verified"]


def test_missing_authoring_subject_is_not_fulfilled(data: dict[str, Any]) -> None:
    row = data["authoring"][0]
    row["sections"].remove("workloads")
    data["authoring"].append(
        {
            "owner": "partial",
            "sections": ["workloads"],
            "subjects": ["example-web"],
            "mode": "authored",
            "source_sha256": None,
        }
    )
    assert status(report(data), "SOURCE-AUTHORSHIP") == "not-fulfilled"


@pytest.mark.parametrize("requirement", ["SOURCE-AUTHORSHIP", "OWNER-CONFORMANCE"])
@pytest.mark.parametrize("change", ["source", "owner", "mode"])
def test_authoring_changes_invalidate_retained_conformance(
    tmp_path: Path, data: dict[str, Any], requirement: str, change: str
) -> None:
    row = data["authoring"][0]
    row.update(mode="generated", source_sha256="3" * 64)
    proof(data, tmp_path, requirement=requirement, profile=None, method="fixture-parity", tier=1)
    assert (
        status(report(data, platform_evidence(), evidence_directory=tmp_path), requirement)
        == "fulfilled-verified"
    )
    if change == "source":
        row["source_sha256"] = "4" * 64
    elif change == "owner":
        row["owner"] = "example-replacement-owner"
    else:
        row.update(mode="authored", source_sha256=None)
    assert (
        status(report(data, platform_evidence(), evidence_directory=tmp_path), requirement)
        == "unverified"
    )


@pytest.mark.parametrize("desired", [None, "f" * 64])
def test_discovery_current_readiness_requires_owner_desired_digest(
    data: dict[str, Any], desired: str | None
) -> None:
    instance = parsed(data)
    evidence = evidence_dict()
    for item in instance.transport:
        evidence["profiles"].append(
            profile_evidence(item.id, resolved_profile_digest(instance, item), transport="present")
        )
    for item in instance.discovery:
        evidence["profiles"].append(
            profile_evidence(
                item.id,
                resolved_discovery_digest(instance, item),
                discovery="present",
                application="present",
            )
        )
    observation = {
        "state": "present",
        "reason": "complete",
        "observed_at": NOW,
        "generation": "example-generation",
    }
    evidence["workloads"] = [
        {"id": workload.id, "observation": observation} for workload in instance.workloads
    ]
    evidence["components"] = [
        {"service": workload.id, "id": component.id, "observation": observation}
        for workload in instance.workloads
        for component in workload.components
    ]
    assert report(data, evidence)["current_ready"]
    evidence["profiles"][-1]["desired_digest"] = desired
    result = report(data, evidence)
    assert not result["current_ready"]
    assert result["discovery_profiles"][-1]["owner_desired_digest"] == desired

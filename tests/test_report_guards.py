"""Each truthfulness guard of the report has a test that notices its removal."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from dataclasses import replace
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from netorch import host_report
from netorch.codec import canonical_bytes
from netorch.host_report import build_report, parse_host_evidence
from netorch.instance import (
    InstanceError,
    instance_contract_digest,
    parse_instance,
    resolved_discovery_digest,
    resolved_profile_digest,
)
from netorch.requirements import requirement

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
NOW = 1000.0
STALE = NOW - 301
SIGNED = "1970-01-01T00:15:00Z"


@pytest.fixture
def data() -> dict[str, Any]:
    return json.loads((EXAMPLES / "instance.json").read_bytes())


def parsed(data: dict[str, Any]) -> Any:
    return parse_instance(canonical_bytes(data) + b"\n")


def fact(key: str, value: Any, *, state: str = "present", at: float = NOW) -> dict[str, Any]:
    return {"key": key, "state": state, "reason": "complete", "observed_at": at, "value": value}


def platform(runtime: str | None = "1.5.0") -> list[dict[str, Any]]:
    facts = [fact("macos_build", "26A434")]
    return facts if runtime is None else [*facts, fact("runtime_version", runtime)]


def evidence(facts: list[dict[str, Any]] | None = None, **members: Any) -> Any:
    return parse_host_evidence(
        {
            "schema_version": 1,
            "source": "owner-snapshot",
            "observed_at": NOW,
            "facts": facts or [],
            "profiles": [],
            **members,
        }
    )


def report(
    data: dict[str, Any],
    facts: list[dict[str, Any]] | None = None,
    members: dict[str, Any] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    return build_report(
        parsed(data), evidence(facts, **(members or {})), now=NOW, data_directory=EXAMPLES, **kwargs
    )


def status(result: dict[str, Any], identifier: str) -> str:
    return str(next(row["status"] for row in result["requirements"] if row["id"] == identifier))


def views(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["key"]: item for item in result["facts"]}


def attest(
    data: dict[str, Any],
    directory: Path,
    identifier: str,
    method: str,
    tier: int,
    profile: str | None = None,
    *,
    context: str = "macos-userspace",
    **overrides: Any,
) -> Path:
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
        "requirement": identifier,
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
        **overrides,
    }
    raw = canonical_bytes(retained(entry, context)) + b"\n"
    entry["evidence_sha256"] = hashlib.sha256(raw).hexdigest()
    target = directory / (entry["evidence_sha256"] + ".json")
    target.write_bytes(raw)
    data["acceptance"].append(entry)
    return target


def retained(entry: dict[str, Any], context: str = "macos-userspace") -> dict[str, Any]:
    return {
        **{key: value for key, value in entry.items() if key != "evidence_sha256"},
        "schema_version": 1,
        "kind": "owner-attestation",
        "capture_context": context,
        "result": "passed",
        "source_versions": ["container-1.5.0"],
    }


def lan_facts(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    lan = data["host"]["lan"]
    return {
        "lan_hardware_id": fact("lan_hardware_id", lan["hardware_id"]),
        "lan_ipv4": fact("lan_ipv4", lan["ipv4"]),
    }


def test_lan_identity_needs_the_declared_current_address_and_adapter(
    data: dict[str, Any],
) -> None:
    declared = lan_facts(data)
    assert status(report(data, list(declared.values())), "LAN-IDENTITY") == "fulfilled-unverified"
    for key, other in (("lan_ipv4", "198.51.100.99"), ("lan_hardware_id", "example-other")):
        differing = {**declared, key: fact(key, other)}
        assert status(report(data, list(differing.values())), "LAN-IDENTITY") == "not-fulfilled"


@pytest.mark.parametrize("key", ["lan_hardware_id", "lan_ipv4"])
@pytest.mark.parametrize("problem", ["missing", "stale", "unknown", "future"])
def test_lan_identity_is_not_fulfilled_while_one_fact_is_unknown(
    data: dict[str, Any], key: str, problem: str
) -> None:
    facts = lan_facts(data)
    value = facts[key]["value"]
    if problem == "missing":
        del facts[key]
    elif problem == "stale":
        facts[key] = fact(key, value, at=STALE)
    elif problem == "unknown":
        facts[key] = fact(key, None, state="unknown")
    else:
        facts[key] = fact(key, value, at=NOW + 1)
    assert status(report(data, list(facts.values())), "LAN-IDENTITY") == "not-fulfilled"


def test_consent_identity_needs_a_current_launch_agent_identity_fact(
    data: dict[str, Any],
) -> None:
    key = "local_network_identity"
    assert status(report(data), "CONSENT-IDENTITY") == "not-fulfilled"
    current = [fact(key, "example-identity")]
    assert status(report(data, current), "CONSENT-IDENTITY") == "fulfilled-unverified"
    for other in (
        fact(key, "example-identity", at=STALE),
        fact(key, None, state="unknown"),
        fact(key, None, state="absent"),
    ):
        assert status(report(data, [other]), "CONSENT-IDENTITY") == "not-fulfilled"


@pytest.mark.parametrize(
    ("context", "expected"),
    [("user-launchagent", "fulfilled-verified"), ("macos-userspace", "fulfilled-unverified")],
)
def test_consent_acceptance_needs_the_launch_agent_context(
    tmp_path: Path, data: dict[str, Any], context: str, expected: str
) -> None:
    for selection in data["discovery"]:
        attest(
            data,
            tmp_path,
            "CONSENT-IDENTITY",
            "local-network-consent",
            3,
            selection["id"],
            context=context,
        )
    facts = [*platform(), fact("local_network_identity", "example-identity")]
    result = report(data, facts, evidence_directory=tmp_path)
    assert status(result, "CONSENT-IDENTITY") == expected


def test_platform_support_needs_apple_silicon(data: dict[str, Any]) -> None:
    facts = [*platform(), fact("macos_version", "27.0.1")]
    result = report(data, [*facts, fact("hardware_class", "apple-silicon")])
    assert status(result, "PLATFORM-SUPPORT") == "fulfilled-unverified"
    assert result["platform"]["candidate_parser_compatible"]
    result = report(data, [*facts, fact("hardware_class", "intel")])
    assert status(result, "PLATFORM-SUPPORT") == "not-fulfilled"
    assert not result["platform"]["candidate_parser_compatible"]


def test_matching_record_verifies_an_instance_wide_requirement(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    assert status(report(data, platform()), "RESTORE-REHEARSAL") == "fulfilled-unverified"
    attest(data, tmp_path, "RESTORE-REHEARSAL", "restore-rehearsal", 4)
    result = report(data, platform(), evidence_directory=tmp_path)
    assert status(result, "RESTORE-REHEARSAL") == "fulfilled-verified"


@pytest.mark.parametrize(
    ("tier", "changes", "runtime"),
    [
        # The host really runs the recorded version, but the instance declares another.
        (4, {"runtime_version": "1.2.0"}, "1.2.0"),
        (4, {"framework_sha256": "f" * 64}, "1.5.0"),
        (4, {"contract_sha256": "e" * 64}, "1.5.0"),
        (3, {}, "1.5.0"),
    ],
)
def test_record_made_for_other_content_or_a_lower_tier_does_not_verify(
    tmp_path: Path, data: dict[str, Any], tier: int, changes: dict[str, str], runtime: str
) -> None:
    attest(data, tmp_path, "RESTORE-REHEARSAL", "restore-rehearsal", tier, **changes)
    result = report(data, platform(runtime), evidence_directory=tmp_path)
    assert status(result, "RESTORE-REHEARSAL") == "fulfilled-unverified"


def test_record_does_not_survive_a_later_change_of_the_instance(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    attest(data, tmp_path, "RESTORE-REHEARSAL", "restore-rehearsal", 4)
    attest(data, tmp_path, "PORT-BUDGET", "port-budget", 3, "example-return")
    result = report(data, platform(), evidence_directory=tmp_path)
    assert (
        status(result, "RESTORE-REHEARSAL") == status(result, "PORT-BUDGET") == "fulfilled-verified"
    )
    data["port_ranges"][0]["last"] += 1
    result = report(data, platform(), evidence_directory=tmp_path)
    assert status(result, "RESTORE-REHEARSAL") == "fulfilled-unverified"
    assert status(result, "PORT-BUDGET") == "fulfilled-unverified"


@pytest.mark.parametrize("runtime", [None, "1.2.0"])
def test_record_needs_the_current_runtime_version_fact(
    tmp_path: Path, data: dict[str, Any], runtime: str | None
) -> None:
    attest(data, tmp_path, "RESTORE-REHEARSAL", "restore-rehearsal", 4)
    result = report(data, platform(runtime), evidence_directory=tmp_path)
    assert status(result, "RESTORE-REHEARSAL") == "fulfilled-unverified"


def test_retained_file_edited_after_signing_does_not_verify(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    target = attest(data, tmp_path, "RESTORE-REHEARSAL", "restore-rehearsal", 4)
    edited = json.loads(target.read_bytes())
    edited["source_versions"] = ["container-1.5.0", "example-added-later"]
    target.write_bytes(canonical_bytes(edited) + b"\n")
    result = report(data, platform(), evidence_directory=tmp_path)
    assert status(result, "RESTORE-REHEARSAL") == "fulfilled-unverified"


def test_record_made_under_another_instance_schema_version_does_not_verify(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    # No parser accepts another schema version today, so the later model is built by hand.
    digest = instance_contract_digest(replace(parsed(data), schema_version=2))
    attest(data, tmp_path, "RESTORE-REHEARSAL", "restore-rehearsal", 4, contract_sha256=digest)
    later = replace(parsed(data), schema_version=2)
    assert later.acceptance[0].instance_schema_version == 1
    assert later.acceptance[0].contract_sha256 == instance_contract_digest(later)
    result = build_report(
        later, evidence(platform()), now=NOW, data_directory=EXAMPLES, evidence_directory=tmp_path
    )
    assert status(result, "RESTORE-REHEARSAL") == "fulfilled-unverified"


@pytest.mark.parametrize(
    ("context", "expected"),
    [("root-launchdaemon", True), ("user-launchagent", False), ("macos-userspace", False)],
)
def test_root_observer_record_needs_the_root_daemon_context(
    tmp_path: Path, data: dict[str, Any], context: str, expected: bool
) -> None:
    # The report never upgrades PLATFORM-SUPPORT, so this guard is reached only directly.
    attest(data, tmp_path, "PLATFORM-SUPPORT", "root-runtime-observer", 2, context=context)
    accepted = host_report._acceptance(
        parsed(data), requirement("PLATFORM-SUPPORT"), evidence(platform()), NOW, tmp_path
    )
    assert accepted is expected


def ready(data: dict[str, Any]) -> dict[str, Any]:
    """Owner-reported evidence in which every declared row is current and consistent."""
    instance = parsed(data)
    observation = {
        "state": "present",
        "reason": "complete",
        "observed_at": NOW,
        "generation": "example-generation",
    }
    unknown = {"state": "unknown", "reason": "not-checked", "observed_at": NOW, "generation": None}
    rows = []
    for item in (*instance.transport, *instance.discovery):
        transport = item in instance.transport
        digest = (
            resolved_profile_digest(instance, item)
            if transport
            else resolved_discovery_digest(instance, item)
        )
        row = {
            "id": item.id,
            "desired_digest": digest,
            "admitted_digest": digest,
            "applied_digest": digest,
            "paused": False,
            "suspensions": [],
            "probe": dict(unknown),
            "heard_audio": dict(unknown),
        }
        for key in ("transport", "discovery", "application"):
            present = key == "transport" if transport else key != "transport"
            row[key] = dict(observation if present else unknown)
        rows.append(row)
    return {
        "profiles": rows,
        "workloads": [
            {"id": item.id, "observation": dict(observation)} for item in instance.workloads
        ],
        "components": [
            {"service": item.id, "id": component.id, "observation": dict(observation)}
            for item in instance.workloads
            for component in item.components
        ],
    }


@pytest.mark.parametrize(
    "problem", ["paused", "suspension", "admitted", "applied", "discovery", "application"]
)
@pytest.mark.parametrize("selection", ["example-export", "example-import"])
def test_current_readiness_needs_every_discovery_row(
    data: dict[str, Any], selection: str, problem: str
) -> None:
    members = ready(data)
    assert report(data, members=members)["current_ready"]
    row = next(item for item in members["profiles"] if item["id"] == selection)
    if problem == "paused":
        row["paused"] = True
    elif problem == "suspension":
        row["suspensions"] = ["other-operation"]
    elif problem in {"admitted", "applied"}:
        row[problem + "_digest"] = "2" * 64
    else:
        row[problem] = {
            "state": "unknown",
            "reason": "timed-out",
            "observed_at": NOW,
            "generation": None,
        }
    assert not report(data, members=members)["current_ready"]


@pytest.mark.parametrize("signature", [(None, None), ("example-reviewer", "1970-01-01T01:00:00Z")])
def test_lifecycle_residual_without_a_current_signature_is_not_accepted(
    data: dict[str, Any], signature: tuple[str | None, str | None]
) -> None:
    data["decisions"]["lifecycle_control"] = {
        "residual": "Reviewed vendor API authority remains.",
        "signed_by": signature[0],
        "signed_at": signature[1],
    }
    assert status(report(data), "LIFECYCLE-WRITERS") == "not-fulfilled"


def resolver(data: dict[str, Any]) -> dict[str, Any]:
    """The example with its web workload declared a resolver behind a direct redirect."""
    result = copy.deepcopy(data)
    result["workloads"][0]["application_profile"] = "resolver"
    result["transport"].append(
        {
            "id": "example-direct",
            "service": "example-web",
            "strategy": "guest-direct-redirect",
            "version": 1,
            "protocol": "tcp",
            "ports": {"first": 80, "last": 80},
            "target_ports": {"first": 8080, "last": 8080},
            "dependencies": ["example-publication"],
            "fallback_publication": "example-publication",
        }
    )
    return result


def test_resolver_requirements_apply_only_to_a_resolver_workload(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    plain = report(data)
    assert status(plain, "RUNTIME-DNS") == status(plain, "DNS-CLIENT-IDENTITY") == "not-applicable"
    declared = resolver(data)
    result = report(declared, platform())
    assert status(result, "RUNTIME-DNS") == "fulfilled-unverified"
    assert status(result, "DNS-CLIENT-IDENTITY") == "fulfilled-unverified"
    preserved = {row["id"]: row["preserves_client_identity"] for row in result["profiles"]}
    assert preserved["example-direct"] is True and preserved["example-publication"] is False
    attest(declared, tmp_path, "DNS-CLIENT-IDENTITY", "dns-client-identity", 5)
    result = report(declared, platform(), evidence_directory=tmp_path)
    assert status(result, "DNS-CLIENT-IDENTITY") == "fulfilled-verified"
    assert status(result, "RUNTIME-DNS") == "fulfilled-unverified"


def test_runtime_dns_settings_are_unknown_until_observed(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    declared = resolver(data)
    unobserved = views(report(declared))
    assert unobserved["runtime_dns_domain"]["state"] == "unknown"
    assert unobserved["runtime_resolvers"]["reason"] == "not-checked"
    observed = [
        fact("runtime_dns_domain", "example.test"),
        fact("runtime_resolvers", ["192.0.2.53"]),
    ]
    result = report(declared, [*platform(), *observed])
    assert views(result)["runtime_dns_domain"]["value"] == "example.test"
    assert views(result)["runtime_resolvers"]["value"] == ["192.0.2.53"]
    assert status(result, "RUNTIME-DNS") == "fulfilled-unverified"
    with pytest.raises(InstanceError):
        evidence([fact("runtime_resolvers", "192.0.2.53")])
    attest(declared, tmp_path, "RUNTIME-DNS", "darwin-cli", 2)
    result = report(declared, [*platform(), *observed], evidence_directory=tmp_path)
    assert status(result, "RUNTIME-DNS") == "fulfilled-verified"


def test_port_budget_counts_are_typed_and_observed_independently(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    idle = [fact("udp_sockets_idle", 4)]
    result = report(data, idle)
    assert views(result)["udp_sockets_idle"]["value"] == 4
    assert views(result)["udp_sockets_loaded"]["state"] == "unknown"
    assert status(result, "PORT-BUDGET") == "fulfilled-unverified"
    for value in ("many", True, ["4"]):
        with pytest.raises(InstanceError):
            evidence([fact("udp_sockets_loaded", value)])
    attest(data, tmp_path, "PORT-BUDGET", "port-budget", 3, "example-return")
    result = report(data, [*platform(), *idle], evidence_directory=tmp_path)
    assert status(result, "PORT-BUDGET") == "fulfilled-verified"


def test_failed_component_is_reported_separately_and_authorizes_no_restart(
    data: dict[str, Any],
) -> None:
    members = ready(data)
    members["components"][0]["observation"]["state"] = "absent"
    result = report(data, members=members)
    media = next(row for row in result["workloads"] if row["id"] == "example-media")
    component = media["components"][0]
    assert media["observation"]["state"] == "present"
    assert component["observation"]["state"] == "absent"
    assert component["recovery"] == "component-owner"
    assert component["workload_restart_authorized"] is False
    assert media["workload_restart_authorized"] is False
    assert not media["current_generation_consistent"] and not result["current_ready"]
    web = next(row for row in result["workloads"] if row["id"] == "example-web")
    assert web["current_generation_consistent"]
    assert status(result, "COMPONENT-HEALTH") == "fulfilled-verified"


# Where the statement of a requirement is exercised: the files its proving tests live in.
PROVED_IN = {
    "HOST-DATA": {"test_privacy.py"},
    "LAN-IDENTITY": {"test_instance.py", "test_report_guards.py"},
    "COMPONENT-HEALTH": {"test_report_guards.py"},
    "PAUSE-PRESERVED": {"test_deployment.py"},
    "CONSENT-IDENTITY": {"test_report_guards.py"},
    "UDP-FIRST-PACKET": {"test_pf.py", "test_pf_owner.py"},
    "DNS-CLIENT-IDENTITY": {"test_pf_owner.py", "test_report_guards.py"},
    "OWNER-CONFORMANCE": {"test_conformance.py"},
    "OWNER-ROLLBACK": {"test_deployment.py"},
    "PORT-BUDGET": {"test_report_guards.py"},
    "RUNTIME-DNS": {"test_host_cli.py", "test_report_guards.py"},
    "RENDER-INDEPENDENCE": {"test_host_cli.py"},
}


@cache
def checked_in_test_files() -> dict[str, frozenset[str]]:
    """Read syntax only, as the registry test does; no test module is imported."""
    found: dict[str, set[str]] = {}
    for source in sorted(Path(__file__).parent.glob("test_*.py")):
        for node in ast.parse(source.read_bytes(), filename=str(source)).body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                found.setdefault(node.name, set()).add(source.name)
    return {name: frozenset(files) for name, files in found.items()}


@pytest.mark.parametrize("identifier", sorted(PROVED_IN))
def test_requirement_names_tests_that_exercise_its_statement(identifier: str) -> None:
    files = checked_in_test_files()
    named = requirement(identifier).proving_tests
    assert {file for name in named for file in files[name]} == PROVED_IN[identifier]

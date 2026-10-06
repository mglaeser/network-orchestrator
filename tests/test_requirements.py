"""Trace the public evidence registry to real tests and resolved behavior."""

from __future__ import annotations

import ast
import copy
import re
from pathlib import Path
from typing import Any

import pytest

from netorch.codec import canonical_bytes, strict_loads
from netorch.instance import parse_instance, resolved_profile_digest
from netorch.platform_contract import ACCEPTED_PLATFORMS, FACTS
from netorch.profile_library import DISCOVERY_PROFILES, STRATEGIES
from netorch.requirements import REQUIREMENTS
from netorch.workflow_gate import StageNotQualified, require_mutation_qualified

ROOT = Path(__file__).resolve().parents[1]
APPLICABILITY = frozenset(
    {
        "all",
        "workloads",
        "components",
        "transport",
        "root-transport",
        "bounded",
        "bounded-udp",
        "exports",
        "imports",
        "discovery",
        "resolver",
        "api-writers",
    }
)
DISCOVERY_CONTRACT_METHODS = frozenset(
    {
        "genuine-record",
        "publication-identity",
        "application-connect",
        "cold-application-scan",
        "receiver-change",
        "heard-audio",
    }
)


def checked_in_test_functions() -> dict[str, set[str]]:
    """Read AST only, without importing tests, fixtures or native owners."""
    found: dict[str, set[str]] = {}
    for source in sorted((ROOT / "tests").glob("test_*.py")):
        tree = ast.parse(source.read_bytes(), filename=str(source))
        nodes: list[ast.AST] = list(tree.body)
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                nodes.extend(node.body)
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
                "test_"
            ):
                found.setdefault(node.name, set()).add(source.name)
    return found


def acceptance_methods() -> set[str]:
    schema = strict_loads((ROOT / "schemas/acceptance-evidence.schema.json").read_bytes())
    return set(schema["properties"]["method"]["enum"])


def test_registry_proving_tests_resolve_to_checked_in_test_functions() -> None:
    functions = checked_in_test_functions()
    missing = {
        item.id: sorted(set(item.proving_tests) - functions.keys())
        for item in REQUIREMENTS
        if set(item.proving_tests) - functions.keys()
    }
    assert not missing, f"Requirement proving tests have no declared pytest function: {missing}"
    missing_facts = {
        item.id: item.proving_test for item in FACTS if item.proving_test not in functions
    }
    assert not missing_facts, (
        f"Platform proving tests have no declared pytest function: {missing_facts}"
    )


def test_registry_has_sources_proofs_and_retirement() -> None:
    methods = acceptance_methods()
    assert len({item.id for item in REQUIREMENTS}) == len(REQUIREMENTS)
    assert len({item.id for item in FACTS}) == len(FACTS)
    for item in REQUIREMENTS:
        assert re.fullmatch(r"[A-Z][A-Z0-9-]{1,63}", item.id)
        assert item.statement.strip() and item.source.startswith("review-")
        assert item.applicability in APPLICABILITY
        assert item.proving_tests and len(set(item.proving_tests)) == len(item.proving_tests)
        assert item.acceptance_methods and set(item.acceptance_methods) <= methods
        assert type(item.minimum_tier) is int and 1 <= item.minimum_tier <= 5
    for fact in FACTS:
        assert fact.statement.strip() and fact.retirement.strip()
        assert fact.sources and all(value.startswith("https://") for value in fact.sources)
        assert fact.source_versions and all(value.strip() for value in fact.source_versions)
        assert fact.proving_test.startswith("test_")


def test_profile_registry_method_and_retirement_labels_are_closed() -> None:
    methods = acceptance_methods()
    assert len({(item.name, item.version) for item in STRATEGIES}) == len(STRATEGIES)
    assert len({(item.name, item.version) for item in DISCOVERY_PROFILES}) == len(
        DISCOVERY_PROFILES
    )
    for item in STRATEGIES:
        assert re.fullmatch(r"[a-z][a-z0-9-]+", item.name)
        assert type(item.version) is int and item.version > 0
        assert item.gate in {"structural", "bounded", "native-owner"}
        assert type(item.preserves_client_identity) is bool
        assert item.retirement.strip()
        assert item.proving_tests and set(item.proving_tests) <= methods
    for profile in DISCOVERY_PROFILES:
        assert profile.direction in {"export", "import"}
        assert profile.service_types and profile.proving_tests
        assert set(profile.proving_tests) <= DISCOVERY_CONTRACT_METHODS


def synthetic_profile_data(kind: str) -> dict[str, Any]:
    data = strict_loads((ROOT / "examples/instance.json").read_bytes())
    extra = {
        "id": "example-redirect",
        "service": "example-web",
        "strategy": "host-port-redirect",
        "version": 1,
        "protocol": "tcp",
        "ports": {"first": 80, "last": 80},
        "target_ports": {"first": 27777, "last": 27777},
        "dependencies": ["example-publication"],
        "fallback_publication": None,
    }
    if kind == "fallback":
        extra.update(
            strategy="guest-direct-redirect",
            target_ports={"first": 8080, "last": 8080},
            dependencies=[],
            fallback_publication="example-publication",
        )
    data["transport"].append(extra)
    return data


def profile_digest(data: dict[str, Any]) -> str:
    instance = parse_instance(canonical_bytes(data) + b"\n")
    return resolved_profile_digest(instance, instance.transport_profile("example-redirect"))


@pytest.mark.parametrize(
    "mutation",
    ["anchor", "owner-label", "framework-artifact", "framework-version", "dependency-contract"],
)
def test_profile_receipt_digest_binds_owner_names_release_and_dependency_behavior(mutation) -> None:
    data = synthetic_profile_data("dependency")
    before = profile_digest(data)
    changed = copy.deepcopy(data)
    if mutation == "anchor":
        changed["names"]["pf_anchor"] = "com.apple/org.example.changed-forwarding"
    elif mutation == "owner-label":
        changed["names"]["pf_label"] = "org.example.changed-forwarding"
    elif mutation == "framework-artifact":
        changed["framework"]["artifact_sha256"] = "1" * 64
    elif mutation == "framework-version":
        major, minor, patch = changed["framework"]["version"].split(".")
        changed["framework"]["version"] = f"{major}.{minor}.{int(patch) + 1}"
    else:
        # The redirect's own host port and dependency ID are unchanged. Its
        # publication now delivers to a different guest service endpoint.
        changed["transport"][0]["target_ports"] = {"first": 8081, "last": 8081}
    assert profile_digest(changed) != before


def test_profile_receipt_digest_binds_fallback_publication_host_port() -> None:
    data = synthetic_profile_data("fallback")
    before = profile_digest(data)
    changed = copy.deepcopy(data)
    # The direct target and fallback ID are unchanged. Degraded traffic uses a
    # different native LAN socket, which needs new content-bound acceptance.
    changed["transport"][0]["ports"] = {"first": 27778, "last": 27778}
    assert profile_digest(changed) != before


@pytest.mark.parametrize("last", [51000, 51031, 52023, 65535])
def test_named_udp_range_never_qualifies_native_behavior_or_lifts_stage_gate(last) -> None:
    data = strict_loads((ROOT / "examples/instance.json").read_bytes())
    data["port_ranges"][0]["last"] = last
    instance = parse_instance(canonical_bytes(data) + b"\n")
    profile = instance.transport_profile("example-return")
    assert profile.ports is not None and profile.ports.range == "example-range"
    assert instance.workload(profile.service).automatic_port_range == profile.ports.range
    assert not ACCEPTED_PLATFORMS
    # A strictly valid and single-sourced range says nothing about native first
    # packet behavior, socket capacity, state invalidation or heard audio.
    with pytest.raises(StageNotQualified):
        require_mutation_qualified("privileged-owner-mutation")

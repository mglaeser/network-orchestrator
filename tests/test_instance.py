"""Canonical instance/property invariants; synthetic data, no host operations."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netorch.codec import canonical_bytes
from netorch.instance import (
    InstanceError,
    canonical_instance_bytes,
    instance_contract_digest,
    instance_digest,
    instance_to_dict,
    load_instance,
    parse_instance,
    read_data,
    resolve_ports,
    resolved_discovery_digest,
    resolved_names,
    resolved_profile_digest,
    validate_instance,
    verify_release,
)
from netorch.platform_contract import ACCEPTED_PLATFORMS, candidate_matches
from netorch.profile_library import DISCOVERY_PROFILES, STRATEGIES, discovery_profile, strategy

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/instance.json"


@pytest.fixture
def instance_data() -> dict[str, Any]:
    return json.loads(EXAMPLE.read_bytes())


def parse(data: dict[str, Any]) -> Any:
    return parse_instance(canonical_bytes(data) + b"\n")


def test_canonical_roundtrip(instance_data: dict[str, Any]) -> None:
    instance = load_instance(EXAMPLE)
    assert canonical_instance_bytes(instance) == EXAMPLE.read_bytes()
    assert instance_to_dict(instance) == instance_data
    assert instance_digest(instance) == instance_digest(parse(instance_data))


@pytest.mark.parametrize(
    "raw",
    [b"{}{}", b'{"x":1,"x":2}', b'{"x":NaN}', b"\xff", b"[" * 40 + b"]" * 40, b" " * 1_048_577],
)
def test_strict_input_rejected(raw: bytes) -> None:
    with pytest.raises(InstanceError):
        parse_instance(raw)


@pytest.mark.parametrize("change", ["indent", "newline", "space", "version", "case", "unknown"])
def test_committed_canonical_shape(instance_data: dict[str, Any], change: str) -> None:
    raw = canonical_bytes(instance_data) + b"\n"
    if change == "indent":
        raw = json.dumps(instance_data, indent=2).encode()
    elif change == "newline":
        raw += b"\n"
    elif change == "space":
        raw = b" " + raw
    elif change == "version":
        instance_data["schema_version"] = 99
        raw = canonical_bytes(instance_data) + b"\n"
    elif change == "case":
        instance_data["Instance"] = instance_data.pop("instance")
        raw = canonical_bytes(instance_data) + b"\n"
    else:
        instance_data["plugin"] = {}
        raw = canonical_bytes(instance_data) + b"\n"
    with pytest.raises(InstanceError):
        parse_instance(raw)


@pytest.mark.parametrize(
    "value",
    [
        "$(id)",
        "${HOME}",
        "{{host}}",
        "`id`",
        "/usr/bin/python3",
        "rdr on example inet proto udp",
        "203.0.113.55",
    ],
)
def test_instance_rejects_code_and_unknown_keys(instance_data: dict[str, Any], value: str) -> None:
    instance_data["host"]["lan"]["hardware_id"] = value
    with pytest.raises(InstanceError):
        parse(instance_data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("ipv4", "::1"),
        ("ipv4", "198.51.100.0"),
        ("ipv4", "127.0.0.1"),
        ("cidr", "0.0.0.0/0"),
        ("cidr", "198.51.100.10/24"),
        ("ipv4", "203.0.113.10"),
    ],
)
def test_instance_has_one_lan_and_no_live_guest_addresses(
    instance_data: dict[str, Any], field: str, value: str
) -> None:
    instance_data["host"]["lan"][field] = value
    with pytest.raises(InstanceError):
        parse(instance_data)


@pytest.mark.parametrize(
    "section", ["workloads", "port_ranges", "transport", "discovery", "lifecycle_tools"]
)
def test_duplicate_identifiers(instance_data: dict[str, Any], section: str) -> None:
    instance_data[section].append(copy.deepcopy(instance_data[section][0]))
    with pytest.raises(InstanceError):
        parse(instance_data)


@pytest.mark.parametrize(
    "change",
    [
        "unknown",
        "bad-version",
        "tcp-return",
        "copy-range",
        "missing-service",
        "missing-range",
        "range-width",
        "direction",
        "self-cycle",
    ],
)
def test_unknown_strategy_or_version_is_rejected(
    instance_data: dict[str, Any], change: str
) -> None:
    item = instance_data["transport"][1]
    if change == "unknown":
        item["strategy"] = "custom-script"
    elif change == "bad-version":
        item["version"] = 2
    elif change == "tcp-return":
        item["protocol"] = "tcp"
    elif change == "copy-range":
        item["ports"] = {"first": 51000, "last": 51031}
    elif change == "missing-service":
        item["service"] = "missing"
    elif change == "missing-range":
        item["ports"] = {"range": "missing"}
    elif change == "range-width":
        instance_data["transport"][0]["target_ports"]["last"] += 1
    elif change == "direction":
        instance_data["discovery"][0]["direction"] = "import"
    else:
        item["dependencies"] = [item["id"]]
    with pytest.raises(InstanceError):
        parse(instance_data)


def test_udp_range_is_one_named_reference(instance_data: dict[str, Any]) -> None:
    instance = parse(instance_data)
    assert resolve_ports(instance, instance.transport[1].ports) == (51000, 51031)
    assert resolve_ports(instance, instance.transport[0].target_ports) == (8080, 8080)
    assert resolve_ports(instance, None) is None
    instance_data["port_ranges"][0]["last"] += 1
    changed = parse(instance_data)
    assert resolved_profile_digest(instance, instance.transport[1]) != resolved_profile_digest(
        changed, changed.transport[1]
    )
    assert resolved_discovery_digest(instance, instance.discovery[1]) != resolved_discovery_digest(
        changed, changed.discovery[1]
    )


def test_instance_rejects_overlapping_port_claims(instance_data: dict[str, Any]) -> None:
    duplicate = copy.deepcopy(instance_data["transport"][0])
    duplicate["id"] = "example-second"
    instance_data["transport"].append(duplicate)
    with pytest.raises(InstanceError, match="overlapping"):
        parse(instance_data)


def test_export_needs_own_publication(instance_data: dict[str, Any]) -> None:
    instance_data["discovery"][0]["service"] = "example-media"
    with pytest.raises(InstanceError, match="dependency"):
        parse(instance_data)


def test_dependency_cycle_is_bounded(instance_data: dict[str, Any]) -> None:
    instance_data["transport"][0]["dependencies"] = ["example-return"]
    instance_data["transport"][1]["dependencies"] = ["example-publication"]
    with pytest.raises(InstanceError, match="cycle"):
        parse(instance_data)


def test_host_redirect_and_direct_fallback_are_structural_data(
    instance_data: dict[str, Any],
) -> None:
    redirect = {
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
    instance_data["transport"].append(redirect)
    parse(instance_data)
    redirect["dependencies"] = []
    with pytest.raises(InstanceError):
        parse(instance_data)
    redirect["dependencies"] = ["example-publication"]
    redirect["strategy"] = "guest-direct-redirect"
    redirect["target_ports"] = {"first": 8080, "last": 8080}
    redirect["fallback_publication"] = "example-publication"
    parse(instance_data)
    redirect["target_ports"] = {"first": 8081, "last": 8081}
    with pytest.raises(InstanceError):
        parse(instance_data)


def test_alias_is_a_native_capability_not_a_fabricated_port_rule(
    instance_data: dict[str, Any],
) -> None:
    item = {
        "id": "example-alias",
        "service": "example-web",
        "strategy": "guest-lan-alias",
        "version": 1,
        "protocol": "ipv4",
        "ports": None,
        "target_ports": None,
        "dependencies": [],
        "fallback_publication": None,
    }
    instance_data["transport"].append(item)
    instance = parse(instance_data)
    assert strategy(item["strategy"], 1).gate == "native-owner"
    assert instance.transport[-1].ports is None
    item["ports"] = {"first": 1, "last": 65535}
    with pytest.raises(InstanceError):
        parse(instance_data)


@pytest.mark.parametrize(
    "change",
    [
        "overlap",
        "unknown-subject",
        "generated-no-hash",
        "authored-hash",
        "reversed",
        "traversal",
        "component-restart",
        "second-interface",
        "huge-namespace",
    ],
)
def test_authoring_claims_cannot_overlap(instance_data: dict[str, Any], change: str) -> None:
    if change == "overlap":
        instance_data["authoring"].append(copy.deepcopy(instance_data["authoring"][0]))
    elif change == "unknown-subject":
        instance_data["authoring"][0]["sections"] = ["workloads"]
        instance_data["authoring"][0]["subjects"] = ["missing"]
    elif change == "generated-no-hash":
        instance_data["authoring"][0]["mode"] = "generated"
    elif change == "authored-hash":
        instance_data["authoring"][0]["source_sha256"] = "1" * 64
    elif change == "reversed":
        instance_data["port_ranges"][0]["first"] = 60000
    elif change == "traversal":
        instance_data["workloads"][0]["contract"]["data_path"] = "../secret.json"
    elif change == "component-restart":
        instance_data["workloads"][1]["components"][0]["recovery"] = "restart-workload"
    elif change == "second-interface":
        instance_data["host"]["second_lan"] = {}
    else:
        instance_data["namespace"] = "x" * 64
    with pytest.raises(InstanceError):
        parse(instance_data)


def test_components_have_no_workload_restart_mapping(instance_data: dict[str, Any]) -> None:
    assert parse(instance_data).workloads[1].components[0].recovery == "component-owner"


def test_names_are_pinned_or_namespace_derived(instance_data: dict[str, Any]) -> None:
    first = parse(instance_data)
    names = resolved_names(first)
    assert names["coordinator_label"].startswith(first.namespace)
    instance_data["names"]["pf_anchor"] = "com.apple/example.pinned"
    second = parse(instance_data)
    assert resolved_names(second)["pf_anchor"] == "com.apple/example.pinned"
    assert resolved_names(second)["coordinator_label"] == names["coordinator_label"]


@given(st.integers(min_value=30000, max_value=49000), st.integers(min_value=1, max_value=32))
def test_profile_digest_binds_resolved_parameters(first: int, width: int) -> None:
    data = json.loads(EXAMPLE.read_bytes())
    before = parse(data)
    data["port_ranges"][0].update(first=first, last=first + width - 1)
    after = parse(data)
    assert resolve_ports(after, after.transport[1].ports) == (first, first + width - 1)
    assert resolved_profile_digest(before, before.transport[1]) != resolved_profile_digest(
        after, after.transport[1]
    )
    assert instance_contract_digest(before) != instance_contract_digest(after)


def test_candidate_platform_is_not_hardware_acceptance() -> None:
    assert candidate_matches("27.0.1", "26A434", "1.5.0")
    assert not candidate_matches("27.0.1", "26A434", "1.2.0")
    assert ACCEPTED_PLATFORMS == ()
    for item in STRATEGIES:
        assert strategy(item.name, item.version) == item
    for item in DISCOVERY_PROFILES:
        assert discovery_profile(item.name, item.version) == item
    with pytest.raises(ValueError):
        strategy("missing", 1)
    with pytest.raises(ValueError):
        discovery_profile("missing", 1)


def test_release_pin_verifies_exact_artifact(tmp_path: Path, instance_data: dict[str, Any]) -> None:
    artifact = tmp_path / "release.whl"
    artifact.write_bytes(b"reviewed artifact")
    instance_data["framework"]["artifact_sha256"] = hashlib.sha256(
        artifact.read_bytes()
    ).hexdigest()
    instance = parse(instance_data)
    assert verify_release(instance, artifact)
    artifact.write_bytes(b"different artifact")
    assert not verify_release(instance, artifact)
    artifact.unlink()
    artifact.symlink_to(EXAMPLE)
    with pytest.raises(OSError):
        read_data(artifact)


def test_directly_constructed_models_are_still_validated(instance_data: dict[str, Any]) -> None:
    with pytest.raises(InstanceError):
        validate_instance(replace(parse(instance_data), schema_version=2))
    assert (
        canonical_instance_bytes(parse_instance(json.dumps(instance_data), require_canonical=False))
        == EXAMPLE.read_bytes()
    )


def test_local_reads_reject_hardlinks_and_nonregular_files(tmp_path: Path) -> None:
    target = tmp_path / "data"
    target.write_bytes(b"data")
    os.link(target, tmp_path / "alias")
    with pytest.raises(InstanceError):
        read_data(target)
    with pytest.raises((InstanceError, OSError)):
        read_data(tmp_path)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(InstanceError):
        read_data(fifo)

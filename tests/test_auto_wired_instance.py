"""Optional wired intent is data, never a cached device name or new authority."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from netorch import wired_interface
from netorch.codec import canonical_bytes
from netorch.host_report import build_report, parse_host_evidence
from netorch.instance import (
    InstanceError,
    canonical_instance_bytes,
    instance_contract_digest,
    instance_digest,
    instance_to_dict,
    load_instance,
    parse_instance,
    resolved_discovery_digest,
    resolved_profile_digest,
)
from netorch.privacy import instance_literals

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/instance.json"


def declaration() -> dict[str, Any]:
    data = json.loads(EXAMPLE.read_bytes())
    data["host"]["lan"].update(selection="auto-wired", hardware_id=None)
    return data


def parsed(data: dict[str, Any]) -> Any:
    return parse_instance(canonical_bytes(data) + b"\n")


def test_legacy_bytes_and_all_resolved_digests_are_unchanged() -> None:
    instance = load_instance(EXAMPLE)
    assert instance.host.lan.selection is None
    assert canonical_instance_bytes(instance) == EXAMPLE.read_bytes()
    assert (
        instance_digest(instance)
        == "f0adf2a76ad106f1ed758b0ab9f05388a15b4e11934f37faa68e377190ff732e"
    )
    assert instance_contract_digest(instance) == (
        "bc7d92900c617507a7d1dfe150df3600fff3d5ad29c1a0a72b467779f16f7a9c"
    )
    assert [resolved_profile_digest(instance, p) for p in instance.transport] == [
        "c4a4f20fb44b4b46fcbdffd4b2a4205c4149faf106208260fe69ecc9dde88425",
        "080ed8c0a2d16eb4e54110730ed205c4aee77d117c4c8c6facb490c23780a208",
    ]
    assert [resolved_discovery_digest(instance, p) for p in instance.discovery] == [
        "a87cb58580aef982e565caa79bb489da0f3996ac5e1c3c45709c3811c6f1ff86",
        "3a399f2f69074be0231e436d0902815936a10c506b77ec7c6cdf609e002c7af3",
    ]


def test_dynamic_intent_roundtrip_changes_contract_without_pinning_observation() -> None:
    data = declaration()
    instance = parsed(data)
    assert instance_to_dict(instance) == data
    assert parsed(instance_to_dict(instance)) == instance
    legacy = load_instance(EXAMPLE)
    assert instance_digest(instance) != instance_digest(legacy)
    assert instance_contract_digest(instance) != instance_contract_digest(legacy)
    assert all(
        resolved_profile_digest(instance, p) != resolved_profile_digest(legacy, p)
        for p in instance.transport
    )
    assert all(
        resolved_discovery_digest(instance, p) != resolved_discovery_digest(legacy, p)
        for p in instance.discovery
    )
    literals = instance_literals(data)
    assert all(item.value not in {"auto-wired", "None"} for item in literals)
    assert any(item.value == data["host"]["lan"]["ipv4"] for item in literals)


@pytest.mark.parametrize(
    "updates",
    [
        {"hardware_id": "example-adapter"},
        {"link": "wifi"},
        {"selection": "en8"},
        {"selection": "route-default"},
        {"selection": None},
        {"selection": True},
        {"selection": ["auto-wired"]},
        {"ipv4": "auto"},
        {"ipv4": "0.0.0.0"},
    ],
)
def test_dynamic_policy_refuses_pins_fallbacks_and_implicit_addressing(
    updates: dict[str, Any],
) -> None:
    data = declaration()
    data["host"]["lan"].update(updates)
    with pytest.raises(InstanceError):
        parsed(data)


def test_null_hardware_identity_without_dynamic_policy_is_not_legacy_admission() -> None:
    data = declaration()
    del data["host"]["lan"]["selection"]
    with pytest.raises(InstanceError):
        parsed(data)


@pytest.mark.parametrize(
    "address,prefix",
    [
        ("240.0.0.10", "240.0.0.0/24"),
        ("0.1.2.3", "0.1.2.0/24"),
    ],
)
def test_dynamic_declaration_rejects_addresses_native_selector_cannot_admit(
    address: str,
    prefix: str,
) -> None:
    data = declaration()
    data["host"]["lan"].update(ipv4=address, cidr=prefix)
    with pytest.raises(InstanceError, match="unicast"):
        parsed(data)


def facts() -> list[dict[str, Any]]:
    ip = declaration()["host"]["lan"]["ipv4"]
    values = {
        "lan_interface": "en108",
        "lan_ipv4": ip,
        "lan_selection": {
            "mode": "auto-wired",
            "interface": "en108",
            "ipv4": ip,
            "selector_sha256": wired_interface.selector_digest(),
        },
    }
    return [
        {
            "key": key,
            "state": "present",
            "reason": "complete",
            "observed_at": 1000.0,
            "value": value,
        }
        for key, value in values.items()
    ]


def report(rows: list[dict[str, Any]]) -> dict[str, Any]:
    evidence = parse_host_evidence(
        {
            "schema_version": 1,
            "source": "synthetic",
            "observed_at": 1000.0,
            "facts": rows,
            "profiles": [],
        }
    )
    return build_report(parsed(declaration()), evidence, now=1000.0, data_directory=EXAMPLE.parent)


def lan_status(document: dict[str, Any]) -> str:
    return next(row["status"] for row in document["requirements"] if row["id"] == "LAN-IDENTITY")


def test_dynamic_proof_needs_no_pinned_mac_but_does_not_confer_acceptance() -> None:
    document = report(facts())
    assert lan_status(document) == "unverified"
    assert document["fully_served"] is False
    assert document["mutation_available"] is False


@pytest.mark.parametrize("key", ["lan_interface", "lan_ipv4", "lan_selection"])
@pytest.mark.parametrize("problem", ["missing", "stale", "future", "unknown", "mismatch"])
def test_dynamic_proof_fails_on_missing_stale_or_inconsistent_sample(
    key: str, problem: str
) -> None:
    rows = facts()
    target = next(row for row in rows if row["key"] == key)
    if problem == "missing":
        rows.remove(target)
    elif problem == "stale":
        target["observed_at"] = 699.0
    elif problem == "future":
        target["observed_at"] = 1001.0
    elif problem == "unknown":
        target.update(state="unknown", reason="incomplete", value=None)
    elif key == "lan_interface":
        target["value"] = "en109"
    elif key == "lan_ipv4":
        target["value"] = "192.0.2.20"
    else:
        target["value"]["selector_sha256"] = "0" * 64
    assert lan_status(report(rows)) == "not-fulfilled"


@pytest.mark.parametrize(
    "field,value",
    [
        ("mode", "en8"),
        ("interface", "auto-wired"),
        ("interface", "en8\nen9"),
        ("ipv4", "0.0.0.0"),
        ("ipv4", "192.0.2.010"),
        ("selector_sha256", "bad"),
    ],
)
def test_selection_proof_has_closed_typed_shape(field: str, value: object) -> None:
    rows = facts()
    rows[-1]["value"][field] = value
    with pytest.raises(InstanceError):
        report(rows)


def test_proof_is_invalidated_if_packaged_selector_cannot_be_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = copy.deepcopy(facts())

    def unavailable() -> str:
        raise PermissionError("private path must not escape")

    monkeypatch.setattr(wired_interface, "selector_digest", unavailable)
    assert lan_status(report(rows)) == "not-fulfilled"

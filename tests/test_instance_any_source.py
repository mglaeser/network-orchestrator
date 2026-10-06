"""The instance side of the unrestricted source: one spelling, one eligible strategy.

A row without the member is LAN-scoped and has exactly the bytes and digests it had
before the member existed. The literal values below were taken from that release.
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch.codec import canonical_bytes
from netorch.host_report import build_report, empty_evidence
from netorch.instance import (
    InstanceError,
    canonical_instance_bytes,
    instance_contract_digest,
    instance_digest,
    instance_to_dict,
    load_instance,
    parse_instance,
    resolved_discovery_digest,
    resolved_profile,
    resolved_profile_digest,
    validate_instance,
)
from netorch.instance_model import Instance

ROOT = Path(__file__).parents[1]
REDIRECT = "example-redirect"
PUBLICATION = "example-publication"

# Taken from the release before the setting existed (examples of that release).
BASE = {
    "instance.json": {
        "file_sha256": "d22664f2dadc18ba4cf907479db29340b4af4bc97795c7cd569ddcb8a3285518",
        "instance_digest": "f0adf2a76ad106f1ed758b0ab9f05388a15b4e11934f37faa68e377190ff732e",
        "contract_digest": "bc7d92900c617507a7d1dfe150df3600fff3d5ad29c1a0a72b467779f16f7a9c",
        "profiles": {
            "example-publication": (
                "c4a4f20fb44b4b46fcbdffd4b2a4205c4149faf106208260fe69ecc9dde88425"
            ),
            "example-return": "080ed8c0a2d16eb4e54110730ed205c4aee77d117c4c8c6facb490c23780a208",
        },
        "discovery": {
            "example-export": "a87cb58580aef982e565caa79bb489da0f3996ac5e1c3c45709c3811c6f1ff86",
            "example-import": "3a399f2f69074be0231e436d0902815936a10c506b77ec7c6cdf609e002c7af3",
        },
        "report_sha256": "16f451c0d6b69b74c2dc56975767e275e9954f1129e78f3cb1490b5dd9ef728a",
    },
    "instance-structural.json": {
        "file_sha256": "3656fa2b945b829525f03508b145c6993c7adfcd89bc83c7559f0b3086bf449a",
        "instance_digest": "345a770371a6dc244234050cd606dd5222d277782a2c27529bc568f5fb92bb23",
        "contract_digest": "6489191df8f66f366323fcd61091c69a45bc2676f5f215e25f6a218674a3fa5e",
        "profiles": {
            "example-publication": (
                "d9e1f0bbf592e18a6a6ff88177539f55f092748a84953a4eba984390401e24b4"
            ),
        },
        "discovery": {
            "example-export": "397d48b2f0097fe344366050efc7ff1ffa9e9178445189ed3d8819c3c766e54d",
        },
        "report_sha256": "bef74bad8cbaf49eecc02a9bb9f31c1f9c07f98f366d32d0a2439c21d81b0090",
    },
}


def with_redirect(**members: Any) -> dict[str, Any]:
    """The example instance plus a host-port redirect in front of its publication."""
    data = instance_to_dict(load_instance(ROOT / "examples/instance.json"))
    publication = next(item for item in data["transport"] if item["id"] == PUBLICATION)
    data["transport"].append(
        {
            "dependencies": [PUBLICATION],
            "fallback_publication": None,
            "id": REDIRECT,
            "ports": {"first": 80, "last": 80},
            "protocol": "tcp",
            "service": publication["service"],
            "strategy": "host-port-redirect",
            "target_ports": dict(publication["ports"]),
            "version": 1,
            **members,
        }
    )
    return data


def parsed(data: dict[str, Any]) -> Instance:
    return parse_instance(canonical_bytes(data) + b"\n")


@pytest.mark.parametrize("name", sorted(BASE))
def test_checked_in_examples_keep_their_bytes_and_digests(name: str) -> None:
    raw = (ROOT / "examples" / name).read_bytes()
    instance = parse_instance(raw)
    expected = BASE[name]
    assert hashlib.sha256(raw).hexdigest() == expected["file_sha256"]
    assert canonical_instance_bytes(instance) == raw
    assert all("source_scope" not in item for item in instance_to_dict(instance)["transport"])
    assert instance_digest(instance) == expected["instance_digest"]
    assert instance_contract_digest(instance) == expected["contract_digest"]
    assert {
        item.id: resolved_profile_digest(instance, item) for item in instance.transport
    } == expected["profiles"]
    assert {
        item.id: resolved_discovery_digest(instance, item) for item in instance.discovery
    } == expected["discovery"]
    assert all("source_scope" not in resolved_profile(instance, p) for p in instance.transport)
    report = build_report(
        instance, empty_evidence(1000.0), now=1000.0, data_directory=ROOT / "examples"
    )
    assert hashlib.sha256(canonical_bytes(report)).hexdigest() == expected["report_sha256"]


@pytest.mark.parametrize("value", ["lan", "LAN", "wan", "", None, ["any"], True, 1])
def test_default_scope_has_no_spelling_in_the_instance(value: Any) -> None:
    assert parsed(with_redirect()).transport_profile(REDIRECT).source_scope == "lan"
    with pytest.raises(InstanceError, match="closed versioned schema"):
        parsed(with_redirect(source_scope=value))


def test_any_scope_is_declared_only_for_a_host_port_redirect() -> None:
    data = with_redirect(source_scope="any")
    instance = parsed(data)
    assert instance.transport_profile(REDIRECT).source_scope == "any"
    # One byte form: what was written is what is canonical.
    assert canonical_instance_bytes(instance) == canonical_bytes(data) + b"\n"
    assert parsed(instance_to_dict(instance)) == instance
    strategies = set()
    for index, profile in enumerate(data["transport"][:-1]):
        changed = copy.deepcopy(data)
        del changed["transport"][-1]["source_scope"]
        changed["transport"][index]["source_scope"] = "any"
        with pytest.raises(InstanceError, match="an unrestricted source is declared only"):
            parsed(changed)
        strategies.add(profile["strategy"])
    assert strategies == {"published-port", "guest-udp-range-forward"}


@pytest.mark.parametrize("strategy", ["guest-direct-redirect", "guest-lan-alias"])
def test_any_scope_is_refused_for_the_other_guest_strategies(strategy: str) -> None:
    data = with_redirect()
    row: dict[str, Any] = {
        "dependencies": [],
        "fallback_publication": None,
        "id": "example-guest",
        "ports": {"first": 53, "last": 53},
        "protocol": "tcp",
        "service": data["transport"][0]["service"],
        "strategy": strategy,
        "target_ports": None,
        "version": 1,
    }
    if strategy == "guest-lan-alias":
        row.update(ports=None, protocol="ipv4")
    data["transport"].append(row)
    assert parsed(data).transport_profile("example-guest").source_scope == "lan"
    data["transport"][-1]["source_scope"] = "any"
    with pytest.raises(InstanceError, match="an unrestricted source is declared only"):
        parsed(data)


def test_a_constructed_instance_is_validated_as_strictly_as_loaded_bytes() -> None:
    instance = parsed(with_redirect())

    def forged(identifier: str, value: Any) -> Instance:
        return replace(
            instance,
            transport=tuple(
                replace(item, source_scope=value) if item.id == identifier else item
                for item in instance.transport
            ),
        )

    validate_instance(forged(REDIRECT, "any"))
    with pytest.raises(InstanceError, match="an unrestricted source is declared only"):
        validate_instance(forged(PUBLICATION, "any"))
    for value in ("everything", None):
        with pytest.raises(InstanceError, match="closed versioned schema"):
            validate_instance(forged(REDIRECT, value))


def test_any_scope_still_needs_its_own_exact_publication_dependency() -> None:
    data = with_redirect(source_scope="any")
    data["transport"][-1]["dependencies"] = []
    with pytest.raises(InstanceError, match="own exact publication dependency"):
        parsed(data)


def test_any_scope_changes_only_the_digests_that_bind_that_profile() -> None:
    lan = parsed(with_redirect())
    any_source = parsed(with_redirect(source_scope="any"))
    assert instance_digest(any_source) != instance_digest(lan)
    assert instance_contract_digest(any_source) != instance_contract_digest(lan)
    for before, after in zip(lan.transport, any_source.transport, strict=True):
        same = resolved_profile_digest(lan, before) == resolved_profile_digest(any_source, after)
        assert same == (before.id != REDIRECT)
    for before, after in zip(lan.discovery, any_source.discovery, strict=True):
        assert resolved_discovery_digest(lan, before) == resolved_discovery_digest(
            any_source, after
        )
    # The profiles of the checked-in example keep the digests of the previous release
    # even beside the new row, and the redirect binds the publication it exposes.
    for identifier, expected in BASE["instance.json"]["profiles"].items():
        assert (
            resolved_profile_digest(any_source, any_source.transport_profile(identifier))
            == expected
        )
    redirect = any_source.transport_profile(REDIRECT)
    assert resolved_profile(any_source, redirect)["source_scope"] == "any"
    assert "source_scope" not in resolved_profile(lan, lan.transport_profile(REDIRECT))
    moved = with_redirect(source_scope="any")
    moved["transport"][0]["target_ports"] = {"first": 8081, "last": 8081}
    assert resolved_profile_digest(
        parsed(moved), parsed(moved).transport_profile(REDIRECT)
    ) != resolved_profile_digest(any_source, redirect)


def test_a_selection_that_depends_on_the_redirect_binds_its_scope() -> None:
    def selection(data: dict[str, Any]) -> str:
        export = next(item for item in data["discovery"] if item["id"] == "example-export")
        export["dependencies"] = [PUBLICATION, REDIRECT]
        instance = parsed(data)
        return resolved_discovery_digest(instance, instance.discovery[0])

    assert selection(with_redirect()) != selection(with_redirect(source_scope="any"))


def test_report_shows_the_scope_only_where_it_is_declared() -> None:
    def rows(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        report = build_report(
            parsed(data), empty_evidence(1000.0), now=1000.0, data_directory=ROOT / "examples"
        )
        return {row["id"]: row for row in report["profiles"]}

    lan, any_source = rows(with_redirect()), rows(with_redirect(source_scope="any"))
    assert any_source[REDIRECT]["source_scope"] == "any"
    assert all("source_scope" not in row for row in lan.values())
    assert all("source_scope" not in row for key, row in any_source.items() if key != REDIRECT)
    # The row differs in the declared scope and in the digest that binds it, nothing else.
    assert {
        key for key in any_source[REDIRECT] if any_source[REDIRECT][key] != lan[REDIRECT].get(key)
    } == {"source_scope", "desired_digest", "states"}
    assert any_source[PUBLICATION] == lan[PUBLICATION]
    assert any_source[REDIRECT]["gate"] == "structural"

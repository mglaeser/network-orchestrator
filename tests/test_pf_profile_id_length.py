"""A policy cannot name a root-owned identifier that the root owner's stores refuse."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import netorch.config as policy_module
import netorch.pf_owner as owner_module
from netorch.codec import canonical_bytes
from netorch.config import ConfigError, parse_config, to_dict, validate_config
from netorch.pf_owner import STRATEGY, Installation, PFError, admit, install, withdraw
from tests.test_pf_owner import ROOT, STAMP, approve_all, environment, run_pass

__all__ = ["environment"]

EXAMPLE = ROOT / "examples/network.json"
LIMIT = "limited to 63 characters"


def name(length: int) -> str:
    return "n" * length


def renamed(kind: str, old: str, new: str) -> dict[str, Any]:
    """The example policy with one identifier, and every reference to it, replaced."""
    policy = json.loads(EXAMPLE.read_text())
    if kind == "site":
        assert policy["site"] == old
        policy["site"] = new
        return policy
    collection, references = {
        "scope": ("scopes", [("profiles", "scope"), ("discovery", "scope")]),
        "owner": (
            "owners",
            [("services", "owner"), ("profiles", "owner"), ("discovery", "owner")],
        ),
        "service": ("services", [("profiles", "service"), ("discovery", "service")]),
        "profile": ("profiles", [("profiles", "fallback_publication")]),
        "discovery": ("discovery", []),
    }[kind]
    assert sum(item["id"] == old for item in policy[collection]) == 1
    for item in policy[collection]:
        if item["id"] == old:
            item["id"] = new
    for table, field in references:
        for item in policy[table]:
            if item.get(field) == old:
                item[field] = new
    if kind == "profile":
        for item in policy["discovery"]:
            item["dependencies"] = [new if x == old else x for x in item["dependencies"]]
    return policy


def test_the_bound_is_the_one_the_owner_stores_and_anchor_accept(environment: Any) -> None:
    bound = policy_module.ROOT_IDENTIFIER_LENGTH
    assert bound == 63
    root = environment[0]
    record = {
        "digest": "0" * 64,
        "approved_at": 1,
        "approved_by": "local-administrator",
        "risk_acknowledged": True,
    }

    def stored(identifier: str) -> None:
        root.write(
            "admissions.json",
            {"schema_version": 1, "strategy": STRATEGY, "profiles": {identifier: record}},
        )
        admit(root, "dns-tcp", acknowledge_bounded_risk=True, now=STAMP - 1)

    stored(name(bound))
    with pytest.raises(PFError, match="admission is damaged"):
        stored(name(bound + 1))

    def installation(owner: str) -> Installation:
        return Installation(owner, f"com.apple/netorch.{owner}", {}, "0" * 64, "/report.json")

    assert installation(name(bound)).owner == name(bound)
    with pytest.raises(PFError, match="identity"):
        installation(name(bound + 1))


@pytest.mark.parametrize("profile", ["dns-udp", "dns-tcp", "proxy-standard", "media-udp"])
def test_a_root_owned_profile_identifier_of_64_characters_is_refused(profile: str) -> None:
    policy = renamed("profile", profile, name(64))

    with pytest.raises(ConfigError, match=f"Profile {name(64)}: .*{LIMIT}"):
        parse_config(json.dumps(policy))

    parse_config(json.dumps(renamed("profile", profile, name(63))))


def test_an_external_root_owner_identifier_of_64_characters_is_refused() -> None:
    policy = renamed("owner", "site-forwarding", name(64))

    with pytest.raises(ConfigError, match=f"Owner {name(64)}: .*{LIMIT}"):
        parse_config(json.dumps(policy))

    parse_config(json.dumps(renamed("owner", "site-forwarding", name(63))))


def test_a_constructed_model_is_held_to_the_same_bound() -> None:
    config = parse_config(EXAMPLE.read_bytes())
    profiles = tuple(
        replace(item, id=name(64)) if item.id == "proxy-standard" else item
        for item in config.profiles
    )

    with pytest.raises(ConfigError, match=LIMIT):
        validate_config(replace(config, profiles=profiles))


@pytest.mark.parametrize(
    "kind,old",
    [
        ("site", "example-site"),
        ("scope", "wired-lan"),
        ("service", "resolver"),
        ("owner", "camera-manager"),
        ("owner", "bonjour-manager"),
        ("profile", "proxy-high"),
        ("profile", "camera-web"),
        ("discovery", "media-import"),
    ],
)
def test_identifiers_no_root_store_holds_keep_the_schema_bound(kind: str, old: str) -> None:
    parse_config(json.dumps(renamed(kind, old, name(64))))

    with pytest.raises(ConfigError, match="Schema violation"):
        parse_config(json.dumps(renamed(kind, old, name(65))))


def test_a_63_character_profile_is_admitted_activated_and_read_back(environment: Any) -> None:
    root, _, settings, backend, snapshots = environment
    policy = renamed("profile", "dns-udp", name(63))
    config = parse_config(json.dumps(policy))
    root.write("policy.json", to_dict(config))
    environment = (root, config, settings, backend, snapshots)

    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"

    assert f"# netorch:{name(63)}" in backend.rules
    assert root.read("live.json")["records"][name(63)]["active"] is True
    # The stores still read back: another admission and another pass succeed.
    admit(root, "dns-tcp", acknowledge_bounded_risk=True, now=STAMP - 1)
    assert run_pass(environment)["phase"] == "committed"


def test_the_installer_stores_nothing_for_a_policy_with_such_an_identifier(
    monkeypatch: Any, environment: Any, tmp_path: Path
) -> None:
    monkeypatch.setattr(owner_module, "protected_ancestors", lambda *args, **kwargs: None)
    policy, settings = tmp_path / "policy", tmp_path / "settings"
    policy.write_bytes(canonical_bytes(renamed("profile", "dns-udp", name(64))))
    settings.write_bytes(canonical_bytes(environment[2].to_dict()))
    destination = tmp_path / "new-root"

    with pytest.raises(ConfigError, match=LIMIT):
        install(destination, policy, settings, ROOT / "platform/macos/pf/backend.sh")

    assert not destination.exists()


def test_a_policy_installed_by_an_older_release_stores_nothing_and_can_be_withdrawn(
    environment: Any,
) -> None:
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    root, _, _, backend, _ = environment
    assert backend.rules
    admissions = root.read("admissions.json")
    # An older release accepted this policy; its long profile was never admitted.
    root.write("policy.json", renamed("profile", "dns-udp", name(64)))

    with pytest.raises(ConfigError, match=LIMIT):
        admit(root, name(64), acknowledge_bounded_risk=True, now=STAMP - 1)
    with pytest.raises(ConfigError, match=LIMIT):
        admit(root, "dns-tcp", acknowledge_bounded_risk=True, now=STAMP - 1)
    with pytest.raises(ConfigError, match=LIMIT):
        run_pass(environment)
    assert root.read("admissions.json") == admissions

    # Quiescence does not read the policy: the known rules can still be retired.
    assert withdraw(root, lambda root, settings: backend)["withdrawn"] is True
    assert backend.rules == ""

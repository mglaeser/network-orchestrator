"""A host redirect may declare an unrestricted source; nothing else may, and nothing moves.

The default (`lan`) has no spelling in the canonical policy, so every digest, rule,
stored record and review output of a policy that does not use the setting is the one
the previous release produced. The literal values below were taken from that release.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest

import netorch.config as config_module
import netorch.pf as preview_module
from netorch.cli import main as user_main
from netorch.codec import canonical_bytes, digest, strict_load, strict_loads
from netorch.config import (
    ConfigError,
    config_digest,
    load_config,
    parse_config,
    profile_digest,
    to_dict,
    validate_config,
)
from netorch.mock import initial_snapshot, mock_admissions
from netorch.model import Config, Profile, Scope
from netorch.pf import render
from netorch.pf_owner import PFError, admit, admitted_digest, main, reconcile, render_profile
from netorch.planner import Action, Plan, plan
from netorch.state import (
    Admission,
    Intent,
    Observation,
    Snapshot,
    admissions_from_dict,
    admissions_to_dict,
)
from netorch.storage import Store
from tests.test_pf_owner import STAMP, environment, legacy_cli_conformance, run_pass

__all__ = ["environment", "legacy_cli_conformance"]

ROOT = Path(__file__).parents[1]
REDIRECT = "proxy-standard"
PUBLICATION = "proxy-high"
ANY = {"source_scope": "any"}

# Taken from the release before the setting existed (examples of that release).
BASE_PROFILE_DIGESTS = {
    "network.json": {
        "camera-web": "15180d8db52f7551664e23914523a7184181ad118e4b96953f960b77fd38e12d",
        "dns-tcp": "e7eb1670ea57d2f18c5cc67eff0115f731308b26a66a968d7a837134308e0b50",
        "dns-udp": "99e950f630af1e1011d053afb465e98d5a9edd88a6c3ac0e181c7a59a7580bbc",
        "media-udp": "edf2ef7ac815bc595d7ee83dbfbfcc98be4850ef22595d35ba20f8385091651a",
        "proxy-high": "231765994c35405272f0a3d59be131552141a2737e37c5098fb496aacda44273",
        "proxy-standard": "18c0d0d684309f20fec35ed22617de1ce8b5fba76b0c985dbd3e89df6c85f67f",
    },
    "network-dns-fallback.json": {
        "camera-web": "15180d8db52f7551664e23914523a7184181ad118e4b96953f960b77fd38e12d",
        "dns-native-tcp": "fdbad834b6e706d241ac45197246531d63a6272a6177d56c9704e2c7b3483f47",
        "dns-native-udp": "ac430273e3d43a8998c4d52fc2957677a662ef9143de9e9936feb1fe55966462",
        "dns-tcp": "4580de32bf605d52a05c29ee7399facd6cb414c0bc0dd2faf5a3ad20750d76af",
        "dns-udp": "8ad024133a236d958387b383d8b961293c7f5ebac1ea1251dca35a37cf829647",
        "media-udp": "edf2ef7ac815bc595d7ee83dbfbfcc98be4850ef22595d35ba20f8385091651a",
        "proxy-high": "231765994c35405272f0a3d59be131552141a2737e37c5098fb496aacda44273",
        "proxy-standard": "18c0d0d684309f20fec35ed22617de1ce8b5fba76b0c985dbd3e89df6c85f67f",
    },
}
BASE_CONFIG_DIGESTS = {
    "network.json": "bfb7a0957461cf456564604ee10a94f3af0253c980dde45c73a1c7ed355548f5",
    "network-dns-fallback.json": "937f20c1c24ddefadb3d20d8ab8ee2ecf13983e1d0a800a6ff5f4142572a7651",
}
BASE_CANONICAL_POLICY_SHA256 = {
    "network.json": "1fbb9601273c11e82d26781b31e9b2754340e10695b26980c470f2534b99d432",
    "network-dns-fallback.json": "c6bd9e6c00b3c49229ea3aad3eb6485c0623b8320214d96f714aba46926e9219",
}
# SHA-256 of the rule text the root owner renders, guest targets at 198.51.100.77.
BASE_RULE_SHA256 = {
    "dns-tcp": "5fdb7b166cf9dc06e66de0e200d982c88641153c74aa52c6f3c97e46a8de9820",
    "dns-tcp#fallback": "3037f5c674abae2233dde01d9a6d7df2311f02811d312e1d03dd03197e41f660",
    "dns-udp": "6241b3c638f1091d7ac9342d6f9de1ad89b423cc808bbf469c0e55d932c608f4",
    "dns-udp#fallback": "d1f7f3bcf2c33a8a8db5d4c5696f8370ccefe329d50e75547a6300e997ec225f",
    "media-udp": "aa49a239c43cfb11c8e10d5a1736ed9559bf994b23ddb5033f0ce8afe8e0da4f",
    "proxy-standard": "2d100e17f2e5c26870aee2d26ca9c831e7884602365e25e308ea2e0f1c027b6d",
}
# SHA-256 of the complete `review-admission` output of the unprivileged command line.
BASE_USER_REVIEW_SHA256 = {
    "camera-web": "4f12c5c54827561048e1076bfb3bef2627aef3aa7961655395423cf52d5809d8",
    "dns-tcp": "b18bad0b26196546ab95ce88f629bedf00c38dd6ef1557fcb03ca602b86c6ba5",
    "dns-udp": "79fc9b6580d4e4650d9c17188271720b0cb086c6a210a167428b4a77fd01c074",
    "media-udp": "c9c5c58a56fb6671a46405e5be666b64ae6c1c878aff0f3548631cf61c1a3c3b",
    "proxy-high": "3b44f00e77508076790a7bbebbd5f3bc29ff79099576f20db195e304a74d803d",
    "proxy-standard": "8746a51c90a44113400356cfe212b5ec6541991a3de367c96cc25b55c018f617",
}
BASE_PREVIEW_SHA256 = "7b88eda46e84d16b8f11c177840b35ddad2f6f8338f4c7209243025ed82d11d2"
BASE_STORED_POLICY_SHA256 = "1fbb9601273c11e82d26781b31e9b2754340e10695b26980c470f2534b99d432"
BASE_LIVE_RECORDS_SHA256 = "dee76e6021fdc0ab4a4c83eac9d86ed0af7900f7438bf6fbe45ed2271ef7749a"
# The digest this change introduces for the example redirect once it is declared `any`.
ANY_SOURCE_DIGEST = "9dd55f2d87e3f217d3f35e9eb5a627346e86f8a0db09cde91b827c022aa6252d"
ANY_RULE_SHA256 = "62159a44853a1209ddc218d06180739dc9b2fe5d76e81986dd89ab4b7571239e"

Environment = tuple[Store, Config, Any, Any, list[Snapshot]]


def sha256(text: str | bytes) -> str:
    return hashlib.sha256(text.encode() if isinstance(text, str) else text).hexdigest()


def policy(name: str = "network.json", **changes: Any) -> dict[str, Any]:
    """The canonical example policy with members of named profiles replaced."""
    raw = to_dict(load_config(ROOT / "examples" / name))
    for identifier, fields in changes.items():
        next(item for item in raw["profiles"] if item["id"] == identifier.replace("_", "-")).update(
            fields
        )
    return raw


def parsed(raw: dict[str, Any]) -> Config:
    return parse_config(canonical_bytes(raw))


def wide() -> Config:
    return parsed(policy(proxy_standard=ANY))


def redirect_rule(config: Config, source: str) -> str:
    """The one rule of the example redirect, built from the scope it belongs to."""
    profile = config.profile(REDIRECT)
    scope = config.scope(profile.scope)
    return (
        f"rdr on {scope.interface} inet proto tcp from {source} to {scope.host_ipv4} "
        f"port 80 -> {scope.host_ipv4} port 8080 # netorch:{REDIRECT}\n"
    )


def host(config: Config) -> str:
    return config.scope(config.profile(REDIRECT).scope).host_ipv4


def verified(config: Config, snapshot: Snapshot, *identifiers: str) -> Snapshot:
    """The mock snapshot with the named native publications read back present."""
    profiles = dict(snapshot.profiles)
    for identifier in identifiers:
        profile = config.profile(identifier)
        endpoint = snapshot.services[profile.service]
        profiles[identifier] = Observation(
            "present",
            "verified",
            snapshot.observed_at,
            endpoint.generation,
            {
                "policy_digest": profile_digest(config, profile),
                "target_ipv4": endpoint.data["ipv4"],
                "target_generation": endpoint.generation,
                "network_generation": snapshot.network_generation,
                "states": [],
            },
        )
    return replace(snapshot, profiles=profiles)


def install_policy(environment: Environment, config: Config) -> None:
    """What a reviewed installation does to the protected desired snapshot."""
    environment[0].write("policy.json", to_dict(config))


def published(environment: Environment) -> tuple[dict[str, Any], Snapshot]:
    """One pass, with the snapshot the owner hands to its report writer."""
    root, _, _, backend, snapshots = environment
    reports: list[Snapshot] = []
    result = reconcile(
        root,
        lambda config, settings: snapshots[-1],
        lambda root, settings: backend,
        now=lambda: STAMP,
        report=lambda settings, snapshot: reports.append(snapshot),
    )
    return result, reports[-1]


# ---- version rule: a policy that does not use the setting is untouched


@pytest.mark.parametrize("name", sorted(BASE_PROFILE_DIGESTS))
def test_default_source_scope_is_left_out_of_the_canonical_policy(name: str) -> None:
    config = load_config(ROOT / "examples" / name)
    assert all("source_scope" not in item for item in to_dict(config)["profiles"])
    assert sha256(canonical_bytes(to_dict(config))) == BASE_CANONICAL_POLICY_SHA256[name]
    assert config_digest(config) == BASE_CONFIG_DIGESTS[name]
    validate_config(config)


@pytest.mark.parametrize("name", sorted(BASE_PROFILE_DIGESTS))
def test_existing_profile_digests_equal_the_pinned_example_admissions(name: str) -> None:
    config = load_config(ROOT / "examples" / name)
    assert {
        profile.id: profile_digest(config, profile) for profile in config.profiles
    } == BASE_PROFILE_DIGESTS[name]
    if name == "network.json":
        pinned = strict_load(ROOT / "examples/admissions.json")
        assert {key: value["digest"] for key, value in pinned.items()} == BASE_PROFILE_DIGESTS[name]


@pytest.mark.parametrize("name", sorted(BASE_PROFILE_DIGESTS))
def test_existing_rules_keep_their_bytes(name: str) -> None:
    config = load_config(ROOT / "examples" / name)
    rendered: dict[str, str] = {}
    for profile in config.profiles:
        if profile.kind == "publication":
            continue
        scope = config.scope(profile.scope)
        target = scope.host_ipv4 if profile.kind == "host-redirect" else "198.51.100.77"
        rendered[profile.id] = sha256(render_profile(config, profile, target))
        if profile.fallback_publication is not None:
            rendered[profile.id + "#fallback"] = sha256(
                render_profile(
                    config, profile, scope.host_ipv4, effective_strategy="degraded-fallback"
                )
            )
    assert rendered == {key: value for key, value in BASE_RULE_SHA256.items() if key in rendered}
    assert ("dns-udp#fallback" in rendered) == (name == "network-dns-fallback.json")
    assert sha256(redirect_rule(config, config.scopes[0].lan_cidr)) == BASE_RULE_SHA256[REDIRECT]


def test_explicit_lan_source_scope_is_the_same_policy_as_leaving_it_out() -> None:
    base = parsed(policy())
    explicit = parsed(policy(proxy_standard={"source_scope": "lan"}))
    assert explicit == base
    assert to_dict(explicit) == to_dict(base)
    assert config_digest(explicit) == config_digest(base) == BASE_CONFIG_DIGESTS["network.json"]
    assert profile_digest(explicit, explicit.profile(REDIRECT)) == profile_digest(
        base, base.profile(REDIRECT)
    )
    # The default may be spelled for every kind; it changes nothing anywhere.
    every = policy()
    for item in every["profiles"]:
        item["source_scope"] = "lan"
    assert to_dict(parsed(every)) == to_dict(base)


# ---- validation: closed values, one eligible shape


@pytest.mark.parametrize("value", ["wan", "ANY", "0.0.0.0/0", "", None, ["any"], True, 0])
def test_unknown_source_scope_is_refused_by_the_closed_schema(value: Any) -> None:
    with pytest.raises(ConfigError, match="Schema violation at profiles/3/source_scope"):
        parsed(policy(proxy_standard={"source_scope": value}))
    # A constructed model is validated as strictly as loaded text.
    forged = replace(
        parsed(policy()),
        profiles=tuple(
            replace(profile, source_scope=value) if profile.id == REDIRECT else profile
            for profile in parsed(policy()).profiles
        ),
    )
    with pytest.raises(ConfigError, match="Schema violation"):
        validate_config(forged)


@pytest.mark.parametrize("identifier", ["dns-udp", "dns-tcp", "media-udp", "proxy-high"])
def test_any_source_is_refused_for_everything_but_a_host_redirect(identifier: str) -> None:
    with pytest.raises(ConfigError, match=f"Profile {identifier}: an unrestricted source"):
        parsed(policy(**{identifier: ANY}))
    assert parsed(policy(**{identifier: {"source_scope": "lan"}})) == parsed(policy())


def test_any_source_is_refused_for_a_host_redirect_declared_bounded() -> None:
    bounded = {"kind": "bounded", "max_age_seconds": 30, "unknown_limit": 1, "statement": "x"}
    assert (
        parsed(policy(proxy_standard={"safety": bounded})).profile(REDIRECT).source_scope == "lan"
    )
    with pytest.raises(ConfigError, match="unrestricted source"):
        parsed(policy(proxy_standard={**ANY, "safety": bounded}))


@pytest.mark.parametrize("identifier", ["dns-udp", "dns-tcp"])
def test_any_source_is_refused_for_a_fallback_capable_direct_profile(identifier: str) -> None:
    name = "network-dns-fallback.json"
    assert parsed(policy(name)).profile(identifier).fallback_publication is not None
    with pytest.raises(ConfigError, match="unrestricted source"):
        parsed(policy(name, **{identifier: ANY}))
    # The fallback's own publication is not eligible either.
    with pytest.raises(ConfigError, match="unrestricted source"):
        parsed(policy(name, dns_native_tcp=ANY))


def test_any_source_still_needs_its_own_publication_target() -> None:
    raw = policy(proxy_standard=ANY)
    raw["profiles"] = [item for item in raw["profiles"] if item["id"] != PUBLICATION]
    with pytest.raises(ConfigError, match="own publication target"):
        parsed(raw)
    # Two candidates are no more acceptable than none.
    doubled = policy(proxy_standard=ANY)
    second = dict(next(item for item in doubled["profiles"] if item["id"] == PUBLICATION))
    second.update(id="proxy-wide", ports={"first": 8080, "last": 8081}, target_ports=None)
    first = next(item for item in doubled["profiles"] if item["id"] == PUBLICATION)
    first.update(ports={"first": 8079, "last": 8080}, target_ports=None)
    doubled["profiles"].append(second)
    with pytest.raises(ConfigError, match=f"Profile {REDIRECT}: host redirect requires its own"):
        parsed(doubled)


def test_backing_publication_is_the_one_the_planner_gates_on() -> None:
    config = wide()
    assert config_module.backing_publication(config, config.profile(REDIRECT)).id == PUBLICATION
    for profile in config.profiles:
        if profile.kind != "host-redirect":
            with pytest.raises(ConfigError, match="own publication target"):
                config_module.backing_publication(config, profile)


# ---- rendering


def test_any_source_host_redirect_renders_from_any_to_the_host_address() -> None:
    lan, any_source = parsed(policy()), wide()
    scope = lan.scopes[0]
    assert render_profile(lan, lan.profile(REDIRECT), scope.host_ipv4) == redirect_rule(
        lan, scope.lan_cidr
    )
    rule = render_profile(any_source, any_source.profile(REDIRECT), scope.host_ipv4)
    assert rule == redirect_rule(any_source, "any")
    assert sha256(rule) == ANY_RULE_SHA256
    # The two differ in exactly the source token.
    assert rule.replace(" from any ", f" from {scope.lan_cidr} ") == redirect_rule(
        lan, scope.lan_cidr
    )
    # Every other profile of the same policy keeps the scope's prefix as its source.
    for profile in any_source.profiles:
        if profile.kind in {"guest-direct", "udp-return"}:
            text = render_profile(any_source, profile, "198.51.100.77")
            assert sha256(text) == BASE_RULE_SHA256[profile.id]
            assert " any " not in text and scope.lan_cidr in text


def test_renderer_itself_never_emits_any_for_a_guest_target_or_a_return_pair() -> None:
    config = wide()
    redirect = config.profile(REDIRECT)
    refused = "an unrestricted source is rendered only for a host redirect"
    with pytest.raises(PFError, match=refused):
        render_profile(config, redirect, "198.51.100.77")  # not the host's own address
    with pytest.raises(PFError, match=refused):
        render_profile(config, redirect, host(config), effective_strategy="degraded-fallback")
    # Objects that never passed the validator must not reach the kernel text either.
    for identifier in ("dns-udp", "dns-tcp", "media-udp"):
        forged = replace(config.profile(identifier), source_scope="any")
        for target in ("198.51.100.77", host(config)):
            for strategy in (None, "degraded-fallback"):
                with pytest.raises(PFError, match=refused):
                    render_profile(config, forged, target, effective_strategy=strategy)
    bounded = replace(redirect, safety=replace(redirect.safety, kind="bounded", statement="x"))
    with pytest.raises(PFError, match=refused):
        render_profile(config, bounded, host(config))
    values: tuple[Any, ...] = ("everything", "", "ANY", None)
    for value in values:
        with pytest.raises(PFError, match=refused):
            render_profile(config, replace(redirect, source_scope=value), host(config))
    # A publication is still refused for what it is.
    with pytest.raises(PFError, match="never PF"):
        render_profile(
            config, replace(config.profile(PUBLICATION), source_scope="any"), host(config)
        )


@pytest.mark.parametrize("name", sorted(BASE_PROFILE_DIGESTS))
def test_no_combination_of_declarations_widens_a_guest_or_return_rule(name: str) -> None:
    """Every subset of profiles declared `any`: accepted or refused, never wider."""
    base = load_config(ROOT / "examples" / name)
    eligible = {
        profile.id
        for profile in base.profiles
        if profile.kind == "host-redirect" and profile.safety.kind == "structural"
    }
    assert eligible == {REDIRECT}
    identifiers = [profile.id for profile in base.profiles]
    accepted = 0
    for mask in range(1 << len(identifiers)):
        chosen = {identifier for bit, identifier in enumerate(identifiers) if mask >> bit & 1}
        raw = to_dict(base)
        for item in raw["profiles"]:
            if item["id"] in chosen:
                item["source_scope"] = "any"
        if not chosen <= eligible:
            with pytest.raises(ConfigError, match="an unrestricted source needs a structural"):
                parsed(raw)
            continue
        accepted += 1
        config = parsed(raw)
        for profile in config.profiles:
            if profile.kind == "publication":
                continue
            scope = config.scope(profile.scope)
            targets = [
                (scope.host_ipv4 if profile.kind == "host-redirect" else "198.51.100.77", None)
            ]
            if profile.fallback_publication is not None:
                targets.append((scope.host_ipv4, "degraded-fallback"))
            for target, strategy in targets:
                text = render_profile(config, profile, target, effective_strategy=strategy)
                sources = {
                    words[words.index("from") + 1]
                    for words in (line.split() for line in text.splitlines())
                    if words[0] == "rdr"
                }
                assert sources == ({"any"} if profile.id in chosen else {scope.lan_cidr})
                # The outbound half of a return pair is bounded by the same prefix.
                assert all(
                    words[words.index("to") + 1] == scope.lan_cidr
                    for words in (line.split() for line in text.splitlines())
                    if words[0] == "nat"
                )
    assert accepted == 2  # nothing declared, and the one structural host redirect


def test_preview_of_the_example_policy_keeps_its_bytes() -> None:
    lan = parsed(policy())
    snapshot = verified(lan, initial_snapshot(lan), PUBLICATION, "camera-web")
    before = render(lan, snapshot, mock_admissions(lan), Intent(), 1000)
    assert sha256(before) == BASE_PREVIEW_SHA256
    assert redirect_rule(lan, lan.scopes[0].lan_cidr).strip() in before.splitlines()


def test_preview_renders_the_same_source_as_the_owner() -> None:
    lan = parsed(policy())
    snapshot = verified(lan, initial_snapshot(lan), PUBLICATION, "camera-web")
    before = render(lan, snapshot, mock_admissions(lan), Intent(), 1000)

    config = wide()
    snapshot = verified(config, initial_snapshot(config), PUBLICATION, "camera-web")
    after = render(config, snapshot, mock_admissions(config), Intent(), 1000)
    owner_rule = render_profile(config, config.profile(REDIRECT), host(config))
    assert owner_rule.strip() in after.splitlines()
    # Nothing else in the preview moved, and nothing else matches every source.
    assert [line for line in after.splitlines() if "netorch:" + REDIRECT not in line] == [
        line for line in before.splitlines() if "netorch:" + REDIRECT not in line
    ]
    assert sum(" from any " in line for line in after.splitlines()) == 1
    # Without the verified publication the redirect is not previewed at all.
    unverified = render(config, initial_snapshot(config), mock_admissions(config), Intent(), 1000)
    assert " any " not in unverified


@pytest.mark.parametrize(
    "target,strategy",
    [("198.51.100.77", None), (None, "degraded-fallback")],
    ids=["guest-target", "fallback-in-effect"],
)
def test_preview_refuses_an_unrestricted_source_its_plan_does_not_justify(
    monkeypatch: pytest.MonkeyPatch, target: str | None, strategy: str | None
) -> None:
    """The preview has its own guard; a wrong plan cannot make it print the rule."""
    config = wide()
    snapshot = verified(config, initial_snapshot(config), PUBLICATION)
    owner = config.profile_owner(REDIRECT).id
    forged = Plan(
        "0" * 64,
        "0" * 64,
        0,
        (Action(REDIRECT, owner, "activate", "ready", target or host(config), "g", strategy),),
    )
    monkeypatch.setattr(preview_module, "plan", lambda *arguments: forged)
    with pytest.raises(ValueError, match="an unrestricted source is rendered only"):
        render(config, snapshot, mock_admissions(config), Intent(), 1000)


def test_preview_refuses_an_unrestricted_source_on_a_model_that_was_never_validated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = parsed(policy())
    forged_profile = replace(base.profile("dns-tcp"), source_scope="any")
    config = replace(
        base,
        profiles=tuple(forged_profile if p.id == "dns-tcp" else p for p in base.profiles),
    )
    owner = base.profile_owner("dns-tcp").id
    for target in ("198.51.100.77", base.scopes[0].host_ipv4):
        forged = Plan(
            "0" * 64, "0" * 64, 0, (Action("dns-tcp", owner, "activate", "ready", target, "g"),)
        )
        monkeypatch.setattr(preview_module, "plan", lambda *arguments, value=forged: value)
        with pytest.raises(ValueError, match="an unrestricted source is rendered only"):
            render(config, initial_snapshot(base), {}, Intent(), 1000)


# ---- digest


def test_any_source_has_its_own_digest_version_and_binds_the_publication() -> None:
    lan, any_source = parsed(policy()), wide()
    profile = any_source.profile(REDIRECT)
    service = any_source.service(profile.service)
    # The complete payload, written out: version 3 and the publication's own digest.
    expected = digest(
        {
            "digest_version": 3,
            "schema_version": 1,
            "profile": {
                key: value
                for key, value in asdict(profile).items()
                if key != "fallback_publication"
            },
            "scope": asdict(any_source.scope(profile.scope)),
            "service": asdict(service),
            "owner": asdict(any_source.profile_owner(profile)),
            "service_owner": asdict(any_source.owner(service.owner)),
            "address_family": "inet",
            "publication_profile_digest": BASE_PROFILE_DIGESTS["network.json"][PUBLICATION],
        }
    )
    assert asdict(profile)["source_scope"] == "any"
    assert profile_digest(any_source, profile) == expected == ANY_SOURCE_DIGEST
    assert expected != BASE_PROFILE_DIGESTS["network.json"][REDIRECT]
    # Only the changed profile gets a new digest.
    for other in lan.profiles:
        if other.id != REDIRECT:
            assert (
                profile_digest(any_source, any_source.profile(other.id))
                == BASE_PROFILE_DIGESTS["network.json"][other.id]
            )
    assert config_digest(any_source) != config_digest(lan)
    # Another guest port behind the publication is another approval for `any`, while
    # the digest of the same redirect with the default scope does not move.
    moved = {"target_ports": {"first": 81, "last": 81}}
    lan_moved = parsed(policy(proxy_high=moved))
    any_moved = parsed(policy(proxy_high=moved, proxy_standard=ANY))
    assert (
        profile_digest(lan_moved, lan_moved.profile(REDIRECT))
        == BASE_PROFILE_DIGESTS["network.json"][REDIRECT]
    )
    assert profile_digest(any_moved, any_moved.profile(REDIRECT)) != expected


def test_any_source_digest_refuses_a_model_without_the_one_publication() -> None:
    config = wide()
    orphan = replace(
        config, profiles=tuple(item for item in config.profiles if item.id != PUBLICATION)
    )
    with pytest.raises(ConfigError, match="own publication target"):
        profile_digest(orphan, orphan.profile(REDIRECT))
    forged = replace(config.profile("dns-tcp"), source_scope="any")
    with pytest.raises(ConfigError, match="own publication target"):
        profile_digest(config, forged)


def test_review_views_leave_the_default_out_and_show_the_declared_scope() -> None:
    lan, any_source = parsed(policy()), wide()
    for profile in lan.profiles:
        view = config_module.profile_view(profile)
        assert "source_scope" not in view
        assert view == {k: v for k, v in asdict(profile).items() if k != "source_scope"}
        assert "fallback_publication" in view  # printed as before, null included
    assert config_module.profile_view(any_source.profile(REDIRECT))["source_scope"] == "any"


# ---- root admission


def test_admission_of_an_unrestricted_source_needs_its_own_acknowledgement(
    environment: Environment,
) -> None:
    root, _, settings, _, _ = environment
    config = wide()
    install_policy(environment, config)
    wanted = admitted_digest(config, config.profile(REDIRECT), settings)
    with pytest.raises(PFError, match="an unrestricted source requires explicit acknowledgement"):
        admit(root, REDIRECT, acknowledge_bounded_risk=False, expected_digest=wanted)
    # Accepting a recyclable guest address is a different statement.
    with pytest.raises(PFError, match="an unrestricted source requires explicit acknowledgement"):
        admit(root, REDIRECT, acknowledge_bounded_risk=True, expected_digest=wanted)
    assert root.read("admissions.json")["profiles"] == {}
    result = admit(
        root,
        REDIRECT,
        acknowledge_bounded_risk=False,
        acknowledge_any_source=True,
        expected_digest=wanted,
        now=STAMP - 1,
    )
    record = root.read("admissions.json")["profiles"][REDIRECT]
    assert record == {
        "digest": wanted,
        "approved_at": STAMP - 1,
        "approved_by": "local-administrator",
        "risk_acknowledged": True,
    }
    assert result["admitted"] == record
    assert result["resolved"]["profile"]["source_scope"] == "any"
    # A bounded profile is not admitted by the new acknowledgement.
    with pytest.raises(PFError, match="bounded guest-reuse risk"):
        admit(root, "dns-udp", acknowledge_bounded_risk=False, acknowledge_any_source=True)


def test_default_scope_admission_record_is_unchanged(environment: Environment) -> None:
    root, config, settings, backend, _ = environment
    result = admit(root, REDIRECT, acknowledge_bounded_risk=False, now=STAMP - 1)
    record = root.read("admissions.json")["profiles"][REDIRECT]
    assert record == {
        "digest": admitted_digest(config, config.profile(REDIRECT), settings),
        "approved_at": STAMP - 1,
        "approved_by": "local-administrator",
        "risk_acknowledged": False,
    }
    assert "source_scope" not in result["resolved"]["profile"]
    # A structural LAN redirect still needs no acknowledgement to be loaded, and the
    # stored policy and rule records are the bytes the previous release wrote.
    assert REDIRECT + ":activate" in run_pass(environment)["changed"]
    assert backend.rules == redirect_rule(config, config.scopes[0].lan_cidr)
    assert sha256(canonical_bytes(root.read("policy.json"))) == BASE_STORED_POLICY_SHA256
    assert sha256(canonical_bytes(root.read("live.json"))) == BASE_LIVE_RECORDS_SHA256


def test_the_new_acknowledgement_adds_nothing_to_a_lan_scoped_record(
    environment: Environment,
) -> None:
    root = environment[0]
    admit(root, REDIRECT, acknowledge_bounded_risk=False, now=STAMP - 1)
    record = root.read("admissions.json")["profiles"][REDIRECT]
    assert record["risk_acknowledged"] is False
    admit(
        root, REDIRECT, acknowledge_bounded_risk=False, acknowledge_any_source=True, now=STAMP - 1
    )
    assert root.read("admissions.json")["profiles"][REDIRECT] == record


def test_user_admissions_file_round_trips_unchanged() -> None:
    raw = strict_load(ROOT / "examples/admissions.json")
    assert set(next(iter(raw.values()))) == {
        "profile",
        "digest",
        "approved_by",
        "approved_at",
        "risk_acknowledged",
    }
    assert admissions_to_dict(admissions_from_dict(raw)) == raw


# ---- the independent owner's pass, fake native tools only


def test_any_source_redirect_is_loaded_only_behind_its_verified_publication(
    environment: Environment,
) -> None:
    root, _, _, backend, snapshots = environment
    config = wide()
    install_policy(environment, config)
    admit(
        root, REDIRECT, acknowledge_bounded_risk=False, acknowledge_any_source=True, now=STAMP - 1
    )
    observed = snapshots[-1]
    # The publication is not verified: nothing is exposed, to any source or to the LAN.
    snapshots.append(
        Snapshot(
            observed.observed_at,
            observed.network_generation,
            observed.services,
            {key: value for key, value in observed.profiles.items() if key != PUBLICATION},
        )
    )
    assert REDIRECT in run_pass(environment)["pending"]
    assert backend.rules == ""
    snapshots.append(observed)
    result, report = published(environment)
    assert REDIRECT + ":activate" in result["changed"]
    assert backend.rules == redirect_rule(config, "any")
    assert root.read("live.json")["records"][REDIRECT]["policy_digest"] == ANY_SOURCE_DIGEST
    assert report.profiles[REDIRECT].data["admitted"] is True
    assert report.profiles[REDIRECT].data["root_ready"] is True
    # The target is the host's own address: no direct-guest check, and no state is killed.
    assert ("endpoint", host(config)) in backend.commands
    assert not any(command[0] == "drain" for command in backend.commands)
    # A healthy second pass reads the same rule back and writes nothing.
    writes = sum(command[0] == "replace" for command in backend.commands)
    assert run_pass(environment)["changed"] == []
    assert sum(command[0] == "replace" for command in backend.commands) == writes
    # When the publication disappears the rule is withdrawn again.
    snapshots.append(snapshots[-2])
    assert REDIRECT + ":withdraw" in run_pass(environment)["changed"]
    assert backend.rules == ""


def test_record_without_the_acknowledgement_never_activates_an_unrestricted_source(
    environment: Environment,
) -> None:
    root, _, settings, backend, _ = environment
    config = wide()
    install_policy(environment, config)
    # Written by other means than `admit`: the digest matches, the acknowledgement is missing.
    root.write(
        "admissions.json",
        {
            "schema_version": 1,
            "strategy": "darwin-pf-v1",
            "profiles": {
                REDIRECT: {
                    "digest": admitted_digest(config, config.profile(REDIRECT), settings),
                    "approved_at": STAMP - 1,
                    "approved_by": "local-administrator",
                    "risk_acknowledged": False,
                }
            },
        },
    )
    for _ in range(2):  # every pass, not only the first
        result, report = published(environment)
        assert REDIRECT in result["pending"] and backend.rules == ""
        data = report.profiles[REDIRECT].data
        assert data["admitted"] is False and data["root_ready"] is False
        assert data["admission_digest"] is None
    actions = [a for a in root.read("journal.json")["actions"] if a["profile"] == REDIRECT]
    assert [(a["operation"], a["reason"]) for a in actions] == [("pending", "risk-unacknowledged")]


def test_widening_an_admitted_lan_redirect_reopens_admission(environment: Environment) -> None:
    root, lan, settings, backend, _ = environment
    admit(root, REDIRECT, acknowledge_bounded_risk=True, now=STAMP - 1)  # more than it needs
    assert REDIRECT + ":activate" in run_pass(environment)["changed"]
    assert backend.rules == redirect_rule(lan, lan.scopes[0].lan_cidr)
    old = root.read("admissions.json")["profiles"][REDIRECT]
    assert old["risk_acknowledged"] is True

    config = wide()
    install_policy(environment, config)
    assert admitted_digest(config, config.profile(REDIRECT), settings) != old["digest"]
    result, report = published(environment)
    # The LAN rule is withdrawn; the earlier approval does not load anything wider.
    assert REDIRECT in result["pending"] and backend.rules == ""
    assert report.profiles[REDIRECT].data["admitted"] is False
    assert root.read("admissions.json")["profiles"][REDIRECT] == old

    admit(
        root, REDIRECT, acknowledge_bounded_risk=False, acknowledge_any_source=True, now=STAMP - 1
    )
    assert REDIRECT + ":activate" in run_pass(environment)["changed"]
    assert backend.rules == redirect_rule(config, "any")

    # Narrowing again is a new approval as well: nothing switches by itself.
    install_policy(environment, lan)
    assert REDIRECT in run_pass(environment)["pending"] and backend.rules == ""


# ---- planner


def test_planner_gates_an_unrestricted_source_on_the_acknowledgement() -> None:
    config = wide()
    snapshot = verified(config, initial_snapshot(config), PUBLICATION)
    admissions = dict(mock_admissions(config))

    def decision(risk_acknowledged: bool) -> list[tuple[str, str]]:
        admissions[REDIRECT] = Admission(
            REDIRECT,
            profile_digest(config, config.profile(REDIRECT)),
            "simulation-only",
            999.0,
            risk_acknowledged,
        )
        actions = plan(config, snapshot, admissions, Intent(), 1000).actions
        return [(a.operation, a.reason) for a in actions if a.profile == REDIRECT]

    assert decision(False) == [("pending", "risk-unacknowledged")]
    assert decision(True) == [("activate", "ready")]
    # An approval of the LAN-scoped rule is not an approval of this one.
    admissions[REDIRECT] = Admission(
        REDIRECT, BASE_PROFILE_DIGESTS["network.json"][REDIRECT], "simulation-only", 999.0, True
    )
    actions = plan(config, snapshot, admissions, Intent(), 1000).actions
    assert [(a.operation, a.reason) for a in actions if a.profile == REDIRECT] == [
        ("pending", "not-admitted")
    ]


def test_planner_still_activates_a_lan_redirect_without_any_acknowledgement() -> None:
    config = parsed(policy())
    snapshot = verified(config, initial_snapshot(config), PUBLICATION)
    admissions = {
        key: replace(value, risk_acknowledged=False)
        for key, value in mock_admissions(config).items()
    }
    actions = plan(config, snapshot, admissions, Intent(), 1000).actions
    assert [(a.operation, a.reason) for a in actions if a.profile == REDIRECT] == [
        ("activate", "ready")
    ]


# ---- command lines


def test_user_review_output_of_the_example_policy_keeps_its_bytes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    example = str(ROOT / "examples/network.json")
    for identifier, expected in BASE_USER_REVIEW_SHA256.items():
        assert user_main(["review-admission", "--config", example, "--profile", identifier]) == 0
        assert sha256(capsys.readouterr().out) == expected


def test_user_review_shows_a_declared_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    changed = tmp_path / "network.json"
    changed.write_bytes(canonical_bytes(policy(proxy_standard=ANY)))
    assert user_main(["review-admission", "--config", str(changed), "--profile", REDIRECT]) == 0
    review = strict_loads(capsys.readouterr().out)
    assert review["profile"]["source_scope"] == "any"
    assert review["digest"] == ANY_SOURCE_DIGEST and review["root_admission_required"] is True


REVIEW_MEMBERS = {
    "profile",
    "scope",
    "service",
    "strategy",
    "implementation_sha256",
    "expected_digest",
    "previous",
    "risk_acknowledgement_required",
}


@pytest.fixture
def root_command(
    environment: Environment,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    legacy_cli_conformance: None,
) -> Any:
    """The root owner's command line on an unprivileged temporary root.

    Direct dependency injection, as in the neighbouring module; never a flag or
    an environment bypass in live code.
    """
    import netorch.pf_owner as module
    import netorch.storage as storage

    root = environment[0]
    monkeypatch.setattr(module.sys, "platform", "darwin")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module, "Store", lambda directory: root)
    monkeypatch.setattr(module, "protected_ancestors", lambda *a, **kw: None)
    monkeypatch.setattr(module, "protected_code", lambda *a, **kw: None)
    monkeypatch.setattr(storage.Store, "_check_directory_info", staticmethod(lambda info: None))
    monkeypatch.setattr(storage, "_check_file", lambda fd: None)

    def run(command: str, *arguments: str) -> tuple[int, Any]:
        code = main([command, "--root-dir", str(root.directory), *arguments])
        output = capsys.readouterr().out
        return code, strict_loads(output) if output else None

    return run


def test_root_review_of_a_lan_scoped_profile_prints_what_it_printed_before(
    environment: Environment, root_command: Any
) -> None:
    lan = environment[1]
    for profile in lan.profiles:
        if lan.profile_owner(profile).id != environment[2].owner:
            continue
        code, review = root_command("review-admission", "--profile", profile.id)
        assert code == 0 and set(review) == REVIEW_MEMBERS
        assert review["profile"] == {
            key: value for key, value in asdict(profile).items() if key != "source_scope"
        }
        assert review["risk_acknowledgement_required"] is (profile.safety.kind == "bounded")


def test_root_command_line_reviews_and_admits_with_the_separate_flag(
    environment: Environment, root_command: Any
) -> None:
    root, lan, _, _, _ = environment
    _, before = root_command("review-admission", "--profile", REDIRECT)
    install_policy(environment, wide())
    code, after = root_command("review-admission", "--profile", REDIRECT)
    assert code == 0 and set(after) == REVIEW_MEMBERS | {"any_source_acknowledgement_required"}
    assert after["any_source_acknowledgement_required"] is True
    assert after["risk_acknowledgement_required"] is False
    assert after["profile"] == {**asdict(lan.profile(REDIRECT)), "source_scope": "any"}
    assert after["expected_digest"] != before["expected_digest"]

    admit_arguments = ("--profile", REDIRECT, "--expected-digest")
    for flags in ((), ("--acknowledge-bounded-risk",)):
        assert root_command("admit", *admit_arguments, after["expected_digest"], *flags)[0] == 65
        assert root.read("admissions.json")["profiles"] == {}
    # The digest reviewed for the LAN-scoped rule admits nothing either.
    stale = (*admit_arguments, before["expected_digest"], "--acknowledge-any-source")
    assert root_command("admit", *stale)[0] == 65
    assert root.read("admissions.json")["profiles"] == {}
    code, admitted = root_command(
        "admit", *admit_arguments, after["expected_digest"], "--acknowledge-any-source"
    )
    assert code == 0 and admitted["admitted"]["risk_acknowledged"] is True
    assert root.read("admissions.json")["profiles"][REDIRECT]["digest"] == after["expected_digest"]


# ---- hosted macOS: the platform's own parser (nothing is loaded)


def recorded(capsys: Any, title: str, seen: str) -> None:
    """On the hosted runner, keep what the platform tool answered as a notice of the job."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        text = seen.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        # Capture is lifted for one line of its own: the runner reads commands at line starts.
        with capsys.disabled():
            print(f"\n::notice title={title}::{text}")


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
@pytest.mark.parametrize("source_scope", ["lan", "any"])
def test_platform_parser_accepts_the_redirect_from_the_lan_and_from_any(
    tmp_path: Path, source_scope: str, capsys: Any
) -> None:
    """`pfctl -n -f` only parses a file; run unprivileged it can load nothing.

    The LAN-scoped rule is the control: if the dry run cannot be used without
    privilege on this image, that case fails too and says so. Evidence for one
    hosted runner image only; it shows nothing about a loaded rule or a packet.
    """
    config = wide() if source_scope == "any" else parsed(policy())
    scope: Scope = config.scope(config.profile(REDIRECT).scope)
    rule = render_profile(config, config.profile(REDIRECT), scope.host_ipv4)
    assert rule == redirect_rule(config, "any" if source_scope == "any" else scope.lan_cidr)
    rules = tmp_path / "redirect.pf"
    rules.write_text(rule)
    result = subprocess.run(
        ["/sbin/pfctl", "-n", "-f", str(rules)], capture_output=True, timeout=10, check=False
    )
    # For the record only, nothing is asserted on it: how the parser prints the rule back.
    printed = subprocess.run(
        ["/sbin/pfctl", "-n", "-v", "-f", str(rules)], capture_output=True, timeout=10, check=False
    )
    recorded(
        capsys,
        f"pfctl dry run for source {source_scope}",
        f"status {result.returncode}, err {result.stderr[:200]!r}; with -v: status "
        f"{printed.returncode}, out {printed.stdout[:300]!r}, err {printed.stderr[:200]!r}",
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def test_profile_type_keeps_its_positional_fields() -> None:
    """The new member is last and optional, so existing constructions are unchanged."""
    base = parsed(policy()).profile(REDIRECT)
    fields = asdict(base)
    assert list(fields)[-1] == "source_scope" and fields["source_scope"] == "lan"
    rebuilt = Profile(
        base.id,
        base.service,
        base.scope,
        base.kind,
        base.protocol,
        base.ports,
        base.target_ports,
        base.safety,
        base.owner,
        base.fallback_publication,
    )
    assert rebuilt == base

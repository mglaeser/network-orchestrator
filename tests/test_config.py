from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netorch.codec import (
    CodecError,
    canonical_bytes,
    canonical_json,
    digest,
    strict_load,
    strict_loads,
)
from netorch.config import (
    ConfigError,
    config_digest,
    load_config,
    parse_config,
    profile_digest,
    to_dict,
    validate_config,
)
from netorch.model import PortRange

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/network.json"


@pytest.fixture
def policy():
    return json.loads(EXAMPLE.read_text())


def parsed(policy):
    return parse_config(json.dumps(policy))


def test_example_round_trip_lookup_and_optional_fields(policy):
    config = load_config(EXAMPLE)
    assert config == parse_config(canonical_json(to_dict(config)))
    assert config.profile("media-udp").target_ports is None
    assert config.service("resolver").automatic_ports is None
    assert config.scope("wired-lan").host_ipv4 == "192.0.2.10"
    assert config.owner("bonjour-manager").privilege == "user"
    assert len(config_digest(config)) == 64
    with pytest.raises(FrozenInstanceError):
        config.site = "mutated"
    for lookup in (config.scope, config.owner, config.service, config.profile):
        with pytest.raises(KeyError):
            lookup("missing")
    validate_config(config)
    data = to_dict(config)
    assert isinstance(data["profiles"], list)
    assert data["profiles"][4]["target_ports"] is None
    assert parsed(policy) == config


@pytest.mark.parametrize(
    "raw",
    [
        '{"a":1,"a":2}',
        '{"outer":{"same":1,"same":2}}',
        '{"nested":[{"a":1,"a":2}]}',
        '{"escaped":1,"\\u0065scaped":2}',
        '{"a":NaN}',
        '{"a":Infinity}',
        '{"a":-Infinity}',
        '{"a":1e400}',
        '{"a":"\\ud800"}',
        "{bad}",
        "[",
        "\ufeff{}",
        b"\xff",
    ],
)
def test_strict_json_rejects_invalid_or_ambiguous_data(raw):
    with pytest.raises(CodecError):
        strict_loads(raw)


def test_strict_json_bounds_and_quoted_braces():
    assert strict_loads('{"text":"[[[{\\"}"}', max_depth=1) == {"text": '[[[{"}'}
    for text, kwargs in [
        ("[[[0]]]", {"max_depth": 2}),
        ('"toolong"', {"max_bytes": 5}),
        ("[" * 10000 + "0" + "]" * 10000, {}),
        ('"' + "x" * 65537 + '"', {}),
        ("[" + ",".join("0" for _ in range(50001)) + "]", {}),
        (str(2**257), {}),
        ("{}", {"max_depth": 0}),
        ("{}", {"max_bytes": 0}),
    ]:
        with pytest.raises(CodecError):
            strict_loads(text, **kwargs)


def test_load_file_is_bounded_and_utf8(tmp_path):
    path = tmp_path / "policy.json"
    path.write_bytes(b"x" * 1_048_577)
    with pytest.raises(CodecError):
        strict_load(path)
    with pytest.raises(ConfigError):
        load_config(path)


@pytest.mark.parametrize(
    "value", [float("inf"), float("nan"), {1: "invalid key"}, {"bad": {1, 2}}, "\ud800", 2**257]
)
def test_canonical_json_rejects_non_json_values(value):
    with pytest.raises(CodecError):
        canonical_json(value)


def test_canonical_json_and_digest_are_order_independent_for_objects():
    assert canonical_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})
    assert canonical_json(PortRange(1, 2)) == '{"first":1,"last":2}'


@given(
    st.dictionaries(
        st.text(alphabet="abc", min_size=1, max_size=4),
        st.integers(min_value=-1000, max_value=1000),
        max_size=12,
    )
)
def test_canonical_round_trip_property(value):
    assert strict_loads(canonical_json(value)) == value
    assert digest(value) == digest(dict(reversed(list(value.items()))))


@pytest.mark.parametrize("field", ["command", "root_command", "$schema", "unknown"])
def test_top_level_schema_is_closed(policy, field):
    policy[field] = "must-not-be-executable"
    with pytest.raises(ConfigError, match="Schema violation"):
        parsed(policy)


@pytest.mark.parametrize("collection", ["scopes", "owners", "services", "profiles", "discovery"])
def test_each_object_schema_is_closed(policy, collection):
    policy[collection][0]["unknown"] = "hidden"
    with pytest.raises(ConfigError, match="Schema violation"):
        parsed(policy)


@pytest.mark.parametrize("collection", ["scopes", "owners", "services", "profiles", "discovery"])
def test_identifiers_are_unique_per_collection(policy, collection):
    policy[collection].append(deepcopy(policy[collection][0]))
    with pytest.raises(ConfigError, match="Duplicate"):
        parsed(policy)


@pytest.mark.parametrize(
    "collection,field",
    [
        ("services", "owner"),
        ("profiles", "service"),
        ("profiles", "scope"),
        ("discovery", "owner"),
        ("discovery", "scope"),
        ("discovery", "service"),
    ],
)
def test_references_must_resolve(policy, collection, field):
    policy[collection][0][field] = "missing"
    with pytest.raises(ConfigError, match="Unknown"):
        parsed(policy)


def test_discovery_dependency_must_resolve(policy):
    policy["discovery"][0]["dependencies"] = ["missing"]
    with pytest.raises(ConfigError, match="Unknown profile"):
        parsed(policy)


def test_transport_and_discovery_identifiers_share_a_disjoint_observation_namespace(policy):
    policy["discovery"][0]["id"] = policy["profiles"][0]["id"]
    with pytest.raises(ConfigError, match="disjoint"):
        parsed(policy)


def test_service_observation_owner_is_independent_of_profile_execution_owner(policy):
    config = parsed(policy)
    assert config.owner(config.service("resolver").owner).privilege == "user"
    assert config.profile_owner("dns-udp").privilege == "external-root"
    assert config.profile_owner(config.profile("camera-web")) == config.owner(
        config.service("camera").owner
    )


def test_explicit_profile_owner_must_resolve_and_have_capability(policy):
    policy["profiles"][0]["owner"] = "missing"
    with pytest.raises(ConfigError, match="Unknown owner"):
        parsed(policy)
    policy["profiles"][0]["owner"] = "bonjour-manager"
    with pytest.raises(ConfigError, match="capability"):
        parsed(policy)


def test_admission_binds_both_profile_and_runtime_observation_owner(policy):
    baseline = parsed(policy)
    root_owner = deepcopy(policy["owners"][0])
    root_owner["id"] = "another-external-owner"
    policy["owners"].append(root_owner)
    policy["profiles"][0]["owner"] = root_owner["id"]
    changed_profile = parsed(policy)
    original_digest = profile_digest(baseline, baseline.profile("dns-udp"))
    assert original_digest != profile_digest(changed_profile, changed_profile.profile("dns-udp"))
    policy["profiles"][0]["owner"] = baseline.profile_owner("dns-udp").id
    user_owner = deepcopy(policy["owners"][1])
    user_owner["id"] = "another-runtime-owner"
    policy["owners"].append(user_owner)
    policy["services"][0]["owner"] = user_owner["id"]
    changed_runtime = parsed(policy)
    assert original_digest != profile_digest(changed_runtime, changed_runtime.profile("dns-udp"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("host_ipv4", "2001:db8::1"),
        ("host_ipv4", "192.0.2.999"),
        ("host_ipv4", "192.0.2.0"),
        ("host_ipv4", "192.0.2.255"),
        ("host_ipv4", "198.51.100.10"),
        ("host_ipv4", "0192.0.2.10"),
        ("host_ipv4", "127.0.0.1"),
        ("lan_cidr", "192.0.2.10/24"),
        ("guest_cidr", "192.0.2.0/24"),
        ("guest_cidr", "198.51.100.5/24"),
        ("guest_cidr", "0.0.0.0/0"),
        ("interface", "en0;id"),
        ("interface", "en0\n"),
        ("interface", "0"),
    ],
)
def test_network_scope_is_valid_and_specific(policy, field, value):
    policy["scopes"][0][field] = value
    with pytest.raises(ConfigError):
        parsed(policy)


@pytest.mark.parametrize(
    "field,value", [("first", 0), ("last", 65536), ("first", True), ("last", "53"), ("first", 54)]
)
def test_port_ranges_are_integer_bounded_and_ordered(policy, field, value):
    policy["profiles"][0]["ports"][field] = value
    with pytest.raises(ConfigError):
        parsed(policy)


def test_target_port_range_width_must_match(policy):
    policy["profiles"][0]["target_ports"]["last"] = 54
    with pytest.raises(ConfigError, match="width"):
        parsed(policy)


def test_host_port_claim_collision_across_scope_labels(policy):
    scope = deepcopy(policy["scopes"][0])
    scope["id"] = "duplicate-scope"
    policy["scopes"].append(scope)
    conflict = deepcopy(policy["profiles"][0])
    conflict.update(id="dns-conflict", scope="duplicate-scope")
    policy["profiles"].append(conflict)
    with pytest.raises(ConfigError, match="overlapping"):
        parsed(policy)


def test_different_protocols_can_claim_same_number(policy):
    assert parsed(policy).profile("dns-tcp").ports == parsed(policy).profile("dns-udp").ports


@pytest.mark.parametrize(
    "mutation", ["missing-target", "wrong-port", "wrong-service", "wrong-scope", "wrong-protocol"]
)
def test_host_redirect_binds_its_own_publication(policy, mutation):
    profile = policy["profiles"][3]
    if mutation == "missing-target":
        profile.pop("target_ports")
    elif mutation == "wrong-port":
        profile["target_ports"] = {"first": 9443, "last": 9443}
    elif mutation == "wrong-service":
        profile["service"] = "resolver"
    elif mutation == "wrong-scope":
        policy["scopes"].append({**policy["scopes"][0], "id": "another-lan"})
        profile["scope"] = "another-lan"
    else:
        profile["protocol"] = "udp"
    with pytest.raises(ConfigError, match="own publication"):
        parsed(policy)


def test_site_identifier_cannot_have_trailing_newline(policy):
    policy["site"] += "\n"
    with pytest.raises(ConfigError):
        parsed(policy)


@pytest.mark.parametrize(
    "mutation",
    ["missing-capability", "user-root-kind", "unknown-capability", "duplicate-capability"],
)
def test_capabilities_and_privilege_are_checked(policy, mutation):
    owner = policy["owners"][0]
    if mutation == "missing-capability":
        owner["capabilities"].remove("guest-direct")
    elif mutation == "user-root-kind":
        owner["privilege"] = "user"
    elif mutation == "unknown-capability":
        owner["capabilities"] = ["sudo"]
    else:
        owner["capabilities"] = ["guest-direct", "guest-direct"]
    with pytest.raises(ConfigError):
        parsed(policy)


@pytest.mark.parametrize(
    "mutation", ["structural-direct", "missing-risk", "blank-risk", "age-zero", "count-zero"]
)
def test_safety_requires_explicit_bounded_risk(policy, mutation):
    safety = policy["profiles"][0]["safety"]
    if mutation == "structural-direct":
        safety["kind"] = "structural"
    elif mutation == "missing-risk":
        safety.pop("statement")
    elif mutation == "blank-risk":
        safety["statement"] = "  \n"
    elif mutation == "age-zero":
        safety["max_age_seconds"] = 0
    else:
        safety["unknown_limit"] = 0
    with pytest.raises(ConfigError):
        parsed(policy)


@pytest.mark.parametrize(
    "mutation", ["protocol", "explicit-target", "no-automatic-ports", "outside-automatic-ports"]
)
def test_udp_return_preserves_reviewed_targetless_semantics(policy, mutation):
    profile = policy["profiles"][4]
    if mutation == "protocol":
        profile["protocol"] = "tcp"
    elif mutation == "explicit-target":
        profile["target_ports"] = deepcopy(profile["ports"])
    elif mutation == "no-automatic-ports":
        policy["services"][2].pop("automatic_ports")
    else:
        profile["ports"]["last"] += 1
    with pytest.raises(ConfigError):
        parsed(policy)


@pytest.mark.parametrize(
    "mutation",
    [
        "root-discovery",
        "capability",
        "missing-media-dependency",
        "wrong-service-export",
        "bad-type",
        "unbounded-records",
        "duplicate-dependency",
    ],
)
def test_discovery_scope_provenance_and_dependencies(policy, mutation):
    if mutation == "root-discovery":
        policy["owners"][2]["privilege"] = "external-root"
    elif mutation == "capability":
        policy["owners"][2]["capabilities"] = ["publication"]
    elif mutation == "missing-media-dependency":
        policy["discovery"][0]["dependencies"] = []
    elif mutation == "wrong-service-export":
        policy["discovery"][1]["dependencies"] = ["proxy-high"]
    elif mutation == "bad-type":
        policy["discovery"][0]["types"] = ["_airplay._tcp\n"]
    elif mutation == "unbounded-records":
        policy["discovery"][0]["max_records"] = 0
    else:
        policy["discovery"][0]["dependencies"] *= 2
    with pytest.raises(ConfigError):
        parsed(policy)


@pytest.mark.parametrize(
    "mutation",
    [
        "ports",
        "target-ports",
        "protocol",
        "kind",
        "risk",
        "age",
        "unknown-limit",
        "interface",
        "host",
        "lan",
        "guest",
        "contract",
        "owner-capabilities",
    ],
)
def test_admission_digest_binds_each_resolved_authority_field(policy, mutation):
    baseline = parsed(policy)
    original = baseline.profile("dns-udp")
    profile = policy["profiles"][0]
    if mutation == "ports":
        profile["ports"] = {"first": 54, "last": 54}
    elif mutation == "target-ports":
        profile["target_ports"] = {"first": 54, "last": 54}
    elif mutation == "protocol":
        policy["profiles"][1]["ports"] = {"first": 54, "last": 54}
        profile["protocol"] = "tcp"
    elif mutation == "kind":
        profile["kind"] = "publication"
    elif mutation == "risk":
        profile["safety"]["statement"] += " Reviewed."
    elif mutation == "age":
        profile["safety"]["max_age_seconds"] += 1
    elif mutation == "unknown-limit":
        profile["safety"]["unknown_limit"] += 1
    elif mutation == "interface":
        policy["scopes"][0]["interface"] = "en1"
    elif mutation == "host":
        policy["scopes"][0]["host_ipv4"] = "192.0.2.11"
    elif mutation == "lan":
        policy["scopes"][0]["lan_cidr"] = "192.0.2.0/25"
    elif mutation == "guest":
        policy["scopes"][0]["guest_cidr"] = "198.51.100.0/25"
    elif mutation == "contract":
        policy["services"][0]["contract_sha256"] = "e" * 64
    else:
        policy["owners"][0]["capabilities"].remove("host-redirect")
        policy["profiles"] = [
            item for item in policy["profiles"] if item["kind"] != "host-redirect"
        ]
    changed = parsed(policy)
    assert profile_digest(baseline, original) != profile_digest(changed, changed.profile("dns-udp"))


def test_unrelated_policy_edit_changes_policy_digest_but_not_admission(policy):
    baseline = parsed(policy)
    policy["site"] = "another-site"
    changed = parsed(policy)
    assert config_digest(baseline) != config_digest(changed)
    assert profile_digest(baseline, baseline.profile("dns-udp")) == profile_digest(
        changed, changed.profile("dns-udp")
    )


def test_constructed_models_are_validated(policy):
    config = parsed(policy)
    with pytest.raises(ConfigError):
        validate_config(
            replace(config, profiles=(replace(config.profiles[0], ports=PortRange(0, 5)),))
        )


def test_validation_errors_do_not_print_unknown_secrets(policy):
    policy["secret"] = "SENSITIVE-VALUE-DO-NOT-ECHO"
    with pytest.raises(ConfigError) as error:
        parsed(policy)
    assert "SENSITIVE" not in str(error.value)

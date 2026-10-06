"""`service_types`: the DNS-SD types of a discovery selection, where they differ from its profile.

Without the member nothing changes. The digests in ``BASE`` were computed on the
tree before the member existed, for the shipped examples as they were then, so
the tests that only use them also pass on that tree. They are here to show that
an instance without the member keeps its bytes and digests.
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import instance as instance_module
from netorch import profile_library
from netorch.codec import canonical_bytes
from netorch.config import ConfigError, parse_config, validate_config
from netorch.instance import (
    InstanceError,
    canonical_instance_bytes,
    instance_contract_digest,
    instance_digest,
    instance_to_dict,
    load_instance,
    resolved_discovery_digest,
    validate_instance,
)
from netorch.instance_model import DiscoverySelection, Instance
from netorch.profile_library import DISCOVERY_PROFILES, discovery_profile
from tests.test_report_guards import parsed, ready, report

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
MEDIA = discovery_profile("apple-media-import", 1).service_types
AUTOMATIC = ["auto-tcp"]
BASE: dict[str, dict[str, Any]] = {
    "instance.json": {
        "instance_digest": "f0adf2a76ad106f1ed758b0ab9f05388a15b4e11934f37faa68e377190ff732e",
        "contract_digest": "bc7d92900c617507a7d1dfe150df3600fff3d5ad29c1a0a72b467779f16f7a9c",
        "discovery": {
            "example-export": "a87cb58580aef982e565caa79bb489da0f3996ac5e1c3c45709c3811c6f1ff86",
            "example-import": "3a399f2f69074be0231e436d0902815936a10c506b77ec7c6cdf609e002c7af3",
        },
    },
    "instance-structural.json": {
        "instance_digest": "345a770371a6dc244234050cd606dd5222d277782a2c27529bc568f5fb92bb23",
        "contract_digest": "6489191df8f66f366323fcd61091c69a45bc2676f5f215e25f6a218674a3fa5e",
        "discovery": {
            "example-export": "397d48b2f0097fe344366050efc7ff1ffa9e9178445189ed3d8819c3c766e54d",
        },
    },
}


def shipped(name: str = "instance.json") -> dict[str, Any]:
    """A shipped instance as it was when ``BASE`` was taken.

    A release changes the release pin of the examples and nothing else.
    """
    data: dict[str, Any] = json.loads((EXAMPLES / name).read_bytes())
    data["framework"]["version"] = "0.3.2"
    return data


def selection(data: dict[str, Any], direction: str) -> dict[str, Any]:
    found: dict[str, Any] = next(
        item for item in data["discovery"] if item["direction"] == direction
    )
    return found


def listing(direction: str, types: Any, profile: str | None = None) -> dict[str, Any]:
    data = shipped()
    selection(data, direction)["service_types"] = types
    if profile is not None:
        selection(data, direction)["profile"] = profile
    return data


def resolved(data: dict[str, Any]) -> dict[str, str]:
    instance = parsed(data)
    return {item.id: resolved_discovery_digest(instance, item) for item in instance.discovery}


def chosen(data: dict[str, Any], direction: str) -> DiscoverySelection:
    return next(item for item in parsed(data).discovery if item.direction == direction)


def named(data: dict[str, Any], direction: str) -> Any:
    """What ``selection_types`` says for the selection of one direction."""
    return instance_module.selection_types(chosen(data, direction))


# ---- an instance written before the member existed keeps its bytes and digests


@pytest.mark.parametrize("name", ["instance.json", "instance-structural.json"])
def test_shipped_instances_keep_their_bytes_and_every_digest(name: str) -> None:
    raw = (EXAMPLES / name).read_bytes()
    live = load_instance(EXAMPLES / name)
    assert canonical_instance_bytes(live) == raw
    assert instance_to_dict(live) == json.loads(raw)
    instance = parsed(shipped(name))
    assert instance_digest(instance) == BASE[name]["instance_digest"]
    assert instance_contract_digest(instance) == BASE[name]["contract_digest"]
    assert resolved(shipped(name)) == BASE[name]["discovery"]


@pytest.mark.parametrize("direction", ["import", "export"])
@pytest.mark.parametrize("value", [None, [], "_airplay._tcp", {"_airplay._tcp": True}])
def test_absence_has_no_other_spelling(direction: str, value: Any) -> None:
    with pytest.raises(InstanceError, match="closed versioned schema"):
        parsed(listing(direction, value))


# ---- a profile with a fixed list: a proper subset, in the profile's order


def test_import_can_name_a_proper_ordered_subset_that_keeps_its_eligibility_type() -> None:
    assert named(shipped(), "import") == MEDIA
    assert discovery_profile("apple-media-import", 1).eligibility_type == MEDIA[0]
    subset = [MEDIA[0], MEDIA[1], MEDIA[3]]
    data = listing("import", subset)
    assert chosen(data, "import").service_types == tuple(subset) == named(data, "import")
    assert canonical_instance_bytes(parsed(data)) == canonical_bytes(data) + b"\n"
    assert instance_to_dict(parsed(data))["discovery"] == data["discovery"]
    for broken in (
        [MEDIA[1], MEDIA[0]],  # not in the profile's order
        [MEDIA[1], MEDIA[2]],  # without the type eligibility is decided from
        [MEDIA[0], "_http._tcp"],  # not a type of this profile
        list(MEDIA),  # the whole list is said by leaving the member out
    ):
        with pytest.raises(InstanceError, match="proper subset"):
            parsed(listing("import", broken))
    assert named(listing("import", [MEDIA[0]]), "import") == (MEDIA[0],)


@pytest.mark.parametrize("profile", ["homekit-export", "home-assistant-export"])
def test_profile_with_one_type_takes_no_list(profile: str) -> None:
    only = discovery_profile(profile, 1).service_types
    assert len(only) == 1
    data = shipped()
    selection(data, "export")["profile"] = profile
    assert named(data, "export") == only
    for types in (list(only), ["_http._tcp"], [*only, "_http._tcp"]):
        with pytest.raises(InstanceError, match="proper subset"):
            parsed(listing("export", types, profile))


# ---- the generic export: automatic unless its types are listed


def test_generic_export_is_automatic_unless_its_types_are_listed() -> None:
    generic = discovery_profile("published-tcp-export", 1)
    assert list(generic.service_types) == list(profile_library.AUTOMATIC_TYPES) == AUTOMATIC
    assert generic.eligibility_type is None
    for name in ("instance.json", "instance-structural.json"):
        assert named(shipped(name), "export") is None
    data = listing("export", ["_http._tcp", "_ssh._tcp"])
    assert named(data, "export") == ("_http._tcp", "_ssh._tcp")
    assert chosen(data, "export").service_types == ("_http._tcp", "_ssh._tcp")
    assert canonical_instance_bytes(parsed(data)) == canonical_bytes(data) + b"\n"
    # A type that has a profile of its own may be listed too; the list is only data.
    assert named(listing("export", ["_hap._tcp"]), "export") == ("_hap._tcp",)
    most = [f"_t{number:02}._tcp" for number in range(16)]
    assert named(listing("export", most), "export") == tuple(most)


@pytest.mark.parametrize(
    ("types", "reason"),
    [
        (["_ssh._tcp", "_http._tcp"], "ascending order"),
        (["_HTTP._tcp", "_http._tcp"], "distinct"),  # one type to DNS
        (["_http._tcp", "_http._tcp"], "closed versioned schema"),
        (["_http._udp"], "closed versioned schema"),
        (AUTOMATIC, "closed versioned schema"),
        (["http"], "closed versioned schema"),
        (["_http._tcp."], "closed versioned schema"),
        (["_" + "a" * 64 + "._tcp"], "closed versioned schema"),
        ([f"_t{number:02}._tcp" for number in range(17)], "closed versioned schema"),
        (["_http._tcp\n"], "control characters"),
    ],
)
def test_explicit_export_types_are_sorted_distinct_tcp_types(types: list[str], reason: str) -> None:
    parsed(listing("export", ["_http._tcp"]))
    with pytest.raises(InstanceError, match=reason):
        parsed(listing("export", types))


def test_automatic_export_has_no_retained_implementation() -> None:
    # The rule this pins: whatever turns an instance into retained discovery policy
    # refuses the automatic form and never guesses its types. The token that stands
    # for the form is no service type of the retained policy, so it cannot be copied
    # there by accident, and no other profile carries it.
    policy = json.loads((EXAMPLES / "network.json").read_bytes())
    entry = next(item for item in policy["discovery"] if item["direction"] == "export")
    for types in (AUTOMATIC, [*entry["types"], *AUTOMATIC]):
        changed = copy.deepcopy(policy)
        next(item for item in changed["discovery"] if item["id"] == entry["id"])["types"] = types
        with pytest.raises(ConfigError, match="Schema violation"):
            parse_config(json.dumps(changed))
    config = parse_config(json.dumps(policy))
    forged = tuple(
        replace(item, types=tuple(AUTOMATIC)) if item.direction == "export" else item
        for item in config.discovery
    )
    with pytest.raises(ConfigError):
        validate_config(replace(config, discovery=forged))
    automatic = [item.name for item in DISCOVERY_PROFILES if list(item.service_types) == AUTOMATIC]
    assert automatic == ["published-tcp-export"]


def test_automatic_form_is_none_and_a_listed_export_is_what_the_retained_policy_takes() -> None:
    assert named(shipped(), "export") is None
    listed = named(listing("export", ["_hap._tcp", "_http._tcp"]), "export")
    policy = json.loads((EXAMPLES / "network.json").read_bytes())
    next(item for item in policy["discovery"] if item["direction"] == "export")["types"] = list(
        listed
    )
    accepted = parse_config(json.dumps(policy))
    assert next(item for item in accepted.discovery if item.direction == "export").types == listed


# ---- the list is part of the selection: of its digest and of its report row


def test_listed_types_change_only_their_own_selection_digest() -> None:
    base = BASE["instance.json"]["discovery"]
    narrowed = resolved(listing("import", [MEDIA[0], MEDIA[1]]))
    assert narrowed["example-export"] == base["example-export"]
    assert narrowed["example-import"] != base["example-import"]
    assert narrowed["example-import"] != resolved(listing("import", [MEDIA[0]]))["example-import"]
    listed = resolved(listing("export", ["_http._tcp"]))
    assert listed["example-import"] == base["example-import"]
    assert listed["example-export"] != base["example-export"]


def test_report_row_carries_the_types_only_when_declared() -> None:
    for name in ("instance.json", "instance-structural.json"):
        rows = report(shipped(name))["discovery_profiles"]
        assert all("service_types" not in row for row in rows)
    plain = report(shipped())["discovery_profiles"]
    data = listing("import", [MEDIA[0], MEDIA[1]])
    export, imported = report(data, members=ready(data))["discovery_profiles"]
    assert set(export) == set(plain[0])
    assert set(imported) == {*plain[1], "service_types"}
    assert imported["service_types"] == [MEDIA[0], MEDIA[1]]


def test_constructed_selection_is_validated_like_a_parsed_one() -> None:
    instance = parsed(shipped())
    export, imported = instance.discovery

    def having(changed: DiscoverySelection) -> Instance:
        return replace(
            instance,
            discovery=tuple(
                changed if item.id == changed.id else item for item in (export, imported)
            ),
        )

    validate_instance(having(replace(imported, service_types=MEDIA[:2])))
    validate_instance(having(replace(export, service_types=("_http._tcp", "_ssh._tcp"))))
    for changed, reason in (
        (replace(imported, service_types=MEDIA), "proper subset"),
        (replace(imported, service_types=(MEDIA[1],)), "proper subset"),
        (replace(imported, service_types=()), "closed versioned schema"),
        (replace(export, service_types=("_ssh._tcp", "_http._tcp")), "ascending order"),
        (replace(export, service_types=tuple(AUTOMATIC)), "closed versioned schema"),
    ):
        with pytest.raises(InstanceError, match=reason):
            validate_instance(having(changed))

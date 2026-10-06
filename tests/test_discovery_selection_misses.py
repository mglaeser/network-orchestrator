"""`misses`: a discovery selection's own miss tolerance, where it differs from the instance's.

Without the member nothing changes. The digests in ``BASE`` were computed on the
tree before the member existed, for the shipped examples as they were then, so
the tests that only use them also pass on that tree. They are here to show that
an instance without the member keeps its bytes and digests.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch.codec import canonical_bytes
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
from tests.test_report_guards import parsed, report

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
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


def tolerating(direction: str, misses: Any, instance_wide: int | None = None) -> dict[str, Any]:
    data = shipped()
    selection(data, direction)["misses"] = misses
    if instance_wide is not None:
        data["supervision"]["discovery_misses"] = instance_wide
    return data


def resolved(data: dict[str, Any]) -> dict[str, str]:
    instance = parsed(data)
    return {item.id: resolved_discovery_digest(instance, item) for item in instance.discovery}


@pytest.mark.parametrize("name", ["instance.json", "instance-structural.json"])
def test_shipped_instances_keep_their_bytes_and_every_digest(name: str) -> None:
    raw = (EXAMPLES / name).read_bytes()
    live = load_instance(EXAMPLES / name)
    assert canonical_instance_bytes(live) == raw
    assert instance_to_dict(live) == json.loads(raw)
    assert json.loads(raw)["supervision"]["discovery_misses"] == 3
    instance = parsed(shipped(name))
    assert instance_digest(instance) == BASE[name]["instance_digest"]
    assert instance_contract_digest(instance) == BASE[name]["contract_digest"]
    assert resolved(shipped(name)) == BASE[name]["discovery"]


@pytest.mark.parametrize("direction", ["import", "export"])
@pytest.mark.parametrize("misses", [1, 2, 4, 5, 6, 7, 8])
def test_tolerance_can_differ_for_one_selection(direction: str, misses: int) -> None:
    data = tolerating(direction, misses)
    instance = parsed(data)
    chosen = next(item for item in instance.discovery if item.direction == direction)
    other = next(item for item in instance.discovery if item.direction != direction)
    assert (chosen.misses, other.misses) == (misses, None)
    assert canonical_instance_bytes(instance) == canonical_bytes(data) + b"\n"
    assert instance_to_dict(instance)["discovery"] == data["discovery"]
    # The member is part of its own selection's digest and of no other.
    base = BASE["instance.json"]["discovery"]
    digests = resolved(data)
    assert digests[chosen.id] != base[chosen.id]
    assert digests[other.id] == base[other.id]
    another = 2 if misses == 1 else 1
    assert digests[chosen.id] != resolved(tolerating(direction, another))[chosen.id]


def test_instance_wide_tolerance_has_no_spelling_on_a_selection() -> None:
    with pytest.raises(InstanceError, match="differs from the instance-wide one"):
        parsed(tolerating("import", 3))
    with pytest.raises(InstanceError, match="differs from the instance-wide one"):
        parsed(tolerating("export", 3))
    # The rule follows the instance-wide value, whatever it is.
    assert parsed(tolerating("import", 3, instance_wide=4)).discovery[1].misses == 3
    with pytest.raises(InstanceError, match="differs from the instance-wide one"):
        parsed(tolerating("import", 4, instance_wide=4))


@pytest.mark.parametrize(
    ("misses", "reason"),
    [
        (0, "closed versioned schema"),
        (9, "closed versioned schema"),
        (-1, "closed versioned schema"),
        (True, "closed versioned schema"),
        ("1", "closed versioned schema"),
        (None, "closed versioned schema"),
        ([1], "closed versioned schema"),
        (1.5, "closed versioned schema"),
        (1.0, "JSON integers"),
    ],
)
def test_tolerance_is_a_json_integer_from_one_to_eight(misses: Any, reason: str) -> None:
    parsed(tolerating("import", 1))
    with pytest.raises(InstanceError, match=reason):
        parsed(tolerating("import", misses))


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

    validate_instance(having(replace(imported, misses=1)))
    validate_instance(having(replace(export, misses=8)))
    for changed, reason in (
        (replace(imported, misses=3), "differs from the instance-wide one"),
        (replace(export, misses=3), "differs from the instance-wide one"),
        (replace(imported, misses=0), "closed versioned schema"),
        (replace(imported, misses=True), "closed versioned schema"),
    ):
        with pytest.raises(InstanceError, match=reason):
            validate_instance(having(changed))


def test_reports_do_not_show_or_require_the_member() -> None:
    plain = report(shipped())
    stated = report(tolerating("import", 1))
    for before, after in zip(
        plain["discovery_profiles"], stated["discovery_profiles"], strict=True
    ):
        assert set(before) == set(after)
    assert [row["status"] for row in plain["requirements"]] == [
        row["status"] for row in stated["requirements"]
    ]

"""A workload declares its LAN alias at most once."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from netorch.codec import canonical_bytes
from netorch.instance import InstanceError, parse_instance

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture
def data() -> dict[str, Any]:
    return json.loads((EXAMPLES / "instance.json").read_bytes())


def parsed(data: dict[str, Any]) -> Any:
    return parse_instance(canonical_bytes(data) + b"\n")


def alias(identifier: str, service: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "service": service,
        "strategy": "guest-lan-alias",
        "version": 1,
        "protocol": "ipv4",
        "ports": None,
        "target_ports": None,
        "dependencies": [],
        "fallback_publication": None,
    }


def test_second_lan_alias_for_one_workload_is_refused(data: dict[str, Any]) -> None:
    data["transport"] += [
        alias("example-alias", "example-web"),
        alias("example-alias-again", "example-web"),
    ]
    with pytest.raises(InstanceError, match="LAN alias at most once"):
        parsed(data)


def test_one_lan_alias_for_each_workload_is_valid(data: dict[str, Any]) -> None:
    data["transport"] += [
        alias("example-alias", "example-web"),
        alias("example-media-alias", "example-media"),
    ]
    strategies = [item.strategy for item in parsed(data).transport]
    assert strategies.count("guest-lan-alias") == 2

"""No live address in instance text, wherever it stands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from netorch.codec import canonical_bytes
from netorch.instance import InstanceError, parse_instance

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
REFUSAL = "live guest or receiver addresses"


def ipv6(*groups: str) -> str:
    """Spell an address from its groups, so that this file holds none as a literal."""
    return ":".join(groups)


UNIQUE_LOCAL = ipv6("fd12", "3456", "789a", "1", "", "10")
ABOVE_DOCUMENTATION = ipv6("2001", "db9", "", "1")
BELOW_DOCUMENTATION = ipv6("2001", "db7", "ffff", "ffff", "ffff", "ffff", "ffff", "ffff")
LINK_LOCAL = ipv6("fe80", "", "1")
MULTICAST = ipv6("ff02", "", "fb")
LOOPBACK = ipv6("", "", "1")


@pytest.fixture
def data() -> dict[str, Any]:
    return json.loads((EXAMPLES / "instance.json").read_bytes())


def parsed(data: dict[str, Any]) -> Any:
    return parse_instance(canonical_bytes(data) + b"\n")


def with_statement(data: dict[str, Any], text: str) -> dict[str, Any]:
    data["deviations"].append(
        {
            "id": "example-deviation",
            "requirement": "COEXISTENCE",
            "statement": text,
            "accepted_by": None,
            "accepted_at": None,
        }
    )
    return data


@pytest.mark.parametrize(
    "text",
    [
        "The receiver answers at 198.51.100.77.",
        "It answers at 198.51.100.77. Nothing else does.",
        "One receiver was moved (now 198.51.100.77.) last week.",
        'The label on the receiver reads "198.51.100.77."',
    ],
)
def test_address_followed_by_a_full_stop_is_refused(data: dict[str, Any], text: str) -> None:
    with pytest.raises(InstanceError, match=REFUSAL):
        parsed(with_statement(data, text))


def test_the_rule_covers_every_text_field(data: dict[str, Any]) -> None:
    data["decisions"]["lifecycle_control"]["residual"] = "The API client stays at 198.51.100.77."
    with pytest.raises(InstanceError, match=REFUSAL):
        parsed(data)


@pytest.mark.parametrize(
    "text",
    [
        "The host itself stays at 198.51.100.10.",
        "The declared LAN is 198.51.100.0/24.",
        "The declared LAN is 198.51.100.0/24 and the host is 198.51.100.10.",
    ],
)
def test_declared_lan_address_and_prefix_may_end_a_sentence(
    data: dict[str, Any], text: str
) -> None:
    assert data["host"]["lan"] == {
        "cidr": "198.51.100.0/24",
        "hardware_id": "example-adapter",
        "ipv4": "198.51.100.10",
        "link": "wired",
    }
    assert parsed(with_statement(data, text)).deviations[0].statement == text


@pytest.mark.parametrize(
    "text",
    [
        "Another prefix, 198.51.100.0/25.",
        "The host with a prefix length, 198.51.100.10/24.",
        "A neighbour of the host, 198.51.100.11.",
    ],
)
def test_only_the_exact_declared_values_are_allowed(data: dict[str, Any], text: str) -> None:
    with pytest.raises(InstanceError, match=REFUSAL):
        parsed(with_statement(data, text))


@pytest.mark.parametrize(
    "text",
    [
        "Reviewed against vendor build 1.2.3.4.5 only.",
        "The contract file is contracts/example-2.11.0.1.json today.",
        "Reviewed on macOS 27.0.1.",
        "The nightly job runs at 12:30:45 and the adapter is 02:00:00:00:00:01.",
        "The helper is named scope::member in its source.",
    ],
)
def test_text_that_only_resembles_an_address_stays_valid(data: dict[str, Any], text: str) -> None:
    assert parsed(with_statement(data, text)).deviations[0].statement == text


@pytest.mark.parametrize(
    "text",
    [
        f"Guest {UNIQUE_LOCAL} is allowed.",
        f"The guest answers at {UNIQUE_LOCAL}.",
        f"The resolver listens on [{UNIQUE_LOCAL}]:53 only.",
        f"The guest network is {ipv6('fd12', '3456', '789a', '1', '', '')}/64 today.",
        f"Seen at {UNIQUE_LOCAL}: twice.",
        f"Receivers:{UNIQUE_LOCAL}",
        f"Guest {UNIQUE_LOCAL.upper()} is allowed.",
        f"Guest {ipv6('fd12', '3456', '789a', '0001', '0000', '0000', '0000', '0010')} too.",
        f"The receiver has {ABOVE_DOCUMENTATION} as well.",
        f"The receiver has {BELOW_DOCUMENTATION} as well.",
        f"Mapped into {ipv6('fd12', '3456', '', '198.51.100.10')} for the guest.",
    ],
    ids=[
        "in-a-sentence",
        "before-a-full-stop",
        "bracketed-with-port",
        "prefix",
        "before-a-colon",
        "after-a-colon",
        "upper-case",
        "written-out",
        "just-above-documentation",
        "just-below-documentation",
        "dotted-quad-tail",
    ],
)
def test_routed_ipv6_address_is_refused(data: dict[str, Any], text: str) -> None:
    with pytest.raises(InstanceError, match=REFUSAL):
        parsed(with_statement(data, text))


@pytest.mark.parametrize(
    "text",
    [
        "The example in the guide uses 2001:db8::10.",
        "The last documentation address is 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff.",
        f"Bonjour uses the group {MULTICAST} on every link.",
        f"The router advertises itself as {LINK_LOCAL} on the link.",
        f"The health check stays on {LOOPBACK}.",
    ],
    ids=["documentation", "last-documentation", "multicast", "link-local", "loopback"],
)
def test_ipv6_text_outside_the_routed_ranges_stays_valid(data: dict[str, Any], text: str) -> None:
    assert parsed(with_statement(data, text)).deviations[0].statement == text

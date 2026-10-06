"""A value at the end of a sentence is still a value the guard must report."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from netorch.privacy import HostLiteral, scan_text
from netorch.privacy_check import load_exceptions

ROOT = Path(__file__).resolve().parents[1]
# Assembled at run time so that this file holds no value the guard would report.
ADDRESS = ".".join(["10", "25", "36", "47"])
NAMESPACE = ".".join(["me", "example", "network"])
HYPHENATED = ".".join(["org", "example", "edge-forwarding"])
LAUNCH_LABEL = ".".join(["org", "netorch", "pf"])
KERNEL_SETTING = ".".join(["net", "inet", "ip", "forwarding"])
OWNER_SOURCE = "src/netorch/pf_owner.py"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def reported(text: str) -> list[tuple[str, int, str]]:
    return [(f.kind, f.column, f.value_sha256) for f in scan_text(text, path="docs/example.md")]


@pytest.mark.parametrize("ending", [".", ". Next sentence", ".\n", '."', ".)", ".,", "..."])
def test_private_address_before_a_full_stop_is_reported(ending: str) -> None:
    assert reported("The host is at " + ADDRESS + ending) == [
        ("private-address", 16, digest(ADDRESS))
    ]


def test_private_prefix_before_a_full_stop_is_reported() -> None:
    prefix = ADDRESS + "/24"
    assert reported("Route " + prefix + ".") == [("private-address", 7, digest(prefix))]


@pytest.mark.parametrize("ending", [".", ". Next sentence", ".\n", '."', ".{owner}", ".*"])
def test_namespace_before_a_full_stop_is_reported(ending: str) -> None:
    assert reported("label " + NAMESPACE + ending) == [("namespace", 7, digest(NAMESPACE))]


def test_hyphenated_namespace_before_a_full_stop_is_reported_whole() -> None:
    assert reported("label " + HYPHENATED + ".") == [("namespace", 7, digest(HYPHENATED))]


def test_value_that_continues_after_the_dot_is_still_one_longer_token() -> None:
    longer = NAMESPACE + ".service"
    assert reported(longer + ".") == [("namespace", 1, digest(longer))]
    assert reported(ADDRESS + ".5") == []
    assert reported(ADDRESS + ".5.") == []
    assert reported("v" + ADDRESS + ".") == []


def test_documentation_and_native_values_before_a_full_stop_stay_unreported() -> None:
    text = "See 192.0.2.11. Loopback 127.0.0.1. Uses com.apple.vmnet. Built on org.python."
    assert reported(text) == []


def test_guard_sees_the_launch_label_the_owner_source_renders() -> None:
    text = (ROOT / OWNER_SOURCE).read_text(encoding="utf-8")
    found = {f.value_sha256 for f in scan_text(text, path=OWNER_SOURCE) if f.kind == "namespace"}
    assert found == {digest(LAUNCH_LABEL), digest(KERNEL_SETTING)}


def test_checked_in_exceptions_exempt_what_their_reasons_describe() -> None:
    exceptions = load_exceptions(ROOT / "schemas/privacy-exceptions.json", scope="generic")
    reasons = {item.value_sha256: item.reason for item in exceptions if item.path == OWNER_SOURCE}
    assert set(reasons) == {digest(LAUNCH_LABEL), digest(KERNEL_SETTING)}
    assert "launch namespace" in reasons[digest(LAUNCH_LABEL)]
    assert "kernel setting" in reasons[digest(KERNEL_SETTING)]


def test_instance_literal_before_a_full_stop_is_reported() -> None:
    literals = (
        HostLiteral("name", "example-server"),
        HostLiteral("port", "45678"),
        HostLiteral("private-address", "192.0.2.11"),
        HostLiteral("namespace", NAMESPACE),
    )
    text = "Runs on example-server. Port 45678. Address 192.0.2.11.\nLabel " + NAMESPACE + "."
    findings = scan_text(text, path="docs/example.md", literals=literals, generic=False)
    assert [(f.kind, f.line, f.column) for f in findings] == [
        ("name", 1, 9),
        ("port", 1, 30),
        ("private-address", 1, 45),
        ("namespace", 2, 7),
    ]


def test_instance_literal_that_continues_after_the_dot_is_not_reported() -> None:
    literals = (HostLiteral("name", "example-server"), HostLiteral("port", "45678"))
    text = "example-server.local example-server.json 45678.5 1.45678. 45678.x"
    assert scan_text(text, path="docs/example.md", literals=literals, generic=False) == ()

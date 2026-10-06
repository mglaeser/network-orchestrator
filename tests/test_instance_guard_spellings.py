"""The per-instance guard finds a chosen name in capitals and as a label of a dotted name."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from netorch.instance import instance_to_dict, load_instance, resolved_names
from netorch.privacy import HostLiteral, instance_literals, scan_text

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
# Assembled at run time so that this file holds no value the public guard would report.
NAMESPACE = ".".join(["org", "example", "site"])
NAME = "kitchen-server"
LITERALS = (
    HostLiteral("namespace", NAMESPACE),
    HostLiteral("name", NAME),
    HostLiteral("private-address", "198.51.100.10"),
    HostLiteral("port", "45678"),
    HostLiteral("interface", "example-adapter"),
    HostLiteral("home", "/example/account"),
)


def found(text):
    findings = scan_text(text, path="src/example.py", literals=LITERALS, generic=False)
    return [(f.kind, f.column, f.value_sha256) for f in findings]


def one(kind, text, value):
    """The single finding expected for ``value`` as it is written inside ``text``."""
    return [(kind, text.index(value) + 1, hashlib.sha256(value.encode("utf-8")).hexdigest())]


@pytest.mark.parametrize(
    "text",
    [
        NAME,
        NAME + ".local",
        NAME + ".local.",
        NAME + ".example.invalid",
        "http://" + NAME + ".local:8080/",
        "user@" + NAME + ".local",
        "runs on " + NAME + ".",
        "(" + NAME + ")",
        NAME + ":22",
        "host." + NAME,
        "gateway.internal." + NAME,
        "*." + NAME + ".local",
        "~/." + NAME,
        "/." + NAME + ".json",
    ],
)
def test_name_is_found_at_either_end_of_a_dotted_name(text):
    assert found(text) == one("name", text, NAME)


@pytest.mark.parametrize(
    "text",
    [
        NAMESPACE,
        NAMESPACE + ".",
        NAMESPACE + ".forwarding",
        NAMESPACE + ".plist",
        NAMESPACE + ".discovery.plist",
        "com.apple/" + NAMESPACE + ".forwarding",
        "/Library/LaunchDaemons/" + NAMESPACE + ".supervisor.plist",
        "gui/501/" + NAMESPACE + ".endpoint",
        "prefix." + NAMESPACE,
    ],
)
def test_namespace_is_found_with_labels_before_or_after_it(text):
    assert found(text) == one("namespace", text, NAMESPACE)


@pytest.mark.parametrize(
    "written",
    [NAME.upper(), NAME.title(), "Kitchen-server", "kITCHEN-sERVER"],
)
@pytest.mark.parametrize("frame", ["{}", "{}.local", "{}.LOCAL", "host.{}", "on {}."])
def test_name_is_found_in_any_letter_case(written, frame):
    text = frame.format(written)
    assert found(text) == one("name", text, written)


@pytest.mark.parametrize("written", [NAMESPACE.upper(), NAMESPACE.title()])
def test_namespace_is_found_in_any_letter_case(written):
    text = written + ".Forwarding"
    assert found(text) == one("namespace", text, written)


@pytest.mark.parametrize(
    "text",
    [
        NAME + "2",
        NAME + "s",
        NAME + "-old",
        NAME + "_old",
        "my-" + NAME,
        "my_" + NAME,
        "my" + NAME,
        "2" + NAME,
        "x" + NAME + ".local",
        NAME + "x.local",
        NAME.upper() + "2",
        NAMESPACE + "s",
        NAMESPACE + "-b",
        NAMESPACE + "_b",
        "f" + NAMESPACE,
        NAMESPACE.upper() + "S.forwarding",
    ],
)
def test_longer_token_that_merely_contains_the_value_is_not_a_finding(text):
    assert found(text) == []


@pytest.mark.parametrize(
    ("kind", "text", "value"),
    [
        ("name", "a." + NAME + ".b", NAME),
        ("name", "_ssh._tcp." + NAME + ".local", NAME),
        ("name", "www." + NAME.upper() + ".example.invalid", NAME.upper()),
        ("namespace", "x." + NAMESPACE + ".y", NAMESPACE),
    ],
)
def test_value_in_the_middle_of_a_dotted_name_is_found(kind, text, value):
    assert found(text) == one(kind, text, value)


def inner_and_outer(text):
    """Findings for an instance whose name is a label of its own namespace."""
    literals = (HostLiteral("namespace", NAMESPACE), HostLiteral("name", "example"))
    findings = scan_text(text, path="src/example.py", literals=literals, generic=False)
    return [(f.kind, f.column) for f in findings]


def test_name_inside_a_longer_chosen_value_is_reported_once_as_the_longer_value():
    assert inner_and_outer(NAMESPACE) == [("namespace", 1)]
    assert inner_and_outer(NAMESPACE.upper() + ".forwarding") == [("namespace", 1)]
    # Outside the namespace the same name is a finding of its own.
    text = NAMESPACE + " and example.local"
    assert inner_and_outer(text) == [("namespace", 1), ("name", text.index("example.local") + 1)]
    # Another dotted name that merely shares the label is not the namespace.
    assert inner_and_outer(".".join(["org", "example", "other"])) == [("name", 5)]


def test_two_kinds_with_one_spelling_are_both_reported():
    literals = (HostLiteral("namespace", NAME), HostLiteral("name", NAME))
    findings = scan_text(NAME + ".local", path="src/example.py", literals=literals, generic=False)
    assert sorted(f.kind for f in findings) == ["name", "namespace"]


@pytest.mark.parametrize(
    "text",
    [
        "198.51.100.10.5",
        "1.198.51.100.10",
        "198.51.100.100",
        "45678.5",
        "1.45678",
        "45678.x",
        "145678",
        "EXAMPLE-ADAPTER",
        "example-adapter.local",
        "host.example-adapter",
        "/EXAMPLE/ACCOUNT",
        "/example/account.json",
    ],
)
def test_address_port_interface_and_home_keep_exact_boundaries_and_case(text):
    assert found(text) == []


@pytest.mark.parametrize(
    "kind,value",
    [
        ("private-address", "198.51.100.10"),
        ("port", "45678"),
        ("interface", "example-adapter"),
        ("home", "/example/account"),
    ],
)
def test_other_kinds_are_still_found_alone_and_before_a_full_stop(kind, value):
    assert found(value) == one(kind, value, value)
    assert found("It is " + value + ".") == one(kind, "It is " + value + ".", value)


def test_names_derived_from_the_namespace_are_found_with_the_instance_literals():
    instance = load_instance(EXAMPLES / "instance.json")
    literals = instance_literals(instance_to_dict(instance))
    labels = {
        key: value for key, value in resolved_names(instance).items() if key.endswith("label")
    }
    assert len(labels) == 5
    for key, value in {**labels, "plist": labels["pf_label"] + ".plist"}.items():
        kinds = [f.kind for f in scan_text(value, path="x", literals=literals, generic=False)]
        assert "namespace" in kinds, key


def test_workload_name_with_a_domain_is_found_with_the_instance_literals():
    data = instance_to_dict(load_instance(EXAMPLES / "instance.json"))
    name = data["workloads"][0]["name"]
    for text in (name + ".local", name.upper(), "http://" + name + ".local/"):
        findings = scan_text(text, path="x", literals=instance_literals(data), generic=False)
        assert [f.kind for f in findings] == ["name"], text

from __future__ import annotations

import json

import pytest

from netorch.privacy import (
    HostLiteral,
    PrivacyError,
    PrivacyException,
    instance_literals,
    scan_framework,
    scan_text,
)


def test_generic_guard_catches_private_site_literals_without_echoing_them():
    # Assemble deliberately forbidden examples: public fixtures contain no
    # actual site's values, and generic guard CI can scan its own source.
    ip = ".".join(["10", "25", "36", "47"])
    text = (
        f"lan={ip}\ninterface=en"
        + str(29)
        + "\nroot=/Users/"
        + "example-owner"
        + "\nnamespace=me.example.network\n"
    )
    findings = scan_text(text, path="src/example.py")
    assert {f.kind for f in findings} == {"private-address", "interface", "home", "namespace"}
    assert {f.line for f in findings} == {1, 2, 3, 4}
    assert all(len(f.value_sha256) == 64 for f in findings)
    assert ip not in json.dumps([f.to_dict() for f in findings])


@pytest.mark.parametrize(
    "address", ["192.0.2.11", "198.51.100.20", "203.0.113.31", "127.0.0.1", "0.0.0.0"]
)
def test_documentation_loopback_and_wildcard_addresses_are_not_host_literals(address):
    assert not scan_text(address, path="fixture")


def test_malformed_ip_and_substrings_not_treated_as_literals():
    assert not scan_text("999.300.4.5 abc192.0.2.1x phraseen29suffix", path="fixture")


def test_native_namespace_is_distinct_from_site_namespace():
    assert not scan_text("com.apple.vmnet org.python.build org.freedesktop.avahi", path="native")
    assert scan_text("me.example.network", path="site")[0].kind == "namespace"


def test_two_way_exact_host_values_and_token_boundaries():
    literals = (
        HostLiteral("name", "example-server"),
        HostLiteral("port", "45678"),
        HostLiteral("interface", "eth-example"),
    )
    text = "example-server example-server-other 45678 145678 eth-example"
    findings = scan_text(text, path="code", literals=literals, generic=False)
    assert [(f.kind, f.column) for f in findings] == [("name", 1), ("port", 37), ("interface", 50)]


def test_exact_exception_must_be_path_kind_and_reason(tmp_path):
    (tmp_path / "platform.py").write_text('iface="en' + str(29) + '"')
    (tmp_path / "owner.py").write_text('iface="en' + str(29) + '"')
    findings = scan_framework(
        tmp_path,
        files=["platform.py", "owner.py"],
        exceptions=[
            PrivacyException("platform.py", "interface", "native interface grammar contract")
        ],
    )
    assert len(findings) == 1 and findings[0].path == "owner.py"


@pytest.mark.parametrize(
    "exception",
    [
        PrivacyException("/absolute", "home", "reason"),
        PrivacyException("../escape", "home", "reason"),
        PrivacyException("file", "unknown", "reason"),
        PrivacyException("file", "home", ""),
    ],
)
def test_unscoped_exception_rejected(tmp_path, exception):
    with pytest.raises(PrivacyError):
        scan_framework(tmp_path, files=[], exceptions=[exception])


@pytest.mark.parametrize(
    "literal",
    [
        HostLiteral("unknown", "x"),
        HostLiteral("name", ""),
        HostLiteral("name", "x\n"),
        HostLiteral("port", "0"),
        HostLiteral("port", "65536"),
        HostLiteral("port", "plain"),
    ],
)
def test_invalid_exact_literal_rejected(literal):
    with pytest.raises(PrivacyError):
        scan_text("plain", path="fixture", literals=[literal])


def test_duplicate_literal_is_not_silent(tmp_path):
    with pytest.raises(PrivacyError):
        scan_framework(tmp_path, files=[], literals=[HostLiteral("name", "example")] * 2)


@pytest.mark.parametrize("files", [["../escape"], ["/absolute"], ["./file"], ["file", "file"]])
def test_inventory_paths_bounded_and_relative(tmp_path, files):
    with pytest.raises(PrivacyError):
        scan_framework(tmp_path, files=files)


def test_scan_refuses_symlink_unreadable_binary_and_oversized_inputs(tmp_path):
    file = tmp_path / "file"
    file.write_text("safe")
    link = tmp_path / "link"
    link.symlink_to(file)
    with pytest.raises(PrivacyError):
        scan_framework(tmp_path, files=["link"])
    file.write_bytes(b"\xff")
    with pytest.raises(PrivacyError):
        scan_framework(tmp_path, files=["file"])
    file.write_bytes(b"x" * 1_048_577)
    with pytest.raises(PrivacyError):
        scan_framework(tmp_path, files=["file"])
    with pytest.raises(PrivacyError):
        scan_text("x" * 1_048_577, path="file")


def test_default_walk_only_skips_tool_state_and_reports_files(tmp_path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "unreadable").write_bytes(b"\xff")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "safe.py").write_text("127.0.0.1")
    (tmp_path / "src" / "site.py").write_text("example-server")
    result = scan_framework(
        tmp_path, literals=[HostLiteral("name", "example-server")], generic=False
    )
    assert len(result) == 1 and result[0].path == "src/site.py"


def test_instance_guard_includes_its_own_facts_and_pinned_names():
    instance = {
        "namespace": "com.example.edge",
        "host": {
            "lan": {
                "ipv4": "192.0.2.11",
                "cidr": "192.0.2.0/24",
                "hardware_id": "ethernet-device-id",
            },
            "account": {"home": "/private/example-home"},
            "runtime": {"network": "example-network"},
        },
        "names": {"anchor": "com.example.edge.pf", "launchd": ["com.example.edge.discovery"]},
        "workloads": [{"name": "example-ha"}],
        "port_ranges": [{"first": 45678, "last": 45689}],
    }
    literals = instance_literals(instance)
    assert HostLiteral("home", "/private/example-home") in literals
    assert HostLiteral("port", "45678") in literals
    assert HostLiteral("name", "com.example.edge.discovery") in literals
    assert HostLiteral("private-address", "192.0.2.11") in literals
    assert len(scan_text("example-ha 45678", path="src", literals=literals, generic=False)) == 2


def test_incomplete_instance_can_still_supply_checked_literals():
    assert instance_literals({}) == ()


def test_default_walk_refuses_unchecked_symlink_directory(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    with pytest.raises(PrivacyError, match="directory symlink"):
        scan_framework(tmp_path)


def test_aggregate_text_bound_is_a_refusal(tmp_path, monkeypatch):
    import netorch.privacy as privacy

    monkeypatch.setattr(privacy, "read_static", lambda _: b"a" * 1_048_576)
    with pytest.raises(PrivacyError, match="aggregate"):
        scan_framework(tmp_path, files=[f"file-{n}" for n in range(65)])


def test_unbounded_finding_inventory_refused():
    with pytest.raises(PrivacyError, match="findings"):
        scan_text(("en" + str(29) + " ") * 10001, path="fixture")


def test_numeric_literals_do_not_match_hashes_versions_identifiers_or_addresses():
    literal = HostLiteral("port", "53")
    text = "hashabc53def 1.53.2 id_53 version-53 192.0.2.53 53 tcp:53"
    findings = scan_text(text, path="fixture", literals=[literal], generic=False)
    assert len(findings) == 2
    assert all(text[f.column - 1 : f.column + 1] == "53" for f in findings)


@pytest.mark.parametrize("prefix", ["org", "io", "dev", "app"])
def test_two_component_reverse_dns_namespaces_are_checked(prefix):
    namespace = ".".join([prefix, "different"])
    findings = scan_text(namespace, path="fixture")
    assert len(findings) == 1 and findings[0].kind == "namespace"


def test_native_namespace_roots_stay_native():
    assert not scan_text("com.apple org.python org.freedesktop", path="native")

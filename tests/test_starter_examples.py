"""Public starter data uses real strict loaders without executing native tools."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from netorch.codec import canonical_bytes, strict_load
from netorch.config import load_config
from netorch.owners import OwnerFailure, ProcessOwner, RootReportOwner, load_bindings
from netorch.pf_owner import Installation, PFError
from netorch.runtime_settings import load_settings, parse_settings
from netorch.workloads import create_arguments, parse_workloads, provision_digest

EXAMPLES = Path(__file__).parents[1] / "examples"
ZERO = "0" * 64


def test_runtime_starter_covers_policy_with_explicit_unenrolled_identities():
    config = load_config(EXAMPLES / "network.json")
    settings = load_settings(EXAMPLES / "runtime-settings.json")
    assert settings.owner == "camera-manager"
    assert settings.accepted_version == "1.5.0"
    assert (settings.account.uid, settings.account.gid, settings.account.home) == (
        501,
        20,
        "/operator",
    )
    assert {item.service for item in settings.contracts} == {
        service.id for service in config.services
    }
    assert {item.scope for item in settings.networks} == {scope.id for scope in config.scopes}
    assert settings.networks[0].gateway == "198.51.100.1"
    assert settings.networks[0].helper_label == "org.example.vendor-helper"
    for item in settings.contracts:
        assert item.configuration_sha256 == ZERO
        assert len(item.mounts) == 1 and not item.receipts
        assert item.mounts[0].device == item.mounts[0].inode == 0
        assert item.mounts[0].path == f"/operator/state/workloads/{item.service}"


@pytest.mark.parametrize("fault", ["field", "version", "account", "hash", "identity"])
def test_runtime_starter_loader_rejects_changed_shape(fault):
    data = copy.deepcopy(strict_load(EXAMPLES / "runtime-settings.json"))
    if fault == "field":
        data["unreviewed"] = True
    elif fault == "version":
        data["accepted_version"] = "99.0.0"
    elif fault == "account":
        data["account"]["uid"] = 0
    elif fault == "hash":
        data["contracts"][0]["configuration_sha256"] = "placeholder"
    else:
        del data["contracts"][0]["mounts"][0]["inode"]
    with pytest.raises(ValueError):
        parse_settings(data)


def test_forwarding_starter_contains_independent_observer_and_matching_root_report():
    config = load_config(EXAMPLES / "network.json")
    installation = Installation.from_dict(strict_load(EXAMPLES / "forwarding-settings.json"))
    assert config.owner(installation.owner).privilege == "external-root"
    assert installation.anchor == "com.apple/netorch.site-forwarding"
    assert installation.backend_sha256 == ZERO
    assert installation.allow_apple_dns_coexistence is False
    assert parse_settings(installation.observer) == load_settings(
        EXAMPLES / "runtime-settings.json"
    )
    bindings = strict_load(EXAMPLES / "owner-bindings.json")
    root = next(item for item in bindings["owners"] if item["id"] == installation.owner)
    assert root == {
        "id": installation.owner,
        "kind": "root-report",
        "path": installation.report_path,
    }
    changed = installation.to_dict()
    changed["exec"] = "/operator/unreviewed"
    with pytest.raises(PFError):
        Installation.from_dict(changed)


def test_owner_starter_loads_only_user_processes_and_a_readonly_root_report(tmp_path):
    config = load_config(EXAMPLES / "network.json")
    path = tmp_path / "bindings.json"
    path.write_bytes((EXAMPLES / "owner-bindings.json").read_bytes())
    path.chmod(0o600)
    clients = load_bindings(config, path)
    assert set(clients) == {owner.id for owner in config.owners}
    assert isinstance(clients["site-forwarding"], RootReportOwner)
    for identifier in ("camera-manager", "bonjour-manager"):
        client = clients[identifier]
        assert isinstance(client, ProcessOwner)
        assert client.argv[0] == "/operator/runtime/bin/python3"
        assert client.argv[-1] == "request"
    changed = strict_load(path)
    changed["owners"][0] = {
        "id": "site-forwarding",
        "kind": "process",
        "argv": ["/operator/runtime/bin/python3"],
    }
    path.write_bytes(canonical_bytes(changed))
    with pytest.raises(OwnerFailure):
        load_bindings(config, path)


def test_workload_starter_builds_exact_native_policy_publications_and_bounded_udp_range():
    config = load_config(EXAMPLES / "network.json")
    settings = load_settings(EXAMPLES / "runtime-settings.json")
    recipes = parse_workloads(strict_load(EXAMPLES / "workloads.json"))
    assert {item.service for item in recipes} == {service.id for service in config.services}
    for recipe in recipes:
        assert recipe.image.startswith("example.invalid/containers/")
        assert recipe.image.endswith("@sha256:" + ZERO)
        arguments = create_arguments(config, settings, recipe)
        assert arguments[:7] == [
            "create",
            "--name",
            settings.contract(recipe.service).name,
            "--platform",
            "linux/arm64",
            "--network",
            "example-network",
        ]
        assert arguments[arguments.index("--cpus") + 1] == "2"
        assert arguments[arguments.index("--memory") + 1] == "4G"
        assert arguments[arguments.index("--volume") + 1] == (
            f"/operator/state/workloads/{recipe.service}:/config:rw"
        )
        publications = [
            arguments[index + 1] for index, arg in enumerate(arguments) if arg == "--publish"
        ]
        expected = [
            f"192.0.2.10:{profile.ports.first}:{profile.target_ports.first}/{profile.protocol}"
            for profile in config.profiles
            if profile.service == recipe.service and profile.kind == "publication"
        ]
        assert publications == expected
        if recipe.service == "media-controller":
            assert arguments[arguments.index("--sysctl") + 1] == (
                "net.ipv4.ip_local_port_range=45000 45127"
            )
    first = provision_digest(config, settings, recipes)
    assert len(first) == 64
    assert provision_digest(config, settings, recipes, start_initial=True) != first


@pytest.mark.parametrize("fault", ["extra", "mutable-image", "duplicate", "publish"])
def test_workload_starter_loader_rejects_unreviewed_or_second_port_authority(fault):
    data = copy.deepcopy(strict_load(EXAMPLES / "workloads.json"))
    if fault == "extra":
        data["restart"] = True
    elif fault == "mutable-image":
        data["workloads"][0]["image"] = "example.invalid/resolver:latest"
    elif fault == "duplicate":
        data["workloads"].append(data["workloads"][0])
    else:
        data["workloads"][0]["options"].append({"flag": "--publish", "value": "53:53/udp"})
    with pytest.raises(ValueError):
        parse_workloads(data)

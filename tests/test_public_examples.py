"""Public fixtures remain synthetic, self-consistent and reproducible."""

from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from netorch.codec import canonical_json, strict_load
from netorch.config import load_config, profile_digest, to_dict
from netorch.derive import derive
from netorch.mock import initial_snapshot, mock_admissions
from netorch.state import admissions_from_dict, snapshot_from_dict

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
DOCUMENTATION_NETWORKS = tuple(
    IPv4Network(prefix) for prefix in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def test_all_public_policy_addresses_are_documentation_only():
    config = load_config(EXAMPLES / "network.json")
    for scope in config.scopes:
        assert any(IPv4Address(scope.host_ipv4) in network for network in DOCUMENTATION_NETWORKS)
        for prefix in (scope.lan_cidr, scope.guest_cidr):
            assert any(IPv4Network(prefix).subnet_of(network) for network in DOCUMENTATION_NETWORKS)
    snapshot = snapshot_from_dict(strict_load(EXAMPLES / "snapshot.json"))
    for service in snapshot.services.values():
        assert any(
            IPv4Address(service.data["ipv4"]) in network for network in DOCUMENTATION_NETWORKS
        )


def test_example_admissions_match_current_resolved_synthetic_policy():
    config = load_config(EXAMPLES / "network.json")
    entries = admissions_from_dict(strict_load(EXAMPLES / "admissions.json"))
    assert entries == mock_admissions(config)
    assert all(
        entries[profile.id].digest == profile_digest(config, profile) for profile in config.profiles
    )


def test_example_snapshot_is_reproducible_without_a_real_runtime():
    config = load_config(EXAMPLES / "network.json")
    assert snapshot_from_dict(strict_load(EXAMPLES / "snapshot.json")) == initial_snapshot(config)


def test_generated_view_has_one_canonical_authority():
    original = load_config(EXAMPLES / "network.json")
    assert canonical_json(to_dict(derive(EXAMPLES / "owner-facts.json"))) == canonical_json(
        to_dict(original)
    )

from __future__ import annotations

import copy

import pytest

from netorch.codec import canonical_bytes
from netorch.runtime_settings import (
    contract_digest,
    load_settings,
    parse_settings,
    settings_to_dict,
)


def authored():
    return {
        "schema_version": 1,
        "owner": "camera-manager",
        "executable": "/usr/bin/example-container",
        "accepted_version": "1.5.0",
        "account": {"uid": 1001, "gid": 1001, "home": "/private/operator"},
        "networks": [
            {
                "scope": "wired-lan",
                "name": "test-network",
                "gateway": "198.51.100.1",
                "helper_domain": "gui/1001",
                "helper_label": "org.example.network",
                "helper_executable": "/usr/libexec/example-network",
                "helper_uid": 1001,
            }
        ],
        "contracts": [
            {
                "service": "camera",
                "name": "example-camera",
                "scope": "wired-lan",
                "configuration_sha256": "a" * 64,
                "mounts": [
                    {
                        "path": "/private/volumes/camera",
                        "kind": "directory",
                        "uid": 1001,
                        "device": 1,
                        "inode": 2,
                    }
                ],
                "receipts": [
                    {
                        "path": "/private/receipts/camera.json",
                        "kind": "file",
                        "uid": 1001,
                        "device": 1,
                        "inode": 3,
                        "sha256": "b" * 64,
                    }
                ],
            }
        ],
        "policy": "/private/network.json",
        "admissions": "/private/admissions.json",
        "intent": "/private/state/intent.json",
        "state_dir": "/private/state/runtime",
    }


def test_runtime_settings_roundtrip_data_and_enrollment_hash(tmp_path):
    raw = authored()
    parsed = parse_settings(raw)
    assert parse_settings(settings_to_dict(parsed)) == parsed
    path = tmp_path / "runtime.json"
    path.write_bytes(canonical_bytes(raw))
    assert load_settings(path) == parsed
    assert len(contract_digest(parsed.contract("camera"))) == 64
    changed = copy.deepcopy(raw)
    changed["contracts"][0]["mounts"][0]["inode"] += 1
    assert contract_digest(parse_settings(changed).contracts[0]) != contract_digest(
        parsed.contracts[0]
    )


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("owner", "Bad Owner"),
        ("owner", 3),
        ("executable", "relative"),
        ("executable", "/a/../b"),
        ("accepted_version", "9.9.9"),
        ("accepted_version", 1),
        ("account", {}),
        ("networks", []),
        ("networks", {}),
        ("contracts", []),
        ("contracts", {}),
        ("policy", "relative"),
        ("admissions", "/a/./b"),
        ("intent", "/a\0b"),
        ("state_dir", False),
        ("legacy_risk_acknowledged", "yes"),
        ("unknown", "ignored"),
    ],
)
def test_runtime_settings_closed_top_level(key, value):
    raw = authored()
    raw[key] = value
    with pytest.raises(ValueError):
        parse_settings(raw)


@pytest.mark.parametrize(
    "key,value",
    [
        ("uid", 0),
        ("uid", True),
        ("uid", -1),
        ("gid", -1),
        ("gid", False),
        ("home", "relative"),
        ("command", "ignore"),
    ],
)
def test_runtime_identity_must_be_explicit_unprivileged_account(key, value):
    raw = authored()
    raw["account"][key] = value
    with pytest.raises(ValueError):
        parse_settings(raw)


@pytest.mark.parametrize(
    "key,value",
    [
        ("scope", ""),
        ("name", "\n"),
        ("gateway", None),
        ("helper_domain", "gui/1002"),
        ("helper_domain", "user/1002"),
        ("helper_label", "unsafe\0"),
        ("helper_uid", -1),
        ("helper_uid", True),
        ("helper_executable", "relative"),
        ("unknown", "ignore"),
    ],
)
def test_network_settings_refuse_unknown_identity(key, value):
    raw = authored()
    raw["networks"][0][key] = value
    with pytest.raises(ValueError):
        parse_settings(raw)


@pytest.mark.parametrize(
    "key,value",
    [
        ("service", "Bad"),
        ("name", ""),
        ("scope", "unknown-scope"),
        ("configuration_sha256", "f" * 63),
        ("configuration_sha256", "F" * 64),
        ("configuration_sha256", 3),
        ("mounts", {}),
        ("receipts", "file"),
        ("unknown", "ignore"),
    ],
)
def test_service_enrollment_fields_are_closed(key, value):
    raw = authored()
    raw["contracts"][0][key] = value
    with pytest.raises(ValueError):
        parse_settings(raw)


@pytest.mark.parametrize(
    "key,value",
    [
        ("path", "/a/../b"),
        ("kind", "fifo"),
        ("kind", 3),
        ("uid", -1),
        ("uid", True),
        ("device", None),
        ("device", True),
        ("inode", -1),
        ("sha256", "A" * 64),
        ("sha256", 0),
        ("unknown", "ignore"),
    ],
)
def test_persistent_file_identity_is_inode_bound(key, value):
    raw = authored()
    raw["contracts"][0]["mounts"][0][key] = value
    with pytest.raises(ValueError):
        parse_settings(raw)


def test_socket_identity_can_reappear_without_inventing_persistent_inode():
    raw = authored()
    raw["contracts"][0]["mounts"] = [
        {"path": "/private/runtime/api.sock", "kind": "socket", "uid": 1001}
    ]
    assert parse_settings(raw).contracts[0].mounts[0].inode is None


@pytest.mark.parametrize("kind", ["network", "service", "name"])
def test_duplicate_runtime_ownership_is_rejected(kind):
    raw = authored()
    if kind == "network":
        raw["networks"].append(copy.deepcopy(raw["networks"][0]))
    else:
        duplicate = copy.deepcopy(raw["contracts"][0])
        duplicate["name" if kind == "service" else "service"] = "different"
        raw["contracts"].append(duplicate)
    with pytest.raises(ValueError):
        parse_settings(raw)


def test_legacy_reader_requires_separate_explicit_runtime_risk_ack():
    raw = authored()
    raw["accepted_version"] = "1.2.0"
    with pytest.raises(ValueError):
        parse_settings(raw)
    raw["legacy_risk_acknowledged"] = True
    assert parse_settings(raw).accepted_version == "1.2.0"

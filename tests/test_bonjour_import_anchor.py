"""An owned import that can never import, and what an active policy without records reports.

Synthetic names and RFC 5737 addresses only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch.codec import canonical_bytes
from netorch.config import config_digest, parse_config, to_dict
from netorch.discovery import Record
from netorch.discovery_plan import discovery_digest
from netorch.model import Config
from netorch.state import Intent
from netorch.storage import Store
from tests.test_bonjour_owner import (
    config,
    expected_settings,
    media_record,
    policy,
    settings,
    snapshot,
    write_private,
)

__all__ = ["config", "settings"]

READY = frozenset({"media-udp", "camera-web"})
REFUSAL = r"an owned import policy needs the _airplay\._tcp type"
WITHOUT_ANCHOR = [
    ["_companion-link._tcp", "_mediaremotetv._tcp"],
    ["_raop._tcp"],
    ["_airplay._udp"],
]


def with_import(config: Config, **changes: Any) -> dict[str, Any]:
    data = to_dict(config)
    declaration = next(item for item in data["discovery"] if item["id"] == "media-import")
    declaration.update(changes)
    return data


def settings_file(settings: owner.BonjourSettings, tmp_path: Path, data: dict[str, Any]) -> Path:
    """The owner's settings file, pointing at a policy file with this content."""
    write_private(settings.config, data)
    return write_private(tmp_path / "bonjour.json", expected_settings(settings))


@pytest.mark.parametrize("types", WITHOUT_ANCHOR)
def test_owner_refuses_settings_whose_own_import_can_never_import(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path, types: list[str]
) -> None:
    path = settings_file(settings, tmp_path, with_import(config, types=types))
    with pytest.raises(ValueError, match=REFUSAL):
        owner.load_settings(path)


@pytest.mark.parametrize("types", WITHOUT_ANCHOR)
def test_the_policy_itself_validates_as_before(config: Config, types: list[str]) -> None:
    # The refusal is this owner's: the policy model is not narrowed.
    parsed = parse_config(canonical_bytes(with_import(config, types=types)))
    assert policy(parsed).types == tuple(types)


@pytest.mark.parametrize("types", WITHOUT_ANCHOR)
def test_an_import_of_another_owner_is_not_refused_here(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path, types: list[str]
) -> None:
    data = with_import(config, types=types, owner="other-discovery")
    data["owners"].append(
        {"id": "other-discovery", "privilege": "user", "capabilities": ["discovery"]}
    )
    loaded = owner.load_settings(settings_file(settings, tmp_path, data))
    assert loaded.owner == "bonjour-manager"


@pytest.mark.parametrize(
    "types", [["_airplay._tcp"], ["_mediaremotetv._tcp", "_airplay._tcp"]], ids=["alone", "last"]
)
def test_an_import_with_its_anchor_loads_as_before(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path, types: list[str]
) -> None:
    loaded = owner.load_settings(
        settings_file(settings, tmp_path, with_import(config, types=types))
    )
    assert loaded == settings


def test_an_export_needs_no_anchor(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    # The example's HomeKit export lists no AirPlay type and loads.
    assert policy(config, "camera-export").types == ("_hap._tcp",)
    assert owner.load_settings(settings_file(settings, tmp_path, to_dict(config))) == settings


class Child:
    def __init__(self, record: Record, index: int, lifetime_seconds: int = 120) -> None:
        self.active = True

    def poll(self) -> bool:
        return True

    def close(self) -> None:
        pass


def observe(
    config: Config, settings: owner.BonjourSettings, records: dict[str, tuple[Record, ...]]
) -> dict[str, Any]:
    """One publisher tick with every policy requested, read back through the endpoint."""
    current = snapshot(config)
    store = Store(settings.state_dir)
    requests, candidates = {}, {}
    for item in config.discovery:
        common = {
            "policy_digest": discovery_digest(config, item),
            "service_generation": current.services[item.service].generation,
            "network_generation": current.network_generation,
        }
        requests[item.id] = {**common, "active": True, "requested_at": 1000}
        projection = owner.project_records(
            config, item, records.get(item.id, ()), current, READY, settings, 1000
        )
        candidates[item.id] = {
            **common,
            "records": [owner.record_to_dict(record) for record in projection],
            "interface_confirmed": True,
            "observed_at": 1000,
        }
    store.write("requests.json", {"schema_version": 1, "policies": requests})
    store.write(
        "candidates.json",
        {"schema_version": 1, "config_digest": config_digest(config), "policies": candidates},
    )
    proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
    owner.publisher_tick(config, settings, store, owner.Publisher(Child), proof, 0, 1000)  # type: ignore[arg-type]
    answer = owner.endpoint(
        config,
        settings,
        store,
        {
            "protocol_version": 1,
            "operation": "observe",
            "owner": settings.owner,
            "config": to_dict(config),
        },
    )
    profiles: dict[str, Any] = answer["result"]["profiles"]
    return profiles


def test_observation_carries_the_number_of_registered_records(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(owner.time, "time", lambda: 1000.0)
    guest = snapshot(config).services["camera"].data["ipv4"]
    # The guest advertises a port that no publication maps: nothing to publish.
    unpublished = Record(
        "Example bridge", "_hap._tcp", "guest.local.", 9444, guest, (b"id=x",), "bridge-test", 1000
    )
    observed = observe(
        config, settings, {"media-import": (media_record(),), "camera-export": (unpublished,)}
    )
    # "present" still means the declaration is active and complete for the planner ...
    assert {key: (item["state"], item["reason"]) for key, item in observed.items()} == {
        "media-import": ("present", "verified"),
        "camera-export": ("present", "verified"),
    }
    # ... and the count says how much that is: one record, and none.
    assert observed["media-import"]["data"]["record_count"] == 1
    assert observed["camera-export"]["data"]["record_count"] == 0

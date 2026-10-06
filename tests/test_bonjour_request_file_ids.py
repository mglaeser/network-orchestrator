"""Durable owner state: a retired policy id and one bulky candidate stay local.

The request file outlives a policy change, and one candidate file holds every
policy. Neither may stop the policies that are still declared and healthy.
Synthetic names and RFC 5737 addresses only.
"""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from netorch import bonjour_owner as owner
from netorch.codec import MAX_JSON_BYTES, canonical_bytes
from netorch.config import config_digest, to_dict
from netorch.discovery import Record
from netorch.discovery_plan import discovery_digest
from netorch.model import Config
from netorch.state import Intent, Snapshot
from netorch.storage import Store
from tests.test_bonjour_owner import (
    candidate_request,
    config,
    media_record,
    policy,
    settings,
    snapshot,
)

__all__ = ["config", "settings"]

READY = frozenset({"media-udp", "camera-web"})


class Child:
    made: ClassVar[list[Child]] = []

    def __init__(self, record: Record, index: int, lifetime_seconds: int = 120) -> None:
        self.record = record
        self.active = True
        Child.made.append(self)

    def poll(self) -> bool:
        return True

    def close(self) -> None:
        pass


def publisher() -> owner.Publisher:
    Child.made = []
    return owner.Publisher(Child)  # type: ignore[arg-type]


def stored(
    config: Config, settings: owner.BonjourSettings, extra: dict[str, Any]
) -> tuple[Store, Snapshot, dict[str, Any]]:
    """An active request and a complete candidate for the import policy, plus `extra`."""
    current = snapshot(config)
    request, candidate = candidate_request(config, settings, current, media_record())
    store = Store(settings.state_dir)
    store.write(
        "requests.json", {"schema_version": 1, "policies": {"media-import": request, **extra}}
    )
    store.write(
        "candidates.json",
        {
            "schema_version": 1,
            "config_digest": config_digest(config),
            "policies": {"media-import": candidate, **extra},
        },
    )
    return store, current, request


def test_retired_policy_id_no_longer_stops_the_remaining_policies(
    config: Config, settings: owner.BonjourSettings
) -> None:
    # Written by an earlier release whose policy still declared this export.
    retired = {"retired-export": {"active": False, "requested_at": 900}}
    store, current, _request = stored(config, settings, retired)
    proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
    observed = owner.publisher_tick(config, settings, store, publisher(), proof, 0, 1000).profiles
    assert {key: (value.state, value.reason) for key, value in observed.items()} == {
        "media-import": ("present", "verified"),
        "camera-export": ("absent", "confirmed-absent"),
    }
    assert [child.record.name for child in Child.made] == ["Example speaker"]


def test_request_for_an_undeclared_id_cannot_register_anything(
    config: Config, settings: owner.BonjourSettings
) -> None:
    current = snapshot(config)
    request, candidate = candidate_request(config, settings, current, media_record())
    store = Store(settings.state_dir)
    # A complete, active, current-looking request and candidate under a name the
    # policy does not declare.
    store.write("requests.json", {"schema_version": 1, "policies": {"renamed-import": request}})
    store.write(
        "candidates.json",
        {
            "schema_version": 1,
            "config_digest": config_digest(config),
            "policies": {"renamed-import": candidate},
        },
    )
    proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
    observed = owner.publisher_tick(config, settings, store, publisher(), proof, 0, 1000).profiles
    assert {value.state for value in observed.values()} == {"absent"}
    assert Child.made == []
    assert owner.desired_requests(config, settings, store) == {}


def test_endpoint_removes_undeclared_ids_with_its_next_write(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    retired = {"retired-export": {"active": True}, "another-old-id": 7}
    store, current, _request = stored(config, settings, retired)
    media = policy(config)
    monkeypatch.setattr(owner.time, "monotonic", iter((0, 8)).__next__)
    # Before this change even a withdrawal was refused: "foreign discovery intent".
    answer = owner.endpoint(
        config,
        settings,
        store,
        {
            "protocol_version": 1,
            "operation": "reconcile-discovery",
            "owner": settings.owner,
            "policy_digest": config_digest(config),
            "discovery_digest": discovery_digest(config, media),
            "discovery": media.id,
            "active": False,
            "config": to_dict(config),
            "service_generation": current.services[media.service].generation,
            "network_generation": current.network_generation,
        },
    )
    assert answer["owner"] == settings.owner
    written = store.read("requests.json")
    assert set(written["policies"]) == {"media-import"}
    assert written["policies"]["media-import"]["active"] is False


@pytest.mark.parametrize(
    "damaged",
    [
        {"schema_version": 2, "policies": {}},
        {"schema_version": 1, "policies": []},
        {"schema_version": 1, "policies": {}, "extra": True},
        [],
    ],
    ids=["version", "policies-not-an-object", "extra-key", "not-an-object"],
)
def test_damaged_request_file_still_invalidates_every_policy(
    config: Config, settings: owner.BonjourSettings, damaged: Any
) -> None:
    store, current, _request = stored(config, settings, {})
    store.write("requests.json", damaged)
    proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
    observed = owner.publisher_tick(config, settings, store, publisher(), proof, 0, 1000).profiles
    assert {(value.state, value.reason) for value in observed.values()} == {
        ("unknown", "malformed")
    }
    assert Child.made == []


def scanned(
    monkeypatch: pytest.MonkeyPatch,
    config: Config,
    settings: owner.BonjourSettings,
    speakers: int,
    txt: tuple[bytes, ...],
) -> tuple[Store, Snapshot]:
    """One real scanner pass over a fake link with `speakers` eligible devices."""
    current = snapshot(config)
    clock = type(
        "Clock", (), {"time": staticmethod(lambda: 1000.0), "monotonic": staticmethod(lambda: 10.0)}
    )()
    monkeypatch.setattr(owner, "time", clock)
    monkeypatch.setattr(owner, "independent_snapshot", lambda *_args: (current, Intent(), READY))
    monkeypatch.setattr(owner, "_interfaces", lambda *_args: {"wired-lan": (7, 9)})
    guest = current.services["camera"].data["ipv4"]

    def scan(
        interface: str, _index: int, kind: str, _limit: int, _seconds: int, now: float, **_more: Any
    ) -> tuple[Record, ...]:
        if kind == "_hap._tcp":
            return (
                Record(
                    "Example bridge", kind, "guest.local.", 9443, guest, (b"id=x",), interface, now
                ),
            )
        if kind == "_airplay._tcp":
            return tuple(
                Record(
                    f"Speaker {number}",
                    kind,
                    f"speaker-{number}.local.",
                    7000,
                    f"192.0.2.{20 + number}",
                    txt,
                    interface,
                    now,
                )
                for number in range(speakers)
            )
        return ()

    monkeypatch.setattr(owner, "scan", scan)
    store = Store(settings.state_dir)
    owner.scan_pass(config, settings, store)
    return store, current


# 8728 bytes of TXT: under the 8900-byte limit of one record.
BULKY = (b"model=AudioAccessory5,1", *([b"p" * 255] * 34))


def test_bulky_policy_gets_its_own_reason_and_the_others_keep_their_lease(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 100 devices are under the policy's bound of 128 records; together their
    # candidate alone is larger than the state file may be.
    store, current = scanned(monkeypatch, config, settings, 100, BULKY)
    written = store.read("candidates.json")
    assert "reason" not in written
    media, camera = written["policies"]["media-import"], written["policies"]["camera-export"]
    assert (media["records"], media["reason"]) == ([], "incomplete")
    assert len(camera["records"]) == 1 and "reason" not in camera

    requests = {
        item.id: {
            "active": True,
            "policy_digest": discovery_digest(config, item),
            "service_generation": current.services[item.service].generation,
            "network_generation": current.network_generation,
            "requested_at": 1000.0,
        }
        for item in config.discovery
    }
    store.write("requests.json", {"schema_version": 1, "policies": requests})
    proof = (current, Intent(), READY, {"wired-lan": (7, 9)})
    observed = owner.publisher_tick(config, settings, store, publisher(), proof, 0, 1000.0).profiles
    assert (observed["camera-export"].state, observed["camera-export"].reason) == (
        "present",
        "verified",
    )
    assert (observed["media-import"].state, observed["media-import"].reason) == (
        "unknown",
        "unobserved",
    )
    assert [child.record.name for child in Child.made] == ["Example bridge"]


def test_pass_that_fits_is_written_as_before(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _current = scanned(monkeypatch, config, settings, 100, (b"model=AudioAccessory5,1",))
    written = store.read("candidates.json")
    assert len(canonical_bytes(written)) < MAX_JSON_BYTES
    assert len(written["policies"]["media-import"]["records"]) == 100
    assert len(written["policies"]["camera-export"]["records"]) == 1
    assert all("reason" not in value for value in written["policies"].values())

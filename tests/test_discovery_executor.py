"""Mocked discovery/transport coordination and partial publication failures."""

from __future__ import annotations

from dataclasses import replace

import pytest

from netorch.config import profile_digest
from netorch.discovery_plan import discovery_digest
from netorch.executor import execute
from netorch.mock import MockOwner, initial_snapshot, mock_admissions
from netorch.model import Config, Discovery, Owner, PortRange, Profile, Safety, Scope, Service
from netorch.owners import OwnerFailure
from netorch.planner import plan
from netorch.state import Intent, Observation, intent_to_dict
from netorch.storage import Store

NOW = 1000.0


def policy():
    runtime = Owner("runtime", "user", ("publication",))
    publisher = Owner("publisher", "user", ("discovery",))
    service = Service("camera", runtime.id, "a" * 64)
    scope = Scope("lan", "test0", "192.0.2.10", "192.0.2.0/24", "198.51.100.0/24")
    profile = Profile(
        "camera-web",
        service.id,
        scope.id,
        "publication",
        "tcp",
        PortRange(9443, 9443),
        PortRange(9443, 9443),
        Safety("structural", 10, 1),
    )
    discovery = Discovery(
        "camera-export",
        publisher.id,
        service.id,
        scope.id,
        "export",
        ("_hap._tcp",),
        (profile.id,),
        10,
        16,
    )
    return Config(
        1, "example", (scope,), (runtime, publisher), (service,), (profile,), (discovery,)
    )


class RecordingClient:
    # Enforce the live client fencing path while all effects remain in MockOwner.
    simulation = False

    def __init__(self, backend, *, fault=None):
        self.backend = backend
        self.fault = fault
        self.events = []

    def observe(self):
        return self.backend.observe()

    def apply(self, action):
        self.events.append(("transport", action.operation))
        return self.backend.apply(action)

    def reconcile_discovery(self, action):
        self.events.append(("discovery", action.active))
        result = self.backend.reconcile_discovery(action)
        return self.fault(result, action) if self.fault else result


def context(tmp_path, *, publisher_state=None, publisher_digest=None):
    config = policy()
    snapshot = initial_snapshot(config)
    endpoint = snapshot.services["camera"]
    profile = config.profiles[0]
    profiles = {
        profile.id: Observation(
            "present",
            "verified",
            NOW,
            "runtime-generation",
            {
                "policy_digest": profile_digest(config, profile),
                "target_ipv4": endpoint.data["ipv4"],
                "target_generation": endpoint.generation,
                "network_generation": snapshot.network_generation,
                "states": [],
            },
        )
    }
    if publisher_state is not None:
        item = config.discovery[0]
        profiles[item.id] = Observation(
            publisher_state,
            "verified" if publisher_state == "present" else "confirmed-absent",
            NOW,
            "publisher-generation",
            {
                "policy_digest": publisher_digest or discovery_digest(config, item),
                "interface_confirmed": True,
                "service_generation": endpoint.generation,
                "network_generation": snapshot.network_generation,
                "states": [],
            },
        )
    snapshot = replace(snapshot, profiles=profiles)
    admissions = mock_admissions(config)
    backend = MockOwner(config, snapshot, admissions)
    client = RecordingClient(backend)
    store = Store(tmp_path / "state")
    intent = Intent()
    store.write("intent.json", intent_to_dict(intent))
    return config, admissions, backend, client, store, intent


def cycle(config, admissions, backend, client, store, intent, *, missing_publisher=False):
    snapshot = backend.observe()
    candidate = plan(config, snapshot, admissions, intent, NOW)
    store.write("intent.json", intent_to_dict(intent))
    clients = {"runtime": client}
    if not missing_publisher:
        clients["publisher"] = client
    return execute(
        config,
        candidate,
        snapshot,
        intent,
        clients,
        store,
        admissions=admissions,
        now=NOW,
        observe_now=backend.observe,
        clock=lambda: NOW,
    )


def test_missing_publisher_is_cleaned_before_a_fresh_cycle_can_activate(tmp_path):
    config, admissions, backend, client, store, intent = context(tmp_path)
    result = cycle(config, admissions, backend, client, store, intent)
    assert result.phase == "inhibited"
    assert client.events == [("discovery", False)]
    assert backend.snapshot.profiles["camera-export"].state == "absent"
    assert not (store.directory / "receipt.json").exists()
    result = cycle(config, admissions, backend, client, store, intent)
    assert result.phase == "committed"
    assert client.events[-1] == ("discovery", True)
    observed = backend.snapshot.profiles["camera-export"]
    assert observed.state == "present"
    assert observed.data["service_generation"] == backend.snapshot.services["camera"].generation
    assert observed.data["network_generation"] == backend.snapshot.network_generation


def test_complete_absence_with_transport_readback_permits_publish(tmp_path):
    config, admissions, backend, client, store, intent = context(tmp_path, publisher_state="absent")
    result = cycle(config, admissions, backend, client, store, intent)
    assert result.phase == "committed"
    assert client.events == [("discovery", True)]
    assert backend.snapshot.profiles["camera-export"].state == "present"


def test_verified_current_publisher_is_not_rewritten_unnecessarily(tmp_path):
    config, admissions, backend, client, store, intent = context(
        tmp_path, publisher_state="present"
    )
    result = cycle(config, admissions, backend, client, store, intent)
    assert result.phase == "committed"
    assert not client.events


def test_operator_pause_withdraws_publication_before_forwarding(tmp_path):
    config, admissions, backend, client, store, intent = context(
        tmp_path, publisher_state="present"
    )
    paused = intent.pause()
    cycle(config, admissions, backend, client, store, paused)
    assert client.events[0] == ("discovery", False)
    assert ("transport", "withdraw") in client.events[1:]
    assert backend.snapshot.profiles["camera-export"].state == "absent"
    assert backend.snapshot.profiles["camera-web"].state == "absent"
    assert store.read("intent.json")["operator_paused"]


def test_changed_publisher_policy_withdraws_before_reactivation(tmp_path):
    config, admissions, backend, client, store, intent = context(
        tmp_path, publisher_state="present", publisher_digest="0" * 64
    )
    result = cycle(config, admissions, backend, client, store, intent)
    assert result.phase == "inhibited"
    assert client.events == [("discovery", False)]
    assert backend.snapshot.profiles["camera-export"].state == "absent"
    result = cycle(config, admissions, backend, client, store, intent)
    assert result.phase == "committed"
    assert client.events[-1] == ("discovery", True)
    assert backend.snapshot.profiles["camera-export"].data["policy_digest"] == discovery_digest(
        config, config.discovery[0]
    )


@pytest.mark.parametrize("field", ["service_generation", "network_generation"])
@pytest.mark.parametrize("publisher_state", ["present", "absent"])
def test_retired_publisher_generation_requires_cleanup_before_reactivation(
    tmp_path,
    field,
    publisher_state,
):
    config, admissions, backend, client, store, intent = context(
        tmp_path, publisher_state=publisher_state
    )
    previous = backend.snapshot.profiles["camera-export"]
    profiles = dict(backend.snapshot.profiles)
    profiles["camera-export"] = replace(
        previous, data={**previous.data, field: "retired-generation"}
    )
    backend.snapshot = replace(backend.snapshot, profiles=profiles)
    result = cycle(config, admissions, backend, client, store, intent)
    assert result.phase == "inhibited"
    assert client.events == [("discovery", False)]
    assert cycle(config, admissions, backend, client, store, intent).phase == "committed"
    assert client.events[-1] == ("discovery", True)


@pytest.mark.parametrize(
    "fault",
    [
        "unknown",
        "stale",
        "future",
        "absent",
        "digest",
        "interface",
        "service-generation",
        "network-generation",
    ],
)
def test_lying_discovery_readback_preserves_failed_journal(tmp_path, fault):
    config, admissions, backend, client, store, intent = context(tmp_path, publisher_state="absent")

    def corrupt(result, action):
        if fault == "unknown":
            return Observation("unknown", "timed-out", NOW, result.generation, result.data)
        if fault == "stale":
            return replace(result, observed_at=NOW - 11)
        if fault == "future":
            return replace(result, observed_at=NOW + 1)
        if fault == "absent":
            return replace(result, state="absent", reason="confirmed-absent")
        key, value = {
            "digest": ("policy_digest", "0" * 64),
            "interface": ("interface_confirmed", False),
            "service-generation": ("service_generation", "retired-service"),
            "network-generation": ("network_generation", "retired-network"),
        }[fault]
        return replace(result, data={**result.data, key: value})

    client.fault = corrupt
    with pytest.raises(OwnerFailure):
        cycle(config, admissions, backend, client, store, intent)
    assert client.events == [("discovery", True)]
    # The registration actually happened in the mock before the failed reply.
    # Journal visibility, rather than speculative automatic reversal, is required.
    assert backend.snapshot.profiles["camera-export"].state == "present"
    assert store.read("journal.json")["phase"] == "failed"
    assert not (store.directory / "receipt.json").exists()


def test_missing_publisher_client_is_pending_without_a_registration(tmp_path):
    config, admissions, backend, client, store, intent = context(tmp_path, publisher_state="absent")
    result = cycle(config, admissions, backend, client, store, intent, missing_publisher=True)
    assert result.phase == "waiting-external-owner"
    assert "camera-export" in result.pending
    assert not client.events
    assert backend.snapshot.profiles["camera-export"].state == "absent"


def test_discovery_owner_fault_prevents_subsequent_transport_writes(tmp_path):
    config, admissions, backend, client, store, intent = context(
        tmp_path, publisher_state="present"
    )

    def broken(action):
        client.events.append(("discovery", action.active))
        raise OwnerFailure("injected publisher process fault")

    client.reconcile_discovery = broken
    with pytest.raises(OwnerFailure):
        cycle(config, admissions, backend, client, store, intent.pause())
    assert client.events == [("discovery", False)]
    assert backend.snapshot.profiles["camera-web"].state == "present"
    assert store.read("journal.json")["phase"] == "failed"

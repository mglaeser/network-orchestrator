from __future__ import annotations

from pathlib import Path

import pytest

from netorch.codec import canonical_bytes
from netorch.config import load_config
from netorch.owners import ExternalOwnerRequired, OwnerFailure, ProcessOwner
from netorch.planner import Action
from netorch.process import Result


def client(monkeypatch):
    config = load_config(Path(__file__).resolve().parents[1] / "examples/network.json")
    profile = config.profile("camera-web")
    owner = config.profile_owner(profile).id
    monkeypatch.setattr("netorch.owners.os.geteuid", lambda: 1000)
    return ProcessOwner(config, owner, ["/usr/bin/fixture-reader"]), profile


@pytest.mark.parametrize("operation", ["activate", "withdraw", "drain"])
def test_native_fixed_socket_is_explicit_maintenance_without_false_readback(monkeypatch, operation):
    provider, profile = client(monkeypatch)
    envelope = {
        "protocol_version": 1,
        "owner": provider.owner,
        "error": "native-publication-maintenance",
    }
    monkeypatch.setattr(
        "netorch.owners.run", lambda *args, **kwargs: Result(78, canonical_bytes(envelope), b"")
    )
    with pytest.raises(ExternalOwnerRequired, match="explicit application maintenance"):
        provider.apply(Action(profile.id, provider.owner, operation, "paused"))


@pytest.mark.parametrize(
    "mutation",
    ["boolean-version", "wrong-owner", "wrong-error", "extra-field", "wrong-status", "broken"],
)
def test_only_exact_maintenance_contract_can_defer_a_native_publication(monkeypatch, mutation):
    provider, profile = client(monkeypatch)
    envelope = {
        "protocol_version": 1,
        "owner": provider.owner,
        "error": "native-publication-maintenance",
    }
    status = 78
    if mutation == "boolean-version":
        envelope["protocol_version"] = True
    elif mutation == "wrong-owner":
        envelope["owner"] = "foreign"
    elif mutation == "wrong-error":
        envelope["error"] = "unknown"
    elif mutation == "extra-field":
        envelope["result"] = "withdrawn"
    elif mutation == "wrong-status":
        status = 69
    raw = b"{" if mutation == "broken" else canonical_bytes(envelope)
    monkeypatch.setattr(
        "netorch.owners.run", lambda *args, **kwargs: Result(status, raw, b"private diagnostic")
    )
    with pytest.raises((OwnerFailure, ValueError)) as caught:
        provider.apply(Action(profile.id, provider.owner, "withdraw", "paused"))
    assert not isinstance(caught.value, ExternalOwnerRequired)


def test_maintenance_status_is_never_an_observation_of_absence(monkeypatch):
    provider, _profile = client(monkeypatch)
    envelope = {
        "protocol_version": 1,
        "owner": provider.owner,
        "error": "native-publication-maintenance",
    }
    monkeypatch.setattr(
        "netorch.owners.run", lambda *args, **kwargs: Result(78, canonical_bytes(envelope), b"")
    )
    snapshot = provider.observe()
    assert snapshot.network_generation is None
    assert all(item.state == "unknown" for item in snapshot.services.values())
    assert all(item.state == "unknown" for item in snapshot.profiles.values())

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from netorch.codec import canonical_bytes
from netorch.config import config_digest, load_config, to_dict
from netorch.discovery_plan import DiscoveryAction, discovery_digest
from netorch.mock import initial_snapshot
from netorch.owners import (
    ExternalOwnerRequired,
    OwnerFailure,
    ProcessOwner,
    SnapshotFileOwner,
    load_bindings,
    observe,
)
from netorch.planner import Action
from netorch.process import OutputLimit, ProcessTimeout, Result
from netorch.state import Observation, Snapshot, observation_to_dict, snapshot_to_dict


@pytest.fixture
def config():
    return load_config(Path(__file__).resolve().parents[1] / "examples/network.json")


def binding_file(tmp_path, entries, **extra):
    path = tmp_path / "bindings.json"
    path.write_text(json.dumps({"schema_version": 1, "owners": entries, **extra}))
    path.chmod(0o600)
    return path


def test_external_root_can_only_bind_snapshot_not_process(config, tmp_path):
    root = next(owner for owner in config.owners if owner.privilege == "external-root")
    with pytest.raises(OwnerFailure):
        load_bindings(
            config,
            binding_file(tmp_path, [{"id": root.id, "kind": "process", "argv": ["/usr/bin/true"]}]),
        )
    clients = load_bindings(
        config,
        binding_file(
            tmp_path,
            [{"id": root.id, "kind": "snapshot-file", "path": str(tmp_path / "snapshot.json")}],
        ),
    )
    assert isinstance(clients[root.id], SnapshotFileOwner)
    with pytest.raises(ExternalOwnerRequired):
        clients[root.id].apply(Action("dns-udp", root.id, "withdraw", "paused"))


def test_user_owner_can_bind_only_explicit_absolute_command(config, tmp_path):
    user = next(owner for owner in config.owners if owner.privilege == "user")
    clients = load_bindings(
        config,
        binding_file(tmp_path, [{"id": user.id, "kind": "process", "argv": ["/usr/bin/true"]}]),
    )
    assert isinstance(clients[user.id], ProcessOwner)


@pytest.mark.parametrize(
    "mutation",
    [
        "relative-command",
        "nul-command",
        "empty-command",
        "unknown-kind",
        "unknown-field",
        "duplicate-owner",
        "relative-snapshot",
        "unknown-top",
        "bool-version",
    ],
)
def test_owner_binding_format_is_closed(config, tmp_path, mutation):
    user = next(owner for owner in config.owners if owner.privilege == "user")
    raw = {"id": user.id, "kind": "process", "argv": ["/usr/bin/true"]}
    if mutation == "relative-command":
        raw["argv"] = ["true"]
    elif mutation == "nul-command":
        raw["argv"] = ["/usr/bin/tr\x00ue"]
    elif mutation == "empty-command":
        raw["argv"] = []
    elif mutation == "unknown-kind":
        raw["kind"] = "root-rpc"
    elif mutation == "unknown-field":
        raw["secret"] = "hidden"
    elif mutation == "relative-snapshot":
        raw = {"id": user.id, "kind": "snapshot-file", "path": "relative.json"}
    entries = [raw, raw] if mutation == "duplicate-owner" else [raw]
    path = binding_file(
        tmp_path, entries, **({"secret": "hidden"} if mutation == "unknown-top" else {})
    )
    if mutation == "bool-version":
        path.write_text(json.dumps({"schema_version": True, "owners": entries}))
    with pytest.raises(OwnerFailure):
        load_bindings(config, path)


@pytest.mark.parametrize("mode", [0o644, 0o660, 0o400])
def test_binding_file_requires_exact_private_mode(config, tmp_path, mode):
    path = binding_file(tmp_path, [])
    path.chmod(mode)
    with pytest.raises(OwnerFailure):
        load_bindings(config, path)


def test_binding_file_symlink_and_hardlink_rejected(config, tmp_path):
    path = binding_file(tmp_path, [])
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(path)
    with pytest.raises(OSError):
        load_bindings(config, symlink)
    hardlink = tmp_path / "hardlink.json"
    os.link(path, hardlink)
    with pytest.raises(OwnerFailure):
        load_bindings(config, path)


def user_process(config, monkeypatch):
    user = next(owner for owner in config.owners if owner.privilege == "user")
    monkeypatch.setattr("netorch.owners.os.geteuid", lambda: 1000)
    return ProcessOwner(config, user.id, ["/usr/bin/owner-adapter"])


def install_response(monkeypatch, owner, result, *, protocol_version=1, returncode=0):
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return Result(
            returncode,
            canonical_bytes(
                {"protocol_version": protocol_version, "owner": owner, "result": result}
            ),
            b"",
        )

    monkeypatch.setattr("netorch.owners.run", runner)
    return calls


def test_user_process_sends_fixed_json_request_and_parses_complete_observation(config, monkeypatch):
    client = user_process(config, monkeypatch)
    snapshot = initial_snapshot(config)
    calls = install_response(monkeypatch, client.owner, snapshot_to_dict(snapshot))
    assert client.observe() == snapshot
    request = json.loads(calls[0][1]["input_data"])
    assert request["protocol_version"] == 1
    assert request["operation"] == "observe"
    assert request["owner"] == client.owner
    assert calls[0][1]["timeout"] == 10


@pytest.mark.parametrize(
    "failure,reason",
    [
        (ProcessTimeout("deadline"), "timed-out"),
        (PermissionError("denied"), "inaccessible"),
        (OutputLimit("bound"), "malformed"),
        (OSError("unavailable"), "malformed"),
    ],
)
def test_process_read_failure_becomes_unknown_without_recovery(
    config, monkeypatch, failure, reason
):
    client = user_process(config, monkeypatch)

    def runner(*args, **kwargs):
        raise failure

    monkeypatch.setattr("netorch.owners.run", runner)
    result = client.observe()
    assert result.network_generation is None
    assert all(
        item.state == "unknown" and item.reason == reason
        for item in (*result.services.values(), *result.profiles.values())
    )


@pytest.mark.parametrize(
    "failure",
    [
        "nonzero",
        "bad-json",
        "bad-utf8",
        "wrong-owner",
        "wrong-version",
        "bool-version",
        "unknown-field",
        "bad-result",
    ],
)
def test_malformed_provider_response_never_proves_presence(config, monkeypatch, failure):
    client = user_process(config, monkeypatch)
    payload = {
        "protocol_version": 1,
        "owner": client.owner,
        "result": snapshot_to_dict(initial_snapshot(config)),
    }
    status = 0
    if failure == "nonzero":
        status = 75
    elif failure == "wrong-owner":
        payload["owner"] = "another-owner"
    elif failure == "wrong-version":
        payload["protocol_version"] = 2
    elif failure == "bool-version":
        payload["protocol_version"] = True
    elif failure == "unknown-field":
        payload["secret"] = "do-not-echo"
    elif failure == "bad-result":
        payload["result"] = {}
    raw = (
        b"{broken"
        if failure == "bad-json"
        else b"\xff"
        if failure == "bad-utf8"
        else canonical_bytes(payload)
    )
    monkeypatch.setattr(
        "netorch.owners.run", lambda *args, **kwargs: Result(status, raw, b"private stderr")
    )
    result = client.observe()
    assert result.network_generation is None
    assert all(
        item.state == "unknown" for item in (*result.services.values(), *result.profiles.values())
    )


def test_process_apply_requires_matching_owner_and_fixed_operation(config, monkeypatch):
    client = user_process(config, monkeypatch)
    observation = Observation("absent", "confirmed-absent", 1000, None, {"states": []})
    calls = install_response(monkeypatch, client.owner, observation_to_dict(observation))
    profile = next(
        item for item in config.profiles if config.profile_owner(item).id == client.owner
    )
    assert client.apply(Action(profile.id, client.owner, "withdraw", "paused")) == observation
    request = json.loads(calls[0][1]["input_data"])
    assert request["operation"] == "reconcile"
    assert request["profile"] == profile.id and request["action"] == "withdraw"
    assert len(request["profile_digest"]) == 64
    with pytest.raises(OwnerFailure):
        client.apply(Action(profile.id, "different-owner", "withdraw", "paused"))
    with pytest.raises(OwnerFailure):
        client.apply(Action(profile.id, client.owner, "noop", "verified"))


def test_live_process_client_refuses_privileged_launch_and_external_owner(config, monkeypatch):
    def runner(*args, **kwargs):
        raise AssertionError("no privileged client call may occur")

    monkeypatch.setattr("netorch.owners.run", runner)
    client = user_process(config, monkeypatch)
    monkeypatch.setattr("netorch.owners.os.geteuid", lambda: 0)
    with pytest.raises(OwnerFailure):
        client._request("observe", {})
    monkeypatch.setattr("netorch.owners.os.geteuid", lambda: 1000)
    root = next(owner for owner in config.owners if owner.privilege == "external-root")
    with pytest.raises(ExternalOwnerRequired):
        ProcessOwner(config, root.id, ["/usr/bin/never"])._request("observe", {})


def test_snapshot_file_reader_errors_are_unknown_and_apply_never_calls_root(config, tmp_path):
    owner = config.owners[0].id
    path = tmp_path / "snapshot.json"
    client = SnapshotFileOwner(config, owner, path)
    assert all(item.state == "unknown" for item in client.observe().profiles.values())
    path.write_text('{"bad":true}')
    assert client.observe().network_generation is None
    snapshot = initial_snapshot(config)
    path.write_bytes(canonical_bytes(snapshot_to_dict(snapshot)))
    assert client.observe() == snapshot
    with pytest.raises(ExternalOwnerRequired):
        client.apply(Action("dns-udp", owner, "withdraw", "paused"))


class StaticClient:
    simulation = False

    def __init__(self, snapshot):
        self.snapshot = snapshot

    def observe(self):
        return self.snapshot


def owned_snapshot(config, owner, generation="network-one"):
    initial = initial_snapshot(config)
    return Snapshot(
        1000,
        generation,
        {
            key: value
            for key, value in initial.services.items()
            if config.service(key).owner == owner
        },
        {
            key: value
            for key, value in initial.profiles.items()
            if config.profile_owner(key).id == owner
        },
    )


def test_owner_merge_excludes_cross_owner_claims(config):
    root = next(owner for owner in config.owners if owner.privilege == "external-root")
    camera = config.service("camera")
    if camera.owner == root.id:
        pytest.fail("synthetic camera must retain a user-level manager")
    malicious = replace(
        owned_snapshot(config, root.id),
        services={camera.id: initial_snapshot(config).services[camera.id]},
    )
    result = observe(config, {root.id: StaticClient(malicious)})
    assert result.profiles["dns-udp"].reason == "identity-mismatch"
    assert result.services[camera.id].state == "unknown"


def test_owner_merge_requires_one_shared_network_generation(config):
    clients = {owner.id: StaticClient(owned_snapshot(config, owner.id)) for owner in config.owners}
    result = observe(config, clients)
    assert result.network_generation == "network-one"
    relevant = next(owner for owner in config.owners if config.service("camera").owner == owner.id)
    clients[relevant.id] = StaticClient(owned_snapshot(config, relevant.id, "network-two"))
    assert observe(config, clients).network_generation is None


def test_missing_owner_produces_unknown_evidence(config):
    result = observe(config, {})
    assert result.network_generation is None
    assert set(result.services) == {service.id for service in config.services}
    assert set(result.profiles) == {profile.id for profile in config.profiles}.union(
        policy.id for policy in config.discovery
    )
    assert all(item.state == "unknown" for item in result.services.values())


def discovery_client(config, monkeypatch):
    policy = config.discovery[0]
    monkeypatch.setattr("netorch.owners.os.geteuid", lambda: 1000)
    client = ProcessOwner(config, policy.owner, ["/usr/bin/discovery-adapter"])
    action = DiscoveryAction(
        policy.id,
        policy.owner,
        True,
        "ready",
        discovery_digest(config, policy),
        "example-service-instance",
        "network-one",
    )
    return client, action


def test_discovery_reconcile_uses_fixed_bounded_data_contract(config, monkeypatch):
    client, action = discovery_client(config, monkeypatch)
    expected = Observation(
        "present",
        "verified",
        1000,
        "publisher-instance-1",
        {
            "policy_digest": action.policy_digest,
            "interface_confirmed": True,
        },
    )
    calls = install_response(monkeypatch, client.owner, observation_to_dict(expected))
    assert client.reconcile_discovery(action) == expected
    request = json.loads(calls[0][1]["input_data"])
    assert set(request) == {
        "protocol_version",
        "operation",
        "owner",
        "config",
        "policy_digest",
        "discovery_digest",
        "discovery",
        "active",
        "service_generation",
        "network_generation",
    }
    assert request == {
        "protocol_version": 1,
        "operation": "reconcile-discovery",
        "owner": client.owner,
        "config": to_dict(config),
        "policy_digest": config_digest(config),
        "discovery_digest": action.policy_digest,
        "discovery": action.id,
        "active": True,
        "service_generation": action.service_generation,
        "network_generation": action.network_generation,
    }
    assert calls[0][1]["timeout"] == 10


@pytest.mark.parametrize("mutation", ["wrong-owner", "unknown-policy", "changed-digest"])
def test_discovery_reconcile_rejects_unbound_action_before_provider_call(
    config, monkeypatch, mutation
):
    client, action = discovery_client(config, monkeypatch)
    if mutation == "wrong-owner":
        action = replace(action, owner="another-owner")
    elif mutation == "unknown-policy":
        action = replace(action, id="unknown-policy")
    else:
        action = replace(action, policy_digest="0" * 64)

    def runner(*args, **kwargs):
        raise AssertionError("Rejected action must not invoke the provider")

    monkeypatch.setattr("netorch.owners.run", runner)
    with pytest.raises(OwnerFailure):
        client.reconcile_discovery(action)


def test_discovery_withdrawal_does_not_pass_shell_or_record_payload(config, monkeypatch):
    client, action = discovery_client(config, monkeypatch)
    action = replace(action, active=False, reason="transport-unverified")
    absent = Observation(
        "absent",
        "confirmed-absent",
        1000,
        "publisher-instance-1",
        {
            "interface_confirmed": True,
        },
    )
    calls = install_response(monkeypatch, client.owner, observation_to_dict(absent))
    assert client.reconcile_discovery(action) == absent
    request = json.loads(calls[0][1]["input_data"])
    assert request["active"] is False
    assert not {"command", "records", "argv", "shell"}.intersection(request)


def test_external_snapshot_owner_never_reconciles_discovery(config, tmp_path, monkeypatch):
    _client, action = discovery_client(config, monkeypatch)
    root = next(owner for owner in config.owners if owner.privilege == "external-root")
    provider = SnapshotFileOwner(config, root.id, tmp_path / "snapshot.json")
    with pytest.raises(ExternalOwnerRequired):
        provider.reconcile_discovery(action)
    root_process = ProcessOwner(config, root.id, ["/usr/bin/never"])
    with pytest.raises(OwnerFailure):
        root_process.reconcile_discovery(replace(action, owner=root.id))


def test_process_cannot_claim_another_profile_execution_owner(config, monkeypatch):
    client = user_process(config, monkeypatch)

    def runner(*args, **kwargs):
        raise AssertionError("External profile must never be sent to a user provider")

    monkeypatch.setattr("netorch.owners.run", runner)
    with pytest.raises(OwnerFailure):
        client.apply(Action("dns-udp", client.owner, "withdraw", "paused"))


def test_discovery_owner_evidence_is_allowed_without_overriding_transport_generation(config):
    policy = config.discovery[0]
    clients = {owner.id: StaticClient(owned_snapshot(config, owner.id)) for owner in config.owners}
    publisher = Observation(
        "present",
        "verified",
        1000,
        "publisher-instance",
        {
            "policy_digest": discovery_digest(config, policy),
            "interface_confirmed": True,
        },
    )
    clients[policy.owner] = StaticClient(Snapshot(1000, None, {}, {policy.id: publisher}))
    result = observe(config, clients)
    assert result.network_generation == "network-one"
    assert result.profiles[policy.id] == publisher


def test_discovery_owner_cannot_supply_transport_readback(config):
    policy = config.discovery[0]
    forged = Snapshot(
        1000,
        "network-one",
        {},
        {
            "dns-udp": Observation("present", "verified", 1000, "forged", {"states": []}),
        },
    )
    result = observe(config, {policy.owner: StaticClient(forged)})
    assert result.profiles[policy.id].state == "unknown"
    assert result.profiles[policy.id].reason == "identity-mismatch"


def test_missing_discovery_owner_is_explicitly_unknown_in_shared_readback_namespace(config):
    result = observe(config, {})
    for policy in config.discovery:
        assert result.profiles[policy.id].state == "unknown"
        assert result.profiles[policy.id].reason == "unobserved"

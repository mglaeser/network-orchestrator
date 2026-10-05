from dataclasses import replace

import pytest

from netorch.config import profile_digest
from netorch.executor import StalePlan, execute
from netorch.mock import MockOwner, initial_snapshot, mock_admissions
from netorch.model import Config, Owner, PortRange, Profile, Safety, Scope, Service
from netorch.owners import ExternalOwnerRequired, OwnerFailure
from netorch.planner import plan
from netorch.state import Intent, Observation, intent_to_dict
from netorch.storage import Store

NOW = 1000.0


def policy(*, external=False, count=1):
    kind = "guest-direct" if external else "publication"
    owner = Owner("owner", "external-root" if external else "user", (kind,))
    service = Service("service", owner.id, "a" * 64)
    scope = Scope("lan", "test0", "192.0.2.10", "192.0.2.0/24", "198.51.100.0/24")
    safety = (
        Safety("bounded", 10, 2, "Synthetic residual address-reuse window accepted.")
        if external
        else Safety("structural", 10, 1)
    )
    profiles = tuple(
        Profile(
            f"p{index}",
            service.id,
            scope.id,
            kind,
            "tcp",
            PortRange(8000 + index, 8000 + index),
            PortRange(8000 + index, 8000 + index),
            safety,
        )
        for index in range(count)
    )
    return Config(1, "synthetic", (scope,), (owner,), (service,), profiles, ())


def context(tmp_path, *, external=False, count=1):
    config = policy(external=external, count=count)
    snapshot = initial_snapshot(config, NOW)
    admissions = mock_admissions(config)
    intent = Intent()
    store = Store(tmp_path / "state")
    store.write("intent.json", intent_to_dict(intent))
    backend = MockOwner(config, snapshot, admissions)
    candidate = plan(config, snapshot, admissions, intent, NOW)
    return config, snapshot, admissions, intent, store, backend, candidate


class LiveClient:
    simulation = False

    def __init__(self, backend, fault=None):
        self.backend = backend
        self.fault = fault
        self.calls = []

    def observe(self):
        return self.backend.observe()

    def apply(self, action):
        self.calls.append(action)
        result = self.backend.apply(action)
        return self.fault(result, action) if self.fault else result


def run(config, snapshot, admissions, intent, store, client, candidate, **kwargs):
    return execute(
        config,
        candidate,
        snapshot,
        intent,
        {"owner": client},
        store,
        admissions=admissions,
        now=NOW,
        observe_now=kwargs.pop("observe_now", client.observe),
        clock=kwargs.pop("clock", lambda: NOW),
        **kwargs,
    )


def test_verified_user_apply_commits_receipt_with_exact_content(tmp_path):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    client = LiveClient(backend)
    result = run(config, snapshot, admissions, intent, store, client, candidate)
    assert (result.phase, result.completed, result.pending) == ("committed", 1, ())
    assert backend.snapshot.profiles["p0"].data["policy_digest"] == profile_digest(
        config, config.profiles[0]
    )
    journal = store.read("journal.json")
    assert journal["phase"] == "committed"
    assert journal["completed"] == 1
    assert journal["initial_snapshot"]["network_generation"] == snapshot.network_generation
    receipt = store.read("receipt.json")
    assert receipt["policy_digest"] == candidate.policy_digest
    assert receipt["simulation"] is False
    assert receipt["completed"] == 1


def test_verified_noop_does_not_invoke_owner(tmp_path):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    run(config, snapshot, admissions, intent, store, backend, candidate)
    observed = backend.snapshot
    candidate = plan(config, observed, admissions, intent, NOW)
    result = run(config, observed, admissions, intent, store, backend, candidate)
    assert result.phase == "committed"
    assert result.completed == 0
    assert len(backend.calls) == 1


@pytest.mark.parametrize("field", ["owner", "operation", "target_ipv4", "target_generation"])
def test_action_tampering_cannot_ride_along_on_valid_plan_hashes(tmp_path, field):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    changes = {
        "owner": "other-owner",
        "operation": "drain",
        "target_ipv4": "198.51.100.200",
        "target_generation": "other-generation",
    }
    tampered = replace(
        candidate, actions=(replace(candidate.actions[0], **{field: changes[field]}),)
    )
    with pytest.raises(StalePlan, match="reviewed operations"):
        run(config, snapshot, admissions, intent, store, backend, tampered)
    assert not backend.calls
    assert not (store.directory / "journal.json").exists()


@pytest.mark.parametrize("change", ["removed", "digest", "future"])
def test_admission_change_between_review_and_apply_is_fenced(tmp_path, change):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    changed = dict(admissions)
    if change == "removed":
        changed.clear()
    elif change == "digest":
        changed["p0"] = replace(changed["p0"], digest="b" * 64)
    else:
        changed["p0"] = replace(changed["p0"], approved_at=NOW + 1)
    with pytest.raises(StalePlan, match="reviewed operations"):
        run(config, snapshot, changed, intent, store, backend, candidate)
    assert not backend.calls


@pytest.mark.parametrize("change", ["address", "instance", "network", "readback"])
def test_fresh_owner_observation_fences_identity_and_state_changes(tmp_path, change):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    current = snapshot
    endpoint = snapshot.services["service"]
    if change == "address":
        endpoint = replace(endpoint, data={**endpoint.data, "ipv4": "198.51.100.200"})
        current = replace(snapshot, services={"service": endpoint})
    elif change == "instance":
        current = replace(snapshot, services={"service": replace(endpoint, generation="new-guest")})
    elif change == "network":
        current = replace(snapshot, network_generation="new-network")
    else:
        current = replace(
            snapshot,
            profiles={"p0": replace(snapshot.profiles["p0"], data={"states": ["retained"]})},
        )
    with pytest.raises(StalePlan, match="identity/readback changed"):
        run(
            config,
            snapshot,
            admissions,
            intent,
            store,
            backend,
            candidate,
            observe_now=lambda: current,
        )
    assert not backend.calls


def test_new_timestamps_with_same_complete_evidence_are_allowed(tmp_path):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    current = replace(
        snapshot,
        observed_at=NOW + 1,
        services={key: replace(obs, observed_at=NOW + 1) for key, obs in snapshot.services.items()},
        profiles={key: replace(obs, observed_at=NOW + 1) for key, obs in snapshot.profiles.items()},
    )
    backend.snapshot = current
    result = run(
        config,
        snapshot,
        admissions,
        intent,
        store,
        backend,
        candidate,
        clock=lambda: NOW + 1,
    )
    assert result.phase == "committed"


def test_clock_ageing_after_review_requires_a_new_plan(tmp_path):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    with pytest.raises(StalePlan, match="reviewed operations"):
        run(
            config,
            snapshot,
            admissions,
            intent,
            store,
            backend,
            candidate,
            clock=lambda: NOW + 11,
        )
    assert not backend.calls


def test_durable_operator_pause_is_checked_under_the_lock(tmp_path):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    paused = intent.pause()
    store.write("intent.json", intent_to_dict(paused))
    with pytest.raises(StalePlan, match="durable operator intent changed"):
        run(config, snapshot, admissions, intent, store, backend, candidate)
    assert not backend.calls
    assert store.read("intent.json")["operator_paused"] is True


def test_live_owner_requires_persisted_intent_and_fresh_observer(tmp_path):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    client = LiveClient(backend)
    (store.directory / "intent.json").unlink()
    with pytest.raises(StalePlan, match="durable operator intent"):
        run(config, snapshot, admissions, intent, store, client, candidate)
    store.write("intent.json", intent_to_dict(intent))
    with pytest.raises(StalePlan, match="fresh owner observation"):
        run(config, snapshot, admissions, intent, store, client, candidate, observe_now=None)
    assert not client.calls


@pytest.mark.parametrize("field", ["policy_digest", "snapshot_digest", "intent_revision"])
def test_review_fences_all_three_top_level_inputs(tmp_path, field):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    value = 1 if field == "intent_revision" else "b" * 64
    changed = replace(candidate, **{field: value})
    with pytest.raises(StalePlan, match="changed after planning"):
        run(config, snapshot, admissions, intent, store, backend, changed)
    assert not backend.calls


def test_failure_after_mutation_preserves_failed_phase_and_prevents_further_work(tmp_path):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path, count=2)

    def crash_after_write(result, action):
        raise OwnerFailure("simulated provider died after its write")

    client = LiveClient(backend, crash_after_write)
    with pytest.raises(OwnerFailure, match="after its write"):
        run(config, snapshot, admissions, intent, store, client, candidate)
    assert len(client.calls) == 1
    assert backend.snapshot.profiles["p0"].state == "present"
    assert backend.snapshot.profiles["p1"].state == "absent"
    journal = store.read("journal.json")
    assert journal["phase"] == "failed"
    assert journal["completed"] == 0
    assert journal["action"] == "p0"
    assert not (store.directory / "receipt.json").exists()
    assert store.read("intent.json") == intent_to_dict(intent)
    current = backend.snapshot
    retry = plan(config, current, admissions, intent, NOW)
    with pytest.raises(OwnerFailure, match="unfinished journal"):
        run(config, current, admissions, intent, store, client, retry)
    assert len(client.calls) == 1


@pytest.mark.parametrize("phase", ["planned", "applying", "failed"])
def test_unfinished_journal_never_automatically_replays_operations(tmp_path, phase):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    store.write("journal.json", {"schema_version": 1, "phase": phase})
    with pytest.raises(OwnerFailure, match="unfinished journal"):
        run(config, snapshot, admissions, intent, store, backend, candidate)
    assert not backend.calls


@pytest.mark.parametrize(
    "journal",
    [
        [],
        {"schema_version": 2, "phase": "committed"},
        {"schema_version": True, "phase": "committed"},
        {"schema_version": 1, "phase": "mystery"},
    ],
)
def test_unknown_journal_format_requires_operator_recovery(tmp_path, journal):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    store.write("journal.json", journal)
    with pytest.raises(OwnerFailure, match="unknown journal format"):
        run(config, snapshot, admissions, intent, store, backend, candidate)
    assert not backend.calls


@pytest.mark.parametrize(
    "fault",
    ["unknown", "stale", "future", "absent", "digest", "address", "instance", "network"],
)
def test_exact_activation_readback_is_required_before_commit(tmp_path, fault):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)

    def corrupt(result, action):
        if fault == "unknown":
            return Observation("unknown", "busy", NOW, result.generation, result.data)
        if fault == "stale":
            return replace(result, observed_at=NOW - 11)
        if fault == "future":
            return replace(result, observed_at=NOW + 1)
        if fault == "absent":
            return Observation("absent", "confirmed-absent", NOW, result.generation, result.data)
        key, value = {
            "digest": ("policy_digest", "b" * 64),
            "address": ("target_ipv4", "198.51.100.200"),
            "instance": ("target_generation", "wrong-instance"),
            "network": ("network_generation", "wrong-network"),
        }[fault]
        return replace(result, data={**result.data, key: value})

    client = LiveClient(backend, corrupt)
    with pytest.raises(OwnerFailure):
        run(config, snapshot, admissions, intent, store, client, candidate)
    assert store.read("journal.json")["phase"] == "failed"
    assert not (store.directory / "receipt.json").exists()


def test_activation_without_state_metadata_is_not_a_complete_readback(tmp_path):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)

    def omit_states(result, action):
        return replace(
            result, data={key: value for key, value in result.data.items() if key != "states"}
        )

    client = LiveClient(backend, omit_states)
    with pytest.raises(OwnerFailure):
        run(config, snapshot, admissions, intent, store, client, candidate)
    assert not (store.directory / "receipt.json").exists()


@pytest.mark.parametrize("fault", ["missing", "nonempty", "present"])
def test_drain_requires_explicit_empty_states_and_absent_rule(tmp_path, fault):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    applied = Observation(
        "absent",
        "confirmed-absent",
        NOW,
        "old-instance",
        {
            "target_ipv4": "198.51.100.20",
            "target_generation": "old-instance",
            "states": [{"id": "old-udp-state"}],
        },
    )
    snapshot = replace(snapshot, profiles={"p0": applied})
    backend.snapshot = snapshot
    candidate = plan(config, snapshot, admissions, intent, NOW)
    assert [action.operation for action in candidate.actions] == ["drain"]

    def corrupt(result, action):
        if fault == "missing":
            return replace(result, data={})
        if fault == "present":
            return Observation("present", "verified", NOW, result.generation, {"states": []})
        return replace(result, data={"states": [{"id": "still-retained"}]})

    client = LiveClient(backend, corrupt)
    with pytest.raises(OwnerFailure):
        run(config, snapshot, admissions, intent, store, client, candidate)
    assert store.read("journal.json")["phase"] == "failed"


def test_live_external_root_owner_is_never_invoked(tmp_path):
    config, snapshot, admissions, intent, store, backend, candidate = context(
        tmp_path, external=True
    )
    client = LiveClient(backend)
    result = run(config, snapshot, admissions, intent, store, client, candidate)
    assert result.phase == "waiting-external-owner"
    assert result.pending == ("p0",)
    assert result.completed == 0
    assert not client.calls
    assert not backend.calls
    assert not (store.directory / "receipt.json").exists()


def test_missing_client_is_reported_as_external_owner_required(tmp_path):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    result = execute(
        config,
        candidate,
        snapshot,
        intent,
        {},
        store,
        admissions=admissions,
        now=NOW,
        observe_now=backend.observe,
        clock=lambda: NOW,
    )
    assert result.phase == "waiting-external-owner"
    assert result.pending == ("p0",)


def test_snapshot_owner_cannot_be_mistaken_for_a_write_capable_owner(tmp_path):
    config, snapshot, admissions, intent, store, _backend, candidate = context(tmp_path)

    class ReadOnlyClient:
        simulation = False

        def observe(self):
            return snapshot

        def apply(self, action):
            raise ExternalOwnerRequired("This owner pulls its own policy")

    result = run(config, snapshot, admissions, intent, store, ReadOnlyClient(), candidate)
    assert result.phase == "waiting-external-owner"
    assert result.completed == 0


@pytest.mark.parametrize("paused,admitted", [(True, True), (False, False)])
def test_blocked_or_pending_profile_produces_no_success_receipt(tmp_path, paused, admitted):
    config, snapshot, admissions, intent, store, backend, candidate = context(tmp_path)
    intent = intent.pause() if paused else intent
    store.write("intent.json", intent_to_dict(intent))
    admissions = admissions if admitted else {}
    candidate = plan(config, snapshot, admissions, intent, NOW)
    result = run(config, snapshot, admissions, intent, store, backend, candidate)
    assert result.phase == "inhibited"
    assert result.completed == 0
    assert not backend.calls
    assert not (store.directory / "receipt.json").exists()

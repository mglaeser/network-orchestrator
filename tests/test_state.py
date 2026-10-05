from dataclasses import FrozenInstanceError

import pytest
from hypothesis import given
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from netorch.codec import canonical_json, strict_loads
from netorch.state import (
    Admission,
    Intent,
    Observation,
    Snapshot,
    admissions_from_dict,
    admissions_to_dict,
    intent_from_dict,
    intent_to_dict,
    observation_from_dict,
    observation_to_dict,
    snapshot_digest,
    snapshot_from_dict,
    snapshot_to_dict,
)


def test_observation_is_deeply_immutable_and_detached():
    original = {"states": [{"target": "198.51.100.2"}]}
    observation = Observation("present", "verified", 100, "instance-1", original)
    original["states"][0]["target"] = "198.51.100.3"
    assert observation.data["states"][0]["target"] == "198.51.100.2"
    with pytest.raises(TypeError):
        observation.data["states"][0]["target"] = "198.51.100.4"
    with pytest.raises(FrozenInstanceError):
        observation.reason = "malformed"


@pytest.mark.parametrize(
    "state,reason",
    [
        ("healthy", "verified"),
        ("present", "timed-out"),
        ("absent", "incomplete"),
        ("unknown", "verified"),
        ("unknown", "confirmed-absent"),
        ("unknown", "new-uncertainty"),
    ],
)
def test_state_reason_combinations_are_closed(state, reason):
    with pytest.raises(ValueError):
        Observation(state, reason, 100, None)


@pytest.mark.parametrize("timestamp", [True, -1, float("nan"), float("inf"), "100"])
def test_invalid_timestamp_is_rejected(timestamp):
    with pytest.raises(ValueError):
        Observation("unknown", "malformed", timestamp, None)


def test_freshness_has_exact_boundary_and_rejects_future():
    original = Observation("present", "verified", 100, "instance-1", {})
    assert original.at(110, 10).state == "present"
    assert original.at(110.01, 10).reason == "stale"
    assert original.at(99, 10).reason == "future"
    assert original.at(110.01, 10).generation == "instance-1"


def test_snapshot_serialization_roundtrip_and_fencing_digest():
    observation = Observation("present", "verified", 100, "instance-1", {"states": []})
    original = {"edge": observation}
    snapshot = Snapshot(100, "network-1", original, {})
    original.clear()
    assert "edge" in snapshot.services
    restored = snapshot_from_dict(strict_loads(canonical_json(snapshot_to_dict(snapshot))))
    assert restored == snapshot
    assert snapshot_digest(restored) == snapshot_digest(snapshot)
    assert snapshot_digest(Snapshot(100, "network-2", snapshot.services, {})) != snapshot_digest(
        snapshot
    )
    assert snapshot_digest(Snapshot(101, "network-1", snapshot.services, {})) != snapshot_digest(
        snapshot
    )
    with pytest.raises(TypeError):
        snapshot.services["edge"] = observation


def test_unknown_does_not_serialise_as_absent():
    observation = Observation("unknown", "timed-out", 100, None)
    assert observation_from_dict(observation_to_dict(observation)).state == "unknown"


@pytest.mark.parametrize("extra", ["execution", "command", "receipt"])
def test_state_import_rejects_unknown_fields(extra):
    data = observation_to_dict(Observation("unknown", "malformed", 100, None))
    data[extra] = "untrusted"
    with pytest.raises(ValueError):
        observation_from_dict(data)


def test_admission_roundtrip_binds_exact_digest_and_key():
    admission = Admission("edge-web", "a" * 64, "test-reviewer", 100, False)
    assert admissions_from_dict(admissions_to_dict({admission.profile: admission})) == {
        "edge-web": admission
    }
    with pytest.raises(ValueError, match="key"):
        admissions_to_dict({"foreign-profile": admission})
    data = admissions_to_dict({admission.profile: admission})
    data["edge-web"]["risk_acknowledged"] = "yes"
    with pytest.raises(ValueError):
        admissions_from_dict(data)


def test_suspension_release_never_clears_operator_pause():
    intent = Intent().suspend("operation-a", "holder-a").pause()
    finished = intent.release("operation-a", "holder-a")
    assert finished.operator_paused
    assert finished.blocked
    assert finished.revision == intent.revision + 1
    with pytest.raises(ValueError, match="holder"):
        intent.release("operation-a", "holder-b")
    assert intent.operator_paused


def test_resume_never_clears_owned_suspension():
    intent = Intent().pause().suspend("operation-a", "holder-a")
    resumed = intent.resume()
    assert resumed.suspensions == {"operation-a": "holder-a"}
    assert resumed.blocked


def test_suspend_holder_cannot_be_replaced_or_expired():
    intent = Intent().suspend("operation-a", "holder-a")
    assert intent.suspend("operation-a", "holder-a") is intent
    with pytest.raises(ValueError):
        intent.suspend("operation-a", "holder-b")
    assert intent_from_dict(intent_to_dict(intent)).blocked


@pytest.mark.parametrize(
    "damaged",
    [
        None,
        {},
        [],
        "broken",
        {"schema_version": 0},
        {
            "schema_version": 99,
            "revision": 100,
            "operator_paused": False,
            "suspensions": {},
            "damaged": False,
        },
        {
            "schema_version": 1,
            "revision": True,
            "operator_paused": False,
            "suspensions": {},
            "damaged": False,
        },
    ],
)
def test_damaged_unknown_version_intent_is_paused(damaged):
    intent = intent_from_dict(damaged)
    assert intent.damaged
    assert intent.blocked
    with pytest.raises(ValueError):
        intent.resume()


@given(
    st.dictionaries(
        st.from_regex(r"[a-z]{1,8}", fullmatch=True),
        st.from_regex(r"[a-z]{1,8}", fullmatch=True),
        max_size=8,
    ),
    st.booleans(),
)
def test_intent_roundtrip(records, paused):
    intent = Intent(17, paused, records)
    assert intent_from_dict(strict_loads(canonical_json(intent_to_dict(intent)))) == intent


class PauseModel(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.intent = Intent()
        self.expected_pause = False
        self.previous_revision = 0

    @rule()
    def pause(self):
        self.intent = self.intent.pause()
        self.expected_pause = True

    @rule()
    def resume(self):
        self.intent = self.intent.resume()
        self.expected_pause = False

    @rule()
    def take(self):
        self.intent = self.intent.suspend("operation-a", "holder-a")

    @rule()
    def release(self):
        if "operation-a" in self.intent.suspensions:
            self.intent = self.intent.release("operation-a", "holder-a")

    @rule()
    def crash_reinstall_or_reopen(self):
        # Releases/reinstalls do not carry intent.  Only re-open the durable
        # record; this operation cannot reset a newer operator pause.
        self.intent = intent_from_dict(intent_to_dict(self.intent))

    @invariant()
    def preserve_pause_and_monotonic_revision(self):
        assert self.intent.operator_paused is self.expected_pause
        assert self.intent.revision >= self.previous_revision
        assert self.intent.blocked == (self.expected_pause or bool(self.intent.suspensions))
        self.previous_revision = self.intent.revision


TestPauseModel = PauseModel.TestCase

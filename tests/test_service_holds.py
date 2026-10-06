"""A hold stops one service; the pause still stops the site.

Every native tool is a fake. The literal bytes and digests below were taken
from the release before holds (0.3.2): a site without a hold stores and plans
exactly what it did there.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from netorch import apple_runtime as runtime
from netorch import bonjour_owner as owner
from netorch import cli
from netorch.codec import canonical_bytes, canonical_json, digest, strict_loads
from netorch.config import config_digest, load_config, parse_config, profile_digest, to_dict
from netorch.discovery_plan import DISCOVERY_REASONS, discovery_digest, plan_discovery
from netorch.executor import StalePlan, execute
from netorch.mock import MockOwner, initial_snapshot, mock_admissions
from netorch.planner import ACTION_REASONS, Plan, plan, plan_from_dict, plan_to_dict
from netorch.state import (
    Intent,
    Snapshot,
    admissions_to_dict,
    intent_from_dict,
    intent_to_dict,
    snapshot_to_dict,
)
from netorch.storage import Store
from netorch.workflow_gate import NOT_QUALIFIED
from netorch.workloads import provision_digest, provision_workloads
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_bonjour_owner import (
    FakeRegistration,
    candidate_request,
    media_record,
    policy,
    publisher,
    settings,
    write_private,
)
from tests.test_bonjour_owner import snapshot as verified_snapshot
from tests.test_discovery_plan import decisions, ready_snapshot
from tests.test_workloads import acknowledge, fleet, interrupted_provision

__all__ = ["enrolled", "settings"]

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/network.json"
NOW = 1000.0
MAINTENANCE = ("maintenance", "manager")

# canonical_bytes(intent_to_dict(...)) on 0.3.2 for an open, a paused and a suspended site.
V1_OPEN = (
    b'{"damaged":false,"operator_paused":false,"revision":0,"schema_version":1,"suspensions":{}}'
)
V1_PAUSED = (
    b'{"damaged":false,"operator_paused":true,"revision":1,"schema_version":1,"suspensions":{}}'
)
V1_SUSPENDED = (
    b'{"damaged":false,"operator_paused":true,"revision":7,"schema_version":1,'
    b'"suspensions":{"maintenance":"manager"}}'
)
# digest(plan_to_dict(plan(...))) on 0.3.2: the example policy, the mock's first
# snapshot and admissions, the clock at 1000.0.
PLAN_DIGESTS = {
    "open": "9827b4c8009c29b99422ff483e1a4423d84249362bf71c3f1b4d6e71fd9d03d6",
    "paused": "c6f0076270844ecdec53a733be41c52651fd4f6683310dfa4e9c1e71a9e91229",
    "suspended": "42d33e2ddf479176be13b9d792b72b733170756594ed942173d8a36d71e88fa2",
}


@pytest.fixture
def config() -> Any:
    return load_config(EXAMPLE)


def holding(
    base: Intent, service: str, operation: str = "maintenance", holder: str = "manager"
) -> Intent:
    """`base` with one more hold, read from its stored form as every owner reads it.

    A release without holds reads the same document as damage; the tests of the
    readers below then observe a full stop where one service should be held.
    """
    holds = {key: dict(records) for key, records in getattr(base, "holds", {}).items()}
    holds.setdefault(service, {})[operation] = holder
    return intent_from_dict(
        {
            "schema_version": 2,
            "revision": base.revision + 1,
            "operator_paused": base.operator_paused,
            "suspensions": dict(base.suspensions),
            "damaged": base.damaged,
            "holds": holds,
        }
    )


def held(service: str, base: Intent | None = None) -> Intent:
    return holding(Intent() if base is None else base, service)


def version_2(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": 2,
        "revision": 4,
        "operator_paused": False,
        "suspensions": {},
        "damaged": False,
        "holds": {"camera": {"maintenance": "manager"}},
    }
    document.update(changes)
    return document


def accepted_by_the_release_before_holds(value: object) -> bool:
    """The complete shape rule of intent_from_dict in 0.3.2; anything else was damage there."""
    return (
        isinstance(value, dict)
        and set(value)
        == {"schema_version", "revision", "operator_paused", "suspensions", "damaged"}
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
    )


def reasons(result: Plan, profile: str) -> list[tuple[str, str]]:
    return [(item.operation, item.reason) for item in result.actions if item.profile == profile]


# The stored form.


def test_no_hold_keeps_the_version_1_bytes(tmp_path: Path) -> None:
    assert canonical_bytes(intent_to_dict(Intent())) == V1_OPEN
    assert canonical_bytes(intent_to_dict(Intent().pause())) == V1_PAUSED
    suspended = Intent(7, True, {"maintenance": "manager"})
    assert canonical_bytes(intent_to_dict(suspended)) == V1_SUSPENDED
    for raw in (V1_OPEN, V1_PAUSED, V1_SUSPENDED):
        read = intent_from_dict(strict_loads(raw))
        assert not read.damaged
        assert canonical_bytes(intent_to_dict(read)) == raw
    store = Store(tmp_path / "state")
    store.write("intent.json", intent_to_dict(Intent().pause()))
    assert (store.directory / "intent.json").read_bytes() == V1_PAUSED + b"\n"


def test_placing_and_releasing_a_hold_returns_to_the_version_1_bytes(tmp_path: Path) -> None:
    # A hold makes the file version 2; releasing the last one restores version 1.
    assert not intent_from_dict(strict_loads(V1_SUSPENDED)).holds
    store = Store(tmp_path / "state")
    path = store.directory / "intent.json"
    store.write("intent.json", intent_to_dict(Intent().pause()))
    assert path.read_bytes() == V1_PAUSED + b"\n"
    placed = intent_from_dict(store.read("intent.json")).hold("camera", *MAINTENANCE)
    store.write("intent.json", intent_to_dict(placed))
    assert store.read("intent.json") == {
        "schema_version": 2,
        "revision": 2,
        "operator_paused": True,
        "suspensions": {},
        "damaged": False,
        "holds": {"camera": {"maintenance": "manager"}},
    }
    released = intent_from_dict(store.read("intent.json")).unhold("camera", *MAINTENANCE)
    store.write("intent.json", intent_to_dict(released))
    assert path.read_bytes() == V1_PAUSED.replace(b'"revision":1', b'"revision":3') + b"\n"


def test_a_release_without_holds_reads_a_hold_as_damage() -> None:
    for raw in (V1_OPEN, V1_PAUSED, V1_SUSPENDED):
        assert accepted_by_the_release_before_holds(strict_loads(raw))
    placed = held("camera", Intent().pause())
    # It is never ignored there: the whole file is damage, which inhibits everything.
    assert not accepted_by_the_release_before_holds(intent_to_dict(placed))
    released = placed.unhold("camera", *MAINTENANCE)
    assert accepted_by_the_release_before_holds(intent_to_dict(released))


@pytest.mark.parametrize(
    "document",
    [
        {key: value for key, value in version_2().items() if key != "holds"},
        version_2(holds={}),
        version_2(schema_version=1),
        version_2(schema_version=3),
        version_2(schema_version=True),
        version_2(schema_version=2.0),
        version_2(holds={"camera": {}}),
        version_2(holds={"Camera": {"maintenance": "manager"}}),
        version_2(holds={"": {"maintenance": "manager"}}),
        version_2(holds={"9camera": {"maintenance": "manager"}}),
        version_2(holds={"c" * 65: {"maintenance": "manager"}}),
        version_2(holds={"camera": {"": "manager"}}),
        version_2(holds={"camera": {"maintenance": ""}}),
        version_2(holds={"camera": {"maintenance": None}}),
        version_2(holds={"camera": {"maintenance": 5}}),
        version_2(holds={"camera": "manager"}),
        version_2(holds={"camera": ["maintenance"]}),
        version_2(holds=[]),
        version_2(holds="camera"),
        version_2(holds=None),
        version_2(holder="manager"),
        version_2(revision=-1),
        [version_2()],
    ],
)
def test_every_other_spelling_is_damaged(document: Any) -> None:
    read = intent_from_dict(document)
    # Nothing of a damaged file is applied in part: no hold, no revision.
    assert read == Intent(damaged=True)
    assert read.blocked
    with pytest.raises(ValueError):
        read.pause()


def test_the_two_stored_shapes_are_read() -> None:
    read = intent_from_dict(version_2())
    assert not read.damaged and read.revision == 4
    assert read.holds == {"camera": {"maintenance": "manager"}}
    assert intent_to_dict(read) == version_2()
    # A service identifier of the policy's full length can be held.
    longest = "c" * 64
    assert intent_from_dict(version_2(holds={longest: {"maintenance": "manager"}})).holds == {
        longest: {"maintenance": "manager"}
    }
    # A damaged flag stored beside holds still inhibits everything.
    flagged = intent_from_dict(version_2(damaged=True))
    assert flagged.damaged and flagged.blocks("resolver")


def test_a_ninth_holder_in_one_stored_file_is_damage() -> None:
    eight = {f"operation-{index}": "manager" for index in range(8)}
    full = intent_from_dict(version_2(holds={"camera": eight}))
    assert not full.damaged and len(full.holds["camera"]) == 8
    nine = {**eight, "operation-8": "manager"}
    assert intent_from_dict(version_2(holds={"camera": nine})) == Intent(damaged=True)
    services = {f"service-{index}": {"maintenance": "manager"} for index in range(64)}
    assert len(intent_from_dict(version_2(holds=services)).holds) == 64
    services["service-64"] = {"maintenance": "manager"}
    assert intent_from_dict(version_2(holds=services)) == Intent(damaged=True)
    # The model does not create what it would not read back.
    with pytest.raises(ValueError, match="bound"):
        full.hold("camera", "operation-8", "manager")
    del services["service-64"]
    with pytest.raises(ValueError, match="bound"):
        intent_from_dict(version_2(holds=services)).hold("service-64", *MAINTENANCE)
    # An owner that merges its own file with one other can represent both in full.
    merged = Intent(holds={"camera": {**eight, **{f"external:{key}": "m" for key in eight}}})
    assert len(merged.holds["camera"]) == 16
    with pytest.raises(ValueError):
        Intent(holds={"camera": {f"operation-{index}": "manager" for index in range(17)}})
    with pytest.raises(ValueError):
        Intent(holds={f"service-{index}": {"maintenance": "manager"} for index in range(129)})


# The model.


def test_holder_rules_match_suspensions() -> None:
    first = Intent().hold("camera", *MAINTENANCE)
    assert first.revision == 1 and first.holds == {"camera": {"maintenance": "manager"}}
    assert holding(Intent(), "camera") == first == held("camera")
    assert first.hold("camera", *MAINTENANCE) is first
    with pytest.raises(ValueError, match="another holder"):
        first.hold("camera", "maintenance", "someone-else")
    for service, operation, holder in (
        ("camera", "maintenance", "someone-else"),
        ("camera", "backup", "manager"),
        ("resolver", "maintenance", "manager"),
    ):
        with pytest.raises(ValueError, match="holder"):
            first.unhold(service, operation, holder)
    second = first.hold("camera", "backup", "backup-owner").hold("resolver", *MAINTENANCE)
    assert second.revision == 3
    remaining = second.unhold("camera", *MAINTENANCE)
    assert remaining.revision == 4
    assert remaining.holds == {
        "camera": {"backup": "backup-owner"},
        "resolver": {"maintenance": "manager"},
    }
    # An emptied service entry disappears; the file is version 1 again with the last one.
    assert remaining.unhold("camera", "backup", "backup-owner").holds == {
        "resolver": {"maintenance": "manager"}
    }
    with pytest.raises(ValueError):
        Intent(damaged=True).hold("camera", *MAINTENANCE)
    for service in ("Camera", "", "camera web", "c" * 65):
        with pytest.raises(ValueError, match="service"):
            Intent().hold(service, *MAINTENANCE)
    with pytest.raises(TypeError):
        first.holds["camera"]["maintenance"] = "someone-else"


def test_every_other_change_carries_the_holds() -> None:
    first = Intent().hold("camera", *MAINTENANCE)
    carried = (
        first.pause().suspend("installation", "bundle").resume().release("installation", "bundle")
    )
    assert carried.holds == first.holds and carried.revision == first.revision + 4
    assert intent_from_dict(strict_loads(canonical_json(intent_to_dict(carried)))) == carried


def test_a_hold_adds_to_the_site_wide_inhibition_and_never_narrows_it() -> None:
    first = Intent().hold("camera", *MAINTENANCE)
    assert not first.blocked and first.blocks("camera") and not first.blocks("resolver")
    for site_wide in (
        first.pause(),
        first.suspend("installation", "bundle"),
        replace(first, damaged=True),
    ):
        assert site_wide.blocked
        assert site_wide.blocks("camera") and site_wide.blocks("resolver")


class HoldModel(RuleBasedStateMachine):
    """Random orders of every operation and of reopening the stored file."""

    services = st.sampled_from(["camera", "resolver"])
    operations = st.sampled_from(["maintenance", "backup"])
    holders = st.sampled_from(["manager", "someone-else"])

    def __init__(self) -> None:
        super().__init__()
        self.intent = Intent()
        self.expected: dict[tuple[str, str], str] = {}
        self.previous_revision = 0

    @rule(service=services, operation=operations, holder=holders)
    def hold(self, service: str, operation: str, holder: str) -> None:
        owned = self.expected.get((service, operation))
        if owned is None or owned == holder:
            self.intent = self.intent.hold(service, operation, holder)
            self.expected[(service, operation)] = holder
        else:
            with pytest.raises(ValueError):
                self.intent.hold(service, operation, holder)

    @rule(service=services, operation=operations, holder=holders)
    def unhold(self, service: str, operation: str, holder: str) -> None:
        if self.expected.get((service, operation)) == holder:
            self.intent = self.intent.unhold(service, operation, holder)
            del self.expected[(service, operation)]
        else:
            with pytest.raises(ValueError):
                self.intent.unhold(service, operation, holder)

    @rule()
    def pause(self) -> None:
        self.intent = self.intent.pause()

    @rule()
    def resume(self) -> None:
        self.intent = self.intent.resume()

    @rule()
    def take_and_release_a_suspension(self) -> None:
        self.intent = self.intent.suspend("installation", "bundle")
        self.intent = self.intent.release("installation", "bundle")

    @rule()
    def reopen(self) -> None:
        self.intent = intent_from_dict(strict_loads(canonical_json(intent_to_dict(self.intent))))

    @invariant()
    def only_the_holder_changes_a_hold(self) -> None:
        actual = {
            (service, operation): holder
            for service, records in self.intent.holds.items()
            for operation, holder in records.items()
        }
        assert actual == self.expected and not self.intent.damaged
        assert self.intent.revision >= self.previous_revision
        assert intent_to_dict(self.intent)["schema_version"] == (2 if self.expected else 1)
        self.previous_revision = self.intent.revision


HoldModel.TestCase.settings = hypothesis_settings(deadline=None, max_examples=60)
TestHoldModel = HoldModel.TestCase


# The planner and the discovery plan.


def test_plan_digests_of_inputs_without_holds_are_unchanged(config: Any) -> None:
    snapshot, admissions = initial_snapshot(config), mock_admissions(config)
    intents = {
        "open": Intent(),
        "paused": Intent().pause(),
        "suspended": Intent().suspend("maintenance", "manager"),
    }
    for label, intent in intents.items():
        result = plan(config, snapshot, admissions, intent, NOW)
        assert digest(plan_to_dict(result)) == PLAN_DIGESTS[label]


def test_planner_holds_one_service_and_leaves_the_others(config: Any) -> None:
    current, admissions = verified_snapshot(config), mock_admissions(config)
    baseline = plan(config, current, admissions, Intent(), NOW)
    assert {(item.operation, item.reason) for item in baseline.actions} == {("noop", "verified")}
    intent = held("web-proxy")
    result = plan(config, current, admissions, intent, NOW)
    assert result.intent_revision == intent.revision
    retired = [("withdraw", "held"), ("drain", "held"), ("blocked", "held")]
    for profile in config.profiles:
        expected = retired if profile.service == "web-proxy" else [("noop", "verified")]
        assert reasons(result, profile.id) == expected
    assert result.ready_profiles == frozenset(
        profile.id for profile in config.profiles if profile.service != "web-proxy"
    )
    assert "held" in ACTION_REASONS and plan_from_dict(plan_to_dict(result)) == result
    # Nothing is exposed for a held service that is not exposed yet.
    fresh = plan(config, initial_snapshot(config), admissions, intent, NOW)
    assert reasons(fresh, "proxy-high") == reasons(fresh, "proxy-standard") == [("blocked", "held")]
    assert reasons(fresh, "dns-udp") == [("activate", "ready")]
    # The pause and a suspension still stop every profile, whatever is held.
    for site_wide, reason in (
        (intent.pause(), "paused"),
        (intent.suspend("installation", "bundle"), "suspended"),
    ):
        stopped = plan(config, current, admissions, site_wide, NOW)
        assert {item.reason for item in stopped.actions} == {reason}
        assert not stopped.ready_profiles


def test_discovery_plan_withdraws_the_held_service_only(config: Any) -> None:
    current = ready_snapshot(config, publisher_state="present")
    baseline = decisions(config, current)
    assert all(item.active and item.reason == "verified" for item in baseline.values())
    result = decisions(config, current, intent=held("camera"))
    assert not result["camera-export"].active and result["camera-export"].reason == "held"
    assert result["camera-export"].policy_digest == discovery_digest(
        config, policy(config, "camera-export")
    )
    assert result["media-import"] == baseline["media-import"]
    assert "held" in DISCOVERY_REASONS
    for site_wide, reason in (
        (held("camera").pause(), "paused"),
        (held("camera").suspend("installation", "bundle"), "suspended"),
    ):
        stopped = decisions(config, current, intent=site_wide)
        assert all(not item.active and item.reason == reason for item in stopped.values())


@pytest.mark.parametrize("reader", ["planner", "discovery-plan"])
def test_a_hold_on_an_unknown_service_inhibits_everything(config: Any, reader: str) -> None:
    unknown = held("retired-service")
    current = ready_snapshot(config, publisher_state="present")
    if reader == "planner":
        result = plan(config, current, mock_admissions(config), unknown, NOW)
        assert {item.reason for item in result.actions} == {"intent-damaged"}
        assert not result.ready_profiles and result.intent_revision == unknown.revision
    else:
        # Even beside a transport plan that somebody made without the hold.
        transport = plan(config, current, mock_admissions(config), Intent(), NOW)
        transport = replace(transport, intent_revision=unknown.revision)
        result = plan_discovery(config, current, transport, unknown, NOW)
        assert all(not item.active and item.reason == "intent-damaged" for item in result)


@pytest.mark.parametrize("damage", [version_2(holds={}), version_2(schema_version=3), b"{"])
def test_a_damaged_hold_file_inhibits_the_planner_and_the_discovery_plan(
    config: Any, damage: Any
) -> None:
    try:
        intent = intent_from_dict(strict_loads(damage) if isinstance(damage, bytes) else damage)
    except ValueError:
        intent = Intent(damaged=True)
    current = ready_snapshot(config, publisher_state="present")
    transport = plan(config, current, mock_admissions(config), intent, NOW)
    assert {item.reason for item in transport.actions} == {"intent-damaged"}
    assert all(
        item.reason == "intent-damaged"
        for item in plan_discovery(config, current, transport, intent, NOW)
    )


# The executor.


def simulated(config: Any, tmp_path: Path) -> tuple[Store, MockOwner, dict[str, Any]]:
    store = Store(tmp_path / "state")
    backend = MockOwner(config, initial_snapshot(config), mock_admissions(config))
    return store, backend, {item.id: backend for item in config.owners}


def cycle(config: Any, store: Store, backend: MockOwner, clients: Any, intent: Intent) -> Any:
    store.write("intent.json", intent_to_dict(intent))
    candidate = plan(config, backend.snapshot, backend.admissions, intent, NOW)
    return execute(
        config,
        candidate,
        backend.snapshot,
        intent,
        clients,
        store,
        admissions=backend.admissions,
        now=NOW,
        observe_now=backend.observe,
    )


def test_a_changed_hold_invalidates_a_plan_in_flight(config: Any, tmp_path: Path) -> None:
    store, backend, clients = simulated(config, tmp_path)
    planned_with = Intent()
    candidate = plan(config, backend.snapshot, backend.admissions, planned_with, NOW)
    for stored, reviewed in (
        (held("camera"), planned_with),
        (held("camera"), replace(planned_with, revision=1)),
        (Intent(1), held("camera")),
        (holding(Intent(), "camera", holder="someone-else"), held("camera")),
    ):
        store.write("intent.json", intent_to_dict(stored))
        reviewed_plan = (
            candidate
            if reviewed is planned_with
            else plan(config, backend.snapshot, backend.admissions, reviewed, NOW)
        )
        with pytest.raises(StalePlan):
            execute(
                config,
                reviewed_plan,
                backend.snapshot,
                reviewed,
                clients,
                store,
                admissions=backend.admissions,
                now=NOW,
                observe_now=backend.observe,
            )
    assert not backend.calls and not backend.discovery_calls


def test_executor_applies_the_other_services_while_one_is_held(config: Any, tmp_path: Path) -> None:
    store, backend, clients = simulated(config, tmp_path)
    intent = held("camera")
    first = cycle(config, store, backend, clients, intent)
    # Unresolved, as during a pause, but the other services were applied.
    assert first.phase == "inhibited" and not first.pending
    assert {item.profile for item in backend.calls} == {
        profile.id
        for profile in config.profiles
        if profile.service != "camera" and profile.kind != "host-redirect"
    }
    assert store.read("journal.json")["intent"] == intent_to_dict(intent)
    assert not (store.directory / "receipt.json").exists()
    cycle(config, store, backend, clients, intent)
    cycle(config, store, backend, clients, intent)
    observed = backend.snapshot.profiles
    assert observed["camera-web"].state == "absent" and observed["camera-export"].state == "absent"
    assert all(
        observed[profile.id].state == "present"
        for profile in config.profiles
        if profile.service != "camera"
    )
    assert observed["media-import"].state == "present"
    released = intent.unhold("camera", *MAINTENANCE)
    cycle(config, store, backend, clients, released)
    cycle(config, store, backend, clients, released)
    assert cycle(config, store, backend, clients, released).phase == "committed"
    assert backend.snapshot.profiles["camera-web"].state == "present"
    assert backend.snapshot.profiles["camera-export"].state == "present"
    # A later hold withdraws the publication and the discovery of that service only.
    again = cycle(config, store, backend, clients, held("camera", released))
    assert again.phase == "inhibited"
    assert backend.snapshot.profiles["camera-web"].state == "absent"
    assert backend.snapshot.profiles["camera-export"].state == "absent"
    assert backend.snapshot.profiles["media-import"].state == "present"
    assert backend.snapshot.profiles["dns-udp"].state == "present"


def test_a_held_service_with_discovery_only_is_resolved_like_a_paused_one(
    config: Any, tmp_path: Path
) -> None:
    document = to_dict(config)
    document["services"].append(
        {"id": "notes", "owner": "camera-manager", "contract_sha256": "e" * 64}
    )
    document["discovery"].append(
        {
            "id": "notes-import",
            "owner": "bonjour-manager",
            "service": "notes",
            "scope": "wired-lan",
            "direction": "import",
            "types": ["_companion-link._tcp"],
            "dependencies": [],
            "max_age_seconds": 120,
            "max_records": 16,
        }
    )
    extended = parse_config(canonical_bytes(document))
    store, backend, clients = simulated(extended, tmp_path)
    for _ in range(3):
        result = cycle(extended, store, backend, clients, Intent())
    assert result.phase == "committed"
    assert backend.snapshot.profiles["notes-import"].state == "present"
    # No transport profile is blocked by this hold; its withdrawn discovery is the
    # intended, complete state, as it is for a paused site.
    intent = held("notes")
    result = cycle(extended, store, backend, clients, intent)
    assert result.phase == "committed" and not result.pending
    assert backend.snapshot.profiles["notes-import"].state == "absent"
    assert backend.snapshot.profiles["media-import"].state == "present"
    assert cycle(extended, store, backend, clients, intent).phase == "committed"


# The commands.


def must_not_call(*_args: Any, **_kwargs: Any) -> Any:
    pytest.fail("a refused command reached configuration or state")


def hold_arguments(state: Path, service: str, holder: str = "manager") -> list[str]:
    return [
        "hold",
        "--state-dir",
        str(state),
        "--config",
        str(EXAMPLE),
        "--service",
        service,
        "--operation",
        "maintenance",
        "--holder",
        holder,
    ]


def test_hold_command_refuses_a_service_that_the_policy_does_not_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = Store(tmp_path / "state")
    store.write("intent.json", intent_to_dict(Intent().pause()))
    path = store.directory / "intent.json"
    # The real gate is in place: placing a hold is never a gated command.
    assert cli.main(hold_arguments(store.directory, "camra")) == 65
    assert strict_loads(capsys.readouterr().out)["error"] == "invalid-or-unverified"
    assert path.read_bytes() == V1_PAUSED + b"\n"
    absent = tmp_path / "not-created"
    assert cli.main(hold_arguments(absent, "camra")) == 65
    assert not absent.exists()
    capsys.readouterr()
    assert cli.main(hold_arguments(store.directory, "camera")) == 0
    printed = strict_loads(capsys.readouterr().out)
    assert printed == store.read("intent.json")
    assert printed["schema_version"] == 2 and printed["revision"] == 2
    assert printed["holds"] == {"camera": {"maintenance": "manager"}}
    assert printed["operator_paused"] is True
    # Another holder cannot replace it, and a policy that cannot be read places nothing.
    before = path.read_bytes()
    assert cli.main(hold_arguments(store.directory, "camera", "someone-else")) == 65
    unreadable = hold_arguments(store.directory, "resolver")
    unreadable[unreadable.index("--config") + 1] = str(tmp_path / "absent.json")
    assert cli.main(unreadable) == 65
    assert path.read_bytes() == before


def test_unhold_is_gated_like_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    store = Store(tmp_path / "state")
    store.write("intent.json", intent_to_dict(held("camera", Intent().pause())))
    before = (store.directory / "intent.json").read_bytes()
    arguments = [
        "unhold",
        "--state-dir",
        str(store.directory),
        "--service",
        "camera",
        "--operation",
        "maintenance",
    ]
    with monkeypatch.context() as denied:
        denied.setattr(cli, "load_config", must_not_call)
        denied.setattr(cli, "Store", must_not_call)
        assert cli.main([*arguments, "--holder", "manager"]) == NOT_QUALIFIED
        refusal = strict_loads(capsys.readouterr().out)
        assert refusal["error"] == "stage-not-qualified"
        assert refusal["capability"] == "authority-mutation"
    assert (store.directory / "intent.json").read_bytes() == before
    # Behind the gate the holder rule decides, as it does for a suspension.
    monkeypatch.setattr(cli, "require_mutation_qualified", lambda _capability: None)
    assert cli.main([*arguments, "--holder", "someone-else"]) == 65
    assert (store.directory / "intent.json").read_bytes() == before
    capsys.readouterr()
    assert cli.main([*arguments, "--holder", "manager"]) == 0
    assert strict_loads(capsys.readouterr().out)["schema_version"] == 1
    assert (store.directory / "intent.json").read_bytes() == (
        V1_PAUSED.replace(b'"revision":1', b'"revision":3') + b"\n"
    )


def test_status_and_plan_commands_show_the_hold(
    config: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    files = {
        "snapshot": tmp_path / "snapshot.json",
        "admissions": tmp_path / "admissions.json",
        "intent": tmp_path / "intent.json",
    }
    intent = held("web-proxy")
    files["snapshot"].write_bytes(canonical_bytes(snapshot_to_dict(verified_snapshot(config))))
    files["admissions"].write_bytes(canonical_bytes(admissions_to_dict(mock_admissions(config))))
    files["intent"].write_bytes(canonical_bytes(intent_to_dict(intent)))
    arguments = ["--config", str(EXAMPLE), "--now", "1000"]
    for key, path in files.items():
        arguments += [f"--{key}", str(path)]
    assert cli.main(["status", *arguments]) == 0
    status = strict_loads(capsys.readouterr().out)
    assert status["intent"] == intent_to_dict(intent)
    assert (
        "proxy-standard" not in status["ready_profiles"] and "dns-udp" in status["ready_profiles"]
    )
    assert cli.main(["render-pf", *arguments]) == 0
    preview = capsys.readouterr().out
    assert "netorch:proxy-standard" not in preview and "netorch:dns-udp" in preview


# Initial provisioning.


def test_provisioning_refuses_while_a_hold_exists(tmp_path: Path) -> None:
    config, settings_, fake, workloads, store = fleet(tmp_path)
    approved = provision_digest(config, settings_, workloads)
    store.write("intent.json", intent_to_dict(held("camera", Intent(operator_paused=True))))
    with pytest.raises(ValueError, match="competing maintenance"):
        provision_workloads(config, settings_, workloads, expected_digest=approved, runner=fake)
    assert not fake.calls and not (store.directory / "workload-journal.json").exists()
    store.write("intent.json", intent_to_dict(Intent(operator_paused=True)))
    assert provision_workloads(config, settings_, workloads, expected_digest=approved, runner=fake)[
        "provisioned"
    ]


def test_acknowledging_an_interrupted_provision_keeps_a_hold(tmp_path: Path) -> None:
    _config, settings_, _fake, _workloads, store, journal = interrupted_provision(tmp_path)
    store.write(
        "intent.json", intent_to_dict(held("camera", intent_from_dict(store.read("intent.json"))))
    )
    acknowledge(settings_, journal)
    current = intent_from_dict(store.read("intent.json"))
    assert current.operator_paused and not current.suspensions
    assert current.holds == {"camera": {"maintenance": "manager"}}


# The runtime endpoint and recovery.


def write_intent(path: str | Path, intent: Intent | dict[str, Any]) -> None:
    document = intent_to_dict(intent) if isinstance(intent, Intent) else intent
    write_private(Path(path), document)


def probe(monkeypatch: pytest.MonkeyPatch, settings_: Any, full: Snapshot, service: str) -> int:
    with monkeypatch.context() as patched:
        patched.setattr(runtime, "load_settings", lambda _path: settings_)
        patched.setattr(runtime, "observe_runtime", lambda *_args: full)
        return runtime.main(["--settings", "/unused/settings.json", "probe", "--service", service])


def starts(runner: FakeRunner) -> list[str]:
    return [call[0][2] for call in runner.calls if call[0][1:2] == ["start"]]


def inventory_reads(runner: FakeRunner) -> list[Any]:
    return [call for call in runner.calls if call[0][1:] == ["list", "--all", "--format", "json"]]


def test_recovery_holds_one_workload_only(enrolled: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    config, settings_, items = enrolled
    runner = FakeRunner(settings_, items)
    for name in ("example-camera", "example-resolver"):
        runner.items[name]["status"]["state"] = "stopped"
    full = runtime.observe_runtime(config, settings_, runner)
    assert full.services["camera"].state == full.services["resolver"].state == "absent"
    write_intent(settings_.intent, held("camera"))
    assert probe(monkeypatch, settings_, full, "camera") == runtime.UNKNOWN == 69
    assert probe(monkeypatch, settings_, full, "resolver") == runtime.STOPPED == 42
    assert probe(monkeypatch, settings_, full, "web-proxy") == 0
    # Held and running is inhibited too, as every workload is during a pause.
    write_intent(settings_.intent, held("web-proxy", held("camera")))
    assert probe(monkeypatch, settings_, full, "web-proxy") == 69
    write_intent(settings_.intent, held("camera"))
    inventories = len(inventory_reads(runner))
    with pytest.raises(runtime.RuntimeReadError) as refused:
        runtime.recover_service(config, settings_, "camera", runner)
    # Refused at the first read of the hold, before a second observation is made.
    assert refused.value.reason == "incomplete"
    assert len(inventory_reads(runner)) == inventories + 1
    assert starts(runner) == []
    recovered = runtime.recover_service(config, settings_, "resolver", runner)
    assert recovered.services["resolver"].state == "present"
    assert starts(runner) == ["example-resolver"]
    # The pause still stops every probe and every start.
    write_intent(settings_.intent, held("camera").pause())
    for service in ("camera", "resolver", "web-proxy"):
        assert probe(monkeypatch, settings_, full, service) == 69


def test_a_hold_placed_between_the_two_observations_stops_the_start(enrolled: Any) -> None:
    config, settings_, items = enrolled
    base = FakeRunner(settings_, items)
    base.items["example-camera"]["status"]["state"] = "stopped"
    inventories = 0

    def runner(argv: list[str], **kwargs: Any) -> Any:
        nonlocal inventories
        if argv[1:] == ["list", "--all", "--format", "json"]:
            inventories += 1
            if inventories == 2:
                write_intent(settings_.intent, held("camera"))
        return base(argv, **kwargs)

    with pytest.raises(runtime.RuntimeReadError) as refused:
        runtime.recover_service(config, settings_, "camera", runner)
    assert refused.value.reason == "generation-mismatch"
    assert inventories == 2 and starts(base) == []


def activation(config: Any, settings_: Any, observed: Snapshot, profile_id: str) -> dict[str, Any]:
    profile = config.profile(profile_id)
    return {
        "protocol_version": 1,
        "operation": "reconcile",
        "owner": settings_.owner,
        "policy_digest": config_digest(config),
        "profile_digest": profile_digest(config, profile),
        "profile": profile.id,
        "action": "activate",
        "target_ipv4": observed.services[profile.service].data["ipv4"],
        "target_generation": observed.services[profile.service].generation,
    }


def test_runtime_endpoint_refuses_the_held_service_and_verifies_the_others(enrolled: Any) -> None:
    config, settings_, items = enrolled
    runner = FakeRunner(settings_, items)
    observed = runtime.observe_runtime(config, settings_, runner)
    write_intent(settings_.intent, held("camera"))
    with pytest.raises(runtime.RuntimeReadError):
        runtime.handle_request(
            config, settings_, activation(config, settings_, observed, "camera-web"), runner
        )
    verified = runtime.handle_request(
        config, settings_, activation(config, settings_, observed, "proxy-high"), runner
    )
    assert verified["result"]["state"] == "present"


@pytest.mark.parametrize(
    "document",
    [
        version_2(revision=1, holds={"retired-service": {"maintenance": "manager"}}),
        version_2(holds={}),
        version_2(holds={"camera": {f"operation-{index}": "manager" for index in range(9)}}),
    ],
)
def test_an_unknown_or_damaged_hold_inhibits_every_workload(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, document: dict[str, Any]
) -> None:
    config, settings_, items = enrolled
    runner = FakeRunner(settings_, items)
    runner.items["example-resolver"]["status"]["state"] = "stopped"
    full = runtime.observe_runtime(config, settings_, runner)
    write_intent(settings_.intent, document)
    for service in ("camera", "resolver", "web-proxy", "media-controller"):
        assert probe(monkeypatch, settings_, full, service) == 69
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings_, "resolver", runner)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.handle_request(
            config, settings_, activation(config, settings_, full, "proxy-high"), runner
        )
    assert starts(runner) == []


# The bundled discovery owner.


def two_published_policies(config: Any, settings_: Any) -> tuple[Store, Any, Any]:
    current = verified_snapshot(config)
    request, candidate = candidate_request(config, settings_, current, media_record())
    camera = policy(config, "camera-export")
    records = owner.project_records(
        config,
        camera,
        (
            media_record(
                name="Camera",
                service_type="_hap._tcp",
                hostname="camera.local.",
                ipv4=current.services["camera"].data["ipv4"],
                interface="bridge-test",
                port=9443,
            ),
        ),
        current,
        frozenset({"camera-web"}),
        settings_,
        1000,
    )
    common = {
        "policy_digest": discovery_digest(config, camera),
        "service_generation": current.services[camera.service].generation,
        "network_generation": current.network_generation,
    }
    store = Store(settings_.state_dir)
    store.write(
        "requests.json",
        {
            "schema_version": 1,
            "policies": {
                "media-import": request,
                "camera-export": {**common, "active": True, "requested_at": 1000},
            },
        },
    )
    store.write(
        "candidates.json",
        {
            "schema_version": 1,
            "config_digest": config_digest(config),
            "policies": {
                "media-import": candidate,
                "camera-export": {
                    **common,
                    "records": [owner.record_to_dict(item) for item in records],
                    "interface_confirmed": True,
                    "observed_at": 1000,
                },
            },
        },
    )
    proof = (current, Intent(), frozenset({"media-udp", "camera-web"}), {"wired-lan": (7, 9)})
    return store, proof, publisher()


def tick(config: Any, settings_: Any, store: Store, manager: Any, proof: Any) -> dict[str, str]:
    observed = owner.publisher_tick(config, settings_, store, manager, proof, 0, 1000)
    return {key: item.state for key, item in observed.profiles.items()}


def children(kind: str) -> list[Any]:
    return [child for child in FakeRegistration.made if child.record.service_type == kind]


def test_discovery_of_a_held_service_is_withdrawn_and_others_stay(
    config: Any, settings: Any
) -> None:
    store, proof, manager = two_published_policies(config, settings)
    both = {"media-import": "present", "camera-export": "present"}
    assert tick(config, settings, store, manager, proof) == both
    write_private(settings.intent, intent_to_dict(held("camera")))
    # The proof is as old as before: the hold is read in the tick itself.
    assert tick(config, settings, store, manager, proof) == {
        "media-import": "present",
        "camera-export": "absent",
    }
    assert all(child.closed for child in children("_hap._tcp"))
    assert not any(child.closed for child in children("_airplay._tcp"))
    assert len(manager.children) == 1
    readback = owner.readback(config, settings, store, 1000).profiles["camera-export"]
    assert readback.state == "absent" and readback.reason == "confirmed-absent"
    write_private(settings.intent, intent_to_dict(Intent(2)))
    assert tick(config, settings, store, manager, proof) == both
    assert len(children("_hap._tcp")) == 2 and len(children("_airplay._tcp")) == 1
    # The other way round, and the pause on top of a hold stops both.
    write_private(settings.intent, intent_to_dict(held("media-controller")))
    assert tick(config, settings, store, manager, proof) == {
        "media-import": "absent",
        "camera-export": "present",
    }
    write_private(settings.intent, intent_to_dict(held("media-controller").pause()))
    assert set(tick(config, settings, store, manager, proof).values()) == {"absent"}
    assert not manager.children


@pytest.mark.parametrize(
    "document",
    [
        version_2(revision=1, holds={"retired-service": {"maintenance": "manager"}}),
        version_2(holds={}),
    ],
)
def test_discovery_owner_withdraws_everything_for_a_hold_it_cannot_place(
    config: Any, settings: Any, document: dict[str, Any]
) -> None:
    store, proof, manager = two_published_policies(config, settings)
    assert set(tick(config, settings, store, manager, proof).values()) == {"present"}
    write_private(settings.intent, document)
    assert set(tick(config, settings, store, manager, proof).values()) == {"absent"}
    assert not manager.children and all(child.closed for child in FakeRegistration.made)


def test_discovery_scanner_and_proof_respect_a_hold(
    config: Any, settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    current = verified_snapshot(config)
    ready = frozenset({"media-udp", "camera-web"})
    intent = held("camera")
    camera, media = policy(config, "camera-export"), policy(config, "media-import")
    assert not owner.dependencies_ready(config, camera, current, intent, ready, 1000)
    assert owner.dependencies_ready(config, media, current, intent, ready, 1000)
    assert not owner.dependencies_ready(config, media, current, intent.pause(), ready, 1000)
    # The proof the publisher collects is planned with the hold and attributed.
    monkeypatch.setattr(owner, "load_bindings", lambda _config, _path: {})
    monkeypatch.setattr(owner, "observe", lambda _config, _clients: current)
    write_private(
        settings.admissions,
        admissions_to_dict(
            {
                key: item
                for key, item in mock_admissions(config).items()
                if config.profile_owner(config.profile(key)).privilege == "user"
            }
        ),
    )
    write_private(settings.intent, intent_to_dict(intent))
    _observed, read, planned = owner.independent_snapshot(config, settings, 1000)
    assert read == intent and "camera-web" not in planned and "proxy-high" in planned
    write_private(settings.intent, intent_to_dict(held("retired-service")))
    _observed, read, planned = owner.independent_snapshot(config, settings, 1000)
    assert read.damaged and read.holds and not planned

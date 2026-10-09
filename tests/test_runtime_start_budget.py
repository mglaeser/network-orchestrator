"""Runtime-start attempts are bounded independently of workload recovery.

All vendor operations use the existing fake. These prove durable accounting,
refusal and compatibility, never native runtime qualification.
"""

from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.codec import canonical_bytes
from netorch.process import ProcessTimeout, Result
from netorch.runtime_settings import parse_settings, settings_to_dict
from netorch.state import Intent, intent_from_dict, intent_to_dict
from netorch.storage import Store
from tests.test_apple_runtime import enrolled
from tests.test_runtime_start_vendor_runtime import IDLE, World, command

__all__ = ["enrolled"]

T0 = 1_800_000_000
RECORD = "runtime-starts.json"
OPERATION = "runtime-start-budget"
HOLDER = "supervisor"


@pytest.fixture
def world(enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> World:
    monkeypatch.setattr(runtime, "_listed_home", lambda _uid: None)
    return World(enrolled, tmp_path, start_budget={"starts": 3, "window_seconds": 600})


def store(world: World) -> Store:
    return Store(Path(world.settings.state_dir))


def attempt(world: World, now: Any = T0, *, idle: bool = False) -> str:
    if idle:
        world.runner.load(**IDLE)
    else:
        world.runner.job = None
    return runtime.start_runtime(world.settings, world.runner, wall=lambda: now)


def refused(world: World, now: Any = T0, *, idle: bool = False) -> None:
    with pytest.raises((runtime.RuntimeReadError, OSError, ProcessTimeout)):
        attempt(world, now, idle=idle)


def intent(world: World) -> Intent:
    return intent_from_dict(store(world).read("intent.json"))


def test_three_failed_starts_are_counted_then_the_probe_and_every_later_start_hold(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.runner.start_answer = Result(1, b"", b"failure")
    world.runner.after_start = lambda: setattr(world.runner, "job", None)
    for count in range(1, 4):
        refused(world)
        assert len(world.vendor_calls()) == count
        assert store(world).read(RECORD)["starts"] == [T0] * count
        assert not intent(world).blocked
    refused(world)
    assert len(world.vendor_calls()) == 3
    assert intent(world).suspensions == {OPERATION: HOLDER}
    assert store(world).read(RECORD)["starts"] == []
    assert command(monkeypatch, world, "runtime-probe") == runtime.UNKNOWN
    # Time and a new process/store do not release negative intent.
    refused(world, T0 + 100_000)
    assert len(world.vendor_calls()) == 3


@pytest.mark.parametrize("idle", [False, True])
def test_successful_starts_and_loaded_idle_activations_both_count(world: World, idle: bool) -> None:
    for count in range(1, 4):
        assert attempt(world, idle=idle) == ("activated" if idle else "started")
        assert len(world.vendor_calls()) == count
    refused(world, idle=idle)
    assert len(world.vendor_calls()) == 3
    assert intent(world).blocked


def test_budget_does_not_rewrite_the_workload_record(world: World) -> None:
    previous = {"schema_version": 1, "services": {"camera": [T0]}}
    store(world).write(runtime.STARTS_RECORD, previous)
    for _ in range(3):
        attempt(world)
    refused(world)
    assert store(world).read(runtime.STARTS_RECORD) == previous


def test_record_is_durable_before_vendor_effect_and_timeout_counts(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = world.runner.system

    def vendor(argv: list[str], kwargs: dict[str, Any]) -> Result:
        assert store(world).read(RECORD) == {"schema_version": 1, "starts": [T0]}
        original(argv, kwargs)
        raise ProcessTimeout("synthetic timeout after native effect")

    monkeypatch.setattr(world.runner, "system", vendor)
    refused(world)
    assert store(world).read(RECORD)["starts"] == [T0]
    assert len(world.vendor_calls()) == 1


def test_window_rounds_up_and_future_timestamps_do_not_release(world: World) -> None:
    for _ in range(3):
        attempt(world, T0 + 0.5)
    assert store(world).read(RECORD)["starts"] == [T0 + 1] * 3
    refused(world, T0 - 100)
    assert len(world.vendor_calls()) == 3
    assert intent(world).blocked


def test_expired_attempts_make_room_before_any_hold_was_taken(world: World) -> None:
    for _ in range(3):
        attempt(world, T0 + 0.5)
    assert attempt(world, T0 + 601) == "started"
    assert store(world).read(RECORD)["starts"] == [T0 + 601]
    assert not intent(world).blocked


def test_explicit_release_resets_only_this_budget_preserving_service_holds(world: World) -> None:
    original = Intent().hold("camera", "maintenance", "operator")
    store(world).write("intent.json", intent_to_dict(original))
    for _ in range(3):
        attempt(world)
    refused(world)
    recorded = intent(world)
    assert recorded.holds == original.holds
    store(world).write("intent.json", intent_to_dict(recorded.release(OPERATION, HOLDER)))
    assert attempt(world) == "started"
    assert intent(world).holds == original.holds


@pytest.mark.parametrize("clock", [None, True, "time", -1, float("nan"), float("inf"), 10**1000])
def test_unusable_clock_starts_nothing_and_takes_a_durable_suspension(
    world: World, clock: Any
) -> None:
    refused(world, clock)
    assert not world.vendor_calls()
    assert intent(world).suspensions == {OPERATION: HOLDER}


@pytest.mark.parametrize(
    "record",
    [
        {},
        None,
        {"schema_version": True, "starts": []},
        {"schema_version": 2, "starts": []},
        {"schema_version": 1, "starts": [], "extra": True},
        {"schema_version": 1, "starts": None},
        *(
            {"schema_version": 1, "starts": entries}
            for entries in ([True], [-1], [1.5], [2**53], [0] * 11)
        ),
    ],
)
def test_malformed_record_is_not_a_new_budget(world: World, record: Any) -> None:
    store(world).write(RECORD, record)
    refused(world)
    assert not world.vendor_calls()
    assert intent(world).suspensions == {OPERATION: HOLDER}


def test_record_write_failure_prevents_vendor_effect(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write = Store.write

    def write(self: Store, name: str, data: Any) -> None:
        if name == RECORD:
            raise OSError("synthetic record failure")
        real_write(self, name, data)

    monkeypatch.setattr(Store, "write", write)
    refused(world)
    assert not world.vendor_calls()


def test_failed_suspension_write_pins_spent_budget_across_later_time(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    for _ in range(3):
        attempt(world)
    real_write = Store.write

    def write(self: Store, name: str, data: Any) -> None:
        if name == "intent.json":
            raise OSError("synthetic intent failure")
        real_write(self, name, data)

    with monkeypatch.context() as patch:
        patch.setattr(Store, "write", write)
        refused(world)
    assert store(world).read(RECORD)["starts"] == [2**53 - 1] * 10
    refused(world, T0 + 100_000)
    assert len(world.vendor_calls()) == 3
    assert intent(world).suspensions == {OPERATION: HOLDER}


def test_suspension_persists_when_counter_clear_is_interrupted(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    for _ in range(3):
        attempt(world)
    real_write = Store.write

    def write(self: Store, name: str, data: Any) -> None:
        if name == RECORD:
            raise OSError("synthetic interruption after hold")
        real_write(self, name, data)

    with monkeypatch.context() as patch:
        patch.setattr(Store, "write", write)
        refused(world)
    assert intent(world).suspensions == {OPERATION: HOLDER}
    refused(world, T0 + 100_000)
    assert len(world.vendor_calls()) == 3


@pytest.mark.parametrize(
    "blocked", [Intent().pause(), Intent().suspend(OPERATION, "another-holder")]
)
def test_pause_or_colliding_holder_starts_nothing_and_is_preserved(
    world: World, blocked: Intent
) -> None:
    store(world).write("intent.json", intent_to_dict(blocked))
    refused(world)
    assert not world.vendor_calls()
    assert intent(world) == blocked
    assert not (store(world).directory / RECORD).exists()


def test_running_or_uncertain_runtime_never_spends_a_budget(world: World) -> None:
    world.runner.load()
    with pytest.raises(runtime.RuntimeReadError):
        runtime.start_runtime(world.settings, world.runner, wall=lambda: T0)
    assert not (store(world).directory / RECORD).exists()
    world.runner.job_answer = Result(1, b"", b"unknown")
    refused(world)
    assert not (store(world).directory / RECORD).exists()
    assert not world.vendor_calls()


def test_old_settings_bytes_remain_unchanged_and_budget_roundtrips(world: World) -> None:
    declared = settings_to_dict(world.settings)
    plain = copy.deepcopy(declared)
    del plain["fleet_start"]["runtime_start"]["start_budget"]
    assert settings_to_dict(parse_settings(plain)) == plain
    assert settings_to_dict(parse_settings(declared)) == declared
    assert canonical_bytes(plain) != canonical_bytes(declared)


@pytest.mark.parametrize(
    "value",
    [None, {}, [], {"starts": 1}, {"starts": 1, "window_seconds": 60, "extra": 1}]
    + [{"starts": starts, "window_seconds": 60} for starts in (True, 0, 11, 1.0, "1")]
    + [{"starts": 1, "window_seconds": seconds} for seconds in (True, 59, 86401, 60.0, "60")],
)
def test_closed_budget_envelope_refuses_ambiguous_or_unbounded_values(
    world: World, value: Any
) -> None:
    declared = settings_to_dict(world.settings)
    declared["fleet_start"]["runtime_start"]["start_budget"] = value
    with pytest.raises(ValueError):
        parse_settings(declared)


@pytest.mark.parametrize(
    "field,value", [("intent", None), ("intent", "/another/intent.json"), ("state_dir", None)]
)
def test_budget_requires_shared_durable_intent(world: World, field: str, value: Any) -> None:
    declared = settings_to_dict(world.settings)
    declared[field] = value
    with pytest.raises(ValueError):
        parse_settings(declared)


def test_direct_caller_cannot_put_budget_and_intent_in_different_stores(world: World) -> None:
    changed = replace(world.settings, intent="/another/intent.json")
    with pytest.raises(ValueError):
        runtime.start_runtime(changed, world.runner)
    assert not world.vendor_calls()


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "mode"])
def test_unsafe_record_is_preserved_and_never_auto_repaired(world: World, unsafe: str) -> None:
    directory = store(world).directory
    target = directory / "unrelated-record.json"
    target.write_bytes(b'{"sentinel":true}\n')
    target.chmod(0o600)
    path = directory / RECORD
    if unsafe == "symlink":
        path.symlink_to(target)
    elif unsafe == "hardlink":
        path.hardlink_to(target)
    else:
        path.write_bytes(b'{"schema_version":1,"starts":[]}\n')
        path.chmod(0o644)
    previous = path.lstat()
    refused(world)
    assert not world.vendor_calls()
    assert path.lstat() == previous
    assert target.read_bytes() == b'{"sentinel":true}\n'
    assert not intent(world).blocked


def test_budget_and_vendor_call_share_the_nonstealable_operation_lock(world: World) -> None:
    from netorch.storage import Busy

    times = iter((0.0, 6.0))
    with store(world).lock(), pytest.raises(Busy):
        runtime.start_runtime(
            world.settings,
            world.runner,
            clock=lambda: next(times),
            sleep=lambda _: pytest.fail("lock is already past its deadline"),
            wall=lambda: T0,
        )
    assert not world.vendor_calls()
    assert not (store(world).directory / RECORD).exists()
    assert attempt(world) == "started"
    assert world.runner.lock_held == [True]

"""Pure safety evidence tests. No OS, network, privilege or receiver operations."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netorch.safety_contract import (
    ALLOCATOR_DEPENDENCY_VERSION,
    ALLOCATOR_RUNTIME_VERSION,
    RECOVERY_FAILURE_EXIT_CODE,
    RotatingAllocatorModel,
    assess_bounded_safety,
    assessment_to_dict,
    recovery_exit_code,
)
from netorch.state import OBSERVATION_REASONS, Observation

SIGNED_AT = "2026-10-05T00:00:00Z"
NOW = 1_759_709_000.0 + 365 * 86400


def assess(**changes: Any) -> Any:
    values = {
        "max_age_seconds": 30,
        "unknown_limit": 3,
        "residual": "An observed shared guest address has a bounded reuse race.",
        "signed_by": "example operator",
        "signed_at": SIGNED_AT,
        "interval_seconds": 10,
        "now": NOW,
    }
    values.update(changes)
    return assess_bounded_safety(**values)


def test_configured_interval_and_signature_do_not_manufacture_a_bound() -> None:
    result = assess()
    assert result.status == "fulfilled-unverified"
    assert result.withdrawal_bound_seconds is None
    assert not result.bounds_verified and not result.zero_misdelivery_guaranteed
    assert result.effective_unknown_limit == 1
    assert result.configured_unknown_limit == 3
    assert "withdrawal-bound-unestablished" in result.reasons
    assert "native-bound-evidence-unverified" in result.reasons


@pytest.mark.parametrize(
    "missing", ["read_timeout_seconds", "apply_timeout_seconds", "scheduler_slack_seconds"]
)
def test_each_unestablished_aggregate_term_blocks_finite_bound(missing: str) -> None:
    values = {
        "read_timeout_seconds": 8,
        "apply_timeout_seconds": 6,
        "scheduler_slack_seconds": 1,
        "evidence_verified": True,
    }
    values[missing] = None
    result = assess(**values)
    assert result.withdrawal_bound_seconds is None
    assert result.status == "fulfilled-unverified"
    assert not result.bounds_verified


def test_complete_native_evidence_can_only_accept_residual_never_zero_misdelivery() -> None:
    result = assess(
        read_timeout_seconds=8,
        apply_timeout_seconds=6,
        scheduler_slack_seconds=1,
        evidence_verified=True,
    )
    assert result.status == "accepted-residual"
    assert result.withdrawal_bound_seconds == 25
    assert result.bounds_verified and not result.zero_misdelivery_guaranteed
    assert result.reasons == ("bounded-address-reuse-residual",)
    value = assessment_to_dict(result)
    assert value["reasons"] == ["bounded-address-reuse-residual"]
    assert value["zero_misdelivery_guaranteed"] is False


def test_timeout_constants_alone_are_not_native_evidence() -> None:
    result = assess(read_timeout_seconds=8, apply_timeout_seconds=6, scheduler_slack_seconds=1)
    assert result.withdrawal_bound_seconds == 25
    assert result.status == "fulfilled-unverified"
    assert not result.bounds_verified


def test_age_is_an_observation_limit_not_automatic_rule_expiry() -> None:
    result = assess(
        max_age_seconds=20,
        read_timeout_seconds=8,
        apply_timeout_seconds=6,
        scheduler_slack_seconds=1,
        evidence_verified=True,
    )
    assert result.status == "not-fulfilled"
    assert "withdrawal-bound-exceeds-age" in result.reasons


def test_launchd_ten_second_floor_is_not_an_upper_bound() -> None:
    result = assess(interval_seconds=1)
    assert result.nominal_interval_seconds == 10
    assert result.withdrawal_bound_seconds is None


@pytest.mark.parametrize("field", ["signed_by", "signed_at"])
def test_owner_must_sign_each_residual(field: str) -> None:
    result = assess(**{field: None})
    assert result.status == "not-fulfilled"
    assert "residual-unsigned" in result.reasons


def test_future_signature_does_not_count_as_approval() -> None:
    result = assess(now=0)
    assert result.status == "not-fulfilled"
    assert "signature-future" in result.reasons


def test_missing_current_time_does_not_silently_validate_signature() -> None:
    result = assess(
        now=None,
        read_timeout_seconds=8,
        apply_timeout_seconds=6,
        scheduler_slack_seconds=1,
        evidence_verified=True,
    )
    assert result.status == "fulfilled-unverified"
    assert "signature-time-unverified" in result.reasons


def test_absolute_never_requirement_requires_architecture_change() -> None:
    result = assess(
        read_timeout_seconds=8,
        apply_timeout_seconds=6,
        scheduler_slack_seconds=1,
        evidence_verified=True,
        zero_misdelivery_required=True,
    )
    assert result.status == "not-fulfilled"
    assert "structural-isolation-required" in result.reasons
    assert not result.zero_misdelivery_guaranteed


@pytest.mark.parametrize(
    "changes",
    [
        {"max_age_seconds": True},
        {"max_age_seconds": 0},
        {"max_age_seconds": 86401},
        {"unknown_limit": 0},
        {"unknown_limit": 1001},
        {"interval_seconds": 0},
        {"interval_seconds": 61},
        {"residual": ""},
        {"residual": "bad\nstatement"},
        {"signed_by": ""},
        {"signed_by": "bad\noperator"},
        {"signed_at": "2026-10-05"},
        {"signed_at": "2026-13-05T00:00:00Z"},
        {"signed_at": "1969-12-31T23:59:59Z"},
        {"signed_at": True},
        {"read_timeout_seconds": float("inf")},
        {"apply_timeout_seconds": -1},
        {"scheduler_slack_seconds": True},
        {"scheduler_slack_seconds": 86401},
        {"evidence_verified": 1},
        {"zero_misdelivery_required": 1},
        {"now": float("nan")},
        {"now": -1},
        {"now": True},
    ],
)
def test_crafted_decisions_cannot_widen_report_authority(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        assess(**changes)


@given(st.integers(min_value=1, max_value=1000))
def test_declared_k_never_changes_existing_owner_first_unknown_behavior(k: int) -> None:
    result = assess(
        unknown_limit=k,
        read_timeout_seconds=8,
        apply_timeout_seconds=6,
        scheduler_slack_seconds=1,
    )
    assert result.effective_unknown_limit == 1
    assert result.withdrawal_bound_seconds == 25


def test_tagged_allocator_contract_is_a_model_not_hardware_acceptance() -> None:
    assert (ALLOCATOR_RUNTIME_VERSION, ALLOCATOR_DEPENDENCY_VERSION) == ("1.5.0", "0.47.0")
    allocator = RotatingAllocatorModel("198.51.100.0/24")
    assert allocator.capacity == 252
    assert allocator.allocate("first") == "198.51.100.2"
    assert allocator.allocate("first") == "198.51.100.2"
    assert allocator.allocate("second") == "198.51.100.3"
    assert allocator.lookup("first") == "198.51.100.2"


def test_released_slot_waits_at_fifo_tail_until_other_available_slots_are_used() -> None:
    allocator = RotatingAllocatorModel("198.51.100.0/29")
    freed = allocator.allocate("removed")
    assert allocator.release("removed") == freed
    assert allocator.lookup("removed") is None
    assert allocator.release("removed") is None
    assert [allocator.allocate(f"replacement-{i}") for i in range(3)] == [
        "198.51.100.3",
        "198.51.100.4",
        "198.51.100.5",
    ]
    assert allocator.allocate("after-rotation") == freed
    with pytest.raises(ValueError, match="exhausted"):
        allocator.allocate("overflow")


def test_pool_rebuild_can_immediately_reassign_an_old_service_address() -> None:
    old = RotatingAllocatorModel("198.51.100.0/24")
    address = old.allocate("target")
    old.allocate("other")
    new = RotatingAllocatorModel("198.51.100.0/24")
    assert new.allocate("other") == address
    assert new.allocate("target") != address


@pytest.mark.parametrize(
    "subnet", ["198.51.100.0/30", "0.0.0.0/0", "198.51.100.1/24", "2001:db8::/64"]
)
def test_synthetic_allocator_is_memory_bounded_and_ipv4_only(subnet: str) -> None:
    with pytest.raises(ValueError):
        RotatingAllocatorModel(subnet)


@pytest.mark.parametrize("holder", ["", "x" * 257, None, 1])
def test_allocator_refuses_invalid_synthetic_holder(holder: Any) -> None:
    with pytest.raises(ValueError):
        RotatingAllocatorModel("198.51.100.0/24").allocate(holder)


@given(st.lists(st.tuples(st.booleans(), st.integers(0, 10)), max_size=100))
def test_allocator_random_lifecycles_never_duplicate_active_leases(
    operations: list[tuple[bool, int]],
) -> None:
    allocator = RotatingAllocatorModel("198.51.100.0/24")
    leases = {}
    for allocate, number in operations:
        holder = f"synthetic-{number}"
        if allocate:
            leases[holder] = allocator.allocate(holder)
        else:
            assert allocator.release(holder) == leases.pop(holder, None)
        assert len(set(leases.values())) == len(leases)
        assert allocator.capacity == 252


@pytest.mark.parametrize("reason", sorted(OBSERVATION_REASONS - {"verified", "confirmed-absent"}))
def test_every_unknown_reason_cannot_trigger_reserved_recovery_code(reason: str) -> None:
    observation = Observation("unknown", reason, 100, None)
    assert (
        recovery_exit_code(observation, now=100, max_age_seconds=30, initial_owners_ready=True) == 1
    )


def test_recovery_only_uses_existing_reserved_code_after_complete_initial_readiness() -> None:
    absent = Observation("absent", "confirmed-absent", 100, "synthetic-1")
    assert RECOVERY_FAILURE_EXIT_CODE == 42 and RECOVERY_FAILURE_EXIT_CODE > 31
    assert recovery_exit_code(absent, now=100, max_age_seconds=30) == 1
    assert recovery_exit_code(absent, now=100, max_age_seconds=30, initial_owners_ready=True) == 42
    assert recovery_exit_code(absent, now=131, max_age_seconds=30, initial_owners_ready=True) == 1
    assert recovery_exit_code(absent, now=99, max_age_seconds=30, initial_owners_ready=True) == 1
    present = Observation("present", "verified", 100, "synthetic-1")
    assert recovery_exit_code(present, now=100, max_age_seconds=30) == 0
    with pytest.raises(ValueError):
        recovery_exit_code(absent, now=100, max_age_seconds=30, initial_owners_ready=1)  # type: ignore[arg-type]

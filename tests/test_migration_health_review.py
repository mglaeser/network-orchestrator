"""Independent counterexamples for the offline health-record boundary."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from netorch.codec import canonical_bytes
from netorch.migration_health import validate_contract
from tests.test_migration_health import NOW, check, fixture


@pytest.mark.parametrize("field", ["since", "now", "started_at", "completed_at"])
def test_unbounded_python_integer_is_refused_without_conversion_overflow(field: str) -> None:
    contract, snapshot = fixture()
    enormous = 10**1000
    with pytest.raises(ValueError):
        if field in {"since", "now"}:
            check(contract, snapshot, **{field: enormous})
        else:
            snapshot[field] = enormous
            check(contract, snapshot)


@pytest.mark.parametrize(
    "metadata",
    [float("nan"), float("inf"), "x" * 65_537, "\ud800", 10**1000],
    ids=["nan", "infinity", "oversized-string", "invalid-unicode", "oversized-integer"],
)
def test_direct_api_metadata_obeys_the_same_json_boundary_as_cli(metadata: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["ignoredMetadata"] = metadata
    with pytest.raises(ValueError):
        check(contract, snapshot)


@pytest.mark.parametrize("shape", ["cycle", "depth", "nodes", "bytes"])
def test_direct_api_cannot_hide_unbounded_structure_in_ignored_metadata(shape: str) -> None:
    contract, snapshot = fixture()
    if shape == "cycle":
        metadata: Any = []
        metadata.append(metadata)
    elif shape == "depth":
        metadata = "leaf"
        for _ in range(33):
            metadata = [metadata]
    elif shape == "nodes":
        metadata = [None] * 50_001
    else:
        metadata = ["x" * 65_536 for _ in range(17)]
    snapshot["dashboard"]["ignoredMetadata"] = metadata
    with pytest.raises(ValueError):
        check(contract, snapshot)


def test_contract_validator_itself_rejects_invalid_unicode() -> None:
    contract, _ = fixture()
    contract["services"][0]["checks"][0] = "\ud800"
    with pytest.raises(ValueError):
        validate_contract(contract)


def test_metadata_is_ignored_semantically_without_becoming_an_action() -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["metadata"] = {
        "command": "this is data, never an executable command",
        "credentials": "do not echo this value",
    }
    result = check(contract, snapshot)
    assert result["recorded_health_passed"] is True
    assert "metadata" not in result and "credentials" not in str(result)
    assert result["mutation_available"] is False
    assert result["native_qualified"] is False
    assert result["provenance_authenticated"] is False


@pytest.mark.parametrize(
    "contract_category,dashboard_category",
    [("service", "services"), ("device", "devices"), ("webpage", "webpages")],
)
def test_real_dashboard_plural_categories_match_reviewed_singular_contract(
    contract_category: str, dashboard_category: str
) -> None:
    contract, snapshot = fixture()
    contract["services"][0]["category"] = contract_category
    snapshot["dashboard"]["services"][0]["category"] = dashboard_category
    # This is a new reviewed contract, so its snapshot must bind the new digest.
    snapshot["contract_sha256"] = hashlib.sha256(canonical_bytes(contract)).hexdigest()
    assert check(contract, snapshot)["recorded_health_passed"] is True


@pytest.mark.parametrize("category", ["devices", "webpages", "Services", "services ", None, 1])
def test_category_normalization_does_not_hide_wrong_or_malformed_category(category: Any) -> None:
    contract, snapshot = fixture()
    snapshot["dashboard"]["services"][0]["category"] = category
    result = check(contract, snapshot)
    assert result["recorded_health_passed"] is False
    assert "console:category-changed" in result["blockers"]


def test_new_retry_boundary_refuses_previous_batch_even_if_generation_is_reused() -> None:
    contract, snapshot = fixture()
    result = check(contract, snapshot, since=NOW - 5)
    assert result["recorded_health_passed"] is False
    assert "checkpoint-window-invalid" in result["blockers"]


def test_contract_reordering_cannot_reuse_an_old_recording_digest() -> None:
    contract, snapshot = fixture()
    contract["services"].reverse()
    result = check(contract, snapshot)
    assert result["recorded_health_passed"] is False
    assert "checkpoint-context-mismatch" in result["blockers"]

"""An enrolled, retained definition may share a writable path while it is stopped."""

from __future__ import annotations

import copy
from dataclasses import replace
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.codec import digest
from netorch.runtime_settings import contract_digest, parse_settings, settings_to_dict
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_runtime_settings import authored

__all__ = ["enrolled"]

RETAINED = "Example_camera.retained-1"
# Digests of `authored()` computed before the tolerance list existed.
CONTRACT_DIGEST = "0ccf3c6325fb34f89e2f2a1f971c6df6fedee8cebfb2636ebd1568576e412daf"
SETTINGS_DIGEST = "6dd79016779aa6e1ef2a82ce99dd40e315faffbd13cb71c1f65ae2df72d1bde9"


def retain(runner: FakeRunner, name: str = RETAINED, state: str = "stopped") -> None:
    """Add a second definition over the camera's writable host path."""
    peer = copy.deepcopy(runner.items["example-camera"])
    peer["id"] = name
    peer["status"] = {"state": state, "networks": []}
    if state == "running":
        peer["status"]["startedDate"] = "2026-01-01T00:00:05Z"
    runner.items[name] = peer


def tolerating(config: Any, settings: Any, service: str, *names: str) -> tuple[Any, Any]:
    """Enroll the names for the service and derive the policy's contract hash again."""
    contract = replace(settings.contract(service), tolerated_stopped_peers=tuple(names))
    settings = replace(
        settings,
        contracts=tuple(contract if c.service == service else c for c in settings.contracts),
    )
    return runtime.derive_policy(config, settings), settings


def camera(config: Any, settings: Any, runner: FakeRunner) -> tuple[str, str]:
    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert observed.services["resolver"].state == "present"
    return observed.services["camera"].state, observed.services["camera"].reason


def test_a_stopped_peer_is_refused_unless_it_is_enrolled(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    assert camera(config, settings, runner) == ("present", "verified")
    retain(runner)
    assert camera(config, settings, runner) == ("unknown", "identity-mismatch")


def test_an_enrolled_stopped_peer_is_tolerated(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    retain(runner)
    config, settings = tolerating(config, settings, "camera", RETAINED)
    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert {item.state for item in observed.services.values()} == {"present"}
    assert observed.profiles["camera-web"].state == "present"


@pytest.mark.parametrize("state", ["running", "stopping", "unknown"])
def test_an_enrolled_peer_that_is_not_stopped_is_refused(enrolled: Any, state: str) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    retain(runner, state=state)
    config, settings = tolerating(config, settings, "camera", RETAINED)
    assert camera(config, settings, runner) == ("unknown", "identity-mismatch")


def test_the_tolerance_covers_only_the_enrolled_name(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    retain(runner)
    retain(runner, name="another-retained-definition")
    config, settings = tolerating(config, settings, "camera", RETAINED)
    assert camera(config, settings, runner) == ("unknown", "identity-mismatch")
    del runner.items["another-retained-definition"]
    assert camera(config, settings, runner) == ("present", "verified")


def test_the_tolerance_belongs_to_one_contract(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    retain(runner)
    # Enrolled for the resolver, the name does nothing for the camera's path.
    config, settings = tolerating(config, settings, "resolver", RETAINED)
    assert camera(config, settings, runner) == ("unknown", "identity-mismatch")


def test_recovery_starts_the_workload_and_never_the_tolerated_peer(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    retain(runner)
    config, settings = tolerating(config, settings, "camera", RETAINED)
    runner.items["example-camera"]["status"]["state"] = "stopped"
    recovered = runtime.recover_service(config, settings, "camera", runner)
    assert recovered.services["camera"].state == "present"
    starts = [argv for argv, _ in runner.calls if argv[1:2] == ["start"]]
    assert starts == [[settings.executable, "start", "example-camera"]]
    assert runner.items[RETAINED]["status"]["state"] == "stopped"


def test_an_enrollment_without_the_list_keeps_its_earlier_digests() -> None:
    # This test also passes on the code before the list existed: the two values
    # are what that code produced for the same enrollment.
    parsed = parse_settings(authored())
    assert contract_digest(parsed.contracts[0]) == CONTRACT_DIGEST
    assert digest(settings_to_dict(parsed)) == SETTINGS_DIGEST
    assert set(settings_to_dict(parsed)["contracts"][0]) == {
        "service",
        "name",
        "scope",
        "configuration_sha256",
        "mounts",
        "receipts",
    }


def test_an_explicit_empty_list_is_the_same_enrollment() -> None:
    raw = authored()
    parsed = parse_settings(raw)
    assert parsed.contracts[0].tolerated_stopped_peers == ()
    raw["contracts"][0]["tolerated_stopped_peers"] = []
    assert parse_settings(raw) == parsed
    assert contract_digest(parse_settings(raw).contracts[0]) == CONTRACT_DIGEST
    assert digest(settings_to_dict(parse_settings(raw))) == SETTINGS_DIGEST


def test_an_enrolled_name_is_part_of_the_contract_and_settings_digests() -> None:
    raw = authored()
    raw["contracts"][0]["tolerated_stopped_peers"] = [RETAINED, "example-camera-retained"]
    parsed = parse_settings(raw)
    assert parsed.contracts[0].tolerated_stopped_peers == (RETAINED, "example-camera-retained")
    assert parse_settings(settings_to_dict(parsed)) == parsed
    assert settings_to_dict(parsed)["contracts"][0]["tolerated_stopped_peers"] == [
        RETAINED,
        "example-camera-retained",
    ]
    assert contract_digest(parsed.contracts[0]) != CONTRACT_DIGEST
    assert digest(settings_to_dict(parsed)) != SETTINGS_DIGEST
    other = copy.deepcopy(raw)
    other["contracts"][0]["tolerated_stopped_peers"] = [RETAINED]
    assert contract_digest(parse_settings(other).contracts[0]) != contract_digest(
        parsed.contracts[0]
    )


def test_enrolling_a_name_changes_only_that_service_in_the_derived_policy(enrolled: Any) -> None:
    config, settings, _items = enrolled
    derived, _ = tolerating(config, settings, "camera", RETAINED)
    changed = {
        before.id
        for before, after in zip(config.services, derived.services, strict=True)
        if before.contract_sha256 != after.contract_sha256
    }
    assert changed == {"camera"}
    assert runtime.derive_policy(config, settings) == config


@pytest.mark.parametrize(
    "value",
    [
        "example-camera-retained",
        {"example-camera-retained": True},
        [7],
        [None],
        [""],
        ["x"],
        ["-leading-dash"],
        ["with space"],
        ["with/slash"],
        ["line\nbreak"],
        ["a" * 64],
        ["zebra", "alpha"],
        ["alpha", "alpha"],
        [f"retained-{index:02d}" for index in range(17)],
        # An enrolled workload can be started by recovery; it is never tolerated.
        ["example-camera"],
        ["example-resolver"],
    ],
)
def test_the_list_is_closed_bounded_sorted_and_names_no_enrolled_workload(value: Any) -> None:
    raw = authored()
    second = copy.deepcopy(raw["contracts"][0])
    second.update(service="resolver", name="example-resolver")
    raw["contracts"].append(second)
    assert parse_settings(raw)
    raw["contracts"][0]["tolerated_stopped_peers"] = value
    with pytest.raises(ValueError):
        parse_settings(raw)


@pytest.mark.parametrize(
    "value", [["ab"], ["A1"], ["a" * 63], [f"retained-{index:02d}" for index in range(16)]]
)
def test_the_list_accepts_any_name_the_vendor_inventory_can_hold(value: list[str]) -> None:
    raw = authored()
    raw["contracts"][0]["tolerated_stopped_peers"] = value
    assert parse_settings(raw).contracts[0].tolerated_stopped_peers == tuple(value)

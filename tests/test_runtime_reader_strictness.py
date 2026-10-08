"""Unfamiliar native output is unknown, and a failed lookup stays a redacted error."""

from __future__ import annotations

import copy
from dataclasses import asdict, replace
from io import BytesIO, TextIOWrapper
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.codec import canonical_bytes, digest
from netorch.config import config_digest, profile_digest
from netorch.mock import mock_admissions
from netorch.runtime_settings import contract_digest, load_settings, settings_to_dict
from netorch.state import admissions_to_dict
from netorch.workloads import Option, create_arguments, main, parse_workloads
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_workloads import cli_settings, fleet, legacy_cli_conformance

__all__ = ["enrolled", "legacy_cli_conformance"]

PIN = "example.invalid/service@sha256:" + "1" * 64


def reenrolled(config: Any, settings: Any, runner: FakeRunner, service: str) -> tuple[Any, Any]:
    """Enroll the service's present native configuration and admit its profiles again."""
    name = settings.contract(service).name
    contract = replace(
        settings.contract(service),
        configuration_sha256=digest(runner.items[name]["configuration"]),
    )
    settings = replace(
        settings,
        contracts=tuple(contract if c.service == service else c for c in settings.contracts),
    )
    config = replace(
        config,
        services=tuple(
            replace(s, contract_sha256=contract_digest(contract)) if s.id == service else s
            for s in config.services
        ),
    )
    Path(settings.admissions).write_bytes(
        canonical_bytes(admissions_to_dict(mock_admissions(config)))
    )
    return config, settings


def activation(config: Any, settings: Any, observed: Any, profile_id: str) -> dict[str, Any]:
    profile = config.profile(profile_id)
    return {
        "protocol_version": 1,
        "operation": "reconcile",
        "owner": settings.owner,
        "policy_digest": config_digest(config),
        "profile_digest": profile_digest(config, profile),
        "profile": profile.id,
        "action": "activate",
        "target_ipv4": observed.services[profile.service].data["ipv4"],
        "target_generation": observed.services[profile.service].generation,
    }


@pytest.mark.parametrize(
    "shape",
    [
        "extra-key",
        "missing-key",
        "number-as-text",
        "true-for-one",
        "repeated",
        "not-an-object",
        "extra-key-on-another-row",
    ],
)
def test_an_unfamiliar_publication_row_is_unknown_not_absent(enrolled: Any, shape: str) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    rows = runner.items["example-camera"]["configuration"]["publishedPorts"]
    other = {**rows[0], "hostPort": rows[0]["hostPort"] + 1000}
    if shape == "extra-key":
        rows[0]["futureField"] = None
    elif shape == "missing-key":
        del rows[0]["count"]
    elif shape == "number-as-text":
        rows[0]["hostPort"] = str(rows[0]["hostPort"])
    elif shape == "true-for-one":
        assert rows[0]["count"] == 1
        rows[0]["count"] = True
    elif shape == "repeated":
        rows.append(copy.deepcopy(rows[0]))
    elif shape == "not-an-object":
        rows.append("192.0.2.10:8443:443/tcp")
    else:
        rows.append({**other, "futureField": None})
    config, settings = reenrolled(config, settings, runner, "camera")
    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert observed.services["camera"].state == "present"
    profile = observed.profiles["camera-web"]
    assert (profile.state, profile.reason, profile.generation) == ("unknown", "malformed", None)
    # Unknown is not the maintenance requirement that a proven absence reports.
    with pytest.raises(runtime.RuntimeReadError) as refusal:
        runtime.handle_request(
            config, settings, activation(config, settings, observed, "camera-web"), runner
        )
    assert type(refusal.value) is runtime.RuntimeReadError
    assert refusal.value.reason == "identity-mismatch"


def test_a_familiar_row_for_another_port_changes_nothing(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    rows = runner.items["example-camera"]["configuration"]["publishedPorts"]
    expected = copy.deepcopy(rows[0])
    rows.append({**expected, "hostPort": expected["hostPort"] + 1000})
    config, settings = reenrolled(config, settings, runner, "camera")
    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert observed.profiles["camera-web"].state == "present"
    request = activation(config, settings, observed, "camera-web")
    assert runtime.handle_request(config, settings, request, runner)["result"]["state"] == "present"
    # Without the expected row the complete list still proves absence.
    rows.remove(expected)
    config, settings = reenrolled(config, settings, runner, "camera")
    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    profile = observed.profiles["camera-web"]
    assert (profile.state, profile.reason) == ("absent", "confirmed-absent")
    with pytest.raises(runtime.NativePublicationMaintenance):
        runtime.handle_request(
            config, settings, activation(config, settings, observed, "camera-web"), runner
        )


@pytest.mark.parametrize("row", ["unfamiliar", None, 7, ["example-network"]])
def test_an_attachment_row_that_is_not_an_object_is_unknown(enrolled: Any, row: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    runner.items["example-camera"]["status"]["networks"].append(row)
    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    camera = observed.services["camera"]
    assert (camera.state, camera.reason, camera.generation) == ("unknown", "malformed", None)
    assert observed.profiles["camera-web"].state == "unknown"
    assert observed.services["resolver"].state == "present"


@pytest.mark.parametrize("version", ["1.2.0", "1.4.1", "1.5.0"])
@pytest.mark.parametrize("state", ["stopped", "running"])
def test_a_flat_container_row_is_not_decoded(version: str, state: str) -> None:
    flat = {
        "id": "example",
        "configuration": {},
        "status": state,
        "startedDate": "2026-01-01T00:00:00Z",
        "networks": [],
    }
    with pytest.raises(runtime.RuntimeReadError):
        runtime.decode_snapshot(flat, version)
    nested = {"id": "example", "configuration": {}, "status": {"state": "stopped"}}
    assert runtime.decode_snapshot(nested, version)["state"] == "stopped"


def test_a_flat_stopped_row_never_starts_a_guest(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    item = runner.items["example-camera"]
    runner.items["example-camera"] = {
        "id": item["id"],
        "configuration": item["configuration"],
        "status": "stopped",
    }
    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert {entry.state for entry in observed.services.values()} == {"unknown"}
    assert observed.network_generation is None
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert not any(argv[1:2] == ["start"] for argv, _ in runner.calls)


def test_a_service_without_enrollment_is_a_value_error(enrolled: Any) -> None:
    _config, settings, _items = enrolled
    assert settings.contract("camera").name == "example-camera"
    with pytest.raises(ValueError, match="no runtime contract"):
        settings.contract("stranger")


@pytest.mark.usefixtures("legacy_cli_conformance")
def test_provisioning_a_recipe_for_an_unenrolled_service_is_a_redacted_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _module, _config, _settings, fake, workloads, store, recipes = cli_settings(
        tmp_path, monkeypatch
    )
    stranger = replace(workloads[0], service="stranger")
    recipes.write_bytes(canonical_bytes({"schema_version": 1, "workloads": [asdict(stranger)]}))
    prefix = ["--settings", str(tmp_path / "private-settings.json"), "--recipes", str(recipes)]
    assert main([*prefix, "provision", "--expected-digest", "0" * 64]) == 69
    captured = capsys.readouterr()
    assert not captured.out
    assert captured.err == '{"error":"workload-evidence-or-authority-incomplete"}\n'
    assert not fake.calls and not fake.existing
    assert not (store.directory / "workload-journal.json").exists()


@pytest.mark.parametrize("action", ["withdraw", "drain"])
@pytest.mark.parametrize("profile", ["no-such-profile", "", ["camera-web"], None])
def test_a_request_for_an_unknown_profile_is_a_redacted_refusal(
    enrolled: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    action: str,
    profile: Any,
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    request = {
        "protocol_version": 1,
        "operation": "reconcile",
        "owner": settings.owner,
        "policy_digest": config_digest(config),
        "profile_digest": "0" * 64,
        "profile": profile,
        "action": action,
        "target_ipv4": "198.51.100.10",
        "target_generation": "guest-example",
    }
    with pytest.raises(ValueError, match="publication authority mismatch"):
        runtime.handle_request(config, settings, request, runner)
    assert not runner.calls
    # The same request through the endpoint command: one redacted line, no trace.
    path = tmp_path / "runtime-settings.json"
    path.write_bytes(canonical_bytes(settings_to_dict(settings)))
    assert load_settings(path) == settings
    monkeypatch.setattr(runtime.sys, "stdin", TextIOWrapper(BytesIO(canonical_bytes(request))))
    assert runtime.main(["--settings", str(path), "request"]) == 69
    captured = capsys.readouterr()
    assert not captured.out
    assert captured.err == '{"error":"runtime-evidence-or-authority-incomplete"}\n'


@pytest.mark.parametrize("name", ["-x", "--rm", "-", ".hidden", "/rooted", ":tagged"])
def test_an_image_reference_begins_with_a_letter_or_digit(tmp_path: Path, name: str) -> None:
    image = name + "@sha256:" + "1" * 64
    recipe = {
        "schema_version": 1,
        "workloads": [{"service": "example", "image": image, "options": [], "arguments": []}],
    }
    with pytest.raises(ValueError, match="invalid workload recipe"):
        parse_workloads(recipe)
    config, settings, _, workloads, _ = fleet(tmp_path)
    with pytest.raises(ValueError, match="init image must be pinned by digest"):
        create_arguments(
            config, settings, replace(workloads[0], options=(Option("--init-image", image),))
        )


@pytest.mark.parametrize(
    "image",
    [
        PIN,
        "localhost/service@sha256:" + "2" * 64,
        "example.invalid:5000/team/service@sha256:" + "3" * 64,
    ],
)
def test_an_ordinary_pinned_image_reference_is_still_accepted(tmp_path: Path, image: str) -> None:
    recipe = {
        "schema_version": 1,
        "workloads": [{"service": "example", "image": image, "options": [], "arguments": []}],
    }
    assert parse_workloads(recipe)[0].image == image
    config, settings, _, workloads, _ = fleet(tmp_path)
    options = (Option("--init-image", image),)
    assert image in create_arguments(config, settings, replace(workloads[0], options=options))

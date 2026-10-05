"""Portable end-to-end operator flows; no live network or privileged command."""

from __future__ import annotations

from pathlib import Path

import pytest

import netorch.cli as cli_module
from netorch import __version__
from netorch.cli import main
from netorch.codec import canonical_json, strict_load, strict_loads
from netorch.config import config_digest, load_config
from netorch.mock import initial_snapshot, mock_admissions
from netorch.state import Intent, Snapshot, admissions_to_dict, intent_to_dict, snapshot_to_dict
from netorch.storage import Store


@pytest.fixture
def inputs(tmp_path):
    config_path = Path(__file__).resolve().parents[1] / "examples" / "network.json"
    config = load_config(config_path)
    snapshot_path = tmp_path / "snapshot.json"
    admission_path = tmp_path / "admissions.json"
    intent_path = tmp_path / "intent.json"
    snapshot_path.write_text(canonical_json(snapshot_to_dict(initial_snapshot(config))) + "\n")
    admission_path.write_text(canonical_json(admissions_to_dict(mock_admissions(config))) + "\n")
    intent_path.write_text(canonical_json(intent_to_dict(Intent())) + "\n")
    return config, config_path, snapshot_path, admission_path, intent_path


def invoke_json(capfd, args, *, expected=0):
    assert main([str(arg) for arg in args]) == expected
    captured = capfd.readouterr()
    assert captured.err == ""
    return strict_loads(captured.out)


def dry_args(command, inputs, *, with_admissions=True, with_intent=True):
    _config, config_path, snapshot_path, admission_path, intent_path = inputs
    args = [command, "--config", config_path, "--snapshot", snapshot_path, "--now", "1000"]
    if with_admissions:
        args += ["--admissions", admission_path]
    if with_intent:
        args += ["--intent", intent_path]
    return args


def snapshot_bindings(inputs, tmp_path):
    config = inputs[0]
    snapshot = initial_snapshot(config)
    profile_owners = {
        **{profile.id: config.profile_owner(profile).id for profile in config.profiles},
        **{item.id: item.owner for item in config.discovery},
    }
    entries = []
    for owner in config.owners:
        fragment = Snapshot(
            snapshot.observed_at,
            snapshot.network_generation,
            {
                key: observation
                for key, observation in snapshot.services.items()
                if config.service(key).owner == owner.id
            },
            {
                key: observation
                for key, observation in snapshot.profiles.items()
                if profile_owners[key] == owner.id
            },
        )
        path = tmp_path / f"{owner.id}-snapshot.json"
        path.write_text(canonical_json(snapshot_to_dict(fragment)))
        entries.append({"id": owner.id, "kind": "snapshot-file", "path": str(path)})
    bindings = tmp_path / "bindings.json"
    bindings.write_text(canonical_json({"schema_version": 1, "owners": entries}))
    bindings.chmod(0o600)
    return bindings


def test_validate_cli_emits_only_verified_config_metadata(capfd, inputs):
    config, config_path, *_rest = inputs
    result = invoke_json(capfd, ["validate", "--config", config_path])
    assert result == {
        "valid": True,
        "policy_digest": config_digest(config),
        "profiles": len(config.profiles),
    }


def test_derive_generate_check_and_drift_detection(capfd, inputs, tmp_path):
    _config, config_path, *_rest = inputs
    manifest = tmp_path / "derive.json"
    manifest.write_text(
        canonical_json(
            {
                "schema_version": 1,
                "sources": [{"path": str(config_path), "format": "json"}],
            }
        )
    )
    output = tmp_path / "derived.json"
    args = ["derive", "--source", manifest, "--output", output]
    assert main([str(arg) for arg in args]) == 0
    assert capfd.readouterr().out == ""
    assert load_config(output) == load_config(config_path)
    assert main([str(arg) for arg in [*args, "--check"]]) == 0
    assert capfd.readouterr().out == ""
    before = output.read_bytes()
    output.write_bytes(before + b"\n")
    result = invoke_json(capfd, [*args, "--check"], expected=65)
    assert result["error"] == "invalid-or-unverified"
    assert output.read_bytes() == before + b"\n"


def test_derive_stdout_does_not_require_generated_authority(capfd, inputs, tmp_path):
    _config, config_path, *_rest = inputs
    manifest = tmp_path / "derive.json"
    manifest.write_text(
        canonical_json(
            {
                "schema_version": 1,
                "sources": [{"path": str(config_path), "format": "json"}],
            }
        )
    )
    derived = invoke_json(capfd, ["derive", "--source", manifest])
    assert derived["site"] == "example-site"
    assert not (tmp_path / "derived.json").exists()


def test_unadmitted_dry_plan_never_activates(capfd, inputs):
    result = invoke_json(capfd, dry_args("plan", inputs, with_admissions=False))
    assert {action["operation"] for action in result["actions"]} == {"pending"}
    assert all(action["reason"] == "not-admitted" for action in result["actions"])


def test_admitted_dry_plan_remains_staged_by_publication_evidence(capfd, inputs):
    result = invoke_json(capfd, dry_args("plan", inputs))
    decisions = {action["profile"]: action for action in result["actions"]}
    assert decisions["camera-web"]["operation"] == "activate"
    assert decisions["proxy-high"]["operation"] == "activate"
    assert decisions["proxy-standard"]["operation"] == "blocked"
    assert decisions["proxy-standard"]["reason"] == "publication-not-ready"
    assert decisions["media-udp"]["operation"] == "activate"


def test_status_reports_no_discovery_ready_before_actual_readback(capfd, inputs):
    result = invoke_json(capfd, dry_args("status", inputs))
    assert result["ready_profiles"] == []
    assert all(not item["dependencies_verified"] for item in result["discovery"])
    assert all(item["application_acceptance"] == "not-established" for item in result["discovery"])
    assert "physical application acceptance is separate" in result["claim"]


def test_observe_reads_explicit_snapshot_bindings_without_mutation(capfd, inputs, tmp_path):
    bindings = snapshot_bindings(inputs, tmp_path)
    result = invoke_json(capfd, ["observe", "--config", inputs[1], "--bindings", bindings])
    assert result["network_generation"] == "mock-network-1"
    assert len(result["services"]) == len(inputs[0].services)
    assert all(observation["state"] == "absent" for observation in result["profiles"].values())
    assert not (tmp_path / "state").exists()


def test_reconcile_defaults_to_dry_plan_and_keeps_external_owners_external(
    capfd,
    inputs,
    tmp_path,
    monkeypatch,
):
    bindings = snapshot_bindings(inputs, tmp_path)
    store = Store(tmp_path / "state")
    store.write("intent.json", intent_to_dict(Intent()))
    monkeypatch.setattr(cli_module.time, "time", lambda: 1000.0)
    args = [
        "reconcile",
        "--config",
        inputs[1],
        "--bindings",
        bindings,
        "--admissions",
        inputs[3],
        "--state-dir",
        store.directory,
    ]
    result = invoke_json(capfd, args)
    assert result["execution"] == "not-requested"
    assert not (store.directory / "journal.json").exists()
    result = invoke_json(capfd, [*args, "--execute-user-owners"], expected=69)
    assert result["phase"] == "waiting-external-owner"
    assert result["completed"] == 0
    assert "media-udp" in result["pending"]
    assert store.read("journal.json")["phase"] == "waiting-external-owner"
    assert not (store.directory / "receipt.json").exists()


def test_missing_intent_is_fail_closed_even_with_admission(capfd, inputs):
    result = invoke_json(capfd, dry_args("status", inputs, with_intent=False))
    assert result["intent"]["damaged"]
    assert result["ready_profiles"] == []
    assert all(action["operation"] == "blocked" for action in result["actions"])
    assert all(action["reason"] == "intent-damaged" for action in result["actions"])


@pytest.mark.parametrize("damaged", [{}, {"schema_version": 99}])
def test_semantically_damaged_intent_is_visible_and_inhibits(capfd, inputs, damaged):
    inputs[-1].write_text(canonical_json(damaged))
    result = invoke_json(capfd, dry_args("status", inputs))
    assert result["intent"]["damaged"]
    assert all(action["operation"] == "blocked" for action in result["actions"])


def test_malformed_intent_file_returns_closed_error_without_plan(capfd, inputs):
    inputs[-1].write_text('{"secret-marker": "untrusted",')
    result = invoke_json(capfd, dry_args("plan", inputs), expected=65)
    assert result["error"] == "invalid-or-unverified"
    assert "actions" not in result
    assert "secret-marker" not in canonical_json(result)


def test_pf_preview_never_invokes_a_command(capfd, inputs, monkeypatch):
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("PF preview attempted an external command")

    monkeypatch.setattr(subprocess, "run", forbidden)
    assert main([str(arg) for arg in dry_args("render-pf", inputs)]) == 0
    captured = capfd.readouterr()
    assert captured.err == ""
    assert captured.out.startswith("# Netorch preview only;")
    assert "static-port" in captured.out
    assert 'label "netorch:media-udp"' in captured.out
    assert "port 45000:45127 -> 198.51.100." in captured.out
    assert "-> 192.0.2.10 port 8080" not in captured.out  # backing socket not yet verified


@pytest.mark.parametrize("command", ["demo", "simulate"])
def test_mock_cli_full_workflow_is_explicitly_simulation(capfd, inputs, command):
    args = [command] if command == "demo" else [command, "--config", inputs[1]]
    result = invoke_json(capfd, args)
    assert result["simulation"] is True
    assert result["all_verified"] is True
    events = {event["stage"]: event for event in result["events"]}
    assert {action["operation"] for action in events["unadmitted"]["plan"]["actions"]} == {
        "pending"
    }
    assert events["operator-pause-survives-release"]["phase"] == "inhibited"
    assert events["final-readback"]["phase"] == "committed"
    assert "no native network or audio acceptance" in result["claim"]


def test_intent_cli_keeps_holder_and_operator_intent_independent(capfd, tmp_path):
    state_dir = tmp_path / "state"
    base = ["--state-dir", state_dir]
    initial = invoke_json(capfd, ["init-state", *base])
    assert initial["operator_paused"] and initial["revision"] == 0
    suspended = invoke_json(
        capfd, ["suspend", *base, "--operation", "maintenance", "--holder", "worker-a"]
    )
    assert suspended["suspensions"] == {"maintenance": "worker-a"}
    result = invoke_json(
        capfd, ["release", *base, "--operation", "maintenance", "--holder", "worker-b"], expected=65
    )
    assert result["error"] == "invalid-or-unverified"
    assert strict_load(state_dir / "intent.json") == suspended
    released = invoke_json(
        capfd, ["release", *base, "--operation", "maintenance", "--holder", "worker-a"]
    )
    assert released["operator_paused"] and released["suspensions"] == {}
    resumed = invoke_json(capfd, ["resume", *base])
    assert resumed["operator_paused"] is False
    assert resumed["revision"] > released["revision"]
    paused = invoke_json(capfd, ["pause", *base])
    assert paused["operator_paused"]
    previous = (state_dir / "intent.json").read_bytes()
    invoke_json(capfd, ["init-state", *base], expected=65)
    assert (state_dir / "intent.json").read_bytes() == previous


def test_resume_does_not_clear_suspension(capfd, tmp_path):
    state_dir = tmp_path / "state"
    base = ["--state-dir", state_dir]
    invoke_json(capfd, ["init-state", *base])
    invoke_json(capfd, ["suspend", *base, "--operation", "maintenance", "--holder", "worker-a"])
    result = invoke_json(capfd, ["resume", *base])
    assert result["operator_paused"] is False
    assert result["suspensions"] == {"maintenance": "worker-a"}


def test_corrupt_persisted_intent_cannot_resume_or_be_reinitialized(capfd, tmp_path):
    state_dir = tmp_path / "state"
    base = ["--state-dir", state_dir]
    invoke_json(capfd, ["init-state", *base])
    path = state_dir / "intent.json"
    path.write_text("invalid private-state-marker")
    before = path.read_bytes()
    for command in ("resume", "pause", "init-state"):
        result = invoke_json(capfd, [command, *base], expected=65)
        assert "private-state-marker" not in canonical_json(result)
        assert path.read_bytes() == before


def test_acknowledge_requires_exact_interrupted_plan_and_performs_no_repair(capfd, tmp_path):
    store = Store(tmp_path / "state")
    journal = {
        "schema_version": 1,
        "phase": "applying",
        "plan_digest": "a" * 64,
        "completed": 1,
        "target_ipv4": "198.51.100.2",
    }
    store.write("journal.json", journal)
    args = ["acknowledge-journal", "--state-dir", store.directory, "--plan-digest"]
    invoke_json(capfd, [*args, "b" * 64], expected=65)
    assert store.read("journal.json") == journal
    result = invoke_json(capfd, [*args, "a" * 64])
    assert result["journal"] == "acknowledged"
    assert "no repair, rollback or admission" in result["claim"]
    updated = store.read("journal.json")
    assert updated["phase"] == "inhibited" and updated["operator_acknowledged"]
    assert updated["completed"] == 1 and updated["target_ipv4"] == journal["target_ipv4"]
    invoke_json(capfd, [*args, "a" * 64], expected=65)


def test_busy_cli_does_not_steal_lock_or_mutate_intent(capfd, tmp_path):
    store = Store(tmp_path / "state")
    store.write("intent.json", intent_to_dict(Intent(operator_paused=True)))
    previous = store.read("intent.json")
    with store.lock():
        result = invoke_json(capfd, ["resume", "--state-dir", store.directory], expected=75)
    assert result["error"] == "busy"
    assert store.read("intent.json") == previous


def test_version_exit_is_consistent_with_package(capfd):
    with pytest.raises(SystemExit) as exited:
        main(["--version"])
    assert exited.value.code == 0
    assert capfd.readouterr().out.strip() == __version__


def test_invalid_config_details_and_paths_are_redacted(capfd, tmp_path):
    path = tmp_path / "private-input-marker.json"
    path.write_text('{"private-token-marker":"not-a-real-token", "schema_version":99}')
    result = invoke_json(capfd, ["validate", "--config", path], expected=65)
    exported = canonical_json(result)
    assert "private-input-marker" not in exported and "private-token-marker" not in exported
    assert "not-a-real-token" not in exported
    assert result["error"] == "invalid-or-unverified"

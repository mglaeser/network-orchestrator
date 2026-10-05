"""Public extraction commands cannot mutate through declaration or privilege."""

from __future__ import annotations

import io
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from netorch import apple_runtime, bonjour_owner, cli, pf_owner, workloads
from netorch.codec import canonical_bytes, strict_loads
from netorch.state import Intent, intent_from_dict, intent_to_dict
from netorch.storage import Store
from netorch.workflow_gate import (
    NOT_QUALIFIED,
    StageNotQualified,
    require_mutation_qualified,
    require_request_qualified,
)


def must_not_call(*_args: Any, **_kwargs: Any) -> Any:
    pytest.fail("denied public command reached state, configuration or a native operation")


@pytest.mark.parametrize("privilege", [0, 501])
def test_no_declared_flag_environment_or_privilege_qualifies_mutation(monkeypatch, privilege):
    monkeypatch.setenv("NETORCH_QUALIFIED", "true")
    monkeypatch.setenv("NETORCH_ALLOW_MUTATION", "1")
    monkeypatch.setattr(pf_owner.os, "geteuid", lambda: privilege)
    with pytest.raises(StageNotQualified) as caught:
        require_mutation_qualified("owner-execution")
    assert caught.value.to_dict()["error"] == "stage-not-qualified"
    assert "read-only" in str(caught.value)


@pytest.mark.parametrize(
    "provider,payload",
    [
        ("runtime", {"operation": "observe"}),
        ("bonjour", {"operation": "observe"}),
        ("runtime", {"operation": "reconcile", "action": "withdraw"}),
        ("runtime", {"operation": "reconcile", "action": "drain"}),
        ("bonjour", {"operation": "reconcile-discovery", "active": False}),
    ],
)
def test_request_gate_preserves_observation_and_negative_authority(provider, payload):
    # Passing the stage classifier is not admission: endpoint validators still
    # reject these incomplete envelopes before exercising their native owners.
    assert require_request_qualified(provider, payload) is None


@pytest.mark.parametrize(
    "provider,payload",
    [
        ("runtime", {"operation": "reconcile", "action": "activate"}),
        ("runtime", {"operation": "reconcile", "action": []}),
        ("bonjour", {"operation": "reconcile-discovery", "active": True}),
        ("bonjour", {"operation": "reconcile-discovery", "active": 0}),
        ("bonjour", {"operation": "reconcile-discovery", "active": None}),
        ("bonjour", {"operation": "publish", "active": False}),
        ("unregistered", {"operation": "observe"}),
        ("runtime", {"operation": "start", "qualified": True}),
        ("runtime", None),
        ("bonjour", []),
    ],
)
def test_future_or_malformed_requests_cannot_bypass_stage(provider, payload):
    with pytest.raises(StageNotQualified):
        require_request_qualified(provider, payload)


CLI_DENIED = [
    [
        "admit",
        "--config",
        "missing",
        "--profile",
        "dns",
        "--expected-digest",
        "0" * 64,
        "--approved-by",
        "operator",
    ],
    ["init-state"],
    ["resume"],
    ["release", "--operation", "maintenance", "--holder", "operator"],
    ["acknowledge-journal", "--plan-digest", "0" * 64],
    [
        "reconcile",
        "--config",
        "missing",
        "--bindings",
        "missing",
        "--admissions",
        "missing",
        "--execute-user-owners",
    ],
]


@pytest.mark.parametrize("arguments", CLI_DENIED)
def test_public_cli_denial_precedes_input_state_and_owner_calls(
    arguments, monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(cli, "load_config", must_not_call)
    monkeypatch.setattr(cli, "load_bindings", must_not_call)
    monkeypatch.setattr(cli, "execute", must_not_call)
    monkeypatch.setattr(cli, "Store", must_not_call)
    state = tmp_path / "not-created"
    assert cli.main([*arguments, "--state-dir", str(state)]) == NOT_QUALIFIED
    output = capsys.readouterr()
    assert strict_loads(output.out)["error"] == "stage-not-qualified"
    assert not output.err and not state.exists()


@pytest.mark.parametrize("operation", ["install-user", "install-root", "recover", "rollback"])
def test_deployment_denial_precedes_bundle_reads_or_native_install(
    operation, monkeypatch, tmp_path, capsys
):
    for name in ("install_bundle", "recover_install", "rollback_install", "validate_bundle"):
        monkeypatch.setattr(cli, name, must_not_call)
    target = tmp_path / "absent"
    arguments = ["deploy", operation, "--expected-digest", "0" * 64]
    if operation.startswith("install"):
        arguments += ["--bundle", str(target)]
    else:
        arguments += ["--state-dir", str(target), "--scope", "root"]
    assert cli.main(arguments) == NOT_QUALIFIED
    assert strict_loads(capsys.readouterr().out)["capability"] == "deployment-mutation"
    assert not target.exists()


@pytest.mark.parametrize(
    "arguments",
    [
        ["reconcile"],
        ["resume"],
        ["acknowledge-journal"],
        ["release", "--operation", "maintenance", "--holder", "operator"],
        ["admit", "--profile", "dns", "--expected-digest", "0" * 64],
        ["install", "--policy", "missing", "--settings", "missing", "--backend", "missing"],
    ],
)
def test_privileged_cli_denial_precedes_platform_code_acl_and_state_checks(
    arguments, monkeypatch, tmp_path, capsys
):
    for name in ("protected_code", "protected_ancestors", "Store", "run", "ShellBackend"):
        monkeypatch.setattr(pf_owner, name, must_not_call)
    monkeypatch.setattr(pf_owner.os, "geteuid", must_not_call)
    target = tmp_path / "absent"
    assert pf_owner.main([*arguments, "--root-dir", str(target)]) == NOT_QUALIFIED
    assert strict_loads(capsys.readouterr().err)["error"] == "stage-not-qualified"
    assert not target.exists()


@pytest.mark.parametrize("command", ["serve", "publisher"])
def test_bonjour_publication_cli_cannot_spawn_or_initialize_state(
    command, monkeypatch, tmp_path, capsys
):
    for name in ("load_settings", "Store", "serve", "publisher_loop"):
        monkeypatch.setattr(bonjour_owner, name, must_not_call)
    target = tmp_path / "absent"
    assert bonjour_owner.main(["--settings", str(target), command]) == NOT_QUALIFIED
    assert strict_loads(capsys.readouterr().err)["capability"] == "discovery-publication"
    assert not target.exists()


@pytest.mark.parametrize(
    "module,command,payload",
    [
        (apple_runtime, "request", {"operation": "reconcile", "action": "activate"}),
        (bonjour_owner, "endpoint", {"operation": "reconcile-discovery", "active": True}),
    ],
)
def test_endpoint_activation_is_denied_before_native_or_state_even_with_declared_qualification(
    module, command, payload, monkeypatch, tmp_path, capsys
):
    payload["qualified"] = True
    for name in ("load_settings", "load_config", "Store"):
        monkeypatch.setattr(module, name, must_not_call)
    monkeypatch.setattr(module.sys, "stdin", io.TextIOWrapper(io.BytesIO(canonical_bytes(payload))))
    target = tmp_path / "absent"
    assert module.main(["--settings", str(target), command]) == NOT_QUALIFIED
    assert strict_loads(capsys.readouterr().err)["error"] == "stage-not-qualified"
    assert not target.exists()


def test_runtime_recovery_denied_before_inventory_or_service_start(monkeypatch, tmp_path, capsys):
    for name in ("load_settings", "observe_runtime", "recover_service", "run"):
        monkeypatch.setattr(apple_runtime, name, must_not_call)
    assert (
        apple_runtime.main(["--settings", str(tmp_path / "missing"), "start", "--service", "media"])
        == NOT_QUALIFIED
    )
    assert strict_loads(capsys.readouterr().err)["capability"] == "workload-recovery"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "arguments",
    [
        ["provision", "--expected-digest", "0" * 64, "--start-initial"],
        ["acknowledge", "--expected-digest", "0" * 64, "--holder", "operator", "--phase", "failed"],
    ],
)
def test_workload_provision_and_release_denied_before_recipe_state_or_native_calls(
    arguments, monkeypatch, tmp_path, capsys
):
    for name in ("load_settings", "provision_workloads", "acknowledge_workload_operation", "run"):
        monkeypatch.setattr(workloads, name, must_not_call)
    assert workloads.main(["--settings", str(tmp_path / "missing"), *arguments]) == NOT_QUALIFIED
    assert strict_loads(capsys.readouterr().err)["capability"] == "workload-provisioning"
    assert not list(tmp_path.iterdir())


def test_public_pause_and_suspension_preserve_other_holders(tmp_path, capsys):
    store = Store(tmp_path / "state")
    store.write("intent.json", intent_to_dict(Intent().suspend("restore", "existing")))
    assert cli.main(["pause", "--state-dir", str(store.directory)]) == 0
    capsys.readouterr()
    assert (
        cli.main(
            [
                "suspend",
                "--state-dir",
                str(store.directory),
                "--operation",
                "maintenance",
                "--holder",
                "current",
            ]
        )
        == 0
    )
    actual = intent_from_dict(store.read("intent.json"))
    assert actual.operator_paused
    assert actual.suspensions == {"restore": "existing", "maintenance": "current"}


def test_preview_with_missing_state_does_not_initialize_or_call_execution(
    tmp_path, monkeypatch, capsys
):
    from tests.test_cli import snapshot_bindings

    config_path = Path(__file__).resolve().parents[1] / "examples/network.json"
    config = cli.load_config(config_path)
    from netorch.mock import mock_admissions
    from netorch.state import admissions_to_dict

    inputs = (config, config_path)
    bindings = snapshot_bindings(inputs, tmp_path)
    admissions = tmp_path / "admissions.json"
    admissions.write_bytes(canonical_bytes(admissions_to_dict(mock_admissions(config))))
    monkeypatch.setattr(cli, "Store", must_not_call)
    monkeypatch.setattr(cli, "execute", must_not_call)
    state = tmp_path / "missing-state"
    assert (
        cli.main(
            [
                "reconcile",
                "--config",
                str(config_path),
                "--bindings",
                str(bindings),
                "--admissions",
                str(admissions),
                "--state-dir",
                str(state),
            ]
        )
        == 0
    )
    assert strict_loads(capsys.readouterr().out)["execution"] == "not-requested"
    assert not state.exists()


def test_root_scoped_withdrawal_still_reaches_existing_owner_without_gate_override(
    monkeypatch, tmp_path, capsys
):
    calls = []
    root = object()
    monkeypatch.setattr(pf_owner.sys, "platform", "darwin")
    monkeypatch.setattr(pf_owner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(pf_owner, "protected_code", lambda *_args: None)
    monkeypatch.setattr(pf_owner, "protected_ancestors", lambda *_args: None)
    monkeypatch.setattr(pf_owner, "Store", lambda _path: root)

    def withdrawal(actual_root, backend, **kwargs):
        calls.append((actual_root, backend, kwargs))
        return {"withdrawn": True}

    monkeypatch.setattr(pf_owner, "withdraw", withdrawal)
    assert (
        pf_owner.main(
            [
                "withdraw",
                "--root-dir",
                str(tmp_path),
                "--operation",
                "maintenance",
                "--holder",
                "existing-holder",
            ]
        )
        == 0
    )
    assert calls == [
        (root, pf_owner.ShellBackend, {"operation": "maintenance", "holder": "existing-holder"})
    ]
    assert strict_loads(capsys.readouterr().out)["withdrawn"] is True


@pytest.mark.parametrize("command", ["pause", "suspend"])
def test_root_negative_intent_preserves_existing_state_without_gate_override(
    command, monkeypatch, tmp_path, capsys
):
    values = {"operator-intent.json": intent_to_dict(Intent().suspend("restore", "other"))}
    fake = SimpleNamespace(lock=nullcontext, read=values.__getitem__, write=values.__setitem__)
    monkeypatch.setattr(pf_owner.sys, "platform", "darwin")
    monkeypatch.setattr(pf_owner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(pf_owner, "protected_code", lambda *_args: None)
    monkeypatch.setattr(pf_owner, "protected_ancestors", lambda *_args: None)
    monkeypatch.setattr(pf_owner, "Store", lambda _path: fake)
    arguments = [command, "--root-dir", str(tmp_path)]
    if command == "suspend":
        arguments += ["--operation", "maintenance", "--holder", "current"]
    assert pf_owner.main(arguments) == 0
    result = intent_from_dict(values["operator-intent.json"])
    assert result.suspensions["restore"] == "other"
    assert result.operator_paused if command == "pause" else result.suspensions["maintenance"]
    assert strict_loads(capsys.readouterr().out)["schema_version"] == 1


def test_bonjour_read_only_health_does_not_create_missing_state(monkeypatch, tmp_path, capsys):
    state = tmp_path / "state"
    monkeypatch.setattr(bonjour_owner.os, "geteuid", lambda: 501)
    monkeypatch.setattr(
        bonjour_owner,
        "load_settings",
        lambda _path: SimpleNamespace(config=tmp_path / "policy", state_dir=state),
    )
    monkeypatch.setattr(bonjour_owner, "load_config", lambda _path: object())
    monkeypatch.setattr(bonjour_owner, "Store", must_not_call)
    assert bonjour_owner.main(["--settings", "unused", "health"]) == 65
    assert not state.exists()
    assert "complete scoped evidence" in capsys.readouterr().err

"""The retained literal-interface owners must not misread an extracted selector.

These are synthetic input-boundary and fault tests, not native adapter-change
qualification. The instance renderer may pass ``auto-wired`` to an existing
owner that implements it; the older retained network policy cannot do so.
"""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from netorch import apple_runtime, bonjour_owner, cli, pf_owner
from netorch.codec import canonical_bytes, strict_loads
from netorch.config import ConfigError, load_config, parse_config, to_dict, validate_config

EXAMPLE = Path(__file__).parents[1] / "examples/network.json"


@pytest.fixture
def reserved_policy(tmp_path):
    data = to_dict(load_config(EXAMPLE))
    data["scopes"][0]["interface"] = "auto-wired"
    path = tmp_path / "policy.json"
    path.write_bytes(canonical_bytes(data))
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("reader", [load_config, lambda path: parse_config(path.read_bytes())])
def test_reserved_selector_is_rejected_at_loaded_policy_boundary(reserved_policy, reader):
    with pytest.raises(ConfigError, match=r"auto-wired.*literal interface"):
        reader(reserved_policy)


def test_reserved_selector_is_rejected_in_constructed_policy():
    config = load_config(EXAMPLE)
    scope = replace(config.scopes[0], interface="auto-wired")
    with pytest.raises(ConfigError, match=r"auto-wired.*literal interface"):
        validate_config(replace(config, scopes=(scope,)))


@pytest.mark.parametrize("interface", ["en0", "en8", "bridge100"])
def test_existing_literal_interface_policy_remains_supported(interface):
    # This is syntax support, not evidence that any named interface is wired.
    config = load_config(EXAMPLE)
    scope = replace(config.scopes[0], interface=interface)
    literal = replace(config, scopes=(scope,))
    validate_config(literal)
    assert parse_config(canonical_bytes(to_dict(literal))) == literal


def forbidden(*args, **kwargs):
    pytest.fail("invalid selector reached an owner, a renderer or native operation")


@pytest.mark.parametrize("command", ["observe", "reconcile", "render-pf"])
def test_cli_rejects_selector_before_observation_render_or_state(
    reserved_policy, command, tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(cli, "load_bindings", forbidden)
    monkeypatch.setattr(cli, "render", forbidden)
    monkeypatch.setattr(cli, "strict_load", forbidden)
    monkeypatch.setattr(cli, "Store", forbidden)
    arguments = [command, "--config", str(reserved_policy)]
    if command == "render-pf":
        arguments += ["--snapshot", str(tmp_path / "unread-snapshot.json")]
    else:
        arguments += ["--bindings", str(tmp_path / "unread-bindings.json")]
        if command == "reconcile":
            arguments += [
                "--state-dir",
                str(tmp_path / "never-created"),
                "--admissions",
                str(tmp_path / "unread-admissions.json"),
            ]
    assert cli.main(arguments) == 65
    captured = capsys.readouterr()
    assert strict_loads(captured.out)["error"] == "invalid-or-unverified"
    assert not captured.err
    assert not (tmp_path / "never-created").exists()


def test_pf_install_refuses_selector_before_state_or_backend(
    reserved_policy, tmp_path, monkeypatch
):
    # Isolate just the policy boundary. No production ownership or platform
    # gate is bypassed; install is called directly with a temporary input.
    monkeypatch.setattr(pf_owner, "protected_ancestors", lambda _path: None)
    monkeypatch.setattr(pf_owner, "Store", forbidden)
    monkeypatch.setattr(pf_owner, "run", forbidden)
    target = tmp_path / "never-created"
    with pytest.raises(ConfigError, match=r"auto-wired.*literal interface"):
        pf_owner.install(
            target, reserved_policy, tmp_path / "unread-settings", tmp_path / "unread-backend"
        )
    assert not target.exists()


def test_runtime_observe_refuses_selector_before_native_collection(
    reserved_policy, monkeypatch, capsys
):
    # Settings parsing is independent of the network policy being tested.
    monkeypatch.setattr(
        apple_runtime, "load_settings", lambda _path: SimpleNamespace(policy=reserved_policy)
    )
    monkeypatch.setattr(apple_runtime, "observe_runtime", forbidden)
    monkeypatch.setattr(apple_runtime, "run", forbidden)
    assert apple_runtime.main(["--settings", "unused", "observe"]) == apple_runtime.UNKNOWN
    captured = capsys.readouterr()
    assert not captured.out
    assert "runtime-evidence-or-authority-incomplete" in captured.err


def test_bonjour_health_refuses_selector_before_state_or_discovery(
    reserved_policy, tmp_path, monkeypatch, capsys
):
    settings = {
        "schema_version": 1,
        "owner": "bonjour-manager",
        "config": str(reserved_policy),
        "bindings": str(tmp_path / "unread-bindings"),
        "admissions": str(tmp_path / "unread-admissions"),
        "intent": str(tmp_path / "unread-intent"),
        "state_dir": str(tmp_path / "never-created"),
        "scopes": [
            {"id": "wired-lan", "guest_interface": "bridge-test", "guest_ipv4": "198.51.100.1"}
        ],
    }
    path = tmp_path / "bonjour.json"
    path.write_bytes(canonical_bytes(settings))
    path.chmod(0o600)
    with pytest.raises(ConfigError, match=r"auto-wired.*literal interface"):
        bonjour_owner.load_settings(path)
    monkeypatch.setattr(bonjour_owner, "Store", forbidden)
    monkeypatch.setattr(bonjour_owner, "interface_index", forbidden)
    monkeypatch.setattr(bonjour_owner, "health", forbidden)
    assert bonjour_owner.main(["--settings", str(path), "health"]) == 65
    captured = capsys.readouterr()
    assert not captured.out
    assert "complete scoped evidence" in captured.err
    assert not (tmp_path / "never-created").exists()

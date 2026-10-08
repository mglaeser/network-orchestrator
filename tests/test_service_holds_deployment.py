"""Holds survive installation, rollback and recovery, in the user's file and in root's.

The portable installation lab of the deployment tests: fake launchd, Monit and
packet-filter effects in a disposable directory, no root command.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

import netorch.pf_owner as forwarding
from netorch.deployment import install_bundle, recover_install, rollback_install
from netorch.deployment_config import DeploymentError
from netorch.model import Config
from netorch.state import Intent, intent_from_dict, intent_to_dict
from netorch.storage import Store
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest
from tests.test_full_deployment import (
    IntegratedTools,
    root_pass,
    runtime_observation,
    setup_forwarding,
)
from tests.test_service_holds import accepted_by_the_release_before_holds, holding

__all__ = ["config", "fake_platform", "manifest"]

HOLDS = {"camera": {"maintenance": "manager"}, "resolver": {"backup": "backup-owner"}}


def two_holds(intent: Intent) -> Intent:
    return holding(holding(intent, "camera"), "resolver", "backup", "backup-owner")


def test_install_rollback_and_recovery_preserve_holds(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    state_dir = Path(manifest["user"]["state_directory"])
    state = Store(state_dir)
    state.write(
        "intent.json", intent_to_dict(two_holds(Intent().pause().suspend("backup", "other-holder")))
    )
    first, old = make_bundle(tmp_path, manifest, config, "old")
    tools = FakeTools()
    assert (
        install_bundle(first, "user", expected_digest=old["bundle_digest"], runner=tools)["phase"]
        == "committed"
    )
    installed = intent_from_dict(state.read("intent.json"))
    assert installed.operator_paused and installed.suspensions == {"backup": "other-holder"}
    assert installed.holds == HOLDS
    # A failed upgrade keeps them beside its own suspension, and so does its recovery.
    changed = copy.deepcopy(manifest)
    changed["jobs"][0]["interval_seconds"] = 15
    second, new = make_bundle(tmp_path, changed, config, "new")
    tools.fail = "bootstrap"
    with pytest.raises(DeploymentError):
        install_bundle(second, "user", expected_digest=new["bundle_digest"], runner=tools)
    interrupted = intent_from_dict(state.read("intent.json"))
    assert interrupted.holds == HOLDS
    assert interrupted.suspensions["installation"] == new["bundle_digest"]
    tools.fail = None
    recovered = recover_install(
        state_dir, "user", expected_failed_digest=new["bundle_digest"], runner=tools
    )
    assert recovered["release_id"] == old["release_id"]
    after_recovery = intent_from_dict(state.read("intent.json"))
    assert after_recovery.holds == HOLDS
    assert after_recovery.suspensions == {"backup": "other-holder"}
    # An upgrade and its explicit rollback keep the holds that exist at that moment.
    changed["jobs"][0]["interval_seconds"] = 20
    third, newer = make_bundle(tmp_path, changed, config, "newer")
    install_bundle(third, "user", expected_digest=newer["bundle_digest"], runner=tools)
    current = intent_from_dict(state.read("intent.json")).unhold(
        "resolver", "backup", "backup-owner"
    )
    state.write("intent.json", intent_to_dict(holding(current, "web-proxy")))
    result = rollback_install(
        state_dir, "user", expected_current_digest=newer["bundle_digest"], runner=tools
    )
    assert result["release_id"] == old["release_id"] and result["preserved_intent"]
    final = intent_from_dict(state.read("intent.json"))
    assert final.operator_paused and final.suspensions == {"backup": "other-holder"}
    assert final.holds == {
        "camera": {"maintenance": "manager"},
        "web-proxy": {"maintenance": "manager"},
    }
    # The stored file is one that a release without holds reads as damage, and
    # such a release refuses to install over damaged intent.
    assert not accepted_by_the_release_before_holds(state.read("intent.json"))


def test_a_failed_first_installation_and_its_recovery_keep_holds(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    state_dir = Path(manifest["user"]["state_directory"])
    state = Store(state_dir)
    state.write("intent.json", intent_to_dict(two_holds(Intent())))
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    with pytest.raises(DeploymentError):
        install_bundle(
            bundle, "user", expected_digest=metadata["bundle_digest"], runner=FakeTools("bootstrap")
        )
    assert intent_from_dict(state.read("intent.json")).holds == HOLDS
    recover_install(
        state_dir, "user", expected_failed_digest=metadata["bundle_digest"], runner=FakeTools()
    )
    recovered = intent_from_dict(state.read("intent.json"))
    # Neither a pause nor a release was manufactured for an operator who had none.
    assert recovered.holds == HOLDS and not recovered.suspensions
    assert not recovered.operator_paused


def test_root_installation_and_rollback_keep_roots_own_holds(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Config,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup_forwarding(manifest, monkeypatch)
    first, original = make_bundle(tmp_path, manifest, config, "first")
    tools = IntegratedTools()
    install_bundle(first, "user", expected_digest=original["bundle_digest"], runner=tools)
    install_bundle(first, "root", expected_digest=original["bundle_digest"], runner=tools)
    root = Store(Path(manifest["forwarding"]["directory"]))
    user = Store(Path(manifest["user"]["state_directory"]))
    for profile in config.profiles:
        if config.profile_owner(profile).id == "site-forwarding":
            forwarding.admit(root, profile.id, acknowledge_bounded_risk=True, now=99)
    held = holding(Intent(), "resolver", "maintenance", "administrator")
    root.write("operator-intent.json", intent_to_dict(held))
    user.write("intent.json", intent_to_dict(holding(Intent(), "camera")))
    observation = runtime_observation(config)
    assert root_pass(root, tools.backend, observation)["pending"] == ["dns-tcp", "dns-udp"]
    assert "netorch:media-udp" in tools.backend.rules
    altered = copy.deepcopy(manifest)
    altered["jobs"][1]["log_directory"] += "-v2"
    second, newer = make_bundle(tmp_path, altered, config, "second")
    install_bundle(second, "root", expected_digest=newer["bundle_digest"], runner=tools)
    assert intent_from_dict(root.read("operator-intent.json")).holds == held.holds
    assert not tools.backend.rules
    rollback_install(
        Path(manifest["root"]["state_directory"]),
        "root",
        expected_current_digest=newer["bundle_digest"],
        runner=tools,
    )
    kept = intent_from_dict(root.read("operator-intent.json"))
    assert kept.holds == held.holds and not kept.suspensions and not kept.operator_paused
    assert intent_from_dict(user.read("intent.json")).holds == {
        "camera": {"maintenance": "manager"}
    }
    # The restored owner still holds that one service and serves the others.
    assert root_pass(root, tools.backend, observation)["pending"] == ["dns-tcp", "dns-udp"]
    assert "netorch:media-udp" in tools.backend.rules
    assert "netorch:dns-udp" not in tools.backend.rules

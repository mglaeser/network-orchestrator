"""Operator CLI wiring against actual disposable deployment and owner models."""

from __future__ import annotations

import copy
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import netorch.cli as cli
import netorch.deployment as deployment
from netorch.codec import canonical_bytes, strict_loads
from netorch.config import load_config, profile_digest, to_dict
from netorch.executor import Execution
from netorch.mock import initial_snapshot, mock_admissions
from netorch.state import (
    Intent,
    admissions_to_dict,
    intent_from_dict,
    intent_to_dict,
)
from netorch.storage import Store
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest

__all__ = ["config", "fake_platform", "manifest"]


def invoke(capsys: pytest.CaptureFixture[str], argv: list[Any], code: int = 0) -> dict[str, Any]:
    assert cli.main([str(item) for item in argv]) == code
    captured = capsys.readouterr()
    assert not captured.err
    return strict_loads(captured.out)


@pytest.mark.parametrize("command", ["render", "build"])
def test_cli_build_validate_verify_and_plan(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "deployment.json"
    source.write_bytes(canonical_bytes(manifest))
    assert invoke(capsys, ["deploy", "validate", "--manifest", source])["valid"] is True
    bundle = tmp_path / "bundle"
    policy = Path(__file__).resolve().parents[1] / "examples/network.json"
    result = invoke(
        capsys, ["deploy", command, "--manifest", source, "--config", policy, "--output", bundle]
    )
    verified = invoke(
        capsys,
        ["deploy", "verify", "--bundle", bundle, "--expected-digest", result["bundle_digest"]],
    )
    assert verified["release_id"] == result["release_id"]
    assert (
        invoke(capsys, ["deploy", "verify", "--bundle", bundle])["bundle_digest"]
        == result["bundle_digest"]
    )
    for scope in ("user", "root"):
        planned = invoke(capsys, ["deploy", "plan", "--bundle", bundle, "--scope", scope])
        assert planned["scope"] == scope and planned["container_recreation"] is False
    prepared = tmp_path / "prepared"
    assert (
        invoke(capsys, ["deploy", "prepare-root", "--bundle", bundle, "--output", prepared])[
            "expected_digest"
        ]
        == result["bundle_digest"]
    )
    assert not Path(manifest["user"]["directory"]).exists()
    assert not Path(manifest["root"]["directory"]).exists()


@pytest.mark.parametrize("scope", ["user", "root"])
def test_cli_install_and_rollback_exact_keywords(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tools = FakeTools()
    monkeypatch.setattr(
        cli,
        "install_bundle",
        lambda bundle, scope, **kwargs: deployment.install_bundle(
            bundle, scope, runner=tools, **kwargs
        ),
    )
    monkeypatch.setattr(
        cli,
        "rollback_install",
        lambda state, scope, **kwargs: deployment.rollback_install(
            state, scope, runner=tools, **kwargs
        ),
    )
    first, old = make_bundle(tmp_path, manifest, config, "first")
    assert (
        invoke(
            capsys,
            [
                "deploy",
                f"install-{scope}",
                "--bundle",
                first,
                "--expected-digest",
                old["bundle_digest"],
            ],
        )["phase"]
        == "committed"
    )
    newer = copy.deepcopy(manifest)
    if scope == "user":
        newer["jobs"][0]["interval_seconds"] = 15
    else:
        newer["jobs"][1]["log_directory"] += "-v2"
    second, new = make_bundle(tmp_path, newer, config, "second")
    assert (
        invoke(
            capsys,
            [
                "deploy",
                f"install-{scope}",
                "--bundle",
                second,
                "--expected-digest",
                new["bundle_digest"],
            ],
        )["phase"]
        == "committed"
    )
    result = invoke(
        capsys,
        [
            "deploy",
            "rollback",
            "--state-dir",
            manifest[scope]["state_directory"],
            "--scope",
            scope,
            "--expected-digest",
            new["bundle_digest"],
        ],
    )
    assert result["release_id"] == old["release_id"]
    assert result["preserved_intent"] is True


def test_cli_failed_install_recovers_exact_failed_digest(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tools = FakeTools("bootstrap")
    monkeypatch.setattr(
        cli,
        "install_bundle",
        lambda bundle, scope, **kwargs: deployment.install_bundle(
            bundle, scope, runner=tools, **kwargs
        ),
    )
    monkeypatch.setattr(
        cli,
        "recover_install",
        lambda state, scope, **kwargs: deployment.recover_install(
            state, scope, runner=tools, **kwargs
        ),
    )
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    result = invoke(
        capsys,
        [
            "deploy",
            "install-user",
            "--bundle",
            bundle,
            "--expected-digest",
            metadata["bundle_digest"],
        ],
        65,
    )
    assert result["error"] == "invalid-or-unverified"
    tools.fail = None
    result = invoke(
        capsys,
        [
            "deploy",
            "recover",
            "--state-dir",
            manifest["user"]["state_directory"],
            "--scope",
            "user",
            "--expected-digest",
            metadata["bundle_digest"],
        ],
    )
    assert result["phase"] == "rolled-back" and result["preserved_intent"] is True


@pytest.mark.parametrize("command", ["verify", "install-user", "install-root"])
def test_cli_rejects_unreviewed_digest_before_platform(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle, _ = make_bundle(tmp_path, manifest, config)
    result = invoke(
        capsys, ["deploy", command, "--bundle", bundle, "--expected-digest", "0" * 64], 65
    )
    assert result["error"] == "invalid-or-unverified"
    assert str(tmp_path) not in str(result)


@pytest.fixture
def policy() -> Path:
    return Path(__file__).resolve().parents[1] / "examples/network.json"


def test_user_admission_exact_review_preserves_pause(
    tmp_path: Path, policy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    if os.geteuid() == 0:
        pytest.skip("user admission intentionally refuses root")
    config = load_config(policy)
    review = invoke(capsys, ["review-admission", "--config", policy, "--profile", "camera-web"])
    assert review["digest"] == profile_digest(config, config.profile("camera-web"))
    assert review["root_admission_required"] is False
    store = Store(tmp_path / "state")
    store.write("intent.json", intent_to_dict(Intent().pause().suspend("migration", "other")))
    args = [
        "admit",
        "--config",
        policy,
        "--profile",
        "camera-web",
        "--state-dir",
        store.directory,
        "--approved-by",
        "reviewer",
        "--expected-digest",
        review["digest"],
    ]
    assert invoke(capsys, args)["resumed"] is False
    assert intent_from_dict(store.read("intent.json")).operator_paused
    assert intent_from_dict(store.read("intent.json")).suspensions == {"migration": "other"}
    before = (store.directory / "admissions.json").read_bytes()
    args[-1] = "0" * 64
    assert invoke(capsys, args, 65)["error"] == "invalid-or-unverified"
    assert (store.directory / "admissions.json").read_bytes() == before


def test_user_admission_never_admits_root_profile(
    tmp_path: Path, policy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    review = invoke(capsys, ["review-admission", "--config", policy, "--profile", "media-udp"])
    assert review["root_admission_required"] is True
    result = invoke(
        capsys,
        [
            "admit",
            "--config",
            policy,
            "--profile",
            "media-udp",
            "--state-dir",
            tmp_path / "state",
            "--approved-by",
            "reviewer",
            "--expected-digest",
            review["digest"],
            "--ack-bounded-risk",
        ],
        65,
    )
    assert result["error"] == "invalid-or-unverified"
    assert not (tmp_path / "state").exists()


def test_user_bounded_admission_requires_risk_ack(
    tmp_path: Path, policy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    if os.geteuid() == 0:
        pytest.skip("user admission intentionally refuses root")
    value = to_dict(load_config(policy))
    next(item for item in value["profiles"] if item["id"] == "camera-web")["safety"] = {
        "kind": "bounded",
        "max_age_seconds": 30,
        "unknown_limit": 1,
        "statement": "Explicit bounded residual publication risk.",
    }
    changed = tmp_path / "bounded.json"
    changed.write_bytes(canonical_bytes(value))
    review = invoke(capsys, ["review-admission", "--config", changed, "--profile", "camera-web"])
    args = [
        "admit",
        "--config",
        changed,
        "--profile",
        "camera-web",
        "--state-dir",
        tmp_path / "state",
        "--approved-by",
        "reviewer",
        "--expected-digest",
        review["digest"],
    ]
    invoke(capsys, args, 65)
    assert not (tmp_path / "state").exists()
    assert invoke(capsys, [*args, "--ack-bounded-risk"])["admitted"] == "camera-web"


def test_corrupt_admissions_never_overwritten(
    tmp_path: Path, policy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    if os.geteuid() == 0:
        pytest.skip("user admission intentionally refuses root")
    store = Store(tmp_path / "state")
    store.write("admissions.json", {"schema_version": 999})
    before = (store.directory / "admissions.json").read_bytes()
    review = invoke(capsys, ["review-admission", "--config", policy, "--profile", "camera-web"])
    invoke(
        capsys,
        [
            "admit",
            "--config",
            policy,
            "--profile",
            "camera-web",
            "--state-dir",
            store.directory,
            "--approved-by",
            "reviewer",
            "--expected-digest",
            review["digest"],
        ],
        65,
    )
    assert (store.directory / "admissions.json").read_bytes() == before


def test_reconcile_quiet_unchanged_ignores_time_only_then_reports_pause(
    tmp_path: Path,
    policy: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = load_config(policy)
    store = Store(tmp_path / "state")
    store.write("intent.json", intent_to_dict(Intent()))
    admissions = tmp_path / "admissions.json"
    admissions.write_bytes(
        canonical_bytes(
            admissions_to_dict(
                {
                    key: value
                    for key, value in mock_admissions(config).items()
                    if config.profile_owner(config.profile(key)).privilege == "user"
                }
            )
        )
    )
    snapshot = initial_snapshot(config)
    snapshots = [snapshot]
    monkeypatch.setattr(cli, "load_bindings", lambda config, path: {})
    monkeypatch.setattr(cli, "observe", lambda config, clients: snapshots[-1])
    monkeypatch.setattr(cli, "execute", lambda *args, **kwargs: Execution("committed", 0, ()))
    monkeypatch.setattr(cli.time, "time", lambda: snapshot.observed_at)
    args = [
        "reconcile",
        "--config",
        policy,
        "--bindings",
        tmp_path / "unused-binding",
        "--admissions",
        admissions,
        "--state-dir",
        store.directory,
        "--execute-user-owners",
        "--quiet-unchanged",
    ]
    first = invoke(capsys, args)
    assert first["phase"] == "committed"
    before = (store.directory / "status.json").stat().st_mtime_ns
    snapshots.append(
        replace(
            snapshot,
            observed_at=snapshot.observed_at + 1,
            services={
                key: replace(item, observed_at=item.observed_at + 1)
                for key, item in snapshot.services.items()
            },
        )
    )
    assert cli.main([str(arg) for arg in args]) == 0
    assert capsys.readouterr().out == ""
    assert (store.directory / "status.json").stat().st_mtime_ns == before
    store.write("intent.json", intent_to_dict(Intent().pause()))
    assert invoke(capsys, args)["intent"]["operator_paused"] is True

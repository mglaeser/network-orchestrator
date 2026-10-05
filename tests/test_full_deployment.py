"""Seven-workload deployment in a disposable filesystem with fake native effects.

This composes the real bundle installer, independent PF installer/admission and
pull reconciler. Only launchd/PF platform effects and runtime observations are
fakes. It establishes the public integration contract, never hardware acceptance.
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import netorch.pf_owner as forwarding
from netorch.codec import canonical_bytes
from netorch.config import parse_config, profile_digest, to_dict
from netorch.deployment import install_bundle, recover_install, rollback_install
from netorch.deployment_config import DeploymentError
from netorch.mock import simulate
from netorch.model import Config
from netorch.process import Result
from netorch.state import Intent, Observation, Snapshot, intent_from_dict, intent_to_dict
from netorch.storage import Store
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest
from tests.test_pf_owner import FakeBackend

__all__ = ["config", "fake_platform", "manifest"]


def seven_workloads(config: Config) -> Config:
    value = to_dict(config)
    for index, identifier in enumerate(("dashboard", "inference", "device-bridge")):
        value["services"].append(
            {"id": identifier, "owner": "camera-manager", "contract_sha256": str(index + 1) * 64}
        )
        profile = copy.deepcopy(value["profiles"][-1])
        profile.update(
            id=f"{identifier}-web",
            service=identifier,
            ports={"first": 10000 + index, "last": 10000 + index},
            target_ports={"first": 8080, "last": 8080},
        )
        value["profiles"].append(profile)
    return parse_config(canonical_bytes(value))


def runtime_observation(config: Config) -> Snapshot:
    services = {
        service.id: Observation(
            "present",
            "verified",
            100,
            "instance-1",
            {
                "ipv4": f"198.51.100.{10 + index}",
                "mac": "02:00:00:00:00:01",
                "contract_sha256": service.contract_sha256,
            },
        )
        for index, service in enumerate(config.services)
    }
    publications = {
        profile.id: Observation(
            "present",
            "verified",
            100,
            "instance-1",
            {
                "target_ipv4": services[profile.service].data["ipv4"],
                "target_generation": "instance-1",
                "network_generation": "network-1",
                "policy_digest": profile_digest(config, profile),
                "states": (),
            },
        )
        for profile in config.profiles
        if profile.kind == "publication"
    }
    return Snapshot(100, "network-1", services, publications)


class IntegratedTools(FakeTools):
    """Dispatch the actual root installer in the lab; all native effects stay fake."""

    def __init__(self) -> None:
        super().__init__()
        self.backend = FakeBackend()

    def __call__(self, argv: tuple[str, ...]) -> Result:
        if (
            "netorch.pf_owner" in argv
            and self.fail is None
            and any(operation in argv for operation in ("suspend", "withdraw", "release"))
        ):
            self.calls.append(argv)
            store = Store(Path(argv[argv.index("--root-dir") + 1]))
            holder = argv[argv.index("--holder") + 1]
            if "withdraw" in argv:
                forwarding.withdraw(
                    store,
                    lambda root, settings: self.backend,
                    operation="installation",
                    holder=holder,
                )
            else:
                intent = intent_from_dict(store.read("operator-intent.json"))
                changed = (
                    intent.suspend("installation", holder)
                    if "suspend" in argv
                    else intent.release("installation", holder)
                )
                store.write("operator-intent.json", intent_to_dict(changed))
            return Result(0, b"", b"")
        if "netorch.pf_owner" in argv and "install" in argv and self.fail is None:
            self.calls.append(argv)
            forwarding.install(
                Path(argv[argv.index("--root-dir") + 1]),
                Path(argv[argv.index("--policy") + 1]),
                Path(argv[argv.index("--settings") + 1]),
                Path(argv[argv.index("--backend") + 1]),
            )
            return Result(0, b"", b"")
        return super().__call__(argv)


def setup_forwarding(manifest: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    backend = Path(manifest["forwarding"]["backend_source"])
    settings = forwarding.Installation(
        "site-forwarding",
        "com.apple/netorch.site-forwarding",
        {"schema_version": 1, "account": "example"},
        hashlib.sha256(backend.read_bytes()).hexdigest(),
        str(backend.parent / "report.json"),
        str(Path(manifest["user"]["state_directory"]) / "intent.json"),
    )
    source = Path(manifest["artifacts"][0]["source"])
    source.write_bytes(canonical_bytes(settings.to_dict()))
    manifest["artifacts"][0]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    # Trust/bootstrap checks have independent tests. This lab runs as the CI user.
    monkeypatch.setattr(forwarding, "protected_ancestors", lambda path, **kwargs: None)


def root_pass(root: Store, backend: FakeBackend, observation: Snapshot) -> dict[str, Any]:
    return forwarding.reconcile(
        root,
        lambda config, settings: observation,
        lambda store, settings: backend,
        now=lambda: 100,
        report=lambda settings, snapshot: None,
    )


def test_full_seven_workload_install_admission_upgrade_and_rollback(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Config,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = seven_workloads(config)
    setup_forwarding(manifest, monkeypatch)
    bundle, initial = make_bundle(tmp_path, manifest, config, "initial")
    tools = IntegratedTools()
    assert (
        install_bundle(bundle, "user", expected_digest=initial["bundle_digest"], runner=tools)[
            "phase"
        ]
        == "committed"
    )
    assert (
        install_bundle(bundle, "root", expected_digest=initial["bundle_digest"], runner=tools)[
            "phase"
        ]
        == "committed"
    )
    root = Store(Path(manifest["forwarding"]["directory"]))
    user = Store(Path(manifest["user"]["state_directory"]))
    assert root.read("admissions.json")["profiles"] == {}
    assert intent_from_dict(root.read("operator-intent.json")).operator_paused
    assert intent_from_dict(user.read("intent.json")).operator_paused
    assert len(root.read("policy.json")["services"]) == 7
    assert simulate(config)["all_verified"] is True
    monitrc = next(Path(manifest["user"]["directory"]).glob("releases/*/monit/monitrc")).read_text()
    assert "if status = 42 for 2 cycles then exec" in monitrc
    assert monitrc.count("then exec") == 1
    backend = tools.backend
    observation = runtime_observation(config)
    assert root_pass(root, backend, observation)["phase"] == "inhibited"
    assert not backend.rules
    # Explicitly model the separate administrator admission and resume decisions.
    for profile in config.profiles:
        if config.profile_owner(profile).id == "site-forwarding":
            forwarding.admit(root, profile.id, acknowledge_bounded_risk=True, now=99)
    approved = root.read("admissions.json")
    root.write("operator-intent.json", intent_to_dict(Intent()))
    user.write("intent.json", intent_to_dict(Intent()))
    assert root_pass(root, backend, observation)["phase"] == "committed"
    assert "static-port" in backend.rules
    changed_data = to_dict(config)
    changed_data["scopes"][0]["host_ipv4"] = "192.0.2.11"
    changed = parse_config(canonical_bytes(changed_data))
    newer_bundle, newer = make_bundle(tmp_path, manifest, changed, "newer")
    assert (
        install_bundle(newer_bundle, "root", expected_digest=newer["bundle_digest"], runner=tools)[
            "phase"
        ]
        == "committed"
    )
    assert root.read("admissions.json") == approved
    pending = root_pass(
        root, backend, replace(observation, profiles=runtime_observation(changed).profiles)
    )
    assert pending["phase"] == "inhibited" and len(pending["pending"]) == 4
    assert not backend.rules
    user.write(
        "intent.json", intent_to_dict(Intent().pause().suspend("external-maintenance", "operator"))
    )
    result = rollback_install(
        Path(manifest["root"]["state_directory"]),
        "root",
        expected_current_digest=newer["bundle_digest"],
        runner=tools,
    )
    assert result["release_id"] == initial["release_id"]
    assert root.read("admissions.json") == approved
    assert root.read("policy.json") == to_dict(config)
    user_intent = intent_from_dict(user.read("intent.json"))
    assert user_intent.operator_paused and user_intent.suspensions == {
        "external-maintenance": "operator"
    }
    assert root_pass(root, backend, observation)["phase"] == "inhibited"
    assert not backend.rules
    assert not any("resume" in argv or "admit" in argv for argv in tools.calls)


def test_full_failed_upgrade_recovers_original_release_without_unpausing(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Config,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = seven_workloads(config)
    setup_forwarding(manifest, monkeypatch)
    tools = IntegratedTools()
    first, original = make_bundle(tmp_path, manifest, config, "first")
    install_bundle(first, "user", expected_digest=original["bundle_digest"], runner=tools)
    install_bundle(first, "root", expected_digest=original["bundle_digest"], runner=tools)
    altered = copy.deepcopy(manifest)
    altered["jobs"][0]["interval_seconds"] = 15
    second, newer = make_bundle(tmp_path, altered, config, "second")
    tools.fail = "bootstrap"
    with pytest.raises(DeploymentError):
        install_bundle(second, "user", expected_digest=newer["bundle_digest"], runner=tools)
    tools.fail = None
    state = Store(Path(manifest["user"]["state_directory"]))
    assert "installation" in intent_from_dict(state.read("intent.json")).suspensions
    assert (
        recover_install(
            state.directory, "user", expected_failed_digest=newer["bundle_digest"], runner=tools
        )["release_id"]
        == original["release_id"]
    )
    assert intent_from_dict(state.read("intent.json")).operator_paused
    assert state.read("installation-receipt.json")["release_id"] == original["release_id"]
    assert (
        len(Store(Path(manifest["forwarding"]["directory"])).read("policy.json")["services"]) == 7
    )


@pytest.mark.parametrize("operator_paused", [True, False])
def test_failed_first_root_install_recovery_retains_negative_authority(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Config,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    operator_paused: bool,
) -> None:
    setup_forwarding(manifest, monkeypatch)
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    tools = IntegratedTools()
    tools.fail = "bootstrap"
    original = tools.__call__

    def fail_bootstrap_only(argv: tuple[str, ...]) -> Result:
        if "netorch.pf_owner" in argv:
            previous_failure = tools.fail
            tools.fail = None
            try:
                return original(argv)
            finally:
                tools.fail = previous_failure
        return original(argv)

    with pytest.raises(DeploymentError):
        install_bundle(
            bundle, "root", expected_digest=metadata["bundle_digest"], runner=fail_bootstrap_only
        )
    root = Store(Path(manifest["forwarding"]["directory"]))
    intent = intent_from_dict(root.read("operator-intent.json"))
    root.write(
        "operator-intent.json", intent_to_dict(replace(intent, operator_paused=operator_paused))
    )
    tools.fail = None
    recovered = recover_install(
        Path(manifest["root"]["state_directory"]),
        "root",
        expected_failed_digest=metadata["bundle_digest"],
        runner=tools,
    )
    final = intent_from_dict(root.read("operator-intent.json"))
    assert final.operator_paused is operator_paused
    assert recovered["root_gate_retained"] is not operator_paused
    assert ("installation" in final.suspensions) is not operator_paused
    assert not tools.backend.rules

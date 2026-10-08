"""Optional `recovery_repeat_cycles`: rendered only when set, invisible when absent.

The fixed manifest below has no site data. Its digest and its rendered Monit
bytes were computed before the setting existed and are pinned here, so the
tests that use them also pass on the tree without the setting. They exist to
show that it changes nothing for a manifest that does not use it.
"""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch.codec import canonical_bytes, digest
from netorch.deployment import install_bundle, validate_bundle
from netorch.deployment_config import DeploymentError, deployment_to_dict, parse_deployment
from netorch.storage import Store
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest

__all__ = ["config", "fake_platform", "manifest"]

RELEASE = Path("/operator/install/netorch/releases") / ("a" * 64)
DIGEST_BEFORE = "78b2c6a1e16bf5018d3ae386308f3b6daa3cb2e2ef330c7f875b8141d0a882a8"
MONITRC_SHA256_BEFORE = "9c1f03617061d19708195552fa4c2ba95395c92d9bd854d5ddae726503326667"
RULE_BEFORE = (
    '  if status = 42 for 2 cycles then exec "/operator/tools/manager start --service camera"'
)
MONITRC_BEFORE = f"""\
# Generated from one reviewed deployment manifest. No wildcard recovery.
set daemon 10
set pidfile "/operator/state/netorch/monit.pid"
set statefile "/operator/state/netorch/monit.state"
set idfile "/operator/state/netorch/monit.id"
set init
set log syslog

check program "workload" with path "/operator/tools/manager probe --service camera"
  timeout 5 seconds
  if status != 0 then alert
{RULE_BEFORE}

check program "pf" with path "/operator/tools/check pf"
  timeout 5 seconds
  if status != 0 then alert
"""


def fixed() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "site": "example-site",
        "user_uid": 501,
        "user": {
            "directory": "/operator/install/netorch",
            "state_directory": "/operator/state/netorch",
            "launchd_directory": "/operator/Library/LaunchAgents",
            "domain": "gui/501",
        },
        "root": {
            "directory": "/Library/Netorch/releases-owner",
            "state_directory": "/Library/Netorch/provision-state",
            "launchd_directory": "/Library/LaunchDaemons",
            "domain": "system",
        },
        "forwarding": {
            "directory": "/Library/Netorch/forwarding",
            "settings_artifact": "forwarding-settings",
            "backend_source": "/operator/site/backend.sh",
            "backend_sha256": "0" * 64,
        },
        "artifacts": [
            {
                "id": "forwarding-settings",
                "scope": "root",
                "source": "/operator/site/forwarding-settings.json",
                "destination": "data/forwarding-settings.json",
                "sha256": "0" * 64,
            }
        ],
        "jobs": [
            {
                "label": "netorch-coordinator",
                "scope": "user",
                "role": "coordinator",
                "argv": ["/operator/runtime/bin/python3", "-m", "netorch", "reconcile"],
                "interval_seconds": 10,
                "keep_alive": False,
                "working_directory": "{release}",
                "log_directory": "/operator/state/netorch/logs",
            },
            {
                "label": "netorch-forwarding",
                "scope": "root",
                "role": "forwarding",
                "argv": [
                    "/Library/Netorch/runtime/bin/python3",
                    "-I",
                    "-m",
                    "netorch.pf_owner",
                    "reconcile",
                    "--root-dir",
                    "/Library/Netorch/forwarding",
                ],
                "interval_seconds": 10,
                "keep_alive": False,
                "working_directory": "{release}",
                "log_directory": "/Library/Netorch/logs",
            },
        ],
        "monitors": [
            {
                "id": "workload",
                "role": "workload",
                "check_argv": ["/operator/tools/manager", "probe", "--service", "camera"],
                "recovery_argv": ["/operator/tools/manager", "start", "--service", "camera"],
                "timeout_seconds": 5,
                "cycles": 2,
                "recovery_code": 42,
            },
            {
                "id": "pf",
                "role": "forwarding",
                "check_argv": ["/operator/tools/check", "pf"],
                "recovery_argv": None,
                "timeout_seconds": 5,
                "cycles": 2,
                "recovery_code": 42,
            },
        ],
        "monit_interval_seconds": 10,
        "launchctl": "/bin/launchctl",
        "monit": "/operator/tools/monit",
    }


def rendered(value: dict[str, Any]) -> str:
    return implementation._monit(parse_deployment(canonical_bytes(value)), RELEASE).decode()


def test_manifest_without_the_setting_keeps_its_canonical_form_and_digest() -> None:
    value = fixed()
    canonical = deployment_to_dict(parse_deployment(canonical_bytes(value)))
    assert canonical_bytes(canonical) == canonical_bytes(value)
    assert all("recovery_repeat_cycles" not in monitor for monitor in canonical["monitors"])
    assert digest(canonical) == DIGEST_BEFORE


def test_manifest_without_the_setting_renders_the_bytes_it_rendered_before() -> None:
    text = rendered(fixed())
    assert text == MONITRC_BEFORE
    assert hashlib.sha256(text.encode()).hexdigest() == MONITRC_SHA256_BEFORE
    assert "repeat" not in text


@pytest.mark.parametrize("cycles", [1, 3, 360])
def test_setting_adds_only_the_repeat_clause_to_its_own_rule(cycles: int) -> None:
    value = fixed()
    value["monitors"][0]["recovery_repeat_cycles"] = cycles
    text = rendered(value)
    rule = f"{RULE_BEFORE} repeat every {cycles} cycles"
    assert text == MONITRC_BEFORE.replace(RULE_BEFORE, rule)
    # What tests/test_deployment.py asserts for the default stays true.
    assert text.count("then exec") == 1 and "restart" not in text
    assert text.count("if status != 0 then alert") == 2


def test_setting_is_part_of_the_canonical_form_and_of_the_digest() -> None:
    value = fixed()
    value["monitors"][0]["recovery_repeat_cycles"] = 3
    canonical = deployment_to_dict(parse_deployment(canonical_bytes(value)))
    assert canonical_bytes(canonical) == canonical_bytes(value)
    assert canonical["monitors"][0]["recovery_repeat_cycles"] == 3
    assert "recovery_repeat_cycles" not in canonical["monitors"][1]
    assert digest(canonical) != DIGEST_BEFORE
    other = copy.deepcopy(value)
    other["monitors"][0]["recovery_repeat_cycles"] = 4
    assert digest(deployment_to_dict(parse_deployment(canonical_bytes(other)))) != digest(canonical)


@pytest.mark.parametrize("cycles", [0, -1, 361, 2.0, 2.5, "3", True, None, [3]])
def test_setting_is_a_bounded_whole_number(cycles: Any) -> None:
    value = fixed()
    value["monitors"][0]["recovery_repeat_cycles"] = cycles
    with pytest.raises(DeploymentError):
        parse_deployment(canonical_bytes(value))


def test_setting_needs_a_recovery_command() -> None:
    value = fixed()
    value["monitors"][1]["recovery_repeat_cycles"] = 3
    with pytest.raises(DeploymentError, match="recovery command"):
        parse_deployment(canonical_bytes(value))


def test_bundle_with_the_setting_validates_installs_and_refuses_an_edited_rule(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    plain, before = make_bundle(tmp_path, manifest, config, "plain")
    manifest["monitors"][0]["recovery_repeat_cycles"] = 6
    bundle, metadata = make_bundle(tmp_path, manifest, config, "repeating")
    assert metadata["release_id"] != before["release_id"]
    assert metadata["deployment"]["monitors"][0]["recovery_repeat_cycles"] == 6
    assert validate_bundle(bundle)["bundle_digest"] == metadata["bundle_digest"]
    text = (bundle / "user/monit/monitrc").read_text()
    assert text.count(" repeat every 6 cycles\n") == 1
    assert text.replace(" repeat every 6 cycles", "") == (plain / "user/monit/monitrc").read_text()

    result = install_bundle(
        bundle, "user", expected_digest=metadata["bundle_digest"], runner=FakeTools()
    )
    assert result["phase"] == "committed"
    receipt = Store(Path(manifest["user"]["state_directory"])).read("installation-receipt.json")
    assert receipt["deployment"]["monitors"][0]["recovery_repeat_cycles"] == 6

    # The clause cannot be added to, or removed from, a bundle after the fact.
    monitrc = plain / "user/monit/monitrc"
    edited = (bundle / "user/monit/monitrc").read_bytes()
    monitrc.write_bytes(edited)
    record = next(item for item in before["files"] if item["path"] == "user/monit/monitrc")
    record.update(sha256=hashlib.sha256(edited).hexdigest(), bytes=len(edited))
    before["bundle_digest"] = digest(
        {key: item for key, item in before.items() if key != "bundle_digest"}
    )
    (plain / "manifest.json").write_bytes(canonical_bytes(before))
    with pytest.raises(DeploymentError, match="Monit definition differs"):
        validate_bundle(plain)

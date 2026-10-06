"""No command line of a deployment reaches root: jobs and monitors alike."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from netorch.codec import canonical_bytes
from netorch.deployment_config import DeploymentError, parse_deployment, validate_deployment
from tests.test_deployment import manifest

__all__ = ["manifest"]

REFUSAL = "never embeds privilege escalation"
ESCALATIONS = [
    ["/usr/bin/sudo", "-n", "/protected/check"],
    ["/protected/check", "sudo", "-n", "/protected/helper"],
    ["/protected/check", "--wrapper", "/usr/bin/sudo"],
    ["/usr/bin/su", "root", "-c", "/protected/check"],
    ["/protected/tools/doas", "/protected/check"],
]
MONITOR_FIELDS = [(0, "check_argv"), (0, "recovery_argv"), (1, "check_argv")]


@pytest.mark.parametrize("argv", ESCALATIONS)
@pytest.mark.parametrize("monitor,field", MONITOR_FIELDS)
def test_monitor_command_cannot_escalate(
    manifest: dict[str, Any], monitor: int, field: str, argv: list[str]
) -> None:
    manifest["monitors"][monitor][field] = argv
    with pytest.raises(DeploymentError, match=REFUSAL):
        parse_deployment(canonical_bytes(manifest))


@pytest.mark.parametrize("argv", ESCALATIONS)
def test_job_command_is_still_refused_for_the_same_reason(
    manifest: dict[str, Any], argv: list[str]
) -> None:
    manifest["jobs"][0]["argv"] = argv
    with pytest.raises(DeploymentError, match=REFUSAL):
        parse_deployment(canonical_bytes(manifest))


@pytest.mark.parametrize("field", ["check_argv", "recovery_argv"])
def test_a_model_built_in_code_is_held_to_the_same_rule(
    manifest: dict[str, Any], field: str
) -> None:
    deployment = parse_deployment(canonical_bytes(manifest))
    changed = replace(deployment.monitors[0], **{field: ("/usr/bin/sudo", "/protected/check")})
    with pytest.raises(DeploymentError, match=REFUSAL):
        validate_deployment(replace(deployment, monitors=(changed, *deployment.monitors[1:])))


def test_words_that_only_contain_those_names_are_not_refused(manifest: dict[str, Any]) -> None:
    manifest["monitors"][0]["check_argv"] = [
        "/protected/pseudo-manager",
        "probe",
        "--service",
        "results",
        "--summary",
        "/protected/issue",
    ]
    manifest["monitors"][0]["recovery_argv"] = ["/protected/resume", "start", "--service", "sum"]
    deployment = parse_deployment(canonical_bytes(manifest))
    assert deployment.monitors[0].check_argv[0] == "/protected/pseudo-manager"
    assert deployment.monitors[0].recovery_argv == (
        "/protected/resume",
        "start",
        "--service",
        "sum",
    )

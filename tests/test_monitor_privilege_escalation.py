"""Known privilege helpers and shell strings are refused in jobs and monitors."""

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


@pytest.mark.parametrize(
    "argv",
    [
        ["/bin/sh", "-c", "/usr/bin/sudo -n /protected/check"],
        ["/bin/bash", "-lc", "exec /protected/check"],
        ["/bin/zsh", "-ec", "exec /protected/check"],
        ["/bin/csh", "-c", "exec /protected/check"],
        ["/opt/homebrew/bin/fish", "--command=exec /protected/check"],
        ["/usr/bin/env", "PATH=/bin", "sh", "-c", "exec /protected/check"],
    ],
)
@pytest.mark.parametrize("field", ["job", "check_argv", "recovery_argv"])
def test_known_shell_command_strings_cannot_be_deployment_data(
    manifest: dict[str, Any], argv: list[str], field: str
) -> None:
    if field == "job":
        manifest["jobs"][0]["argv"] = argv
    else:
        manifest["monitors"][0][field] = argv
    with pytest.raises(DeploymentError, match="shell command strings"):
        parse_deployment(canonical_bytes(manifest))


def test_reviewed_script_path_and_non_shell_options_remain_provider_bindings(
    manifest: dict[str, Any],
) -> None:
    manifest["monitors"][0]["check_argv"] = ["/bin/sh", "/protected/check.sh"]
    manifest["monitors"][0]["recovery_argv"] = ["/protected/manager", "-c", "camera"]
    deployment = parse_deployment(canonical_bytes(manifest))
    assert deployment.monitors[0].check_argv == ("/bin/sh", "/protected/check.sh")
    assert deployment.monitors[0].recovery_argv == ("/protected/manager", "-c", "camera")

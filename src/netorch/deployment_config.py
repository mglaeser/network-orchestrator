"""Strict offline manifest loading; deployment is explicitly trusted operator data."""

from __future__ import annotations

from dataclasses import asdict
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator

from .codec import canonical_bytes, read_bounded_file, strict_load, strict_loads
from .deployment_model import (
    Artifact,
    Deployment,
    ForwardingInstallation,
    Installation,
    Job,
    Monitor,
)


class DeploymentError(ValueError):
    pass


def _path(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or str(path) != value
        or any(character in value for character in ('"', "\\", "{", "}"))
    ):
        raise DeploymentError("deployment paths must be canonical absolute paths")


def _unprivileged(argv: tuple[str, ...]) -> None:
    # Bindings are trusted executable code, not a sandbox. These guards reject
    # explicit elevation and known shell-command strings in manifest data.
    if any(
        value in {"sudo", "su", "doas"} or value.endswith(("/sudo", "/su", "/doas"))
        for value in argv
    ):
        raise DeploymentError("deployment never embeds privilege escalation")
    shells = {"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh"}
    for index, value in enumerate(argv):
        # Include an explicit env/wrapper shell argument, without interpreting
        # command text or claiming to detect renamed executables or scripts.
        if PurePosixPath(value).name in shells and any(
            item == "--command"
            or item.startswith("--command=")
            or (item.startswith("-") and not item.startswith("--") and "c" in item[1:])
            for item in argv[index + 1 :]
        ):
            raise DeploymentError("deployment never embeds shell command strings")


def _shape(value: Any) -> None:
    schema_path = resources.files("netorch").joinpath("deployment.schema.json")
    schema = (
        strict_loads(schema_path.read_bytes())
        if schema_path.is_file()
        else strict_load(Path(__file__).resolve().parents[2] / "schemas/deployment.schema.json")
    )
    errors = list(Draft202012Validator(schema).iter_errors(value))
    if errors:
        raise DeploymentError("deployment manifest violates its closed schema")


def parse_deployment(raw: str | bytes) -> Deployment:
    value = strict_loads(raw)
    _shape(value)
    data: dict[str, Any] = value
    deployment = Deployment(
        data["schema_version"],
        data["site"],
        data["user_uid"],
        Installation(**data["user"]),
        Installation(**data["root"]),
        ForwardingInstallation(**data["forwarding"]),
        tuple(Artifact(**item) for item in data["artifacts"]),
        tuple(Job(**{**item, "argv": tuple(item["argv"])}) for item in data["jobs"]),
        tuple(
            Monitor(
                **{
                    **item,
                    "check_argv": tuple(item["check_argv"]),
                    "recovery_argv": None
                    if item["recovery_argv"] is None
                    else tuple(item["recovery_argv"]),
                }
            )
            for item in data["monitors"]
        ),
        data["monit_interval_seconds"],
        data["launchctl"],
        data["monit"],
    )
    validate_deployment(deployment)
    return deployment


def load_deployment(path: Path) -> Deployment:
    return parse_deployment(read_bounded_file(path))


def deployment_to_dict(deployment: Deployment) -> dict[str, Any]:
    return asdict(deployment)


def validate_deployment(deployment: Deployment) -> None:
    _shape(strict_loads(canonical_bytes(deployment_to_dict(deployment))))
    for scope in ("user", "root"):
        installation = deployment.installation(scope)
        for value in (
            installation.directory,
            installation.state_directory,
            installation.launchd_directory,
        ):
            _path(value)
        release_root = PurePosixPath(installation.directory) / "releases"
        if PurePosixPath(installation.state_directory).is_relative_to(release_root):
            raise DeploymentError("mutable intent must live outside release directories")
    if deployment.user.domain != f"gui/{deployment.user_uid}" or deployment.root.domain != "system":
        raise DeploymentError("user and root launchd domains are distinct and fixed")
    if PurePosixPath(deployment.user.directory).is_relative_to(
        deployment.root.directory
    ) or PurePosixPath(deployment.root.directory).is_relative_to(deployment.user.directory):
        raise DeploymentError("user and root release trees must be disjoint")
    for collection, key in (
        (deployment.artifacts, "id"),
        (deployment.jobs, "label"),
        (deployment.monitors, "id"),
    ):
        keys = [getattr(item, key) for item in collection]
        if len(keys) != len(set(keys)):
            raise DeploymentError("deployment identifiers must be unique")
    destinations = [(item.scope, item.destination) for item in deployment.artifacts]
    if len(destinations) != len(set(destinations)):
        raise DeploymentError("each release artifact has one author")
    for artifact in deployment.artifacts:
        _path(artifact.source)
        if (
            ".." in PurePosixPath(artifact.destination).parts
            or str(PurePosixPath(artifact.destination)) != artifact.destination
        ):
            raise DeploymentError("artifact destinations cannot escape the release")
    for job in deployment.jobs:
        for value in (job.argv[0], job.log_directory):
            _path(value)
        _path(job.working_directory.replace("{release}", "/release").replace("{state}", "/state"))
        if job.keep_alive and job.interval_seconds is not None:
            raise DeploymentError("job must be a daemon or periodic task, not both")
        if job.scope == "root" and job.role != "forwarding":
            raise DeploymentError("only the independent forwarding owner is a root job")
        if job.scope == "user" and job.role == "forwarding":
            raise DeploymentError("forwarding cannot be invoked by a user launch job")
        _unprivileged(job.argv)
    for monitor in deployment.monitors:
        _path(monitor.check_argv[0])
        _unprivileged(monitor.check_argv)
        if monitor.recovery_argv is not None:
            _path(monitor.recovery_argv[0])
            _unprivileged(monitor.recovery_argv)
        if monitor.role != "workload" and monitor.recovery_argv is not None:
            raise DeploymentError("networking failure must not initiate workload recovery")
    _path(deployment.launchctl)
    _path(deployment.monit)
    _path(deployment.forwarding.directory)
    _path(deployment.forwarding.backend_source)
    matches = [
        artifact
        for artifact in deployment.artifacts
        if artifact.id == deployment.forwarding.settings_artifact and artifact.scope == "root"
    ]
    if len(matches) != 1:
        raise DeploymentError("forwarding requires exactly one protected root settings artifact")
    if PurePosixPath(deployment.forwarding.directory).is_relative_to(
        PurePosixPath(deployment.root.directory) / "releases"
    ):
        raise DeploymentError("forwarding admission and intent must live outside releases")
    root_jobs = [job for job in deployment.jobs if job.scope == "root"]
    if len(root_jobs) != 1 or root_jobs[0].argv[1:] != (
        "-I",
        "-m",
        "netorch.pf_owner",
        "reconcile",
        "--root-dir",
        deployment.forwarding.directory,
    ):
        raise DeploymentError(
            "one independent forwarding root job must pull its protected directory"
        )

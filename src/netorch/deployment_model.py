"""Installation data, separate from policy and mutable operational intent."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Artifact:
    id: str
    scope: str
    source: str
    destination: str
    sha256: str


@dataclass(frozen=True, slots=True)
class Job:
    label: str
    scope: str
    role: str
    argv: tuple[str, ...]
    interval_seconds: int | None
    keep_alive: bool
    working_directory: str
    log_directory: str
    # Optional. Absent means "background", the class every job had before.
    process_type: str = "background"


@dataclass(frozen=True, slots=True)
class Monitor:
    id: str
    role: str
    check_argv: tuple[str, ...]
    recovery_argv: tuple[str, ...] | None
    timeout_seconds: int
    cycles: int
    recovery_code: int


@dataclass(frozen=True, slots=True)
class Installation:
    directory: str
    state_directory: str
    launchd_directory: str
    domain: str


@dataclass(frozen=True, slots=True)
class ForwardingInstallation:
    directory: str
    settings_artifact: str
    backend_source: str
    backend_sha256: str


@dataclass(frozen=True, slots=True)
class Deployment:
    schema_version: int
    site: str
    user_uid: int
    user: Installation
    root: Installation
    forwarding: ForwardingInstallation
    artifacts: tuple[Artifact, ...]
    jobs: tuple[Job, ...]
    monitors: tuple[Monitor, ...]
    monit_interval_seconds: int
    launchctl: str
    monit: str

    def installation(self, scope: str) -> Installation:
        if scope == "user":
            return self.user
        if scope == "root":
            return self.root
        raise ValueError("installation scope must be user or root")

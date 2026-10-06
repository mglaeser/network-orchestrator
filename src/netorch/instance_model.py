"""Data-only host declarations; observations and executable policy are separate."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FrameworkPin:
    version: str
    artifact_sha256: str
    revision: str
    dependency_lock_sha256: str
    schema_version: int


@dataclass(frozen=True, slots=True)
class Account:
    uid: int
    gid: int
    home: str


@dataclass(frozen=True, slots=True)
class LAN:
    hardware_id: str
    link: str
    ipv4: str
    cidr: str


@dataclass(frozen=True, slots=True)
class Runtime:
    network: str
    version: str


@dataclass(frozen=True, slots=True)
class Platform:
    macos_version: str
    macos_build: str


@dataclass(frozen=True, slots=True)
class Baseline:
    filevault: bool | None
    automatic_login: bool | None
    power_restart: bool | None
    application_firewall: bool | None
    network_extensions: tuple[str, ...]
    proxies: tuple[str, ...]
    vpns: tuple[str, ...]
    internet_sharing: bool | None


@dataclass(frozen=True, slots=True)
class Host:
    account: Account
    lan: LAN
    runtime: Runtime
    platform: Platform
    baseline: Baseline


@dataclass(frozen=True, slots=True)
class Names:
    coordinator_label: str | None
    bonjour_label: str | None
    supervisor_label: str | None
    pf_label: str | None
    pf_anchor: str | None
    helper_label: str | None
    state_directory: str | None
    root_state_directory: str | None
    bonjour_prefix: str | None
    import_prefix: str | None


@dataclass(frozen=True, slots=True)
class ContractRef:
    sha256: str
    data_path: str


@dataclass(frozen=True, slots=True)
class Component:
    id: str
    health: str
    recovery: str


@dataclass(frozen=True, slots=True)
class Deadlines:
    """Where one workload differs from the site's probe and start-action deadlines."""

    probe_seconds: int | None = None
    action_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class Workload:
    id: str
    name: str
    application_profile: str
    contract: ContractRef
    automatic_port_range: str | None
    recovery: str
    components: tuple[Component, ...]
    deadlines: Deadlines | None = None


@dataclass(frozen=True, slots=True)
class NamedPortRange:
    id: str
    first: int
    last: int


@dataclass(frozen=True, slots=True)
class Ports:
    range: str | None = None
    first: int | None = None
    last: int | None = None


@dataclass(frozen=True, slots=True)
class Transport:
    id: str
    service: str
    strategy: str
    version: int
    protocol: str
    ports: Ports | None
    target_ports: Ports | None
    dependencies: tuple[str, ...]
    fallback_publication: str | None
    # The LAN prefix unless "any"; the default has no spelling in an instance.
    source_scope: str = "lan"


@dataclass(frozen=True, slots=True)
class DiscoverySelection:
    id: str
    service: str
    profile: str
    version: int
    direction: str
    dependencies: tuple[str, ...]
    misses: int | None = None
    service_types: tuple[str, ...] | None = None
    return_path: str = "required"


@dataclass(frozen=True, slots=True)
class RestartBudget:
    """Start actions for one workload within a period before the supervisor stops acting."""

    starts: int
    window_seconds: int


@dataclass(frozen=True, slots=True)
class Supervision:
    supervisor: str
    reconcile_seconds: int
    health_seconds: int
    discovery_seconds: int
    discovery_misses: int
    read_timeout_seconds: int
    failure_exit_code: int
    component_exit_code: int | None = None
    restart_budget: RestartBudget | None = None
    action_timeout_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class LifecycleTool:
    id: str
    kind: str
    container_api_access: bool
    starts_runtime: bool | None
    version: str | None
    # Written only as true, on the one supervisor tool that starts the workloads
    # after a boot; left out of the canonical form otherwise.
    starts_fleet: bool = False


@dataclass(frozen=True, slots=True)
class BoundedDecision:
    profile: str
    max_age_seconds: int
    unknown_limit: int
    residual: str
    signed_by: str | None
    signed_at: str | None


@dataclass(frozen=True, slots=True)
class RecoveryDecision:
    accepted: bool | None
    max_dns_ready_seconds: int | None


@dataclass(frozen=True, slots=True)
class VisibilityDecision:
    accepted: bool | None
    signed_by: str | None
    signed_at: str | None


@dataclass(frozen=True, slots=True)
class LifecycleDecision:
    residual: str | None
    signed_by: str | None
    signed_at: str | None


@dataclass(frozen=True, slots=True)
class Decisions:
    bounded: tuple[BoundedDecision, ...]
    unattended_recovery: RecoveryDecision
    import_visibility: VisibilityDecision
    lifecycle_control: LifecycleDecision


@dataclass(frozen=True, slots=True)
class Acceptance:
    requirement: str
    instance_schema_version: int
    profile: str | None
    method: str
    tier: int
    observed_at: str
    macos_build: str
    runtime_version: str
    framework_sha256: str
    contract_sha256: str
    evidence_sha256: str
    signed_by: str


@dataclass(frozen=True, slots=True)
class Deviation:
    id: str
    requirement: str
    statement: str
    accepted_by: str | None
    accepted_at: str | None


@dataclass(frozen=True, slots=True)
class Authoring:
    owner: str
    sections: tuple[str, ...]
    subjects: tuple[str, ...]
    mode: str
    source_sha256: str | None


@dataclass(frozen=True, slots=True)
class Instance:
    schema_version: int
    instance: str
    namespace: str
    framework: FrameworkPin
    host: Host
    names: Names
    workloads: tuple[Workload, ...]
    port_ranges: tuple[NamedPortRange, ...]
    transport: tuple[Transport, ...]
    discovery: tuple[DiscoverySelection, ...]
    supervision: Supervision
    lifecycle_tools: tuple[LifecycleTool, ...]
    decisions: Decisions
    acceptance: tuple[Acceptance, ...]
    deviations: tuple[Deviation, ...]
    authoring: tuple[Authoring, ...]

    def workload(self, identifier: str) -> Workload:
        return next(item for item in self.workloads if item.id == identifier)

    def transport_profile(self, identifier: str) -> Transport:
        return next(item for item in self.transport if item.id == identifier)

    def port_range(self, identifier: str) -> NamedPortRange:
        return next(item for item in self.port_ranges if item.id == identifier)

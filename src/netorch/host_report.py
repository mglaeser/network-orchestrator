"""Truthful host reports from local data only; no owner/process/network API."""

from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .codec import canonical_bytes, strict_loads
from .instance import (
    InstanceError,
    check_plain_data,
    instance_contract_digest,
    instance_digest,
    instance_to_dict,
    read_data,
    resolved_discovery_digest,
    resolved_names,
    resolved_profile_digest,
)
from .instance_model import Instance
from .platform_contract import ACCEPTED_PLATFORMS, FACTS, candidate_matches
from .profile_library import STRATEGIES, discovery_profile, strategy
from .requirements import REQUIREMENTS, Requirement
from .safety_contract import assess_bounded_safety, assessment_to_dict

REASONS = (
    "complete",
    "not-checked",
    "incomplete",
    "malformed",
    "inaccessible",
    "timed-out",
    "busy",
    "stale",
    "local-network-denied",
    "unsupported",
    "contradictory",
    "declared-only",
    "missing",
    "identity-mismatch",
)
FACT_KEYS = (
    "hardware_class",
    "hardware_model",
    "macos_version",
    "macos_build",
    "runtime_version",
    "runtime_domain",
    "runtime_install_method",
    "socktainer_version",
    "socktainer_install_method",
    "filevault",
    "automatic_login",
    "power_restart",
    "application_firewall",
    "network_extensions",
    "proxies",
    "vpns",
    "internet_sharing",
    "lan_interface",
    "lan_hardware_id",
    "lan_ipv4",
    "pf_baseline_sha256",
    "pf_anchors",
    "local_network_identity",
    "kernel_references",
    "runtime_dns_domain",
    "runtime_resolvers",
    "udp_sockets_idle",
    "udp_sockets_loaded",
    "installed_framework_sha256",
    "installed_framework_version",
    "anchor_order",
    "owner_conformance",
    "names_preserved",
    "framework_literal_check",
    "instance_literal_check",
    "recovery_material",
    "startup_chain",
    "dns_secondary_resolver",
)
MAX_FACT_AGE_SECONDS = 300
# A supplied absent or false observation keeps its requirement not fulfilled until a
# positive one replaces it. Growing stale never clears it.
BLOCKING_FACTS = {
    "HOST-DATA": ("framework_literal_check", "instance_literal_check"),
    "NAMES-PRESERVED": ("names_preserved",),
    "OWNER-CONFORMANCE": ("owner_conformance",),
    "RESTORE-REHEARSAL": ("recovery_material",),
}
# Safety/provenance gates and every native, lifecycle or application acceptance
# need their own proof. A generic deviation cannot replace that proving ladder.
MANDATORY_PROVING_GATES = frozenset(
    {
        "BOUNDED-IDENTITY",
        "PLATFORM-SUPPORT",
        "SOURCE-AUTHORSHIP",
        "OWNER-CONFORMANCE",
        "ROOT-ADMISSION",
        "ROOT-HARD-BOUNDS",
        "ROOT-INDEPENDENCE",
        "PAUSE-PRESERVED",
        "UNKNOWN-NO-RECOVERY",
        "RESTORE-REHEARSAL",
        "NO-LOCAL-NETWORK",
        "CURRENT-OBSERVATIONS",
    }
    | {item.id for item in REQUIREMENTS if item.minimum_tier >= 3}
)


@dataclass(frozen=True, slots=True)
class Observation:
    state: str
    reason: str
    observed_at: float
    generation: str | None


@dataclass(frozen=True, slots=True)
class Fact:
    key: str
    state: str
    reason: str
    observed_at: float
    value: Any


@dataclass(frozen=True, slots=True)
class ProfileEvidence:
    id: str
    desired_digest: str | None
    admitted_digest: str | None
    applied_digest: str | None
    paused: bool | None
    suspensions: tuple[str, ...]
    transport: Observation
    discovery: Observation
    probe: Observation
    application: Observation
    heard_audio: Observation
    receipt: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class ComponentEvidence:
    service: str
    id: str
    observation: Observation


@dataclass(frozen=True, slots=True)
class WorkloadEvidence:
    id: str
    observation: Observation


@dataclass(frozen=True, slots=True)
class HostEvidence:
    schema_version: int
    observed_at: float
    source: str
    facts: tuple[Fact, ...]
    profiles: tuple[ProfileEvidence, ...]
    components: tuple[ComponentEvidence, ...] = ()
    workloads: tuple[WorkloadEvidence, ...] = ()


@lru_cache(maxsize=2)
def _validator(name: str) -> Draft202012Validator:
    resource = resources.files("netorch").joinpath(name)
    raw = (
        resource.read_bytes()
        if resource.is_file()
        else read_data(Path(__file__).resolve().parents[2] / "schemas" / name)
    )
    schema = strict_loads(raw)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def parse_host_evidence(raw: bytes | str | dict[str, Any]) -> HostEvidence:
    data = strict_loads(canonical_bytes(raw)) if isinstance(raw, dict) else strict_loads(raw)
    if list(_validator("host-evidence.schema.json").iter_errors(data)):
        raise InstanceError("host evidence violates its closed bounded schema")
    # Evidence times are epoch seconds; every other number in a closed document is an integer.
    check_plain_data(data, frozenset({"observed_at", "recorded_at"}))
    facts = tuple(Fact(**item) for item in data["facts"])
    profiles = tuple(
        ProfileEvidence(
            **{
                **item,
                "suspensions": tuple(item["suspensions"]),
                **{
                    key: Observation(**item[key])
                    for key in ("transport", "discovery", "probe", "application", "heard_audio")
                },
            }
        )
        for item in data["profiles"]
    )
    components = tuple(
        ComponentEvidence(item["service"], item["id"], Observation(**item["observation"]))
        for item in data.get("components", [])
    )
    workloads = tuple(
        WorkloadEvidence(item["id"], Observation(**item["observation"]))
        for item in data.get("workloads", [])
    )
    if (
        len({item.key for item in facts}) != len(facts)
        or len({item.id for item in profiles}) != len(profiles)
        or len({(item.service, item.id) for item in components}) != len(components)
        or len({item.id for item in workloads}) != len(workloads)
    ):
        raise InstanceError("duplicate owner evidence identity")
    for item in facts:
        if (item.state == "unknown" and item.value is not None) or (
            item.state == "present" and item.value is None
        ):
            raise InstanceError("fact decision and value disagree")
        if item.value is not None:
            bool_keys = {
                "automatic_login",
                "power_restart",
                "application_firewall",
                "internet_sharing",
                "proxies",
                "vpns",
            } | {key for keys in BLOCKING_FACTS.values() for key in keys}
            list_keys = {"network_extensions", "pf_anchors", "anchor_order", "runtime_resolvers"}
            int_keys = {"udp_sockets_idle", "udp_sockets_loaded"}
            if (
                (item.key in bool_keys and type(item.value) is not bool)
                or (item.key in list_keys and not isinstance(item.value, list))
                or (item.key in int_keys and type(item.value) is not int)
            ):
                raise InstanceError("fact value has the wrong declared type")
            if item.key == "filevault" and (
                not isinstance(item.value, str) or item.value not in {"on", "off"}
            ):
                raise InstanceError("FileVault value has the wrong declared type")
            if item.key == "local_network_identity" and (
                not isinstance(item.value, str) or not item.value.strip()
            ):
                raise InstanceError("Local Network identity must be nonblank text")
    return HostEvidence(
        data["schema_version"],
        data["observed_at"],
        data["source"],
        facts,
        profiles,
        components,
        workloads,
    )


def empty_evidence(now: float) -> HostEvidence:
    return HostEvidence(1, now, "synthetic", (), ())


def evidence_to_dict(evidence: HostEvidence) -> dict[str, Any]:
    return strict_loads(canonical_bytes(asdict(evidence)))  # type: ignore[no-any-return]


def _age(observed_at: float, now: float, maximum: float) -> tuple[float | None, str | None]:
    if not math.isfinite(now) or not math.isfinite(observed_at) or observed_at > now:
        return None, "contradictory"
    age = now - observed_at
    return age, "stale" if age > maximum else None


def fact_view(evidence: HostEvidence, key: str, now: float) -> dict[str, Any]:
    fact = next((item for item in evidence.facts if item.key == key), None)
    if fact is None:
        return {
            "key": key,
            "state": "unknown",
            "reason": "not-checked",
            "age_seconds": None,
            "value": None,
        }
    age, reason = _age(fact.observed_at, now, MAX_FACT_AGE_SECONDS)
    if fact.state != "unknown" and fact.reason != "complete":
        reason = fact.reason
    return {
        "key": key,
        "state": "unknown" if reason else fact.state,
        "reason": reason or fact.reason,
        "age_seconds": age,
        "value": None if reason else fact.value,
    }


def _reported(evidence: HostEvidence, key: str) -> Fact | None:
    """The supplied record whatever its age; only ``fact_view`` says what is current."""
    return next((item for item in evidence.facts if item.key == key), None)


def observation_view(observation: Observation | None, now: float, maximum: float) -> dict[str, Any]:
    if observation is None:
        return {
            "state": "unknown",
            "reason": "not-checked",
            "age_seconds": None,
            "generation": None,
        }
    age, reason = _age(observation.observed_at, now, maximum)
    if observation.state != "unknown" and observation.reason != "complete":
        reason = observation.reason
    if observation.state != "unknown" and observation.generation is None:
        reason = "incomplete"
    return {
        "state": "unknown" if reason else observation.state,
        "reason": reason or observation.reason,
        "age_seconds": age,
        "generation": observation.generation,
    }


def verify_contracts(instance: Instance, data_directory: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in instance.workloads:
        try:
            raw = read_data(data_directory / item.contract.data_path)
            data = strict_loads(raw)
            check_plain_data(data)
            if raw != canonical_bytes(data) + b"\n" or list(
                _validator("workload-contract.schema.json").iter_errors(data)
            ):
                raise InstanceError("workload contract is not closed canonical data")
            if hashlib.sha256(raw).hexdigest() != item.contract.sha256:
                raise InstanceError("workload contract content differs from its pinned hash")
            if data["network"]["name"] != instance.host.runtime.network:
                raise InstanceError("workload contract runtime network differs")
            if any(
                ".." in Path(mount["source"]).parts or not Path(mount["source"]).is_absolute()
                for mount in data["mounts"]
            ):
                raise InstanceError("workload mount path is not absolute data")
            results.append(
                {
                    "service": item.id,
                    "state": "present",
                    "reason": "complete",
                    "sha256": item.contract.sha256,
                }
            )
        except (OSError, ValueError):
            results.append(
                {
                    "service": item.id,
                    "state": "unknown",
                    "reason": "missing-or-invalid-contract",
                    "sha256": item.contract.sha256,
                }
            )
    return results


def _applicable(instance: Instance, requirement: Requirement) -> bool:
    strategies = {item.strategy for item in instance.transport}
    condition = requirement.applicability
    return {
        "all": True,
        "workloads": bool(instance.workloads),
        "components": any(item.components for item in instance.workloads),
        "transport": bool(instance.transport),
        "root-transport": bool(strategies - {"published-port", "guest-lan-alias"}),
        "bounded": any(
            strategy(item.strategy, item.version).gate == "bounded" for item in instance.transport
        ),
        "bounded-udp": "guest-udp-range-forward" in strategies,
        "exports": any(item.direction == "export" for item in instance.discovery),
        "imports": any(item.direction == "import" for item in instance.discovery),
        "discovery": bool(instance.discovery),
        "resolver": any(item.application_profile == "resolver" for item in instance.workloads),
        "api-writers": any(item.container_api_access for item in instance.lifecycle_tools),
    }[condition]


def _acceptance(
    instance: Instance,
    requirement: Requirement,
    evidence: HostEvidence,
    now: float,
    directory: Path | None,
) -> bool:
    if directory is None or evidence.source == "synthetic":
        return False
    relevant = {
        item.id
        for item in instance.discovery
        if requirement.applicability == "discovery"
        or (requirement.applicability == "imports" and item.direction == "import")
        or (requirement.applicability == "exports" and item.direction == "export")
    }
    if requirement.applicability in {"transport", "root-transport", "bounded", "bounded-udp"}:
        relevant = {
            item.id
            for item in instance.transport
            if requirement.applicability == "transport"
            or (
                requirement.applicability == "root-transport"
                and item.strategy not in {"published-port", "guest-lan-alias"}
            )
            or (
                requirement.applicability == "bounded"
                and strategy(item.strategy, item.version).gate == "bounded"
            )
            or (
                requirement.applicability == "bounded-udp"
                and item.strategy == "guest-udp-range-forward"
            )
        }
    matched: set[str] = set()
    for entry in instance.acceptance:
        if (
            entry.requirement != requirement.id
            or not entry.signed_by.strip()
            or entry.method not in requirement.acceptance_methods
            or entry.tier < requirement.minimum_tier
            or (entry.profile is not None and entry.profile not in relevant)
            # One instance-wide record is never proof for each applicable profile.
            or (entry.profile is None and bool(relevant))
        ):
            continue
        expected = instance_contract_digest(instance)
        if entry.profile is not None:
            profile = next((item for item in instance.transport if item.id == entry.profile), None)
            if profile is not None:
                expected = resolved_profile_digest(instance, profile)
            else:
                expected = resolved_discovery_digest(
                    instance, next(item for item in instance.discovery if item.id == entry.profile)
                )
        observed = (
            datetime.strptime(entry.observed_at, "%Y-%m-%dT%H:%M:%SZ")
            .replace(tzinfo=UTC)
            .timestamp()
        )
        if (
            observed > now
            or entry.instance_schema_version != instance.schema_version
            or entry.framework_sha256 != instance.framework.artifact_sha256
            or entry.contract_sha256 != expected
            or entry.macos_build != instance.host.platform.macos_build
            or entry.runtime_version != instance.host.runtime.version
        ):
            continue
        for key, declared in (
            ("macos_build", entry.macos_build),
            ("runtime_version", entry.runtime_version),
        ):
            fact = fact_view(evidence, key, now)
            if fact["state"] != "present" or fact["value"] != declared:
                break
        else:
            try:
                artifact = read_data(directory / (entry.evidence_sha256 + ".json"))
                proof = strict_loads(artifact)
                check_plain_data(proof)
                if artifact != canonical_bytes(proof) + b"\n" or list(
                    _validator("acceptance-evidence.schema.json").iter_errors(proof)
                ):
                    continue
                if (
                    proof["kind"] == "synthetic"
                    or proof["result"] != "passed"
                    or (
                        proof["capture_context"] == "offline-fixture"
                        and requirement.minimum_tier > 1
                    )
                ):
                    continue
                if entry.method == "heard-audio" and proof["capture_context"] != "host-person":
                    continue
                if (
                    entry.method == "root-runtime-observer"
                    and proof["capture_context"] != "root-launchdaemon"
                ):
                    continue
                if (
                    entry.method == "local-network-consent"
                    and proof["capture_context"] != "user-launchagent"
                ):
                    continue
                if any(
                    proof[key] != getattr(entry, key)
                    for key in (
                        "requirement",
                        "instance_schema_version",
                        "profile",
                        "method",
                        "tier",
                        "observed_at",
                        "macos_build",
                        "runtime_version",
                        "framework_sha256",
                        "contract_sha256",
                        "signed_by",
                    )
                ):
                    continue
                if hashlib.sha256(artifact).hexdigest() == entry.evidence_sha256:
                    if entry.profile is None:
                        return True
                    matched.add(entry.profile)
            except (OSError, ValueError):
                continue
    return bool(relevant) and relevant <= matched


def _base_assessment(
    instance: Instance,
    requirement: Requirement,
    evidence: HostEvidence,
    now: float,
    contracts: list[dict[str, Any]],
    release_verified: bool,
) -> tuple[str, str]:
    identifier = requirement.id
    pure = {
        "DATA-ONLY",
        "IPV4-SCOPE",
        "COMPONENT-HEALTH",
        "PORT-RANGES",
        "ROOT-INDEPENDENCE",
        "UNKNOWN-NO-RECOVERY",
        "APPLICATION-PRESERVED",
        "NO-LOCAL-NETWORK",
        "EXIT-STRATEGIES",
        "CURRENT-OBSERVATIONS",
    }
    if identifier in pure:
        return (
            "fulfilled-verified",
            "Implemented read-only model/command contract; native behavior is separate.",
        )
    if identifier == "FRAMEWORK-PIN":
        installed = _reported(evidence, "installed_framework_sha256")
        if installed is not None and installed.value not in (
            None,
            instance.framework.artifact_sha256,
        ):
            return (
                "not-fulfilled",
                "Host evidence reports an installed framework other than the pinned artifact.",
            )
        return (
            ("fulfilled-verified", "Exact local release artifact matches its declared SHA-256.")
            if release_verified
            else (
                "fulfilled-unverified",
                "Release pin declared; exact local artifact has not been verified.",
            )
        )
    if identifier == "WORKLOAD-CONTRACTS":
        return (
            (
                "fulfilled-unverified",
                "Content references verified; installed definition parity still needs acceptance.",
            )
            if contracts and all(item["state"] == "present" for item in contracts)
            else (
                "not-fulfilled",
                "A declared workload contract is missing or differs from its hash.",
            )
        )
    if identifier == "SOURCE-AUTHORSHIP":
        data = instance_to_dict(instance)
        required = set(data) - {"schema_version", "instance", "namespace", "framework", "authoring"}
        covered = set()
        for section in required:
            rows = [row for row in instance.authoring if section in row.sections]
            subjects = (
                {
                    item.get("id", item.get("profile", item.get("requirement")))
                    for item in data[section]
                }
                if isinstance(data[section], list)
                else set()
            )
            if any(not row.subjects for row in rows) or (
                subjects and subjects <= {subject for row in rows for subject in row.subjects}
            ):
                covered.add(section)
        return (
            (
                "fulfilled-unverified",
                "Authoring declared; generated source/conformance checks require evidence.",
            )
            if covered == required
            else ("not-fulfilled", "One or more instance sections have no authoring record.")
        )
    if identifier == "LIFECYCLE-WRITERS":
        value = instance.decisions.lifecycle_control
        return (
            (
                "accepted-residual",
                "Owner-recorded residual; not authentication against a hostile API client.",
            )
            if value.residual is not None
            and value.residual.strip()
            and value.signed_by is not None
            and value.signed_by.strip()
            and value.signed_at
            and datetime.strptime(value.signed_at, "%Y-%m-%dT%H:%M:%SZ")
            .replace(tzinfo=UTC)
            .timestamp()
            <= now
            else (
                "not-fulfilled",
                "Container API authority residual has no current owner signature.",
            )
        )
    if identifier == "IMPORT-VISIBILITY":
        visibility = instance.decisions.import_visibility
        if (
            visibility.accepted is True
            and visibility.signed_by is not None
            and visibility.signed_by.strip()
            and visibility.signed_at is not None
            and datetime.strptime(visibility.signed_at, "%Y-%m-%dT%H:%M:%SZ")
            .replace(tzinfo=UTC)
            .timestamp()
            <= now
        ):
            return (
                "accepted-residual",
                "Owner-recorded import visibility decision; not authenticated authorization.",
            )
        return (
            "not-fulfilled",
            "Imported record visibility is declined, undecided or lacks a current owner signature.",
        )
    if identifier == "BOUNDED-IDENTITY":
        bounded = [
            item
            for item in instance.transport
            if strategy(item.strategy, item.version).gate == "bounded"
        ]
        decisions = {item.profile: item for item in instance.decisions.bounded}
        if any(item.id not in decisions for item in bounded):
            return "not-fulfilled", "A bounded profile lacks its T/K/residual decision."
        if any(not decisions[item.id].signed_by for item in bounded):
            return "not-fulfilled", "A bounded profile has no owner signature."
        if any(
            assess_bounded_safety(
                decisions[item.id].max_age_seconds,
                decisions[item.id].unknown_limit,
                decisions[item.id].residual,
                decisions[item.id].signed_by,
                decisions[item.id].signed_at,
                interval_seconds=instance.supervision.reconcile_seconds,
                now=now,
            ).status
            == "not-fulfilled"
            for item in bounded
        ):
            return "not-fulfilled", "A bounded decision is invalid or has a future signature."
        return (
            "fulfilled-unverified",
            "Configured T/K and residual do not establish the whole-pass withdrawal bound.",
        )
    if identifier == "BOOT-RECOVERY":
        filevault = fact_view(evidence, "filevault", now)
        reported = _reported(evidence, "filevault")
        baseline = instance.host.baseline.filevault
        decision = instance.decisions.unattended_recovery
        # Only a current observation says off. A reported on blocks at any age, and
        # the declared baseline speaks when nothing current is observed.
        off = filevault["state"] == "present" and filevault["value"] == "off"
        if (reported is not None and reported.value == "on") or (not off and baseline is True):
            return (
                "not-fulfilled",
                "FileVault needs a person; automatic login cannot establish unattended recovery.",
            )
        if decision.accepted is not True or decision.max_dns_ready_seconds is None:
            return "not-fulfilled", "Unattended recovery and its DNS-ready limit are undecided."
        if not off and baseline is not False:
            return (
                "not-fulfilled",
                "FileVault is neither currently observed off nor declared off.",
            )
    if identifier == "PLATFORM-SUPPORT":
        values = [
            fact_view(evidence, key, now)
            for key in ("macos_version", "macos_build", "runtime_version", "hardware_class")
        ]
        if any(item["state"] != "present" for item in values):
            return "not-fulfilled", "Required current hardware/platform facts are unknown."
        if (
            not candidate_matches(
                str(values[0]["value"]), str(values[1]["value"]), str(values[2]["value"])
            )
            or values[3]["value"] != "apple-silicon"
        ):
            return (
                "not-fulfilled",
                "Observed host differs from the declared candidate platform; read-only only.",
            )
    if (
        identifier == "CONSENT-IDENTITY"
        and fact_view(evidence, "local_network_identity", now)["state"] != "present"
    ):
        return "not-fulfilled", "Real LaunchAgent Local Network identity has not been observed."
    if identifier == "LAN-IDENTITY":
        for key, declared in (
            ("lan_hardware_id", instance.host.lan.hardware_id),
            ("lan_ipv4", instance.host.lan.ipv4),
        ):
            view = fact_view(evidence, key, now)
            if view["state"] != "present" or view["value"] != declared:
                return (
                    "not-fulfilled",
                    "LAN stable identity or current address is unknown or differs.",
                )
    for key in BLOCKING_FACTS.get(identifier, ()):
        negative = _reported(evidence, key)
        if negative is not None and (negative.state == "absent" or negative.value is False):
            return "not-fulfilled", "Host evidence reports this prerequisite as absent."
    return (
        "fulfilled-unverified",
        "Declared capability requires its proving test at the recorded host tier.",
    )


def _deviation(instance: Instance, identifier: str, now: float) -> tuple[str, str] | None:
    """A recorded deviation means the requirement is not met, accepted or not."""
    named = [item for item in instance.deviations if item.requirement == identifier]
    if not named:
        return None
    for item in named:
        if not item.statement.strip():
            return "not-fulfilled", "A recorded deviation has no nonblank statement to accept."
        if (
            item.accepted_by is None
            or not item.accepted_by.strip()
            or item.accepted_at is None
            or datetime.strptime(item.accepted_at, "%Y-%m-%dT%H:%M:%SZ")
            .replace(tzinfo=UTC)
            .timestamp()
            > now
        ):
            return (
                "not-fulfilled",
                "A recorded deviation from this requirement has no current owner acceptance.",
            )
    if identifier in MANDATORY_PROVING_GATES:
        return (
            "not-fulfilled",
            "An owner-accepted deviation cannot replace this mandatory proving gate.",
        )
    return "accepted-residual", "Owner-accepted deviation; the requirement itself is not met."


def _state_layers(
    expected: str, current: ProfileEvidence | None, observations: dict[str, Any], now: float
) -> dict[str, Any]:
    receipt = None if current is None else current.receipt
    return {
        "desired": {"state": "present", "digest": expected, "authority": "canonical-instance"},
        "admitted": {
            "state": "unknown" if current is None or current.admitted_digest is None else "present",
            "digest": None if current is None else current.admitted_digest,
            "authority": "owner-reported, unverified; not authorization",
        },
        "observed": observations,
        "applied": {
            "state": "unknown" if current is None or current.applied_digest is None else "present",
            "digest": None if current is None else current.applied_digest,
            "authority": "owner-reported, unverified; not readback",
        },
        "receipt": {
            "state": "unknown" if receipt is None else "present",
            "record": receipt,
            "age_seconds": None if receipt is None else max(0, now - receipt["recorded_at"]),
            "historical": True,
            "current_authority": False,
        },
    }


def build_report(
    instance: Instance,
    evidence: HostEvidence,
    *,
    now: float,
    data_directory: Path,
    release_verified: bool = False,
    evidence_directory: Path | None = None,
) -> dict[str, Any]:
    contracts = verify_contracts(instance, data_directory)
    rows: list[dict[str, Any]] = []
    for requirement in REQUIREMENTS:
        if not _applicable(instance, requirement):
            status, reason = "not-applicable", "No corresponding declared capability."
        else:
            status, reason = _base_assessment(
                instance, requirement, evidence, now, contracts, release_verified
            )
            if (
                requirement.id
                not in {
                    "BOUNDED-IDENTITY",
                    "PLATFORM-SUPPORT",
                    "IMPORT-VISIBILITY",
                    "LIFECYCLE-WRITERS",
                }
                and status != "not-fulfilled"
                and _acceptance(instance, requirement, evidence, now, evidence_directory)
            ):
                status, reason = (
                    "fulfilled-verified",
                    "Current content-bound owner acceptance and retained evidence hash verified.",
                )
            deviation = _deviation(instance, requirement.id, now)
            # Never better than an accepted residual, and never a lift for a row that is
            # not fulfilled for another reason.
            if deviation is not None and (
                deviation[0] == "not-fulfilled" or status != "not-fulfilled"
            ):
                status, reason = deviation
        rows.append(
            {
                "id": requirement.id,
                "statement": requirement.statement,
                "source": requirement.source,
                "status": status,
                "reason": reason,
                "proving_tests": list(requirement.proving_tests),
                "required_methods": list(requirement.acceptance_methods),
                "minimum_tier": requirement.minimum_tier,
            }
        )
    profiles: list[dict[str, Any]] = []
    for item in instance.transport:
        expected = resolved_profile_digest(instance, item)
        current = next((value for value in evidence.profiles if value.id == item.id), None)
        decision = next(
            (value for value in instance.decisions.bounded if value.profile == item.id), None
        )
        maximum = decision.max_age_seconds if decision is not None else MAX_FACT_AGE_SECONDS
        layers = {
            key: observation_view(
                getattr(current, key) if current is not None else None, now, maximum
            )
            for key in ("transport", "discovery", "probe", "application", "heard_audio")
        }
        safety = (
            None
            if decision is None
            else assessment_to_dict(
                assess_bounded_safety(
                    decision.max_age_seconds,
                    decision.unknown_limit,
                    decision.residual,
                    decision.signed_by,
                    decision.signed_at,
                    interval_seconds=instance.supervision.reconcile_seconds,
                    now=now,
                )
            )
        )
        profiles.append(
            {
                "id": item.id,
                "strategy": item.strategy,
                "strategy_version": item.version,
                "gate": strategy(item.strategy, item.version).gate,
                "desired_digest": expected,
                "owner_desired_digest": None if current is None else current.desired_digest,
                "admitted_digest": None if current is None else current.admitted_digest,
                "applied_digest": None if current is None else current.applied_digest,
                "pending": current is None or current.admitted_digest != expected,
                "paused": None if current is None else current.paused,
                "suspensions": [] if current is None else list(current.suspensions),
                "observations": layers,
                "states": _state_layers(expected, current, layers, now),
                "composite": "transport-"
                + layers["transport"]["state"]
                + ", discovery-"
                + layers["discovery"]["state"],
                "preserves_client_identity": strategy(
                    item.strategy, item.version
                ).preserves_client_identity,
                "safety": safety,
                "observation_authority": "owner-reported; never root admission authority",
            }
        )
    discovery_rows: list[dict[str, Any]] = []
    for selection in instance.discovery:
        expected = resolved_discovery_digest(instance, selection)
        current = next((value for value in evidence.profiles if value.id == selection.id), None)
        layers = {
            key: observation_view(
                getattr(current, key) if current is not None else None, now, MAX_FACT_AGE_SECONDS
            )
            for key in ("transport", "discovery", "probe", "application", "heard_audio")
        }
        dependencies = [
            {
                "id": dependency,
                "transport": next(value for value in profiles if value["id"] == dependency)[
                    "observations"
                ]["transport"],
            }
            for dependency in selection.dependencies
        ]
        discovery_rows.append(
            {
                "id": selection.id,
                "profile": selection.profile,
                "profile_version": selection.version,
                "direction": selection.direction,
                "desired_digest": expected,
                "owner_desired_digest": None if current is None else current.desired_digest,
                "dependencies": dependencies,
                "states": _state_layers(expected, current, layers, now),
                "observations": layers,
                "pending": current is None or current.admitted_digest != expected,
                "paused": None if current is None else current.paused,
                "suspensions": [] if current is None else list(current.suspensions),
                "composite": "discovery-"
                + layers["discovery"]["state"]
                + ", dependencies-"
                + (
                    "present"
                    if all(value["transport"]["state"] == "present" for value in dependencies)
                    else "unknown"
                ),
                "native_proving_methods": list(
                    discovery_profile(selection.profile, selection.version).proving_tests
                ),
                "observation_authority": "owner-reported; never root admission authority",
            }
        )
    observed_platform = [
        fact_view(evidence, key, now)
        for key in ("macos_version", "macos_build", "runtime_version", "hardware_class")
    ]
    compatible = (
        all(item["state"] == "present" for item in observed_platform)
        and candidate_matches(*(str(item["value"]) for item in observed_platform[:3]))
        and observed_platform[3]["value"] == "apple-silicon"
    )
    accepted = (
        next(item for item in rows if item["id"] == "PLATFORM-SUPPORT")["status"]
        == "fulfilled-verified"
        and (
            instance.host.platform.macos_version,
            instance.host.platform.macos_build,
            instance.host.runtime.version,
        )
        in ACCEPTED_PLATFORMS
    )
    current_ready = (
        evidence.source != "synthetic"
        and all(
            row["paused"] is False
            and not row["suspensions"]
            and row["owner_desired_digest"]
            == row["desired_digest"]
            == row["admitted_digest"]
            == row["applied_digest"]
            and row["observations"]["transport"]["state"] == "present"
            for row in profiles
        )
        and all(
            row["paused"] is False
            and not row["suspensions"]
            and row["owner_desired_digest"]
            == row["states"]["admitted"]["digest"]
            == row["desired_digest"]
            == row["states"]["applied"]["digest"]
            and row["observations"]["discovery"]["state"] == "present"
            and row["observations"]["application"]["state"] == "present"
            and all(
                dependency["transport"]["state"] == "present" for dependency in row["dependencies"]
            )
            for row in discovery_rows
        )
    )
    workload_rows: list[dict[str, Any]] = []
    for workload in instance.workloads:
        own_observation = observation_view(
            next(
                (value.observation for value in evidence.workloads if value.id == workload.id), None
            ),
            now,
            MAX_FACT_AGE_SECONDS,
        )
        components: list[dict[str, Any]] = [
            {
                "id": component.id,
                "recovery": component.recovery,
                "workload_restart_authorized": False,
                "observation": observation_view(
                    next(
                        (
                            value.observation
                            for value in evidence.components
                            if value.service == workload.id and value.id == component.id
                        ),
                        None,
                    ),
                    now,
                    MAX_FACT_AGE_SECONDS,
                ),
            }
            for component in workload.components
        ]
        related = [own_observation] + [component["observation"] for component in components]
        related.extend(
            row["observations"]["transport"]
            for declared, row in zip(instance.transport, profiles, strict=True)
            if declared.service == workload.id
        )
        for declared, row in zip(instance.discovery, discovery_rows, strict=True):
            if declared.service == workload.id:
                related.extend(
                    (row["observations"]["discovery"], row["observations"]["application"])
                )
        consistent = (
            all(value["state"] == "present" for value in related)
            and len({value["generation"] for value in related}) == 1
        )
        current_ready = current_ready and consistent
        workload_rows.append(
            {
                "id": workload.id,
                "recovery": workload.recovery,
                "observation": own_observation,
                "components": components,
                "current_generation_consistent": consistent,
                "workload_restart_authorized": False,
            }
        )
    fully_served = (
        all(
            item["status"] in {"fulfilled-verified", "accepted-residual", "not-applicable"}
            for item in rows
        )
        and release_verified
        and accepted
        and current_ready
    )
    return {
        "schema_version": 1,
        "instance": instance.instance,
        "instance_digest": instance_digest(instance),
        "contract_digest": instance_contract_digest(instance),
        "generated_at": now,
        "read_only": True,
        "mutation_available": False,
        "fully_served": fully_served,
        "current_ready": current_ready,
        "current_readiness_authority": (
            "Local owner-reported evidence; not independently verified or mutation authority"
        ),
        "evidence_source": evidence.source,
        "acceptance_authority": (
            "Owner-recorded attestations and local evidence content; "
            "not independently replayed and never root authorization."
        ),
        "platform": {
            "candidate_parser_compatible": compatible,
            "host_accepted": accepted,
            "mutation_qualified": False,
        },
        "ipv6": "outside the custom policy, not blocked",
        "names": resolved_names(instance),
        "contracts": contracts,
        "facts": [fact_view(evidence, key, now) for key in FACT_KEYS],
        "profiles": profiles,
        "discovery_profiles": discovery_rows,
        "workloads": workload_rows,
        "requirements": rows,
        "deviations": [asdict(item) for item in instance.deviations],
        "lifecycle_tools": [asdict(item) for item in instance.lifecycle_tools],
        "retirement": [
            asdict(item)
            for item in STRATEGIES
            if any(profile.strategy == item.name for profile in instance.transport)
        ],
        "platform_facts": [asdict(item) for item in FACTS],
    }

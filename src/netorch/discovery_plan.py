"""Pure, dependency-gated discovery lease intent for independent user owners.

An inactive action requests cleanup of only that owner's scoped publication.
It never starts a guest, changes a packet rule, or fabricates discovery records.
Actual registration, source eligibility and record ownership stay in the owner.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, replace

from .codec import digest
from .config import config_digest, profile_digest, validate_config
from .model import Config, Discovery
from .planner import Plan
from .state import Intent, Observation, Snapshot, snapshot_digest

DISCOVERY_REASONS = frozenset(
    {
        "ready",
        "verified",
        "intent-damaged",
        "paused",
        "suspended",
        "transport-plan-stale",
        "transport-unverified",
        "service-unknown",
        "service-absent",
        "service-stale",
        "service-future",
        "contract-mismatch",
        "generation-unknown",
        "publisher-unknown",
        "publisher-stale",
        "publisher-future",
        "publisher-generation-changed",
        "interface-unconfirmed",
        "policy-changed",
        "network-unknown",
        "snapshot-stale",
        "snapshot-future",
    }
)
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9-]*\Z")


@dataclass(frozen=True, slots=True)
class DiscoveryAction:
    id: str
    owner: str
    active: bool
    reason: str
    policy_digest: str
    service_generation: str | None = None
    network_generation: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.id, str)
            or not _ID.fullmatch(self.id)
            or not isinstance(self.owner, str)
            or not _ID.fullmatch(self.owner)
        ):
            raise ValueError("invalid discovery action identity")
        if not isinstance(self.active, bool):
            raise ValueError("discovery active flag must be boolean")
        if not isinstance(self.reason, str) or self.reason not in DISCOVERY_REASONS:
            raise ValueError("invalid discovery action reason")
        if not isinstance(self.policy_digest, str) or not _HASH.fullmatch(self.policy_digest):
            raise ValueError("invalid discovery policy digest")
        if self.active != (self.reason in {"ready", "verified"}):
            raise ValueError("discovery activity must match its decision reason")
        for generation in (self.service_generation, self.network_generation):
            if generation is not None and (
                not isinstance(generation, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", generation)
            ):
                raise ValueError("invalid discovery generation")
        if self.active and (self.service_generation is None or self.network_generation is None):
            raise ValueError("active discovery requires service and network generations")


def discovery_digest(config: Config, item: Discovery) -> str:
    """Bind resolved policy, dependencies and the v2 discovery selector contract.

    V2 binds related records by ASCII DNS hostname plus address and excludes
    both projection prefixes case-insensitively. V1 approval cannot enable it.
    """
    service = config.service(item.service)
    return digest(
        {
            "digest_version": 2,
            "schema_version": config.schema_version,
            "discovery": asdict(item),
            "scope": asdict(config.scope(item.scope)),
            "service": asdict(service),
            "service_owner": asdict(config.owner(service.owner)),
            "owner": asdict(config.owner(item.owner)),
            "dependencies": {
                identifier: profile_digest(config, config.profile(identifier))
                for identifier in sorted(item.dependencies)
            },
        }
    )


def _unobserved(now: float) -> Observation:
    return Observation("unknown", "unobserved", now, None)


def _dependencies_verified(
    config: Config, item: Discovery, snapshot: Snapshot, transport: Plan, now: float
) -> bool:
    if not set(item.dependencies) <= transport.ready_profiles:
        return False
    for identifier in item.dependencies:
        dependency = config.profile(identifier)
        decisions = [action for action in transport.actions if action.profile == identifier]
        if (
            len(decisions) != 1
            or decisions[0].operation != "noop"
            or decisions[0].reason != "verified"
            or decisions[0].owner != config.profile_owner(dependency).id
        ):
            return False
        decision = decisions[0]
        applied = snapshot.profiles.get(identifier, _unobserved(now)).at(
            now,
            dependency.safety.max_age_seconds,
        )
        service = config.service(dependency.service)
        endpoint = snapshot.services.get(service.id, _unobserved(now)).at(
            now,
            dependency.safety.max_age_seconds,
        )
        fallback = decision.effective_strategy == "degraded-fallback"
        if fallback and (
            dependency.fallback_publication is None
            or applied.data.get("direct_available") is not False
            or not _dependencies_verified(
                config,
                replace(item, dependencies=(dependency.fallback_publication,)),
                snapshot,
                transport,
                now,
            )
        ):
            return False
        target = (
            config.scope(dependency.scope).host_ipv4
            if dependency.kind == "host-redirect" or fallback
            else endpoint.data.get("ipv4")
        )
        if (
            applied.state != "present"
            or endpoint.state != "present"
            or endpoint.generation is None
            or endpoint.data.get("contract_sha256") != service.contract_sha256
            or applied.data.get("policy_digest") != profile_digest(config, dependency)
            or applied.data.get("target_ipv4") != target
            or applied.data.get("target_generation") != endpoint.generation
            or applied.data.get("network_generation") != snapshot.network_generation
            or applied.data.get("effective_strategy") != decision.effective_strategy
            or decision.target_ipv4 != target
            or decision.target_generation != endpoint.generation
            or not isinstance(applied.data.get("states"), tuple)
        ):
            return False
    return True


def _reason(
    config: Config,
    item: Discovery,
    snapshot: Snapshot,
    transport: Plan,
    intent: Intent,
    now: float,
    policy_digest: str,
) -> str:
    if intent.damaged:
        return "intent-damaged"
    if intent.operator_paused:
        return "paused"
    if intent.suspensions:
        return "suspended"
    if (
        transport.policy_digest != config_digest(config)
        or transport.snapshot_digest != snapshot_digest(snapshot)
        or transport.intent_revision != intent.revision
    ):
        return "transport-plan-stale"
    if snapshot.network_generation is None:
        return "network-unknown"
    if snapshot.observed_at > now:
        return "snapshot-future"
    if now - snapshot.observed_at > item.max_age_seconds:
        return "snapshot-stale"
    endpoint = snapshot.services.get(item.service, _unobserved(now)).at(now, item.max_age_seconds)
    if endpoint.state == "unknown":
        return (
            "service-stale"
            if endpoint.reason == "stale"
            else "service-future"
            if endpoint.reason == "future"
            else "service-unknown"
        )
    if endpoint.state == "absent":
        return "service-absent"
    if endpoint.generation is None:
        return "generation-unknown"
    if endpoint.data.get("contract_sha256") != config.service(item.service).contract_sha256:
        return "contract-mismatch"
    if not _dependencies_verified(config, item, snapshot, transport, now):
        return "transport-unverified"
    publisher = snapshot.profiles.get(item.id, _unobserved(now)).at(now, item.max_age_seconds)
    if publisher.state == "unknown":
        return (
            "publisher-stale"
            if publisher.reason == "stale"
            else "publisher-future"
            if publisher.reason == "future"
            else "publisher-unknown"
        )
    if publisher.data.get("interface_confirmed") is not True:
        return "interface-unconfirmed"
    if (
        publisher.data.get("service_generation") != endpoint.generation
        or publisher.data.get("network_generation") != snapshot.network_generation
    ):
        return "publisher-generation-changed"
    if publisher.state == "present":
        if publisher.data.get("policy_digest") != policy_digest:
            return "policy-changed"
        return "verified"
    return "ready"


def plan_discovery(
    config: Config, snapshot: Snapshot, transport: Plan, intent: Intent, now: float
) -> tuple[DiscoveryAction, ...]:
    """Produce safe publication/withdrawal intent; this function invokes nothing.

    A missing, denied or otherwise unknown publisher always produces inactive
    cleanup intent. Complete absence with a confirmed interface permits an
    activation only after all dependency and service gates are satisfied.
    """
    if (
        isinstance(now, bool)
        or not isinstance(now, (float, int))
        or not math.isfinite(now)
        or now < 0
    ):
        raise ValueError("now must be a finite nonnegative timestamp")
    validate_config(config)
    result = []
    for item in sorted(config.discovery, key=lambda policy: policy.id):
        policy_digest = discovery_digest(config, item)
        reason = _reason(config, item, snapshot, transport, intent, float(now), policy_digest)
        endpoint = snapshot.services.get(item.service, _unobserved(float(now)))
        result.append(
            DiscoveryAction(
                item.id,
                item.owner,
                reason in {"ready", "verified"},
                reason,
                policy_digest,
                endpoint.generation,
                snapshot.network_generation,
            )
        )
    return tuple(result)

"""Pure, conservative orchestration plans with explicit evidence fencing.

This module never invokes an owner.  An external-root action is only a proposal;
the root owner must independently read its admitted policy and current evidence.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .config import config_digest, profile_digest, validate_config
from .model import Config, Profile
from .state import Admission, Intent, Observation, Snapshot, snapshot_digest

OPERATIONS = frozenset({"activate", "withdraw", "drain", "noop", "pending", "blocked"})
ACTION_REASONS = frozenset(
    {
        "verified",
        "not-admitted",
        "risk-unacknowledged",
        "admission-future",
        "paused",
        "suspended",
        "intent-damaged",
        "endpoint-unknown",
        "endpoint-absent",
        "contract-mismatch",
        "endpoint-invalid",
        "network-unknown",
        "snapshot-stale",
        "profile-unknown",
        "target-replaced",
        "policy-changed",
        "retained-states",
        "ready",
        "invalid-readback",
        "publication-not-ready",
    }
)
_HASH = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class Action:
    profile: str
    owner: str
    operation: str
    reason: str
    target_ipv4: str | None = None
    target_generation: str | None = None
    effective_strategy: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.profile, str) or not self.profile:
            raise ValueError("action needs a profile")
        if not isinstance(self.owner, str) or not self.owner:
            raise ValueError("action needs an owner")
        if self.effective_strategy not in {None, "degraded-fallback"}:
            raise ValueError("invalid effective transport strategy")
        if self.operation not in OPERATIONS or self.reason not in ACTION_REASONS:
            raise ValueError("invalid action operation or reason")
        if self.target_ipv4 is not None:
            ipaddress.IPv4Address(self.target_ipv4)
        if self.target_generation is not None and (
            not isinstance(self.target_generation, str) or not self.target_generation
        ):
            raise ValueError("invalid action target generation")


@dataclass(frozen=True, slots=True)
class Plan:
    policy_digest: str
    snapshot_digest: str
    intent_revision: int
    actions: tuple[Action, ...]

    def __post_init__(self) -> None:
        if not _HASH.fullmatch(self.policy_digest) or not _HASH.fullmatch(self.snapshot_digest):
            raise ValueError("invalid plan digest")
        if type(self.intent_revision) is not int or self.intent_revision < 0:
            raise ValueError("invalid plan intent revision")
        if not all(isinstance(action, Action) for action in self.actions):
            raise ValueError("invalid plan actions")
        object.__setattr__(self, "actions", tuple(self.actions))

    @property
    def ready_profiles(self) -> frozenset[str]:
        """Only verified readback satisfies a discovery dependency."""
        return frozenset(action.profile for action in self.actions if action.operation == "noop")


def _unknown(now: float) -> Observation:
    return Observation("unknown", "unobserved", now, None)


def _valid_ipv4(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        return None


def _existing_target(observation: Observation) -> tuple[str | None, str | None]:
    ipv4 = _valid_ipv4(observation.data.get("target_ipv4"))
    generation = observation.data.get("target_generation")
    if not isinstance(generation, str) or not generation:
        generation = None
    return ipv4, generation


def _has_states(observation: Observation) -> bool:
    return bool(observation.data.get("states"))


def _retire(profile: Profile, owner: str, observation: Observation, reason: str) -> list[Action]:
    """Never activate a replacement in the same plan as retirement."""
    target, generation = _existing_target(observation)
    actions = []
    if observation.state == "present" or target is not None:
        actions.append(Action(profile.id, owner, "withdraw", reason, target, generation))
    if observation.state == "present" or target is not None or _has_states(observation):
        actions.append(Action(profile.id, owner, "drain", reason, target, generation))
    return actions


def _profile_plan(
    config: Config,
    profile: Profile,
    snapshot: Snapshot,
    admissions: Mapping[str, Admission],
    intent: Intent,
    now: float,
) -> list[Action]:
    service = config.service(profile.service)
    scope = config.scope(profile.scope)
    owner = config.profile_owner(profile).id
    max_age = profile.safety.max_age_seconds
    raw_profile = snapshot.profiles.get(profile.id, _unknown(now))
    current = raw_profile.at(now, max_age)
    endpoint = snapshot.services.get(service.id, _unknown(now)).at(now, max_age)
    digest = profile_digest(config, profile)

    def inhibit(reason: str, operation: str = "blocked") -> list[Action]:
        retired = _retire(profile, owner, raw_profile, reason)
        return [*retired, Action(profile.id, owner, operation, reason)]

    if intent.damaged:
        return inhibit("intent-damaged")
    if intent.operator_paused:
        return inhibit("paused")
    if intent.suspensions:
        return inhibit("suspended")

    admission = admissions.get(profile.id)
    if admission is None or admission.profile != profile.id or admission.digest != digest:
        return inhibit("not-admitted", "pending")
    if admission.approved_at > now:
        return inhibit("admission-future", "pending")
    # Repeated on every pass: an approval record without the acknowledgement
    # never activates a bounded target or a rule that matches every source.
    if (
        profile.safety.kind == "bounded" or profile.source_scope != "lan"
    ) and not admission.risk_acknowledged:
        return inhibit("risk-unacknowledged", "pending")
    if snapshot.network_generation is None:
        return inhibit("network-unknown")
    if snapshot.observed_at > now or now - snapshot.observed_at > max_age:
        return inhibit("snapshot-stale")
    if endpoint.state == "unknown":
        return inhibit("endpoint-unknown")
    if endpoint.state == "absent":
        return inhibit("endpoint-absent")
    if endpoint.data.get("contract_sha256") != service.contract_sha256:
        return inhibit("contract-mismatch")
    if endpoint.generation is None:
        return inhibit("endpoint-invalid")
    guest_ipv4 = _valid_ipv4(endpoint.data.get("ipv4"))
    guest_network = ipaddress.IPv4Network(scope.guest_cidr)
    if (
        guest_ipv4 is None
        or ipaddress.IPv4Address(guest_ipv4) not in guest_network
        or (
            guest_network.prefixlen < 31
            and ipaddress.IPv4Address(guest_ipv4)
            in {guest_network.network_address, guest_network.broadcast_address}
        )
    ):
        return inhibit("endpoint-invalid")
    # A host redirect has a structurally fixed host socket target.  Direct
    # guest publications and UDP return profiles bind the current guest.
    target = scope.host_ipv4 if profile.kind == "host-redirect" else guest_ipv4
    target_generation = endpoint.generation
    strategy = None
    if profile.fallback_publication is not None and current.data.get("direct_available") is False:
        backing = config.profile(profile.fallback_publication)
        backing_actions = _profile_plan(config, backing, snapshot, admissions, intent, now)
        if len(backing_actions) != 1 or backing_actions[0].operation != "noop":
            return inhibit("publication-not-ready")
        target = scope.host_ipv4
        strategy = "degraded-fallback"
    if profile.kind == "host-redirect":
        # A configured socket declaration is not evidence that the matching
        # service owns today's socket.  Native publication must be independently
        # admitted and verified before the redirect can expose it.
        backing = next(
            publication
            for publication in config.profiles
            if publication.kind == "publication"
            and publication.service == profile.service
            and publication.scope == profile.scope
            and publication.protocol == profile.protocol
            and profile.target_ports is not None
            and publication.ports.contains(profile.target_ports)
        )
        backing_actions = _profile_plan(config, backing, snapshot, admissions, intent, now)
        if len(backing_actions) != 1 or backing_actions[0].operation != "noop":
            return inhibit("publication-not-ready")
    if current.state == "unknown":
        return inhibit("profile-unknown")
    states = current.data.get("states")
    if not isinstance(states, tuple):
        return inhibit("invalid-readback")
    if current.state == "absent":
        if states:
            old_target, old_generation = _existing_target(current)
            return [
                Action(profile.id, owner, "drain", "retained-states", old_target, old_generation)
            ]
        return [Action(profile.id, owner, "activate", "ready", target, target_generation, strategy)]
    if current.data.get("policy_digest") != digest:
        return _retire(profile, owner, raw_profile, "policy-changed")
    if (
        current.data.get("target_ipv4") != target
        or current.data.get("target_generation") != target_generation
        or current.data.get("network_generation") != snapshot.network_generation
        or current.data.get("effective_strategy") != strategy
    ):
        return _retire(profile, owner, raw_profile, "target-replaced")
    return [Action(profile.id, owner, "noop", "verified", target, target_generation, strategy)]


def plan(
    config: Config,
    snapshot: Snapshot,
    admissions: Mapping[str, Admission],
    intent: Intent,
    now: float,
) -> Plan:
    """Return deterministic instructions; unknown never initiates recovery.

    A configured unknown_limit is an upper bound for an owner's observation
    retries.  This planner conservatively retires exposure at the first unknown
    identity rather than retaining a potentially stale address for that limit.
    """
    if (
        isinstance(now, bool)
        or not isinstance(now, (int, float))
        or not math.isfinite(now)
        or now < 0
    ):
        raise ValueError("now must be a finite nonnegative timestamp")
    validate_config(config)
    if any(key != value.profile for key, value in admissions.items()):
        raise ValueError("admission key does not match profile")
    actions = tuple(
        action
        for profile in sorted(config.profiles, key=lambda p: p.id)
        for action in _profile_plan(config, profile, snapshot, admissions, intent, float(now))
    )
    return Plan(config_digest(config), snapshot_digest(snapshot), intent.revision, actions)


def plan_to_dict(value: Plan) -> dict[str, Any]:
    return {
        "policy_digest": value.policy_digest,
        "snapshot_digest": value.snapshot_digest,
        "intent_revision": value.intent_revision,
        "actions": [
            {
                "profile": action.profile,
                "owner": action.owner,
                "operation": action.operation,
                "reason": action.reason,
                "target_ipv4": action.target_ipv4,
                "target_generation": action.target_generation,
                **(
                    {"effective_strategy": action.effective_strategy}
                    if action.effective_strategy is not None
                    else {}
                ),
            }
            for action in value.actions
        ],
    }


def plan_from_dict(value: object) -> Plan:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"policy_digest", "snapshot_digest", "intent_revision", "actions"}
        or not isinstance(value["actions"], list)
    ):
        raise ValueError("invalid plan fields")
    actions = []
    for raw in value["actions"]:
        required = {
            "profile",
            "owner",
            "operation",
            "reason",
            "target_ipv4",
            "target_generation",
        }
        if not isinstance(raw, Mapping) or set(raw) not in (
            required,
            required | {"effective_strategy"},
        ):
            raise ValueError("invalid action fields")
        actions.append(Action(**raw))
    return Plan(
        value["policy_digest"], value["snapshot_digest"], value["intent_revision"], tuple(actions)
    )

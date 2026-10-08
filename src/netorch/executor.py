"""Fenced user-owner execution with explicit partial-completion journals."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from .codec import digest
from .config import config_digest, profile_digest
from .discovery_plan import plan_discovery
from .model import Config
from .owners import ExternalOwnerRequired, OwnerClient, OwnerFailure
from .planner import Plan, plan, plan_to_dict
from .state import (
    Admission,
    Intent,
    Snapshot,
    intent_from_dict,
    intent_to_dict,
    snapshot_digest,
    snapshot_to_dict,
)
from .storage import Store


class StalePlan(RuntimeError):
    pass


@dataclass(frozen=True)
class Execution:
    phase: str
    completed: int
    pending: tuple[str, ...]


def execute(
    config: Config,
    reviewed: Plan,
    snapshot: Snapshot,
    intent: Intent,
    clients: Mapping[str, OwnerClient],
    store: Store,
    *,
    admissions: Mapping[str, Admission],
    now: float,
    observe_now: Callable[[], Snapshot] | None = None,
    clock: Callable[[], float] | None = None,
) -> Execution:
    """Execute user owner work only; external-root plans stay external.

    This function does not call sudo, pfctl or a privileged RPC. Providers must
    independently revalidate their action against live identity before mutating.
    A journal write failure or owner failure stops subsequent actions.
    """
    with store.lock():
        simulation = bool(clients) and all(client.simulation for client in clients.values())
        current_time = clock or ((lambda: now) if simulation else time.time)
        try:
            durable_intent = intent_from_dict(store.read("intent.json"))
        except FileNotFoundError:
            if not simulation:
                raise StalePlan("live execution requires durable operator intent") from None
            durable_intent = intent
        if durable_intent != intent:
            raise StalePlan("durable operator intent changed after planning")
        if (
            reviewed.policy_digest != config_digest(config)
            or reviewed.snapshot_digest != snapshot_digest(snapshot)
            or reviewed.intent_revision != intent.revision
        ):
            raise StalePlan("policy, observation or operator intent changed after planning")
        current = observe_now() if observe_now is not None else snapshot
        if observe_now is None and any(not client.simulation for client in clients.values()):
            raise StalePlan("live execution requires a fresh owner observation under the lock")

        # Fresh observation timestamps may differ without changing identity. The
        # complete rederived action list must still exactly match the reviewed
        # plan; user-edited actions cannot ride along on otherwise valid hashes.
        def evidence_digest(value: Snapshot) -> str:
            document = snapshot_to_dict(value)
            document.pop("observed_at")
            for group in ("services", "profiles"):
                for observation in document[group].values():
                    observation.pop("observed_at")
            return digest(document)

        if evidence_digest(current) != evidence_digest(snapshot):
            raise StalePlan("fresh owner identity/readback changed after planning")
        expected = plan(config, current, admissions, durable_intent, current_time())
        if expected.actions != reviewed.actions or expected.policy_digest != reviewed.policy_digest:
            raise StalePlan("fresh owner evidence or admission changed the reviewed operations")
        discovery = plan_discovery(config, current, expected, durable_intent, current_time())
        if discovery != plan_discovery(config, snapshot, reviewed, intent, now):
            raise StalePlan("fresh discovery evidence changed the reviewed operations")
        try:
            previous = store.read("journal.json")
        except FileNotFoundError:
            previous = None
        if previous is not None:
            if (
                not isinstance(previous, dict)
                or type(previous.get("schema_version")) is not int
                or previous.get("schema_version") != 1
                or previous.get("phase")
                not in {
                    "planned",
                    "applying",
                    "failed",
                    "waiting-external-owner",
                    "committed",
                    "inhibited",
                }
            ):
                raise OwnerFailure("unknown journal format requires explicit operator recovery")
            if previous["phase"] in {"planned", "applying", "failed"}:
                raise OwnerFailure(
                    "unfinished journal needs explicit phase-aware operator recovery"
                )
        document: dict[str, Any] = {
            "schema_version": 1,
            "plan_digest": digest(plan_to_dict(reviewed)),
            "phase": "planned",
            "completed": 0,
            "updated_at": time.time(),
            "pending": [],
            "plan": plan_to_dict(reviewed),
            "initial_snapshot": snapshot_to_dict(current),
            "intent": intent_to_dict(durable_intent),
            "discovery": [asdict(action) for action in discovery],
        }
        store.write("journal.json", document)
        pending: list[str] = []
        completed = 0
        # Withdraw publication before a transport dependency is retired. Active
        # leases require dependencies already verified in this fresh snapshot;
        # newly applied packet policy cannot publish in the same cycle.
        discovery_unresolved = False
        for decision in discovery:
            item = next(policy for policy in config.discovery if policy.id == decision.id)
            evidence = current.profiles.get(item.id)
            readback = evidence.at(current_time(), item.max_age_seconds) if evidence else None
            complete = bool(
                readback is not None
                and readback.state == ("present" if decision.active else "absent")
                and readback.data.get("policy_digest") == decision.policy_digest
                and readback.data.get("interface_confirmed") is True
                and readback.data.get("service_generation") == decision.service_generation
                and readback.data.get("network_generation") == decision.network_generation
            )
            discovery_unresolved |= decision.reason not in {
                "ready",
                "verified",
                "paused",
                "suspended",
                "held",
                "service-absent",
            }
            if complete:
                continue
            client = clients.get(decision.owner)
            if client is None:
                pending.append(item.id)
                continue
            document.update(phase="applying", action=item.id, operation="reconcile-discovery")
            store.write("journal.json", document)
            try:
                observed = client.reconcile_discovery(decision).at(
                    current_time(), item.max_age_seconds
                )
                if (
                    observed.state != ("present" if decision.active else "absent")
                    or observed.data.get("policy_digest") != decision.policy_digest
                    or (decision.active and observed.data.get("interface_confirmed") is not True)
                    or observed.data.get("service_generation") != decision.service_generation
                    or observed.data.get("network_generation") != decision.network_generation
                ):
                    raise OwnerFailure("publisher failed complete scoped lease readback")
                completed += 1
                document.update(completed=completed, updated_at=time.time())
                store.write("journal.json", document)
            except ExternalOwnerRequired:
                pending.append(item.id)
            except BaseException:
                document.update(phase="failed", completed=completed, updated_at=time.time())
                store.write("journal.json", document)
                raise
        for action in reviewed.actions:
            if action.operation in {"noop", "pending", "blocked"}:
                continue
            client = clients.get(action.owner)
            owner = config.owner(action.owner)
            if client is None or (owner.privilege == "external-root" and not client.simulation):
                pending.append(action.profile)
                continue
            document.update(phase="applying", action=action.profile, operation=action.operation)
            store.write("journal.json", document)
            try:
                observed = client.apply(action)
                profile = config.profile(action.profile)
                readback = observed.at(current_time(), profile.safety.max_age_seconds)
                if readback.state == "unknown":
                    raise OwnerFailure("owner returned unknown after operation")
                if not isinstance(readback.data.get("states"), tuple):
                    raise OwnerFailure("owner did not provide complete retained-state evidence")
                if action.operation == "activate" and (
                    readback.state != "present"
                    or readback.data.get("policy_digest") != profile_digest(config, profile)
                    or readback.data.get("target_ipv4") != action.target_ipv4
                    or readback.data.get("target_generation") != action.target_generation
                    or readback.data.get("network_generation") != current.network_generation
                ):
                    raise OwnerFailure("owner failed exact activation readback")
                if action.operation == "withdraw" and observed.state != "absent":
                    raise OwnerFailure("owner failed withdrawal readback")
                if action.operation == "drain" and (
                    readback.state != "absent" or readback.data["states"]
                ):
                    raise OwnerFailure("owner failed retained-state readback")
                completed += 1
                document.update(completed=completed, updated_at=time.time())
                store.write("journal.json", document)
            except ExternalOwnerRequired:
                pending.append(action.profile)
            except BaseException:
                document.update(phase="failed", completed=completed, updated_at=time.time())
                store.write("journal.json", document)
                raise
        unresolved = discovery_unresolved or any(
            a.operation in {"pending", "blocked"} for a in reviewed.actions
        )
        phase = "waiting-external-owner" if pending else "inhibited" if unresolved else "committed"
        document.update(phase=phase, pending=sorted(set(pending)), completed=completed)
        store.write("journal.json", document)
        if phase == "committed":
            store.write(
                "receipt.json",
                {
                    "schema_version": 1,
                    "policy_digest": reviewed.policy_digest,
                    "plan_digest": document["plan_digest"],
                    "completed": completed,
                    "observed_at": snapshot.observed_at,
                    "simulation": any(c.simulation for c in clients.values()),
                },
            )
        return Execution(phase, completed, tuple(sorted(set(pending))))

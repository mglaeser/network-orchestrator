"""Deterministic simulated owners; no sockets, PF, guests or application calls."""

from __future__ import annotations

import tempfile
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

from .config import profile_digest
from .discovery_plan import DiscoveryAction, discovery_digest, plan_discovery
from .executor import execute
from .model import Config
from .owners import OwnerFailure
from .planner import Action, plan, plan_to_dict
from .state import Admission, Intent, Observation, Snapshot, intent_to_dict, snapshot_to_dict
from .storage import Store


def initial_snapshot(config: Config, now: float = 1000.0) -> Snapshot:
    import ipaddress

    services: dict[str, Observation] = {}
    for index, service in enumerate(config.services):
        scope = next(
            (config.scope(p.scope) for p in config.profiles if p.service == service.id),
            config.scopes[0],
        )
        network = ipaddress.IPv4Network(scope.guest_cidr)
        if index + 10 >= network.num_addresses - 1:
            raise ValueError("example private network is too small for simulated guests")
        services[service.id] = Observation(
            "present",
            "verified",
            now,
            f"mock-{service.id}-1",
            {
                "ipv4": str(network.network_address + index + 10),
                "contract_sha256": service.contract_sha256,
            },
        )
    profiles = {
        p.id: Observation("absent", "confirmed-absent", now, None, {"states": []})
        for p in config.profiles
    }
    return Snapshot(now, "mock-network-1", services, profiles)


def mock_admissions(config: Config, now: float = 999.0) -> dict[str, Admission]:
    """Simulation fixture, never a live root admission/installer."""
    return {
        p.id: Admission(p.id, profile_digest(config, p), "simulation-only", now, True)
        for p in config.profiles
    }


class MockOwner:
    simulation = True

    def __init__(
        self, config: Config, snapshot: Snapshot, admissions: Mapping[str, Admission]
    ) -> None:
        self.config = config
        self.snapshot = snapshot
        self.admissions = admissions
        self.calls: list[Action] = []
        self.discovery_calls: list[DiscoveryAction] = []
        self.fail_on: int | None = None

    def observe(self) -> Snapshot:
        return self.snapshot

    def apply(self, action: Action) -> Observation:
        profile = self.config.profile(action.profile)
        if self.config.profile_owner(profile).id != action.owner:
            raise OwnerFailure("mock owner mismatch")
        if self.fail_on is not None and len(self.calls) + 1 == self.fail_on:
            raise OwnerFailure("injected owner fault")
        current = self.snapshot.profiles[profile.id]
        if action.operation == "activate":
            entry = self.admissions.get(profile.id)
            endpoint = self.snapshot.services[profile.service]
            now = self.snapshot.observed_at
            endpoint = endpoint.at(now, profile.safety.max_age_seconds)
            current = current.at(now, profile.safety.max_age_seconds)
            expected_target = (
                self.config.scope(profile.scope).host_ipv4
                if profile.kind == "host-redirect"
                else endpoint.data.get("ipv4")
            )
            if (
                entry is None
                or entry.profile != profile.id
                or entry.digest != profile_digest(self.config, profile)
                or entry.approved_at > now
                or (
                    (profile.safety.kind == "bounded" or profile.source_scope != "lan")
                    and not entry.risk_acknowledged
                )
                or self.snapshot.network_generation is None
                or endpoint.state != "present"
                or endpoint.generation != action.target_generation
                or endpoint.data.get("contract_sha256")
                != self.config.service(profile.service).contract_sha256
                or action.target_ipv4 != expected_target
                or current.state != "absent"
                or not isinstance(current.data.get("states"), tuple)
                or current.data.get("states")
            ):
                raise OwnerFailure("mock owner independently rejected changed preconditions")
            result = Observation(
                "present",
                "verified",
                self.snapshot.observed_at,
                endpoint.generation,
                {
                    "policy_digest": profile_digest(self.config, profile),
                    "target_ipv4": action.target_ipv4,
                    "target_generation": action.target_generation,
                    "network_generation": self.snapshot.network_generation,
                    "states": [],
                },
            )
        elif action.operation in {"withdraw", "drain"}:
            old_target = current.data.get("target_ipv4")
            if old_target is not None and old_target != action.target_ipv4:
                raise OwnerFailure("mock owner rejected mismatched retirement target")
            data = dict(current.data)
            if action.operation == "drain":
                data["states"] = []
            result = Observation(
                "absent", "confirmed-absent", self.snapshot.observed_at, current.generation, data
            )
        else:
            raise OwnerFailure("unsupported mock operation")
        profiles = dict(self.snapshot.profiles)
        profiles[profile.id] = result
        self.snapshot = replace(self.snapshot, profiles=profiles)
        self.calls.append(action)
        return result

    def reconcile_discovery(self, action: DiscoveryAction) -> Observation:
        policy = next(item for item in self.config.discovery if item.id == action.id)
        if policy.owner != action.owner or action.policy_digest != discovery_digest(
            self.config, policy
        ):
            raise OwnerFailure("mock discovery owner mismatch")
        if action.active:
            endpoint = self.snapshot.services[policy.service]
            if (
                endpoint.generation != action.service_generation
                or self.snapshot.network_generation != action.network_generation
            ):
                raise OwnerFailure("mock publisher rejected changed runtime generation")
            for dependency in policy.dependencies:
                observed = self.snapshot.profiles[dependency]
                if observed.state != "present" or observed.data.get(
                    "policy_digest"
                ) != profile_digest(self.config, self.config.profile(dependency)):
                    raise OwnerFailure("mock publisher rejected unverified transport")
        result = Observation(
            "present" if action.active else "absent",
            "verified" if action.active else "confirmed-absent",
            self.snapshot.observed_at,
            "mock-publisher-1",
            {
                "policy_digest": action.policy_digest,
                "interface_confirmed": True,
                "states": [],
                "service_generation": action.service_generation,
                "network_generation": action.network_generation,
            },
        )
        profiles = dict(self.snapshot.profiles)
        profiles[action.id] = result
        self.snapshot = replace(self.snapshot, profiles=profiles)
        self.discovery_calls.append(action)
        return result


def simulate(config: Config) -> dict[str, Any]:
    now = 1000.0
    initial = initial_snapshot(config, now)
    admissions = mock_admissions(config)
    backend = MockOwner(config, initial, admissions)
    clients = {owner.id: backend for owner in config.owners}
    intent = Intent()
    events: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="netorch-simulation-") as directory:
        store = Store(Path(directory) / "state")

        def cycle(label: str) -> None:
            candidate = plan(config, backend.snapshot, admissions, intent, now)
            store.write("intent.json", intent_to_dict(intent))
            result = execute(
                config,
                candidate,
                backend.snapshot,
                intent,
                clients,
                store,
                admissions=admissions,
                now=now,
                observe_now=backend.observe,
            )
            events.append(
                {
                    "stage": label,
                    "phase": result.phase,
                    "completed": result.completed,
                    "plan": plan_to_dict(candidate),
                }
            )

        # Demonstrate that desired policy alone cannot activate anything.
        unadmitted = plan(config, initial, {}, intent, now)
        events.append({"stage": "unadmitted", "plan": plan_to_dict(unadmitted)})
        cycle("activate")
        cycle("verify-and-complete-dependencies")
        intent = intent.suspend("mock-maintenance", "mock-holder").pause()
        cycle("withdraw-for-maintenance")
        intent = intent.release("mock-maintenance", "mock-holder")
        cycle("operator-pause-survives-release")
        intent = intent.resume()
        cycle("resume")
        target_service = config.services[0]
        import ipaddress

        scope = next(
            (config.scope(p.scope) for p in config.profiles if p.service == target_service.id),
            config.scopes[0],
        )
        used = {obs.data.get("ipv4") for obs in backend.snapshot.services.values()}
        network = ipaddress.IPv4Network(scope.guest_cidr)
        new_ip = next(
            (str(address) for address in network.hosts() if str(address) not in used), None
        )
        if new_ip is None:
            raise ValueError("simulation has no free guest address for recreation")
        services = dict(backend.snapshot.services)
        services[target_service.id] = Observation(
            "present",
            "verified",
            now,
            "mock-recreated-2",
            {
                "ipv4": new_ip,
                "contract_sha256": target_service.contract_sha256,
            },
        )
        backend.snapshot = replace(backend.snapshot, services=services)
        cycle("retire-old-generation")
        cycle("activate-new-generation")
        cycle("final-readback")
        final_plan = plan(config, backend.snapshot, admissions, intent, now)
        return {
            "simulation": True,
            "claim": "policy/owner contract behavior only; no native network or audio acceptance",
            "events": events,
            "final_snapshot": snapshot_to_dict(backend.snapshot),
            "all_verified": len(final_plan.ready_profiles) == len(config.profiles)
            and all(
                decision.reason == "verified"
                for decision in plan_discovery(config, backend.snapshot, final_plan, intent, now)
            ),
        }

"""Explicit local owner bindings; network policy cannot select executables."""

from __future__ import annotations

import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .codec import canonical_bytes, strict_load, strict_loads
from .config import config_digest, profile_digest, to_dict
from .discovery_plan import DiscoveryAction, discovery_digest
from .model import Config
from .pf_owner import reject_acl
from .planner import Action
from .process import OutputLimit, ProcessTimeout, run
from .state import Admission, Observation, Snapshot, observation_from_dict, snapshot_from_dict


class OwnerFailure(RuntimeError):
    pass


class ExternalOwnerRequired(OwnerFailure):
    pass


class OwnerClient(Protocol):
    simulation: bool

    def observe(self) -> Snapshot: ...

    def apply(self, action: Action) -> Observation: ...

    def reconcile_discovery(self, action: DiscoveryAction) -> Observation: ...


def _unknown(config: Config, owner: str, reason: str) -> Snapshot:
    now = time.time()
    services = {
        service.id: Observation("unknown", reason, now, None)
        for service in config.services
        if service.owner == owner
    }
    profiles = {
        profile.id: Observation("unknown", reason, now, None)
        for profile in config.profiles
        if config.profile_owner(profile).id == owner
    }
    profiles.update(
        {
            item.id: Observation("unknown", reason, now, None)
            for item in config.discovery
            if item.owner == owner
        }
    )
    return Snapshot(now, None, services, profiles)


def _secure_binding_file(path: Path) -> Any:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise OwnerFailure("binding file must be private and owned by the operator")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(1_048_577)
        if len(raw) > 1_048_576:
            raise OwnerFailure("binding file exceeds size bound")
        return strict_loads(raw.decode("utf-8"))
    finally:
        os.close(fd)


@dataclass
class ProcessOwner:
    config: Config
    owner: str
    argv: list[str]
    simulation: bool = False

    def _request(self, operation: str, payload: dict[str, Any]) -> Any:
        if os.geteuid() == 0:
            raise OwnerFailure("live user-owner clients must run as an unprivileged operator")
        if self.config.owner(self.owner).privilege != "user":
            raise ExternalOwnerRequired("external-root owners pull their own policy independently")
        response = run(
            self.argv,
            input_data=canonical_bytes(
                {
                    "protocol_version": 1,
                    "operation": operation,
                    "owner": self.owner,
                    **payload,
                }
            ),
            timeout=10,
        )
        if response.returncode == 78 and operation == "reconcile":
            maintenance = strict_loads(response.stdout)
            if (
                maintenance
                == {
                    "protocol_version": 1,
                    "owner": self.owner,
                    "error": "native-publication-maintenance",
                }
                and type(maintenance["protocol_version"]) is int
                and self.config.profile(payload["profile"]).kind == "publication"
            ):
                raise ExternalOwnerRequired(
                    "native publication requires explicit application maintenance"
                )
        if response.returncode:
            raise OwnerFailure("owner did not return a successful complete response")
        data = strict_loads(response.stdout.decode("utf-8"))
        if not isinstance(data, dict) or set(data) != {"protocol_version", "owner", "result"}:
            raise OwnerFailure("invalid owner response envelope")
        if (
            type(data["protocol_version"]) is not int
            or data["protocol_version"] != 1
            or data["owner"] != self.owner
        ):
            raise OwnerFailure("owner identity/protocol mismatch")
        return data["result"]

    def observe(self) -> Snapshot:
        try:
            value = self._request("observe", {"config": to_dict(self.config)})
            return snapshot_from_dict(value)
        except ProcessTimeout:
            return _unknown(self.config, self.owner, "timed-out")
        except PermissionError:
            return _unknown(self.config, self.owner, "inaccessible")
        except (ValueError, UnicodeError, OwnerFailure, OutputLimit, OSError):
            return _unknown(self.config, self.owner, "malformed")

    def apply(self, action: Action) -> Observation:
        if (
            action.owner != self.owner
            or self.config.profile_owner(action.profile).id != self.owner
            or action.operation not in {"activate", "withdraw", "drain"}
        ):
            raise OwnerFailure("unsupported fixed owner operation")
        return observation_from_dict(
            self._request(
                "reconcile",
                {
                    "policy_digest": config_digest(self.config),
                    "profile_digest": profile_digest(
                        self.config, self.config.profile(action.profile)
                    ),
                    "profile": action.profile,
                    "action": action.operation,
                    "target_ipv4": action.target_ipv4,
                    "target_generation": action.target_generation,
                },
            )
        )

    def reconcile_discovery(self, action: DiscoveryAction) -> Observation:
        policy = next((item for item in self.config.discovery if item.id == action.id), None)
        if (
            policy is None
            or action.owner != self.owner
            or policy.owner != self.owner
            or action.policy_digest != discovery_digest(self.config, policy)
        ):
            raise OwnerFailure("discovery owner identity mismatch")
        return observation_from_dict(
            self._request(
                "reconcile-discovery",
                {
                    "policy_digest": config_digest(self.config),
                    "discovery_digest": action.policy_digest,
                    "discovery": action.id,
                    "active": action.active,
                    "config": to_dict(self.config),
                    "service_generation": action.service_generation,
                    "network_generation": action.network_generation,
                },
            )
        )


@dataclass
class SnapshotFileOwner:
    config: Config
    owner: str
    path: Path
    simulation: bool = False

    def observe(self) -> Snapshot:
        try:
            return snapshot_from_dict(strict_load(self.path))
        except (OSError, ValueError, UnicodeError):
            return _unknown(self.config, self.owner, "inaccessible")

    def apply(self, action: Action) -> Observation:
        raise ExternalOwnerRequired("external owner work is required; no privileged call was made")

    def reconcile_discovery(self, action: DiscoveryAction) -> Observation:
        raise ExternalOwnerRequired("discovery owner work is required; no publication was made")


def _root_report(path: Path) -> Any:
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise OwnerFailure("root report ancestors must be root-owned and protected")
        reject_acl(parent)
    reject_acl(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o022
        ):
            raise OwnerFailure("invalid protected root report")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(1_048_577)
        final = path.lstat()

        def captured(item: os.stat_result) -> tuple[int, ...]:
            return (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_uid,
                item.st_gid,
                item.st_nlink,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if captured(final) != captured(info) or captured(os.fstat(fd)) != captured(info):
            raise OwnerFailure("root report changed during capture")
        reject_acl(path)
        return strict_loads(raw)
    finally:
        os.close(fd)


@dataclass
class RootReportOwner(SnapshotFileOwner):
    """Read protected independent-owner evidence; never invoke its executable."""

    def observe(self) -> Snapshot:
        try:
            return snapshot_from_dict(_root_report(self.path))
        except (OSError, ValueError, RuntimeError):
            return _unknown(self.config, self.owner, "inaccessible")


def effective_admissions(
    config: Config,
    clients: dict[str, OwnerClient],
    snapshot: Snapshot,
    user_admissions: dict[str, Admission],
    now: float,
) -> dict[str, Admission]:
    """Derive root readiness from protected fresh root proof, never user approval.

    This is a read-only view for downstream dependency planning. It cannot admit
    a root profile or ask root to activate one. Only independently admitted,
    currently verified root exposure can become ready in the user plan.
    """
    result = {
        key: item
        for key, item in user_admissions.items()
        if key
        in {
            profile.id
            for profile in config.profiles
            if config.profile_owner(profile).privilege == "user"
        }
    }
    for profile in config.profiles:
        owner = config.profile_owner(profile)
        client = clients.get(owner.id)
        if owner.privilege != "external-root" or not isinstance(client, RootReportOwner):
            continue
        observation = snapshot.profiles.get(profile.id)
        if observation is None:
            continue
        evidence = observation.at(now, profile.safety.max_age_seconds)
        proof = evidence.data.get("admission_digest")
        if (
            evidence.state == "present"
            and evidence.data.get("admitted") is True
            and evidence.data.get("root_ready") is True
            and isinstance(proof, str)
            and re.fullmatch(r"[0-9a-f]{64}", proof)
            and evidence.data.get("policy_digest") == profile_digest(config, profile)
            and snapshot.network_generation is not None
            and evidence.data.get("network_generation") == snapshot.network_generation
        ):
            result[profile.id] = Admission(
                profile.id,
                profile_digest(config, profile),
                "independent-root:" + owner.id,
                evidence.observed_at,
                True,
            )
    return result


def load_bindings(config: Config, path: Path) -> dict[str, OwnerClient]:
    value = _secure_binding_file(path)
    if not isinstance(value, dict) or set(value) != {"schema_version", "owners"}:
        raise OwnerFailure("invalid binding envelope")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise OwnerFailure("unsupported binding version")
    if not isinstance(value["owners"], list):
        raise OwnerFailure("bindings must contain owner entries")
    result: dict[str, OwnerClient] = {}
    for raw in value["owners"]:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            raise OwnerFailure("invalid owner binding")
        owner = config.owner(raw["id"])
        if owner.id in result:
            raise OwnerFailure("duplicate owner binding")
        if raw.get("kind") == "process" and set(raw) == {"id", "kind", "argv"}:
            argv = raw["argv"]
            if (
                owner.privilege != "user"
                or not isinstance(argv, list)
                or not argv
                or any(not isinstance(arg, str) or "\0" in arg for arg in argv)
                or not os.path.isabs(argv[0])
            ):
                raise OwnerFailure("only explicit absolute user-owner commands can be bound")
            result[owner.id] = ProcessOwner(config, owner.id, argv)
        elif raw.get("kind") == "snapshot-file" and set(raw) == {"id", "kind", "path"}:
            if not isinstance(raw["path"], str) or not os.path.isabs(raw["path"]):
                raise OwnerFailure("snapshot path must be absolute")
            result[owner.id] = SnapshotFileOwner(config, owner.id, Path(raw["path"]))
        elif raw.get("kind") == "root-report" and set(raw) == {"id", "kind", "path"}:
            if (
                owner.privilege != "external-root"
                or not isinstance(raw["path"], str)
                or not os.path.isabs(raw["path"])
            ):
                raise OwnerFailure("root report belongs to a protected independent root owner")
            result[owner.id] = RootReportOwner(config, owner.id, Path(raw["path"]))
        else:
            raise OwnerFailure("unknown owner binding type or fields")
    return result


def observe(config: Config, clients: dict[str, OwnerClient]) -> Snapshot:
    """Merge bounded evidence. Cross-owner claims never establish another owner."""
    snapshots: list[Snapshot] = []
    for owner in config.owners:
        snapshot = (
            clients[owner.id].observe()
            if owner.id in clients
            else _unknown(config, owner.id, "unobserved")
        )
        allowed_services = {s.id for s in config.services if s.owner == owner.id}
        allowed_profiles = {p.id for p in config.profiles if config.profile_owner(p).id == owner.id}
        allowed_profiles.update(d.id for d in config.discovery if d.owner == owner.id)
        if set(snapshot.services) - allowed_services or set(snapshot.profiles) - allowed_profiles:
            snapshot = _unknown(config, owner.id, "identity-mismatch")
        snapshots.append(snapshot)
    # A discovery-only owner has no guest-network facts and need not know its generation.
    transport_ids = {p.id for p in config.profiles}
    generations = {
        s.network_generation for s in snapshots if s.services or set(s.profiles) & transport_ids
    }
    generation = next(iter(generations)) if len(generations) == 1 else None
    return Snapshot(
        time.time(),
        generation,
        {key: item for s in snapshots for key, item in s.services.items()},
        {key: item for s in snapshots for key, item in s.profiles.items()},
    )

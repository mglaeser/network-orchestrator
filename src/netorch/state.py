"""Immutable observations, exact admission and independent durable intent.

Snapshots are evidence, never authority.  A caller must make a complete read
before creating a present/absent observation; malformed and missing reads are
unknown.  Persistence itself belongs to the executor/owner, not this module.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .codec import digest

OBSERVATION_STATES = frozenset({"present", "absent", "unknown"})
OBSERVATION_REASONS = frozenset(
    {
        "verified",
        "confirmed-absent",
        "incomplete",
        "malformed",
        "inaccessible",
        "timed-out",
        "busy",
        "stale",
        "future",
        "local-network-denied",
        "identity-mismatch",
        "generation-mismatch",
        "unobserved",
        "unavailable",
    }
)
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}\Z")


def _time(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("timestamp must be a finite nonnegative number")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError("timestamp must be a finite nonnegative number")
    return result


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError("expected lowercase SHA-256 digest")
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(item) for item in value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise ValueError("observation contains a non-JSON value")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _object(value: object, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"invalid {label} fields")
    return value


@dataclass(frozen=True, slots=True)
class Observation:
    state: str
    reason: str
    observed_at: float
    generation: str | None
    data: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.state, str)
            or not isinstance(self.reason, str)
            or self.state not in OBSERVATION_STATES
            or self.reason not in OBSERVATION_REASONS
        ):
            raise ValueError("invalid observation state or reason")
        if self.state == "present" and self.reason != "verified":
            raise ValueError("present requires a verified complete read")
        if self.state == "absent" and self.reason != "confirmed-absent":
            raise ValueError("absent requires a confirmed complete read")
        if self.state == "unknown" and self.reason in {"verified", "confirmed-absent"}:
            raise ValueError("unknown requires an uncertainty reason")
        object.__setattr__(self, "observed_at", _time(self.observed_at))
        if self.generation is not None:
            _identifier(self.generation, "generation")
        if not isinstance(self.data, Mapping):
            raise ValueError("observation data must be an object")
        object.__setattr__(self, "data", _freeze(self.data))

    def at(self, now: float, max_age_seconds: float) -> Observation:
        """Decay evidence; a future timestamp cannot prove freshness."""
        now = _time(now)
        age_limit = _time(max_age_seconds)
        if self.observed_at > now:
            return Observation("unknown", "future", self.observed_at, self.generation, self.data)
        if now - self.observed_at > age_limit:
            return Observation("unknown", "stale", self.observed_at, self.generation, self.data)
        return self


@dataclass(frozen=True, slots=True)
class Snapshot:
    observed_at: float
    network_generation: str | None
    services: Mapping[str, Observation] = field(default_factory=dict)
    profiles: Mapping[str, Observation] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_at", _time(self.observed_at))
        if self.network_generation is not None:
            _identifier(self.network_generation, "network generation")
        for name in ("services", "profiles"):
            values = getattr(self, name)
            if not isinstance(values, Mapping):
                raise ValueError(f"{name} must be an object")
            for key, observation in values.items():
                _identifier(key, name)
                if not isinstance(observation, Observation):
                    raise ValueError("snapshot values must be observations")
            object.__setattr__(self, name, MappingProxyType(dict(values)))


@dataclass(frozen=True, slots=True)
class Admission:
    profile: str
    digest: str
    approved_by: str
    approved_at: float
    risk_acknowledged: bool

    def __post_init__(self) -> None:
        _identifier(self.profile, "profile")
        _digest(self.digest)
        if not isinstance(self.approved_by, str) or not self.approved_by.strip():
            raise ValueError("admission must identify its approver")
        if len(self.approved_by) > 256 or any(ord(c) < 32 for c in self.approved_by):
            raise ValueError("invalid admission approver")
        object.__setattr__(self, "approved_at", _time(self.approved_at))
        if not isinstance(self.risk_acknowledged, bool):
            raise ValueError("risk acknowledgement must be boolean")


@dataclass(frozen=True, slots=True)
class Intent:
    revision: int = 0
    operator_paused: bool = False
    suspensions: Mapping[str, str] = field(default_factory=dict)
    damaged: bool = False

    def __post_init__(self) -> None:
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 0
        ):
            raise ValueError("intent revision must be a nonnegative integer")
        if not isinstance(self.operator_paused, bool) or not isinstance(self.damaged, bool):
            raise ValueError("intent flags must be boolean")
        if not isinstance(self.suspensions, Mapping):
            raise ValueError("suspensions must be operation-to-holder records")
        for operation, holder in self.suspensions.items():
            _identifier(operation, "operation")
            _identifier(holder, "holder")
        object.__setattr__(self, "suspensions", MappingProxyType(dict(self.suspensions)))

    @property
    def blocked(self) -> bool:
        return self.damaged or self.operator_paused or bool(self.suspensions)

    def _change(
        self, *, paused: bool | None = None, suspensions: Mapping[str, str] | None = None
    ) -> Intent:
        if self.damaged:
            raise ValueError("damaged intent requires explicit owner repair")
        next_pause = self.operator_paused if paused is None else paused
        next_suspensions = dict(self.suspensions if suspensions is None else suspensions)
        if next_pause == self.operator_paused and next_suspensions == dict(self.suspensions):
            return self
        return Intent(self.revision + 1, next_pause, next_suspensions)

    def pause(self) -> Intent:
        return self._change(paused=True)

    def resume(self) -> Intent:
        """Operator-only semantic operation; suspensions are never cleared."""
        return self._change(paused=False)

    def suspend(self, operation: str, holder: str) -> Intent:
        operation = _identifier(operation, "operation")
        holder = _identifier(holder, "holder")
        existing = self.suspensions.get(operation)
        if existing is not None and existing != holder:
            raise ValueError("suspension is owned by another holder")
        records = dict(self.suspensions)
        records[operation] = holder
        return self._change(suspensions=records)

    def release(self, operation: str, holder: str) -> Intent:
        operation = _identifier(operation, "operation")
        holder = _identifier(holder, "holder")
        if self.suspensions.get(operation) != holder:
            raise ValueError("only the suspension holder may release it")
        records = dict(self.suspensions)
        del records[operation]
        return self._change(suspensions=records)


def observation_to_dict(observation: Observation) -> dict[str, Any]:
    return {
        "state": observation.state,
        "reason": observation.reason,
        "observed_at": observation.observed_at,
        "generation": observation.generation,
        "data": _thaw(observation.data),
    }


def observation_from_dict(value: object) -> Observation:
    item = _object(value, {"state", "reason", "observed_at", "generation", "data"}, "observation")
    return Observation(**item)


def snapshot_to_dict(snapshot: Snapshot) -> dict[str, Any]:
    return {
        "observed_at": snapshot.observed_at,
        "network_generation": snapshot.network_generation,
        "services": {key: observation_to_dict(value) for key, value in snapshot.services.items()},
        "profiles": {key: observation_to_dict(value) for key, value in snapshot.profiles.items()},
    }


def snapshot_from_dict(value: object) -> Snapshot:
    item = _object(value, {"observed_at", "network_generation", "services", "profiles"}, "snapshot")
    for name in ("services", "profiles"):
        if not isinstance(item[name], Mapping):
            raise ValueError(f"{name} must be an object")
    return Snapshot(
        item["observed_at"],
        item["network_generation"],
        {key: observation_from_dict(obs) for key, obs in item["services"].items()},
        {key: observation_from_dict(obs) for key, obs in item["profiles"].items()},
    )


def snapshot_digest(snapshot: Snapshot) -> str:
    return digest(snapshot_to_dict(snapshot))


def admissions_to_dict(admissions: Mapping[str, Admission]) -> dict[str, Any]:
    result = {}
    for key, admission in admissions.items():
        if key != admission.profile:
            raise ValueError("admission key does not match profile")
        result[key] = {
            "profile": admission.profile,
            "digest": admission.digest,
            "approved_by": admission.approved_by,
            "approved_at": admission.approved_at,
            "risk_acknowledged": admission.risk_acknowledged,
        }
    return result


def admissions_from_dict(value: object) -> dict[str, Admission]:
    if not isinstance(value, Mapping):
        raise ValueError("admissions must be an object")
    result = {}
    for key, raw in value.items():
        _identifier(key, "admission key")
        item = _object(
            raw,
            {"profile", "digest", "approved_by", "approved_at", "risk_acknowledged"},
            "admission",
        )
        admission = Admission(**item)
        if admission.profile != key:
            raise ValueError("admission key does not match profile")
        result[key] = admission
    return result


def intent_to_dict(intent: Intent) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "revision": intent.revision,
        "operator_paused": intent.operator_paused,
        "suspensions": dict(intent.suspensions),
        "damaged": intent.damaged,
    }


def intent_from_dict(value: object) -> Intent:
    """Unreadable, old-format and unknown-version intent always inhibits apply."""
    try:
        item = _object(
            value,
            {"schema_version", "revision", "operator_paused", "suspensions", "damaged"},
            "intent",
        )
        if type(item["schema_version"]) is not int or item["schema_version"] != 1:
            raise ValueError("unsupported intent version")
        return Intent(
            item["revision"], item["operator_paused"], item["suspensions"], item["damaged"]
        )
    except (ValueError, TypeError):
        return Intent(damaged=True)

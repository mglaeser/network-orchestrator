"""Read-only safety assessments and a synthetic allocator contract model.

These functions neither qualify a host for mutation nor control an owner. A
configured interval is not a measured scheduling guarantee. The model captures
the tagged vendor's address-pool algorithm, not an observation of vmnet.
"""

from __future__ import annotations

import math
import re
from collections import deque
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from .state import Observation

EFFECTIVE_UNKNOWN_LIMIT = 1
LAUNCHD_INTERVAL_FLOOR_SECONDS = 10
RECOVERY_FAILURE_EXIT_CODE = 42
UNKNOWN_CHECK_EXIT_CODE = 1
ALLOCATOR_RUNTIME_VERSION = "1.5.0"
ALLOCATOR_DEPENDENCY_VERSION = "0.47.0"
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


@dataclass(frozen=True, slots=True)
class SafetyAssessment:
    status: str
    reasons: tuple[str, ...]
    max_age_seconds: int
    configured_unknown_limit: int
    effective_unknown_limit: int
    nominal_interval_seconds: int
    withdrawal_bound_seconds: float | None
    bounds_verified: bool
    zero_misdelivery_guaranteed: bool = False


def assessment_to_dict(value: SafetyAssessment) -> dict[str, Any]:
    result = asdict(value)
    result["reasons"] = list(value.reasons)
    return result


def _integer(value: object, lower: int, upper: int, label: str) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f"invalid {label}")
    return value


def _duration(value: object, label: str) -> float | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
        or value > 86400
    ):
        raise ValueError(f"invalid {label}")
    return float(value)


def _signature_time(value: object) -> float | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ValueError("signature time must be a UTC timestamp")
    timestamp = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    if timestamp < 0:
        raise ValueError("signature time must be nonnegative")
    return timestamp


def assess_bounded_safety(
    max_age_seconds: int,
    unknown_limit: int,
    residual: str,
    signed_by: str | None,
    signed_at: str | None,
    *,
    interval_seconds: int,
    read_timeout_seconds: float | None = None,
    apply_timeout_seconds: float | None = None,
    scheduler_slack_seconds: float | None = None,
    evidence_verified: bool = False,
    now: float | None = None,
    zero_misdelivery_required: bool = False,
) -> SafetyAssessment:
    """Assess evidence for a bounded profile; never grant admission or support.

    Read/apply durations mean aggregate upper bounds for the relevant pass and
    complete withdrawal plus state invalidation, not one subprocess's timeout.
    Scheduler slack includes missed/overlapping launchd launches and any outage
    of the owner. No finite bound is inferred when one term is unestablished.
    ``evidence_verified`` must come from separately validated native evidence;
    the report caller is responsible for its OS/release/profile binding.
    """
    _integer(max_age_seconds, 1, 86400, "maximum observation age")
    _integer(unknown_limit, 1, 1000, "unknown limit")
    _integer(interval_seconds, 1, 60, "owner interval")
    if (
        not isinstance(residual, str)
        or not residual.strip()
        or len(residual) > 2000
        or any(ord(character) < 32 for character in residual)
    ):
        raise ValueError("invalid residual statement")
    if signed_by is not None and (
        not isinstance(signed_by, str)
        or not signed_by.strip()
        or len(signed_by) > 256
        or any(ord(character) < 32 for character in signed_by)
    ):
        raise ValueError("invalid residual signer")
    signature_at = _signature_time(signed_at)
    if type(evidence_verified) is not bool or type(zero_misdelivery_required) is not bool:
        raise ValueError("safety decisions must be boolean")
    current = None
    # Epoch time is not a duration and may exceed one day.
    if now is not None:
        if (
            isinstance(now, bool)
            or not isinstance(now, (int, float))
            or not math.isfinite(now)
            or now < 0
        ):
            raise ValueError("invalid current time")
        current = float(now)
    durations = (
        _duration(read_timeout_seconds, "aggregate read bound"),
        _duration(apply_timeout_seconds, "aggregate withdrawal bound"),
        _duration(scheduler_slack_seconds, "scheduling slack bound"),
    )
    interval = max(LAUNCHD_INTERVAL_FLOOR_SECONDS, interval_seconds)
    bound = None
    if all(value is not None for value in durations):
        bound = interval * EFFECTIVE_UNKNOWN_LIMIT + sum(
            value for value in durations if value is not None
        )
    reasons = []
    status = "fulfilled-unverified"
    if signed_by is None or signature_at is None:
        reasons.append("residual-unsigned")
        status = "not-fulfilled"
    elif current is None:
        reasons.append("signature-time-unverified")
    elif signature_at > current:
        reasons.append("signature-future")
        status = "not-fulfilled"
    if bound is None:
        reasons.append("withdrawal-bound-unestablished")
    elif bound > max_age_seconds:
        reasons.append("withdrawal-bound-exceeds-age")
        status = "not-fulfilled"
    if not evidence_verified:
        reasons.append("native-bound-evidence-unverified")
    if zero_misdelivery_required:
        reasons.append("structural-isolation-required")
        status = "not-fulfilled"
    reasons.append("bounded-address-reuse-residual")
    if (
        status != "not-fulfilled"
        and current is not None
        and bound is not None
        and evidence_verified
        and signed_by is not None
        and signature_at is not None
    ):
        status = "accepted-residual"
    return SafetyAssessment(
        status,
        tuple(reasons),
        max_age_seconds,
        unknown_limit,
        EFFECTIVE_UNKNOWN_LIMIT,
        interval,
        bound,
        evidence_verified and bound is not None,
    )


def recovery_exit_code(
    observation: Observation,
    *,
    now: float,
    max_age_seconds: float,
    initial_owners_ready: bool = False,
    fleet_start_proven: bool = False,
) -> int:
    """Only fresh complete absence after initial readiness gets failure code42.

    This is a check result, not recovery. Unknown, timeout and cold-start gates
    yield ordinary uncertainty code1, which a supervisor must never recover on.
    The caller must separately establish dependency readiness from owner reports.
    A cold start is no longer uncertain when the absence itself was established
    with the declared fleet-start evidence: the enrolled API job before and after
    the read, and no runtime job for the workload in the service manager.
    """
    if type(initial_owners_ready) is not bool:
        raise ValueError("initial readiness must be boolean")
    if type(fleet_start_proven) is not bool:
        raise ValueError("fleet-start proof must be boolean")
    current = observation.at(now, max_age_seconds)
    if current.state == "present":
        return 0
    if current.state == "absent" and (initial_owners_ready or fleet_start_proven):
        return RECOVERY_FAILURE_EXIT_CODE
    return UNKNOWN_CHECK_EXIT_CODE


class RotatingAllocatorModel:
    """Synthetic contract of DefaultNetworkService + AttachmentAllocator.

    Container1.5.0 uses containerization0.47.0: pool slots run from subnet+2
    through subnet upper-2; allocate removes the head; release appends the tail.
    Reconstructing this object models a helper/pool rebuild. It does not predict
    actual guest leases or certify a native runtime upgrade.
    """

    def __init__(self, subnet: str) -> None:
        network = IPv4Network(subnet, strict=True)
        # Keep fixture memory bounded, including crafted inputs. These are model
        # bounds, not a declaration of supported production subnet sizes.
        if network.prefixlen < 16 or network.num_addresses < 8:
            raise ValueError("allocator model needs a bounded nonempty IPv4 pool")
        self._available = deque(
            str(IPv4Address(int(network.network_address) + offset))
            for offset in range(2, network.num_addresses - 2)
        )
        self._leases: dict[str, str] = {}

    @property
    def capacity(self) -> int:
        return len(self._available) + len(self._leases)

    def allocate(self, holder: str) -> str:
        if not isinstance(holder, str) or not holder or len(holder) > 256:
            raise ValueError("invalid synthetic holder")
        if holder in self._leases:
            return self._leases[holder]
        if not self._available:
            raise ValueError("synthetic allocator exhausted")
        address = self._available.popleft()
        self._leases[holder] = address
        return address

    def release(self, holder: str) -> str | None:
        address = self._leases.pop(holder, None)
        if address is not None:
            self._available.append(address)
        return address

    def lookup(self, holder: str) -> str | None:
        return self._leases.get(holder)

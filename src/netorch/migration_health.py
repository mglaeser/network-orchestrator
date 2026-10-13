"""Offline checkpoint coverage for an existing dashboard, never a health collector.

This validates recorded outcomes, not their authenticity or native qualification.
It opens no socket, runs no command and cannot authorize a migration or recovery.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import re
import time
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Any

from .codec import canonical_bytes, canonical_json, read_bounded_file, strict_loads

_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
PHASES = ("pre", "post", "rollback", "soak")
_CATEGORIES = {
    "services": "service",
    "devices": "device",
    "webpages": "webpage",
    "service": "service",
    "device": "device",
    "webpage": "webpage",
}


def _object(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("invalid checkpoint object")
    return value


def _text(value: Any, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError("invalid checkpoint identifier")
    return value


def _list(value: Any, maximum: int = 128) -> list[Any]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise ValueError("invalid checkpoint list")
    return value


def _clock(value: Any) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 <= value <= 253402300799
        or not math.isfinite(value)
    ):
        raise ValueError("invalid checkpoint clock")
    return float(value)


def _names(value: Any) -> list[str]:
    entries = _list(value)
    if any(
        not isinstance(name, str)
        or not name.strip()
        or len(name) > 256
        or any(ord(char) < 32 for char in name)
        for name in entries
    ) or len(set(entries)) != len(entries):
        raise ValueError("invalid checkpoint check names")
    return entries


def validate_contract(raw: Any) -> dict[str, Any]:
    """Validate the complete reviewed roster; no per-step success-only subset."""
    canonical_bytes(raw)  # Direct callers share the CLI's bounded JSON tree contract.
    if not isinstance(raw, dict) or type(raw.get("schema_version")) is not int:
        raise ValueError("unsupported checkpoint contract")
    version = raw["schema_version"]
    if version not in (1, 2):
        raise ValueError("unsupported checkpoint contract")
    keys = {"schema_version", "plan_sha256", "catalog_sha256", "steps", "services"}
    if version == 2:
        keys |= {"dashboard_api", "critical_severity_max"}
    contract = _object(raw, keys)
    if version == 2 and (
        contract["dashboard_api"] != "status-v1"
        or type(contract["critical_severity_max"]) is not int
        or contract["critical_severity_max"] != 3
    ):
        raise ValueError("invalid dashboard checkpoint policy")
    for field in ("plan_sha256", "catalog_sha256"):
        _text(contract[field], _SHA)
    steps = [_text(step, _ID) for step in _list(contract["steps"])]
    if len(set(steps)) != len(steps):
        raise ValueError("duplicate checkpoint step")
    seen: set[str] = set()
    for raw_service in _list(contract["services"]):
        service_keys = {"id", "category", "checks", "max_age_seconds"}
        if version == 2:
            service_keys.add("severity")
        service = _object(raw_service, service_keys)
        if version == 2 and (
            type(service["severity"]) is not int or not 1 <= service["severity"] <= 5
        ):
            raise ValueError("invalid checkpoint severity")
        identifier = _text(service["id"], _ID)
        if identifier in seen:
            raise ValueError("duplicate checkpoint service")
        seen.add(identifier)
        if service["category"] not in ("service", "device", "webpage"):
            raise ValueError("invalid checkpoint category")
        _names(service["checks"])
        age = service["max_age_seconds"]
        if type(age) is not int or not 1 <= age <= 300:
            raise ValueError("invalid checkpoint freshness bound")
    return contract


def _required_object(value: Any, keys: set[str]) -> dict[str, Any]:
    """Read the health projection while tolerating bounded additive API metadata."""
    if not isinstance(value, dict) or not keys <= set(value):
        raise ValueError("incomplete dashboard status recording")
    return value


def _timestamp(value: Any) -> float:
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        raise ValueError("invalid dashboard status timestamp")
    try:
        return _clock(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except (ValueError, OverflowError) as exc:
        raise ValueError("invalid dashboard status timestamp") from exc


def _status_checkpoint(
    contract: dict[str, Any], dashboard: Any, start: float, end: float, now: float
) -> list[str]:
    """Validate status-v1 independently of its displayed aggregate or SEV choices.

    All entries remain mandatory. Configured severity is pinned policy, not an
    active incident and not authority to skip a low-priority entry. Times are
    recomputed; the one-microsecond tolerance covers binary float conversion,
    never the checkpoint or freshness inequalities.
    """
    dashboard = _required_object(
        dashboard,
        {
            "schema_version",
            "generated_at",
            "page",
            "status",
            "observation",
            "components",
            "hosts",
            "severity_levels",
        },
    )
    if dashboard["schema_version"] != "1":
        raise ValueError("unsupported dashboard status version")
    generated = _timestamp(dashboard["generated_at"])
    blockers: list[str] = []
    if not start <= generated <= end:
        blockers.append("dashboard-generation-outside-checkpoint")
    observation = _required_object(
        dashboard["observation"],
        {"source", "interval_seconds", "max_age_seconds", "refreshing"},
    )
    if observation["source"] != "dashboard_checks":
        blockers.append("dashboard-observation-source-changed")
    if (
        type(observation["interval_seconds"]) is not int
        or observation["interval_seconds"] < 1
        or type(observation["max_age_seconds"]) is not int
        or not 1 <= observation["max_age_seconds"] <= 300
        or type(observation["refreshing"]) is not bool
    ):
        raise ValueError("invalid dashboard status observation")
    if observation["refreshing"]:
        blockers.append("dashboard-refresh-not-complete")
    max_age = observation["max_age_seconds"]
    aggregate = _required_object(
        dashboard["status"], {"state", "highest_affected_severity", "counts"}
    )
    counts = _required_object(aggregate["counts"], {"total", "operational", "degraded", "unknown"})
    if any(
        type(counts[key]) is not int or not 0 <= counts[key] <= 128
        for key in ("total", "operational", "degraded", "unknown")
    ):
        raise ValueError("invalid dashboard aggregate counts")
    affected = aggregate["highest_affected_severity"]
    if affected is not None and (type(affected) is not int or not 1 <= affected <= 5):
        raise ValueError("invalid dashboard aggregate severity")
    recorded: dict[str, dict[str, Any]] = {}
    computed_counts = {"total": 0, "operational": 0, "degraded": 0, "unknown": 0}
    computed_affected: list[int] = []
    missing_observation_reasons = {
        "not_checked",
        "context_changed",
        "invalid_timestamp",
        "invalid_result",
        "credentials_error",
        "configuration_error",
    }
    # Empty API catalogues are valid summaries, but cannot satisfy a nonempty
    # migration contract; retain an explicit roster failure instead of guessing.
    components = dashboard["components"]
    if not isinstance(components, list) or len(components) > 128:
        raise ValueError("invalid dashboard components")
    for raw in components:
        service = _required_object(
            raw,
            {
                "id",
                "category",
                "severity",
                "status",
                "status_reason",
                "checked_at",
                "age_seconds",
                "expires_at",
                "refreshing",
                "checks",
            },
        )
        identifier = _text(service["id"], _ID)
        if identifier in recorded:
            raise ValueError("duplicate recorded service")
        recorded[identifier] = service
        severity = service["severity"]
        if type(severity) is not int or not 1 <= severity <= 5:
            raise ValueError("invalid dashboard component severity")
        state, reason = service["status"], service["status_reason"]
        if not isinstance(state, str) or state not in computed_counts or state == "total":
            raise ValueError("invalid dashboard component state")
        if not isinstance(reason, str) or reason not in missing_observation_reasons | {
            "checks_passed",
            "checks_failed",
            "stale",
        }:
            raise ValueError("invalid dashboard component reason")
        if type(service["refreshing"]) is not bool:
            raise ValueError("invalid dashboard refresh state")
        if service["refreshing"]:
            blockers.append(identifier + ":refresh-not-complete")
        computed_counts["total"] += 1
        computed_counts[state] += 1
        if state == "degraded":
            computed_affected.append(severity)
        checks = service["checks"]
        if not isinstance(checks, list) or len(checks) > 128:
            raise ValueError("invalid dashboard status checks")
        names: list[str] = []
        all_pass = bool(checks)
        for check in checks:
            check = _required_object(check, {"name", "status", "message"})
            if (
                not isinstance(check["name"], str)
                or not check["name"].strip()
                or len(check["name"]) > 256
                or any(ord(char) < 32 for char in check["name"])
                or check["status"] not in ("pass", "fail")
                or not isinstance(check["message"], str)
            ):
                raise ValueError("invalid dashboard status check")
            names.append(check["name"])
            all_pass = all_pass and check["status"] == "pass"
        if len(set(names)) != len(names):
            blockers.append(identifier + ":check-roster-changed")
        if state != "operational" or reason != "checks_passed":
            blockers.append(identifier + ":not-healthy")
        if not all_pass:
            blockers.append(identifier + ":check-not-healthy")
        if service["checked_at"] is None:
            if (
                service["age_seconds"] is not None
                or service["expires_at"] is not None
                or checks
                or state != "unknown"
                or reason not in missing_observation_reasons
            ):
                blockers.append(identifier + ":observation-inconsistent")
        else:
            checked = _timestamp(service["checked_at"])
            expires = _timestamp(service["expires_at"])
            age = _clock(service["age_seconds"])
            if (
                checked > generated
                or abs(age - (generated - checked)) > 0.000001
                or abs(expires - (checked + max_age)) > 0.000001
                or not checks
            ):
                blockers.append(identifier + ":observation-inconsistent")
            expected_state, expected_reason = (
                ("unknown", "stale")
                if generated - checked > max_age
                else ("operational", "checks_passed")
                if all_pass
                else ("degraded", "checks_failed")
            )
            if (state, reason) != (expected_state, expected_reason):
                blockers.append(identifier + ":observation-inconsistent")
    expected_ids = {service["id"] for service in contract["services"]}
    if set(recorded) != expected_ids:
        blockers.append("dashboard-roster-changed")
    for expected in contract["services"]:
        identifier = expected["id"]
        found = recorded.get(identifier)
        if found is None:
            blockers.append(identifier + ":missing")
            continue
        service = found
        # v2 uses only the documented plural API categories. Do not let an older
        # response silently satisfy the new contract by category fallback.
        if service["category"] != expected["category"] + "s":
            blockers.append(identifier + ":category-changed")
        if service["severity"] != expected["severity"]:
            blockers.append(identifier + ":severity-changed")
        stamp = service["checked_at"]
        if stamp is None:
            blockers.append(identifier + ":stale-or-outside-checkpoint")
        else:
            checked = _timestamp(stamp)
            if (
                not start <= checked <= generated <= end
                or now - checked > expected["max_age_seconds"]
            ):
                blockers.append(identifier + ":stale-or-outside-checkpoint")
        if {check["name"] for check in service["checks"]} != set(expected["checks"]):
            blockers.append(identifier + ":check-roster-changed")
    computed_state = (
        "degraded"
        if computed_counts["degraded"]
        else "unknown"
        if computed_counts["unknown"] or not computed_counts["total"]
        else "operational"
    )
    if (
        any(counts[key] != value for key, value in computed_counts.items())
        or aggregate["state"] != computed_state
        or affected != (min(computed_affected) if computed_affected else None)
    ):
        blockers.append("dashboard-aggregate-inconsistent")
    return blockers


def evaluate(
    contract: Any,
    snapshot: Any,
    *,
    step: str,
    phase: str,
    generation: str,
    since: float,
    now: float,
) -> dict[str, Any]:
    """Compare one post-refresh recording to independently supplied checkpoint context.

    A new generation and ``since`` boundary are required on every retry. The
    caller must retain those outside the recording. IDs/digests only bind data;
    they do not authenticate the dashboard, sign evidence or establish truth.
    """
    contract = validate_contract(contract)
    canonical_bytes(snapshot)  # Ignored metadata is still bounded, finite JSON data.
    _text(step, _ID)
    _text(generation, _ID)
    if step not in contract["steps"] or phase not in PHASES:
        raise ValueError("unknown checkpoint context")
    since, now = _clock(since), _clock(now)
    if since > now:
        raise ValueError("checkpoint starts in the future")
    record = _object(
        snapshot,
        {
            "schema_version",
            "contract_sha256",
            "catalog_sha256",
            "step",
            "phase",
            "generation",
            "started_at",
            "completed_at",
            "source",
            "dashboard",
        },
    )
    if (
        type(record["schema_version"]) is not int
        or record["schema_version"] != contract["schema_version"]
    ):
        raise ValueError("unsupported checkpoint recording")
    digest = hashlib.sha256(canonical_bytes(contract)).hexdigest()
    blockers: list[str] = []
    if any(
        record[key] != expected
        for key, expected in (
            ("contract_sha256", digest),
            ("catalog_sha256", contract["catalog_sha256"]),
            ("step", step),
            ("phase", phase),
            ("generation", generation),
        )
    ):
        blockers.append("checkpoint-context-mismatch")
    source = "dashboard-api" if contract["schema_version"] == 1 else "dashboard-status-api-v1"
    if record["source"] != source:
        blockers.append("dashboard-api-recording-required")
    start, end = _clock(record["started_at"]), _clock(record["completed_at"])
    # Status-v2 collection starts at the independent refresh boundary. A later
    # self-reported capture start cannot renew that original collection budget.
    # Keep version 1's pre-existing recording-duration contract unchanged.
    budget_start = since if contract["schema_version"] == 2 else start
    if not since <= start <= end <= now or end - budget_start > 300:
        blockers.append("checkpoint-window-invalid")
    if contract["schema_version"] == 2:
        blockers.extend(_status_checkpoint(contract, record["dashboard"], start, end, now))
    else:
        dashboard = record["dashboard"]
        if not isinstance(dashboard, dict) or not {"services", "configError", "running"} <= set(
            dashboard
        ):
            raise ValueError("incomplete dashboard recording")
        if dashboard["configError"] is not None:
            blockers.append("dashboard-configuration-error")
        if dashboard["running"] is not False:
            blockers.append("dashboard-refresh-not-complete")
        recorded: dict[str, dict[str, Any]] = {}
        for service in _list(dashboard["services"]):
            if not isinstance(service, dict) or "id" not in service or "result" not in service:
                raise ValueError("incomplete dashboard service")
            identifier = _text(service["id"], _ID)
            if identifier in recorded:
                raise ValueError("duplicate recorded service")
            recorded[identifier] = service
        if set(recorded) != {service["id"] for service in contract["services"]}:
            blockers.append("dashboard-roster-changed")
        for expected in contract["services"]:
            identifier = expected["id"]
            service = recorded.get(identifier)
            if service is None:
                blockers.append(identifier + ":missing")
                continue
            # Older dashboards omit category. The reviewed catalog remains its author.
            if "category" in service:
                category = service["category"]
                if (
                    not isinstance(category, str)
                    or _CATEGORIES.get(category) != expected["category"]
                ):
                    blockers.append(identifier + ":category-changed")
            result = service["result"]
            if not isinstance(result, dict) or not {
                "status",
                "checkedAt",
                "checks",
                "running",
            } <= set(result):
                blockers.append(identifier + ":result-unavailable")
                continue
            if result["running"] is not False:
                blockers.append(identifier + ":refresh-not-complete")
            if result["status"] != "green":
                blockers.append(identifier + ":not-healthy")
            stamp = result["checkedAt"]
            observed = None
            if isinstance(stamp, str) and _DATE.fullmatch(stamp):
                with suppress(ValueError, OverflowError):
                    observed = datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
            if (
                observed is None
                or not start <= observed <= end
                or now - observed > expected["max_age_seconds"]
            ):
                blockers.append(identifier + ":stale-or-outside-checkpoint")
            checks = result["checks"]
            if not isinstance(checks, list) or not 1 <= len(checks) <= 128:
                blockers.append(identifier + ":checks-unavailable")
                continue
            names: list[str] = []
            for check in checks:
                if not isinstance(check, dict) or not isinstance(check.get("name"), str):
                    raise ValueError("invalid dashboard check")
                names.append(check["name"])
                if check.get("ok") is not True:
                    blockers.append(identifier + ":check-not-healthy")
            if len(set(names)) != len(names) or set(names) != set(expected["checks"]):
                blockers.append(identifier + ":check-roster-changed")
    result = {
        "schema_version": contract["schema_version"],
        "read_only": True,
        "mutation_available": False,
        "native_qualified": False,
        "provenance_authenticated": False,
        "recorded_health_passed": not blockers,
        "contract_sha256": digest,
        "step": step,
        "phase": phase,
        "generation": generation,
        "expected_services": len(contract["services"]),
        "blockers": sorted(set(blockers)),
    }

    if contract["schema_version"] == 2:
        critical_ids = {
            service["id"]
            for service in contract["services"]
            if service["severity"] <= contract["critical_severity_max"]
        }
        # A scoped noncritical outage may leave critical availability true, but
        # never overall acceptance. Any global/context or catalog contradiction
        # also invalidates the critical result, even if critical rows look green.
        critical_blocked = any(
            ":" not in blocker
            or blocker.split(":", 1)[0] in critical_ids
            or blocker.endswith((":severity-changed", ":category-changed", ":check-roster-changed"))
            for blocker in blockers
        )
        result.update(
            {
                "critical_services": len(critical_ids),
                "noncritical_services": len(contract["services"]) - len(critical_ids),
                "critical_health_passed": not critical_blocked,
            }
        )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--step", required=True)
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--since", type=float, required=True)
    args = parser.parse_args(argv)
    try:
        raw = read_bounded_file(args.contract)
        contract = validate_contract(strict_loads(raw))
        if raw != canonical_bytes(contract) + b"\n":
            raise ValueError("noncanonical contract")
        result = evaluate(
            contract,
            strict_loads(read_bounded_file(args.snapshot)),
            step=args.step,
            phase=args.phase,
            generation=args.generation,
            since=args.since,
            now=time.time(),
        )
    except (ValueError, OSError):
        # Never echo URLs, check messages, file contents, credentials or paths.
        print(
            canonical_json(
                {
                    "read_only": True,
                    "mutation_available": False,
                    "error": "invalid-or-unavailable-checkpoint-data",
                }
            )
        )
        return 65
    print(canonical_json(result))
    return 0 if result["recorded_health_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

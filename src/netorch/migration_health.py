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
    contract = _object(
        raw, {"schema_version", "plan_sha256", "catalog_sha256", "steps", "services"}
    )
    if type(contract["schema_version"]) is not int or contract["schema_version"] != 1:
        raise ValueError("unsupported checkpoint contract")
    for field in ("plan_sha256", "catalog_sha256"):
        _text(contract[field], _SHA)
    steps = [_text(step, _ID) for step in _list(contract["steps"])]
    if len(set(steps)) != len(steps):
        raise ValueError("duplicate checkpoint step")
    seen: set[str] = set()
    for raw_service in _list(contract["services"]):
        service = _object(raw_service, {"id", "category", "checks", "max_age_seconds"})
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
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
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
    if record["source"] != "dashboard-api":
        blockers.append("dashboard-api-recording-required")
    start, end = _clock(record["started_at"]), _clock(record["completed_at"])
    if not since <= start <= end <= now or end - start > 300:
        blockers.append("checkpoint-window-invalid")
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
            if not isinstance(category, str) or _CATEGORIES.get(category) != expected["category"]:
                blockers.append(identifier + ":category-changed")
        result = service["result"]
        if not isinstance(result, dict) or not {"status", "checkedAt", "checks", "running"} <= set(
            result
        ):
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
    return {
        "schema_version": 1,
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

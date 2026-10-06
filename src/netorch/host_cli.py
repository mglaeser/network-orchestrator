"""Six read-only host operations; no install/admit/recover/apply namespace."""

from __future__ import annotations

import argparse
import hashlib
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import __version__
from .codec import canonical_json
from .host_report import build_report, empty_evidence, parse_host_evidence
from .instance import load_instance, read_data, verify_release

COMMANDS = ("validate", "preflight", "status", "plan", "check", "report")
Collector = Callable[[Any], dict[str, Any]]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netorch-host",
        description="Read-only instance validation and local evidence; no network or owner action.",
    )
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("--instance", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--framework-artifact", type=Path)
    parser.add_argument("--dependency-lock", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument(
        "--collect-local",
        action="store_true",
        help="Explicit bounded local OS reads, never LAN/Bonjour probes.",
    )
    return parser


def main(
    argv: list[str] | None = None, *, collector: Collector | None = None, now: float | None = None
) -> int:
    args = _parser().parse_args(argv)
    if args.collect_local and (
        args.command not in {"preflight", "status", "report"} or args.evidence is not None
    ):
        _parser().error(
            "--collect-local is separate from --evidence and only for preflight/status/report"
        )
    if os.geteuid() == 0:
        print(
            canonical_json(
                {"read_only": True, "error": "host-entrypoint-requires-unprivileged-user"}
            )
        )
        return 77
    try:
        instance = load_instance(args.instance)
        clock = time.time() if now is None else now
        if args.collect_local:
            if collector is None:
                # This collector has a fixed local-only command set. It is not
                # an owner endpoint and receives no executable from an instance.
                from .macos_preflight import collect_preflight

                collector = collect_preflight
            evidence = parse_host_evidence(collector(instance))
            if now is None:
                # The collector stamps each fact while it runs. A report clock
                # read before collection sees every fresh fact as dated in the
                # future and discards it as contradictory.
                clock = time.time()
        else:
            evidence = (
                empty_evidence(clock)
                if args.evidence is None
                else parse_host_evidence(read_data(args.evidence))
            )
        release_verified = (
            args.framework_artifact is not None
            and args.dependency_lock is not None
            and verify_release(instance, args.framework_artifact)
            and hashlib.sha256(read_data(args.dependency_lock)).hexdigest()
            == instance.framework.dependency_lock_sha256
            and instance.framework.version == __version__
        )
        report = build_report(
            instance,
            evidence,
            now=clock,
            data_directory=args.data_dir or args.instance.parent,
            release_verified=release_verified,
            evidence_directory=args.evidence_dir,
        )
        result: dict[str, Any]
        if args.command == "validate":
            valid = all(item["state"] == "present" for item in report["contracts"])
            result = {
                "schema_version": 1,
                "instance": instance.instance,
                "valid": valid,
                "canonical": True,
                "read_only": True,
                "mutation_available": False,
                "release_verified": release_verified,
                "contracts": report["contracts"],
            }
            code = 0 if valid else 65
        elif args.command == "preflight":
            result = {
                key: report[key]
                for key in (
                    "schema_version",
                    "instance",
                    "read_only",
                    "mutation_available",
                    "platform",
                    "facts",
                    "names",
                    "evidence_source",
                )
            }
            code = 0
        elif args.command == "plan":
            result = {
                "schema_version": 1,
                "instance": instance.instance,
                "read_only": True,
                "mutation_available": False,
                "actions": [],
                "profiles": report["profiles"],
                "discovery_profiles": report["discovery_profiles"],
                "names": report["names"],
                "changes_require": (
                    "Separate per-owner review, byte conformance, administrator "
                    "install/admission and host acceptance; this command never applies."
                ),
            }
            code = 0
        elif args.command == "check":
            result = {
                "schema_version": 1,
                "instance": instance.instance,
                "read_only": True,
                "mutation_available": False,
                "passed": report["fully_served"],
                "requirements": report["requirements"],
                "platform": report["platform"],
            }
            code = 0 if report["fully_served"] else 1
        else:
            result = report
            code = 0
        print(canonical_json(result))
        return code
    except (OSError, ValueError, RuntimeError):
        # Never echo a parser's private path, raw input, native output or secret.
        print(
            canonical_json(
                {
                    "read_only": True,
                    "mutation_available": False,
                    "error": "invalid-or-unavailable-local-data",
                }
            )
        )
        return 65


if __name__ == "__main__":
    raise SystemExit(main())

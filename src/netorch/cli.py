"""Public command line: portable policy, mocks and explicit user-owner binding."""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import asdict
from importlib import resources
from pathlib import Path
from typing import Any

from . import __version__
from .codec import canonical_json, read_bounded_file, strict_load
from .config import config_digest, load_config, parse_config, profile_digest, to_dict
from .deployment import (
    install_bundle,
    plan_install,
    prepare_root_bundle,
    recover_install,
    render_bundle,
    rollback_install,
    validate_bundle,
)
from .deployment_config import load_deployment
from .derive import derive
from .discovery_plan import plan_discovery
from .executor import execute
from .mock import simulate
from .owners import effective_admissions, load_bindings, observe
from .pf import render
from .planner import plan, plan_to_dict
from .state import (
    Admission,
    Intent,
    admissions_from_dict,
    admissions_to_dict,
    intent_from_dict,
    intent_to_dict,
    snapshot_from_dict,
    snapshot_to_dict,
)
from .storage import Busy, Store
from .workflow_gate import NOT_QUALIFIED, StageNotQualified, require_mutation_qualified


def _emit(value: Any) -> None:
    print(canonical_json(value))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netorch", description="Network policy over independent owners"
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "simulate"):
        item = commands.add_parser(name)
        item.add_argument("--config", type=Path, required=True)
    for name in ("review-admission", "admit"):
        item = commands.add_parser(name)
        item.add_argument("--config", type=Path, required=True)
        item.add_argument("--profile", required=True)
        if name == "admit":
            item.add_argument("--state-dir", type=Path, required=True)
            item.add_argument("--expected-digest", required=True)
            item.add_argument("--approved-by", required=True)
            item.add_argument("--ack-bounded-risk", action="store_true")
    commands.add_parser("demo", help="run a built-in simulation with documentation-only addresses")
    item = commands.add_parser(
        "derive", help="statically derive a view from existing authored files"
    )
    item.add_argument("--source", type=Path, required=True)
    item.add_argument("--output", type=Path)
    item.add_argument("--check", action="store_true", help="fail if the existing output differs")
    for name in ("plan", "status", "render-pf"):
        item = commands.add_parser(name)
        item.add_argument("--config", type=Path, required=True)
        item.add_argument("--snapshot", type=Path, required=True)
        item.add_argument("--admissions", type=Path)
        item.add_argument("--intent", type=Path)
        item.add_argument(
            "--now", type=float, help="injected fixture clock; omit for real observations"
        )
    for name in ("observe", "reconcile"):
        item = commands.add_parser(name)
        item.add_argument("--config", type=Path, required=True)
        item.add_argument("--bindings", type=Path, required=True)
        if name == "reconcile":
            item.add_argument("--admissions", type=Path, required=True)
            item.add_argument("--state-dir", type=Path, required=True)
            item.add_argument("--execute-user-owners", action="store_true")
            item.add_argument("--quiet-unchanged", action="store_true")
    for name in ("init-state", "pause", "resume", "suspend", "release", "acknowledge-journal"):
        item = commands.add_parser(name)
        item.add_argument("--state-dir", type=Path, required=True)
        if name in {"suspend", "release"}:
            item.add_argument("--operation", required=True)
            item.add_argument("--holder", required=True)
        if name == "acknowledge-journal":
            item.add_argument("--plan-digest", required=True)
    deploy = commands.add_parser("deploy", help="build and explicitly install protected releases")
    actions = deploy.add_subparsers(dest="deploy_command", required=True)
    item = actions.add_parser("validate")
    item.add_argument("--manifest", type=Path, required=True)
    item = actions.add_parser("build", aliases=["render"])
    item.add_argument("--deployment", "--manifest", dest="deployment", type=Path, required=True)
    item.add_argument("--config", type=Path, required=True)
    item.add_argument("--output", type=Path, required=True)
    for name in ("verify", "plan", "install-user", "install-root", "prepare-root"):
        item = actions.add_parser(name)
        item.add_argument("--bundle", type=Path, required=True)
        if name in {"plan", "prepare-root"}:
            if name == "plan":
                item.add_argument("--scope", choices=("user", "root"), required=True)
            else:
                item.add_argument("--output", type=Path, required=True)
        if name in {"verify", "install-user", "install-root"}:
            item.add_argument("--expected-digest", required=name != "verify")
    for name in ("rollback", "recover"):
        item = actions.add_parser(name)
        item.add_argument("--state-dir", type=Path, required=True)
        item.add_argument("--scope", choices=("user", "root"), required=True)
        item.add_argument("--expected-digest", required=True)
    return parser


def _deployment_operation(args: argparse.Namespace) -> int:
    if args.deploy_command == "validate":
        deployment = load_deployment(args.manifest)
        result = {"valid": True, "site": deployment.site, "jobs": len(deployment.jobs)}
    elif args.deploy_command in {"build", "render"}:
        result = render_bundle(
            load_deployment(args.deployment), load_config(args.config), args.output
        )
    elif args.deploy_command == "verify":
        result = validate_bundle(args.bundle, args.expected_digest)
    elif args.deploy_command == "plan":
        result = plan_install(args.bundle, args.scope)
    elif args.deploy_command == "prepare-root":
        result = prepare_root_bundle(args.bundle, args.output)
    elif args.deploy_command in {"install-user", "install-root"}:
        result = install_bundle(
            args.bundle,
            args.deploy_command.removeprefix("install-"),
            expected_digest=args.expected_digest,
        )
    elif args.deploy_command == "recover":
        result = recover_install(
            args.state_dir, args.scope, expected_failed_digest=args.expected_digest
        )
    else:
        result = rollback_install(
            args.state_dir, args.scope, expected_current_digest=args.expected_digest
        )
    _emit(result)
    return 0


def _load_intent(store: Store) -> Intent:
    try:
        return intent_from_dict(store.read("intent.json"))
    except (ValueError, OSError):
        return Intent(damaged=True)


def _intent_operation(args: argparse.Namespace) -> int:
    store = Store(args.state_dir)
    with store.lock():
        if args.command == "init-state":
            if (store.directory / "intent.json").exists():
                raise ValueError(
                    "operator intent already exists; initialization cannot overwrite it"
                )
            intent = Intent(operator_paused=True)
        elif args.command == "acknowledge-journal":
            previous = store.read("journal.json")
            if (
                not isinstance(previous, dict)
                or type(previous.get("schema_version")) is not int
                or previous.get("schema_version") != 1
                or previous.get("plan_digest") != args.plan_digest
                or previous.get("phase") not in {"planned", "applying", "failed"}
            ):
                raise ValueError(
                    "journal acknowledgement must identify the exact interrupted operation"
                )
            previous.update(phase="inhibited", operator_acknowledged=True, updated_at=time.time())
            store.write("journal.json", previous)
            _emit(
                {
                    "journal": "acknowledged",
                    "claim": "no repair, rollback or admission was performed",
                }
            )
            return 0
        else:
            current = _load_intent(store)
            if args.command == "pause":
                intent = current.pause()
            elif args.command == "resume":
                intent = current.resume()
            elif args.command == "suspend":
                intent = current.suspend(args.operation, args.holder)
            else:
                intent = current.release(args.operation, args.holder)
        store.write("intent.json", intent_to_dict(intent))
        _emit(intent_to_dict(intent))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "deploy" and args.deploy_command in {
            "install-user",
            "install-root",
            "recover",
            "rollback",
        }:
            require_mutation_qualified("deployment-mutation")
        if args.command in {"admit", "init-state", "resume", "release", "acknowledge-journal"}:
            require_mutation_qualified("authority-mutation")
        if args.command == "reconcile" and args.execute_user_owners:
            require_mutation_qualified("owner-execution")
        if args.command == "deploy":
            return _deployment_operation(args)
        if args.command in {
            "init-state",
            "pause",
            "resume",
            "suspend",
            "release",
            "acknowledge-journal",
        }:
            return _intent_operation(args)
        if args.command == "derive":
            value = canonical_json(to_dict(derive(args.source))) + "\n"
            if args.check:
                if args.output is None or read_bounded_file(args.output).decode("utf-8") != value:
                    raise ValueError(
                        "derived view differs; regenerate it from its authored sources"
                    )
            elif args.output is not None:
                args.output.write_text(value)
            else:
                print(value, end="")
            return 0
        if args.command == "demo":
            sample = resources.files("netorch").joinpath("example-network.json")
            config = (
                parse_config(sample.read_bytes())
                if sample.is_file()
                else load_config(Path(__file__).resolve().parents[2] / "examples/network.json")
            )
            _emit(simulate(config))
            return 0
        config = load_config(args.config)
        if args.command in {"review-admission", "admit"}:
            profile = config.profile(args.profile)
            owner = config.profile_owner(profile)
            expected = profile_digest(config, profile)
            if args.command == "review-admission":
                _emit(
                    {
                        "profile": asdict(profile),
                        "scope": asdict(config.scope(profile.scope)),
                        "service": asdict(config.service(profile.service)),
                        "owner": asdict(owner),
                        "digest": expected,
                        "root_admission_required": owner.privilege == "external-root",
                    }
                )
                return 0
            if (
                owner.privilege != "user"
                or os.geteuid() == 0
                or expected != args.expected_digest
                or (profile.safety.kind == "bounded" and not args.ack_bounded_risk)
            ):
                raise ValueError("exact independent user-owner admission is required")
            store = Store(args.state_dir)
            with store.lock():
                try:
                    admissions = admissions_from_dict(store.read("admissions.json"))
                except FileNotFoundError:
                    admissions = {}
                admissions[profile.id] = Admission(
                    profile.id, expected, args.approved_by, time.time(), args.ack_bounded_risk
                )
                store.write("admissions.json", admissions_to_dict(admissions))
            _emit({"admitted": profile.id, "digest": expected, "resumed": False})
            return 0
        if args.command == "validate":
            _emit(
                {
                    "valid": True,
                    "policy_digest": config_digest(config),
                    "profiles": len(config.profiles),
                }
            )
            return 0
        if args.command == "simulate":
            _emit(simulate(config))
            return 0
        if args.command in {"observe", "reconcile"}:
            clients = load_bindings(config, args.bindings)
            snapshot = observe(config, clients)
            if args.command == "observe":
                _emit(snapshot_to_dict(snapshot))
                return 0
            if args.execute_user_owners:
                store = Store(args.state_dir)
                intent = _load_intent(store)
            else:
                # A preview must not initialize host state or create a lock.
                try:
                    intent = intent_from_dict(strict_load(args.state_dir / "intent.json"))
                except (ValueError, OSError):
                    intent = Intent(damaged=True)
            admissions = admissions_from_dict(strict_load(args.admissions))
            now = time.time()
            admissions = effective_admissions(config, clients, snapshot, admissions, now)
            candidate = plan(config, snapshot, admissions, intent, now)
            if not args.execute_user_owners:
                _emit(
                    {
                        "execution": "not-requested",
                        "plan": plan_to_dict(candidate),
                        "discovery": [
                            asdict(action)
                            for action in plan_discovery(config, snapshot, candidate, intent, now)
                        ],
                    }
                )
                return 0
            result = execute(
                config,
                candidate,
                snapshot,
                intent,
                clients,
                store,
                admissions=admissions,
                now=now,
                observe_now=lambda: observe(config, clients),
            )
            if args.quiet_unchanged:
                stable = {
                    "phase": result.phase,
                    "completed": result.completed,
                    "pending": list(result.pending),
                    "policy": config_digest(config),
                    "intent": intent_to_dict(_load_intent(store)),
                    "services": {
                        key: {
                            "state": item.state,
                            "reason": item.reason,
                            "generation": item.generation,
                        }
                        for key, item in snapshot.services.items()
                    },
                    "profiles": {
                        key: {
                            "state": item.state,
                            "reason": item.reason,
                            "generation": item.generation,
                        }
                        for key, item in snapshot.profiles.items()
                    },
                }
                with store.lock():
                    try:
                        previous_status = store.read("status.json")
                    except FileNotFoundError:
                        previous_status = None
                    if previous_status != stable:
                        store.write("status.json", stable)
                        _emit(stable)
            else:
                _emit(asdict(result))
            return 0 if result.phase == "committed" else 69
        snapshot = snapshot_from_dict(strict_load(args.snapshot))
        admissions = admissions_from_dict(strict_load(args.admissions)) if args.admissions else {}
        intent = intent_from_dict(strict_load(args.intent)) if args.intent else Intent(damaged=True)
        now = args.now if args.now is not None else time.time()
        candidate = plan(config, snapshot, admissions, intent, now)
        if args.command == "render-pf":
            print(render(config, snapshot, admissions, intent, now), end="")
        elif args.command == "plan":
            _emit(plan_to_dict(candidate))
        else:
            _emit(
                {
                    "policy_digest": config_digest(config),
                    "observed_at": snapshot.observed_at,
                    "intent": intent_to_dict(intent),
                    "ready_profiles": sorted(candidate.ready_profiles),
                    "actions": plan_to_dict(candidate)["actions"],
                    "discovery": [
                        {
                            **asdict(action),
                            "dependencies_verified": set(
                                next(
                                    item.dependencies
                                    for item in config.discovery
                                    if item.id == action.id
                                )
                            )
                            <= candidate.ready_profiles,
                            "application_acceptance": "not-established",
                        }
                        for action in plan_discovery(config, snapshot, candidate, intent, now)
                    ],
                    "claim": (
                        "transport-policy evidence only; "
                        "physical application acceptance is separate"
                    ),
                }
            )
        return 0
    except StageNotQualified as exc:
        _emit(exc.to_dict())
        return NOT_QUALIFIED
    except Busy:
        _emit({"error": "busy", "message": "owner lock is held; no lock was replaced"})
        return 75
    except (ValueError, OSError, RuntimeError):
        # Provider/config errors may contain private paths or payloads. Export a
        # closed diagnostic; inspect the private owner evidence separately.
        _emit(
            {
                "error": "invalid-or-unverified",
                "message": "operation stopped; inspect private inputs and owner evidence",
            }
        )
        return 65


if __name__ == "__main__":
    sys.exit(main())

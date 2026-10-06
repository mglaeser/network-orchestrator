"""Explicit initial provisioning of declared native workloads, never recovery.

This is an operator maintenance command, not an executor capability. Existing
definitions are retained only when their complete enrolled fingerprint agrees;
this module never stops, deletes or replaces a container or edits its application.
"""

from __future__ import annotations

import argparse
import math
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .apple_runtime import Reader, Runner, RuntimeReadError, check_identity
from .codec import canonical_json, digest, strict_load, strict_loads
from .config import load_config, to_dict
from .model import Config
from .process import OutputLimit, ProcessTimeout, run
from .runtime_settings import RuntimeSettings, load_settings, settings_to_dict
from .state import intent_from_dict, intent_to_dict
from .storage import Busy, Store, UnsafeState
from .workflow_gate import NOT_QUALIFIED, StageNotQualified, require_mutation_qualified

_OPTIONS = {
    "--cpus",
    "--memory",
    "--env",
    "--env-file",
    "--gid",
    "--uid",
    "--user",
    "--ulimit",
    "--workdir",
    "--cap-add",
    "--cap-drop",
    "--dns",
    "--dns-domain",
    "--dns-option",
    "--dns-search",
    "--entrypoint",
    "--init-image",
    "--kernel",
    "--kernel-arg",
    "--label",
    "--mount",
    "--publish-socket",
    "--sysctl",
    "--volume",
}
_BOOL_OPTIONS = {"--init", "--read-only", "--rosetta", "--ssh", "--virtualization"}
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_IMAGE = re.compile(r"[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class Option:
    flag: str
    value: str | None


@dataclass(frozen=True, slots=True)
class Workload:
    service: str
    image: str
    options: tuple[Option, ...]
    arguments: tuple[str, ...]


def parse_workloads(value: Any) -> tuple[Workload, ...]:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "workloads"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(value["workloads"], list)
        or not 1 <= len(value["workloads"]) <= 256
    ):
        raise ValueError("invalid workload recipe envelope")
    workloads = []
    for item in value["workloads"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"service", "image", "options", "arguments"}
            or not isinstance(item["service"], str)
            or not _ID.fullmatch(item["service"])
            or not isinstance(item["image"], str)
            or not _IMAGE.fullmatch(item["image"])
            or not isinstance(item["options"], list)
            or len(item["options"]) > 256
            or not isinstance(item["arguments"], list)
            or len(item["arguments"]) > 256
        ):
            raise ValueError("invalid workload recipe")
        options = []
        for raw in item["options"]:
            if (
                not isinstance(raw, dict)
                or set(raw) != {"flag", "value"}
                or not isinstance(raw["flag"], str)
            ):
                raise ValueError("invalid workload option")
            flag, argument = raw["flag"], raw["value"]
            if flag in _BOOL_OPTIONS:
                if argument is not None:
                    raise ValueError("boolean workload option has a value")
            elif flag in _OPTIONS:
                if (
                    not isinstance(argument, str)
                    or not argument
                    or "\0" in argument
                    or "\n" in argument
                    or len(argument) > 16_384
                ):
                    raise ValueError("invalid workload argument")
                if flag == "--env" and "=" not in argument:
                    raise ValueError("environment inheritance is forbidden")
            else:
                raise ValueError("unsupported workload option")
            options.append(Option(flag, argument))
        if any(
            not isinstance(arg, str) or "\0" in arg or len(arg) > 16_384
            for arg in item["arguments"]
        ):
            raise ValueError("invalid workload process arguments")
        workloads.append(
            Workload(item["service"], item["image"], tuple(options), tuple(item["arguments"]))
        )
    if len({item.service for item in workloads}) != len(workloads):
        raise ValueError("duplicate workload recipes")
    return tuple(workloads)


def recipe_digest(workloads: tuple[Workload, ...]) -> str:
    return digest(
        {
            "strategy": "apple-initial-provision-v1",
            "workloads": [asdict(item) for item in workloads],
        }
    )


def create_arguments(config: Config, settings: RuntimeSettings, workload: Workload) -> list[str]:
    contract = settings.contract(workload.service)
    network = next(item for item in settings.networks if item.scope == contract.scope)
    argv = [
        "create",
        "--name",
        contract.name,
        "--platform",
        "linux/arm64",
        "--network",
        network.name,
    ]
    mount_sources: set[str] = set()
    for option in workload.options:
        if option.flag == "--volume":
            assert option.value is not None
            pieces = option.value.split(":")
            if (
                len(pieces) not in {2, 3}
                or not pieces[0].startswith("/")
                or not pieces[1].startswith("/")
                or (len(pieces) == 3 and pieces[2] not in {"ro", "rw"})
            ):
                raise ValueError("volume requires explicit absolute host and guest paths")
            mount_sources.add(pieces[0])
        if option.flag == "--mount":
            assert option.value is not None
            pairs = [piece.split("=", 1) for piece in option.value.split(",")]
            values = {pair[0]: pair[1] for pair in pairs if len(pair) == 2}
            if (
                len(values) != len([pair for pair in pairs if len(pair) == 2])
                # The vendor also reads `src` as the source and `dst` or
                # `destination` as the target, keeps the last spelling it saw
                # and drops an empty piece after a further `=`. Any other key,
                # or a value holding `=`, names a path that is not checked here.
                or set(values) != {"type", "source", "target"}
                or any("=" in value for value in values.values())
                or values["type"] != "bind"
                or not values["source"].startswith("/")
                or not values["target"].startswith("/")
                or any(pair not in [["readonly"]] and len(pair) != 2 for pair in pairs)
            ):
                raise ValueError("mount requires an unambiguous absolute bind source")
            mount_sources.add(values["source"])
        if option.flag == "--kernel-arg" and settings.accepted_version != "1.5.0":
            raise ValueError("kernel-arg requires its reviewed 1.5.0 CLI contract")
        if option.flag in {"--kernel", "--env-file"} and not any(
            item.path == option.value and item.kind == "file" and item.sha256 is not None
            for item in contract.receipts
        ):
            raise ValueError("external workload input requires a hashed file receipt")
        if option.flag == "--init-image" and (
            option.value is None or not _IMAGE.fullmatch(option.value)
        ):
            raise ValueError("init image must be pinned by digest")
        argv.append(option.flag)
        if option.value is not None:
            argv.append(option.value)
    if mount_sources != {item.path for item in contract.mounts}:
        raise ValueError("recipe mount sources must exactly match enrolled persistent identities")
    # Native port publications have exactly one author: the policy table.
    for profile in config.profiles:
        if profile.service == workload.service and profile.kind == "publication":
            assert profile.target_ports is not None
            host = (
                str(profile.ports.first)
                if profile.ports.width == 1
                else f"{profile.ports.first}-{profile.ports.last}"
            )
            guest = (
                str(profile.target_ports.first)
                if profile.target_ports.width == 1
                else f"{profile.target_ports.first}-{profile.target_ports.last}"
            )
            argv.extend(
                [
                    "--publish",
                    f"{config.scope(profile.scope).host_ipv4}:{host}:{guest}/{profile.protocol}",
                ]
            )
    argv.extend([workload.image, *workload.arguments])
    return argv


def provision_digest(
    config: Config,
    settings: RuntimeSettings,
    workloads: tuple[Workload, ...],
    *,
    start_initial: bool = False,
) -> str:
    """Approve resolved creation authority, never only an application recipe.

    Network/publication settings and enrollment independently affect native
    arguments. Include their closed canonical data and the resulting argv so
    changes to either data or compilation semantics require a new review.
    Hashing private argv does not disclose its environment or process values.
    """
    if type(start_initial) is not bool:
        raise ValueError("initial start mode must be an explicit boolean")
    return digest(
        {
            "strategy": "apple-resolved-initial-provision-v2",
            "create_cli_semantics": "apple-container-create-linux-arm64-v1",
            "recipe_digest": recipe_digest(workloads),
            "config": to_dict(config),
            "settings": settings_to_dict(settings),
            "create_argv": [create_arguments(config, settings, item) for item in workloads],
            "start_initial": start_initial,
        }
    )


def plan_workloads(
    config: Config,
    settings: RuntimeSettings,
    workloads: tuple[Workload, ...],
    runner: Runner = run,
    *,
    start_initial: bool = False,
) -> dict[str, Any]:
    if {item.service for item in workloads} != {item.service for item in settings.contracts} or {
        item.service for item in settings.contracts
    } != {item.id for item in config.services}:
        raise ValueError("recipes must cover exactly the enrolled policy services")
    reader = Reader(settings, runner)
    reader.version()
    for network in settings.networks:
        reader.helper(network)
        reader.network(config, network)
    inventory = reader.inventory()
    steps = []
    for workload in workloads:
        contract = settings.contract(workload.service)
        for identity in (*contract.mounts, *contract.receipts):
            check_identity(identity, deadline=reader.deadline, checked_acls=reader.checked_acls)
        listed = [item for item in inventory if item["id"] == contract.name]
        if listed:
            current = reader.inspect(contract.name)
            if (
                current != listed[0]
                or digest(current["configuration"]) != contract.configuration_sha256
            ):
                raise RuntimeReadError("identity-mismatch")
            action = (
                "retain"
                if current["state"] == "running"
                else "start-existing"
                if current["state"] == "stopped"
                else "blocked"
            )
        else:
            action = "create-stopped"
        create_arguments(config, settings, workload)  # Validate the complete CLI before any write.
        # Creation must not initiate an unbounded registry download. The pinned
        # image is fetched by an explicit preparatory vendor operation, then its
        # cached existence is verified before any workload write.
        images = strict_loads(reader.native(["image", "inspect", workload.image]))
        if not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict):
            raise RuntimeReadError("incomplete")
        # Plans intentionally omit argv/environment/arguments: private recipes
        # may contain application secrets. Only content digests are displayed.
        steps.append({"service": workload.service, "name": contract.name, "action": action})
    return {
        "schema_version": 1,
        "recipe_digest": recipe_digest(workloads),
        "provision_digest": provision_digest(
            config, settings, workloads, start_initial=start_initial
        ),
        "start_initial": start_initial,
        "steps": steps,
        "automatic_recreation": False,
    }


def _operator_store(settings: RuntimeSettings) -> Store:
    if (
        os.geteuid() == 0
        or os.geteuid() != settings.account.uid
        or settings.state_dir is None
        or settings.intent != str(Path(settings.state_dir) / "intent.json")
    ):
        raise PermissionError(
            "initial provisioning requires the enrolled operator and intent store"
        )
    directory = Path(settings.state_dir)
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("existing operator state store is required")
    return Store(directory)


def _workload_journal(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version",
        "recipe_digest",
        "provision_digest",
        "start_initial",
        "holder",
        "phase",
        "completed",
        "updated_at",
    }
    acknowledgements = {"operator_acknowledged", "acknowledgement_phase", "acknowledged_at"}
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("phase"), str)
        or value["phase"]
        not in {
            "applying",
            "failed",
            "committed",
            "acknowledged",
        }
    ):
        raise ValueError("invalid workload journal")
    expected = fields | acknowledgements if value["phase"] == "acknowledged" else fields
    if (
        set(value) != expected
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or any(
            not isinstance(value[key], str) or not _HASH.fullmatch(value[key])
            for key in ("recipe_digest", "provision_digest")
        )
        or type(value["start_initial"]) is not bool
        or value["holder"] != "provision-" + value["provision_digest"][:32]
        or not isinstance(value["completed"], list)
        or len(value["completed"]) > 256
        or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in value["completed"])
        or len(value["completed"]) != len(set(value["completed"]))
    ):
        raise ValueError("invalid workload journal fields")
    for key in ("updated_at", *(("acknowledged_at",) if value["phase"] == "acknowledged" else ())):
        timestamp = value[key]
        if (
            type(timestamp) not in {int, float}
            or timestamp < 0
            or timestamp > sys.float_info.max
            or not math.isfinite(timestamp)
        ):
            raise ValueError("invalid workload journal timestamp")
    if value["phase"] == "acknowledged" and (
        value["operator_acknowledged"] is not True
        or not isinstance(value["acknowledgement_phase"], str)
        or value["acknowledgement_phase"] not in {"applying", "failed"}
        or value["acknowledged_at"] > value["updated_at"]
    ):
        raise ValueError("invalid workload acknowledgement")
    return value


def acknowledge_workload_operation(
    settings: RuntimeSettings,
    *,
    expected_digest: str,
    holder: str,
    expected_phase: str,
) -> dict[str, Any]:
    """Record explicit inspection and release only the exact interrupted holder.

    The durable operator pause remains. This command performs no runtime reads
    or lifecycle operation and makes no claim to repair partial provisioning.
    An interrupted acknowledgement is retryable only while its exact hold is
    still present; unrelated intent can never be cleared through this path.
    """
    if (
        not isinstance(expected_digest, str)
        or not _HASH.fullmatch(expected_digest)
        or holder != "provision-" + expected_digest[:32]
        or not isinstance(expected_phase, str)
        or expected_phase not in {"failed", "applying"}
    ):
        raise ValueError("exact failed workload identity is required")
    store = _operator_store(settings)
    with store.lock():
        intent = intent_from_dict(store.read("intent.json"))
        journal = _workload_journal(store.read("workload-journal.json"))
        phase = (
            journal["acknowledgement_phase"]
            if journal["phase"] == "acknowledged"
            else journal["phase"]
        )
        if (
            not intent.operator_paused
            or intent.damaged
            or intent.suspensions.get("initial-provision") != holder
            or journal["provision_digest"] != expected_digest
            or journal["holder"] != holder
            or phase != expected_phase
        ):
            raise ValueError("inspected interrupted workload and exact held pause are required")
        if journal["phase"] != "acknowledged":
            acknowledged = time.time()
            journal = {
                **journal,
                "phase": "acknowledged",
                "operator_acknowledged": True,
                "acknowledgement_phase": expected_phase,
                "acknowledged_at": acknowledged,
                "updated_at": acknowledged,
            }
            store.write("workload-journal.json", journal)
        # Persist acknowledgement before releasing negative authority. A crash
        # between these writes leaves the exact operation held and retryable.
        store.write("intent.json", intent_to_dict(intent.release("initial-provision", holder)))
        return {
            "acknowledged": True,
            "provision_digest": expected_digest,
            "operator_paused": True,
            "remaining_suspensions": sorted(intent.suspensions.keys() - {"initial-provision"}),
            "lifecycle_changed": False,
            "admitted": False,
        }


def provision_workloads(
    config: Config,
    settings: RuntimeSettings,
    workloads: tuple[Workload, ...],
    *,
    expected_digest: str,
    start_initial: bool = False,
    runner: Runner = run,
) -> dict[str, Any]:
    store = _operator_store(settings)
    if expected_digest != provision_digest(
        config, settings, workloads, start_initial=start_initial
    ):
        raise ValueError("exact resolved provisioning digest was not approved")
    holder = "provision-" + expected_digest[:32]
    with store.lock():
        intent = intent_from_dict(store.read("intent.json"))
        # A hold on any service is maintenance in progress, like a suspension.
        if not intent.operator_paused or intent.damaged or intent.suspensions or intent.holds:
            raise ValueError(
                "initial provisioning requires operator pause and no competing maintenance"
            )
        if (store.directory / "workload-journal.json").exists():
            previous = _workload_journal(store.read("workload-journal.json"))
            if previous["phase"] not in {"committed", "acknowledged"}:
                raise ValueError(
                    "unfinished workload provision requires inspected operator recovery"
                )
        candidate = plan_workloads(config, settings, workloads, runner, start_initial=start_initial)
        if any(step["action"] == "blocked" for step in candidate["steps"]):
            raise RuntimeReadError("incomplete")
        intent = intent.suspend("initial-provision", holder)
        store.write("intent.json", intent_to_dict(intent))
        journal: dict[str, Any] = {
            "schema_version": 1,
            "recipe_digest": recipe_digest(workloads),
            "provision_digest": expected_digest,
            "start_initial": start_initial,
            "holder": holder,
            "phase": "applying",
            "completed": [],
            "updated_at": time.time(),
        }
        store.write("workload-journal.json", journal)
        try:
            hashes = {
                settings.contract(step["service"]).name: settings.contract(
                    step["service"]
                ).configuration_sha256
                for step in candidate["steps"]
                if step["action"] != "create-stopped"
            }
            for workload, step in zip(workloads, candidate["steps"], strict=True):
                reader = Reader(settings, runner)
                reader.version()
                for network in settings.networks:
                    reader.helper(network)
                    reader.network(config, network)
                inventory = reader.inventory()
                for name, expected in hashes.items():
                    listed = [item for item in inventory if item["id"] == name]
                    if (
                        len(listed) != 1
                        or digest(listed[0]["configuration"]) != expected
                        or reader.inspect(name) != listed[0]
                    ):
                        raise RuntimeReadError("generation-mismatch")
                for identity in (
                    *settings.contract(workload.service).mounts,
                    *settings.contract(workload.service).receipts,
                ):
                    check_identity(
                        identity, deadline=reader.deadline, checked_acls=reader.checked_acls
                    )
                if step["action"] == "create-stopped":
                    if any(item["id"] == step["name"] for item in inventory):
                        raise RuntimeReadError("generation-mismatch")
                    Reader(settings, runner).native(create_arguments(config, settings, workload))
                    created = Reader(settings, runner).inspect(step["name"])
                    if created["state"] != "stopped":
                        raise RuntimeReadError("incomplete")
                    hashes[step["name"]] = digest(created["configuration"])
                if start_initial and step["action"] in {"create-stopped", "start-existing"}:
                    Reader(settings, runner).native(["start", step["name"]])
                    if Reader(settings, runner).inspect(step["name"])["state"] != "running":
                        raise RuntimeReadError("incomplete")
                journal["completed"].append(workload.service)
                store.write("workload-journal.json", journal)
            journal["phase"] = "committed"
            store.write("workload-journal.json", journal)
            store.write("intent.json", intent_to_dict(intent.release("initial-provision", holder)))
            return {
                "provisioned": True,
                "operator_paused": True,
                "admitted": False,
                "enrollment_required": True,
                "started_initial": start_initial,
            }
        except BaseException:
            journal["phase"] = "failed"
            store.write("workload-journal.json", journal)
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", required=True, type=Path)
    parser.add_argument("--recipes", type=Path)
    actions = parser.add_subparsers(dest="command", required=True)
    item = actions.add_parser("plan")
    item.add_argument("--start-initial", action="store_true")
    item = actions.add_parser("acknowledge")
    item.add_argument("--expected-digest", required=True)
    item.add_argument("--holder", required=True)
    item.add_argument("--phase", choices=("failed", "applying"), required=True)
    item = actions.add_parser("provision")
    item.add_argument("--expected-digest", required=True)
    item.add_argument("--start-initial", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command in {"provision", "acknowledge"}:
            require_mutation_qualified("workload-provisioning")
        settings = load_settings(args.settings)
        if args.command == "acknowledge":
            print(
                canonical_json(
                    acknowledge_workload_operation(
                        settings,
                        expected_digest=args.expected_digest,
                        holder=args.holder,
                        expected_phase=args.phase,
                    )
                )
            )
            return 0
        if settings.policy is None or args.recipes is None:
            raise ValueError("workload policy path is required")
        config = load_config(Path(settings.policy))
        workloads = parse_workloads(strict_load(args.recipes))
        value = (
            plan_workloads(config, settings, workloads, start_initial=args.start_initial)
            if args.command == "plan"
            else provision_workloads(
                config,
                settings,
                workloads,
                expected_digest=args.expected_digest,
                start_initial=args.start_initial,
            )
        )
        print(canonical_json(value))
        return 0
    except StageNotQualified as exc:
        print(canonical_json(exc.to_dict()), file=sys.stderr)
        return NOT_QUALIFIED
    except Busy:
        print(canonical_json({"error": "workload-maintenance-busy"}), file=sys.stderr)
        return 75
    except (ValueError, OSError, RuntimeError, UnsafeState, ProcessTimeout, OutputLimit):
        print(
            canonical_json({"error": "workload-evidence-or-authority-incomplete"}), file=sys.stderr
        )
        return 69


if __name__ == "__main__":
    raise SystemExit(main())

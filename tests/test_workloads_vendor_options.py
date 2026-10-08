"""A recipe carries only options that the vendor's `create` defines."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import netorch.workloads as module
from netorch.codec import strict_load
from netorch.workloads import (
    Option,
    create_arguments,
    parse_workloads,
    plan_workloads,
    provision_digest,
)
from tests.test_workloads import fleet

EXAMPLES = Path(__file__).parents[1] / "examples"
PIN = "example.invalid/service@sha256:" + "1" * 64
RANGE = 'sysctl.net.ipv4.ip_local_port_range="45000 45127"'

# Long option names that apple/container declares in
# `Sources/Services/ContainerAPIService/Client/Flags.swift` at each of the tags
# 1.2.0, 1.4.1 and 1.5.0. The two later tags add `--masked-path` and
# `--read-only-path`; none of the three declares a sysctl option.
VENDOR_OPTIONS = frozenset(
    {
        "--arch",
        "--cap-add",
        "--cap-drop",
        "--cidfile",
        "--cpus",
        "--cwd",
        "--debug",
        "--detach",
        "--dns",
        "--dns-domain",
        "--dns-option",
        "--dns-search",
        "--entrypoint",
        "--env",
        "--env-file",
        "--gid",
        "--init",
        "--init-image",
        "--interactive",
        "--kernel",
        "--kernel-arg",
        "--label",
        "--max-concurrent-downloads",
        "--memory",
        "--mount",
        "--name",
        "--network",
        "--no-dns",
        "--os",
        "--platform",
        "--progress",
        "--publish",
        "--publish-socket",
        "--read-only",
        "--remove",
        "--rm",
        "--rosetta",
        "--runtime",
        "--scheme",
        "--shm-size",
        "--ssh",
        "--tmpfs",
        "--tty",
        "--uid",
        "--ulimit",
        "--user",
        "--virtualization",
        "--volume",
        "--workdir",
    }
)


def recipe(flag: str, value: str | None) -> dict[str, Any]:
    row = {"service": "example", "image": PIN, "options": [{"flag": flag, "value": value}]}
    return {"schema_version": 1, "workloads": [{**row, "arguments": []}]}


def legacy(settings: Any, version: str) -> Any:
    return replace(settings, accepted_version=version, legacy_risk_acknowledged=version == "1.2.0")


def test_the_allowlist_names_only_options_the_vendor_defines() -> None:
    assert module._OPTIONS | module._BOOL_OPTIONS <= VENDOR_OPTIONS


@pytest.mark.parametrize("value", ["vm.swappiness=40", "kernel.shmmax=1"])
def test_a_recipe_cannot_carry_a_sysctl_option(value: str) -> None:
    with pytest.raises(ValueError, match="unsupported workload option"):
        parse_workloads(recipe("--sysctl", value))


@pytest.mark.parametrize("version", ["1.2.0", "1.4.1", "1.5.0"])
def test_a_kernel_argument_is_compiled_for_each_reader_version(
    tmp_path: Path, version: str
) -> None:
    config, settings, _, workloads, _ = fleet(tmp_path)
    workload = replace(workloads[0], options=(Option("--kernel-arg", RANGE),))
    arguments = create_arguments(config, legacy(settings, version), workload)
    assert arguments[arguments.index("--kernel-arg") + 1] == RANGE


@pytest.mark.parametrize("version", ["1.3.0", "1.6.0", "9.9.9"])
def test_a_kernel_argument_is_refused_for_a_version_nobody_has_read(
    tmp_path: Path, version: str
) -> None:
    config, settings, _, workloads, _ = fleet(tmp_path)
    workload = replace(workloads[0], options=(Option("--kernel-arg", RANGE),))
    with pytest.raises(ValueError, match="vendor version whose source defines it"):
        create_arguments(config, replace(settings, accepted_version=version), workload)


@pytest.mark.parametrize("version", ["1.2.0", "1.4.1"])
def test_a_running_fleet_with_a_kernel_argument_plans_on_an_older_version(
    tmp_path: Path, version: str
) -> None:
    config, settings, fake, workloads, _ = fleet(tmp_path)
    settings = legacy(settings, version)
    fake.settings = settings
    fake.existing = {item.name: fake.snapshot(item.name) for item in settings.contracts}
    recipes = (replace(workloads[0], options=(Option("--kernel-arg", RANGE),)), *workloads[1:])
    plan = plan_workloads(config, settings, recipes, fake)
    assert {step["action"] for step in plan["steps"]} == {"retain"}
    assert plan["provision_digest"] == provision_digest(config, settings, recipes)
    assert not any(argv[1:2] in (["create"], ["start"]) for argv, _ in fake.calls)


def test_the_starter_recipe_sets_its_port_range_with_a_vendor_option() -> None:
    raw = strict_load(EXAMPLES / "workloads.json")
    rows = [
        (option["flag"], option["value"]) for item in raw["workloads"] for option in item["options"]
    ]
    assert {flag for flag, _ in rows} <= VENDOR_OPTIONS
    assert ("--kernel-arg", RANGE) in rows
    assert parse_workloads(raw)

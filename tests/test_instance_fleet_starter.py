"""The instance names who starts the workloads and the runtime after a boot.

`lifecycle_tools[].kind` has the value `supervisor`, and that one tool may carry
`starts_fleet: true`. An instance that accepts unattended recovery without a
declared starter of the workloads and of the runtime reads `not-fulfilled`.
Instances without the new member keep their bytes, both digests and reports.
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import host_cli
from netorch.codec import canonical_bytes
from netorch.host_report import build_report, empty_evidence
from netorch.instance import (
    InstanceError,
    canonical_instance_bytes,
    instance_contract_digest,
    instance_digest,
    instance_to_dict,
    instance_validator,
    load_instance,
    parse_instance,
)
from netorch.requirements import REQUIREMENTS, requirement
from tests.test_report_truthfulness import (
    EXAMPLES,
    NOW,
    attest,
    fact,
    platform,
    report,
    row,
)

# Taken from the tree before the member existed: (instance digest, contract digest).
EXAMPLE_DIGESTS = {
    "instance.json": (
        "f0adf2a76ad106f1ed758b0ab9f05388a15b4e11934f37faa68e377190ff732e",
        "bc7d92900c617507a7d1dfe150df3600fff3d5ad29c1a0a72b467779f16f7a9c",
    ),
    "instance-structural.json": (
        "345a770371a6dc244234050cd606dd5222d277782a2c27529bc568f5fb92bb23",
        "6489191df8f66f366323fcd61091c69a45bc2676f5f215e25f6a218674a3fa5e",
    ),
}
UNDECIDED = "Unattended recovery and its DNS-ready limit are undecided."
NEEDS_A_PERSON = "FileVault needs a person; automatic login cannot establish unattended recovery."
# What the base tree reports for the two examples, neither of which accepts unattended recovery.
EXAMPLE_REASONS = {"instance.json": UNDECIDED, "instance-structural.json": NEEDS_A_PERSON}
NO_STARTER = (
    "Unattended recovery is accepted but no declared tool starts the workloads "
    "(or the runtime) after a boot."
)
# The row's reason once nothing but its proving test at the recorded tier is missing.
# The tests name this reason, not the status, which an open change renames.
DECLARED = "Declared capability requires its proving test at the recorded host tier."
TOOL_KEYS = {"id", "kind", "container_api_access", "starts_runtime", "version"}


@pytest.fixture
def data() -> dict[str, Any]:
    return json.loads((EXAMPLES / "instance.json").read_bytes())


def parsed(data: dict[str, Any]) -> Any:
    return parse_instance(canonical_bytes(data) + b"\n")


def tool(identifier: str = "example-supervisor", **members: Any) -> dict[str, Any]:
    return {
        "id": identifier,
        "kind": "supervisor",
        "container_api_access": True,
        "starts_runtime": None,
        "version": None,
        **members,
    }


def accepted(data: dict[str, Any], *tools: dict[str, Any]) -> dict[str, Any]:
    """Unattended recovery accepted on a host whose FileVault is declared off."""
    data = copy.deepcopy(data)
    data["decisions"]["unattended_recovery"] = {"accepted": True, "max_dns_ready_seconds": 60}
    data["host"]["baseline"]["filevault"] = False
    data["lifecycle_tools"].extend(tools)
    return data


def boot_recovery(data: dict[str, Any], **kwargs: Any) -> tuple[str, str]:
    result = row(report(data, **kwargs), "BOOT-RECOVERY")
    return result["status"], result["reason"]


def test_only_one_tool_starts_the_fleet(data: dict[str, Any]) -> None:
    def with_tools(*tools: dict[str, Any]) -> dict[str, Any]:
        return {**data, "lifecycle_tools": [*data["lifecycle_tools"], *tools]}

    # The kind alone, and the kind with the member, are valid.
    assert parsed(with_tools(tool())).lifecycle_tools[-1].starts_fleet is False
    assert parsed(with_tools(tool(starts_fleet=True))).lifecycle_tools[-1].starts_fleet is True
    one_supervisor, starter_only = "at most one supervisor tool", "starts the fleet"
    refused = [
        # A second supervisor, with or without the member.
        (with_tools(tool(), tool("example-second")), one_supervisor),
        (with_tools(tool(starts_fleet=True), tool("example-second")), one_supervisor),
        (
            with_tools(tool(starts_fleet=True), tool("example-second", starts_fleet=True)),
            one_supervisor,
        ),
        # The member on a tool of another kind.
        (with_tools(tool(kind="application-manager", starts_fleet=True)), starter_only),
        (with_tools(tool(kind="vendor-cli", starts_fleet=True)), starter_only),
        # A starter that cannot reach the container API.
        (with_tools(tool(container_api_access=False, starts_fleet=True)), starter_only),
    ]
    for document, reason in refused:
        with pytest.raises(InstanceError, match=reason):
            parsed(document)
    # The existing tool of the example is a vendor CLI: it cannot take the member either.
    document = copy.deepcopy(data)
    document["lifecycle_tools"][0]["starts_fleet"] = True
    with pytest.raises(InstanceError, match=starter_only):
        parsed(document)


@pytest.mark.parametrize("value", [False, None, 1, 0, "true", [True], {}])
def test_starts_fleet_is_written_only_as_true(data: dict[str, Any], value: Any) -> None:
    data["lifecycle_tools"].append(tool(starts_fleet=value))
    with pytest.raises(InstanceError):
        parsed(data)


def test_a_supervisor_is_a_declared_kind_and_unknown_kinds_stay_refused(
    data: dict[str, Any],
) -> None:
    kinds = instance_validator().schema["properties"]["lifecycle_tools"]["items"]["properties"][
        "kind"
    ]["enum"]
    assert "supervisor" in kinds
    data["lifecycle_tools"].append(tool(kind="scheduler"))
    with pytest.raises(InstanceError):
        parsed(data)


@pytest.mark.parametrize("name", sorted(EXAMPLE_DIGESTS))
def test_starts_fleet_is_left_out_of_the_canonical_form(name: str) -> None:
    committed = (EXAMPLES / name).read_bytes()
    instance = load_instance(EXAMPLES / name)
    assert canonical_instance_bytes(instance) == committed
    assert (instance_digest(instance), instance_contract_digest(instance)) == EXAMPLE_DIGESTS[name]
    assert all(set(item) == TOOL_KEYS for item in instance_to_dict(instance)["lifecycle_tools"])
    # Naming the model's default changes nothing either.
    spelled = replace(
        instance,
        lifecycle_tools=tuple(
            replace(item, starts_fleet=False) for item in instance.lifecycle_tools
        ),
    )
    assert canonical_instance_bytes(spelled) == committed

    declared = json.loads(committed)
    declared["lifecycle_tools"].append(tool(starts_fleet=True))
    starter = parsed(declared)
    assert instance_to_dict(starter) == declared
    assert parsed(json.loads(canonical_instance_bytes(starter))) == starter
    members = [set(item) for item in instance_to_dict(starter)["lifecycle_tools"]]
    assert members == [*[TOOL_KEYS] * (len(members) - 1), TOOL_KEYS | {"starts_fleet"}]
    # The declaration is part of what the instance contracts.
    assert instance_digest(starter) != EXAMPLE_DIGESTS[name][0]
    assert instance_contract_digest(starter) != EXAMPLE_DIGESTS[name][1]


@pytest.mark.parametrize("name", sorted(EXAMPLE_DIGESTS))
def test_the_shipped_examples_report_as_before(name: str, capsys: Any) -> None:
    instance = load_instance(EXAMPLES / name)
    result = build_report(instance, empty_evidence(NOW), now=NOW, data_directory=EXAMPLES)
    assert instance.decisions.unattended_recovery.accepted is None
    boot = row(result, "BOOT-RECOVERY")
    assert (boot["status"], boot["reason"]) == ("not-fulfilled", EXAMPLE_REASONS[name])
    committed = json.loads((EXAMPLES / name).read_bytes())
    assert result["lifecycle_tools"] == committed["lifecycle_tools"]
    assert all(set(item) == TOOL_KEYS for item in result["lifecycle_tools"])
    # The registry row itself is unchanged: its tests are printed in every report.
    assert requirement("BOOT-RECOVERY").proving_tests == (
        "test_filevault_on_does_not_fulfil_unattended_recovery",
    )
    assert len(REQUIREMENTS) == len(result["requirements"])
    for command, code in (("status", 0), ("report", 0), ("check", 1), ("plan", 0)):
        assert host_cli.main([command, "--instance", str(EXAMPLES / name)], now=NOW) == code
        assert '"starts_fleet"' not in capsys.readouterr().out


def test_a_declared_starter_is_reported_with_its_member(data: dict[str, Any]) -> None:
    document = accepted(data, tool(starts_fleet=True, starts_runtime=True))
    assert report(document)["lifecycle_tools"] == document["lifecycle_tools"]


def test_accepted_unattended_recovery_needs_a_declared_starter(data: dict[str, Any]) -> None:
    # Nobody starts anything.
    assert boot_recovery(accepted(data)) == ("not-fulfilled", NO_STARTER)
    # A starter of the workloads, but nobody starts the runtime.
    for runtime in (None, False):
        document = accepted(data, tool(starts_fleet=True, starts_runtime=runtime))
        assert boot_recovery(document) == ("not-fulfilled", NO_STARTER)
    # The runtime is started, but nobody starts the workloads.
    assert boot_recovery(accepted(data, tool(starts_runtime=True))) == ("not-fulfilled", NO_STARTER)
    manager = tool("example-login-item", kind="application-manager", starts_runtime=True)
    assert boot_recovery(accepted(data, manager)) == ("not-fulfilled", NO_STARTER)
    # Both named: by one tool, or by the supervisor and another tool.
    for tools in (
        (tool(starts_fleet=True, starts_runtime=True),),
        (tool(starts_fleet=True), manager),
        (tool(starts_fleet=True, starts_runtime=False), manager),
    ):
        current, reason = boot_recovery(accepted(data, *tools))
        assert current != "not-fulfilled" and reason == DECLARED


def test_the_starter_rule_applies_only_to_an_accepted_recovery(data: dict[str, Any]) -> None:
    starter = tool(starts_fleet=True, starts_runtime=True)
    for decision in (
        {"accepted": None, "max_dns_ready_seconds": None},
        {"accepted": False, "max_dns_ready_seconds": None},
        {"accepted": True, "max_dns_ready_seconds": None},
        {"accepted": None, "max_dns_ready_seconds": 60},
    ):
        for tools in ((), (starter,)):
            document = accepted(data, *tools)
            document["decisions"]["unattended_recovery"] = decision
            assert boot_recovery(document) == ("not-fulfilled", UNDECIDED)
    # FileVault that needs a person is reported first, starter or not.
    for tools in ((), (starter,)):
        document = accepted(data, *tools)
        document["host"]["baseline"]["filevault"] = True
        assert boot_recovery(document) == ("not-fulfilled", NEEDS_A_PERSON)
    # With a starter the remaining FileVault rule still decides.
    document = accepted(data, starter)
    document["host"]["baseline"]["filevault"] = None
    current, reason = boot_recovery(document)
    assert current == "not-fulfilled" and reason.startswith("FileVault is neither")
    assert boot_recovery(document, facts=[fact("filevault", "off")])[1] == DECLARED


def test_retained_acceptance_cannot_stand_in_for_a_starter(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    without = accepted(data)
    attest(without, tmp_path, "BOOT-RECOVERY", "unattended-reboot", 4)
    assert boot_recovery(without, facts=platform(), evidence_directory=tmp_path) == (
        "not-fulfilled",
        NO_STARTER,
    )
    # Naming the starter afterwards changes the contract the old record was made for.
    renamed = copy.deepcopy(without)
    renamed["lifecycle_tools"].append(tool(starts_fleet=True, starts_runtime=True))
    assert boot_recovery(renamed, facts=platform(), evidence_directory=tmp_path)[1] == DECLARED
    renewed = accepted(data, tool(starts_fleet=True, starts_runtime=True))
    attest(renewed, tmp_path, "BOOT-RECOVERY", "unattended-reboot", 4)
    assert (
        boot_recovery(renewed, facts=platform(), evidence_directory=tmp_path)[0]
        == "fulfilled-verified"
    )


def test_two_starters_in_a_model_built_without_the_loader_are_not_one(
    data: dict[str, Any],
) -> None:
    one = parsed(accepted(data, tool(starts_fleet=True, starts_runtime=True)))
    second = replace(one.lifecycle_tools[-1], id="example-second")
    two = replace(one, lifecycle_tools=(*one.lifecycle_tools, second))
    with pytest.raises(InstanceError):
        canonical_instance_bytes(two)

    def assess(instance: Any) -> tuple[str, str]:
        result = build_report(instance, empty_evidence(NOW), now=NOW, data_directory=EXAMPLES)
        return row(result, "BOOT-RECOVERY")["status"], row(result, "BOOT-RECOVERY")["reason"]

    assert assess(one)[1] == DECLARED
    assert assess(two) == ("not-fulfilled", NO_STARTER)

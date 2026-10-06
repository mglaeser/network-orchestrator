"""An instance can describe a site supervisor that differs from the retained one."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import instance as instance_module
from netorch import instance_model
from netorch.codec import canonical_bytes, strict_loads
from netorch.instance import (
    InstanceError,
    canonical_instance_bytes,
    instance_contract_digest,
    instance_digest,
    instance_to_dict,
    load_instance,
    resolved_discovery_digest,
    resolved_profile_digest,
    validate_instance,
)
from netorch.runtime_settings import parse_settings
from netorch.safety_contract import RECOVERY_FAILURE_EXIT_CODE
from tests.test_report_truthfulness import (
    EXAMPLES,
    attest,
    deviation,
    parsed,
    platform,
    report,
    row,
    status,
)

ROOT = Path(__file__).resolve().parents[1]
AMBIGUOUS = "A declared start status can also be produced by a signal or by a tool's own failure."
# Taken from the tree before the vocabulary was widened: the bytes and every content
# digest of the two shipped examples.
BASE = {
    "instance.json": {
        "bytes": "d22664f2dadc18ba4cf907479db29340b4af4bc97795c7cd569ddcb8a3285518",
        "instance": "f0adf2a76ad106f1ed758b0ab9f05388a15b4e11934f37faa68e377190ff732e",
        "contract": "bc7d92900c617507a7d1dfe150df3600fff3d5ad29c1a0a72b467779f16f7a9c",
        "profiles": {
            "example-publication": (
                "c4a4f20fb44b4b46fcbdffd4b2a4205c4149faf106208260fe69ecc9dde88425"
            ),
            "example-return": "080ed8c0a2d16eb4e54110730ed205c4aee77d117c4c8c6facb490c23780a208",
        },
        "discovery": {
            "example-export": "a87cb58580aef982e565caa79bb489da0f3996ac5e1c3c45709c3811c6f1ff86",
            "example-import": "3a399f2f69074be0231e436d0902815936a10c506b77ec7c6cdf609e002c7af3",
        },
    },
    "instance-structural.json": {
        "bytes": "3656fa2b945b829525f03508b145c6993c7adfcd89bc83c7559f0b3086bf449a",
        "instance": "345a770371a6dc244234050cd606dd5222d277782a2c27529bc568f5fb92bb23",
        "contract": "6489191df8f66f366323fcd61091c69a45bc2676f5f215e25f6a218674a3fa5e",
        "profiles": {
            "example-publication": (
                "d9e1f0bbf592e18a6a6ff88177539f55f092748a84953a4eba984390401e24b4"
            ),
        },
        "discovery": {
            "example-export": "397d48b2f0097fe344366050efc7ff1ffa9e9178445189ed3d8819c3c766e54d",
        },
    },
}


@pytest.fixture
def data() -> dict[str, Any]:
    return json.loads((EXAMPLES / "instance.json").read_bytes())


def ensured(data: dict[str, Any], code: int = 45) -> dict[str, Any]:
    """The example with its one component restored by the supervisor on a second status."""
    result = copy.deepcopy(data)
    result["workloads"][1]["components"][0]["recovery"] = "supervisor-ensure"
    result["supervision"]["component_exit_code"] = code
    return result


def refused(data: dict[str, Any]) -> None:
    with pytest.raises(InstanceError):
        parsed(data)


def label(value: Any) -> str | None:
    """Readable test identifiers for a member path and for the value put there."""
    if isinstance(value, tuple):
        return ".".join(str(part) for part in value)
    if isinstance(value, dict):
        return canonical_bytes(value).decode()
    return None


def gaps(instance: Any) -> tuple[str, ...]:
    # New names are reached through their modules, so that on a tree without the
    # vocabulary this file still collects and each test fails or passes on its own.
    return tuple(instance_module.retained_supervision_gaps(instance))


@pytest.mark.parametrize("name", sorted(BASE))
def test_existing_instances_keep_bytes_and_digests_under_the_wider_schema(name: str) -> None:
    expected = BASE[name]
    raw = (EXAMPLES / name).read_bytes()
    instance = load_instance(EXAMPLES / name)
    assert hashlib.sha256(raw).hexdigest() == expected["bytes"]
    assert canonical_instance_bytes(instance) == raw
    assert instance_digest(instance) == expected["instance"]
    assert instance_contract_digest(instance) == expected["contract"]
    assert {
        item.id: resolved_profile_digest(instance, item) for item in instance.transport
    } == expected["profiles"]
    assert {
        item.id: resolved_discovery_digest(instance, item) for item in instance.discovery
    } == expected["discovery"]
    result = report(json.loads(raw))
    assert result["instance_digest"] == expected["instance"]
    assert result["contract_digest"] == expected["contract"]
    assert {item["id"]: item["desired_digest"] for item in result["profiles"]} == expected[
        "profiles"
    ]
    assert row(result, "UNKNOWN-NO-RECOVERY")["status"] == "fulfilled-verified"
    assert row(result, "UNKNOWN-NO-RECOVERY")["reason"] != AMBIGUOUS


@pytest.mark.parametrize(
    ("code", "valid"),
    [
        (1, True),
        (10, True),
        (42, True),
        (125, True),
        (0, False),
        (-1, False),
        (126, False),
        (255, False),
        (True, False),
        ("42", False),
        (42.0, False),
        (None, False),
    ],
)
def test_failure_exit_code_accepts_1_to_125_only(
    data: dict[str, Any], code: Any, valid: bool
) -> None:
    data["supervision"]["failure_exit_code"] = code
    if valid:
        assert parsed(data).supervision.failure_exit_code == code
    else:
        refused(data)
    # The member stays required.
    del data["supervision"]["failure_exit_code"]
    refused(data)


def test_component_exit_code_and_supervisor_ensure_need_each_other(
    data: dict[str, Any],
) -> None:
    both = ensured(data)
    instance = parsed(both)
    assert instance.supervision.component_exit_code == 45
    assert instance.workloads[1].components[0].recovery == "supervisor-ensure"
    assert canonical_instance_bytes(instance) == canonical_bytes(both) + b"\n"
    code_only = copy.deepcopy(both)
    code_only["workloads"][1]["components"][0]["recovery"] = "component-owner"
    refused(code_only)
    component_only = copy.deepcopy(both)
    del component_only["supervision"]["component_exit_code"]
    refused(component_only)
    # One status cannot mean both "start the workload" and "start a component in it".
    refused(ensured(data, code=42))
    for code in (0, 126, True, "45", 45.0):
        refused(ensured(data, code=code))


def test_new_supervision_members_are_left_out_when_absent_and_refuse_null(
    data: dict[str, Any],
) -> None:
    instance = parsed(data)
    supervision = instance.supervision
    assert supervision.component_exit_code is None
    assert supervision.restart_budget is None
    assert supervision.action_timeout_seconds is None
    assert all(item.deadlines is None for item in instance.workloads)
    canonical = instance_to_dict(instance)
    assert canonical == data
    assert set(canonical["supervision"]) == set(data["supervision"])
    assert all("deadlines" not in item for item in canonical["workloads"])
    # Absent is the one spelling of "not stated".
    for member in ("component_exit_code", "restart_budget", "action_timeout_seconds"):
        changed = copy.deepcopy(data)
        changed["supervision"][member] = None
        refused(changed)
    changed = copy.deepcopy(data)
    changed["workloads"][0]["deadlines"] = None
    refused(changed)
    for member in ("probe_seconds", "action_seconds"):
        changed = copy.deepcopy(data)
        changed["workloads"][0]["deadlines"] = {"probe_seconds": 12, "action_seconds": 45}
        changed["workloads"][0]["deadlines"][member] = None
        refused(changed)
    for member in ("starts", "window_seconds"):
        changed = copy.deepcopy(data)
        changed["supervision"]["restart_budget"] = {"starts": 4, "window_seconds": 1200}
        changed["supervision"]["restart_budget"][member] = None
        refused(changed)


def test_stated_members_are_part_of_the_canonical_form(data: dict[str, Any]) -> None:
    stated = ensured(data)
    stated["supervision"]["restart_budget"] = {"starts": 4, "window_seconds": 1200}
    stated["supervision"]["action_timeout_seconds"] = 40
    stated["workloads"][0]["deadlines"] = {"action_seconds": 70}
    stated["workloads"][1]["deadlines"] = {"action_seconds": 80, "probe_seconds": 25}
    stated["lifecycle_tools"].append(
        {
            "id": "example-supervisor",
            "kind": "supervisor",
            "container_api_access": True,
            "starts_runtime": False,
            "version": None,
        }
    )
    instance = parsed(stated)
    assert instance.supervision.restart_budget == instance_model.RestartBudget(4, 1200)
    assert instance.supervision.action_timeout_seconds == 40
    assert instance.workloads[0].deadlines == instance_model.Deadlines(action_seconds=70)
    assert instance.workloads[1].deadlines == instance_model.Deadlines(25, 80)
    assert instance.lifecycle_tools[-1].kind == "supervisor"
    assert instance_to_dict(instance) == stated
    assert canonical_instance_bytes(instance) == canonical_bytes(stated) + b"\n"
    assert instance_digest(instance) != instance_digest(parsed(data))
    assert instance_contract_digest(instance) != instance_contract_digest(parsed(data))


def test_directly_constructed_members_are_validated(data: dict[str, Any]) -> None:
    instance = parsed(data)
    budget = replace(instance.supervision, restart_budget=instance_model.RestartBudget(4, 1200))
    stated = replace(instance, supervision=budget)
    validate_instance(stated)
    assert instance_to_dict(stated)["supervision"]["restart_budget"] == {
        "starts": 4,
        "window_seconds": 1200,
    }
    first, second = instance.workloads
    with pytest.raises(InstanceError):
        # An empty statement is not a second spelling of "not stated".
        validate_instance(
            replace(
                instance, workloads=(replace(first, deadlines=instance_model.Deadlines()), second)
            )
        )
    with pytest.raises(InstanceError):
        validate_instance(
            replace(
                instance,
                supervision=replace(budget, restart_budget=instance_model.RestartBudget(0, 1200)),
            )
        )
    with pytest.raises(InstanceError):
        validate_instance(
            replace(instance, supervision=replace(instance.supervision, component_exit_code=45))
        )


BUDGET = ("supervision", "restart_budget")
ACTION = ("supervision", "action_timeout_seconds")
DEADLINES = ("workloads", 1, "deadlines")


@pytest.mark.parametrize(
    ("path", "value", "valid"),
    [
        (BUDGET, {"starts": 1, "window_seconds": 60}, True),
        (BUDGET, {"starts": 10, "window_seconds": 86400}, True),
        (BUDGET, {"starts": 0, "window_seconds": 1200}, False),
        (BUDGET, {"starts": 11, "window_seconds": 1200}, False),
        (BUDGET, {"starts": 4, "window_seconds": 59}, False),
        (BUDGET, {"starts": 4, "window_seconds": 86401}, False),
        (BUDGET, {"starts": 4}, False),
        (BUDGET, {"window_seconds": 1200}, False),
        (BUDGET, {}, False),
        (BUDGET, {"starts": 4, "window_seconds": 1200, "cycles": 80}, False),
        (BUDGET, {"starts": 4.0, "window_seconds": 1200}, False),
        (BUDGET, {"starts": True, "window_seconds": 1200}, False),
        (BUDGET, {"starts": "4", "window_seconds": 1200}, False),
        (ACTION, 1, True),
        (ACTION, 300, True),
        (ACTION, 0, False),
        (ACTION, 301, False),
        (ACTION, 40.0, False),
        (ACTION, True, False),
        (DEADLINES, {"probe_seconds": 1}, True),
        (DEADLINES, {"probe_seconds": 300}, True),
        (DEADLINES, {"action_seconds": 1}, True),
        (DEADLINES, {"action_seconds": 300}, True),
        (DEADLINES, {"action_seconds": 80, "probe_seconds": 25}, True),
        (DEADLINES, {}, False),
        (DEADLINES, {"probe_seconds": 0}, False),
        (DEADLINES, {"probe_seconds": 301}, False),
        (DEADLINES, {"action_seconds": 0}, False),
        (DEADLINES, {"action_seconds": 301}, False),
        (DEADLINES, {"action_seconds": 80.0}, False),
        (DEADLINES, {"action_seconds": "80"}, False),
        (DEADLINES, {"action_seconds": True}, False),
        (DEADLINES, {"start_seconds": 80}, False),
    ],
    ids=label,
)
def test_restart_budget_and_deadline_bounds(
    data: dict[str, Any], path: tuple[str | int, ...], value: Any, valid: bool
) -> None:
    node: Any = data
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    if not valid:
        refused(data)
        return
    assert instance_to_dict(parsed(data)) == data
    if path == DEADLINES:
        # A workload may differ from a site default whether or not the site states it.
        data["supervision"]["action_timeout_seconds"] = 40
        assert instance_to_dict(parsed(data)) == data


def test_lifecycle_tool_kind_names_the_supervisor(data: dict[str, Any]) -> None:
    data["lifecycle_tools"][0]["kind"] = "supervisor"
    assert parsed(data).lifecycle_tools[0].kind == "supervisor"
    data["lifecycle_tools"][0]["kind"] = "watchdog"
    refused(data)


@pytest.mark.parametrize("code", [1, 2, 10, 31, 64, 65, 69, 75, 77, 78])
def test_start_status_in_the_signal_or_error_range_is_not_fulfilled(
    tmp_path: Path, data: dict[str, Any], code: int
) -> None:
    data["supervision"]["failure_exit_code"] = code
    result = report(data)
    assert row(result, "UNKNOWN-NO-RECOVERY")["status"] == "not-fulfilled"
    assert row(result, "UNKNOWN-NO-RECOVERY")["reason"] == AMBIGUOUS
    assert not result["fully_served"]
    # Like every row that is not fulfilled, it is lifted by no record and no deviation.
    attest(data, tmp_path, "UNKNOWN-NO-RECOVERY", "schema-tests", 1)
    lifted = report(data, platform(), evidence_directory=tmp_path)
    assert status(lifted, "UNKNOWN-NO-RECOVERY") == "not-fulfilled"
    data["deviations"].append(deviation("UNKNOWN-NO-RECOVERY"))
    assert status(report(data), "UNKNOWN-NO-RECOVERY") == "not-fulfilled"


@pytest.mark.parametrize("code", [32, 42, 63, 79, 125])
def test_start_status_outside_both_ranges_stays_verified(data: dict[str, Any], code: int) -> None:
    before = report(data)
    data["supervision"]["failure_exit_code"] = code
    result = report(data)
    assert row(result, "UNKNOWN-NO-RECOVERY") == row(before, "UNKNOWN-NO-RECOVERY")
    assert status(result, "UNKNOWN-NO-RECOVERY") == "fulfilled-verified"
    # No other row looks at the start status.
    assert result["requirements"] == before["requirements"]


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (10, "not-fulfilled"),
        (31, "not-fulfilled"),
        (69, "not-fulfilled"),
        (45, "fulfilled-verified"),
    ],
)
def test_component_start_status_is_judged_like_the_workload_status(
    data: dict[str, Any], code: int, expected: str
) -> None:
    result = report(ensured(data, code=code))
    assert status(result, "UNKNOWN-NO-RECOVERY") == expected
    assert (row(result, "UNKNOWN-NO-RECOVERY")["reason"] == AMBIGUOUS) == (
        expected == "not-fulfilled"
    )


def test_ensured_component_still_authorizes_no_workload_restart(data: dict[str, Any]) -> None:
    result = report(ensured(data))
    media = next(item for item in result["workloads"] if item["id"] == "example-media")
    assert media["components"][0]["recovery"] == "supervisor-ensure"
    assert media["components"][0]["workload_restart_authorized"] is False
    assert media["workload_restart_authorized"] is False
    assert status(result, "COMPONENT-HEALTH") == "fulfilled-verified"


def digests(data: dict[str, Any]) -> dict[str, str]:
    instance = parsed(data)
    return {
        **{item.id: resolved_profile_digest(instance, item) for item in instance.transport},
        **{item.id: resolved_discovery_digest(instance, item) for item in instance.discovery},
    }


def test_stated_supervision_members_are_bound_into_every_resolved_digest(
    data: dict[str, Any],
) -> None:
    before = digests(data)
    for member, value in (
        ("failure_exit_code", 43),
        ("restart_budget", {"starts": 4, "window_seconds": 1200}),
        ("action_timeout_seconds", 40),
    ):
        changed = copy.deepcopy(data)
        changed["supervision"][member] = value
        after = digests(changed)
        assert set(after) == set(before)
        assert all(after[identifier] != before[identifier] for identifier in before)
    after = digests(ensured(data))
    assert all(after[identifier] != before[identifier] for identifier in before)


def test_workload_deadlines_are_bound_into_the_digests_of_that_workload_only(
    data: dict[str, Any],
) -> None:
    before = digests(data)
    data["workloads"][1]["deadlines"] = {"probe_seconds": 25}
    stated = digests(data)
    own = {"example-return", "example-import"}
    assert {identifier for identifier in before if stated[identifier] != before[identifier]} == own
    data["workloads"][1]["deadlines"] = {"probe_seconds": 26}
    changed = digests(data)
    assert {identifier for identifier in before if changed[identifier] != stated[identifier]} == own


def test_profile_evidence_does_not_survive_a_changed_workload_deadline(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    data["workloads"][1]["deadlines"] = {"action_seconds": 70}
    attest(data, tmp_path, "PORT-BUDGET", "port-budget", 3, "example-return")
    result = report(data, platform(), evidence_directory=tmp_path)
    assert status(result, "PORT-BUDGET") == "fulfilled-verified"
    data["workloads"][1]["deadlines"] = {"action_seconds": 75}
    result = report(data, platform(), evidence_directory=tmp_path)
    assert status(result, "PORT-BUDGET") != "fulfilled-verified"


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ("status", ("/supervision/failure_exit_code",)),
        (
            "ensure",
            ("/supervision/component_exit_code", "/workloads/1/components/0/recovery"),
        ),
        ("budget", ("/supervision/restart_budget",)),
        ("action", ("/supervision/action_timeout_seconds",)),
        ("action-within", ()),
        ("workload-action", ("/workloads/0/deadlines/action_seconds",)),
        ("workload-action-of-the-site", ()),
        ("workload-probe", ("/workloads/1/deadlines/probe_seconds",)),
        ("workload-probe-within", ()),
        ("supervisor-tool", ()),
    ],
)
def test_retained_supervision_gaps_names_every_describe_only_member(
    data: dict[str, Any], change: str, expected: tuple[str, ...]
) -> None:
    assert gaps(parsed(data)) == ()
    if change == "status":
        data["supervision"]["failure_exit_code"] = 43
    elif change == "ensure":
        data = ensured(data)
    elif change == "budget":
        data["supervision"]["restart_budget"] = {"starts": 4, "window_seconds": 1200}
    elif change == "action":
        data["supervision"]["action_timeout_seconds"] = 121
    elif change == "action-within":
        data["supervision"]["action_timeout_seconds"] = 120
    elif change == "workload-action":
        # One start bound for the installation: a value of its own is not honoured.
        data["workloads"][0]["deadlines"] = {"action_seconds": 1}
    elif change == "workload-action-of-the-site":
        data["supervision"]["action_timeout_seconds"] = 30
        data["workloads"][0]["deadlines"] = {"action_seconds": 30}
    elif change == "workload-probe":
        data["workloads"][1]["deadlines"] = {"probe_seconds": 121}
    elif change == "workload-probe-within":
        data["workloads"][1]["deadlines"] = {"probe_seconds": 120}
    else:
        data["lifecycle_tools"][0]["kind"] = "supervisor"
    assert gaps(parsed(data)) == expected


@pytest.mark.parametrize("name", sorted(BASE))
def test_shipped_examples_use_only_what_the_retained_supervisor_honours(name: str) -> None:
    assert gaps(load_instance(EXAMPLES / name)) == ()


def test_retained_supervision_gaps_are_listed_in_document_order(data: dict[str, Any]) -> None:
    data = ensured(data)
    data["supervision"].update(
        failure_exit_code=43,
        restart_budget={"starts": 4, "window_seconds": 1200},
        action_timeout_seconds=121,
    )
    data["workloads"][0]["deadlines"] = {"action_seconds": 70}
    data["workloads"][1]["deadlines"] = {"action_seconds": 80, "probe_seconds": 300}
    named = gaps(parsed(data))
    assert named == (
        "/supervision/action_timeout_seconds",
        "/supervision/component_exit_code",
        "/supervision/failure_exit_code",
        "/supervision/restart_budget",
        "/workloads/0/deadlines/action_seconds",
        "/workloads/1/components/0/recovery",
        "/workloads/1/deadlines/action_seconds",
        "/workloads/1/deadlines/probe_seconds",
    )
    # Each name is a pointer to a member the canonical document really has.
    document = instance_to_dict(parsed(data))
    for pointer in named:
        node: Any = document
        for part in pointer.split("/")[1:]:
            node = node[int(part)] if isinstance(node, list) else node[part]
        assert node is not None


def test_retained_bounds_are_those_of_the_retained_supervisor() -> None:
    schema = strict_loads((ROOT / "schemas/deployment.schema.json").read_bytes())
    monitor = schema["$defs"]["monitor"]["properties"]
    assert monitor["recovery_code"] == {"const": RECOVERY_FAILURE_EXIT_CODE}
    assert monitor["timeout_seconds"]["maximum"] == instance_module.RETAINED_PROBE_DEADLINE_MAXIMUM
    # No member of a monitor, and so nothing a manifest can state, bounds a start action.
    assert set(monitor) == {
        "id",
        "role",
        "check_argv",
        "recovery_argv",
        "timeout_seconds",
        "cycles",
        "recovery_code",
        "recovery_repeat_cycles",
    }
    # The runtime settings bound the start call of recovery, once per installation.
    assert instance_module.RETAINED_ACTION_DEADLINE_MAXIMUM == 120
    settings = strict_loads((ROOT / "examples/runtime-settings.json").read_bytes())
    parse_settings({**settings, "start_timeout_seconds": 120})
    with pytest.raises(ValueError, match="start timeout"):
        parse_settings({**settings, "start_timeout_seconds": 121})


def test_action_deadlines_within_the_start_bound_are_not_gaps(data: dict[str, Any]) -> None:
    """The retained supervisor has one start bound: longer ones and differing ones remain."""
    data["supervision"]["action_timeout_seconds"] = 120
    data["workloads"][0]["deadlines"] = {"action_seconds": 121}
    data["workloads"][1]["deadlines"] = {"action_seconds": 120}
    assert gaps(parsed(data)) == ("/workloads/0/deadlines/action_seconds",)
    data["workloads"][1]["deadlines"] = {"action_seconds": 40}
    assert gaps(parsed(data)) == (
        "/workloads/0/deadlines/action_seconds",
        "/workloads/1/deadlines/action_seconds",
    )

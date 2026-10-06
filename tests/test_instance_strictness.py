"""Closed documents hold JSON integers and single-line text; colliding names are refused."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netorch import host_cli
from netorch.codec import canonical_bytes
from netorch.host_report import (
    build_report,
    empty_evidence,
    parse_host_evidence,
    verify_contracts,
)
from netorch.instance import (
    InstanceError,
    instance_contract_digest,
    parse_instance,
    resolved_names,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
NOW = 1000.0
SIGNED = "1970-01-01T00:15:00Z"
Keys = tuple[str | int, ...]


@pytest.fixture
def data() -> dict[str, Any]:
    return json.loads((EXAMPLES / "instance.json").read_bytes())


def parsed(data: dict[str, Any]) -> Any:
    return parse_instance(canonical_bytes(data) + b"\n")


def member(data: Any, path: Keys) -> Any:
    for key in path:
        data = data[key]
    return data


def changed(data: dict[str, Any], path: Keys, value: Any) -> dict[str, Any]:
    result = copy.deepcopy(data)
    member(result, path[:-1])[path[-1]] = value
    return result


def bounded(data: dict[str, Any], **changes: Any) -> dict[str, Any]:
    decision = {
        "profile": "example-return",
        "max_age_seconds": 30,
        "unknown_limit": 1,
        "residual": "Example statement of the remaining address-reuse risk.",
        "signed_by": None,
        "signed_at": None,
        **changes,
    }
    return changed(data, ("decisions", "bounded"), [decision])


def record(requirement: str) -> dict[str, Any]:
    return {
        "requirement": requirement,
        "instance_schema_version": 1,
        "profile": None,
        "method": "schema-tests",
        "tier": 1,
        "observed_at": SIGNED,
        "macos_build": "26A434",
        "runtime_version": "1.5.0",
        "framework_sha256": "0" * 64,
        "contract_sha256": "1" * 64,
        "evidence_sha256": "2" * 64,
        "signed_by": "example-reviewer",
    }


def deviation(requirement: str, statement: str = "Example statement.") -> dict[str, Any]:
    return {
        "id": "example-deviation",
        "requirement": requirement,
        "statement": statement,
        "accepted_by": None,
        "accepted_at": None,
    }


def fact(key: str, value: Any, at: float = NOW) -> dict[str, Any]:
    return {"key": key, "state": "present", "reason": "complete", "observed_at": at, "value": value}


def evidence(**changes: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": "owner-snapshot",
        "observed_at": NOW,
        "facts": [],
        "profiles": [],
        **changes,
    }


def observation(generation: str | None = "example-generation", at: float = NOW) -> dict[str, Any]:
    return {"state": "present", "reason": "complete", "observed_at": at, "generation": generation}


def profile_row(identifier: str = "example-return", **changes: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": identifier,
        "desired_digest": "1" * 64,
        "admitted_digest": "1" * 64,
        "applied_digest": "1" * 64,
        "paused": False,
        "suspensions": [],
    }
    for key in ("transport", "discovery", "probe", "application", "heard_audio"):
        row[key] = observation()
    return {**row, **changes}


@pytest.mark.parametrize(
    "path",
    [
        ("schema_version",),
        ("framework", "schema_version"),
        ("host", "account", "uid"),
        ("host", "account", "gid"),
        ("supervision", "failure_exit_code"),
        ("supervision", "reconcile_seconds"),
        ("port_ranges", 0, "first"),
        ("transport", 0, "ports", "first"),
        ("transport", 0, "target_ports", "last"),
        ("transport", 1, "version"),
        ("discovery", 0, "version"),
    ],
)
def test_instance_refuses_an_integer_written_as_a_fraction(
    data: dict[str, Any], path: Keys
) -> None:
    whole = member(data, path)
    assert type(whole) is int
    with pytest.raises(InstanceError):
        parsed(changed(data, path, float(whole)))


def test_fractional_spelling_is_refused_in_the_committed_bytes() -> None:
    committed = (EXAMPLES / "instance.json").read_bytes()
    spelled = committed.replace(b'"uid":501}', b'"uid":501.0}')
    assert spelled != committed
    # The spelling is canonical for a fraction, so only the integer rule refuses it.
    assert canonical_bytes(json.loads(spelled)) + b"\n" == spelled
    with pytest.raises(InstanceError):
        parse_instance(spelled)
    assert parse_instance(committed).host.account.uid == 501


def test_decisions_and_records_refuse_fractional_numbers(data: dict[str, Any]) -> None:
    recovery = {"accepted": True, "max_dns_ready_seconds": 60.0}
    with pytest.raises(InstanceError):
        parsed(changed(data, ("decisions", "unattended_recovery"), recovery))
    with pytest.raises(InstanceError):
        parsed(bounded(data, max_age_seconds=30.0))
    with pytest.raises(InstanceError):
        parsed(changed(data, ("acceptance",), [{**record("HOST-DATA"), "tier": 1.0}]))
    recovery["max_dns_ready_seconds"] = 60
    assert parsed(changed(data, ("decisions", "unattended_recovery"), recovery))


@pytest.mark.parametrize(
    "path",
    [
        ("instance",),
        ("namespace",),
        ("host", "account", "home"),
        ("host", "platform", "macos_build"),
        ("host", "runtime", "version"),
        ("host", "runtime", "network"),
        ("framework", "version"),
        ("workloads", 0, "name"),
        ("workloads", 0, "contract", "data_path"),
        ("workloads", 1, "components", 0, "id"),
        ("discovery", 0, "id"),
        ("lifecycle_tools", 0, "id"),
        ("authoring", 0, "owner"),
    ],
)
def test_instance_refuses_a_trailing_newline(data: dict[str, Any], path: Keys) -> None:
    with pytest.raises(InstanceError):
        parsed(changed(data, path, member(data, path) + "\n"))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("pf_anchor", "com.apple/example.anchor"),
        ("pf_label", "example.forwarding-label"),
        ("helper_label", "example.endpoint-label"),
        ("bonjour_prefix", "example-export-"),
        ("state_directory", "/example/state"),
        ("root_state_directory", "/example/root-state"),
    ],
)
def test_pinned_name_refuses_a_trailing_newline(data: dict[str, Any], key: str, value: str) -> None:
    assert parsed(changed(data, ("names", key), value))
    with pytest.raises(InstanceError):
        parsed(changed(data, ("names", key), value + "\n"))


@pytest.mark.parametrize("character", ["\t", "\r", "\x1b", "\x7f", "\u0085", "\u2028", "\u2029"])
def test_free_text_refuses_control_and_line_separator_characters(
    data: dict[str, Any], character: str
) -> None:
    text = "first" + character + "second"
    for candidate in (
        changed(data, ("host", "lan", "hardware_id"), text),
        changed(data, ("host", "account", "home"), "/example/" + text),
        changed(data, ("host", "baseline", "proxies"), [text]),
        changed(data, ("deviations",), [deviation("HOST-DATA", text)]),
        changed(data, ("acceptance",), [{**record("HOST-DATA"), "signed_by": text}]),
        changed(
            data,
            ("decisions", "lifecycle_control"),
            {"residual": text, "signed_by": None, "signed_at": None},
        ),
        bounded(data, residual=text),
    ):
        with pytest.raises(InstanceError):
            parsed(candidate)


def test_ordinary_single_line_text_still_parses(data: dict[str, Any]) -> None:
    text = "Example statement: caf\u00e9, na\u00efve, 100\u00a0% \u2013 one line."
    candidate = changed(data, ("deviations",), [deviation("HOST-DATA", text)])
    candidate = bounded(candidate, residual=text)
    candidate["host"]["lan"]["hardware_id"] = "example adapter \u00e9"
    assert parsed(candidate).deviations[0].statement == text


@pytest.mark.parametrize(
    "changes",
    [
        {"residual": "first line\nsecond line"},
        {"residual": "x" * 2001},
        {"residual": "x" * 2048},
        {"residual": " "},
        {"signed_by": " ", "signed_at": SIGNED},
        {"signed_by": "example-reviewer", "signed_at": "1969-12-31T23:59:59Z"},
    ],
)
def test_bounded_decision_the_report_cannot_assess_is_refused_at_parse(
    data: dict[str, Any], changes: dict[str, Any]
) -> None:
    with pytest.raises(InstanceError):
        parsed(bounded(data, **changes))


@pytest.mark.parametrize(
    "changes",
    [{}, {"residual": "x" * 2000}, {"signed_by": "example-reviewer", "signed_at": SIGNED}],
)
def test_every_verb_answers_for_a_bounded_decision_that_parses(
    tmp_path: Path,
    data: dict[str, Any],
    changes: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    shutil.copytree(EXAMPLES / "contracts", tmp_path / "contracts")
    target = tmp_path / "instance.json"
    target.write_bytes(canonical_bytes(bounded(data, **changes)) + b"\n")
    codes = {
        verb: host_cli.main([verb, "--instance", str(target)], now=NOW)
        for verb in host_cli.COMMANDS
    }
    capsys.readouterr()
    assert codes == {"validate": 0, "preflight": 0, "status": 0, "plan": 0, "check": 1, "report": 0}


@given(
    residual=st.text(max_size=2060),
    signature=st.none()
    | st.tuples(
        st.text(min_size=1, max_size=128),
        st.sampled_from([SIGNED, "1969-12-31T23:59:59Z", "0001-01-01T00:00:00Z"]),
    ),
)
def test_any_bounded_decision_that_parses_can_be_reported(
    residual: str, signature: tuple[str, str] | None
) -> None:
    data = json.loads((EXAMPLES / "instance.json").read_bytes())
    signed_by, signed_at = signature or (None, None)
    try:
        instance = parsed(
            bounded(data, residual=residual, signed_by=signed_by, signed_at=signed_at)
        )
    except InstanceError:
        return
    result = build_report(instance, empty_evidence(NOW), now=NOW, data_directory=EXAMPLES)
    assert result["profiles"][1]["safety"]["status"] in {"not-fulfilled", "unverified"}


@pytest.mark.parametrize("section", ["acceptance", "deviations"])
def test_record_naming_an_unregistered_requirement_is_refused(
    data: dict[str, Any], section: str
) -> None:
    build = record if section == "acceptance" else deviation
    assert parsed(changed(data, (section,), [build("HOST-DATA")]))
    with pytest.raises(InstanceError):
        parsed(changed(data, (section,), [build("NOT-REGISTERED")]))


def test_two_workloads_cannot_share_a_container_name(data: dict[str, Any]) -> None:
    assert data["workloads"][0]["id"] != data["workloads"][1]["id"]
    with pytest.raises(InstanceError):
        parsed(changed(data, ("workloads", 1, "name"), data["workloads"][0]["name"]))


@pytest.mark.parametrize(
    ("first", "second", "value"),
    [
        ("coordinator_label", "supervisor_label", "example.same-label"),
        ("bonjour_label", "coordinator_label", "example.same-label"),
        ("pf_label", "helper_label", "example.same-label"),
        ("bonjour_prefix", "import_prefix", "example-same-"),
        ("state_directory", "root_state_directory", "/example/same"),
    ],
)
def test_pinned_names_of_one_kind_must_be_distinct(
    data: dict[str, Any], first: str, second: str, value: str
) -> None:
    one = changed(data, ("names", first), value)
    assert parsed(one)
    with pytest.raises(InstanceError):
        parsed(changed(one, ("names", second), value))


@pytest.mark.parametrize(
    ("pinned", "derived"),
    [
        ("coordinator_label", "bonjour_label"),
        ("helper_label", "pf_label"),
        ("bonjour_prefix", "import_prefix"),
        ("import_prefix", "bonjour_prefix"),
        ("state_directory", "root_state_directory"),
    ],
)
def test_pinned_name_cannot_equal_a_derived_name_of_the_same_kind(
    data: dict[str, Any], pinned: str, derived: str
) -> None:
    assert data["names"][derived] is None
    default = resolved_names(parsed(data))[derived]
    with pytest.raises(InstanceError):
        parsed(changed(data, ("names", pinned), default))


def test_distinct_pinned_names_still_parse(data: dict[str, Any]) -> None:
    data["names"].update(
        coordinator_label="example.one-label",
        supervisor_label="example.two-label",
        bonjour_prefix="example-export-",
        import_prefix="example-import-",
        state_directory="/example/state",
        root_state_directory="/example/root-state",
    )
    names = resolved_names(parsed(data))
    assert len(set(names.values())) == len(names)


@pytest.mark.parametrize("change", ["cpus", "mtu", "schema_version", "mount-newline", "mount-tab"])
def test_workload_contract_must_hold_integers_and_single_line_text(
    tmp_path: Path, data: dict[str, Any], change: str
) -> None:
    shutil.copytree(EXAMPLES / "contracts", tmp_path / "contracts")
    target = tmp_path / data["workloads"][0]["contract"]["data_path"]
    contract = json.loads(target.read_bytes())
    if change == "cpus":
        contract["cpus"] = float(contract["cpus"])
    elif change == "mtu":
        contract["network"]["mtu"] = float(contract["network"]["mtu"])
    elif change == "schema_version":
        contract["schema_version"] = 1.0
    elif change == "mount-newline":
        contract["mounts"][0]["source"] += "\n"
    else:
        contract["mounts"][0]["destination"] += "\tx"
    raw = canonical_bytes(contract) + b"\n"
    target.write_bytes(raw)
    data["workloads"][0]["contract"]["sha256"] = hashlib.sha256(raw).hexdigest()
    rows = verify_contracts(parsed(data), tmp_path)
    assert [row["state"] for row in rows] == ["unknown", "present"]
    assert rows[0]["reason"] == "missing-or-invalid-contract"


@pytest.mark.parametrize(
    "document",
    [
        evidence(schema_version=1.0),
        evidence(facts=[fact("kernel_references", 3.0)]),
        evidence(facts=[fact("macos_build", "26A434\n")]),
        evidence(facts=[fact("pf_anchors", ["example\u2028anchor"])]),
        evidence(profiles=[profile_row("example-return\n")]),
        evidence(profiles=[profile_row(suspensions=["example-suspension\n"])]),
        evidence(profiles=[profile_row(transport=observation("first\tsecond"))]),
    ],
)
def test_evidence_refuses_fractional_integers_and_control_characters(
    document: dict[str, Any],
) -> None:
    with pytest.raises(InstanceError):
        parse_host_evidence(document)
    with pytest.raises(InstanceError):
        parse_host_evidence(canonical_bytes(document) + b"\n")


def test_evidence_times_may_stay_fractional() -> None:
    receipt = {
        "digest": "1" * 64,
        "recorded_at": 998.75,
        "generation": "example-generation",
        "result": "passed",
    }
    document = evidence(
        observed_at=999.5,
        facts=[fact("udp_sockets_idle", 5, at=999.25)],
        profiles=[profile_row(transport=observation(at=999.125), receipt=receipt)],
        components=[
            {
                "service": "example-media",
                "id": "example-component",
                "observation": observation(at=999.0625),
            }
        ],
        workloads=[{"id": "example-web", "observation": observation(at=998.5)}],
    )
    parsed_evidence = parse_host_evidence(document)
    assert parsed_evidence.observed_at == 999.5
    assert parsed_evidence.facts[0].observed_at == 999.25
    assert parsed_evidence.facts[0].value == 5


@pytest.mark.parametrize(
    "key",
    [
        "recovery_material",
        "owner_conformance",
        "names_preserved",
        "framework_literal_check",
        "instance_literal_check",
    ],
)
@pytest.mark.parametrize("value", [0, 1, "false", []])
def test_prerequisite_facts_cannot_disguise_a_negative_as_another_type(
    key: str, value: Any
) -> None:
    with pytest.raises(InstanceError):
        parse_host_evidence(evidence(facts=[fact(key, value)]))


@pytest.mark.parametrize(
    ("member_name", "value", "expected"),
    [
        ("tier", 4, "fulfilled-verified"),
        ("tier", 4.0, "unverified"),
        ("schema_version", 1.0, "unverified"),
        ("source_versions", ["container-1.5.0\n"], "unverified"),
    ],
)
def test_retained_acceptance_file_must_hold_integers_and_single_line_text(
    tmp_path: Path, data: dict[str, Any], member_name: str, value: Any, expected: str
) -> None:
    instance = parsed(data)
    entry = {
        **record("RESTORE-REHEARSAL"),
        "method": "restore-rehearsal",
        "tier": 4,
        "framework_sha256": instance.framework.artifact_sha256,
        "contract_sha256": instance_contract_digest(instance),
    }
    del entry["evidence_sha256"]
    retained = {
        **entry,
        "schema_version": 1,
        "kind": "owner-attestation",
        "capture_context": "macos-userspace",
        "result": "passed",
        "source_versions": ["container-1.5.0"],
        member_name: value,
    }
    raw = canonical_bytes(retained) + b"\n"
    entry["evidence_sha256"] = hashlib.sha256(raw).hexdigest()
    (tmp_path / (entry["evidence_sha256"] + ".json")).write_bytes(raw)
    data["acceptance"].append(entry)
    facts = [fact("macos_build", "26A434"), fact("runtime_version", "1.5.0")]
    result = build_report(
        parsed(data),
        parse_host_evidence(evidence(facts=facts)),
        now=NOW,
        data_directory=EXAMPLES,
        evidence_directory=tmp_path,
    )
    row = next(item for item in result["requirements"] if item["id"] == "RESTORE-REHEARSAL")
    assert row["status"] == expected

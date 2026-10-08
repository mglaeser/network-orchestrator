"""`netorch-host supervision-gaps` prints what the retained supervisor cannot honour.

The command adds nothing to `instance.retained_supervision_gaps`: it reads an instance as
`validate` does and prints the function's pointers. No test runs a host command.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from netorch import host_cli, workflow_gate
from netorch import instance as instance_module
from netorch.codec import MAX_JSON_BYTES, canonical_bytes, canonical_json
from netorch.instance import InstanceError, load_instance

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
SHIPPED = ("instance.json", "instance-structural.json")
NOW = 1000.0
VERB = "supervision-gaps"
MEMBER = "retained_supervision_gaps"
# The six commands that existed before this one, in the order the entry point lists them.
NEIGHBOURS = ("validate", "preflight", "status", "plan", "check", "report")
NO_GAPS = (
    '{"mutation_available":false,"read_only":true,"retained_supervision_gaps":[],'
    '"schema_version":1}\n'
)
# What every command of the entry point prints for local data it cannot use, and for root.
REFUSED = (
    '{"error":"invalid-or-unavailable-local-data","mutation_available":false,"read_only":true}\n'
)
ROOT_REFUSED = '{"error":"host-entrypoint-requires-unprivileged-user","read_only":true}\n'
# Standard output of the six existing commands for the shipped examples at the clock 1000.0,
# as the tree before this command printed it: the SHA-256 of the bytes, final newline
# included. A later change that means to alter one of these outputs recomputes its value.
BASE_OUTPUT_SHA256 = {
    "instance.json": {
        "validate": "2086100c7ad81419ef1161d2ab8493034402988f9340dc59f1ab623089387a36",
        "preflight": "e0466b247db6a280787279e842d1a0b74636cfba468827c68d0e383b37f26627",
        "status": "cb239359488aa413adbcb91db33128a3986728059ae127e22b4cdb71dac5513c",
        "plan": "06cdb6df75215902a420e100e7956f77fd270b2e751cfd8c1c1540be39ef3d7f",
        "check": "708763e8b952081e1a2086328266520c62d3ca7f7614d848b6bbd50cadab1898",
        "report": "cb239359488aa413adbcb91db33128a3986728059ae127e22b4cdb71dac5513c",
    },
    "instance-structural.json": {
        "validate": "7725528c672ef2f764f053e3b19ddc11f265cbfb1ce78e835cdcfaffec7ee8fb",
        "preflight": "decf8bde6e9539a15daaa9d1b69109725a7d4b0312cba8a4b11f0e4086341426",
        "status": "6aac69ca059118340018774809b7e0071449627e370d1f0d1d4b6fedad0ed75f",
        "plan": "fe7056bc6332335dd14ccf8c2ae8a17fbadc2480e5df1dab1937ffd05c82bd4b",
        "check": "b35e2d3cd718dab04bf98fe9e95629e544296470c7e8a55ef4ebb5a32d9e5e29",
        "report": "6aac69ca059118340018774809b7e0071449627e370d1f0d1d4b6fedad0ed75f",
    },
}
# The same for `validate` where no contract file is found: its answer with `valid` false.
BASE_INVALID_SHA256 = {
    "instance.json": "53db1a200a4e799646a11e1dcbb6bccc582cc0cfd2ac5ab22b938f441759e7e8",
    "instance-structural.json": "de52a1e9d889871fd2007f8f750574009d845d0e36799138905467dd38339bc9",
}
BASE_STATUS = {"validate": 0, "preflight": 0, "status": 0, "plan": 0, "check": 1, "report": 0}
# The same for the five other commands where no contract file is found: each still gives its
# own answer with the status above. `preflight` and `plan` print nothing about the contracts
# and keep their bytes; `status` and `report` print each contract as unknown and, like
# `check`, the requirement that rests on the contracts as not fulfilled.
BASE_NO_CONTRACT_SHA256 = {
    "instance.json": {
        "preflight": BASE_OUTPUT_SHA256["instance.json"]["preflight"],
        "status": "54b142ef99bdb01b3125dfdefbd47da669c24785e9181590097b4e88b3fc972e",
        "plan": BASE_OUTPUT_SHA256["instance.json"]["plan"],
        "check": "93b688e3f9456bac03298128c61dc56fb957717bd24ada6c9320fb760ed3d703",
        "report": "54b142ef99bdb01b3125dfdefbd47da669c24785e9181590097b4e88b3fc972e",
    },
    "instance-structural.json": {
        "preflight": BASE_OUTPUT_SHA256["instance-structural.json"]["preflight"],
        "status": "06678dd8bde2832878be340aa7b73035be1e4ea0c808caa1cf4a3d84429215a5",
        "plan": BASE_OUTPUT_SHA256["instance-structural.json"]["plan"],
        "check": "77839903f2dabf0e43d73aa9ba5b80274504b45131bc80021ff9c2885451f305",
        "report": "06678dd8bde2832878be340aa7b73035be1e4ea0c808caa1cf4a3d84429215a5",
    },
}

Change = Callable[[dict[str, Any]], None]


@pytest.fixture(autouse=True)
def unprivileged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 501)


@pytest.fixture
def data() -> dict[str, Any]:
    return json.loads((EXAMPLES / "instance.json").read_bytes())


def nothing(data: dict[str, Any]) -> None:
    """The example as shipped: it states no member the retained supervisor cannot honour."""


def start_status(data: dict[str, Any]) -> None:
    data["supervision"]["failure_exit_code"] = 43


def ensure(data: dict[str, Any]) -> None:
    data["workloads"][1]["components"][0]["recovery"] = "supervisor-ensure"
    data["supervision"]["component_exit_code"] = 45


def budget(data: dict[str, Any]) -> None:
    data["supervision"]["restart_budget"] = {"starts": 7, "window_seconds": 1260}


def site_action(data: dict[str, Any]) -> None:
    data["supervision"]["action_timeout_seconds"] = 121


def workload_action(data: dict[str, Any]) -> None:
    data["workloads"][0]["deadlines"] = {"action_seconds": 122}


def workload_probe(data: dict[str, Any]) -> None:
    data["workloads"][1]["deadlines"] = {"probe_seconds": 123}


def within_bounds(data: dict[str, Any]) -> None:
    data["supervision"]["action_timeout_seconds"] = 120
    data["workloads"][1]["deadlines"] = {"probe_seconds": 120}
    data["lifecycle_tools"][0]["kind"] = "supervisor"


def everything(data: dict[str, Any]) -> None:
    for change in (start_status, ensure, budget, site_action, workload_action):
        change(data)
    data["workloads"][1]["deadlines"] = {"action_seconds": 124, "probe_seconds": 123}


# One instance per kind of member, with the pointers the command prints for it. Another
# open change teaches the retained supervisor a restart budget and adjusts the function, so
# that kind is compared with the function alone; the other literals hold either way.
KINDS: dict[str, tuple[Change, tuple[str, ...] | None]] = {
    "start-status": (start_status, ("/supervision/failure_exit_code",)),
    "second-status-and-ensure": (
        ensure,
        ("/supervision/component_exit_code", "/workloads/1/components/0/recovery"),
    ),
    "restart-budget": (budget, None),
    "site-action-deadline": (site_action, ("/supervision/action_timeout_seconds",)),
    "workload-action-deadline": (workload_action, ("/workloads/0/deadlines/action_seconds",)),
    "workload-probe-deadline": (workload_probe, ("/workloads/1/deadlines/probe_seconds",)),
    "stated-within-bounds": (within_bounds, ()),
}
EVERYTHING = [
    "/supervision/action_timeout_seconds",
    "/supervision/component_exit_code",
    "/supervision/failure_exit_code",
    "/workloads/0/deadlines/action_seconds",
    "/workloads/1/components/0/recovery",
    "/workloads/1/deadlines/action_seconds",
    "/workloads/1/deadlines/probe_seconds",
]


def changed(data: dict[str, Any], change: Change) -> dict[str, Any]:
    result = copy.deepcopy(data)
    change(result)
    return result


def site(tmp_path: Path, data: dict[str, Any], *, contracts: bool = True) -> Path:
    """A directory like a private one: the instance and, beside it, the contracts it names."""
    directory = tmp_path / "site"
    directory.mkdir(parents=True)
    if contracts:
        shutil.copytree(EXAMPLES / "contracts", directory / "contracts")
    target = directory / "instance.json"
    target.write_bytes(canonical_bytes(data) + b"\n")
    return target


def run(capsys: pytest.CaptureFixture[str], *argv: str, now: float | None = NOW) -> tuple[int, str]:
    code = host_cli.main(list(argv), now=now)
    captured = capsys.readouterr()
    assert captured.err == ""
    return code, captured.out


def named(instance: Path) -> list[str]:
    """What the existing function says about a file, without the command."""
    return list(instance_module.retained_supervision_gaps(load_instance(instance)))


def document_order(document: Any, prefix: str = "") -> Iterator[str]:
    """Every JSON pointer of a canonical document, in the order its bytes state the members."""
    if isinstance(document, dict):
        for key in sorted(document):
            here = prefix + "/" + key.replace("~", "~0").replace("/", "~1")
            yield here
            yield from document_order(document[key], here)
    elif isinstance(document, list):
        for index, item in enumerate(document):
            here = f"{prefix}/{index}"
            yield here
            yield from document_order(item, here)


def strings(value: Any) -> Iterator[str]:
    """Every text a JSON value holds as a value, at any depth; member names are not values."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for member in value.values():
            yield from strings(member)
    elif isinstance(value, list):
        for member in value:
            yield from strings(member)


# ---- what the command prints


@pytest.mark.parametrize("name", SHIPPED)
def test_shipped_examples_print_an_empty_list_and_return_zero(
    name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(capsys, VERB, "--instance", str(EXAMPLES / name)) == (0, NO_GAPS)


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_each_kind_of_gap_is_printed_as_the_function_names_it(
    kind: str, tmp_path: Path, data: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    change, literal = KINDS[kind]
    target = site(tmp_path, changed(data, change))
    expected = named(target)
    if literal is not None:
        assert expected == list(literal)
    code, output = run(capsys, VERB, "--instance", str(target))
    assert (
        output
        == canonical_json(
            {"schema_version": 1, "read_only": True, "mutation_available": False, MEMBER: expected}
        )
        + "\n"
    )
    assert code == (1 if expected else 0)
    # `validate` accepts the same file: stating such a member is valid data.
    assert run(capsys, "validate", "--instance", str(target))[0] == 0


def test_every_kind_together_is_listed_once_and_in_document_order(
    tmp_path: Path, data: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    target = site(tmp_path, changed(data, everything))
    code, output = run(capsys, VERB, "--instance", str(target))
    printed = json.loads(output)[MEMBER]
    assert code == 1
    assert printed == named(target)
    assert [pointer for pointer in printed if pointer in EVERYTHING] == EVERYTHING
    assert len(set(printed)) == len(printed)
    document = json.loads(target.read_bytes())
    position = {pointer: index for index, pointer in enumerate(document_order(document))}
    # Each entry points at a member the document has, and the entries follow its order.
    assert all(pointer in position for pointer in printed)
    assert [position[pointer] for pointer in printed] == sorted(
        position[pointer] for pointer in printed
    )


def test_a_long_list_is_printed_whole(
    tmp_path: Path, data: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    # Ten further workloads, each with both deadlines beyond what the retained supervisor
    # can be given: twenty members, more than any other instance of this file states.
    document = copy.deepcopy(data)
    for number in range(10):
        workload = copy.deepcopy(document["workloads"][0])
        workload["id"] = workload["name"] = f"example-further-{number}"
        workload["deadlines"] = {"action_seconds": 121 + number, "probe_seconds": 131 + number}
        document["workloads"].append(workload)
    target = site(tmp_path, document)
    expected = [
        f"/workloads/{index}/deadlines/{member}"
        for index in range(2, 12)
        for member in ("action_seconds", "probe_seconds")
    ]
    assert len(expected) == 20 and named(target) == expected
    # Every entry is printed, none is cut off, and the whole output is their canonical form.
    assert run(capsys, VERB, "--instance", str(target)) == (
        1,
        canonical_json(
            {"schema_version": 1, "read_only": True, "mutation_available": False, MEMBER: expected}
        )
        + "\n",
    )
    assert run(capsys, "validate", "--instance", str(target))[0] == 0


@pytest.mark.parametrize(
    "answer",
    [(), ("/supervision/failure_exit_code",), ("/zz", "/aa", "/zz"), ("",)],
    ids=["nothing", "one", "unordered-with-a-repeat", "the-whole-document"],
)
def test_the_command_prints_whatever_the_function_returns(
    answer: tuple[str, ...],
    tmp_path: Path,
    data: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The command uses the existing function, not a copy of its rules.
    assert host_cli.retained_supervision_gaps is instance_module.retained_supervision_gaps
    target = site(tmp_path, changed(data, everything))
    asked: list[Any] = []

    def function(instance: Any) -> tuple[str, ...]:
        asked.append(instance)
        return answer

    monkeypatch.setattr(host_cli, "retained_supervision_gaps", function)
    code, output = run(capsys, VERB, "--instance", str(target))
    # Nothing is sorted, merged, dropped or added, and the status follows the list alone.
    assert json.loads(output)[MEMBER] == list(answer)
    assert code == (1 if answer else 0)
    assert asked == [load_instance(target)]


def test_the_function_is_asked_about_the_very_instance_that_was_loaded(
    tmp_path: Path,
    data: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = site(tmp_path, changed(data, start_status))
    load = host_cli.load_instance
    answer = host_cli.retained_supervision_gaps
    loaded: list[Any] = []
    asked: list[Any] = []

    def loader(path: Path) -> Any:
        loaded.append(load(path))
        return loaded[-1]

    def function(instance: Any) -> tuple[str, ...]:
        asked.append(instance)
        return answer(instance)

    monkeypatch.setattr(host_cli, "load_instance", loader)
    monkeypatch.setattr(host_cli, "retained_supervision_gaps", function)
    assert run(capsys, VERB, "--instance", str(target))[0] == 1
    # The file is read once, and the function is asked about that object and no other: the
    # answer is about the instance whose contract files were checked, not about a second
    # read of the file, which could by then hold something else.
    assert len(loaded) == 1 and len(asked) == 1
    assert asked[0] is loaded[0]


def test_an_error_of_the_function_is_a_refusal_not_an_empty_list(
    tmp_path: Path,
    data: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def function(instance: Any) -> tuple[str, ...]:
        raise InstanceError("example refusal with example-private-text")

    monkeypatch.setattr(host_cli, "retained_supervision_gaps", function)
    target = site(tmp_path, changed(data, everything))
    assert run(capsys, VERB, "--instance", str(target)) == (65, REFUSED)


def test_three_answers_have_three_statuses(
    tmp_path: Path, data: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    gaps = site(tmp_path, changed(data, start_status))
    unreadable = tmp_path / "absent.json"
    none = run(capsys, VERB, "--instance", str(EXAMPLES / "instance.json"))
    some = run(capsys, VERB, "--instance", str(gaps))
    refused = run(capsys, VERB, "--instance", str(unreadable))
    assert (none[0], some[0], refused[0]) == (0, 1, 65)
    assert json.loads(none[1])[MEMBER] == []
    assert json.loads(some[1])[MEMBER] == ["/supervision/failure_exit_code"]
    assert MEMBER not in json.loads(refused[1])
    # The status of a negative answer is the one `check` uses, and that answer is complete.
    assert run(capsys, "check", "--instance", str(gaps))[0] == 1
    assert json.loads(some[1]) == {
        "schema_version": 1,
        "read_only": True,
        "mutation_available": False,
        MEMBER: ["/supervision/failure_exit_code"],
    }


# ---- an instance that is not read


def absent(directory: Path, raw: bytes) -> Path:
    return directory / "absent.json"


def a_directory(directory: Path, raw: bytes) -> Path:
    target = directory / "instance.json"
    target.mkdir()
    return target


def written(content: Callable[[bytes], bytes]) -> Callable[[Path, bytes], Path]:
    def build(directory: Path, raw: bytes) -> Path:
        target = directory / "instance.json"
        target.write_bytes(content(raw))
        return target

    return build


def linked(directory: Path, raw: bytes) -> Path:
    (directory / "kept.json").write_bytes(raw)
    target = directory / "instance.json"
    target.symlink_to(directory / "kept.json")
    return target


def second_name(directory: Path, raw: bytes) -> Path:
    target = directory / "instance.json"
    target.write_bytes(raw)
    os.link(target, directory / "other-name.json")
    return target


def altered(change: Change) -> Callable[[Path, bytes], Path]:
    def build(directory: Path, raw: bytes) -> Path:
        document = json.loads(raw)
        change(document)
        target = directory / "instance.json"
        target.write_bytes(canonical_bytes(document) + b"\n")
        return target

    return build


def unknown_member(data: dict[str, Any]) -> None:
    data["supervision"]["cycles"] = 80


def status_zero(data: dict[str, Any]) -> None:
    data["supervision"]["failure_exit_code"] = 0


def null_budget(data: dict[str, Any]) -> None:
    data["supervision"]["restart_budget"] = None


def second_status_without_ensure(data: dict[str, Any]) -> None:
    data["supervision"]["component_exit_code"] = 45


def ensure_without_second_status(data: dict[str, Any]) -> None:
    data["workloads"][1]["components"][0]["recovery"] = "supervisor-ensure"


UNREADABLE: dict[str, Callable[[Path, bytes], Path]] = {
    "absent": absent,
    "a-directory": a_directory,
    "empty": written(lambda raw: b""),
    "not-json": written(lambda raw: b"not json\n"),
    "indented": written(lambda raw: json.dumps(json.loads(raw), indent=2).encode() + b"\n"),
    "no-final-newline": written(lambda raw: raw[:-1]),
    "two-final-newlines": written(lambda raw: raw + b"\n"),
    "duplicate-member": written(lambda raw: raw[:-2] + b',"schema_version":1}\n'),
    "above-the-byte-bound": written(lambda raw: raw + b" " * MAX_JSON_BYTES),
    "symbolic-link": linked,
    "second-hard-link": second_name,
    "unknown-member": altered(unknown_member),
    "start-status-zero": altered(status_zero),
    "null-for-an-optional-member": altered(null_budget),
    "second-status-without-ensure": altered(second_status_without_ensure),
    "ensure-without-second-status": altered(ensure_without_second_status),
}


@pytest.mark.parametrize("defect", sorted(UNREADABLE))
def test_an_instance_that_is_not_read_gets_the_neighbours_refusal_and_no_list(
    defect: str, tmp_path: Path, data: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    # The content states a start status of its own, so a partial answer would show a pointer.
    good = site(tmp_path, changed(data, start_status))
    raw = good.read_bytes()
    assert run(capsys, VERB, "--instance", str(good))[0] == 1
    directory = tmp_path / "defect"
    shutil.copytree(good.parent, directory)
    (directory / "instance.json").unlink()
    target = UNREADABLE[defect](directory, raw)
    assert run(capsys, VERB, "--instance", str(target)) == (65, REFUSED)
    # Exactly what `validate` answers for the same file.
    assert run(capsys, "validate", "--instance", str(target)) == (65, REFUSED)


def drop_all(contracts: Path) -> None:
    shutil.rmtree(contracts)


def drop_one(contracts: Path) -> None:
    (contracts / "example-media.json").unlink()


def alter_one(contracts: Path) -> None:
    target = contracts / "example-web.json"
    document = json.loads(target.read_bytes())
    document["cpus"] += 1
    target.write_bytes(canonical_bytes(document) + b"\n")


@pytest.mark.parametrize("damage", [drop_all, drop_one, alter_one], ids=lambda item: item.__name__)
@pytest.mark.parametrize("stated", [nothing, start_status], ids=lambda item: item.__name__)
def test_no_answer_for_an_instance_validate_does_not_accept(
    stated: Change,
    damage: Callable[[Path], None],
    tmp_path: Path,
    data: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = site(tmp_path, changed(data, stated))
    expected = named(target)
    assert expected == ([] if stated is nothing else ["/supervision/failure_exit_code"])
    assert run(capsys, "validate", "--instance", str(target))[0] == 0
    assert run(capsys, VERB, "--instance", str(target))[0] == (1 if expected else 0)
    damage(target.parent / "contracts")
    code, answer = run(capsys, "validate", "--instance", str(target))
    assert code == 65 and json.loads(answer)["valid"] is False
    # The instance document itself still loads, and the function still answers for it:
    # neither an empty list nor a pointer is printed for an instance that is not valid.
    assert named(target) == expected
    assert run(capsys, VERB, "--instance", str(target)) == (65, REFUSED)


def test_the_refusal_does_not_say_which_input_failed_and_validate_tells_the_contract_case(
    tmp_path: Path, data: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    good = site(tmp_path, changed(data, start_status))
    raw = good.read_bytes()
    assert run(capsys, VERB, "--instance", str(good))[0] == 1

    def copied(name: str) -> Path:
        directory = tmp_path / name
        shutil.copytree(good.parent, directory)
        return directory

    drop_one(copied("one-gone") / "contracts")
    alter_one(copied("one-altered") / "contracts")
    (copied("not-canonical") / "instance.json").write_bytes(raw + b"\n")
    not_evidence = tmp_path / "not-evidence.json"
    not_evidence.write_bytes(raw)
    absent = str(tmp_path / "absent")
    here = ("--instance", str(good))
    # Which input fails, and for a contract file what `validate` says of each contract.
    failures: list[tuple[tuple[str, ...], dict[str, str] | None]] = [
        (("--instance", absent), None),
        (("--instance", str(tmp_path / "not-canonical/instance.json")), None),
        ((*here, "--evidence", str(not_evidence)), None),
        ((*here, "--evidence", absent), None),
        ((*here, "--framework-artifact", absent, "--dependency-lock", absent), None),
        (
            ("--instance", str(tmp_path / "one-gone/instance.json")),
            {"example-web": "present", "example-media": "unknown"},
        ),
        (
            ("--instance", str(tmp_path / "one-altered/instance.json")),
            {"example-web": "unknown", "example-media": "present"},
        ),
        ((*here, "--data-dir", absent), {"example-web": "unknown", "example-media": "unknown"}),
    ]
    for options, contracts in failures:
        # The command: one status and the same bytes, whichever input it could not use.
        assert run(capsys, VERB, *options) == (65, REFUSED), options
        code, answer = run(capsys, "validate", *options)
        assert code == 65, options
        if contracts is None:
            assert answer == REFUSED, options
        else:
            # The instance was read: `validate` gives its own answer and names the contract.
            result = json.loads(answer)
            assert result["valid"] is False and result["canonical"] is True
            assert {row["service"]: row["state"] for row in result["contracts"]} == contracts
    # The guide says both halves where it describes the command.
    guide = " ".join((ROOT / "docs/instances.md").read_text(encoding="utf-8").split())
    assert "That status and that error do not say which input failed" in guide
    assert "`validate` with the same options tells the contract case from the others" in guide


def test_contract_files_are_looked_up_where_validate_looks_them_up(
    tmp_path: Path, data: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    alone = site(tmp_path, changed(data, start_status), contracts=False)
    empty = tmp_path / "empty"
    empty.mkdir()
    answer = canonical_json(
        {
            "schema_version": 1,
            "read_only": True,
            "mutation_available": False,
            MEMBER: ["/supervision/failure_exit_code"],
        }
    )
    for options, expected in (
        ((), (65, REFUSED)),  # the directory of the instance file, which holds no contract
        (("--data-dir", str(EXAMPLES)), (1, answer + "\n")),
        (("--data-dir", str(empty)), (65, REFUSED)),
        (("--data-dir", str(tmp_path / "absent")), (65, REFUSED)),
    ):
        assert run(capsys, VERB, "--instance", str(alone), *options) == expected
        assert (run(capsys, "validate", "--instance", str(alone), *options)[0] == 65) == (
            expected[0] == 65
        )
    # An explicit directory replaces the default one; it is not searched in addition.
    beside = tmp_path / "beside"
    shutil.copytree(alone.parent, beside)
    shutil.copytree(EXAMPLES / "contracts", beside / "contracts")
    held = str(beside / "instance.json")
    assert run(capsys, VERB, "--instance", held)[0] == 1
    assert run(capsys, VERB, "--instance", held, "--data-dir", str(empty)) == (65, REFUSED)


def test_other_inputs_are_read_as_validate_reads_them(
    tmp_path: Path, data: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    target = str(site(tmp_path, changed(data, start_status)))
    evidence = tmp_path / "host-evidence.json"
    evidence.write_bytes(
        canonical_bytes(
            {
                "schema_version": 1,
                "source": "owner-snapshot",
                "observed_at": NOW,
                "facts": [],
                "profiles": [],
            }
        )
        + b"\n"
    )
    not_evidence = tmp_path / "not-evidence.json"
    not_evidence.write_text(run(capsys, VERB, "--instance", target)[1])
    release = tmp_path / "package.whl"
    release.write_bytes(b"example release file")
    for options, readable in (
        (("--evidence", str(evidence)), True),
        (("--evidence", str(not_evidence)), False),
        (("--evidence", str(tmp_path / "absent.json")), False),
        (("--framework-artifact", str(release), "--dependency-lock", str(release)), True),
        (("--framework-artifact", str(tmp_path / "absent.whl"), "--dependency-lock", "x"), False),
        (("--evidence-dir", str(tmp_path / "absent")), True),
    ):
        code, output = run(capsys, VERB, "--instance", target, *options)
        assert (code, output != REFUSED) == ((1 if readable else 65), readable), options
        assert (run(capsys, "validate", "--instance", target, *options)[0] == 0) is readable
    # The command's own output is not an evidence document for any neighbour either.
    assert run(capsys, "status", "--instance", target, "--evidence", str(not_evidence)) == (
        65,
        REFUSED,
    )


def test_root_is_refused_before_the_instance_is_read(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def must_not_read(path: Path) -> Any:
        raise AssertionError("root reached the instance file")

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(host_cli, "load_instance", must_not_read)
    assert run(capsys, VERB, "--instance", "/nonexistent/example-private-name") == (
        77,
        ROOT_REFUSED,
    )


@pytest.mark.parametrize(
    "options",
    [["--collect-local"], ["--emit-evidence"], ["--collect-local", "--emit-evidence"]],
    ids=" ".join,
)
def test_collecting_or_emitting_evidence_is_a_usage_error(
    options: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    def collector(instance: Any) -> dict[str, Any]:
        raise AssertionError("the command collected local facts")

    with pytest.raises(SystemExit) as refused:
        host_cli.main(
            [VERB, *options, "--instance", str(EXAMPLES / "instance.json")],
            collector=collector,
            now=NOW,
        )
    assert refused.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    # Refused as an option that does not belong to this command, which the parser knows.
    assert "invalid choice" not in captured.err
    reason = "--emit-evidence is only" if options == ["--emit-evidence"] else "--collect-local is"
    assert reason in captured.err


# ---- the output: deterministic, and no value of the instance


def test_output_is_canonical_and_the_same_on_every_run(
    tmp_path: Path,
    data: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = site(tmp_path, changed(data, everything))
    code, first = run(capsys, VERB, "--instance", str(target))
    assert code == 1
    assert first == canonical_json(json.loads(first)) + "\n"
    assert first.count("\n") == 1
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    relative = os.path.relpath(target, elsewhere)
    for argv, now in (
        ((VERB, "--instance", str(target)), NOW),
        ((VERB, "--instance", str(target)), 0.0),
        ((VERB, "--instance", str(target)), None),  # the real clock
        (("--instance", str(target), VERB), NOW),
        ((VERB, "--instance", relative), NOW),
        ((VERB, "--instance", str(target), "--data-dir", str(EXAMPLES)), NOW),
        ((VERB, "--data-dir", str(target.parent), "--instance", str(target)), NOW),
    ):
        assert run(capsys, *argv, now=now) == (1, first), argv
    assert list(elsewhere.iterdir()) == []


def test_output_names_members_by_pointer_and_carries_no_value(
    tmp_path: Path, data: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    target = site(tmp_path, changed(data, everything))
    document = json.loads(target.read_bytes())
    output = run(capsys, VERB, "--instance", str(target))[1]
    result = json.loads(output)
    assert set(result) == {"schema_version", "read_only", "mutation_available", MEMBER}
    assert (result["schema_version"], result["read_only"], result["mutation_available"]) == (
        1,
        True,
        False,
    )
    assert type(result["schema_version"]) is int
    assert result[MEMBER] and all(type(pointer) is str for pointer in result[MEMBER])
    for pointer in result[MEMBER]:
        # Every step is the name of a member or a position in a list, never content.
        node: Any = document
        assert pointer.startswith("/")
        for step in pointer.split("/")[1:]:
            if isinstance(node, list):
                assert step == str(int(step)) and int(step) < len(node)
                node = node[int(step)]
            else:
                assert isinstance(node, dict) and step in node
                node = node[step]
        # What the member holds is not printed.
        held = [node] if not isinstance(node, dict) else list(node.values())
        assert all(type(value) in (int, str) for value in held)
        assert all(str(value) not in output for value in held), pointer
    # No text the instance holds as a value is a text of the output.
    assert not set(strings(document)) & (set(result) | set(result[MEMBER]))
    assert not any(json.dumps(value) in output for value in set(strings(document)))
    assert document["instance"] not in output and document["namespace"] not in output


def test_other_values_at_the_same_members_print_the_same_bytes(
    tmp_path: Path, data: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    first = changed(data, everything)
    second = copy.deepcopy(first)
    second["instance"] = "specimen"
    second["namespace"] = ".".join(["org", "example", "specimen"])
    second["host"]["lan"]["hardware_id"] = "specimen-adapter"
    second["supervision"].update(
        failure_exit_code=44,
        component_exit_code=46,
        restart_budget={"starts": 8, "window_seconds": 1320},
        action_timeout_seconds=131,
    )
    second["workloads"][0]["deadlines"] = {"action_seconds": 132}
    second["workloads"][1]["deadlines"] = {"action_seconds": 134, "probe_seconds": 133}
    outputs = []
    for index, document in enumerate((first, second)):
        target = site(tmp_path / str(index), document)
        outputs.append(run(capsys, VERB, "--instance", str(target)))
    assert outputs[0] == outputs[1] and outputs[0][0] == 1


# ---- the neighbours: nothing they print has changed


@pytest.mark.parametrize("command", NEIGHBOURS)
@pytest.mark.parametrize("name", SHIPPED)
def test_existing_commands_print_what_they_printed_before(
    name: str, command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code, output = run(capsys, command, "--instance", str(EXAMPLES / name))
    assert code == BASE_STATUS[command]
    assert hashlib.sha256(output.encode()).hexdigest() == BASE_OUTPUT_SHA256[name][command]


@pytest.mark.parametrize("name", SHIPPED)
def test_validate_keeps_its_answer_for_missing_contract_files(
    name: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, output = run(
        capsys, "validate", "--instance", str(EXAMPLES / name), "--data-dir", str(tmp_path)
    )
    assert code == 65 and json.loads(output)["valid"] is False
    assert hashlib.sha256(output.encode()).hexdigest() == BASE_INVALID_SHA256[name]


@pytest.mark.parametrize("command", NEIGHBOURS[1:])
@pytest.mark.parametrize("name", SHIPPED)
def test_other_commands_keep_their_answers_for_missing_contract_files(
    name: str, command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Here `validate` returns 65 with its answer and the new command 65 with the closed error.
    # The validity of the contracts is now computed before the commands branch; it must not
    # reach the other five, which answer as they did on the base.
    code, output = run(
        capsys, command, "--instance", str(EXAMPLES / name), "--data-dir", str(tmp_path)
    )
    assert code == BASE_STATUS[command]
    assert output != REFUSED and json.loads(output)["read_only"] is True
    assert hashlib.sha256(output.encode()).hexdigest() == BASE_NO_CONTRACT_SHA256[name][command]


@pytest.mark.parametrize("command", [*NEIGHBOURS, VERB])
def test_refusals_are_the_same_bytes_for_every_command(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    unusable = tmp_path / "example-private-name"
    unusable.write_bytes(b'{"secret":"do-not-echo"}')
    assert run(capsys, command, "--instance", str(unusable)) == (65, REFUSED)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert run(capsys, command, "--instance", str(EXAMPLES / "instance.json")) == (
        77,
        ROOT_REFUSED,
    )


# ---- a read-only command of this release


def test_help_lists_the_command_as_it_lists_its_neighbours(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The neighbours keep their places; the new command follows them.
    assert tuple(host_cli.COMMANDS) == (*NEIGHBOURS, VERB)
    for name, value in (("COLUMNS", "80"), ("NO_COLOR", "1"), ("PYTHON_COLORS", "0")):
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    with pytest.raises(SystemExit) as shown:
        host_cli.main(["--help"])
    assert shown.value.code == 0
    text = capsys.readouterr().out
    choices = "{" + ",".join((*NEIGHBOURS, VERB)) + "}"
    # A command is named in the usage line and as the positional argument, nowhere else.
    assert text.count(choices) == 2
    assert text.count(VERB) == 2
    with pytest.raises(SystemExit) as refused:
        host_cli.main(["unknown-command", "--instance", str(EXAMPLES / "instance.json")])
    assert refused.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == "" and VERB in captured.err


def test_command_runs_in_this_release_and_never_asks_the_mutation_gate(
    tmp_path: Path,
    data: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The gate of this release refuses every native mutation.
    with pytest.raises(workflow_gate.StageNotQualified):
        workflow_gate.require_mutation_qualified("example-capability")
    asked: list[str] = []

    def refuse(capability: str) -> None:
        asked.append(capability)
        raise workflow_gate.StageNotQualified(capability)

    monkeypatch.setattr(workflow_gate, "require_mutation_qualified", refuse)
    # The entry point does not even import the gate.
    gate = (
        "workflow_gate",
        "NOT_QUALIFIED",
        "StageNotQualified",
        "require_mutation_qualified",
        "require_request_qualified",
    )
    assert all(hasattr(workflow_gate, name) for name in gate[1:])
    assert not any(hasattr(host_cli, name) for name in gate)
    gaps = site(tmp_path, changed(data, everything))
    assert run(capsys, VERB, "--instance", str(EXAMPLES / "instance.json")) == (0, NO_GAPS)
    assert run(capsys, VERB, "--instance", str(gaps))[0] == 1
    for command in NEIGHBOURS:
        code = run(capsys, command, "--instance", str(EXAMPLES / "instance.json"))[0]
        assert code == BASE_STATUS[command]
    assert asked == []


def test_command_writes_nothing_and_starts_nothing(
    tmp_path: Path,
    data: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a read-only command started a process or opened a socket")

    target = site(tmp_path, changed(data, everything))
    shutil.copytree(EXAMPLES, tmp_path / "examples")

    def snapshot() -> dict[str, tuple[bytes, int]]:
        return {
            str(path.relative_to(tmp_path)): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in sorted(tmp_path.rglob("*"))
            if path.is_file()
        }

    def entries() -> list[str]:
        return sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))

    before = snapshot(), entries()
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert run(capsys, VERB, "--instance", str(target))[0] == 1
    assert run(capsys, VERB, "--instance", str(tmp_path / "examples/instance.json")) == (
        0,
        NO_GAPS,
    )
    assert run(capsys, VERB, "--instance", str(tmp_path / "absent.json")) == (65, REFUSED)
    assert (snapshot(), entries()) == before


# ---- the documents


def test_documented_example_is_what_the_command_prints(
    tmp_path: Path, data: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    guide = (ROOT / "docs/instances.md").read_text(encoding="utf-8")
    shown = re.findall(r"```json\n(\{[^\n]*retained_supervision_gaps[^\n]*\})\n```", guide)
    assert len(shown) == 1
    target = site(tmp_path, changed(data, start_status))
    assert run(capsys, VERB, "--instance", str(target)) == (1, shown[0] + "\n")
    assert f"netorch-host {VERB} --instance /private/instance/instance.json\n" in guide


def test_documents_that_count_or_list_the_commands_include_this_one() -> None:
    maintained = [ROOT / "README.md", ROOT / "examples/README.md", *sorted(ROOT.glob("docs/*.md"))]
    counted = re.compile(
        r"\bsix(?:[ -](?:read-only|host|`netorch-host`))*[ -](?:verbs?|operations)\b", re.I
    )
    stale = [path.name for path in maintained if counted.search(path.read_text(encoding="utf-8"))]
    assert stale == []
    listing = re.compile(
        r"`validate`,\s+`preflight`,\s+`status`,\s+`plan`,\s+`check`,\s+`report`\s+and\s+`"
        + re.escape(VERB)
        + "`"
    )
    for name in ("README.md", "docs/getting-started.md"):
        assert listing.search((ROOT / name).read_text(encoding="utf-8")), name


def test_architecture_diagram_names_every_command() -> None:
    # The diagram's node of the unprivileged commands lists them by name, without a count.
    text = (ROOT / "docs/architecture.md").read_text(encoding="utf-8")
    nodes = re.findall(r"\[Unprivileged ([^\]\n]+)\]", text)
    assert len(nodes) == 1
    assert nodes[0].split(" / ") == list(host_cli.COMMANDS)

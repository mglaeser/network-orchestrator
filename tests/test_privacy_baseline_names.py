"""The per-instance guard also knows the names an instance declares in ``host.baseline``.

A network-extension identifier and a proxy or VPN service name are chosen host
values like the runtime network name. The guard extracts them as ``name``
literals, under the validation every other literal gets.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from netorch.codec import canonical_bytes
from netorch.instance import InstanceError, instance_to_dict, load_instance
from netorch.privacy import HostLiteral, PrivacyError, instance_literals, scan_text
from netorch.privacy_check import check
from netorch.process import Result

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
LISTS = ("network_extensions", "proxies", "vpns")
# Assembled here so that the public guard does not read the fixture as a site namespace.
EXTENSION = ".".join(["org", "example", "filter", "extension"])
PROXY = "example-proxy-service"
VPN = "Synthetic Office VPN"


def example(name: str = "instance.json") -> dict[str, Any]:
    return instance_to_dict(load_instance(EXAMPLES / name))


def declared(**lists: list[Any]) -> dict[str, Any]:
    data = example()
    data["host"]["baseline"].update(lists)
    return data


def git(files: list[str]) -> Callable[[list[str]], Result]:
    return lambda argv: Result(0, b"".join(name.encode() + b"\0" for name in files), b"")


def exceptions(tmp_path: Path) -> Path:
    path = tmp_path / "exceptions.json"
    path.write_bytes(canonical_bytes({"schema_version": 1, "exceptions": []}) + b"\n")
    return path


def test_declared_baseline_names_are_name_literals_and_nothing_else_changes() -> None:
    before = set(instance_literals(example()))
    after = set(
        instance_literals(declared(network_extensions=[EXTENSION], proxies=[PROXY], vpns=[VPN]))
    )
    assert after - before == {HostLiteral("name", value) for value in (EXTENSION, PROXY, VPN)}
    assert before <= after


@pytest.mark.parametrize("key", LISTS)
def test_every_entry_of_each_list_is_extracted(key: str) -> None:
    literals = instance_literals(declared(**{key: [PROXY, VPN]}))
    assert {HostLiteral("name", PROXY), HostLiteral("name", VPN)} <= set(literals)


@pytest.mark.parametrize(
    "name,count,digest",
    [
        ("instance.json", 20, "72882ede5372fc7b871a15643d5a9f8e06b16faf71a97d1f14931f0be70650fc"),
        (
            "instance-structural.json",
            14,
            "09f46c4c410d992b9ea35c6e00b898602a9fe9ffe5d8da53fe1d163b33bcf63e",
        ),
    ],
)
def test_shipped_examples_declare_no_baseline_names_and_keep_their_literals(
    name: str, count: int, digest: str
) -> None:
    data = example(name)
    assert all(data["host"]["baseline"][key] == [] for key in LISTS)
    literals = instance_literals(data)
    assert len(literals) == count
    # The digest was computed with the extraction of 0.3.2.
    listed = canonical_bytes([[literal.kind, literal.value] for literal in literals])
    assert hashlib.sha256(listed).hexdigest() == digest


def test_declared_baseline_name_in_a_framework_file_is_a_finding(tmp_path: Path) -> None:
    instance = tmp_path / "instance.json"
    instance.write_bytes(
        canonical_bytes(declared(network_extensions=[EXTENSION], proxies=[PROXY], vpns=[VPN]))
        + b"\n"
    )
    (tmp_path / "notes.md").write_text(
        f"The filter {EXTENSION} is active.\nTraffic leaves through {VPN}.\nUse {PROXY}.\n"
    )
    files = git(["notes.md"])
    # The fixture is written so that the generic pass has nothing to report.
    (tmp_path / "plain.md").write_text(f"Traffic leaves through {VPN}.\nUse {PROXY}.\n")
    assert not check(tmp_path, exceptions(tmp_path), runner=git(["plain.md"]))
    findings = [
        finding
        for finding in check(tmp_path, exceptions(tmp_path), instance=instance, runner=files)
        if finding.kind == "name"
    ]
    assert {(finding.line, finding.value_sha256) for finding in findings} == {
        (line, hashlib.sha256(value.encode()).hexdigest())
        for line, value in ((1, EXTENSION), (2, VPN), (3, PROXY))
    }


def test_baseline_name_is_matched_as_a_whole_value_only() -> None:
    literals = instance_literals(declared(vpns=[VPN], proxies=[PROXY]))
    text = f"{VPN}s\nx{PROXY}\n{PROXY}-2\n{PROXY}.\n({VPN})\n"
    found = scan_text(text, path="notes.md", literals=literals, generic=False)
    assert [(finding.line, finding.kind) for finding in found] == [(4, "name"), (5, "name")]


def test_baseline_name_equal_to_another_chosen_name_stays_one_literal() -> None:
    data = declared(vpns=["example-network"], proxies=["example-network"])
    assert data["host"]["runtime"]["network"] == "example-network"
    literals = instance_literals(data)
    assert literals.count(HostLiteral("name", "example-network")) == 1
    assert len(literals) == len(instance_literals(example()))


def test_entries_that_are_not_text_are_not_literals() -> None:
    data = example()
    data["host"]["baseline"] = {"network_extensions": ["", 7, None, ["nested"]], "proxies": VPN}
    assert set(instance_literals(data)) == set(instance_literals(example()))
    data["host"]["baseline"] = [VPN]
    assert set(instance_literals(data)) == set(instance_literals(example()))


@pytest.mark.parametrize(
    "value",
    ["line\nbreak", "tab\tstop", "x" * 4097],
    ids=["line break", "tab", "4097 characters"],
)
def test_value_the_literal_contract_cannot_hold_is_refused(value: str) -> None:
    with pytest.raises(PrivacyError, match="Invalid host literal"):
        instance_literals(declared(vpns=[value]))


def test_loaded_instance_cannot_carry_a_baseline_name_with_a_line_break(tmp_path: Path) -> None:
    # Instance validation refuses the value before the guard reads it; the
    # command reports either refusal as `refused` with exit status 2.
    instance = tmp_path / "instance.json"
    instance.write_bytes(canonical_bytes(declared(proxies=["line\nbreak"])) + b"\n")
    with pytest.raises(InstanceError, match="control characters"):
        check(tmp_path, exceptions(tmp_path), instance=instance, runner=git([]))

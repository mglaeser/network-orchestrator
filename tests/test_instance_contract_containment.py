"""A contract file is read only from inside the data directory.

A reference is a relative path and a hash. The hash pins the content wherever the
file lies, so nothing false was accepted before; but a report that reads a file
outside the data directory does not describe the directory somebody reviewed. The
directory of a contract file, with every symbolic link resolved, has to lie in the
resolved data directory. What the reader already refused for the last component (a
symbolic link, a second hard link, anything but a regular file) is refused as before
and keeps its reason.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import host_cli
from netorch import host_report as report_module
from netorch.codec import canonical_bytes
from netorch.host_report import build_report, empty_evidence, verify_contracts
from netorch.instance import InstanceError, load_instance
from netorch.instance_model import ContractRef, Instance
from tests.test_host_cli import EXAMPLES, NOW, data, parsed
from tests.test_instance_any_source import BASE

__all__ = ["data"]

WEB, MEDIA = "example-web.json", "example-media.json"
OUTSIDE = "contract-outside-data-directory"
INVALID = "missing-or-invalid-contract"
# Directory names that occur nowhere else, to show that no output repeats a path.
INSIDE_NAME, ELSEWHERE_NAME = "reviewed-7c1e", "elsewhere-4b9d"


def contracts(directory: Path) -> Path:
    """A plain directory with the two contract files of the example instance."""
    shutil.copytree(EXAMPLES / "contracts", directory)
    return directory


def layout(tmp_path: Path) -> tuple[Path, Path]:
    """An empty data directory and a place beside it that holds the contract files."""
    directory = tmp_path / INSIDE_NAME
    directory.mkdir()
    return directory, contracts(tmp_path / ELSEWHERE_NAME)


def rows(instance: Instance, directory: Path) -> list[tuple[str, str]]:
    result = verify_contracts(instance, directory)
    assert [row["service"] for row in result] == [item.id for item in instance.workloads]
    for row, item in zip(result, instance.workloads, strict=True):
        # A row holds four fixed members and the pinned hash, never a path.
        assert set(row) == {"service", "state", "reason", "sha256"}
        assert row["sha256"] == item.contract.sha256
    return [(row["state"], row["reason"]) for row in result]


def read_paths(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Record every file that contract verification opens."""
    seen: list[Path] = []
    reader: Callable[[Path], bytes] = report_module.read_data

    def recording(path: Path) -> bytes:
        seen.append(path)
        return reader(path)

    monkeypatch.setattr(report_module, "read_data", recording)
    return seen


PRESENT = [("present", "complete")] * 2
LEFT = [("unknown", OUTSIDE)] * 2


# ---- where the directory of a contract file may lie


def test_plain_directory_reads_as_before(tmp_path: Path, data: dict[str, Any]) -> None:
    contracts(tmp_path / "contracts")
    assert rows(parsed(data), tmp_path) == PRESENT
    # A reference without a directory names a file in the data directory itself.
    shutil.copy(tmp_path / "contracts" / WEB, tmp_path / WEB)
    data["workloads"][0]["contract"]["data_path"] = WEB
    assert rows(parsed(data), tmp_path) == PRESENT


@pytest.mark.parametrize("target", ["relative", "absolute"])
def test_linked_directory_that_stays_inside_is_followed(
    tmp_path: Path, data: dict[str, Any], target: str
) -> None:
    store = contracts(tmp_path / "store")
    (tmp_path / "contracts").symlink_to("store" if target == "relative" else store)
    assert rows(parsed(data), tmp_path) == PRESENT


@pytest.mark.parametrize("target", ["relative", "absolute"])
def test_linked_directory_that_leaves_is_not_read(
    tmp_path: Path, data: dict[str, Any], monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    """The reproducer of the first review: the files exist, are valid and match."""
    directory, elsewhere = layout(tmp_path)
    (directory / "contracts").symlink_to(
        Path("..") / ELSEWHERE_NAME if target == "relative" else elsewhere
    )
    assert (directory / "contracts" / WEB).read_bytes() == (
        EXAMPLES / "contracts" / WEB
    ).read_bytes()
    seen = read_paths(monkeypatch)
    assert rows(parsed(data), directory) == LEFT
    assert seen == []


def test_directory_whose_name_only_begins_like_the_data_directory_is_outside(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    """Inside means below the directory, not a path that is spelled with its prefix."""
    directory = tmp_path / INSIDE_NAME
    directory.mkdir()
    (directory / "contracts").symlink_to(contracts(tmp_path / (INSIDE_NAME + "-copy")))
    assert rows(parsed(data), directory) == LEFT


def test_only_the_reference_that_leaves_is_unknown(
    tmp_path: Path, data: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    directory, elsewhere = layout(tmp_path)
    contracts(directory / "contracts")
    (directory / "linked").symlink_to(elsewhere)
    data["workloads"][1]["contract"]["data_path"] = "linked/" + MEDIA
    seen = read_paths(monkeypatch)
    assert rows(parsed(data), directory) == [("present", "complete"), ("unknown", OUTSIDE)]
    assert [path.name for path in seen if path.name in {WEB, MEDIA}] == [WEB]


def test_row_of_a_reference_that_leaves_names_the_workload_by_its_identifier(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    """The identifier and the container name are two values; a row carries the first."""
    container = "example-web-guest"
    data["workloads"][0]["name"] = container
    instance: Instance = parsed(data)
    assert (instance.workloads[0].id, instance.workloads[0].name) == ("example-web", container)
    directory, elsewhere = layout(tmp_path)
    (directory / "contracts").symlink_to(elsewhere)
    result = verify_contracts(instance, directory)
    assert [(row["service"], row["state"], row["reason"]) for row in result] == [
        ("example-web", "unknown", OUTSIDE),
        ("example-media", "unknown", OUTSIDE),
    ]
    assert container not in json.dumps(result)


def test_chain_of_links_is_judged_by_where_it_ends(tmp_path: Path, data: dict[str, Any]) -> None:
    directory, elsewhere = layout(tmp_path)
    contracts(directory / "store")
    (directory / "contracts").symlink_to("first")
    (directory / "first").symlink_to("second")
    (directory / "second").symlink_to("store")
    assert rows(parsed(data), directory) == PRESENT
    (directory / "second").unlink()
    (directory / "second").symlink_to(elsewhere)
    assert rows(parsed(data), directory) == LEFT
    # A way that leaves and comes back ends inside: the resolved place decides.
    (elsewhere / "back").symlink_to(directory / "store")
    (directory / "second").unlink()
    (directory / "second").symlink_to(elsewhere / "back")
    assert rows(parsed(data), directory) == PRESENT


def test_nested_reference_is_held_to_the_same_rule(tmp_path: Path, data: dict[str, Any]) -> None:
    directory, elsewhere = layout(tmp_path)
    (directory / "contracts").mkdir()
    shutil.copytree(EXAMPLES / "contracts", directory / "contracts" / "site")
    for workload, name in zip(data["workloads"], (WEB, MEDIA), strict=True):
        workload["contract"]["data_path"] = "contracts/site/" + name
    assert rows(parsed(data), directory) == PRESENT
    shutil.rmtree(directory / "contracts" / "site")
    (directory / "contracts" / "site").symlink_to(elsewhere)
    assert rows(parsed(data), directory) == LEFT


def test_data_directory_reached_through_a_link_reads_as_before(
    tmp_path: Path, data: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both sides are resolved: a linked or relative data directory is no escape."""
    real = tmp_path / "real"
    contracts(real / "site" / "contracts")
    (tmp_path / "alias").symlink_to(real / "site")
    (tmp_path / "parent").symlink_to(real)
    assert rows(parsed(data), tmp_path / "alias") == PRESENT
    assert rows(parsed(data), tmp_path / "parent" / "site") == PRESENT
    monkeypatch.chdir(real)
    assert rows(parsed(data), Path("site")) == PRESENT
    assert rows(parsed(data), Path("site") / ".." / "site") == PRESENT
    # And a link that leaves is found from such a directory as well.
    elsewhere = contracts(tmp_path / ELSEWHERE_NAME)
    shutil.rmtree(real / "site" / "contracts")
    (real / "site" / "contracts").symlink_to(elsewhere)
    for directory in (tmp_path / "alias", tmp_path / "parent" / "site", Path("site")):
        assert rows(parsed(data), directory) == LEFT


# ---- `..` and an absolute path: refused where the instance is parsed, and here too


def test_parent_step_passes_the_schema_pattern_and_is_refused_by_the_parser(
    data: dict[str, Any],
) -> None:
    schema = json.loads((EXAMPLES.parent / "schemas" / "instance.schema.json").read_bytes())
    pattern = schema["properties"]["workloads"]["items"]["properties"]["contract"]["properties"][
        "data_path"
    ]["pattern"]
    # The schema's pattern lets a parent step through; the parser's own rule refuses it.
    inside = "contracts/../contracts/" + WEB
    assert re.search(pattern, inside) is not None
    data["workloads"][0]["contract"]["data_path"] = inside
    with pytest.raises(InstanceError, match="contract reference escapes its data directory"):
        parsed(data)
    # A reference that begins with one, or with a slash, does not pass the pattern.
    for reference in ("../" + ELSEWHERE_NAME + "/" + WEB, "/" + ELSEWHERE_NAME + "/" + WEB):
        assert re.search(pattern, reference) is None
        data["workloads"][0]["contract"]["data_path"] = reference
        with pytest.raises(InstanceError):
            parsed(data)


def constructed(data: dict[str, Any], reference: str) -> Instance:
    """An instance object whose first reference never passed the parser."""
    instance: Instance = parsed(data)
    first = instance.workloads[0]
    changed = replace(first, contract=ContractRef(first.contract.sha256, reference))
    return replace(instance, workloads=(changed, *instance.workloads[1:]))


def test_constructed_reference_cannot_leave_either(tmp_path: Path, data: dict[str, Any]) -> None:
    directory, elsewhere = layout(tmp_path)
    contracts(directory / "contracts")
    inside = ("present", "complete")
    for reference in (
        "../" + ELSEWHERE_NAME + "/" + WEB,
        "contracts/../../" + ELSEWHERE_NAME + "/" + WEB,
        str(elsewhere / WEB),
    ):
        assert rows(constructed(data, reference), directory) == [("unknown", OUTSIDE), inside]
    # A parent step that ends inside names a file of the data directory.
    assert rows(constructed(data, "contracts/../contracts/" + WEB), directory) == [inside] * 2


# ---- the last component: refused as before, with the reason it had


def test_final_link_hard_link_and_other_file_types_keep_their_refusal(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    directory, elsewhere = layout(tmp_path)
    store = contracts(directory / "contracts")
    target = store / WEB
    kept = directory / "kept.json"
    target.rename(kept)
    refused = [("unknown", INVALID), ("present", "complete")]

    def placed(make: Callable[[], None]) -> list[tuple[str, str]]:
        make()
        try:
            return rows(parsed(data), directory)
        finally:
            if target.is_dir() and not target.is_symlink():
                target.rmdir()
            else:
                target.unlink()

    # Absent, then five things that are not one regular single-link file.
    assert rows(parsed(data), directory) == refused
    assert placed(lambda: target.symlink_to(kept)) == refused
    assert placed(lambda: target.symlink_to(elsewhere / WEB)) == refused
    assert placed(lambda: os.link(kept, target)) == refused
    assert placed(target.mkdir) == refused
    assert placed(lambda: os.mkfifo(target, 0o600)) == refused
    # The file itself, back in its place.
    kept.rename(target)
    assert rows(parsed(data), directory) == PRESENT


def test_missing_looping_and_dangling_directories_keep_their_refusal(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    directory, _ = layout(tmp_path)
    refused = [("unknown", INVALID)] * 2
    assert rows(parsed(data), directory) == refused
    assert rows(parsed(data), tmp_path / "no-such-directory") == refused
    (directory / "contracts").symlink_to("nowhere")
    assert rows(parsed(data), directory) == refused
    (directory / "nowhere").symlink_to("contracts")
    assert rows(parsed(data), directory) == refused
    # A file where the directory should be.
    (directory / "nowhere").unlink()
    (directory / "nowhere").write_bytes(b"{}\n")
    assert rows(parsed(data), directory) == refused
    # A link to a place that does not exist is not resolved, wherever it points:
    # only a directory that exists is judged inside or outside.
    (directory / "contracts").unlink()
    (directory / "contracts").symlink_to(tmp_path / "no-such-place")
    assert rows(parsed(data), directory) == refused


def test_data_directory_that_does_not_resolve_is_not_judged(
    tmp_path: Path, data: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inside and outside exist only for a data directory that resolves.

    A reference that never passed the parser can name an existing directory by an
    absolute path. With a data directory that is missing, a link to nowhere or a
    loop, its row says what every row says there, and nothing is read.
    """
    _, elsewhere = layout(tmp_path)
    instance = constructed(data, str(elsewhere / WEB))
    (tmp_path / "dangling").symlink_to(tmp_path / "no-such-place")
    (tmp_path / "loop").symlink_to("loop")
    seen = read_paths(monkeypatch)
    for directory in (tmp_path / "no-such-directory", tmp_path / "dangling", tmp_path / "loop"):
        assert rows(instance, directory) == [("unknown", INVALID)] * 2, directory.name
    assert seen == []
    # The same reference from a data directory that exists is judged, and is outside.
    assert rows(instance, tmp_path / INSIDE_NAME)[0] == ("unknown", OUTSIDE)


def test_chain_longer_than_the_kernel_follows_stays_refused(
    tmp_path: Path, data: dict[str, Any]
) -> None:
    """The check is a gate in front of the read; the read goes the way it always went.

    The check resolves the links itself and finds the files inside. The reader then
    opens the reference as written, and the kernel gives up on a hundred links.
    """
    contracts(tmp_path / "store")
    previous = "store"
    for index in range(100):
        (tmp_path / f"hop-{index}").symlink_to(previous)
        previous = f"hop-{index}"
    (tmp_path / "contracts").symlink_to(previous)
    assert rows(parsed(data), tmp_path) == [("unknown", INVALID)] * 2


def test_chain_that_exhausts_the_resolver_reads_like_every_long_chain(
    tmp_path: Path, data: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """A chain can be too long for the check itself, not only for the kernel.

    Python 3.12 resolves a link by recursion and ends with RecursionError where the
    chain is longer than the interpreter's stack allows; later versions resolve it,
    and the kernel then refuses it on the read. The rows are the same on every
    version, as they were before the check existed, and the commands still report.
    """
    # More links than frames. The cap keeps the test bounded where a limit was raised.
    hops = min(sys.getrecursionlimit(), 3000) + 100
    contracts(tmp_path / "store")
    previous = "store"
    for index in range(hops - 1):
        (tmp_path / f"hop-{index}").symlink_to(previous)
        previous = f"hop-{index}"
    (tmp_path / "contracts").symlink_to(previous)
    assert rows(parsed(data), tmp_path) == [("unknown", INVALID)] * 2
    instance = tmp_path / "instance.json"
    instance.write_bytes(canonical_bytes(data) + b"\n")
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    assert host_cli.main(["report", "--instance", str(instance)], now=NOW) == 0
    report = json.loads(capsys.readouterr().out)
    assert [(row["state"], row["reason"]) for row in report["contracts"]] == [
        ("unknown", INVALID)
    ] * 2
    assert host_cli.main(["validate", "--instance", str(instance)], now=NOW) == 65
    assert json.loads(capsys.readouterr().out)["valid"] is False


# ---- the commands


def test_validate_refuses_such_a_layout_and_repeats_no_path(
    tmp_path: Path, data: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    directory, elsewhere = layout(tmp_path)
    (directory / "contracts").symlink_to(elsewhere)
    instance = directory / "instance.json"
    instance.write_bytes(canonical_bytes(data) + b"\n")
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    assert host_cli.main(["validate", "--instance", str(instance)], now=NOW) == 65
    validated = capsys.readouterr().out
    result = json.loads(validated)
    assert result["valid"] is False
    assert [(row["state"], row["reason"]) for row in result["contracts"]] == LEFT
    assert host_cli.main(["report", "--instance", str(instance)], now=NOW) == 0
    reported = capsys.readouterr().out
    report = json.loads(reported)
    assert report["contracts"] == result["contracts"]
    requirement = next(row for row in report["requirements"] if row["id"] == "WORKLOAD-CONTRACTS")
    assert requirement["status"] == "not-fulfilled"
    for output in (validated, reported):
        assert INSIDE_NAME not in output and ELSEWHERE_NAME not in output
        assert str(tmp_path) not in output
    # The same files inside the directory: valid again, nothing to sign anew.
    (directory / "contracts").unlink()
    shutil.copytree(elsewhere, directory / "contracts")
    assert host_cli.main(["validate", "--instance", str(instance)], now=NOW) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True


# ---- the shipped examples print what they printed

VALIDATE = {
    "instance.json": (
        '{"canonical":true,"contracts":[{"reason":"complete","service":"example-web",'
        '"sha256":"a8cf1fc0b73c43ee7e0cabd93f3bccb7b7e8361127e6de54075c65f2fca26dff",'
        '"state":"present"},{"reason":"complete","service":"example-media",'
        '"sha256":"733e7f593484fb0df8c51f2af583be8922af3d528cb84736e072b282754cf5a0",'
        '"state":"present"}],"instance":"example","mutation_available":false,'
        '"read_only":true,"release_verified":false,"schema_version":1,"valid":true}\n'
    ),
    "instance-structural.json": (
        '{"canonical":true,"contracts":[{"reason":"complete","service":"example-web",'
        '"sha256":"c8dca430700c180e31dcd60a853bd34e6bbbd2ae9f9661738ae09ffebeb641c5",'
        '"state":"present"}],"instance":"example-structural","mutation_available":false,'
        '"read_only":true,"release_verified":false,"schema_version":1,"valid":true}\n'
    ),
}


@pytest.mark.parametrize("name", sorted(VALIDATE))
def test_shipped_examples_validate_and_report_byte_for_byte_as_before(
    name: str, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """Literal output of the tree this change is based on; the report by its hash there."""
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    assert host_cli.main(["validate", "--instance", str(EXAMPLES / name)], now=NOW) == 0
    assert capsys.readouterr().out == VALIDATE[name]
    instance = load_instance(EXAMPLES / name)
    report = build_report(instance, empty_evidence(NOW), now=NOW, data_directory=EXAMPLES)
    assert hashlib.sha256(canonical_bytes(report)).hexdigest() == BASE[name]["report_sha256"]
    assert all(row == ("present", "complete") for row in rows(instance, EXAMPLES))

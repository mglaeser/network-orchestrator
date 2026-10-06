"""A destination has one mapping in the whole manifest, whatever the mappings yield."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netorch.instance import instance_to_dict, load_instance
from netorch.legacy_import import ImportError, ImportResult, import_sources, project_instance

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
ARABIC_ZERO = "\N{ARABIC-INDIC DIGIT ZERO}"
FULLWIDTH_ONE = "\N{FULLWIDTH DIGIT ONE}"


def source(identifier, mapping, path=None, fmt="json"):
    return {
        "id": identifier,
        "owner": "example",
        "path": path or identifier + ".json",
        "format": fmt,
        "sha256": None,
        "mapping": mapping,
    }


def run(tmp_path, files, sources):
    for name, content in files.items():
        text = content if isinstance(content, str) else json.dumps(content)
        (tmp_path / name).write_text(text)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "sources": sources}))
    return import_sources(path)


@pytest.mark.parametrize("first,second", [(None, "second"), ("first", None), (None, None)])
def test_null_does_not_make_room_for_a_second_author(tmp_path, first, second):
    files = {"first.json": {"value": first}, "second.json": {"value": second}}
    sources = [source("first", {"/value": "/value"}), source("second", {"/value": "/value"})]
    with pytest.raises(ImportError, match="more than one author"):
        run(tmp_path, files, sources)
    with pytest.raises(ImportError, match="more than one author"):
        run(tmp_path, files, sources[::-1])


def test_two_selectors_of_one_source_cannot_share_a_destination(tmp_path):
    files = {"first.json": {"unset": None, "chosen": "value"}}
    mapping = {"/unset": "/value", "/chosen": "/value"}
    with pytest.raises(ImportError, match="more than one author"):
        run(tmp_path, files, [source("first", mapping)])


@pytest.mark.parametrize(
    "files,first",
    [
        ({"first.json": {}}, source("first", {"/value": "/value"})),
        (
            {"first.env": "VALUE=$(id)\n"},
            source("first", {"/VALUE": "/value"}, "first.env", "literal-env"),
        ),
    ],
    ids=["absent-value", "underivable-source"],
)
def test_mapping_without_a_value_still_counts_as_an_author(tmp_path, files, first):
    second = source("second", {"/value": "/value"})
    files = files | {"second.json": {"value": "second"}}
    with pytest.raises(ImportError, match="more than one author"):
        run(tmp_path, files, [first, second])
    with pytest.raises(ImportError, match="more than one author"):
        run(tmp_path, files, [second, first])


@pytest.mark.parametrize(
    "whole",
    [{"inner": None, "other": 1}, {"other": 1}, None],
    ids=["null-member", "absent-member", "null-object"],
)
def test_destination_inside_another_mapped_destination_is_refused(tmp_path, whole):
    files = {"first.json": {"whole": whole}, "second.json": {"inner": "second"}}
    outer = source("first", {"/whole": "/outer"})
    inner = source("second", {"/inner": "/outer/inner"})
    with pytest.raises(ImportError, match="unavailable"):
        run(tmp_path, files, [outer, inner])
    with pytest.raises(ImportError, match="more than one author"):
        run(tmp_path, files, [inner, outer])


def test_distinct_destinations_may_share_their_containers(tmp_path):
    files = {"first.json": {"lan": "192.0.2.11"}, "second.json": {"cidr": "192.0.2.0/24"}}
    sources = [
        source("first", {"/lan": "/host/lan/ipv4"}),
        source("second", {"/cidr": "/host/lan/cidr"}),
    ]
    expected = {"host": {"lan": {"ipv4": "192.0.2.11", "cidr": "192.0.2.0/24"}}}
    assert run(tmp_path, files, sources).values == expected
    assert run(tmp_path, files, sources[::-1]).values == expected


def test_null_is_still_imported_when_it_has_one_author(tmp_path):
    result = run(tmp_path, {"first.json": {"value": None}}, [source("first", {"/value": "/value"})])
    assert result.values == {"value": None}
    assert not result.underivable


# One spelling for every list index


@pytest.mark.parametrize("index", ["00", "01", ARABIC_ZERO, ARABIC_ZERO + "1", FULLWIDTH_ONE])
@pytest.mark.parametrize("side", ["selector", "destination"])
def test_index_with_a_second_spelling_is_refused(tmp_path, index, side):
    mapping = {"/names/" + index: "/name"} if side == "selector" else {"/names/0": "/list/" + index}
    with pytest.raises(ImportError, match="Ambiguous"):
        run(tmp_path, {"first.json": {"names": ["one", "two"]}}, [source("first", mapping)])


def test_two_spellings_of_one_index_cannot_fill_one_slot():
    data = instance_to_dict(load_instance(EXAMPLES / "instance.json"))
    data["workloads"][0]["name"] = None
    values = {"workloads": {"0": {"name": None}, ARABIC_ZERO: {"name": "example-other"}}}
    with pytest.raises(ImportError, match="Ambiguous"):
        project_instance(ImportResult(values, (), ()), data)


@pytest.mark.parametrize("index", ["0", "1", "10"])
def test_plain_index_still_selects_and_names_a_slot(tmp_path, index):
    names = [f"name-{number}" for number in range(11)]
    mapping = {"/names/" + index: "/list/" + index}
    result = run(tmp_path, {"first.json": {"names": names}}, [source("first", mapping)])
    assert result.values == {"list": {index: names[int(index)]}}

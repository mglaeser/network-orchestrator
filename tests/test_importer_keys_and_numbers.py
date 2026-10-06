"""Literal files with keys in either case, and text for the instance's integer fields."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netorch import legacy_import
from netorch.config import load_config, to_dict
from netorch.derive import DeriveError, derive, literal_assignments
from netorch.instance import (
    InstanceError,
    canonical_instance_bytes,
    instance_to_dict,
    load_instance,
)
from netorch.legacy_import import (
    ImportError,
    ImportResult,
    generated_bytes,
    import_sources,
    project_instance,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
AUTHORED = {"decisions", "acceptance", "deviations", "authoring", "framework"}
IMAGE = "example.invalid/containers/tool@sha256:" + "1" * 64
INTEGER = {"type": "integer"}


def import_one(tmp_path, raw, mapping):
    (tmp_path / "owner").write_bytes(raw)
    source = {
        "id": "source",
        "owner": "example",
        "path": "owner",
        "format": "literal-env",
        "sha256": None,
        "mapping": mapping,
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "sources": [source]}))
    return import_sources(path)


def template(name="instance.json"):
    return instance_to_dict(load_instance(EXAMPLES / name))


def nested(pointer, value):
    for part in reversed(pointer[1:].split("/")):
        value = {part: value}
    return value


def clear(data, pointer):
    *path, last = pointer[1:].split("/")
    for part in path:
        data = data[int(part)] if isinstance(data, list) else data[part]
    data[last] = None


def integer_leaves(node, pointer=""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from integer_leaves(value, f"{pointer}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from integer_leaves(value, f"{pointer}/{index}")
    elif type(node) is int:
        yield pointer, node


# Keys in either case


def test_assignment_keys_may_be_lower_or_mixed_case():
    text = "schema=4\ninterval=10\nscanMisses='3'\n_note=\"two words\"\nUPPER_1=x\n"
    assert literal_assignments(text) == {
        "schema": "4",
        "interval": "10",
        "scanMisses": "3",
        "_note": "two words",
        "UPPER_1": "x",
    }


@given(
    st.dictionaries(
        st.from_regex(r"[A-Za-z_][A-Za-z0-9_]{0,6}", fullmatch=True),
        st.from_regex(r"[A-Za-z0-9:/._@-]{1,8}", fullmatch=True),
        max_size=6,
    )
)
def test_every_name_with_a_bare_literal_is_read_back_exactly(pairs):
    text = "".join(f"{key}={value}\n" for key, value in pairs.items())
    assert literal_assignments(text) == pairs


def test_settings_file_with_lower_case_keys_is_imported(tmp_path):
    raw = b"# literal policy\nschema=4\ninterval=10\naddress=192.0.2.11\n"
    result = import_one(tmp_path, raw, {"/interval": "/seconds", "/address": "/address"})
    assert result.values == {"seconds": "10", "address": "192.0.2.11"}
    assert not result.underivable


def test_key_case_is_significant(tmp_path):
    assert literal_assignments("port=1\nPORT=2\nPort=3\n") == {
        "port": "1",
        "PORT": "2",
        "Port": "3",
    }
    result = import_one(tmp_path, b"port=1\nPORT=2\n", {"/port": "/lower", "/PORT": "/upper"})
    assert result.values == {"lower": "1", "upper": "2"}
    with pytest.raises(DeriveError, match="Duplicate"):
        literal_assignments("port=1\nport=2\n")


@pytest.mark.parametrize(
    "line",
    [
        "export name=value",
        "local name=value",
        "readonly name=value",
        "declare -x name=value",
        "typeset name=value",
        "set name=value",
        "env name=value",
        "name = value",
        "name =value",
        "name= value",
        "name+=value",
        "name[0]=value",
        "name:=value",
        "name: value",
        "1name=value",
        "na-me=value",
        "na.me=value",
        "na me=value",
        "n\N{LATIN SMALL LETTER A WITH DIAERESIS}me=value",
        "\N{CYRILLIC SMALL LETTER A}=value",
        "=value",
        "name",
        "[section]",
        "name=$other",
        "name=${other}",
        "name=$(id)",
        "name=`id`",
        "name=a\\b",
        "name=two words",
        "name=one;two",
        "name=value # note",
        "name='one' 'two'",
        "name=",
        "name=~",
        "name=*",
        "name=a|b",
        "name=a&",
        "name=<file",
        "name=(one two)",
        "name={a,b}",
        "name=a=b",
    ],
)
def test_lower_case_keys_open_no_other_form(line):
    with pytest.raises(DeriveError):
        literal_assignments(line + "\n")
    # One such line still makes the whole file underivable.
    with pytest.raises(DeriveError):
        literal_assignments("shown=1\n" + line + "\nlast=2\n")


@pytest.mark.parametrize("key", ["password", "db_password", "api_key", "apiToken", "token"])
def test_lower_case_credential_keys_stay_refused(tmp_path, key):
    raw = f"{key}=never-copy\naddress=192.0.2.11\n".encode()
    with pytest.raises(ImportError, match="Credential") as error:
        import_one(tmp_path, raw, {"/" + key: "/chosen"})
    assert "never-copy" not in str(error.value)


def test_unmapped_lines_of_a_lower_case_file_are_not_copied(tmp_path):
    raw = b"password=never-copy\naddress=192.0.2.11\n"
    result = import_one(tmp_path, raw, {"/address": "/address"})
    assert result.values == {"address": "192.0.2.11"}
    assert b"never-copy" not in generated_bytes(result)


def test_policy_derivation_reads_lower_case_keys(tmp_path):
    data = to_dict(load_config(EXAMPLES / "network.json"))
    data["site"] = None
    data["scopes"][0]["host_ipv4"] = None
    (tmp_path / "fragment.json").write_text(json.dumps(data))
    (tmp_path / "owner.conf").write_text("site='example-site'\nhost='192.0.2.10'\n")
    sources = [
        {"path": "fragment.json", "format": "json"},
        {
            "path": "owner.conf",
            "format": "literal-env",
            "mapping": {"site": "/site", "host": "/scopes/0/host_ipv4"},
        },
    ]
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "sources": sources}))
    assert derive(manifest) == load_config(EXAMPLES / "network.json")


@pytest.mark.parametrize(
    "text,expected",
    [
        ("", {}),
        ("# only a comment\n\n", {}),
        (
            "# comment\nA='plain value'\nB=192.0.2.10\nC=\"quoted\"\n",
            {"A": "plain value", "B": "192.0.2.10", "C": "quoted"},
        ),
        (
            "\tA=one  \n\n  # note\twith a tab\nB='two\tparts'\n C=three",
            {"A": "one", "B": "two\tparts", "C": "three"},
        ),
        (f"HOST=192.0.2.11\nIMAGE={IMAGE}\n", {"HOST": "192.0.2.11", "IMAGE": IMAGE}),
        ("A1_B2=x\nZ=''\nQ=\"it's\"\n", {"A1_B2": "x", "Z": "", "Q": "it's"}),
    ],
)
def test_upper_case_files_are_read_as_before(text, expected):
    assert literal_assignments(text) == expected


# Text for integer fields


def test_literal_number_fills_an_integer_field(tmp_path):
    base = load_instance(EXAMPLES / "instance.json")
    data = instance_to_dict(base)
    wanted = data["supervision"]["discovery_seconds"]
    data["supervision"]["discovery_seconds"] = None
    result = import_one(
        tmp_path,
        f"SCAN_SECONDS={wanted}\n".encode(),
        {"/SCAN_SECONDS": "/supervision/discovery_seconds"},
    )
    assert result.values == {"supervision": {"discovery_seconds": str(wanted)}}
    assert project_instance(result, data) == canonical_instance_bytes(base)
    assert data["supervision"]["discovery_seconds"] is None


def test_lower_case_settings_file_fills_two_integer_fields(tmp_path):
    base = load_instance(EXAMPLES / "instance.json")
    data = instance_to_dict(base)
    seconds = data["supervision"]["discovery_seconds"]
    misses = data["supervision"]["discovery_misses"]
    data["supervision"].update(discovery_seconds=None, discovery_misses=None)
    result = import_one(
        tmp_path,
        f"# scan settings\nscan_seconds={seconds}\nscan_misses='{misses}'\n".encode(),
        {
            "/scan_seconds": "/supervision/discovery_seconds",
            "/scan_misses": "/supervision/discovery_misses",
        },
    )
    assert not result.underivable
    assert project_instance(result, data) == canonical_instance_bytes(base)


@pytest.mark.parametrize("name", ["instance.json", "instance-structural.json"])
def test_every_integer_field_takes_its_decimal_text(name):
    base = load_instance(EXAMPLES / name)
    fields = [
        (pointer, value)
        for pointer, value in integer_leaves(instance_to_dict(base))
        if pointer.split("/")[1] not in AUTHORED
    ]
    assert len(fields) >= 12
    assert {"/schema_version", "/host/account/uid", "/supervision/failure_exit_code"} <= {
        pointer for pointer, _ in fields
    }
    for pointer, value in fields:
        data = instance_to_dict(base)
        clear(data, pointer)
        result = ImportResult(nested(pointer, str(value)), (), ())
        assert project_instance(result, data) == canonical_instance_bytes(base), pointer


@pytest.mark.parametrize(
    "text",
    [
        "",
        " 20",
        "20 ",
        "+20",
        "-20",
        "020",
        "00",
        "20.0",
        "2e1",
        "0x14",
        "1_0",
        "20\n",
        "twenty",
        "\N{ARABIC-INDIC DIGIT TWO}\N{ARABIC-INDIC DIGIT ZERO}",
        "\N{FULLWIDTH DIGIT TWO}\N{FULLWIDTH DIGIT ZERO}",
        "12345678901",
    ],
)
def test_other_text_for_an_integer_field_is_refused_by_name(text):
    data = template()
    data["supervision"]["discovery_seconds"] = None
    result = ImportResult({"supervision": {"discovery_seconds": text}}, (), ())
    with pytest.raises(ImportError, match="integer field /supervision/discovery_seconds") as error:
        project_instance(result, data)
    if text:
        assert text not in str(error.value)


def test_ten_digits_is_the_longest_plain_integer():
    data = template()
    data["host"]["account"]["uid"] = None

    def project(text):
        return project_instance(ImportResult({"host": {"account": {"uid": text}}}, (), ()), data)

    assert json.loads(project("2147483647"))["host"]["account"]["uid"] == 2147483647
    # A converted number is still subject to the field's own range.
    with pytest.raises(InstanceError, match="closed versioned schema"):
        project("4294967296")
    with pytest.raises(ImportError, match="plain decimal integer"):
        project("21474836470")


def test_zero_is_a_plain_integer():
    data = template()
    data["host"]["account"]["gid"] = None
    result = ImportResult({"host": {"account": {"gid": "0"}}}, (), ())
    assert json.loads(project_instance(result, data))["host"]["account"]["gid"] == 0


@pytest.mark.parametrize("pointer", ["/host/platform/macos_build", "/host/lan/hardware_id"])
def test_digits_for_a_text_field_stay_text(pointer):
    data = template()
    clear(data, pointer)
    projected = json.loads(project_instance(ImportResult(nested(pointer, "12345"), (), ()), data))
    for part in pointer[1:].split("/"):
        projected = projected[part]
    assert projected == "12345"


@pytest.mark.parametrize("text", ["true", "false", "yes", "1", "0"])
@pytest.mark.parametrize(
    "pointer", ["/host/baseline/filevault", "/lifecycle_tools/0/container_api_access"]
)
def test_text_never_becomes_a_boolean(pointer, text):
    data = template()
    clear(data, pointer)
    with pytest.raises(InstanceError, match="closed versioned schema"):
        project_instance(ImportResult(nested(pointer, text), (), ()), data)


@pytest.mark.parametrize("value", [True, 20.0, [20], None])
def test_values_that_are_not_text_are_left_to_the_instance_parser(value):
    data = template()
    data["supervision"]["discovery_seconds"] = None
    result = ImportResult({"supervision": {"discovery_seconds": value}}, (), ())
    with pytest.raises(InstanceError):
        project_instance(result, data)


def test_generated_view_still_records_the_text(tmp_path):
    result = import_one(
        tmp_path, b"SCAN_SECONDS=20\n", {"/SCAN_SECONDS": "/supervision/discovery_seconds"}
    )
    assert result.values == {"supervision": {"discovery_seconds": "20"}}
    assert b'"discovery_seconds":"20"' in generated_bytes(result)


def test_text_cannot_replace_an_authored_number():
    result = ImportResult({"supervision": {"discovery_seconds": "20"}}, (), ())
    with pytest.raises(ImportError, match="more than one author"):
        project_instance(result, template())


def test_text_does_not_reach_a_number_in_an_authored_section():
    values = {"decisions": {"unattended_recovery": {"max_dns_ready_seconds": "120"}}}
    with pytest.raises(ImportError, match="Authored instance sections"):
        project_instance(ImportResult(values, (), ()), template())


@pytest.mark.parametrize(
    "schema,expected",
    [
        (INTEGER, True),
        ({"type": "integer", "minimum": 1, "maximum": 8}, True),
        ({"anyOf": [INTEGER, {"type": "null"}]}, True),
        ({"oneOf": [{"enum": [1, 2]}, {"const": 3}]}, True),
        ({"type": "null"}, False),
        ({"type": "string"}, False),
        ({"type": "boolean"}, False),
        ({"type": "number"}, False),
        ({"enum": [True]}, False),
        ({"enum": [1, "1"]}, False),
        ({"const": "1"}, False),
        ({"type": ["integer", "null"]}, False),
        ({"anyOf": [INTEGER, {"type": "string"}]}, False),
        ({"$ref": "#/$defs/number"}, False),
        ({}, False),
        (True, False),
    ],
)
def test_integer_slot_is_decided_by_the_schema_alone(schema, expected):
    root = {"type": "object", "additionalProperties": False, "properties": {"slot": schema}}
    assert legacy_import._integer_slot(root, "/slot") is expected


def test_integer_slot_needs_every_alternative_to_exclude_other_members():
    slot = legacy_import._integer_slot
    numbered = {"type": "object", "additionalProperties": False, "properties": {"first": INTEGER}}
    named = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"range": {"type": "string"}},
    }
    unclosed = {"type": "object", "properties": {"range": {"type": "string"}}}
    assert slot({"anyOf": [{"oneOf": [named, numbered]}, {"type": "null"}]}, "/first")
    assert not slot({"oneOf": [unclosed, numbered]}, "/first")
    assert slot({"type": "array", "items": numbered}, "/3/first")
    # A member can be named by its identifier as well as by its position.
    assert slot({"type": "array", "items": numbered}, "/x/first")
    assert not slot(numbered, "/missing")
    assert not slot(numbered, "/first/deeper")

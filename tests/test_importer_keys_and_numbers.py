"""Literal files with keys in either case, and text for the instance's integer fields."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
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
    instance_validator,
    load_instance,
)
from netorch.legacy_import import (
    ImportError,
    ImportResult,
    check_generated_view,
    generated_bytes,
    import_sources,
    project_instance,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
AUTHORED = {"decisions", "acceptance", "deviations", "authoring", "framework"}
IMAGE = "example.invalid/containers/tool@sha256:" + "1" * 64
INTEGER = {"type": "integer"}
STRING = {"type": "string"}
SECONDS = "/supervision/discovery_seconds"
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
DRAFT_4 = "http://json-schema.org/draft-04/schema#"


def manifest(tmp_path, *sources):
    """Write the sources, each (id, format, bytes, mapping), and a manifest that names them."""
    entries = []
    for identifier, fmt, raw, mapping in sources:
        (tmp_path / identifier).write_bytes(raw)
        entries.append(
            {
                "id": identifier,
                "owner": "example",
                "path": identifier,
                "format": fmt,
                "sha256": None,
                "mapping": mapping,
            }
        )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "sources": entries}))
    return path


def import_one(tmp_path, raw, mapping, fmt="literal-env"):
    return import_sources(manifest(tmp_path, ("source", fmt, raw, mapping)))


def template(name="instance.json"):
    return instance_to_dict(load_instance(EXAMPLES / name))


def nested(pointer, value):
    for part in reversed(pointer[1:].split("/")):
        value = {part: value}
    return value


def from_literal(pointer, value):
    """A result that holds ``value`` at ``pointer`` as text read from a format without types."""
    return ImportResult(nested(pointer, value), (), (), frozenset({pointer}))


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
        result = from_literal(pointer, str(value))
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
    result = from_literal(SECONDS, text)
    with pytest.raises(ImportError, match="integer field /supervision/discovery_seconds") as error:
        project_instance(result, data)
    if text:
        assert text not in str(error.value)


def test_ten_digits_is_the_longest_plain_integer():
    data = template()
    data["host"]["account"]["uid"] = None

    def project(text):
        return project_instance(from_literal("/host/account/uid", text), data)

    assert json.loads(project("2147483647"))["host"]["account"]["uid"] == 2147483647
    # A converted number is still subject to the field's own range.
    with pytest.raises(InstanceError, match="closed versioned schema"):
        project("4294967296")
    with pytest.raises(ImportError, match="plain decimal integer"):
        project("21474836470")


def test_zero_is_a_plain_integer():
    data = template()
    data["host"]["account"]["gid"] = None
    result = from_literal("/host/account/gid", "0")
    assert json.loads(project_instance(result, data))["host"]["account"]["gid"] == 0


@pytest.mark.parametrize("pointer", ["/host/platform/macos_build", "/host/lan/hardware_id"])
def test_digits_for_a_text_field_stay_text(pointer):
    data = template()
    clear(data, pointer)
    projected = json.loads(project_instance(from_literal(pointer, "12345"), data))
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
        project_instance(from_literal(pointer, text), data)


@pytest.mark.parametrize("value", [True, 20.0, [20], None])
def test_values_that_are_not_text_are_left_to_the_instance_parser(value):
    data = template()
    data["supervision"]["discovery_seconds"] = None
    result = from_literal(SECONDS, value)
    with pytest.raises(InstanceError):
        project_instance(result, data)


def test_generated_view_still_records_the_text(tmp_path):
    result = import_one(
        tmp_path, b"SCAN_SECONDS=20\n", {"/SCAN_SECONDS": "/supervision/discovery_seconds"}
    )
    assert result.values == {"supervision": {"discovery_seconds": "20"}}
    assert b'"discovery_seconds":"20"' in generated_bytes(result)


def test_text_cannot_replace_an_authored_number():
    result = from_literal(SECONDS, "20")
    with pytest.raises(ImportError, match="more than one author"):
        project_instance(result, template())


def test_text_does_not_reach_a_number_in_an_authored_section():
    result = from_literal("/decisions/unattended_recovery/max_dns_ready_seconds", "120")
    with pytest.raises(ImportError, match="Authored instance sections"):
        project_instance(result, template())


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
    assert not slot({"type": "array", "items": numbered}, "/x/first")
    assert not slot(numbered, "/missing")
    assert not slot(numbered, "/first/deeper")


# Only text from a format without types is converted

TYPED = ["json", "toml", "plist"]
PROPERTY_LIST = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<plist version="1.0"><dict><key>text</key><string>40</string></dict></plist>\n'
)
SOURCES = (
    (
        "assignments",
        "literal-env",
        b"# scan settings\nSCAN_SECONDS=20\nLAN=192.0.2.11\n",
        {"/SCAN_SECONDS": SECONDS, "/LAN": "/host/lan/ipv4", "/ABSENT": "/absent"},
    ),
    (
        "list",
        "text-list",
        b"# data list\n3\nexample-item\n",
        {"/items/0": "/supervision/discovery_misses", "/items": "/names"},
    ),
    (
        "typed",
        "json",
        b'{"count":2,"text":"30"}',
        {"/text": "/supervision/health_seconds", "/count": "/count"},
    ),
    ("table", "toml", b'text = "10"\n', {"/text": "/supervision/reconcile_seconds"}),
    ("properties", "plist", PROPERTY_LIST, {"/text": "/supervision/read_timeout_seconds"}),
    ("expression", "literal-env", b"NAME=$OTHER\n", {"/NAME": "/name"}),
)
# Digest and length of the view generated for SOURCES before a result recorded any provenance.
VIEW_SHA256 = "f8008dc93572f04c30e355b10bd21b28337d6af81a6563ada92e49f9b35883cc"
VIEW_LENGTH = 1219


def typed_source(fmt, value):
    """``value`` under the key ``seconds``, in a format that tells a number from text."""
    if fmt == "plist":
        kind = "string" if isinstance(value, str) else "integer"
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
            f"<key>seconds</key><{kind}>{value}</{kind}></dict></plist>\n"
        ).encode()
    spelled = json.dumps(value)
    return (f"seconds = {spelled}\n" if fmt == "toml" else f'{{"seconds":{spelled}}}').encode()


def test_import_records_which_destinations_hold_text_from_a_format_without_types(tmp_path):
    result = import_sources(manifest(tmp_path, *SOURCES))
    # Text of an assignment file and one item of a data list, each mapped by itself. Not: a
    # mapped list, a string or a number from JSON, TOML or a property list, an unavailable
    # selector, or anything of an underivable source.
    assert result.untyped == {SECONDS, "/host/lan/ipv4", "/supervision/discovery_misses"}
    assert [(issue.source, issue.reason) for issue in result.underivable] == [
        ("assignments", "mapped-value-unavailable"),
        ("expression", "unsupported-static-syntax"),
    ]
    # The provenance is no part of the generated view.
    assert generated_bytes(replace(result, untyped=frozenset())) == generated_bytes(result)


def test_generated_view_is_byte_for_byte_what_it_was_without_provenance(tmp_path):
    path = manifest(tmp_path, *SOURCES)
    view = generated_bytes(import_sources(path))
    assert (hashlib.sha256(view).hexdigest(), len(view)) == (VIEW_SHA256, VIEW_LENGTH)
    assert set(json.loads(view)) == {"schema_version", "sources", "underivable", "values"}
    (tmp_path / "view.json").write_bytes(view)
    assert check_generated_view(path, tmp_path / "view.json")


@pytest.mark.parametrize("fmt", TYPED)
def test_text_from_a_format_with_types_is_refused_for_an_integer_field_as_before(tmp_path, fmt):
    base = load_instance(EXAMPLES / "instance.json")
    data = instance_to_dict(base)
    wanted = data["supervision"]["discovery_seconds"]
    data["supervision"]["discovery_seconds"] = None
    result = import_one(tmp_path, typed_source(fmt, str(wanted)), {"/seconds": SECONDS}, fmt)
    assert result.values == {"supervision": {"discovery_seconds": str(wanted)}}
    with pytest.raises(InstanceError) as error:
        project_instance(result, data)
    # The instance parser's own refusal, as before any text was converted.
    assert type(error.value) is InstanceError
    assert str(error.value) == "instance violates its closed versioned schema"


@pytest.mark.parametrize("fmt", TYPED)
def test_number_from_a_format_with_types_fills_an_integer_field_as_before(tmp_path, fmt):
    base = load_instance(EXAMPLES / "instance.json")
    data = instance_to_dict(base)
    wanted = data["supervision"]["discovery_seconds"]
    data["supervision"]["discovery_seconds"] = None
    result = import_one(tmp_path, typed_source(fmt, wanted), {"/seconds": SECONDS}, fmt)
    assert result.values == {"supervision": {"discovery_seconds": wanted}}
    assert project_instance(result, data) == canonical_instance_bytes(base)


def test_item_of_a_data_list_mapped_by_itself_fills_an_integer_field(tmp_path):
    base = load_instance(EXAMPLES / "instance.json")
    data = instance_to_dict(base)
    wanted = data["supervision"]["discovery_seconds"]
    data["supervision"]["discovery_seconds"] = None
    raw = f"# data list\n{wanted}\n".encode()
    result = import_one(tmp_path, raw, {"/items/0": SECONDS}, "text-list")
    assert result.values == {"supervision": {"discovery_seconds": str(wanted)}}
    assert project_instance(result, data) == canonical_instance_bytes(base)


def test_text_inside_a_mapped_list_is_not_converted(tmp_path):
    base = load_instance(EXAMPLES / "instance.json")
    data = instance_to_dict(base)
    first = data["port_ranges"][0]["first"]
    data["port_ranges"][0]["first"] = None
    literal = (
        "number",
        "literal-env",
        f"FIRST={first}\n".encode(),
        {"/FIRST": "/port_ranges/0/first"},
    )
    # Mapped by itself onto the slot of a range that the template holds: converted.
    result = import_sources(manifest(tmp_path, literal))
    assert project_instance(result, data) == canonical_instance_bytes(base)

    def listed(ranges):
        raw = json.dumps({"ranges": ranges}).encode()
        return ("ranges", "json", raw, {"/ranges": "/port_ranges"})

    # A whole list of ranges is taken from another mapping as it is.
    ranges = instance_to_dict(base)["port_ranges"]
    data["port_ranges"] = None
    result = import_sources(manifest(tmp_path, listed(ranges)))
    assert project_instance(result, data) == canonical_instance_bytes(base)
    # The same text mapped by itself into that list stays text there.
    ranges[0]["first"] = None
    result = import_sources(manifest(tmp_path, listed(ranges), literal))
    assert result.values == {"port_ranges": [ranges[0] | {"first": str(first)}]}
    with pytest.raises(InstanceError, match="closed versioned schema"):
        project_instance(result, data)


def test_hand_built_result_without_provenance_converts_nothing():
    data = template()
    data["supervision"]["discovery_seconds"] = None
    result = ImportResult({"supervision": {"discovery_seconds": "20"}}, (), ())
    with pytest.raises(InstanceError) as error:
        project_instance(result, data)
    assert str(error.value) == "instance violates its closed versioned schema"
    assert result.untyped == frozenset()
    # The same text with its provenance stated is taken.
    projected = json.loads(project_instance(replace(result, untyped=frozenset({SECONDS})), data))
    assert projected["supervision"]["discovery_seconds"] == 20


# Refusals that do not depend on the text come first


@pytest.mark.parametrize("text", ["20", "twenty"])
def test_author_conflict_is_reported_whatever_the_text(tmp_path, text):
    result = import_one(tmp_path, f"SCAN_SECONDS={text}\n".encode(), {"/SCAN_SECONDS": SECONDS})
    with pytest.raises(ImportError) as error:
        project_instance(result, template())
    assert str(error.value) == "Mapped value has more than one author"


@pytest.mark.parametrize("text", ["20", "twenty"])
def test_unavailable_container_is_reported_whatever_the_text(tmp_path, text):
    raw = f"SCAN_SECONDS={text}\n".encode()
    data = template()
    data["supervision"] = "unavailable"
    data["port_ranges"] = []
    result = import_one(tmp_path, raw, {"/SCAN_SECONDS": SECONDS})
    with pytest.raises(ImportError) as error:
        project_instance(result, data)
    assert str(error.value) == "Mapping target is unavailable"
    result = import_one(tmp_path, raw, {"/SCAN_SECONDS": "/port_ranges/0/first"})
    with pytest.raises(ImportError) as error:
        project_instance(result, data)
    assert str(error.value) == "Mapping container is unavailable"


@pytest.mark.parametrize("text", ["20", "twenty"])
def test_conflict_of_a_later_value_and_unresolved_sources_come_before_the_text(tmp_path, text):
    data = template()
    data["supervision"]["discovery_seconds"] = None
    raw = f"SCAN_SECONDS={text}\nSCAN_MISSES=3\n".encode()
    # The text has a free slot; the value mapped after it has not.
    mapping = {"/SCAN_SECONDS": SECONDS, "/SCAN_MISSES": "/supervision/discovery_misses"}
    with pytest.raises(ImportError) as error:
        project_instance(import_one(tmp_path, raw, mapping), data)
    assert str(error.value) == "Mapped value has more than one author"
    # The text has a free slot; another source of the same import is underivable.
    sources = (
        ("source", "literal-env", raw, {"/SCAN_SECONDS": SECONDS}),
        ("expression", "literal-env", b"NAME=$OTHER\n", {}),
    )
    with pytest.raises(ImportError) as error:
        project_instance(import_sources(manifest(tmp_path, *sources)), data)
    assert str(error.value) == "Unresolved owner inputs cannot become a complete instance"


def test_other_text_from_a_literal_file_is_refused_by_name_when_nothing_else_is_wrong(tmp_path):
    data = template()
    data["supervision"].update(discovery_seconds=None, discovery_misses=None)
    mapping = {"/SCAN_MISSES": "/supervision/discovery_misses", "/SCAN_SECONDS": SECONDS}
    result = import_one(tmp_path, b"SCAN_SECONDS=twenty\nSCAN_MISSES=many\n", mapping)
    with pytest.raises(ImportError) as error:
        project_instance(result, data)
    # The first such field in the order of the mapping; never the value.
    assert str(error.value) == (
        "Text mapped to integer field /supervision/discovery_misses is not a plain decimal integer"
    )


# Constructs that the integer-slot walk does not judge

CLOSED = {"type": "object", "additionalProperties": False}
NUMBERED = CLOSED | {"properties": {"a": INTEGER}}
INDEXED = CLOSED | {"properties": {"0": INTEGER}}
LISTED = {"type": "array", "items": INTEGER}
UNJUDGED = {
    "patternProperties": {"^x": {}},
    "prefixItems": [{}],
    "additionalItems": {},
    "unevaluatedProperties": {},
    "unevaluatedItems": {},
    "allOf": [{}],
    "not": {"type": "string"},
    "if": {},
    "then": {},
    "else": {},
    "dependentSchemas": {"x": {}},
    "$ref": "#/$defs/number",
    "$dynamicRef": "#/$defs/number",
}
# What the walk reads in the shipped instance schema.
WALKED = {"type", "properties", "additionalProperties", "items", "anyOf", "oneOf", "enum", "const"}
# Bounds on a value of one type and the list of required members. None of them changes which
# types a member may have.
BOUNDS = {
    "required",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minProperties",
    "maxProperties",
}


def admits_text(schema, pointer):
    """Whether the instance parser's validator accepts text at a one-part ``pointer``."""
    part = pointer[1:]
    holders = [{part: "20"}, ["20"]] if part == "0" else [{part: "20"}]
    validator = type(instance_validator())(schema)
    return any(validator.is_valid(holder) for holder in holders)


def unjudged_keywords(schema):
    """Every keyword in neither list and every ``type`` that is not one name, each with its place.

    The root may name its dialect.
    """
    found = []

    def visit(node, pointer):
        if isinstance(node, bool):
            return
        for keyword, value in node.items():
            if keyword == "$schema" and not pointer:
                continue
            if keyword not in WALKED | BOUNDS or (keyword == "type" and type(value) is not str):
                found.append(f"{keyword} at {pointer or 'the root'}")
            elif keyword == "properties":
                for name, member in value.items():
                    visit(member, f"{pointer}/properties/{name}")
            elif keyword in ("items", "additionalProperties"):
                visit(value, f"{pointer}/{keyword}")
            elif keyword in ("anyOf", "oneOf"):
                for index, alternative in enumerate(value):
                    visit(alternative, f"{pointer}/{keyword}/{index}")

    visit(schema, "")
    return found


@pytest.mark.parametrize(
    "schema,twin,pointer",
    [
        ({"type": "array", "prefixItems": [STRING], "items": INTEGER}, LISTED, "/0"),
        ({"type": "object", "items": INTEGER}, LISTED, "/0"),
        ({"items": INTEGER}, LISTED, "/0"),
        ({"type": ["array", "object"], "items": INTEGER}, LISTED, "/0"),
        (
            {"anyOf": [NUMBERED, CLOSED | {"patternProperties": {"^a$": STRING}}]},
            {"anyOf": [NUMBERED, CLOSED]},
            "/a",
        ),
    ],
    ids=[
        "prefixItems beside items",
        "items on an object",
        "items on a node without a type",
        "list-valued type with items",
        "closed object with patternProperties",
    ],
)
def test_integer_slot_answers_no_where_an_unjudged_construct_admits_text(schema, twin, pointer):
    slot = legacy_import._integer_slot
    # The validator accepts text there, so the slot must not count as an integer slot.
    assert admits_text(schema, pointer)
    assert slot(schema, pointer) is False
    # Without the construct nothing but an integer is accepted there, and the walk says so.
    assert not admits_text(twin, pointer)
    assert slot(twin, pointer) is True


@pytest.mark.parametrize("keyword", sorted(UNJUDGED))
def test_integer_slot_answers_no_at_and_below_a_node_with_an_unjudged_keyword(keyword):
    slot = legacy_import._integer_slot
    extra = {keyword: UNJUDGED[keyword]}
    outer = CLOSED | {"properties": {"b": NUMBERED}}
    assert slot(NUMBERED, "/a") is True
    assert slot(outer, "/b/a") is True
    # On the member, on the node that holds it, further up, and on an alternative that
    # could otherwise be left out.
    assert slot(CLOSED | {"properties": {"a": INTEGER | extra}}, "/a") is False
    assert slot(NUMBERED | extra, "/a") is False
    assert slot(outer | extra, "/b/a") is False
    assert slot({"anyOf": [NUMBERED, {"type": "null"}]}, "/a") is True
    assert slot({"anyOf": [NUMBERED, {"type": "null"} | extra]}, "/a") is False


def test_integer_slot_answers_no_below_a_list_valued_type():
    slot = legacy_import._integer_slot
    assert slot(NUMBERED | {"type": ["object"]}, "/a") is False
    assert slot(LISTED | {"type": ["array"]}, "/0") is False
    assert slot(CLOSED | {"properties": {"a": {"type": ["integer"]}}}, "/a") is False


@pytest.mark.parametrize(
    "schema,twin",
    [
        ({"additionalProperties": False, "properties": {"0": INTEGER}}, INDEXED),
        (INDEXED | {"type": "array"}, INDEXED),
        ({"anyOf": [{"additionalProperties": False}, LISTED]}, {"anyOf": [CLOSED, LISTED]}),
        ({"anyOf": [CLOSED | {"type": "array"}, LISTED]}, {"anyOf": [CLOSED, LISTED]}),
    ],
    ids=[
        "properties on a node without a type",
        "properties on an array",
        "closed alternative without a type",
        "closed alternative that is an array",
    ],
)
def test_integer_slot_reads_object_keywords_only_on_an_object(schema, twin):
    slot = legacy_import._integer_slot
    # The node says nothing about a list, so a list with text at that index is accepted.
    assert admits_text(schema, "/0")
    assert slot(schema, "/0") is False
    assert not admits_text(twin, "/0")
    assert slot(twin, "/0") is True


def test_integer_slot_answers_no_below_another_dialect():
    slot = legacy_import._integer_slot
    # Draft 4 has no "const"; the validator reads a subschema by the dialect that it names.
    older = CLOSED | {"properties": {"a": {"$schema": DRAFT_4, "const": 3}}}
    assert admits_text(older, "/a")
    assert slot(older, "/a") is False
    same = CLOSED | {"properties": {"a": {"$schema": DRAFT_2020_12, "const": 3}}}
    assert not admits_text(same, "/a")
    assert slot(same, "/a") is True
    assert slot(NUMBERED | {"$schema": DRAFT_2020_12}, "/a") is True
    assert slot(NUMBERED | {"$schema": DRAFT_4}, "/a") is False
    # The dialect the walk reads is the one the instance parser validates by.
    assert legacy_import._DIALECT == DRAFT_2020_12 == instance_validator().META_SCHEMA["$id"]


def test_shipped_instance_schema_has_no_keyword_that_the_walk_does_not_judge():
    schema = instance_validator().schema
    assert schema["$schema"] == DRAFT_2020_12
    assert unjudged_keywords(schema) == []
    # The check names the keyword and the place of anything else.
    changed = copy.deepcopy(schema)
    supervision = changed["properties"]["supervision"]
    supervision["patternProperties"] = {"_seconds$": STRING}
    supervision["properties"]["discovery_seconds"]["$schema"] = DRAFT_4
    supervision["properties"]["discovery_misses"]["type"] = ["integer", "null"]
    changed["properties"]["port_ranges"]["items"]["properties"]["first"]["description"] = "text"
    assert sorted(unjudged_keywords(changed)) == [
        "$schema at /properties/supervision/properties/discovery_seconds",
        "description at /properties/port_ranges/items/properties/first",
        "patternProperties at /properties/supervision",
        "type at /properties/supervision/properties/discovery_misses",
    ]


# A source is declared in the format in which its owner reads it


@pytest.mark.parametrize("line", ['directory="$HOME/data"', 'user="`id -un`"', "path='a\\b'"])
def test_only_the_assignment_format_refuses_expansion_characters(tmp_path, line):
    raw = (line + "\n").encode()
    literal = import_one(tmp_path, raw, {})
    assert [issue.reason for issue in literal.underivable] == ["unsupported-static-syntax"]
    # The same bytes are valid TOML, and that format takes the value as literal text.
    key, _, value = line.partition("=")
    table = import_one(tmp_path, raw, {"/" + key: "/chosen"}, "toml")
    assert not table.underivable
    assert table.values == {"chosen": value[1:-1]}

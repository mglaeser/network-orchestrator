from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netorch.config import load_config, to_dict
from netorch.derive import DeriveError, derive, literal_assignments
from netorch.legacy_import import generated_bytes, import_sources

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
IMAGE = "example.invalid/containers/app@sha256:" + "1" * 64
# Characters that some readers treat as the end of a line. A reader that ends
# lines at a line feed only, such as a shell, does not.
SEPARATORS = {
    "carriage-return": "\r",
    "vertical-tab": "\x0b",
    "form-feed": "\x0c",
    "file-separator": "\x1c",
    "group-separator": "\x1d",
    "record-separator": "\x1e",
    "next-line": "\x85",
    "line-separator": "\N{LINE SEPARATOR}",
    "paragraph-separator": "\N{PARAGRAPH SEPARATOR}",
}
WIDE_SPACES = {
    "no-break-space": "\N{NO-BREAK SPACE}",
    "em-space": "\N{EM SPACE}",
    "ideographic-space": "\N{IDEOGRAPHIC SPACE}",
}
PLIST_HEAD = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
    b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    b'<plist version="1.0">'
)
FIRST = b"<dict><key>Label</key><string>first-job</string></dict>"
SECOND = b"<dict><key>Label</key><string>second-job</string></dict>"


def import_one(tmp_path, fmt, raw, mapping):
    (tmp_path / "owner").write_bytes(raw)
    source = {
        "id": "source",
        "owner": "example",
        "path": "owner",
        "format": fmt,
        "sha256": None,
        "mapping": mapping,
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "sources": [source]}))
    return import_sources(path)


def assert_refused(result):
    assert not result.values
    assert [issue.reason for issue in result.underivable] == ["unsupported-static-syntax"]


def test_unquoted_digest_pinned_image_reference_is_a_literal():
    assert literal_assignments(f"IMAGE={IMAGE}\n") == {"IMAGE": IMAGE}


def test_file_with_an_unquoted_image_reference_keeps_its_other_settings(tmp_path):
    raw = f"# literal settings\nHOST=192.0.2.11\nIMAGE={IMAGE}\n".encode()
    result = import_one(tmp_path, "literal-env", raw, {"/HOST": "/address", "/IMAGE": "/image"})
    assert result.values == {"address": "192.0.2.11", "image": IMAGE}
    assert not result.underivable


@pytest.mark.parametrize(
    "raw",
    [
        "A=name@$(id)",
        "A=name@`id`",
        "A=name@host;id",
        "A=name@host other",
        "A=name@{host}",
        "A=name@(host)",
        "A=name@host\\n",
    ],
)
def test_at_sign_admits_no_expansion_or_second_word(raw):
    with pytest.raises(DeriveError):
        literal_assignments(raw)


@pytest.mark.parametrize("name", sorted(SEPARATORS))
def test_setting_hidden_in_a_comment_is_never_an_assignment(name):
    text = f"# previous value: {SEPARATORS[name]}PORT=4242\nHOST=192.0.2.11\n"
    with pytest.raises(DeriveError):
        literal_assignments(text)


@pytest.mark.parametrize("name", sorted(SEPARATORS))
def test_setting_hidden_in_a_comment_is_not_imported(tmp_path, name):
    raw = f"# previous value: {SEPARATORS[name]}PORT=4242\nHOST=192.0.2.11\n".encode()
    assert_refused(
        import_one(tmp_path, "literal-env", raw, {"/PORT": "/port", "/HOST": "/address"})
    )


@pytest.mark.parametrize("name", sorted(SEPARATORS))
def test_list_item_hidden_in_a_comment_is_not_imported(tmp_path, name):
    raw = f"# retired: {SEPARATORS[name]}retired-item\nlive-item\n".encode()
    result = import_one(tmp_path, "text-list", raw, {"/items": "/items"})
    assert_refused(result)
    assert b"retired-item" not in generated_bytes(result)


NOISE = [*SEPARATORS.values(), *WIDE_SPACES.values(), *" \t#='\"Az0", "\x00", "\x1b"]


@given(st.text(alphabet=st.sampled_from(NOISE), max_size=8))
def test_no_text_after_a_comment_mark_becomes_a_setting(noise):
    try:
        result = literal_assignments(f"#{noise}HIDDEN=1\nSHOWN=2\n")
    except DeriveError:
        return
    assert result == {"SHOWN": "2"}


def test_carriage_return_line_endings_are_refused_not_trimmed(tmp_path):
    # A line-feed-delimited reader keeps the carriage return in the value.
    with pytest.raises(DeriveError):
        literal_assignments("A=one\r\nB=two\r\n")
    assert_refused(import_one(tmp_path, "text-list", b"one\r\ntwo\r\n", {"/items": "/items"}))


@pytest.mark.parametrize("char", ["\x07", "\x08", "\x1b", "\x1f", "\x7f", "\x9b"])
def test_other_control_characters_are_refused_even_inside_quotes(char):
    with pytest.raises(DeriveError):
        literal_assignments(f"A='left{char}right'\n")


@pytest.mark.parametrize("name", sorted(WIDE_SPACES))
def test_only_spaces_and_tabs_are_trimmed_from_an_assignment(name):
    space = WIDE_SPACES[name]
    for text in (f"{space}PORT=4242\n", f"PORT=4242{space}\n", f"PORT='4242'{space}\n"):
        with pytest.raises(DeriveError):
            literal_assignments(text)


@pytest.mark.parametrize("name", sorted(WIDE_SPACES))
def test_only_spaces_and_tabs_are_trimmed_from_a_list_item(tmp_path, name):
    raw = f"live-item{WIDE_SPACES[name]}\n".encode()
    assert_refused(import_one(tmp_path, "text-list", raw, {"/items": "/items"}))


def test_spaces_tabs_blank_lines_and_missing_final_line_feed_still_work(tmp_path):
    text = "\tA=one  \n\n  # note\twith a tab\nB='two\tparts'\n C=three"
    assert literal_assignments(text) == {"A": "one", "B": "two\tparts", "C": "three"}
    result = import_one(
        tmp_path, "text-list", b"# note\n\n\t_hap._tcp \n  auto-tcp", {"/items": "/items"}
    )
    assert result.values == {"items": ["_hap._tcp", "auto-tcp"]}
    assert not result.underivable


def test_policy_derivation_refuses_a_setting_hidden_in_a_comment(tmp_path):
    data = to_dict(load_config(EXAMPLES / "network.json"))
    data["site"] = None
    data["scopes"][0]["host_ipv4"] = None
    (tmp_path / "fragment.json").write_text(json.dumps(data))
    (tmp_path / "owner.env").write_text("# retired: \x0cHOST='192.0.2.99'\nSITE='example-site'\n")
    sources = [
        {"path": "fragment.json", "format": "json"},
        {
            "path": "owner.env",
            "format": "literal-env",
            "mapping": {"SITE": "/site", "HOST": "/scopes/0/host_ipv4"},
        },
    ]
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "sources": sources}))
    with pytest.raises(DeriveError, match="control or line-separator"):
        derive(manifest)


@pytest.mark.parametrize(
    "body",
    [
        FIRST + SECOND,
        b"<string>first-job</string>" + SECOND,
        FIRST + b"<string>second-job</string>",
        b"<plist>" + FIRST + SECOND + b"</plist>",
        b'<plist version="1.0">' + SECOND + b"</plist>",
        FIRST + b'<plist version="1.0">' + SECOND + b"</plist>",
    ],
    ids=[
        "two-dictionaries",
        "scalar-then-dictionary",
        "dictionary-then-scalar",
        "two-in-a-nested-plist",
        "one-in-a-nested-plist",
        "nested-plist-after-a-root",
    ],
)
def test_property_list_with_more_than_one_root_object_is_refused(tmp_path, body):
    result = import_one(tmp_path, "plist", PLIST_HEAD + body + b"</plist>", {"/Label": "/label"})
    assert_refused(result)
    assert b"-job" not in generated_bytes(result)


@pytest.mark.parametrize(
    "body",
    [b"<key>Label</key>", b"<key>Label</key><string>first-job</string>"],
    ids=["key-alone", "key-then-value"],
)
def test_key_outside_a_dictionary_is_no_root_object(tmp_path, body):
    result = import_one(tmp_path, "plist", PLIST_HEAD + body + b"</plist>", {"/Label": "/label"})
    assert_refused(result)


@pytest.mark.parametrize(
    "value,mapping,expected",
    [
        ({"Label": "only-job"}, {"/Label": "/label"}, {"label": "only-job"}),
        (["one", "two"], {"/1": "/second"}, {"second": "two"}),
        (
            {"Nested": {"Items": [{"Label": "only-job"}]}},
            {"/Nested/Items/0/Label": "/l"},
            {"l": "only-job"},
        ),
    ],
    ids=["dictionary", "array", "nested"],
)
def test_property_list_with_one_root_object_is_still_imported(tmp_path, value, mapping, expected):
    result = import_one(tmp_path, "plist", plistlib.dumps(value), mapping)
    assert result.values == expected
    assert not result.underivable

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netorch.config import load_config, to_dict
from netorch.derive import DeriveError, derive, literal_assignments

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def write_manifest(tmp_path, sources, **extra):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "sources": sources, **extra}))
    return path


def test_single_source_derived_policy_matches_owner_exactly():
    assert derive(EXAMPLES / "owner-facts.json") == load_config(EXAMPLES / "network.json")


def test_literal_parser_no_evaluation_and_comment_support():
    assert literal_assignments("# comment\nA='plain value'\nB=192.0.2.10\nC=\"en0\"\n") == {
        "A": "plain value",
        "B": "192.0.2.10",
        "C": "en0",
    }


@pytest.mark.parametrize(
    "raw",
    [
        "A=$(id)",
        "A=${HOME}",
        "A=`id`",
        "A=$HOME",
        "export A=thing",
        "A='first' 'second'",
        "A=word;id",
        "A=first\nA=second",
        "A=a\\nb",
        "source file",
        "A=",
        'A="x$HOME"',
        "A='literal$unknown'",
    ],
)
def test_underivable_assignment_is_rejected(raw):
    with pytest.raises(DeriveError):
        literal_assignments(raw)


def test_literals_fill_placeholders_without_another_author(tmp_path):
    data = to_dict(load_config(EXAMPLES / "network.json"))
    data["site"] = None
    data["scopes"][0]["host_ipv4"] = None
    (tmp_path / "fragment.json").write_text(json.dumps(data))
    (tmp_path / "owner.env").write_text("SITE='example-site'\nHOST='192.0.2.10'\n")
    manifest = write_manifest(
        tmp_path,
        [
            {"path": "fragment.json", "format": "json"},
            {
                "path": "owner.env",
                "format": "literal-env",
                "mapping": {"SITE": "/site", "HOST": "/scopes/0/host_ipv4"},
            },
        ],
    )
    assert derive(manifest) == load_config(EXAMPLES / "network.json")


def test_json_fragments_merge_distinct_settings(tmp_path):
    data = to_dict(load_config(EXAMPLES / "network.json"))
    site = data.pop("site")
    (tmp_path / "one.json").write_text(json.dumps(data))
    (tmp_path / "two.json").write_text(json.dumps({"site": site}))
    manifest = write_manifest(
        tmp_path, [{"path": "one.json", "format": "json"}, {"path": "two.json", "format": "json"}]
    )
    assert derive(manifest) == load_config(EXAMPLES / "network.json")


def test_duplicate_json_author_rejected_even_when_values_match(tmp_path):
    (tmp_path / "one.json").write_text('{"site":"example-site"}')
    manifest = write_manifest(tmp_path, [{"path": "one.json", "format": "json"}] * 2)
    with pytest.raises(DeriveError, match="Conflicting"):
        derive(manifest)


@pytest.mark.parametrize(
    "pointer",
    [
        "",
        "/",
        "site",
        "/bad/site",
        "/scopes/999/site",
        "/scopes/x/site",
        "/site~1bad",
        "/scopes//site",
    ],
)
def test_invalid_mapping_is_rejected(tmp_path, pointer):
    (tmp_path / "owner.env").write_text("SITE=example-site\n")
    manifest = write_manifest(
        tmp_path,
        [
            {"path": str(EXAMPLES / "network.json"), "format": "json"},
            {"path": "owner.env", "format": "literal-env", "mapping": {"SITE": pointer}},
        ],
    )
    with pytest.raises(DeriveError):
        derive(manifest)


def test_mapping_cannot_overwrite_canonical_policy(tmp_path):
    (tmp_path / "owner.env").write_text("SITE=example-site\n")
    manifest = write_manifest(
        tmp_path,
        [
            {"path": str(EXAMPLES / "network.json"), "format": "json"},
            {"path": "owner.env", "format": "literal-env", "mapping": {"SITE": "/site"}},
        ],
    )
    with pytest.raises(DeriveError, match="overwrite"):
        derive(manifest)


@pytest.mark.parametrize(
    "source",
    [
        {"path": "irrelevant", "format": "shell"},
        {"path": "irrelevant", "format": "json", "command": "id"},
        {"path": "irrelevant", "format": "json", "mapping": {}},
        {"path": "", "format": "json"},
        {"path": "irrelevant", "format": "literal-env"},
        {"path": "irrelevant", "format": "literal-env", "mapping": {"A": 1}},
    ],
)
def test_manifest_is_closed_and_formats_are_explicit(tmp_path, source):
    with pytest.raises(DeriveError):
        derive(write_manifest(tmp_path, [source]))


def test_manifest_rejects_unknown_fields_and_empty_sources(tmp_path):
    with pytest.raises(DeriveError):
        derive(write_manifest(tmp_path, [], root_command="id"))
    with pytest.raises(DeriveError):
        derive(write_manifest(tmp_path, []))


def test_missing_mapped_key_rejected(tmp_path):
    (tmp_path / "owner.env").write_text("OTHER=thing\n")
    manifest = write_manifest(
        tmp_path, [{"path": "owner.env", "format": "literal-env", "mapping": {"SITE": "/site"}}]
    )
    with pytest.raises(DeriveError, match="missing"):
        derive(manifest)

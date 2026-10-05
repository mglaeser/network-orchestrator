from __future__ import annotations

import hashlib
import json
import os
import plistlib
from dataclasses import replace
from pathlib import Path

import pytest

from netorch.legacy_import import (
    ImportError,
    check_generated_view,
    generated_bytes,
    import_sources,
    project_instance,
    read_static,
)


def manifest(tmp_path, sources, **extra):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "sources": sources, **extra}))
    return path


def entry(path="owner.json", fmt="json", **changes):
    result = {
        "id": "source",
        "owner": "forwarding",
        "path": path,
        "format": fmt,
        "sha256": None,
        "mapping": {"/lan": "/host/lan/ipv4"},
    }
    return result | changes


def test_json_is_explicit_projection_not_unfiltered_capture(tmp_path):
    (tmp_path / "owner.json").write_text('{"lan":"192.0.2.11","password":"secret-not-emitted"}')
    result = import_sources(manifest(tmp_path, [entry()]))
    assert result.values == {"host": {"lan": {"ipv4": "192.0.2.11"}}}
    assert not result.underivable
    assert b"secret-not-emitted" not in generated_bytes(result)
    assert len(result.owner_digest("forwarding")) == 64
    with pytest.raises(ImportError, match="no captured"):
        result.owner_digest("other")


@pytest.mark.parametrize(
    "fmt,raw,mapping,expected",
    [
        (
            "literal-env",
            b"HOST='192.0.2.11'\n# plain\n",
            {"/HOST": "/address"},
            {"address": "192.0.2.11"},
        ),
        ("toml", b'lan="192.0.2.11"\n', {"/lan": "/address"}, {"address": "192.0.2.11"}),
        (
            "plist",
            plistlib.dumps({"lan": "192.0.2.11"}),
            {"/lan": "/address"},
            {"address": "192.0.2.11"},
        ),
        (
            "text-list",
            b"# comment\n_hap._tcp\nauto-tcp\n",
            {"/items": "/types"},
            {"types": ["_hap._tcp", "auto-tcp"]},
        ),
        (
            "json",
            b'{"names":["example-one","example-two"]}',
            {"/names/1": "/name"},
            {"name": "example-two"},
        ),
    ],
)
def test_closed_data_formats(tmp_path, fmt, raw, mapping, expected):
    (tmp_path / "owner").write_bytes(raw)
    result = import_sources(manifest(tmp_path, [entry("owner", fmt, mapping=mapping)]))
    assert result.values == expected
    assert not result.underivable


@pytest.mark.parametrize(
    "fmt,raw",
    [
        ("json", b'{"lan":"192.0.2.11","lan":"192.0.2.12"}'),
        ("json", b'{"lan":1} trailing'),
        ("json", b'{"lan":NaN}'),
        ("json", b'{"lan":' + b"[" * 34 + b"0" + b"]" * 34 + b"}"),
        ("json", b"\xff"),
        ("toml", b'lan="one"\nlan="two"'),
        ("toml", b"lan=2000-01-01"),
        (
            "plist",
            b'<?xml version="1.0"?><plist><dict><key>lan</key><string>a</string>'
            b"<key>lan</key><string>b</string></dict></plist>",
        ),
        ("plist", b'<?xml version="1.0"?><plist><dict><key>lan</key></dict></plist>'),
        (
            "plist",
            b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY p SYSTEM "file:///etc/passwd">]><plist><string>&p;</string></plist>',
        ),
        ("plist", b"bplist00junk"),
        (
            "plist",
            b'<?xml version="1.0"?><plist>' + b"<array>" * 65 + b"</array>" * 65 + b"</plist>",
        ),
        ("plist", b'<?xml version="1.0"?><plist><dict>'),
        ("literal-env", b"A=$(touch /should-not-exist)\nHOST=192.0.2.11"),
        ("literal-env", b"HOST=192.0.2.11\nif true; then HOST=192.0.2.12; fi"),
        ("literal-env", b"HOST=192.0.2.11\nsource private.env"),
        ("literal-env", b"HOST=192.0.2.11\nHOST=192.0.2.12"),
        ("text-list", b"_hap._tcp\n_hap._tcp"),
        ("text-list", b"_hap._tcp; echo exploit"),
    ],
)
def test_unsupported_input_is_underivable_without_leaking_expression(tmp_path, fmt, raw):
    (tmp_path / "owner").write_bytes(raw)
    result = import_sources(manifest(tmp_path, [entry("owner", fmt)]))
    assert not result.values
    assert result.underivable[0].reason == "unsupported-static-syntax"
    assert b"should-not-exist" not in generated_bytes(result)


def test_executable_source_inventory_hashes_only_and_never_runs(tmp_path):
    marker = tmp_path / "would-exist"
    raw = f"#!/bin/sh\ntouch {marker}\nHOST=192.0.2.11\n".encode()
    (tmp_path / "code.sh").write_bytes(raw)
    result = import_sources(manifest(tmp_path, [entry("code.sh", "source-inventory", mapping={})]))
    assert not marker.exists()
    assert result.receipts[0].sha256 == hashlib.sha256(raw).hexdigest()
    assert result.underivable[0].reason == "executable-source-not-evaluated"
    assert not result.values


def test_missing_selector_has_closed_reason(tmp_path):
    (tmp_path / "owner.json").write_text("{}")
    result = import_sources(manifest(tmp_path, [entry()]))
    assert result.underivable[0].selector == "/lan"
    assert result.underivable[0].reason == "mapped-value-unavailable"


def test_reimport_exact_bytes_detects_comments_and_output_format_drift(tmp_path):
    (tmp_path / "owner.json").write_text('{"lan":"192.0.2.11"}')
    source = manifest(tmp_path, [entry()])
    out = tmp_path / "view.json"
    out.write_bytes(generated_bytes(import_sources(source)))
    assert check_generated_view(source, out)
    out.write_bytes(out.read_bytes().rstrip(b"\n"))
    assert not check_generated_view(source, out)
    out.write_bytes(generated_bytes(import_sources(source)))
    (tmp_path / "owner.json").write_text('{"lan": "192.0.2.11"}')
    assert not check_generated_view(source, out)


def test_pinned_source_digest_cannot_change_silently(tmp_path):
    raw = b'{"lan":"192.0.2.11"}'
    (tmp_path / "owner.json").write_bytes(raw)
    source = manifest(tmp_path, [entry(sha256=hashlib.sha256(raw).hexdigest())])
    assert import_sources(source).values
    (tmp_path / "owner.json").write_bytes(raw + b" ")
    with pytest.raises(ImportError, match="digest changed"):
        import_sources(source)


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": 2},
        {"schema_version": True},
        {"extra": True},
        {"sources": []},
        {"sources": None},
    ],
)
def test_manifest_shape_is_closed(tmp_path, change):
    path = manifest(tmp_path, [entry()])
    data = json.loads(path.read_text()) | change
    path.write_text(json.dumps(data))
    with pytest.raises(ImportError):
        import_sources(path)


@pytest.mark.parametrize(
    "changes",
    [
        {"extra": 1},
        {"id": "UPPER"},
        {"owner": None},
        {"path": ""},
        {"path": "bad\x00path"},
        {"format": []},
        {"format": "shell"},
        {"sha256": "abcd"},
        {"mapping": []},
        {"mapping": {"lan": "/address"}},
        {"mapping": {"/lan": "/"}},
        {"mapping": {"/lan": "/bad~1name"}},
        {"mapping": {"/lan": "/bad//name"}},
        {"mapping": {"/PASSWORD": "/name"}},
        {"mapping": {"/api_key": "/name"}},
        {"mapping": {"/config/Env": "/workloads"}},
        {"mapping": {"/lan": "/token"}},
        {"format": "source-inventory"},
    ],
)
def test_source_contract_is_closed(tmp_path, changes):
    with pytest.raises(ImportError):
        import_sources(manifest(tmp_path, [entry(**changes)]))


def test_duplicate_source_and_mapped_author_rejected(tmp_path):
    (tmp_path / "owner.json").write_text('{"lan":"192.0.2.11"}')
    with pytest.raises(ImportError, match="unique"):
        import_sources(manifest(tmp_path, [entry(), entry()]))
    with pytest.raises(ImportError, match="more than one author"):
        import_sources(manifest(tmp_path, [entry(), entry(id="second")]))


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "missing"])
def test_capture_refuses_ambiguous_or_nonregular_file(tmp_path, kind):
    original = tmp_path / "original"
    original.write_text("data")
    path = tmp_path / "source"
    if kind == "symlink":
        path.symlink_to(original)
    elif kind == "hardlink":
        os.link(original, path)
    elif kind == "directory":
        path.mkdir()
    with pytest.raises(ImportError):
        read_static(path)


def test_capture_is_bounded_and_fences_midread_changes(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"1234")
    with pytest.raises(ImportError, match="byte bound"):
        read_static(source, limit=3)
    with pytest.raises(ImportError, match="capture byte bound"):
        read_static(source, limit=0)
    original = os.read

    def mutate(fd, n):
        raw = original(fd, n)
        source.write_bytes(b"other")
        return raw

    monkeypatch.setattr(os, "read", mutate)
    with pytest.raises(ImportError, match="changed"):
        read_static(source)


def test_source_owner_digest_order_independent(tmp_path):
    (tmp_path / "one").write_text("{}")
    (tmp_path / "two").write_text("{}")
    entries = [entry("one", mapping={}), entry("two", id="other", mapping={})]
    one = import_sources(manifest(tmp_path, entries))
    two = import_sources(manifest(tmp_path, entries[::-1]))
    assert one.owner_digest("forwarding") == two.owner_digest("forwarding")
    assert one.owner_digest("forwarding") != replace(
        one, receipts=(replace(one.receipts[0], sha256="a" * 64),)
    ).owner_digest("forwarding")


def test_project_instance_requires_complete_inputs(tmp_path):
    # Model validation is supplied by instance tests; unresolved captures never
    # enter even a structurally complete candidate.
    (tmp_path / "owner.json").write_text("{}")
    result = import_sources(manifest(tmp_path, [entry()]))
    with pytest.raises(ImportError, match="Unresolved"):
        project_instance(result, {})


def test_nested_credential_objects_cannot_be_selected(tmp_path):
    (tmp_path / "owner.json").write_text('{"lan":{"password":"never-copy"}}')
    with pytest.raises(ImportError, match="Credential"):
        import_sources(manifest(tmp_path, [entry()]))


def test_complete_projection_validates_model_and_existing_list_slots(tmp_path):
    from netorch.instance import canonical_instance_bytes, instance_to_dict, load_instance

    base = load_instance(Path(__file__).parents[1] / "examples" / "instance.json")
    data = instance_to_dict(base)
    original = data["workloads"][0]["name"]
    data["workloads"][0]["name"] = None
    (tmp_path / "owner.json").write_text(json.dumps({"name": original}))
    result = import_sources(manifest(tmp_path, [entry(mapping={"/name": "/workloads/0/name"})]))
    assert project_instance(result, data) == canonical_instance_bytes(base)
    assert data["workloads"][0]["name"] is None
    with pytest.raises(ImportError, match="more than one author"):
        project_instance(result, instance_to_dict(base))


def test_projection_refuses_missing_list_or_scalar_parent(tmp_path):
    (tmp_path / "owner.json").write_text('{"lan":"192.0.2.11"}')
    result = import_sources(manifest(tmp_path, [entry(mapping={"/lan": "/workloads/9/name"})]))
    with pytest.raises(ImportError, match="unavailable"):
        project_instance(result, {"workloads": []})
    result = import_sources(manifest(tmp_path, [entry(mapping={"/lan": "/host/lan/name"})]))
    with pytest.raises(ImportError, match="unavailable"):
        project_instance(result, {"host": "unavailable"})


def test_import_refuses_conflicting_scalar_parent_and_leading_zero_index(tmp_path):
    (tmp_path / "owner.json").write_text('{"lan":"192.0.2.11","names":["one"]}')
    with pytest.raises(ImportError, match="unavailable"):
        import_sources(
            manifest(tmp_path, [entry(mapping={"/lan": "/address", "/names": "/address/name"})])
        )
    with pytest.raises(ImportError, match="Ambiguous"):
        import_sources(manifest(tmp_path, [entry(mapping={"/names/00": "/name"})]))


def test_capture_fences_replacement_between_stat_and_open(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"stable")
    original = os.open

    def replace_file(path, flags):
        source.unlink()
        source.write_bytes(b"different")
        return original(path, flags)

    monkeypatch.setattr(os, "open", replace_file)
    with pytest.raises(ImportError, match="identity changed"):
        read_static(source)

"""Synthetic provisioning parity through the real static importer and renderer.

No owner or selector executes. The captured literal file is the template; its
policy token stays desired data while a resolved device name is never imported
as a replacement for that policy.
"""

import hashlib
from pathlib import Path

import pytest

from netorch.codec import canonical_bytes
from netorch.instance import InstanceError, instance_to_dict, parse_instance
from netorch.legacy_import import (
    check_generated_view,
    generated_bytes,
    import_sources,
    project_instance,
)
from netorch.render import render_sources
from tests.test_render_promotion import owner_instance
from tests.test_render_sources import manifest, source

RAW = b'# preserved owner input\nLAN_INTERFACE="auto-wired"\nLAN_HOST_IP=198.51.100.10\n'


def owner_inputs(tmp_path: Path, raw: bytes = RAW):
    (tmp_path / "owner.env").write_bytes(raw)
    entry = source(
        "wired-owner",
        "owner.env",
        "literal-env",
        {"/LAN_INTERFACE": "/host/lan/selection", "/LAN_HOST_IP": "/host/lan/ipv4"},
    ) | {"owner": "forwarding", "sha256": hashlib.sha256(raw).hexdigest()}
    path = manifest(tmp_path, [entry])
    imported = import_sources(path)
    template = owner_instance("forwarding", imported.owner_digest("forwarding"), "host")
    template["host"]["lan"].update(hardware_id=None, selection=None, ipv4=None)
    return path, imported, template


def test_auto_wired_import_project_reimport_and_render_preserve_literal_bytes(tmp_path):
    path, imported, template = owner_inputs(tmp_path)
    assert imported.values == {
        "host": {"lan": {"selection": "auto-wired", "ipv4": "198.51.100.10"}}
    }
    assert not imported.underivable
    projected = project_instance(imported, template)
    instance = parse_instance(projected)
    assert instance.host.lan.selection == "auto-wired"
    assert instance.host.lan.hardware_id is None
    assert [row.mode for row in instance.authoring if row.owner == "forwarding"] == ["generated"]

    generated = tmp_path / "generated.json"
    generated.write_bytes(generated_bytes(imported))
    assert check_generated_view(path, generated)
    assert project_instance(import_sources(path), template) == projected

    collected: dict[str, bytes] = {}
    rendered = render_sources(path, instance, collect=collected)
    assert not rendered.issues
    assert [(row.identical, row.complete) for row in rendered.sources] == [(True, True)]
    assert collected == {"wired-owner": RAW}
    assert (tmp_path / "owner.env").read_bytes() == RAW


def test_address_change_renders_only_the_address_then_reimports_dynamic_policy(tmp_path):
    path, imported, template = owner_inputs(tmp_path)
    document = instance_to_dict(parse_instance(project_instance(imported, template)))
    document["host"]["lan"]["ipv4"] = "198.51.100.20"
    changed = parse_instance(canonical_bytes(document) + b"\n")
    collected: dict[str, bytes] = {}
    rendered = render_sources(path, changed, collect=collected)
    expected = RAW.replace(b"198.51.100.10", b"198.51.100.20")
    assert collected == {"wired-owner": expected}
    assert [(row.identical, row.complete) for row in rendered.sources] == [(False, True)]
    assert not rendered.issues
    # Rendering is read-only. After an owner accepts new inputs, its next import
    # gets a fresh source digest; it must not reuse the old provenance record.
    assert (tmp_path / "owner.env").read_bytes() == RAW
    next_path, next_imported, next_template = owner_inputs(tmp_path, expected)
    assert next_imported.owner_digest("forwarding") != imported.owner_digest("forwarding")
    next_instance = parse_instance(project_instance(next_imported, next_template))
    assert next_instance.host.lan.ipv4 == "198.51.100.20"
    assert next_instance.host.lan.selection == "auto-wired"
    assert next_instance.host.lan.hardware_id is None
    next_output: dict[str, bytes] = {}
    assert render_sources(next_path, next_instance, collect=next_output).sources[0].identical
    assert next_output == {"wired-owner": expected}


def test_resolved_device_cannot_be_imported_as_durable_auto_wired_policy(tmp_path):
    path, imported, template = owner_inputs(tmp_path, RAW.replace(b"auto-wired", b"en207"))
    assert imported.values["host"]["lan"]["selection"] == "en207"
    with pytest.raises(InstanceError, match="schema"):
        project_instance(imported, template)
    # A rejected import leaves only the original synthetic source and manifest;
    # no candidate instance, rendered output or native change was produced.
    assert set(item.name for item in tmp_path.iterdir()) == {"owner.env", path.name}

"""A static import fills settings; it never writes decisions, records or the release pin."""

from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest

from netorch.instance import canonical_instance_bytes, instance_to_dict, load_instance
from netorch.legacy_import import (
    ImportError,
    ImportResult,
    import_sources,
    project_instance,
)

ROOT = Path(__file__).resolve().parents[1]
SIGNED_AT = "2026-01-01T00:00:00Z"
DEVIATION = {
    "id": "example-deviation",
    "requirement": "HOST-DATA",
    "statement": "Example statement.",
    "accepted_by": None,
    "accepted_at": None,
}
ACCEPTANCE = {
    "requirement": "NO-LOCAL-NETWORK",
    "profile": None,
    "method": "schema-tests",
    "tier": 1,
    "observed_at": SIGNED_AT,
    "macos_build": "26A434",
    "runtime_version": "1.5.0",
    "framework_sha256": "0" * 64,
    "contract_sha256": "0" * 64,
    "evidence_sha256": "0" * 64,
    "signed_by": None,
    "instance_schema_version": 1,
}


def template():
    return instance_to_dict(load_instance(ROOT / "examples" / "instance.json"))


def imported(tmp_path, legacy, mapping, fmt="json"):
    raw = plistlib.dumps(legacy) if fmt == "plist" else json.dumps(legacy).encode()
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


def test_import_cannot_accept_a_decision_or_sign_it(tmp_path):
    legacy = {"approved": True, "limit": 300, "visible": True, "who": "operator", "when": SIGNED_AT}
    mapping = {
        "/approved": "/decisions/unattended_recovery/accepted",
        "/limit": "/decisions/unattended_recovery/max_dns_ready_seconds",
        "/visible": "/decisions/import_visibility/accepted",
        "/who": "/decisions/import_visibility/signed_by",
        "/when": "/decisions/import_visibility/signed_at",
    }
    result = imported(tmp_path, legacy, mapping)
    with pytest.raises(ImportError, match="Authored instance sections"):
        project_instance(result, template())


def test_import_cannot_set_the_release_pin(tmp_path):
    data = template()
    data["framework"]["artifact_sha256"] = None
    result = imported(tmp_path, {"pin": "f" * 64}, {"/pin": "/framework/artifact_sha256"})
    with pytest.raises(ImportError, match="Authored instance sections"):
        project_instance(result, data)


def test_import_cannot_accept_a_deviation(tmp_path):
    data = template()
    data["deviations"] = [dict(DEVIATION)]
    mapping = {"/who": "/deviations/0/accepted_by", "/when": "/deviations/0/accepted_at"}
    result = imported(tmp_path, {"who": "operator", "when": SIGNED_AT}, mapping)
    with pytest.raises(ImportError, match="Authored instance sections"):
        project_instance(result, data)


def test_import_cannot_replace_a_whole_authored_section():
    data = template()
    data["deviations"] = None
    accepted = DEVIATION | {"accepted_by": "operator", "accepted_at": SIGNED_AT}
    with pytest.raises(ImportError, match="Authored instance sections"):
        project_instance(ImportResult({"deviations": [accepted]}, (), ()), data)


@pytest.mark.parametrize(
    "values,prepare",
    [
        (
            {"decisions": {"lifecycle_control": {"residual": "Example residual."}}},
            lambda data: None,
        ),
        (
            {"acceptance": {"0": {"signed_by": "operator"}}},
            lambda data: data.update(acceptance=[dict(ACCEPTANCE)]),
        ),
        (
            {"deviations": {"0": {"accepted_by": "operator", "accepted_at": SIGNED_AT}}},
            lambda data: data.update(deviations=[dict(DEVIATION)]),
        ),
        (
            {"authoring": {"0": {"mode": "authored"}}},
            lambda data: data["authoring"][0].update(mode=None),
        ),
        (
            {"framework": {"revision": "f" * 40}},
            lambda data: data["framework"].update(revision=None),
        ),
    ],
    ids=["decisions", "acceptance", "deviations", "authoring", "framework"],
)
def test_no_authored_section_has_an_importable_slot(values, prepare):
    data = template()
    prepare(data)
    with pytest.raises(ImportError, match="Authored instance sections"):
        project_instance(ImportResult(values, (), ()), data)


def test_authored_section_is_refused_before_the_template_is_consulted():
    # Not "more than one author": the destination itself is out of bounds.
    values = {"framework": {"version": "9.9.9"}}
    with pytest.raises(ImportError, match="Authored instance sections"):
        project_instance(ImportResult(values, (), ()), template())


def test_other_sections_are_still_filled_from_an_import(tmp_path):
    base = load_instance(ROOT / "examples" / "instance.json")
    data = instance_to_dict(base)
    seconds = data["supervision"]["reconcile_seconds"]
    data["supervision"]["reconcile_seconds"] = None
    result = imported(
        tmp_path, {"interval": seconds}, {"/interval": "/supervision/reconcile_seconds"}
    )
    assert project_instance(result, data) == canonical_instance_bytes(base)


def test_a_free_inventory_may_still_record_such_paths(tmp_path):
    # The boundary is the projection onto an instance, not the inventory.
    result = imported(tmp_path, {"approved": True}, {"/approved": "/decisions/legacy/approved"})
    assert result.values == {"decisions": {"legacy": {"approved": True}}}

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from netorch.conformance import (
    ByteComparison,
    ConformanceError,
    check_owner_flip,
    compare_artifacts,
    compare_bytes,
    promote_owner,
)
from netorch.legacy_import import ImportResult, Issue, SourceReceipt


def sources():
    return ImportResult(
        {},
        (
            SourceReceipt(
                "owner-input",
                "forwarding",
                hashlib.sha256(b"IP=192.0.2.11\n").hexdigest(),
                "literal-env",
            ),
        ),
        (),
    )


def instance():
    return {
        "names": {"anchor": "com.example.network"},
        "authoring": [
            {
                "owner": "forwarding",
                "sections": ["names"],
                "subjects": [],
                "mode": "generated",
                "source_sha256": sources().owner_digest("forwarding"),
            }
        ],
    }


def equal():
    return (
        compare_bytes("owner-input", b"IP=192.0.2.11\n", b"IP=192.0.2.11\n", owner="forwarding"),
    )


def test_exact_owner_flip_changes_only_provenance_and_not_inputs():
    before = instance()
    after = promote_owner(before, "forwarding", sources(), equal())
    assert before["authoring"][0]["mode"] == "generated"
    assert after["authoring"][0]["mode"] == "authored"
    assert after["authoring"][0]["source_sha256"] is None
    assert check_owner_flip(before, after, "forwarding")


@pytest.mark.parametrize(
    "rendered",
    [b"IP=192.0.2.11", b"# new header\nIP=192.0.2.11\n", b"IP=192.0.2.12\n", b"IP = 192.0.2.11\n"],
)
def test_even_headers_whitespace_and_final_newline_break_parity(rendered):
    comparison = compare_bytes("owner-input", b"IP=192.0.2.11\n", rendered, owner="forwarding")
    assert not comparison.identical
    assert len(comparison.to_dict()["captured_sha256"]) == 64
    with pytest.raises(ConformanceError, match="byte parity"):
        promote_owner(instance(), "forwarding", sources(), (comparison,))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data["names"].update(anchor="com.example.renamed"),
        lambda data: data["authoring"][0].update(subjects=["other"]),
        lambda data: data["authoring"].append(
            {
                "owner": "other",
                "sections": ["host"],
                "subjects": [],
                "mode": "authored",
                "source_sha256": None,
            }
        ),
        lambda data: data.update(state_directory="/different"),
        lambda data: data["authoring"][0].update(source_sha256="b" * 64),
        lambda data: data["authoring"][0].update(mode="generated"),
    ],
)
def test_flip_cannot_hide_other_changes(mutate):
    before = instance()
    after = promote_owner(before, "forwarding", sources(), equal())
    mutate(after)
    assert not check_owner_flip(before, after, "forwarding")


@pytest.mark.parametrize(
    "comparisons",
    [
        (),
        equal() * 2,
        (compare_bytes("unrelated", b"a", b"a", owner="forwarding"),),
        (ByteComparison("owner-input", "a" * 64, "b" * 64, 1, 1, True, "forwarding"),),
        (ByteComparison("owner-input", "a" * 64, "a" * 64, 1, 2, True, "forwarding"),),
    ],
)
def test_parity_requires_every_source_exactly_once(comparisons):
    with pytest.raises(ConformanceError, match="byte parity"):
        promote_owner(instance(), "forwarding", sources(), comparisons)


def test_owner_source_drift_and_underivable_are_not_authorized():
    changed = instance()
    changed["authoring"][0]["source_sha256"] = "b" * 64
    with pytest.raises(ConformanceError, match="digest"):
        promote_owner(changed, "forwarding", sources(), equal())
    unresolved = ImportResult(
        {}, sources().receipts, (Issue("owner-input", "unsupported-static-syntax"),)
    )
    with pytest.raises(ConformanceError, match="unresolved"):
        promote_owner(instance(), "forwarding", unresolved, equal())
    unrelated = ImportResult({}, sources().receipts, (Issue("other", "unsupported-static-syntax"),))
    assert promote_owner(instance(), "forwarding", unrelated, equal())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data.pop("authoring"),
        lambda data: data.update(authoring=[]),
        lambda data: data["authoring"].append(copy.deepcopy(data["authoring"][0])),
        lambda data: data["authoring"][0].update(extra=True),
        lambda data: data["authoring"][0].update(sections=[]),
        lambda data: data["authoring"][0].update(sections=["unknown"]),
        lambda data: data["authoring"][0].update(sections=["names", "names"]),
        lambda data: data["authoring"][0].update(subjects=["UPPER"]),
        lambda data: data["authoring"][0].update(subjects=["one", "one"]),
        lambda data: data["authoring"][0].update(mode="authored"),
    ],
)
def test_authoring_record_is_closed(mutate):
    before = instance()
    mutate(before)
    with pytest.raises(ConformanceError):
        promote_owner(before, "forwarding", sources(), equal())


def artifact_manifest(tmp_path, **changes):
    (tmp_path / "captured").write_bytes(b"IP=192.0.2.11\n")
    (tmp_path / "rendered").write_bytes(b"IP=192.0.2.11\n")
    data = {
        "schema_version": 1,
        "owner": "forwarding",
        "artifacts": [{"id": "owner-input", "captured": "captured", "rendered": "rendered"}],
    } | changes
    path = tmp_path / "manifest"
    path.write_text(json.dumps(data))
    return path


def test_fresh_file_byte_comparison(tmp_path):
    path = artifact_manifest(tmp_path)
    assert compare_artifacts(path)[0].identical
    (tmp_path / "rendered").write_bytes(b"# new header\nIP=192.0.2.11\n")
    assert not compare_artifacts(path)[0].identical


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": 2},
        {"schema_version": True},
        {"extra": 1},
        {"owner": "UPPER"},
        {"artifacts": []},
        {"artifacts": None},
        {"artifacts": [{"id": "one", "captured": "captured", "rendered": "rendered", "extra": 1}]},
        {"artifacts": [{"id": "UPPER", "captured": "captured", "rendered": "rendered"}]},
        {"artifacts": [{"id": "one", "captured": "", "rendered": "rendered"}]},
        {"artifacts": [{"id": "one", "captured": "captured", "rendered": "bad\x00path"}]},
        {"artifacts": [{"id": "one", "captured": "captured", "rendered": "rendered"}] * 2},
    ],
)
def test_artifact_manifest_closed(tmp_path, changes):
    with pytest.raises(ConformanceError):
        compare_artifacts(artifact_manifest(tmp_path, **changes))


def test_invalid_artifact_identifier():
    with pytest.raises(ConformanceError):
        compare_bytes("UPPER", b"a", b"a")

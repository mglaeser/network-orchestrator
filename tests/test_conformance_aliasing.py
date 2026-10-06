"""A manifest compares two different files, and only for the owner it names."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from netorch.conformance import (
    ConformanceError,
    check_owner_flip,
    compare_artifacts,
    compare_bytes,
    promote_owner,
)
from netorch.legacy_import import ImportResult, SourceReceipt

CAPTURED = b"IP=192.0.2.11\n"
SECOND = b"PORT=4242\n"


def sources(*identifiers: str) -> ImportResult:
    contents = {"owner-input": CAPTURED, "second-input": SECOND}
    return ImportResult(
        {},
        tuple(
            SourceReceipt(
                identifier,
                "forwarding",
                hashlib.sha256(contents[identifier]).hexdigest(),
                "literal-env",
            )
            for identifier in identifiers or ("owner-input",)
        ),
        (),
    )


def instance(*identifiers: str) -> dict[str, Any]:
    return {
        "names": {"anchor": "example-anchor"},
        "authoring": [
            {
                "owner": "forwarding",
                "sections": ["names"],
                "subjects": [],
                "mode": "generated",
                "source_sha256": sources(*identifiers).owner_digest("forwarding"),
            }
        ],
    }


def manifest(directory: Path, *, owner: str = "forwarding", rendered: str = "rendered") -> Path:
    (directory / "captured").write_bytes(CAPTURED)
    (directory / "rendered").write_bytes(CAPTURED)
    data = {
        "schema_version": 1,
        "owner": owner,
        "artifacts": [{"id": "owner-input", "captured": "captured", "rendered": rendered}],
    }
    path = directory / "manifest"
    path.write_text(json.dumps(data))
    return path


def test_two_identical_files_still_promote_their_owner(tmp_path: Path) -> None:
    comparisons = compare_artifacts(manifest(tmp_path))
    assert [item.identical for item in comparisons] == [True]
    before = instance()
    after = promote_owner(before, "forwarding", sources(), comparisons)
    assert check_owner_flip(before, after, "forwarding")


@pytest.mark.parametrize(
    "spelling", ["same", "dot", "parent", "absolute", "linked-directory", "linked-parent"]
)
def test_rendered_artifact_cannot_be_the_captured_file_itself(
    tmp_path: Path, spelling: str
) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
    rendered = {
        "same": "captured",
        "dot": "./captured",
        "parent": "nested/../captured",
        "absolute": str(tmp_path / "captured"),
        "linked-directory": "link/captured",
        "linked-parent": str(tmp_path / "link" / "nested" / ".." / "captured"),
    }[spelling]
    with pytest.raises(ConformanceError, match="different files"):
        compare_artifacts(manifest(tmp_path, rendered=rendered))


def test_hard_linked_rendered_artifact_stays_refused(tmp_path: Path) -> None:
    path = manifest(tmp_path, rendered="linked")
    os.link(tmp_path / "captured", tmp_path / "linked")
    with pytest.raises(ValueError, match="unlinked"):
        compare_artifacts(path)


def test_artifact_that_vanishes_before_the_identity_check_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def vanished(first: Any, second: Any) -> bool:
        raise FileNotFoundError("example")

    path = manifest(tmp_path)
    monkeypatch.setattr(os.path, "samefile", vanished)
    with pytest.raises(ConformanceError, match="unavailable"):
        compare_artifacts(path)


def test_comparison_records_the_owner_it_was_made_for(tmp_path: Path) -> None:
    assert [item.owner for item in compare_artifacts(manifest(tmp_path))] == ["forwarding"]
    bound = compare_bytes("owner-input", CAPTURED, CAPTURED, owner="forwarding")
    assert bound.to_dict()["owner"] == "forwarding"
    assert compare_bytes("owner-input", CAPTURED, CAPTURED).to_dict()["owner"] is None
    with pytest.raises(ConformanceError, match="owner"):
        compare_bytes("owner-input", CAPTURED, CAPTURED, owner="UPPER")


def test_manifest_for_another_owner_promotes_no_one(tmp_path: Path) -> None:
    comparisons = compare_artifacts(manifest(tmp_path, owner="discovery"))
    assert [item.identical for item in comparisons] == [True]
    with pytest.raises(ConformanceError, match="not bound to this owner"):
        promote_owner(instance(), "forwarding", sources(), comparisons)


def test_comparison_without_an_owner_promotes_no_one() -> None:
    unbound = (compare_bytes("owner-input", CAPTURED, CAPTURED),)
    with pytest.raises(ConformanceError, match="not bound to this owner"):
        promote_owner(instance(), "forwarding", sources(), unbound)


@pytest.mark.parametrize("other", ["discovery", None])
def test_one_foreign_comparison_among_several_is_refused(other: str | None) -> None:
    identifiers = ("owner-input", "second-input")
    own = compare_bytes("owner-input", CAPTURED, CAPTURED, owner="forwarding")
    second = compare_bytes("second-input", SECOND, SECOND, owner="forwarding")
    before = instance(*identifiers)
    assert promote_owner(before, "forwarding", sources(*identifiers), (own, second))
    foreign = compare_bytes("second-input", SECOND, SECOND, owner=other)
    for comparisons in ((own, foreign), (foreign, own)):
        with pytest.raises(ConformanceError, match="not bound to this owner"):
            promote_owner(before, "forwarding", sources(*identifiers), comparisons)

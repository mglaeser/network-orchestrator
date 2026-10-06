"""Byte conformance for one owner at a time, without executing renderers.

A renderer's output is an explicit data file. This module never invokes a
legacy owner, installer, template engine, subprocess, or privileged command.
"""

from __future__ import annotations

import copy
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .codec import canonical_bytes, strict_loads
from .legacy_import import INVENTORY_ONLY, ImportResult, capture_static, read_static

_ID = re.compile(r"[a-z][a-z0-9-]{0,63}")
_SECTIONS = {
    "host",
    "names",
    "workloads",
    "port_ranges",
    "transport",
    "discovery",
    "supervision",
    "lifecycle_tools",
    "decisions",
    "acceptance",
    "deviations",
}


class ConformanceError(ValueError):
    """Owner promotion lacks exact captured input/output agreement."""


@dataclass(frozen=True)
class ByteComparison:
    id: str
    captured_sha256: str
    rendered_sha256: str
    captured_bytes: int
    rendered_bytes: int
    identical: bool
    # The owner the comparison was made for; an unbound comparison promotes no one.
    owner: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "owner": self.owner,
            "captured_sha256": self.captured_sha256,
            "rendered_sha256": self.rendered_sha256,
            "captured_bytes": self.captured_bytes,
            "rendered_bytes": self.rendered_bytes,
            "identical": self.identical,
        }


@dataclass(frozen=True)
class InventoryCheck:
    """A source that is pinned by its hash and searched as text, never evaluated or rendered.

    ``netorch.render`` makes one for every program of a manifest. ``scanned`` is
    false when the bytes could not be searched as text; ``embedded_literals``
    counts the places that hold one of the instance's specific string settings.
    """

    id: str
    owner: str
    sha256: str
    scanned: bool
    embedded_literals: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "owner": self.owner,
            "sha256": self.sha256,
            "scanned": self.scanned,
            "embedded_literals": self.embedded_literals,
        }


def compare_bytes(
    identifier: str, captured: bytes, rendered: bytes, *, owner: str | None = None
) -> ByteComparison:
    if not _ID.fullmatch(identifier):
        raise ConformanceError("Invalid conformance artifact identifier")
    if owner is not None and not _ID.fullmatch(owner):
        raise ConformanceError("Invalid conformance owner")
    return ByteComparison(
        identifier,
        hashlib.sha256(captured).hexdigest(),
        hashlib.sha256(rendered).hexdigest(),
        len(captured),
        len(rendered),
        captured == rendered,
        owner,
    )


def compare_artifacts(manifest: str | Path) -> tuple[ByteComparison, ...]:
    """Compare fresh bounded captures, including comments, whitespace and final LF."""
    path = Path(manifest)
    data = strict_loads(read_static(path))
    if (
        not isinstance(data, dict)
        or set(data) != {"schema_version", "owner", "artifacts"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
    ):
        raise ConformanceError("Unsupported conformance manifest")
    if not isinstance(data["owner"], str) or not _ID.fullmatch(data["owner"]):
        raise ConformanceError("Invalid conformance owner")
    entries = data["artifacts"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 128:
        raise ConformanceError("A bounded nonempty artifact list is required")
    seen: set[str] = set()
    captured_files: set[tuple[int, int]] = set()
    rendered_files: set[tuple[int, int]] = set()
    comparisons: list[ByteComparison] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "captured", "rendered"}:
            raise ConformanceError("Unsupported conformance artifact")
        identifier = entry["id"]
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier) or identifier in seen:
            raise ConformanceError("Conformance artifact IDs must be unique")
        seen.add(identifier)
        paths: list[Path] = []
        for key in ("captured", "rendered"):
            value = entry[key]
            if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
                raise ConformanceError("Invalid conformance data path")
            p = Path(value)
            paths.append(p if p.is_absolute() else path.parent / p)
        captured, rendered = capture_static(paths[0]), capture_static(paths[1])
        captured_files.add(captured.file_identity)
        rendered_files.add(rendered.file_identity)
        if captured_files & rendered_files:
            raise ConformanceError("Captured and rendered artifacts must be different files")
        try:
            # One file in both roles is trivially identical and proves no rendering.
            aliased = os.path.samefile(paths[0], paths[1])
        except OSError as exc:
            raise ConformanceError("Conformance artifact is unavailable") from exc
        if aliased:
            raise ConformanceError("Captured and rendered artifacts must be different files")
        comparisons.append(
            compare_bytes(identifier, captured.data, rendered.data, owner=data["owner"])
        )
    return tuple(comparisons)


def _authoring(instance: dict[str, Any], owner: str) -> dict[str, Any]:
    records = instance.get("authoring")
    if not isinstance(records, list):
        raise ConformanceError("Instance authoring provenance is required")
    selected = [r for r in records if isinstance(r, dict) and r.get("owner") == owner]
    if len(selected) != 1:
        raise ConformanceError("Exactly one owner authoring record is required")
    record = selected[0]
    if set(record) != {"owner", "sections", "subjects", "mode", "source_sha256"}:
        raise ConformanceError("Unsupported owner authoring record")
    sections = record["sections"]
    if (
        not isinstance(sections, list)
        or not sections
        or any(not isinstance(s, str) or s not in _SECTIONS for s in sections)
        or len(set(sections)) != len(sections)
    ):
        raise ConformanceError("Owner must name distinct closed instance sections")
    subjects = record["subjects"]
    if (
        not isinstance(subjects, list)
        or len(subjects) > 128
        or any(not isinstance(s, str) or not _ID.fullmatch(s) for s in subjects)
        or len(set(subjects)) != len(subjects)
    ):
        raise ConformanceError("Owner subjects must be bounded distinct identifiers")
    return record


def promote_owner(
    instance: dict[str, Any],
    owner: str,
    sources: ImportResult,
    comparisons: tuple[ByteComparison, ...],
    inventory: tuple[InventoryCheck, ...] = (),
) -> dict[str, Any]:
    """Produce the single owner flip only after fresh source and byte parity checks.

    The caller must validate the full instance with the closed instance parser;
    this operation changes only that owner's provenance, never desired values.
    A program of the owner is never compared, because nothing renders it. It
    stays pinned by its hash in the owner digest and needs an inventory check
    that searched its text and found none of the instance's settings.
    """
    record = _authoring(instance, owner)
    if record["mode"] != "generated" or record["source_sha256"] != sources.owner_digest(owner):
        raise ConformanceError("Generated owner digest does not match freshly captured sources")
    receipt_hashes = {r.id: r.sha256 for r in sources.receipts if r.owner == owner}
    owner_sources = set(receipt_hashes)
    formats = {r.id: r.format for r in sources.receipts if r.owner == owner}
    programs = {key for key in owner_sources if formats[key] == "source-inventory"}
    if any(
        issue.source in owner_sources
        and not (issue.source in programs and issue.reason == INVENTORY_ONLY)
        for issue in sources.underivable
    ):
        raise ConformanceError("Owner has unresolved static inputs")
    if any(check.owner != owner for check in inventory):
        raise ConformanceError("Inventory checks are not bound to this owner")
    checked = {check.id for check in inventory}
    # A data file in a format that is not rendered may be searched instead of compared.
    searched = programs | {key for key in checked & owner_sources if formats[key] == "toml"}
    if (
        checked != searched
        or len(checked) != len(inventory)
        or any(
            check.sha256 != receipt_hashes.get(check.id)
            or check.scanned is not True
            or type(check.embedded_literals) is not int
            or check.embedded_literals != 0
            for check in inventory
        )
    ):
        raise ConformanceError("Owner program still holds or may hold instance settings")
    if any(c.owner != owner for c in comparisons):
        raise ConformanceError("Byte comparisons are not bound to this owner")
    if (
        not comparisons
        or {c.id for c in comparisons} != owner_sources - searched
        or len({c.id for c in comparisons}) != len(comparisons)
        or any(
            not c.identical
            or c.captured_sha256 != receipt_hashes.get(c.id)
            or c.captured_sha256 != c.rendered_sha256
            or c.captured_bytes != c.rendered_bytes
            for c in comparisons
        )
    ):
        raise ConformanceError("Every owner input must have exact byte parity")
    result = copy.deepcopy(instance)
    promoted = _authoring(result, owner)
    promoted["mode"] = "authored"
    promoted["source_sha256"] = None
    return result


def check_owner_flip(before: dict[str, Any], after: dict[str, Any], owner: str) -> bool:
    """Reject hidden renames, desired changes, other owner flips or state movement."""
    before_record = _authoring(before, owner)
    after_record = _authoring(after, owner)
    if (
        before_record["mode"] != "generated"
        or after_record["mode"] != "authored"
        or after_record["source_sha256"] is not None
    ):
        return False
    expected = copy.deepcopy(before)
    expected_record = _authoring(expected, owner)
    expected_record["mode"] = "authored"
    expected_record["source_sha256"] = None
    return canonical_bytes(expected) == canonical_bytes(after)

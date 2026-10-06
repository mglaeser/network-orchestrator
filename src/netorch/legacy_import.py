"""Read-only projection of existing owner data; no legacy input is evaluated.

The manifest is local migration evidence, not an executable instance policy.
Only explicitly mapped data is emitted. Unsupported syntax is reported without
copying its body, so expressions and secrets cannot become generated settings.
"""

from __future__ import annotations

import copy
import hashlib
import os
import plistlib
import re
import stat
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .codec import MAX_JSON_BYTES, CodecError, canonical_bytes, strict_loads
from .derive import DeriveError, literal_assignments, literal_lines

_ID = re.compile(r"[a-z][a-z0-9-]{0,63}")
_SHA = re.compile(r"[0-9a-f]{64}")
_SECRET_KEY = re.compile(
    r"(?:^|[_-])(env|environment|password|passwd|token|secret|credential|credentials|authorization|private_?key|api_?key)(?:$|[_-])",
    re.I,
)
_FORMATS = {"json", "plist", "toml", "literal-env", "text-list", "source-inventory"}
# Decisions, acceptance records, deviations, provenance and the release pin are
# written by a person; a static import never fills them.
_AUTHORED_SECTIONS = frozenset({"decisions", "acceptance", "deviations", "authoring", "framework"})


class ImportError(ValueError):
    """The static migration contract is ambiguous or cannot be read safely."""


def _secret_key(key: str) -> bool:
    """Recognize closed credential words across common data-key spellings.

    This filters known key names, not arbitrary secret values. Preserve word
    boundaries so harmless substrings such as ``monkey`` stay ordinary data.
    """
    words = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", words).replace("-", "_")
    return _SECRET_KEY.search(words) is not None


@dataclass(frozen=True)
class Issue:
    source: str
    reason: str
    selector: str | None = None


@dataclass(frozen=True)
class SourceReceipt:
    id: str
    owner: str
    sha256: str
    format: str


@dataclass(frozen=True)
class ImportResult:
    values: dict[str, Any]
    receipts: tuple[SourceReceipt, ...]
    underivable: tuple[Issue, ...]

    def owner_digest(self, owner: str) -> str:
        records = [{"id": r.id, "sha256": r.sha256} for r in self.receipts if r.owner == owner]
        if not records:
            raise ImportError("Owner has no captured static sources")
        return hashlib.sha256(canonical_bytes(sorted(records, key=lambda r: r["id"]))).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "values": self.values,
            "sources": [
                {"id": r.id, "owner": r.owner, "sha256": r.sha256, "format": r.format}
                for r in self.receipts
            ],
            "underivable": [
                {"source": i.source, "reason": i.reason, "selector": i.selector}
                for i in self.underivable
            ],
        }


def read_static(path: str | Path, *, limit: int = MAX_JSON_BYTES) -> bytes:
    """Bounded regular-file read with no final symlink and an identity fence."""
    if not 1 <= limit <= MAX_JSON_BYTES:
        raise ImportError("Unsupported capture byte bound")
    p = Path(path)
    try:
        before = p.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ImportError("Capture requires a regular, unlinked file")
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            if _identity(opened) != _identity(before):
                raise ImportError("Capture identity changed before reading")
            chunks: list[bytes] = []
            size = 0
            while size <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            raw = b"".join(chunks)
            if size > limit:
                raise ImportError("Capture exceeds the byte bound")
            if _identity(os.fstat(fd)) != _identity(before) or _identity(p.lstat()) != _identity(
                before
            ):
                raise ImportError("Capture changed during reading")
            return raw
        finally:
            os.close(fd)
    except OSError as exc:
        raise ImportError("Static source is unavailable") from exc


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _pointer(pointer: object) -> list[str]:
    if not isinstance(pointer, str) or len(pointer) > 2048 or not pointer.startswith("/"):
        raise ImportError("Expected a nonempty JSON pointer")
    if pointer == "/" or "~" in pointer or any(not p for p in pointer[1:].split("/")):
        raise ImportError("Unsupported JSON pointer")
    parts = pointer[1:].split("/")
    if any(part.isdecimal() and len(part) > 1 and part.startswith("0") for part in parts):
        raise ImportError("Ambiguous JSON pointer index")
    return parts


def _lookup(data: Any, pointer: str) -> Any:
    value = data
    for part in _pointer(pointer):
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif (
            isinstance(value, list)
            and re.fullmatch(r"0|[1-9][0-9]*", part)
            and int(part) < len(value)
        ):
            value = value[int(part)]
        else:
            raise ImportError("Mapped static value is unavailable")
    return value


def _fill(data: dict[str, Any], pointer: str, value: Any) -> None:
    parts = _pointer(pointer)
    node: Any = data
    for part in parts[:-1]:
        if isinstance(node, dict):
            node = node.setdefault(part, {})
        elif isinstance(node, list) and part.isdecimal() and int(part) < len(node):
            node = node[int(part)]
        else:
            raise ImportError("Mapping container is unavailable")
    last = parts[-1]
    if isinstance(node, dict):
        if last in node and node[last] is not None:
            raise ImportError("Mapped value has more than one author")
        node[last] = copy.deepcopy(value)
    elif isinstance(node, list) and last.isdecimal() and int(last) < len(node):
        if node[int(last)] is not None:
            raise ImportError("Mapped value has more than one author")
        node[int(last)] = copy.deepcopy(value)
    else:
        raise ImportError("Mapping target is unavailable")


def _decode(raw: bytes, fmt: str) -> Any:
    if fmt == "json":
        return strict_loads(raw)
    if fmt == "plist":
        # Entity/DTD expansion and binary objects are not migration data contracts.
        if (
            not raw.startswith(b"<?xml")
            or b"<!ENTITY" in raw
            or re.search(
                rb"<!DOCTYPE(?! plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">)",
                raw,
            )
        ):
            raise ImportError("Only standard XML property-list data is supported")
        parser: ET.XMLPullParser[ET.Element] = ET.XMLPullParser(events=("start", "end"))
        depth = nodes = roots = 0
        for offset in range(0, len(raw), 65536):
            parser.feed(raw[offset : offset + 65536])
            for event, element in cast(Iterable[tuple[str, ET.Element]], parser.read_events()):
                if event == "start":
                    if element.tag not in {
                        "plist",
                        "dict",
                        "key",
                        "array",
                        "string",
                        "integer",
                        "real",
                        "true",
                        "false",
                        "date",
                        "data",
                    } or (
                        element.attrib
                        and not (element.tag == "plist" and element.attrib == {"version": "1.0"})
                    ):
                        raise ImportError("Unknown property-list structure")
                    if (depth == 0) != (element.tag == "plist"):
                        raise ImportError("Property list must have a plist root")
                    if depth == 1:
                        # The standard parser silently keeps the last root object.
                        roots += 1
                        if roots > 1 or element.tag == "key":
                            raise ImportError("Property list must contain one root object")
                    depth += 1
                    nodes += 1
                    if depth > 64 or nodes > 50000:
                        raise ImportError("Property list exceeds structural bounds")
                else:
                    depth -= 1
                    if element.tag == "dict":
                        children = list(element)
                        keys = [item.text or "" for item in children[::2]]
                        if (
                            len(children) % 2
                            or any(item.tag != "key" for item in children[::2])
                            or len(keys) != len(set(keys))
                        ):
                            raise ImportError("Duplicate or malformed property-list keys")
        parser.close()
        return plistlib.loads(raw, fmt=plistlib.FMT_XML)
    text = raw.decode("utf-8", "strict")
    if fmt == "toml":
        return tomllib.loads(text)
    if fmt == "literal-env":
        return literal_assignments(text)
    if fmt == "text-list":
        values = [line for line in literal_lines(text) if line and not line.startswith("#")]
        if (
            len(values) > 1024
            or len(set(values)) != len(values)
            or any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", item) for item in values)
        ):
            raise ImportError("Unsupported literal data-list syntax")
        return {"items": values}
    raise ImportError("Source code is inventory only")


def _safe_projection(value: Any) -> None:
    nodes = [value]
    while nodes:
        node = nodes.pop()
        if isinstance(node, dict):
            if any(_secret_key(key) for key in node):
                raise ImportError("Credential and environment values are not instance data")
            nodes.extend(node.values())
        elif isinstance(node, list):
            nodes.extend(node)


def import_sources(manifest: str | Path) -> ImportResult:
    path = Path(manifest)
    data = strict_loads(read_static(path))
    if (
        not isinstance(data, dict)
        or set(data) != {"schema_version", "sources"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
    ):
        raise ImportError("Unsupported static import manifest")
    entries = data["sources"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 128:
        raise ImportError("A bounded static source list is required")
    values: dict[str, Any] = {}
    receipts: list[SourceReceipt] = []
    issues: list[Issue] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "id",
            "owner",
            "path",
            "format",
            "sha256",
            "mapping",
        }:
            raise ImportError("Unsupported static source contract")
        sid, owner, fmt, source_path = (entry[k] for k in ("id", "owner", "format", "path"))
        if any(not isinstance(v, str) or not _ID.fullmatch(v) for v in (sid, owner)) or sid in seen:
            raise ImportError("Static source IDs must be unique closed identifiers")
        seen.add(sid)
        if (
            not isinstance(fmt, str)
            or fmt not in _FORMATS
            or not isinstance(source_path, str)
            or not source_path
            or len(source_path) > 4096
            or "\x00" in source_path
        ):
            raise ImportError("Invalid static source format or path")
        expected = entry["sha256"]
        if expected is not None and (not isinstance(expected, str) or not _SHA.fullmatch(expected)):
            raise ImportError("Invalid static source digest")
        mapping = entry["mapping"]
        if not isinstance(mapping, dict) or len(mapping) > 1024:
            raise ImportError("Static mappings must be a bounded object")
        for selector, pointer in mapping.items():
            if any(_secret_key(part) for part in _pointer(selector) + _pointer(pointer)):
                raise ImportError("Credential and environment values are not instance data")
        if fmt == "source-inventory" and mapping:
            raise ImportError("Executable owner sources cannot provide desired settings")
        capture = Path(source_path)
        if not capture.is_absolute():
            capture = path.parent / capture
        raw = read_static(capture)
        sha = hashlib.sha256(raw).hexdigest()
        if expected is not None and expected != sha:
            raise ImportError("Static source digest changed; capture requires explicit review")
        receipts.append(SourceReceipt(sid, owner, sha, fmt))
        if fmt == "source-inventory":
            issues.append(Issue(sid, "executable-source-not-evaluated"))
            continue
        try:
            source = _decode(raw, fmt)
            canonical_bytes(source)  # Bound nodes/types, including XML and TOML values.
        except (
            ImportError,
            DeriveError,
            CodecError,
            UnicodeError,
            ValueError,
            plistlib.InvalidFileException,
            ET.ParseError,
            RecursionError,
        ) as exc:
            issues.append(Issue(sid, "unsupported-static-syntax"))
            # Do not emit error text: it can contain the input's secret expression.
            del exc
            continue
        for selector, pointer in mapping.items():
            try:
                value = _lookup(source, selector)
            except ImportError:
                issues.append(Issue(sid, "mapped-value-unavailable", selector))
                continue
            _safe_projection(value)
            _fill(values, pointer, value)
    return ImportResult(values, tuple(receipts), tuple(issues))


def generated_bytes(result: ImportResult) -> bytes:
    return canonical_bytes(result.to_dict()) + b"\n"


def check_generated_view(manifest: str | Path, generated: str | Path) -> bool:
    """Byte-for-byte regeneration check; no canonicalization hides drift."""
    return generated_bytes(import_sources(manifest)) == read_static(generated)


def project_instance(result: ImportResult, template: dict[str, Any]) -> bytes:
    """Fill explicit null slots and validate the independently closed instance model."""
    from .instance import canonical_instance_bytes, parse_instance

    if not _AUTHORED_SECTIONS.isdisjoint(result.values):
        raise ImportError("Authored instance sections cannot be filled by an import")
    data = copy.deepcopy(template)

    def apply(node: Any, prefix: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                pointer = f"{prefix}/{key}"
                if isinstance(value, dict):
                    apply(value, pointer)
                else:
                    _fill(data, pointer, value)
        else:
            raise ImportError("Generated projection must be an object")

    apply(result.values, "")
    if result.underivable:
        raise ImportError("Unresolved owner inputs cannot become a complete instance")
    return canonical_instance_bytes(parse_instance(canonical_bytes(data) + b"\n"))

"""Static migration import; configuration files are never executed or sourced.

A manifest references canonical JSON policy fragments or literal assignment
files. Explicit mappings fill placeholders; conflicting authors are rejected.
Any shell expansion or unsupported expression is an underivable value.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .codec import MAX_JSON_BYTES, read_bounded_file, strict_load
from .config import ConfigError, parse_config
from .model import Config


class DeriveError(ConfigError):
    """An owner input cannot be derived without execution or ambiguity."""


def literal_assignments(text: str) -> dict[str, str]:
    if len(text.encode("utf-8")) > MAX_JSON_BYTES:
        raise DeriveError("Literal owner input exceeds the byte limit")
    result: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line)
        if match is None:
            raise DeriveError(f"Underivable owner expression on line {number}")
        key, expression = match.groups()
        if key in result:
            raise DeriveError(f"Duplicate owner assignment on line {number}")
        if any(char in expression for char in ("$", "`", "\\", "\x00")):
            raise DeriveError(f"Underivable owner expression on line {number}")
        if len(expression) >= 2 and expression[0] == expression[-1] and expression[0] in "\"'":
            quote = expression[0]
            value = expression[1:-1]
            if quote in value:
                raise DeriveError(f"Underivable owner expression on line {number}")
        elif re.fullmatch(r"[A-Za-z0-9:/._-]+", expression):
            value = expression
        else:
            raise DeriveError(f"Underivable owner expression on line {number}")
        result[key] = value
    return result


def _merge(target: dict[str, Any], fragment: dict[str, Any]) -> None:
    for key, value in fragment.items():
        if key not in target or target[key] is None:
            target[key] = value
        elif isinstance(target[key], dict) and isinstance(value, dict):
            _merge(target[key], value)
        else:
            raise DeriveError("Conflicting JSON owner fields; each setting needs one author")


def _fill_pointer(data: dict[str, Any], pointer: str, value: str) -> None:
    if not pointer.startswith("/") or pointer == "/" or "~" in pointer:
        raise DeriveError("Mapping must be a nonempty simple JSON pointer")
    parts = pointer[1:].split("/")
    if any(not part for part in parts):
        raise DeriveError("Mapping contains an empty JSON pointer segment")
    node: Any = data
    for part in parts[:-1]:
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdecimal() and int(part) < len(node):
            node = node[int(part)]
        else:
            raise DeriveError("Mapping container is missing")
    last = parts[-1]
    if isinstance(node, dict):
        if last in node and node[last] is not None:
            raise DeriveError("Mapping would overwrite an authored value")
        node[last] = value
    elif isinstance(node, list) and last.isdecimal() and int(last) < len(node):
        if node[int(last)] is not None:
            raise DeriveError("Mapping would overwrite an authored value")
        node[int(last)] = value
    else:
        raise DeriveError("Mapping target is unavailable")


def derive(source: str | Path) -> Config:
    source_path = Path(source)
    manifest = strict_load(source_path)
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "sources"}:
        raise DeriveError("Derivation manifest has unsupported fields")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise DeriveError("Unsupported derivation manifest version")
    entries = manifest["sources"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 128:
        raise DeriveError("Derivation manifest requires a bounded source list")
    data: dict[str, Any] = {}
    mappings: list[tuple[dict[str, str], dict[str, str]]] = []
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not {"path", "format"} <= set(entry)
            or not set(entry) <= {"path", "format", "mapping"}
        ):
            raise DeriveError("Derivation source has unsupported fields")
        path_value = entry["path"]
        if (
            not isinstance(path_value, str)
            or not path_value
            or len(path_value) > 4096
            or "\x00" in path_value
        ):
            raise DeriveError("Invalid derivation source path")
        path = Path(path_value)
        if not path.is_absolute():
            path = source_path.parent / path
        if entry["format"] == "json":
            if "mapping" in entry:
                raise DeriveError("JSON fragments do not accept literal mappings")
            fragment = strict_load(path)
            if not isinstance(fragment, dict):
                raise DeriveError("JSON owner source must be an object")
            _merge(data, fragment)
        elif entry["format"] == "literal-env":
            mapping = entry.get("mapping")
            if (
                not isinstance(mapping, dict)
                or not mapping
                or len(mapping) > 1024
                or any(
                    not isinstance(key, str) or not isinstance(pointer, str)
                    for key, pointer in mapping.items()
                )
            ):
                raise DeriveError("Literal owner source requires a closed key-to-pointer mapping")
            raw = read_bounded_file(path)
            if len(raw) > MAX_JSON_BYTES:
                raise DeriveError("Literal owner input exceeds the byte limit")
            try:
                assignments = literal_assignments(raw.decode("utf-8", "strict"))
            except UnicodeError as exc:
                raise DeriveError("Malformed literal owner text") from exc
            if any(key not in assignments for key in mapping):
                raise DeriveError("Mapped owner key is missing")
            mappings.append((assignments, mapping))
        else:
            raise DeriveError("Unsupported static owner input format")
    for assignments, mapping in mappings:
        for key, pointer in mapping.items():
            _fill_pointer(data, pointer, assignments[key])
    return parse_config(json.dumps(data))


derive_config = derive

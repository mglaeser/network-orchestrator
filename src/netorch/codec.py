"""Bounded strict JSON parsing and deterministic content digests.

No parser silently keeps the last duplicate key, accepts NaN or invokes a remote
resolver. Canonical output is this package's versioned digest representation,
not a claim of RFC 8785 conformance.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 50_000
MAX_STRING_LENGTH = 65_536


class CodecError(ValueError):
    """Input cannot be accepted as bounded, deterministic JSON."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CodecError("Duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise CodecError("Nonfinite JSON numbers are forbidden")


def _parse_integer(token: str) -> int:
    # A 256-bit magnitude has at most 78 decimal digits. Refuse longer tokens
    # before integer conversion, independently of Python's optional digit cap.
    # The tree check still enforces the exact bit bound for a 78-digit value.
    if len(token.removeprefix("-")) > 78:
        raise CodecError("JSON integer exceeds the limit")
    return int(token)


def _scan_depth(text: str, maximum: int) -> None:
    """Bound structural depth before the recursive stdlib decoder runs."""
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > maximum:
                raise CodecError("JSON nesting exceeds the limit")
        elif char in "]}":
            depth -= 1


def _validate_tree(value: Any, maximum_depth: int = MAX_JSON_DEPTH) -> None:
    count = 0
    stack = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_JSON_NODES or depth > maximum_depth:
            raise CodecError("JSON structure exceeds the limit")
        if node is None or isinstance(node, bool):
            continue
        if isinstance(node, str):
            if len(node) > MAX_STRING_LENGTH:
                raise CodecError("JSON string exceeds the limit")
            try:
                node.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise CodecError("JSON strings must be valid Unicode") from exc
        elif isinstance(node, int):
            if node.bit_length() > 256:
                raise CodecError("JSON integer exceeds the limit")
        elif isinstance(node, float):
            if not math.isfinite(node):
                raise CodecError("Nonfinite JSON numbers are forbidden")
        elif isinstance(node, dict):
            if any(not isinstance(key, str) for key in node):
                raise CodecError("JSON object keys must be strings")
            stack.extend((key, depth + 1) for key in node)
            stack.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, (list, tuple)):
            stack.extend((item, depth + 1) for item in node)
        else:
            raise CodecError("Unsupported value in JSON structure")


def strict_loads(
    text: str | bytes, *, max_bytes: int = MAX_JSON_BYTES, max_depth: int = MAX_JSON_DEPTH
) -> Any:
    if type(max_bytes) is not int or type(max_depth) is not int or max_bytes < 1 or max_depth < 1:
        raise CodecError("JSON limits must be positive integers")
    if not isinstance(text, (str, bytes)):
        raise CodecError("JSON input must be text or bytes")
    try:
        raw = text if isinstance(text, bytes) else text.encode("utf-8", "strict")
        if len(raw) > max_bytes:
            raise CodecError("JSON input exceeds the byte limit")
        decoded = raw.decode("utf-8", "strict")
        _scan_depth(decoded, max_depth)
        value = json.loads(
            decoded,
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
            parse_int=_parse_integer,
        )
        _validate_tree(value, max_depth)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CodecError("Malformed JSON input") from exc


def read_bounded_file(path: str | Path, *, maximum: int = MAX_JSON_BYTES) -> bytes:
    """Read at most limit + 1 bytes from regular data; callers reject overflow.

    Open nonblocking before inspecting the descriptor: opening a FIFO for read
    otherwise waits for a writer before its nonregular type can be rejected.
    Symlink behavior matches the original general data reader; protected owner
    readers separately enforce O_NOFOLLOW, metadata and authority boundaries.
    """
    if type(maximum) is not int or maximum < 1:
        raise CodecError("File read limit must be positive")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise CodecError("Input must be a regular file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            return stream.read(maximum + 1)
    finally:
        os.close(fd)


def strict_load(path: str | Path) -> Any:
    return strict_loads(read_bounded_file(path))


def canonical_json(value: Any) -> str:
    if is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    _validate_tree(value)
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
        raise CodecError("Canonical JSON exceeds the byte limit")
    return encoded


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()

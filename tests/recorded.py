"""Offline replay of reviewed native recordings; provenance is not authentication.

Fixtures contain sanitized observations, never commands to execute. Loading one
does not confer native acceptance or change any production activation gate.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netorch.codec import CodecError, read_bounded_file, strict_loads

ROOT = Path(__file__).parent / "recordings"
_ID = re.compile(r"[a-z][a-z0-9-]{0,95}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
# The pytest audit hook records actual loads, including those in setup/teardown.
# A load is traceability only: it does not prove that an assertion used the bytes.
CURRENT_TEST: ContextVar[str | None] = ContextVar("recording_test", default=None)
USAGE: dict[str, set[tuple[str, str]]] = {}


class RecordingError(ValueError):
    """A fixture is malformed or no longer matches its reviewed bytes."""


@dataclass(frozen=True)
class Recording:
    id: str
    component: str
    source: dict[str, Any]
    status: str
    returncode: int | None
    stdout: bytes
    stderr: bytes


def _object(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RecordingError("unsupported recording structure")
    return value


def _text(value: Any, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise RecordingError("invalid recording metadata")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise RecordingError("invalid recording metadata")
    return value


def _descriptions(value: Any, *, required: bool = True) -> list[str]:
    if not isinstance(value, list) or not (int(required) <= len(value) <= 64):
        raise RecordingError("missing bounded recording explanation")
    return [_text(item, 2048) for item in value]


def _payload(value: Any) -> bytes:
    # Native tables can exceed the codec's per-string bound. Explicit ordered
    # chunks retain every byte without weakening that production JSON bound.
    if isinstance(value, str):
        text = value
    elif (
        isinstance(value, list)
        and 1 <= len(value) <= 64
        and all(isinstance(chunk, str) and chunk for chunk in value)
    ):
        text = "".join(value)
    else:
        raise RecordingError("recorded stream is not bounded UTF-8 text")
    raw = text.encode("utf-8", "strict")
    if len(raw) > 524_288:
        raise RecordingError("recorded stream exceeds its byte bound")
    return raw


def decode_recording(raw: bytes, expected_id: str) -> Recording:
    """Validate the closed envelope and every payload hash, without native I/O."""
    try:
        value = _object(
            strict_loads(raw), {"schema_version", "id", "component", "source", "result"}
        )
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise RecordingError("unsupported recording version")
        if (
            not isinstance(expected_id, str)
            or _ID.fullmatch(expected_id) is None
            or value["id"] != expected_id
        ):
            raise RecordingError("recording identity mismatch")
        component = _text(value["component"])
        source = _object(
            value["source"],
            {
                "kind",
                "captured_on",
                "capture_context",
                "os_version",
                "os_build",
                "architecture",
                "tool",
                "tool_version",
                "original_stdout_sha256",
                "original_stderr_sha256",
                "transformations",
                "limitations",
            },
        )
        if source["kind"] not in {"native-capture", "sanitized-native-capture"}:
            raise RecordingError("unsupported recording provenance")
        for field in ("capture_context", "os_version", "os_build", "architecture", "tool"):
            _text(source[field])
        if source["tool_version"] is not None:
            _text(source["tool_version"])
        date = _text(source["captured_on"], 10)
        if dt.date.fromisoformat(date).isoformat() != date:
            raise RecordingError("invalid recording date")
        for field in ("original_stdout_sha256", "original_stderr_sha256"):
            if _SHA.fullmatch(_text(source[field])) is None:
                raise RecordingError("invalid recording source digest")
        transforms = _descriptions(
            source["transformations"], required=source["kind"] == "sanitized-native-capture"
        )
        if source["kind"] == "native-capture" and transforms:
            raise RecordingError("unmodified capture cannot declare transformations")
        _descriptions(source["limitations"])
        result = _object(
            value["result"],
            {"status", "returncode", "stdout", "stderr", "stdout_sha256", "stderr_sha256"},
        )
        status = result["status"]
        code = result["returncode"]
        if status not in {"exited", "timed-out", "unavailable"}:
            raise RecordingError("unsupported recording outcome")
        if code is not None and (type(code) is not int or not -128 <= code <= 255):
            raise RecordingError("invalid recorded exit status")
        if (status == "exited") != (code is not None):
            raise RecordingError("contradictory recorded completion")
        streams: dict[str, bytes] = {}
        for stream in ("stdout", "stderr"):
            data = _payload(result[stream])
            if hashlib.sha256(data).hexdigest() != result[stream + "_sha256"]:
                raise RecordingError("recorded payload digest mismatch")
            if source["kind"] == "native-capture" and (
                source["original_" + stream + "_sha256"] != result[stream + "_sha256"]
            ):
                raise RecordingError("unmodified capture digest mismatch")
            streams[stream] = data
        return Recording(
            expected_id, component, source, status, code, streams["stdout"], streams["stderr"]
        )
    except (CodecError, UnicodeError, TypeError, ValueError) as exc:
        if isinstance(exc, RecordingError):
            raise
        raise RecordingError("malformed recording") from None


def load_recording(category: str, identifier: str) -> Recording:
    if (
        not isinstance(category, str)
        or not isinstance(identifier, str)
        or _ID.fullmatch(category) is None
        or _ID.fullmatch(identifier) is None
    ):
        raise RecordingError("invalid recording selector")
    directory = ROOT / category
    path = directory / (identifier + ".json")
    if ROOT.is_symlink() or directory.is_symlink() or path.is_symlink():
        raise RecordingError("recording path must not be a link")
    try:
        result = decode_recording(read_bounded_file(path), identifier)
    except OSError:
        raise RecordingError("recording is unavailable") from None
    current = CURRENT_TEST.get()
    if current is not None:
        USAGE.setdefault(current, set()).add((category, identifier))
    return result


def recording_ids() -> tuple[tuple[str, str], ...]:
    return tuple(sorted((path.parent.name, path.stem) for path in ROOT.glob("*/*.json")))

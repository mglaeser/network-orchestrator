"""Replay corpus integrity and deliberately mutated metadata, never host probes."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tests import recorded
from tests.recorded import RecordingError, decode_recording, load_recording, recording_ids


@pytest.mark.parametrize("category,identifier", recording_ids())
def test_recording_has_bounded_complete_provenance_and_matching_bytes(
    category: str, identifier: str
) -> None:
    record = load_recording(category, identifier)
    assert record.id == identifier
    assert record.source["limitations"]
    assert record.source["original_stdout_sha256"]


def baseline() -> dict:
    record = load_recording("packet", "native-lan-interface")
    assert record.source["kind"] == "sanitized-native-capture"
    return json.loads((recorded.ROOT / "packet/native-lan-interface.json").read_bytes())


@pytest.mark.parametrize(
    "path,value",
    [
        (("schema_version",), True),
        (("schema_version",), 2),
        (("id",), "different"),
        (("source", "kind"), "invented"),
        (("source", "kind"), []),
        (("source", "captured_on"), "2026-02-30"),
        (("source", "captured_on"), "20261009"),
        (("source", "capture_context"), ""),
        (("source", "tool"), "line\nbreak"),
        (("source", "tool_version"), 1),
        (("source", "transformations"), []),
        (("source", "limitations"), []),
        (("source", "original_stdout_sha256"), "invalid"),
        (("result", "status"), "success"),
        (("result", "returncode"), True),
        (("result", "returncode"), None),
        (("result", "returncode"), 256),
        (("result", "stdout"), "corrupted"),
        (("result", "stderr"), "unexpected warning"),
        (("result", "stdout_sha256"), "0" * 64),
        (("result", "stdout"), []),
    ],
)
def test_mutated_recording_cannot_pass_as_reviewed_native_bytes(path: tuple, value: object) -> None:
    data = baseline()
    target = data
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises(RecordingError):
        decode_recording(json.dumps(data).encode(), "native-lan-interface")


def test_sanitized_recording_cannot_relabel_itself_unmodified() -> None:
    data = baseline()
    data["source"]["kind"] = "native-capture"
    with pytest.raises(RecordingError):
        decode_recording(json.dumps(data).encode(), "native-lan-interface")
    data["source"]["transformations"] = []
    with pytest.raises(RecordingError):
        decode_recording(json.dumps(data).encode(), "native-lan-interface")


@pytest.mark.parametrize("section", [None, "source", "result"])
def test_unreviewed_metadata_is_not_silently_ignored(section: str | None) -> None:
    data = baseline()
    (data if section is None else data[section])["future"] = "value"
    with pytest.raises(RecordingError):
        decode_recording(json.dumps(data).encode(), "native-lan-interface")


def test_duplicate_json_member_cannot_replace_a_payload() -> None:
    data = baseline()
    raw = (
        json.dumps(data)
        .encode()
        .replace(b'"schema_version": 1', b'"schema_version": 2,"schema_version": 1')
    )
    with pytest.raises(RecordingError):
        decode_recording(raw, "native-lan-interface")


@pytest.mark.parametrize(
    "category,identifier",
    [("../packet", "native-lan-interface"), ("packet", "../other"), ("packet", "/absolute")],
)
def test_recording_selectors_cannot_escape_the_corpus(category: str, identifier: str) -> None:
    with pytest.raises(RecordingError):
        load_recording(category, identifier)


def test_recording_link_is_refused_before_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = baseline()
    directory = tmp_path / "packet"
    directory.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(copy.deepcopy(data)))
    (directory / "native-lan-interface.json").symlink_to(outside)
    monkeypatch.setattr(recorded, "ROOT", tmp_path)
    with pytest.raises(RecordingError, match="link"):
        load_recording("packet", "native-lan-interface")


def test_payload_chunks_preserve_bytes_and_order() -> None:
    data = baseline()
    original = data["result"]["stdout"]
    midpoint = len(original) // 2
    data["result"]["stdout"] = [original[:midpoint], original[midpoint:]]
    record = decode_recording(json.dumps(data).encode(), "native-lan-interface")
    assert record.stdout == original.encode()
    data["result"]["stdout"].reverse()
    with pytest.raises(RecordingError, match="digest"):
        decode_recording(json.dumps(data).encode(), "native-lan-interface")


@pytest.mark.parametrize("chunks", [[""], ["a", 3], ["a"] * 65, ["a" * 50_000] * 11])
def test_chunks_cannot_evade_stream_type_or_size_bounds(chunks: list) -> None:
    data = baseline()
    data["result"]["stdout"] = chunks
    with pytest.raises(RecordingError):
        decode_recording(json.dumps(data).encode(), "native-lan-interface")

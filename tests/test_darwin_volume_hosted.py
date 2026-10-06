"""Hosted macOS userspace contract of the volume identity provider.

These tests make the real `fgetattrlist` call, so they run on a Darwin host only
and are skipped everywhere else. They are read-only and unprivileged and touch
nothing outside `tmp_path`. A pass is evidence for the runner image that ran
them; it qualifies no production macOS build.
"""

from __future__ import annotations

import ctypes
import os
import plistlib
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from netorch import darwin_volume
from netorch.darwin_volume import volume_uuid

HOSTED = "hosted macOS userspace contract"
LOWER_CASE_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
# What the reader opens an enrolled directory or file with.
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def _volume(path: str | Path, extra: int = 0) -> str:
    fd = os.open(path, FLAGS | extra)
    try:
        return volume_uuid(fd)
    finally:
        os.close(fd)


def _recorded(capsys: Any, title: str, seen: str) -> None:
    """On the hosted runner, keep what was observed as a notice of the job."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        text = seen.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        # Capture is lifted for one line of its own: the runner reads commands at line starts.
        with capsys.disabled():
            print(f"\n::notice title={title}::{text}")


def _raw_answer(fd: int) -> str:
    """The call's own answer to the production request, for the record of a failure."""
    reply = ctypes.create_string_buffer(darwin_volume.REPLY_BYTES)
    status = ctypes.CDLL(None, use_errno=True).fgetattrlist(
        ctypes.c_int(fd),
        darwin_volume.REQUEST,
        reply,
        ctypes.c_size_t(darwin_volume.REPLY_BYTES),
        ctypes.c_uint(darwin_volume.OPTIONS),
    )
    return f"status {status}, errno {ctypes.get_errno()}, reply {reply.raw.hex()}"


def _raw_answer_at(path: str | Path, extra: int = 0) -> str:
    try:
        fd = os.open(path, FLAGS | extra)
    except OSError as exc:
        return f"open failed with errno {exc.errno}"
    try:
        return _raw_answer(fd)
    finally:
        os.close(fd)


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason=HOSTED)
def test_directory_and_file_report_one_lower_case_identifier(tmp_path: Path, capsys: Any) -> None:
    directory = tmp_path / "data"
    directory.mkdir()
    file = directory / "receipt"
    file.write_bytes(b"content")
    try:
        first = _volume(directory, os.O_DIRECTORY)
        assert LOWER_CASE_UUID.fullmatch(first), "the identifier is not a lower-case UUID"
        assert first != "00000000-0000-0000-0000-000000000000", "the identifier is all zero"
        assert _volume(directory, os.O_DIRECTORY) == first, "two calls on one directory disagree"
        assert _volume(file) == first, "a file is reported on another volume than its directory"
    except (OSError, ValueError, AssertionError) as failure:
        seen = f"{type(failure).__name__}: {failure}"
        answers = (
            f"directory {_raw_answer_at(directory, os.O_DIRECTORY)}; file {_raw_answer_at(file)}"
        )
        _recorded(capsys, "volume identifier", f"{seen}; {answers}")
        raise
    _recorded(capsys, "volume identifier", "a directory and a file in it name one lower-case UUID")


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason=HOSTED)
def test_identifier_is_the_one_diskutil_reports_for_the_data_volume(capsys: Any) -> None:
    mount_point = "/System/Volumes/Data"
    described = subprocess.run(
        ["/usr/sbin/diskutil", "info", "-plist", mount_point],
        capture_output=True,
        timeout=10,
        check=False,
    )
    try:
        observed = _volume(mount_point, os.O_DIRECTORY)
        assert described.returncode == 0, "diskutil did not describe the data volume"
        document = plistlib.loads(described.stdout)
        # A missing key is a failure of this cross-check, never a reason to skip it.
        assert "VolumeUUID" in document, "diskutil names no VolumeUUID for the data volume"
        assert isinstance(document["VolumeUUID"], str), "diskutil's VolumeUUID is not text"
        assert observed == document["VolumeUUID"].lower(), "the two sources name different volumes"
    except (OSError, ValueError, AssertionError) as failure:
        seen = f"{type(failure).__name__}: {failure}; diskutil status {described.returncode}"
        _recorded(
            capsys,
            "data volume",
            f"{seen}, {len(described.stdout)} bytes; {_raw_answer_at(mount_point, os.O_DIRECTORY)}",
        )
        raise
    _recorded(capsys, "data volume", "the identifier equals diskutil's VolumeUUID")


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason=HOSTED)
def test_descriptor_that_is_not_a_file_or_directory_is_refused(capsys: Any) -> None:
    read_end, write_end = os.pipe()
    try:
        # A failed call is an OSError; a pipe has no volume and must not decode.
        try:
            answer: str | None = volume_uuid(read_end)
        except OSError as refusal:
            answer = None
            _recorded(capsys, "pipe", f"refused with errno {refusal.errno}")
        except ValueError as refusal:
            _recorded(capsys, "pipe", f"ValueError: {refusal}; {_raw_answer(read_end)}")
            raise
        else:
            _recorded(capsys, "pipe", f"answered; {_raw_answer(read_end)}")
        assert answer is None, "a pipe was given a volume identifier"
    finally:
        os.close(read_end)
        os.close(write_end)

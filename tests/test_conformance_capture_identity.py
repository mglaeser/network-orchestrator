"""Conformance roles refer to the files read, across the entire manifest."""

from __future__ import annotations

import json

import pytest

from netorch import conformance
from netorch.conformance import ConformanceError, compare_artifacts
from tests.test_conformance_aliasing import CAPTURED, manifest


def test_captures_cannot_serve_as_other_artifacts_rendered_output(tmp_path):
    path = manifest(tmp_path)
    data = json.loads(path.read_text())
    data["artifacts"].append({"id": "second-input", "captured": "rendered", "rendered": "captured"})
    path.write_text(json.dumps(data))
    with pytest.raises(ConformanceError, match="different files"):
        compare_artifacts(path)


def test_parent_link_replacement_cannot_change_the_identity_of_a_completed_capture(
    tmp_path, monkeypatch
):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (second / "captured").write_bytes(CAPTURED)
    link = tmp_path / "link"
    link.symlink_to(first, target_is_directory=True)
    path = manifest(first, rendered="../link/captured")
    # Real filesystem replacement at the boundary after a successful bounded
    # read. The bytes and descriptor metadata are never supplied by a mock.
    reader = conformance.capture_static

    def replace_parent_after_read(path, **kwargs):
        captured = reader(path, **kwargs)
        if "link" in path.parts:
            link.unlink()
            link.symlink_to(second, target_is_directory=True)
        return captured

    monkeypatch.setattr(conformance, "capture_static", replace_parent_after_read)
    with pytest.raises(ConformanceError, match="different files"):
        compare_artifacts(path)

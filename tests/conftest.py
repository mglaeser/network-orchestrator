"""Optional test-evidence audit output; no native collection or test selection."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from netorch.legacy_import import read_static
from netorch.privacy_check import git_candidates
from tests.recorded import CURRENT_TEST, ROOT, USAGE, recording_ids

_NODES: dict[str, dict[str, Any]] = {}
_SOURCE_START: dict[str, str | None] = {}
REPOSITORY = Path(__file__).resolve().parents[1]


def source_snapshot() -> dict[str, str | None]:
    result = {}
    for name in git_candidates(REPOSITORY):
        path = REPOSITORY / name
        if path.is_symlink():
            raise ValueError("evidence inventory refuses linked sources")
        if not path.exists():
            result[name] = None
            continue
        result[name] = hashlib.sha256(read_static(path, limit=1024 * 1024)).hexdigest()
    return result


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--evidence-report",
        default=None,
        help="Write offline test collection/results/recording-load traceability as JSON",
    )

    parser.addoption(
        "--evidence-coverage", default=None, help="Coverage data file to hash after tests"
    )


def pytest_sessionstart(session: pytest.Session) -> None:
    _NODES.clear()
    USAGE.clear()
    _SOURCE_START.clear()
    if session.config.getoption("--evidence-report") is not None:
        _SOURCE_START.update(source_snapshot())


def pytest_collection_finish(session: pytest.Session) -> None:
    for item in session.items:
        _NODES[item.nodeid] = {
            "source": item.location[0],
            "line": item.location[1] + 1,
            "markers": sorted({marker.name for marker in item.iter_markers()}),
            "fixtures": sorted(item.fixturenames),
            "outcomes": {},
        }


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item: pytest.Item, nextitem: pytest.Item | None) -> Iterator[None]:
    token = CURRENT_TEST.set(item.nodeid)
    try:
        yield
    finally:
        CURRENT_TEST.reset(token)


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.nodeid in _NODES:
        _NODES[report.nodeid]["outcomes"][report.when] = report.outcome


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    destination = session.config.getoption("--evidence-report")
    if destination is None:
        return
    for nodeid, row in _NODES.items():
        row["recording_loads"] = ["/".join(pair) for pair in sorted(USAGE.get(nodeid, set()))]
        row["recorded_input_observed"] = bool(row["recording_loads"])
    recordings = {
        f"{category}/{identifier}": hashlib.sha256(
            (ROOT / category / (identifier + ".json")).read_bytes()
        ).hexdigest()
        for category, identifier in recording_ids()
    }
    source_end = source_snapshot()
    coverage_path = session.config.getoption("--evidence-coverage")
    coverage_hash = None
    if (
        coverage_path is not None
        and session.config.getoption("--cov", default=None)
        and Path(coverage_path).is_file()
    ):
        with Path(coverage_path).open("rb") as stream:
            coverage_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    result = {
        "schema_version": 1,
        "sources_start": _SOURCE_START,
        "sources_end": source_end,
        "sources_changed": sorted(
            name
            for name in set(_SOURCE_START) | set(source_end)
            if _SOURCE_START.get(name) != source_end.get(name)
        ),
        "coverage_file_sha256": coverage_hash,
        "exitstatus": int(exitstatus),
        "collected": len(_NODES),
        "tests_with_recording_loads": sum(bool(row["recording_loads"]) for row in _NODES.values()),
        "recording_files": recordings,
        "tests": dict(sorted(_NODES.items())),
        "limitations": [
            "A recorded load does not prove assertion relevance or native acceptance.",
            "Tests with no recorded load remain explicit; no universal production claim is made.",
            "Mocked faults and mutations are not observations of production failures.",
            "Loads in fresh threads/subprocesses and cached later fixture uses are not traced.",
        ],
    }
    Path(destination).write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")

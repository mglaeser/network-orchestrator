"""Test the audit mechanism itself; recording loads are traceability, not proof."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import coverage
import pytest

from tools.test_inventory import inventory, python_structure, repository_files

ROOT = Path(__file__).resolve().parents[1]


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, timeout=10)


def test_inventory_includes_untracked_and_deleted_but_excludes_ignored(tmp_path: Path) -> None:
    git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("ignored\n")
    (tmp_path / "tracked").write_text("old")
    git(tmp_path, "add", "tracked")
    (tmp_path / "tracked").unlink()
    (tmp_path / "new").write_text("new")
    (tmp_path / "ignored").write_text("private")
    assert [p.name for p in repository_files(tmp_path)] == [".gitignore", "new", "tracked"]
    report = inventory(tmp_path, {"schema_version": 1, "tests": {}}, None)
    assert report["files"][-1] == {"path": "tracked", "state": "deleted"}


@pytest.mark.parametrize("target_exists", [True, False])
def test_inventory_refuses_even_a_dangling_symlink(tmp_path: Path, target_exists: bool) -> None:
    git(tmp_path, "init", "-q")
    if target_exists:
        (tmp_path / "target").write_text("content")
    (tmp_path / "link").symlink_to(tmp_path / "target")
    with pytest.raises(ValueError, match="linked"):
        repository_files(tmp_path)


def test_ast_inventory_covers_nested_async_lambdas_and_comments_without_import() -> None:
    raw = b'''"""Module contract."""
# deliberate comment
class Owner:
    """Class contract."""
    async def run(self):
        """Function contract."""
        def nested():
            return 9
        value = lambda: 4
        return nested(), value()
raise RuntimeError("must never be executed")
'''
    functions, comments, docs = python_structure(raw)
    assert {f["name"] for f in functions} == {
        "Owner.run",
        "Owner.run.nested",
        "Owner.run.<lambda@9>",
    }
    parent = functions[0]
    assert parent["async"] is True
    assert 8 in parent["excluded_nested_lines"]
    assert comments == [2]
    assert {d["scope"] for d in docs} == {"<module>", "Owner", "Owner.run"}
    assert all(len(d["sha256"]) == 64 for d in docs)


def test_execution_contexts_are_attached_to_owned_body_not_nested_bodies(tmp_path: Path) -> None:
    git(tmp_path, "init", "-q")
    source = tmp_path / "sample.py"
    source.write_text(
        "def outer():\n    def inner():\n        return 3\n    return inner\n"
        "def unused():\n    return 99\n"
    )
    cov = coverage.Coverage(data_file=str(tmp_path / "data"), config_file=False)
    cov.start()
    cov.switch_context("tests/test_sample.py::test_outer|run")
    scope: dict = {}
    exec(compile(source.read_text(), str(source), "exec"), scope)
    inner = scope["outer"]()
    cov.switch_context("tests/test_sample.py::test_inner|run")
    assert inner() == 3
    cov.stop()
    cov.save()
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    evidence = {
        "sources_start": {"sample.py": source_hash},
        "sources_end": {"sample.py": source_hash},
        "coverage_file_sha256": hashlib.sha256(
            Path(cov.get_data().data_filename()).read_bytes()
        ).hexdigest(),
        "schema_version": 1,
        "tests": {
            "tests/test_sample.py::test_outer": {"recording_loads": []},
            "tests/test_sample.py::test_inner": {"recording_loads": ["synthetic/control"]},
        },
    }
    result = inventory(tmp_path, evidence, cov)
    source_row = next(row for row in result["files"] if row["path"] == "sample.py")
    functions = {f["name"]: f for f in source_row["functions"]}
    indices = {name: i for i, name in enumerate(result["test_index"])}
    assert functions["outer"]["test_indices"] == [indices["tests/test_sample.py::test_outer"]]
    assert functions["outer.inner"]["test_indices"] == [indices["tests/test_sample.py::test_inner"]]
    assert functions["unused"]["test_indices"] == []
    assert functions["unused"]["missing_statement_lines"] == [6]
    assert functions["outer"]["recorded_test_indices"] == []
    assert functions["outer.inner"]["recorded_test_indices"] == [0]
    # The controlled test name above is not a genuine production claim.
    assert any("does not establish" in item for item in result["limitations"])
    assert result["coverage_binding_failures"] == []
    source.write_text(source.read_text().replace("return 99", "raise RuntimeError(99)"))
    stale = inventory(tmp_path, evidence, cov)
    row = next(row for row in stale["files"] if row["path"] == "sample.py")
    assert stale["coverage_binding_failures"] == ["sample.py"]
    assert row["coverage_measured"] is False
    assert all(not function["test_indices"] for function in row["functions"])


def test_pytest_report_observes_setup_loads_failures_and_missing_recordings(tmp_path: Path) -> None:
    sample = tmp_path / "test_probe.py"
    sample.write_text(
        "import pytest\nfrom tests.recorded import load_recording\n"
        "@pytest.fixture\ndef native():\n"
        "    return load_recording('packet', 'native-lan-interface')\n"
        "def test_recorded(native):\n    assert native.stdout\n"
        "def test_synthetic():\n    assert 1 + 1 == 2\n"
        "def test_failure():\n    assert False, 'controlled failure'\n"
    )
    destination = tmp_path / "evidence.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--noconftest",
            "-p",
            "tests.conftest",
            "-o",
            "addopts=",
            str(sample),
            f"--evidence-report={destination}",
        ],
        cwd=ROOT,
        env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 1, result.stdout.decode()
    data = json.loads(destination.read_bytes())
    assert data["collected"] == 3 and data["tests_with_recording_loads"] == 1
    assert data["sources_start"] == data["sources_end"]
    assert data["sources_changed"] == []
    assert data["coverage_file_sha256"] is None
    tests = {name.rsplit("::", 1)[-1]: value for name, value in data["tests"].items()}
    assert tests["test_recorded"]["recording_loads"] == ["packet/native-lan-interface"]
    assert tests["test_synthetic"]["recorded_input_observed"] is False
    assert tests["test_failure"]["outcomes"]["call"] == "failed"
    assert len(data["recording_files"]["packet/native-lan-interface"]) == 64


@pytest.mark.parametrize(
    "child", ["    def inner(): return 3\n    return inner\n", "    return lambda: 3\n"]
)
def test_same_line_nested_bodies_are_explicitly_ambiguous(child: str) -> None:
    functions, _, _ = python_structure(("def outer():\n" + child).encode())
    parent, nested = functions
    assert parent["ambiguous_shared_lines"] == [2]
    assert nested["ambiguous_shared_lines"] == [2]


@pytest.mark.parametrize(
    "child", ["    def inner(): return 3\n    return inner\n", "    return lambda: 3\n"]
)
def test_shared_line_contexts_are_not_claimed_for_either_function(
    tmp_path: Path, child: str
) -> None:
    git(tmp_path, "init", "-q")
    source = tmp_path / "sample.py"
    source.write_text("def outer():\n" + child)
    cov = coverage.Coverage(data_file=str(tmp_path / "data"), config_file=False)
    cov.start()
    scope: dict = {}
    cov.switch_context("tests/probe.py::parent|run")
    exec(compile(source.read_text(), str(source), "exec"), scope)
    inner = scope["outer"]()
    cov.switch_context("tests/probe.py::child|run")
    assert inner() == 3
    cov.stop()
    cov.save()
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    evidence = {
        "schema_version": 1,
        "sources_start": {"sample.py": digest},
        "sources_end": {"sample.py": digest},
        "coverage_file_sha256": hashlib.sha256(
            Path(cov.get_data().data_filename()).read_bytes()
        ).hexdigest(),
        "tests": {
            name: {"recording_loads": []}
            for name in ("tests/probe.py::parent", "tests/probe.py::child")
        },
    }
    report = inventory(tmp_path, evidence, cov)
    row = next(row for row in report["files"] if row["path"] == "sample.py")
    parent, child_row = row["functions"]
    assert child_row["test_indices"] == []
    assert all("::child" not in report["test_index"][index] for index in parent["test_indices"])
    assert all(2 not in function["statement_lines"] for function in row["functions"])
    assert all(function["ambiguous_shared_lines"] == [2] for function in row["functions"])
    evidence["coverage_file_sha256"] = "0" * 64
    refused = inventory(tmp_path, evidence, cov)
    assert refused["coverage_binding_failures"] == ["sample.py"]
    assert refused["coverage_file_bound"] is False


@pytest.mark.parametrize("foreign_only", [False, True])
def test_cli_cannot_pass_bound_but_unmapped_coverage(tmp_path: Path, foreign_only: bool) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    source = (tmp_path if foreign_only else root) / "sample.py"
    source.write_text("def probe():\n    return 3\n")
    covpath = tmp_path / "coverage-data"
    cov = coverage.Coverage(data_file=str(covpath), config_file=False)
    cov.start()
    scope: dict = {}
    exec(compile(source.read_text(), str(source), "exec"), scope)
    assert scope["probe"]() == 3
    cov.stop()
    cov.save()
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    evidence = {
        "schema_version": 1,
        "sources_start": {"sample.py": digest},
        "sources_end": {"sample.py": digest},
        "tests": {"tests/probe.py::probe": {"recording_loads": []}},
        "coverage_file_sha256": hashlib.sha256(covpath.read_bytes()).hexdigest(),
    }
    saved = tmp_path / "evidence.json"
    saved.write_text(json.dumps(evidence))
    output = tmp_path / "report.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/test_inventory.py"),
            "--root",
            str(root),
            "--evidence",
            str(saved),
            "--coverage",
            str(covpath),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 1, result.stderr.decode()
    report = json.loads(output.read_bytes())
    assert report["matched_test_context_count"] == 0
    assert report["measured_repository_files"] == (0 if foreign_only else 1)


def test_tracked_fifo_is_refused_by_session_snapshot_without_waiting(tmp_path: Path) -> None:
    git(tmp_path, "init", "-q")
    path = tmp_path / "tracked"
    path.write_text("regular")
    git(tmp_path, "add", "tracked")
    path.unlink()
    os.mkfifo(path)
    script = (
        "from pathlib import Path; from tests import conftest; "
        "conftest.REPOSITORY=Path(__import__('sys').argv[1]); "
        "conftest.source_snapshot()"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        cwd=ROOT,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode != 0
    assert b"ImportError" in result.stderr


def test_import_execution_never_claims_an_uncalled_one_line_body(tmp_path: Path) -> None:
    git(tmp_path, "init", "-q")
    source = tmp_path / "sample.py"
    source.write_text("def unused(): return 99\nvalue = lambda: 42\n")
    cov = coverage.Coverage(data_file=str(tmp_path / "data"), config_file=False)
    cov.start()
    cov.switch_context("tests/probe.py::import_only|run")
    exec(compile(source.read_text(), str(source), "exec"), {})
    cov.stop()
    cov.save()
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    evidence = {
        "schema_version": 1,
        "sources_start": {"sample.py": digest},
        "sources_end": {"sample.py": digest},
        "coverage_file_sha256": hashlib.sha256(
            Path(cov.get_data().data_filename()).read_bytes()
        ).hexdigest(),
        "tests": {"tests/probe.py::import_only": {"recording_loads": []}},
    }
    report = inventory(tmp_path, evidence, cov)
    row = next(row for row in report["files"] if row["path"] == "sample.py")
    assert all(function["test_indices"] == [] for function in row["functions"])
    assert [function["ambiguous_shared_lines"] for function in row["functions"]] == [[1], [2]]


def test_later_generator_iteration_is_not_attributed_to_its_factory(tmp_path: Path) -> None:
    git(tmp_path, "init", "-q")
    source = tmp_path / "sample.py"
    source.write_text("def make():\n    return (x + 1 for x in (1, 2))\n")
    cov = coverage.Coverage(data_file=str(tmp_path / "data"), config_file=False)
    cov.start()
    cov.switch_context("tests/probe.py::create|run")
    scope: dict = {}
    exec(compile(source.read_text(), str(source), "exec"), scope)
    generator = scope["make"]()
    cov.switch_context("tests/probe.py::iterate|run")
    assert list(generator) == [2, 3]
    cov.stop()
    cov.save()
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    evidence = {
        "schema_version": 1,
        "sources_start": {"sample.py": digest},
        "sources_end": {"sample.py": digest},
        "coverage_file_sha256": hashlib.sha256(
            Path(cov.get_data().data_filename()).read_bytes()
        ).hexdigest(),
        "tests": {
            name: {"recording_loads": []}
            for name in ("tests/probe.py::create", "tests/probe.py::iterate")
        },
    }
    report = inventory(tmp_path, evidence, cov)
    row = next(row for row in report["files"] if row["path"] == "sample.py")
    assert row["functions"][0]["test_indices"] == []
    assert row["functions"][0]["ambiguous_shared_lines"] == [2]

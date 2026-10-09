"""Offline source/function/comment inventory joined to pytest/coverage evidence.

Run after pytest. It never imports inventoried code, contacts a host, or treats
line execution or a recording load as proof of a correct assertion.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import tokenize
from pathlib import Path
from typing import Any

import coverage

from netorch.legacy_import import read_static
from netorch.privacy_check import git_candidates

MAX_FILE_BYTES = 1024 * 1024


def repository_files(root: Path) -> list[Path]:
    names = git_candidates(root)
    paths = []
    for name in names:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("repository inventory contains an unsafe path")
        path = root / relative
        if path.is_symlink():
            raise ValueError("inventory refuses linked source paths")
        if not path.exists():
            # A tracked deletion is still represented; never read the index copy.
            paths.append(path)
            continue
        if any(part.is_symlink() for part in (path, *path.parents) if part != root.parent):
            raise ValueError("inventory refuses linked source paths")
        if not path.is_file():
            raise ValueError("inventory needs regular source files")
        paths.append(path)
    return paths


def python_structure(raw: bytes) -> tuple[list[dict[str, Any]], list[int], list[dict[str, Any]]]:
    """Describe every definition and comment without executing the source."""
    tree = ast.parse(raw)
    functions: list[dict[str, Any]] = []
    documentation: list[dict[str, Any]] = []

    def visit(node: ast.AST, prefix: str = "") -> None:
        current = prefix
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            current = f"{prefix}.{node.name}" if prefix else node.name
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc is not None:
                expression = node.body[0]
                documentation.append(
                    {
                        "scope": current or "<module>",
                        "line": expression.lineno,
                        "end_line": expression.end_lineno,
                        "sha256": hashlib.sha256(doc.encode()).hexdigest(),
                    }
                )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            name = (
                current if not isinstance(node, ast.Lambda) else f"{prefix}.<lambda@{node.lineno}>"
            )
            # A parent's coverage must not absorb statements in nested scopes.
            excluded: set[int] = set()
            deferred: set[int] = set()
            for child in ast.walk(node):
                if isinstance(child, ast.GeneratorExp):
                    deferred.update(range(child.lineno, (child.end_lineno or child.lineno) + 1))
                if child is not node and isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
                ):
                    # Defining a nested function is a statement of its parent;
                    # executing the child's body is not.
                    excluded.update(range(child.lineno + 1, (child.end_lineno or child.lineno) + 1))
            functions.append(
                {
                    "name": name,
                    "line": node.lineno,
                    "end_line": node.end_lineno,
                    "async": isinstance(node, ast.AsyncFunctionDef),
                    "body_start": node.lineno
                    if isinstance(node, ast.Lambda)
                    else node.body[0].lineno,
                    "excluded_nested_lines": sorted(excluded),
                    "review_status": "execution-inventory-only",
                    "ambiguous_shared_lines": sorted(deferred),
                }
            )
        for child in ast.iter_child_nodes(node):
            visit(child, current)

    visit(tree)
    for function in functions:
        if function["body_start"] == function["line"]:
            function["ambiguous_shared_lines"].append(function["line"])
    for parent in functions:
        for child in functions:
            if child is parent:
                continue
            if (
                parent["line"] <= child["line"] <= child["end_line"] <= parent["end_line"]
                and parent["name"] != child["name"]
                and child["name"].startswith(parent["name"] + ".")
                and child["body_start"] == child["line"]
            ):
                parent["ambiguous_shared_lines"].append(child["line"])
                child["ambiguous_shared_lines"].append(child["line"])
    for function in functions:
        function["ambiguous_shared_lines"] = sorted(set(function["ambiguous_shared_lines"]))
    comments = [
        token.start[0]
        for token in tokenize.tokenize(io.BytesIO(raw).readline)
        if token.type == tokenize.COMMENT
    ]
    return functions, comments, documentation


def _test_context(context: str) -> str | None:
    # pytest-cov contexts are nodeid|setup/run/teardown. Empty/import contexts
    # cannot establish execution by a particular test.
    name, separator, phase = context.rpartition("|")
    return name if separator and phase in {"setup", "run", "teardown"} else None


def inventory(
    root: Path, evidence: dict[str, Any], cov: coverage.Coverage | None
) -> dict[str, Any]:
    if evidence.get("schema_version") != 1 or not isinstance(evidence.get("tests"), dict):
        raise ValueError("missing pytest evidence document")
    tests = evidence["tests"]
    names = sorted(tests)
    indices = {name: index for index, name in enumerate(names)}
    data = None if cov is None else cov.get_data()
    measured = set() if data is None else set(data.measured_files())
    coverage_bound = False
    if data is not None and Path(data.data_filename()).is_file():
        with Path(data.data_filename()).open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        coverage_bound = digest == evidence.get("coverage_file_sha256")
    source_start = evidence.get("sources_start", {})
    source_end = evidence.get("sources_end", {})
    binding_failures = []
    mapped_tests: set[str] = set()
    measured_repository_files = 0
    rows: list[dict[str, Any]] = []
    for path in repository_files(root):
        relative = path.relative_to(root).as_posix()
        if not path.exists():
            rows.append({"path": relative, "state": "deleted"})
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("source inventory file exceeds its bound")
        raw = read_static(path, limit=MAX_FILE_BYTES)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError("source inventory file exceeds its bound")
        row: dict[str, Any] = {
            "path": relative,
            "state": "present",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
            "review_status": "inventory-only",
        }
        if path.suffix == ".py":
            functions, comments, documentation = python_structure(raw)
            row.update(functions=functions, comment_lines=comments, docstrings=documentation)
            absolute = str(path)
            # Coverage can use relative or absolute source paths. Neither is
            # emitted; report identities always remain checkout-relative.
            key = absolute if absolute in measured else relative if relative in measured else None
            statements: set[int] = set()
            missing: set[int] = set()
            contexts: dict[int, list[str]] = {}
            source_bound = source_start.get(relative) == source_end.get(relative) == row["sha256"]
            bound = source_bound and coverage_bound
            row["coverage_source_binding"] = "matched" if bound else "unbound-or-changed"
            if key is not None and not bound:
                binding_failures.append(relative)
            if key is not None and cov is not None and data is not None and bound:
                _, executable, _, missed, _ = cov.analysis2(key)
                statements, missing = set(executable), set(missed)
                contexts = data.contexts_by_lineno(key)
            row["coverage_measured"] = key is not None and bound
            measured_repository_files += int(row["coverage_measured"])
            row["missing_statement_lines"] = sorted(missing)
            for function in functions:
                owned = set(range(function.pop("body_start"), function["end_line"] + 1)) - set(
                    function.pop("excluded_nested_lines")
                )
                owned -= set(function["ambiguous_shared_lines"])
                executable = owned & statements
                observed = {
                    name
                    for line in executable
                    for context in contexts.get(line, [])
                    if (name := _test_context(context)) is not None and name in indices
                }
                mapped_tests.update(observed)
                function.update(
                    statement_lines=sorted(executable),
                    missing_statement_lines=sorted(executable & missing),
                    test_indices=sorted(indices[name] for name in observed),
                    recorded_test_indices=sorted(
                        indices[name] for name in observed if tests[name].get("recording_loads")
                    ),
                )
        elif path.suffix in {".sh", ".bash"}:
            row["comment_lines"] = [
                number
                for number, line in enumerate(raw.decode().splitlines(), 1)
                if line.lstrip().startswith("#")
            ]
            row["coverage_measured"] = False
            row["review_status"] = "shell-behavior-needs-process-contract-tests"
        rows.append(row)
    return {
        "schema_version": 1,
        "files": rows,
        "test_index": names,
        "tests_without_recording_loads": [
            index for index, name in enumerate(names) if not tests[name].get("recording_loads")
        ],
        "recording_files": evidence.get("recording_files", {}),
        "coverage_binding_failures": binding_failures,
        "measured_repository_files": measured_repository_files,
        "matched_test_context_count": len(mapped_tests),
        "coverage_file_bound": coverage_bound,
        "sources_changed_during_tests": evidence.get("sources_changed", []),
        "limitations": [
            "Coverage is execution evidence, not a proof of assertion quality or human review.",
            "Nested scopes are excluded; same-line bodies and deferred generators are ambiguous.",
            "Recording load in a test does not establish that every covered function consumed it.",
            "Shell, schema, workflow and documentation semantics require their own review.",
            "Synthetic fault cases cannot be relabelled as observed production failures.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--coverage", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    evidence = json.loads(args.evidence.read_bytes())
    cov = None
    if args.coverage is not None:
        if not args.coverage.is_file():
            parser.error("coverage data is missing")
        cov = coverage.Coverage(data_file=str(args.coverage))
        cov.load()
    result = inventory(root, evidence, cov)
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(
        json.dumps(
            {
                "files": len(result["files"]),
                "tests": len(result["test_index"]),
                "tests_without_recording_loads": len(result["tests_without_recording_loads"]),
            }
        )
    )
    return (
        1
        if (
            result["coverage_binding_failures"]
            or result["sources_changed_during_tests"]
            or (
                args.coverage is not None
                and (
                    not result["coverage_file_bound"]
                    or result["measured_repository_files"] == 0
                    or result["matched_test_context_count"] == 0
                )
            )
        )
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())

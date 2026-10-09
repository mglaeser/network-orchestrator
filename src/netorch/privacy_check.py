"""CI entry point for public and instance-to-framework static privacy guards."""

from __future__ import annotations

import argparse
import re
from collections.abc import Callable
from pathlib import Path

from .codec import canonical_json, strict_loads
from .instance import instance_to_dict, load_instance
from .legacy_import import read_static
from .privacy import Finding, PrivacyError, PrivacyException, instance_literals, scan_framework
from .process import ProcessError, Result, run


def git_candidates(root: Path, *, runner: Callable[[list[str]], Result] | None = None) -> list[str]:
    """Only tracked and nonignored candidate files, using bounded local Git metadata.

    This fixed command does not run a shell, hook, filter or network operation.
    Ignored files and tool state never enter the inventory. Tracked ignored files
    remain tracked and therefore must still be checked.
    """
    try:
        directory = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PrivacyError("Git candidate root is unavailable") from exc
    argv = [
        "/usr/bin/git",
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        str(directory),
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
    ]
    result = runner(argv) if runner else run(argv, timeout=5, max_output=4_194_304)
    if result.returncode or result.stderr or len(result.stdout) > 4_194_304:
        raise PrivacyError("Git candidate inventory is unavailable")
    try:
        raw = result.stdout.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise PrivacyError("Git candidate inventory is malformed") from exc
    if raw and not raw.endswith("\x00"):
        raise PrivacyError("Git candidate inventory is incomplete")
    names = raw[:-1].split("\x00") if raw else []
    if len(names) > 10000 or any(not name or any(ord(c) < 32 for c in name) for name in names):
        raise PrivacyError("Git candidate inventory exceeds the closed path contract")
    return sorted(set(names))


def load_exceptions(path: Path, *, scope: str) -> tuple[PrivacyException, ...]:
    if scope not in {"generic", "instance"}:
        raise PrivacyError("Unknown privacy exception scope")
    data = strict_loads(read_static(path))
    if (
        not isinstance(data, dict)
        or set(data) != {"schema_version", "exceptions"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
    ):
        raise PrivacyError("Unsupported privacy exception data")
    entries = data["exceptions"]
    if not isinstance(entries, list) or len(entries) > 256:
        raise PrivacyError("Privacy exceptions must be finite")
    values: list[PrivacyException] = []
    seen: set[tuple[str, str, str | None]] = set()
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "kind", "reason", "value_sha256"}
            or any(not isinstance(entry[k], str) for k in ("path", "kind", "reason"))
        ):
            raise PrivacyError("Unsupported privacy exception")
        sha = entry["value_sha256"]
        if sha is not None and (not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha)):
            raise PrivacyError("Invalid privacy exception digest")
        if sha is None:
            raise PrivacyError("Exact privacy exceptions require an exact value digest")
        key = (entry["path"], entry["kind"], sha)
        if key in seen:
            raise PrivacyError("Duplicate privacy exception")
        seen.add(key)
        values.append(PrivacyException(entry["path"], entry["kind"], entry["reason"], sha))
    return tuple(values)


def check(
    root: Path,
    exceptions: Path,
    *,
    instance: Path | None = None,
    instance_exceptions: Path | None = None,
    runner: Callable[[list[str]], Result] | None = None,
) -> tuple[Finding, ...]:
    files = git_candidates(root, runner=runner)
    found = list(
        scan_framework(root, files=files, exceptions=load_exceptions(exceptions, scope="generic"))
    )
    if instance is None and instance_exceptions is not None:
        raise PrivacyError("Instance exceptions require a validated instance")
    if instance is not None:
        literals = instance_literals(instance_to_dict(load_instance(instance)))
        exact = (
            load_exceptions(instance_exceptions, scope="instance") if instance_exceptions else ()
        )
        # Generic fixture exceptions cannot suppress a copied actual site value.
        found.extend(
            scan_framework(root, files=files, literals=literals, exceptions=exact, generic=False)
        )
    return tuple(
        sorted(set(found), key=lambda f: (f.path, f.line, f.column, f.kind, f.value_sha256))
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--exceptions", type=Path, required=True)
    parser.add_argument("--instance", type=Path)
    parser.add_argument("--instance-exceptions", type=Path)
    args = parser.parse_args(argv)
    try:
        findings = check(
            args.root,
            args.exceptions,
            instance=args.instance,
            instance_exceptions=args.instance_exceptions,
        )
    except (ValueError, OSError, ProcessError):
        print(canonical_json({"status": "refused", "reason": "privacy-scan-contract-refused"}))
        return 2
    print(
        canonical_json(
            {
                "status": "failed" if findings else "passed",
                "findings": [f.to_dict() for f in findings],
            }
        )
    )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

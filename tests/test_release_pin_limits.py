"""What `release_verified` establishes, and what it does not.

The field compares two files on disk and one version string with the pin. It
does not open the artifact, does not look at the installed package and does
not compare `revision` with anything. `docs/instances.md` says so; these tests
keep the statement and the behaviour together, so that neither changes alone.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from netorch import __version__, host_cli
from netorch.codec import MAX_JSON_BYTES, canonical_bytes

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
NOW = 1000.0

# Loads the package from the directory given first, whatever else is installed
# or on the path, and runs the host command with the remaining arguments.
CHILD = """
import importlib.util, json, os, sys
package = sys.argv[1]
spec = importlib.util.spec_from_file_location(
    "netorch", os.path.join(package, "__init__.py"), submodule_search_locations=[package]
)
module = importlib.util.module_from_spec(spec)
sys.modules["netorch"] = module
spec.loader.exec_module(module)
from netorch import host_cli
os.geteuid = lambda: 501
print(json.dumps({"package": os.path.dirname(os.path.abspath(host_cli.__file__))}))
raise SystemExit(host_cli.main(sys.argv[2:]))
"""


def another_release() -> bytes:
    """A wheel-shaped archive whose package claims another version."""
    payload = BytesIO()
    member = zipfile.ZipInfo("netorch/__init__.py", date_time=(1980, 1, 1, 0, 0, 0))
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr(member, '__version__ = "0.0.0"\n')
    return payload.getvalue()


class Pinned:
    """A valid instance beside two files whose hashes it pins."""

    def __init__(self, directory: Path, artifact: bytes = b"not a wheel at all") -> None:
        shutil.copytree(EXAMPLES / "contracts", directory / "contracts")
        self.data: dict[str, Any] = json.loads((EXAMPLES / "instance.json").read_bytes())
        self.artifact = directory / "package.whl"
        self.artifact.write_bytes(artifact)
        self.lock = directory / "requirements-lock.txt"
        self.lock.write_bytes(b"example runtime lock\n")
        self.instance = directory / "instance.json"
        self.data["framework"].update(
            version=__version__,
            artifact_sha256=hashlib.sha256(artifact).hexdigest(),
            dependency_lock_sha256=hashlib.sha256(self.lock.read_bytes()).hexdigest(),
        )
        self.write()

    def write(self) -> None:
        self.instance.write_bytes(canonical_bytes(self.data) + b"\n")

    def arguments(self, command: str, *, artifact: bool = True, lock: bool = True) -> list[str]:
        argv = [command, "--instance", str(self.instance)]
        if artifact:
            argv += ["--framework-artifact", str(self.artifact)]
        if lock:
            argv += ["--dependency-lock", str(self.lock)]
        return argv


@pytest.fixture
def unprivileged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 501)


def run(capsys: Any, argv: list[str], code: int = 0) -> dict[str, Any]:
    assert host_cli.main(argv, now=NOW) == code
    result = json.loads(capsys.readouterr().out)
    assert isinstance(result, dict)
    return result


def pin_row(report: dict[str, Any]) -> dict[str, Any]:
    (row,) = (item for item in report["requirements"] if item["id"] == "FRAMEWORK-PIN")
    assert isinstance(row, dict)
    return row


@pytest.mark.parametrize(
    "revision", ["0" * 40, "f" * 40, "0123456789abcdef0123456789abcdef01234567"]
)
@pytest.mark.parametrize("artifact", [b"not a wheel at all", another_release()])
def test_matching_files_verify_whatever_revision_says_and_whatever_the_artifact_holds(
    tmp_path: Path, unprivileged: None, capsys: Any, revision: str, artifact: bytes
) -> None:
    pinned = Pinned(tmp_path, artifact)
    pinned.data["framework"]["revision"] = revision
    pinned.write()
    # The code that runs comes from this checkout or installation, not from the
    # pinned file: that file is no installable wheel, or holds another version.
    assert not Path(host_cli.__file__).resolve().is_relative_to(tmp_path.resolve())
    assert run(capsys, pinned.arguments("validate"))["release_verified"] is True
    row = pin_row(run(capsys, pinned.arguments("report")))
    assert row["status"] == "fulfilled-verified"
    assert row["reason"] == "Exact local release artifact matches its declared SHA-256."


def test_a_relocated_and_edited_copy_of_the_package_verifies_the_same_files(
    tmp_path: Path,
) -> None:
    site = tmp_path / "site"
    site.mkdir()
    pinned = Pinned(site)
    package = tmp_path / "elsewhere" / "netorch"
    shutil.copytree(
        Path(host_cli.__file__).resolve().parent,
        package,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    # Laid out like an installed wheel, which carries its schemas in the package.
    for schema in (ROOT / "schemas").glob("*.schema.json"):
        shutil.copy(schema, package / schema.name)
    # The running code now has bytes that no release has.
    with (package / "host_cli.py").open("a", encoding="utf-8") as stream:
        stream.write("\n# edited after installation\n")
    result = subprocess.run(
        [sys.executable, "-c", CHILD, str(package), *pinned.arguments("validate")],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    where, output = (json.loads(line) for line in result.stdout.splitlines())
    assert Path(where["package"]).resolve() == package.resolve()
    assert output["valid"] is True and output["release_verified"] is True


def test_version_string_is_the_only_tie_to_the_running_package(
    tmp_path: Path, unprivileged: None, capsys: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    pinned = Pinned(tmp_path)
    pinned.data["framework"]["version"] = "9.9.9"
    pinned.write()
    assert run(capsys, pinned.arguments("validate"))["release_verified"] is False
    # The same running code under another version string: verified.
    monkeypatch.setattr(host_cli, "__version__", "9.9.9")
    assert run(capsys, pinned.arguments("validate"))["release_verified"] is True


def test_both_files_are_needed_and_each_is_compared_with_its_own_pin(
    tmp_path: Path, unprivileged: None, capsys: Any
) -> None:
    pinned = Pinned(tmp_path)
    assert run(capsys, pinned.arguments("validate"))["release_verified"] is True
    for options in ({"artifact": False}, {"lock": False}, {"artifact": False, "lock": False}):
        assert run(capsys, pinned.arguments("validate", **options))["release_verified"] is False
        row = pin_row(run(capsys, pinned.arguments("report", **options)))
        assert row["status"] != "fulfilled-verified"
    swapped = [
        "validate",
        "--instance",
        str(pinned.instance),
        "--framework-artifact",
        str(pinned.lock),
        "--dependency-lock",
        str(pinned.artifact),
    ]
    assert run(capsys, swapped)["release_verified"] is False
    pinned.artifact.write_bytes(b"not a wheel at all, changed")
    assert run(capsys, pinned.arguments("validate"))["release_verified"] is False


@pytest.mark.parametrize("fault", ["symlink", "hardlink", "oversized"])
@pytest.mark.parametrize("option", ["artifact", "lock"])
def test_release_files_are_ordinary_bounded_local_files(
    tmp_path: Path, unprivileged: None, capsys: Any, option: str, fault: str
) -> None:
    pinned = Pinned(tmp_path)
    target = pinned.artifact if option == "artifact" else pinned.lock
    if fault == "symlink":
        real = tmp_path / "real"
        target.rename(real)
        target.symlink_to(real)
    elif fault == "hardlink":
        os.link(target, tmp_path / "second-name")
    else:
        target.write_bytes(b"x" * (MAX_JSON_BYTES + 1))
    result = run(capsys, pinned.arguments("validate"), 65)
    assert result == {
        "read_only": True,
        "mutation_available": False,
        "error": "invalid-or-unavailable-local-data",
    }

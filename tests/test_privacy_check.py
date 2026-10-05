from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from netorch.codec import canonical_bytes
from netorch.instance import instance_to_dict, load_instance
from netorch.privacy import PrivacyError
from netorch.privacy_check import check, git_candidates, load_exceptions, main
from netorch.process import ProcessTimeout, Result, run


def exception_file(tmp_path, entries=()):
    path = tmp_path / "exceptions.json"
    path.write_bytes(canonical_bytes({"schema_version": 1, "exceptions": list(entries)}) + b"\n")
    return path


def runner(files):
    def observed(argv):
        assert argv[0] == "/usr/bin/git"
        assert argv[1:6] == [
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ]
        assert argv[8:] == ["ls-files", "--cached", "--others", "--exclude-standard", "-z"]
        return Result(0, b"".join(name.encode() + b"\0" for name in files), b"")

    return observed


def test_git_inventory_only_tracked_and_nonignored_candidates(tmp_path):
    for name in ("tracked.py", "candidate.py", "ignored.py", "force-tracked.py"):
        (tmp_path / name).write_text("safe")
    (tmp_path / ".gitignore").write_text("ignored.py\nforce-tracked.py\n")
    for args in (
        ["init", "-q"],
        ["add", ".gitignore", "tracked.py"],
        ["add", "-f", "force-tracked.py"],
    ):
        result = run(["/usr/bin/git", "-C", str(tmp_path), *args], account_home=str(tmp_path))
        assert result.returncode == 0
    assert git_candidates(tmp_path) == [
        ".gitignore",
        "candidate.py",
        "force-tracked.py",
        "tracked.py",
    ]


@pytest.mark.parametrize(
    "result",
    [
        Result(1, b"", b"not-logged"),
        Result(0, b"file\0", b"unknown-warning"),
        Result(0, b"\xff\0", b""),
        Result(0, b"partial", b""),
        Result(0, b"\0", b""),
        Result(0, b"bad\nfile\0", b""),
        Result(0, b"x" * 4_194_305, b""),
    ],
)
def test_git_inventory_unknown_output_refuses(tmp_path, result):
    with pytest.raises(PrivacyError):
        git_candidates(tmp_path, runner=lambda _: result)


def test_mock_git_inventory_is_sorted_deduplicated_and_all_checked(tmp_path):
    assert git_candidates(tmp_path, runner=runner(["z.py", "a.py", "z.py"])) == ["a.py", "z.py"]
    assert git_candidates(tmp_path, runner=runner([])) == []


def test_generic_entrypoint_catches_candidate_and_hash_only_reports(tmp_path):
    (tmp_path / "candidate.py").write_text("interface=en" + str(29))
    findings = check(tmp_path, exception_file(tmp_path), runner=runner(["candidate.py"]))
    assert len(findings) == 1 and findings[0].kind == "interface"
    assert ("en" + str(29)) not in json.dumps(findings[0].to_dict())


def test_instance_entrypoint_cannot_reuse_generic_fixture_exceptions(tmp_path):
    sample = Path(__file__).parents[1] / "examples" / "instance.json"
    data = instance_to_dict(load_instance(sample))
    instance = tmp_path / "instance.json"
    instance.write_bytes(canonical_bytes(data) + b"\n")
    private = data["namespace"]
    (tmp_path / "candidate.py").write_text(private)
    generic = exception_file(
        tmp_path,
        [
            {
                "path": "candidate.py",
                "kind": "namespace",
                "reason": "synthetic namespace fixture",
                "value_sha256": hashlib.sha256(private.encode()).hexdigest(),
            }
        ],
    )
    assert not check(tmp_path, generic, runner=runner(["candidate.py"]))
    findings = check(tmp_path, generic, instance=instance, runner=runner(["candidate.py"]))
    assert any(f.value_sha256 == hashlib.sha256(private.encode()).hexdigest() for f in findings)
    exact = tmp_path / "exact.json"
    exact.write_bytes(
        canonical_bytes(
            {
                "schema_version": 1,
                "exceptions": [
                    {
                        "path": "candidate.py",
                        "kind": "namespace",
                        "reason": "same synthetic example value on both sides",
                        "value_sha256": hashlib.sha256(private.encode()).hexdigest(),
                    }
                ],
            }
        )
        + b"\n"
    )
    assert not check(
        tmp_path,
        generic,
        instance=instance,
        instance_exceptions=exact,
        runner=runner(["candidate.py"]),
    )
    exact.write_bytes(
        canonical_bytes(
            {
                "schema_version": 1,
                "exceptions": [
                    {
                        "path": "candidate.py",
                        "kind": "namespace",
                        "reason": "wrong hash cannot exempt",
                        "value_sha256": "a" * 64,
                    }
                ],
            }
        )
        + b"\n"
    )
    assert check(
        tmp_path,
        generic,
        instance=instance,
        instance_exceptions=exact,
        runner=runner(["candidate.py"]),
    )


@pytest.mark.parametrize(
    "data",
    [
        {"schema_version": 2, "exceptions": []},
        {"schema_version": True, "exceptions": []},
        {"schema_version": 1, "exceptions": [], "extra": True},
        {"schema_version": 1, "exceptions": None},
        {"schema_version": 1, "exceptions": [{}]},
        {
            "schema_version": 1,
            "exceptions": [
                {"path": "file", "kind": "interface", "reason": "reason", "value_sha256": "invalid"}
            ],
        },
        {
            "schema_version": 1,
            "exceptions": [
                {"path": 1, "kind": "interface", "reason": "reason", "value_sha256": None}
            ],
        },
        {
            "schema_version": 1,
            "exceptions": [
                {"path": "file", "kind": "interface", "reason": "reason", "value_sha256": None}
            ]
            * 2,
        },
    ],
)
def test_exception_data_shape_closed(tmp_path, data):
    path = tmp_path / "exceptions.json"
    path.write_text(json.dumps(data))
    with pytest.raises(PrivacyError):
        load_exceptions(path, scope="generic")


def test_exact_guard_needs_exact_exception_hash_and_validated_instance(tmp_path):
    exception = exception_file(
        tmp_path, [{"path": "file", "kind": "interface", "reason": "reason", "value_sha256": None}]
    )
    with pytest.raises(PrivacyError, match="exact value"):
        load_exceptions(exception, scope="instance")
    with pytest.raises(PrivacyError, match="validated instance"):
        check(tmp_path, exception_file(tmp_path), instance_exceptions=exception, runner=runner([]))


def test_cli_pass_fail_refusal_never_echoes_captured_exception_text(tmp_path, monkeypatch, capsys):
    import netorch.privacy_check as entrypoint

    path = exception_file(tmp_path)
    monkeypatch.setattr(entrypoint, "git_candidates", lambda _, **kwargs: [])
    assert main(["--root", str(tmp_path), "--exceptions", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "passed"
    (tmp_path / "candidate.py").write_text("en" + str(29))
    monkeypatch.setattr(entrypoint, "git_candidates", lambda _, **kwargs: ["candidate.py"])
    assert main(["--root", str(tmp_path), "--exceptions", str(path)]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "failed"

    def fail(*_args, **_kwargs):
        raise ProcessTimeout("private-captured-data-never-logged")

    monkeypatch.setattr(entrypoint, "check", fail)
    assert main(["--root", str(tmp_path), "--exceptions", str(path)]) == 2
    captured = capsys.readouterr().out
    assert json.loads(captured)["status"] == "refused"
    assert "private-captured-data" not in captured


def test_new_namespace_in_previously_exempt_fixture_is_a_finding(tmp_path):
    sample = instance_to_dict(
        load_instance(Path(__file__).parents[1] / "examples" / "instance.json")
    )
    expected = sample["namespace"]
    p = tmp_path / "candidate.py"
    p.write_text(expected)
    exceptions = exception_file(
        tmp_path,
        [
            {
                "path": "candidate.py",
                "kind": "namespace",
                "reason": "one exact synthetic fixture namespace",
                "value_sha256": hashlib.sha256(expected.encode()).hexdigest(),
            }
        ],
    )
    assert not check(tmp_path, exceptions, runner=runner(["candidate.py"]))
    unexpected = ".".join(["org", "different", "production"])
    p.write_text(expected + "\n" + unexpected)
    findings = check(tmp_path, exceptions, runner=runner(["candidate.py"]))
    assert (
        len(findings) == 1
        and findings[0].value_sha256 == hashlib.sha256(unexpected.encode()).hexdigest()
    )


def test_unhashed_public_exception_is_not_a_ci_bypass(tmp_path):
    exceptions = exception_file(
        tmp_path,
        [
            {
                "path": "candidate.py",
                "kind": "namespace",
                "reason": "unhashed never permitted by entrypoint",
                "value_sha256": None,
            }
        ],
    )
    with pytest.raises(PrivacyError, match="exact value"):
        check(tmp_path, exceptions, runner=runner([]))


def test_unknown_exception_scope_refuses(tmp_path):
    with pytest.raises(PrivacyError, match="scope"):
        load_exceptions(exception_file(tmp_path), scope="unknown")

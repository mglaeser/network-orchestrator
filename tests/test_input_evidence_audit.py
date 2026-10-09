"""Independent bounded-input and privacy traversal refusal proofs.

All paths and data are local synthetic temporary fixtures; no server inputs,
commands, credentials or production services are accessed.
"""

from __future__ import annotations

import os
import sys

import pytest

from netorch import legacy_import, privacy
from netorch.codec import CodecError, strict_loads
from netorch.config import ConfigError, parse_config
from netorch.privacy import PrivacyError, scan_framework


@pytest.mark.parametrize("kind", ["missing", "regular-file"])
def test_privacy_walk_cannot_report_success_for_a_non_directory_root(tmp_path, kind):
    root = tmp_path / "candidate"
    if kind == "regular-file":
        root.write_text("not a checkout")
    with pytest.raises(PrivacyError):
        scan_framework(root)


@pytest.mark.parametrize("target", ["inside", "outside"])
def test_explicit_privacy_inventory_refuses_a_symlink_ancestor(tmp_path, target):
    root = tmp_path / "root"
    root.mkdir()
    other = root / "real" if target == "inside" else tmp_path / "outside"
    other.mkdir()
    (other / "data.txt").write_text("neutral sample")
    (root / "linked").symlink_to(other, target_is_directory=True)
    with pytest.raises(PrivacyError):
        scan_framework(root, files=["linked/data.txt"])


def test_default_privacy_walk_refuses_an_unreadable_subdirectory(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root can read mode000 directories; unprivileged refusal case")
    hidden = tmp_path / "unreadable"
    hidden.mkdir()
    (hidden / "input.txt").write_text("must be examined or refused")
    hidden.chmod(0)
    try:
        with pytest.raises(PrivacyError):
            scan_framework(tmp_path)
    finally:
        hidden.chmod(0o700)


@pytest.mark.parametrize("limit_name", ["max_bytes", "max_depth"])
@pytest.mark.parametrize("value", [True, False, 1.0, float("nan"), float("inf"), "2", None])
def test_strict_json_limits_must_be_positive_exact_integers(limit_name, value):
    with pytest.raises(CodecError):
        strict_loads("0", **{limit_name: value})


@pytest.mark.parametrize("parse", [strict_loads, parse_config])
def test_oversized_decimal_integer_keeps_the_public_parser_error_contract(parse):
    # Python's own integer-string limit can be more restrictive than the JSON
    # byte limit. No generic ValueError may escape the public typed error API.
    if not hasattr(sys, "get_int_max_str_digits") or sys.get_int_max_str_digits() == 0:
        pytest.skip("interpreter decimal conversion guard is not enabled")
    raw = "9" * (sys.get_int_max_str_digits() + 1)
    error = CodecError if parse is strict_loads else ConfigError
    with pytest.raises(error):
        parse(raw)


def test_static_capture_closes_its_descriptor_after_read_failure(tmp_path, monkeypatch):
    source = tmp_path / "input"
    source.write_bytes(b"neutral input")
    opened = []
    original_open = legacy_import.os.open

    def capture_open(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def fail_read(fd, size):
        raise OSError("injected read failure")

    monkeypatch.setattr(legacy_import.os, "open", capture_open)
    monkeypatch.setattr(legacy_import.os, "read", fail_read)
    with pytest.raises(legacy_import.ImportError, match="unavailable"):
        legacy_import.capture_static(source)
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_failed_privacy_read_does_not_echo_private_source_contents(tmp_path, monkeypatch):
    source = tmp_path / "candidate.txt"
    source.write_text("neutral sample")

    def fail_read(path):
        raise legacy_import.ImportError("example-sensitive-value")

    monkeypatch.setattr(privacy, "read_static", fail_read)
    with pytest.raises(PrivacyError) as error:
        scan_framework(tmp_path, files=["candidate.txt"])
    assert str(error.value) == "Privacy source cannot be checked: candidate.txt"
    assert "example-sensitive-value" not in str(error.value)


@pytest.mark.parametrize("value", [2**256 - 1, -(2**256 - 1), 0, -1])
def test_strict_json_exact_integer_boundary_preserves_valid_values(value):
    assert strict_loads(str(value)) == value


@pytest.mark.parametrize("raw", [str(2**256), str(-(2**256)), "9" * 100000])
def test_strict_json_rejects_both_bit_and_decimal_width_overflow(raw):
    with pytest.raises(CodecError, match="integer"):
        strict_loads(raw)


def test_privacy_traversal_failure_is_a_closed_cli_refusal(tmp_path, monkeypatch, capsys):
    from netorch import privacy_check
    from netorch.codec import canonical_bytes, strict_loads
    from netorch.process import Result

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "data.txt").write_text("neutral")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "alias").symlink_to(outside, target_is_directory=True)
    exceptions = tmp_path / "exceptions.json"
    exceptions.write_bytes(canonical_bytes({"schema_version": 1, "exceptions": []}))
    monkeypatch.setattr(privacy_check, "run", lambda *a, **k: Result(0, b"alias/data.txt\0", b""))
    assert privacy_check.main(["--root", str(checkout), "--exceptions", str(exceptions)]) == 2
    assert strict_loads(capsys.readouterr().out) == {
        "status": "refused",
        "reason": "privacy-scan-contract-refused",
    }


@pytest.mark.parametrize("api", ["direct", "cli"])
def test_cyclic_root_link_is_a_closed_privacy_refusal(tmp_path, api, capsys):
    from netorch import privacy_check
    from netorch.codec import canonical_bytes, strict_loads

    first, second = tmp_path / "first", tmp_path / "second"
    first.symlink_to(second)
    second.symlink_to(first)
    if api == "direct":
        with pytest.raises(PrivacyError):
            scan_framework(first)
    else:
        exceptions = tmp_path / "exceptions.json"
        exceptions.write_bytes(canonical_bytes({"schema_version": 1, "exceptions": []}))
        assert privacy_check.main(["--root", str(first), "--exceptions", str(exceptions)]) == 2
        assert strict_loads(capsys.readouterr().out) == {
            "status": "refused",
            "reason": "privacy-scan-contract-refused",
        }

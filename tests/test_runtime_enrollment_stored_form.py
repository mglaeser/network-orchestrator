"""`enroll` writes the bytes the settings loader reads, and the size bound is judged on them.

The loader takes at most 1 MiB. `enroll` stores the canonical form of a capture
and one final newline. Exactly those bytes are read back through the loader's
own functions before the output file is created: by the capture, and again by
the command on the payload it is about to write. An unset `fleet_start` is no
part of the stored form, so it is dropped before any bytes are taken and takes
no part in the bound. Everything native is faked here.
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.codec import MAX_JSON_BYTES, CodecError, canonical_json, strict_load, strict_loads
from netorch.runtime_settings import FleetStart, load_settings, parse_settings, settings_to_dict
from tests.test_apple_runtime import FakeRunner, enrolled

__all__ = ["enrolled"]

ROOT = Path(__file__).resolve().parents[1]
LIMIT = MAX_JSON_BYTES
REDACTED = '{"error":"runtime-evidence-or-authority-incomplete"}\n'
VOLUME = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
# Platform constants, not a synthetic alternative namespace: another label cannot prove a stop.
DECLARATION = {
    "api_label": "com.apple.container.apiserver",
    "api_executable": "/usr/libexec/example-api",
    "runtime_label_prefix": "com.apple.container.",
}
FLEET = FleetStart(**DECLARATION)
# SHA-256 of the canonical form `settings_to_dict` gives, taken from the tree
# before the unset declaration was dropped earlier. Declared fixtures now use
# the source-defined vendor labels; their expected hashes were recomputed for
# that deliberate fixture-input change, not a serialization change.
BASE_FORM = {
    "example": "d1307ffc7cb45fb28b71c4cd190e57a4f8548b76b28a66fad9c4eec52cc28ab8",
    "example-declared": "8bad530ee4454b91f756cb62eab5e6244f643e7150155426b7671c7715b612c3",
    "every-member": "74291cd0a91bfabb879201824a013ac00b9f445a6f768b32001241ea265a1a89",
    "every-member-declared": "9d892ce28fd9bbf36fe08db71ed54c1bfa3449c81c22c18f66302ef86c3a7b4d",
}


def documents() -> dict[str, dict[str, Any]]:
    """The shipped example, and one document that uses every optional member."""
    example = strict_load(ROOT / "examples/runtime-settings.json")
    full = copy.deepcopy(example)
    del full["policy"], full["admissions"]
    full["start_timeout_seconds"] = 30
    for contract in full["contracts"]:
        contract["tolerated_stopped_peers"] = ["retired-a", "retired-b"]
        contract["receipts"] = [
            {
                "path": "/operator/site/kernel",
                "kind": "file",
                "uid": 501,
                "device": 3,
                "inode": 7,
                "sha256": "ab" * 32,
            },
            {
                "path": "/operator/site/inputs",
                "kind": "directory",
                "uid": 501,
                "inode": 9,
                "volume_uuid": VOLUME,
            },
            {"path": "/operator/site/runtime.sock", "kind": "socket", "uid": 501},
        ]
    return {
        "example": example,
        "example-declared": {**example, "fleet_start": dict(DECLARATION)},
        "every-member": full,
        "every-member-declared": {**full, "fleet_start": dict(DECLARATION)},
    }


def sized(settings: Any, size: int, fleet: FleetStart | None) -> tuple[Any, dict[str, Any]]:
    """Loadable settings whose canonical form has exactly `size` bytes, and that form's value.

    Further networks with long helper paths carry the weight; the state directory
    is the fine adjustment. Nothing of it is touched by a capture.
    """
    weight = tuple(
        replace(settings.networks[0], scope=f"weight-{index}", helper_executable="/" + "w" * 60_000)
        for index in range(17)
    )
    light = replace(
        settings, networks=(*settings.networks, *weight), fleet_start=fleet, state_dir="/s"
    )
    value = settings_to_dict(light)
    missing = size - len(canonical_json(value).encode())
    assert 0 < missing < 60_000
    value["state_dir"] = "/s" + "x" * missing
    return replace(light, state_dir=value["state_dir"]), value


def enroll(monkeypatch: pytest.MonkeyPatch, source: Path, items: Any, output: Path) -> int:
    """The command as it runs on a stored settings file, with the native tool faked."""
    real = runtime.capture_enrollment
    with monkeypatch.context() as patch:
        patch.setattr(
            runtime,
            "capture_enrollment",
            lambda actual, **keywords: real(actual, FakeRunner(actual, items), **keywords),
        )
        return runtime.main(["--settings", str(source), "enroll", "--output", str(output)])


@pytest.mark.parametrize("name", sorted(BASE_FORM))
def test_no_byte_of_a_stored_form_moves(name: str) -> None:
    parsed = parse_settings(documents()[name])
    value = settings_to_dict(parsed)
    form = canonical_json(value).encode()
    assert hashlib.sha256(form).hexdigest() == BASE_FORM[name]
    # Present exactly when declared, and the stored bytes read back as the same settings.
    assert ("fleet_start" in value) == name.endswith("declared")
    assert parse_settings(strict_loads(form + b"\n")) == parsed


def test_an_unset_fleet_start_takes_no_part_in_the_size_bound(enrolled: Any) -> None:
    _config, settings, _items = enrolled
    exact, value = sized(settings, LIMIT, None)
    assert "fleet_start" not in value
    # The whole bound is available to the stored form: on the tree before this
    # change the member was serialised as null first, and 19 bytes were lost.
    assert settings_to_dict(exact) == value
    assert len(canonical_json(settings_to_dict(exact)).encode()) == LIMIT
    over, _value = sized(settings, LIMIT + 1, None)
    with pytest.raises(CodecError):
        settings_to_dict(over)


@pytest.mark.parametrize("declared", [False, True], ids=["undeclared", "declared"])
@pytest.mark.parametrize("size", [LIMIT - 1, LIMIT], ids=["newline-fits", "newline-is-too-much"])
def test_enroll_writes_up_to_the_last_byte_the_loader_reads(
    enrolled: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    declared: bool,
    size: int,
) -> None:
    """The final newline decides: with it the file has 1 MiB, or one byte more."""
    _config, settings, items = enrolled
    exact, value = sized(settings, size, FLEET if declared else None)
    form = canonical_json(value).encode()
    source = tmp_path / "settings.json"
    # Kept without a final newline, so that the loader reads the input at either size.
    source.write_bytes(form)
    assert len(form) == size and load_settings(source) == exact
    output = tmp_path / "enrollment.next.json"
    status = enroll(monkeypatch, source, items, output)
    streams = capsys.readouterr()
    if size < LIMIT:
        assert status == 0 and not streams.err
        assert output.read_bytes() == form + b"\n" and output.stat().st_size == LIMIT
        assert load_settings(output) == exact
    else:
        assert status == runtime.UNKNOWN
        assert (streams.out, streams.err) == ("", REDACTED)
        assert not output.exists()


@pytest.mark.parametrize("declared", [False, True], ids=["undeclared", "declared"])
def test_the_capture_is_refused_exactly_when_the_stored_bytes_would_not_load(
    enrolled: Any, declared: bool
) -> None:
    _config, settings, items = enrolled
    fleet = FLEET if declared else None
    fits, _value = sized(settings, LIMIT - 1, fleet)
    assert runtime.capture_enrollment(fits, FakeRunner(fits, items)) == fits
    for size in (LIMIT, LIMIT + 1):
        exact, _value = sized(settings, size, fleet)
        with pytest.raises(runtime.RuntimeReadError) as refused:
            runtime.capture_enrollment(exact, FakeRunner(exact, items))
        assert refused.value.reason == "identity-mismatch"


@pytest.mark.parametrize("below", [19, 18, 10, 1])
def test_what_the_loader_reads_the_capture_returns_and_the_loader_reads_that(
    enrolled: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    below: int,
) -> None:
    """The last bytes below the bound, where an unset `fleet_start` used to count."""
    _config, settings, items = enrolled
    exact, value = sized(settings, LIMIT - below, None)
    stored = tmp_path / "enrollment.json"
    stored.write_bytes(canonical_json(value).encode() + b"\n")
    # What the loader reads, the capture returns ...
    existing = load_settings(stored)
    captured = runtime.capture_enrollment(existing, FakeRunner(existing, items))
    assert captured == existing == exact
    # ... and what the capture returns is stored as bytes the loader reads.
    output = tmp_path / "enrollment.next.json"
    assert enroll(monkeypatch, stored, items, output) == 0
    assert not capsys.readouterr().err
    assert output.read_bytes() == stored.read_bytes()
    assert load_settings(output) == captured


def test_enroll_reads_back_its_payload_whatever_the_capture_returned(
    enrolled: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The command does not rest on the capture's check: it parses what it is about to write."""
    _config, settings, _items = enrolled
    first = settings.contracts[0]
    unchecked = replace(
        settings,
        contracts=(
            replace(first, mounts=(replace(first.mounts[0], path="relative/source"),)),
            *settings.contracts[1:],
        ),
    )
    with pytest.raises(ValueError):
        parse_settings(settings_to_dict(unchecked))
    monkeypatch.setattr(runtime, "load_settings", lambda _path: settings)
    monkeypatch.setattr(runtime, "capture_enrollment", lambda _actual, **_keywords: unchecked)
    output = tmp_path / "enrollment.next.json"
    status = runtime.main(["--settings", "/unused", "enroll", "--output", str(output)])
    streams = capsys.readouterr()
    assert status == runtime.UNKNOWN and (streams.out, streams.err) == ("", REDACTED)
    assert not output.exists()

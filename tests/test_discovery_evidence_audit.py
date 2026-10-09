"""Additional boundary proofs from a source audit; all input data is synthetic."""

import json
import selectors
from dataclasses import replace
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.config import load_config, to_dict
from netorch.derive import DeriveError, _fill_pointer, derive
from netorch.storage import Store
from tests.test_bonjour_owner import config, media_record, settings
from tests.test_derive import EXAMPLES, write_manifest

__all__ = ["config", "settings"]


@pytest.mark.parametrize("invalid", ["dot-name", "combined-txt", "lifetime"])
def test_rejected_registration_allocates_no_os_resources(
    monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    record = media_record()
    lifetime = 120
    if invalid == "dot-name":
        record = replace(record, name=".")
    elif invalid == "combined-txt":
        record = replace(record, txt=(b"x" * 255,) * 35)
    else:
        lifetime = 121
    made: list[selectors.BaseSelector] = []
    select = selectors.DefaultSelector

    def selector() -> selectors.BaseSelector:
        result = select()
        made.append(result)
        return result

    def unexpected_spawn(*args: Any, **kwargs: Any) -> None:
        pytest.fail("an invalid registration must not create a process")

    monkeypatch.setattr(native.selectors, "DefaultSelector", selector)
    monkeypatch.setattr(native.subprocess, "Popen", unexpected_spawn)
    try:
        with pytest.raises(native.DiscoveryFailure):
            native.Registration(record, 7, lifetime)
        assert made == [], "validation must precede native selector allocation"
    finally:
        for item in made:
            item.close()


@pytest.mark.parametrize("pid", [None, True, False, -1, 0, 1.5, "42", [], {}])
@pytest.mark.parametrize("which", ["scanner", "publisher"])
def test_malformed_heartbeat_pid_is_not_healthy(
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    pid: Any,
    which: str,
) -> None:
    monkeypatch.setattr(owner.time, "time", lambda: 1000.0)
    store = Store(settings.state_dir)
    for name in ("scanner", "publisher"):
        store.write(
            f"{name}-heartbeat.json",
            {"schema_version": 1, "observed_at": 999.0, "pid": pid if name == which else 42},
        )
    assert owner.health(settings, store) is False


@pytest.mark.parametrize("index", ["00", "01", "\u0660", "\uff10"])
def test_literal_mapping_refuses_noncanonical_array_indexes(tmp_path: Any, index: str) -> None:
    raw = to_dict(load_config(EXAMPLES / "network.json"))
    for scope in raw["scopes"]:
        scope["host_ipv4"] = None
    (tmp_path / "fragment.json").write_text(json.dumps(raw))
    (tmp_path / "source.env").write_text("HOST=192.0.2.10\n")
    manifest = write_manifest(
        tmp_path,
        [
            {"path": "fragment.json", "format": "json"},
            {
                "path": "source.env",
                "format": "literal-env",
                "mapping": {"HOST": f"/scopes/{index}/host_ipv4"},
            },
        ],
    )
    with pytest.raises(DeriveError, match="Mapping"):
        derive(manifest)


@pytest.mark.parametrize("failure", [ValueError, RuntimeError, KeyboardInterrupt])
def test_non_os_spawn_exception_closes_selector_without_disguising_failure(
    monkeypatch: pytest.MonkeyPatch, failure: type[BaseException]
) -> None:
    made: list[selectors.BaseSelector] = []
    select = selectors.DefaultSelector

    def selector() -> selectors.BaseSelector:
        result = select()
        made.append(result)
        return result

    def cannot_spawn(*args: Any, **kwargs: Any) -> None:
        raise failure("synthetic spawn interruption")

    monkeypatch.setattr(native.selectors, "DefaultSelector", selector)
    monkeypatch.setattr(native.subprocess, "Popen", cannot_spawn)
    try:
        with pytest.raises(failure, match="synthetic spawn interruption"):
            native.Registration(media_record(), 7)
        assert len(made) == 1 and made[0].get_map() is None
    finally:
        for item in made:
            item.close()


def test_array_leaf_mapping_preserves_siblings_and_refuses_second_author() -> None:
    data: dict[str, Any] = {"rows": ["previous", None]}
    _fill_pointer(data, "/rows/1", "example")
    assert data == {"rows": ["previous", "example"]}
    with pytest.raises(DeriveError, match="overwrite"):
        _fill_pointer(data, "/rows/1", "other")
    assert data == {"rows": ["previous", "example"]}


@pytest.mark.parametrize("index", ["00", "01", "\u0660", "\uff10", "9" * 5000, "-"])
def test_invalid_array_leaf_never_targets_a_different_element(index: str) -> None:
    data: dict[str, Any] = {"rows": [None, None]}
    with pytest.raises(DeriveError, match="Mapping"):
        _fill_pointer(data, f"/rows/{index}", "example")
    assert data == {"rows": [None, None]}


def test_numeric_object_keys_are_literal_not_array_indexes() -> None:
    data: dict[str, Any] = {"rows": {"00": None, "\u0660": None}}
    _fill_pointer(data, "/rows/00", "first")
    _fill_pointer(data, "/rows/\u0660", "second")
    assert data == {"rows": {"00": "first", "\u0660": "second"}}

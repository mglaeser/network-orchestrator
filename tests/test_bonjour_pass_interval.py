"""The scanner's pass interval is a setting of its own, bounded by the leases.

Synthetic names and RFC 5737 addresses only.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch.config import to_dict
from netorch.model import Config
from netorch.storage import Store
from tests.test_bonjour_owner import config, expected_settings, settings, write_private

__all__ = ["config", "settings"]


def loaded(settings: owner.BonjourSettings, tmp_path: Path, **extra: Any) -> owner.BonjourSettings:
    return owner.load_settings(
        write_private(tmp_path / "bonjour.json", {**expected_settings(settings), **extra})
    )


def test_unset_pass_interval_is_the_evidence_interval_as_before(
    settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    assert loaded(settings, tmp_path) == settings
    assert settings.pass_seconds is None and settings.pass_interval == settings.poll_seconds == 5
    assert loaded(settings, tmp_path, poll_seconds=9).pass_interval == 9


@pytest.mark.parametrize("value", [5, 20, 60])
def test_pass_interval_within_the_range_and_the_leases_is_accepted(
    settings: owner.BonjourSettings, tmp_path: Path, value: int
) -> None:
    result = loaded(settings, tmp_path, pass_seconds=value)
    assert result == replace(settings, pass_seconds=value)
    # The evidence interval keeps its own value and range.
    assert (result.pass_interval, result.poll_seconds) == (value, 5)


@pytest.mark.parametrize("value", [0, 4, 121, -20, True, 20.0, "20", None])
def test_pass_interval_outside_its_range_is_refused(
    settings: owner.BonjourSettings, tmp_path: Path, value: Any
) -> None:
    with pytest.raises(ValueError, match="polling must be bounded"):
        loaded(settings, tmp_path, pass_seconds=value)


def test_pass_interval_must_leave_room_inside_every_owned_lease(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    # The example leases are 120 seconds: half of that is the longest rest.
    with pytest.raises(ValueError, match="room inside every owned lease"):
        loaded(settings, tmp_path, pass_seconds=61)
    data = to_dict(config)
    for declaration in data["discovery"]:
        declaration["max_age_seconds"] = 240 if declaration["id"] == "media-import" else 300
    write_private(settings.config, data)
    assert loaded(settings, tmp_path, pass_seconds=120).pass_interval == 120
    # One shorter lease among the owned policies is enough to refuse.
    data["discovery"][1]["max_age_seconds"] = 239
    write_private(settings.config, data)
    with pytest.raises(ValueError, match="room inside every owned lease"):
        loaded(settings, tmp_path, pass_seconds=120)


class Watchdog:
    """Stands in for the publisher process: gone after one scanner pass."""

    calls = 0

    def poll(self) -> int | None:
        self.calls += 1
        return 0 if self.calls > 1 else None

    def terminate(self) -> None:
        pass

    def wait(self, timeout: float) -> int:
        return 0


@pytest.mark.parametrize(("pass_seconds", "rest"), [(None, 5), (20, 20)])
def test_scanner_rests_for_the_pass_interval(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    pass_seconds: int | None,
    rest: int,
) -> None:
    rests: list[float] = []
    monkeypatch.setattr(owner.subprocess, "Popen", lambda *_args, **_kwargs: Watchdog())
    monkeypatch.setattr(owner, "_signal_stop", lambda _function: None)
    monkeypatch.setattr(owner, "scan_pass", lambda *_args: None)
    monkeypatch.setattr(owner.time, "sleep", rests.append)
    owner.serve(config, replace(settings, pass_seconds=pass_seconds), settings.config)
    assert rests == [rest]


def test_health_allows_the_scanner_three_of_its_own_intervals(
    settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = Store(settings.state_dir)
    monkeypatch.setattr(owner.time, "time", lambda: 1000)
    slow = replace(settings, pass_seconds=60)

    def beats(scanner: float, publisher: float) -> None:
        store.write(
            "scanner-heartbeat.json", {"schema_version": 1, "observed_at": scanner, "pid": 1}
        )
        store.write(
            "publisher-heartbeat.json", {"schema_version": 1, "observed_at": publisher, "pid": 1}
        )

    # A scanner that writes once per 60-second pass is not stalled after 150 seconds ...
    beats(850, 1000)
    assert owner.health(slow, store) and not owner.health(settings, store)
    # ... but it is after three of its intervals, and the publisher keeps its own bound.
    beats(819, 1000)
    assert not owner.health(slow, store)
    beats(1000, 850)
    assert not owner.health(slow, store) and not owner.health(settings, store)

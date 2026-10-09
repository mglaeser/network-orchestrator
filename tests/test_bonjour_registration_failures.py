"""OS failures cross the real registration boundary without bypassing backoff."""

import errno
import selectors
import subprocess
import sys
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.model import Config
from tests.test_bonjour_owner import config, media_record, settings
from tests.test_bonjour_registration_holdoff import Turns, clock
from tests.test_bonjour_renewal_overlap import Clock

__all__ = ["clock", "config", "settings"]


@pytest.mark.parametrize("failure", [errno.ENOENT, errno.EACCES, errno.EAGAIN, errno.EMFILE])
def test_native_spawn_failure_preserves_record_backoff(
    config: Config,
    settings: owner.BonjourSettings,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
    failure: int,
) -> None:
    attempts: list[float] = []

    def cannot_spawn(*args: Any, **kwargs: Any) -> None:
        attempts.append(clock.elapsed)
        raise OSError(failure, "synthetic native spawn failure")

    monkeypatch.setattr(native.subprocess, "Popen", cannot_spawn)
    manager = owner.Publisher(native.Registration)
    turns = Turns(config, settings, clock, manager, sources=1)
    observed = turns.until(5)
    assert attempts == [0.0, 1.0, 3.0]
    assert all(state == "unknown" and count == 0 for state, _, count in observed.values())
    assert {reason for _, reason, _ in observed.values()} == {"unavailable"}
    assert len(manager.held) == 1


def test_selector_allocation_failure_does_not_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_selector() -> None:
        raise OSError(errno.EMFILE, "synthetic selector exhaustion")

    def must_not_spawn(*args: Any, **kwargs: Any) -> None:
        pytest.fail("a selector failure must happen before a child exists")

    monkeypatch.setattr(native.selectors, "DefaultSelector", no_selector)
    monkeypatch.setattr(native.subprocess, "Popen", must_not_spawn)
    with pytest.raises(native.DiscoveryFailure, match="unavailable"):
        native.Registration(media_record(), 7)


@pytest.mark.parametrize("stage", ["set-blocking", "register"])
def test_setup_failure_reaps_only_the_owned_child_and_closes_resources(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    children: list[subprocess.Popen[bytes]] = []
    selectors_made: list[selectors.BaseSelector] = []
    popen = subprocess.Popen
    selector = selectors.DefaultSelector

    def spawn(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        child = popen(*args, **kwargs)
        children.append(child)
        return child

    def unavailable(*args: Any, **kwargs: Any) -> None:
        raise OSError(errno.EIO, "synthetic pipe setup error")

    def select() -> selectors.BaseSelector:
        result = selector()
        selectors_made.append(result)
        if stage == "register":
            monkeypatch.setattr(result, "register", unavailable)
        return result

    monkeypatch.setattr(native.subprocess, "Popen", spawn)
    monkeypatch.setattr(native.selectors, "DefaultSelector", select)
    monkeypatch.setattr(
        native,
        "registration_argv",
        lambda *_: [sys.executable, "-c", "import time; time.sleep(60)"],
    )
    if stage == "set-blocking":
        monkeypatch.setattr(native.os, "set_blocking", unavailable)
    try:
        with pytest.raises(native.DiscoveryFailure, match="unavailable"):
            native.Registration(media_record(), 7)
        assert len(children) == 1
        assert children[0].poll() is not None
        assert children[0].stdout is not None and children[0].stdout.closed
        assert len(selectors_made) == 1 and selectors_made[0].get_map() is None
    finally:
        # Cleanup still runs if a future regression breaks one of the assertions.
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
            if child.stdout is not None:
                child.stdout.close()
        for item in selectors_made:
            item.close()


def test_registration_io_failure_uses_the_client_failure_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        native,
        "registration_argv",
        lambda *_: [sys.executable, "-c", "import time; time.sleep(60)"],
    )
    registration = native.Registration(media_record(), 7)

    def unavailable(*args: Any, **kwargs: Any) -> None:
        raise OSError(errno.EIO, "synthetic selector read error")

    monkeypatch.setattr(registration.selector, "select", unavailable)
    try:
        with pytest.raises(native.DiscoveryFailure, match="unavailable"):
            registration.poll()
    finally:
        registration.close()
    assert registration.process.poll() is not None
    assert registration.selector.get_map() is None

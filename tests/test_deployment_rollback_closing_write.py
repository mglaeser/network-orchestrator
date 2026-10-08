"""A rollback whose closing journal write did not complete is closed by its repeat.

A rollback writes the predecessor's receipt, releases its hold and then closes
its journal. If that last write fails, or the operator interrupts it, the
failure handler records the rollback as failed. It used to record the phase the
write was about to set, ``rolled-back``, as the phase the rollback failed in.
No command accepted that journal: a rollback is repeated only from
``rolling-back``, recovery reads installation journals, and an installation
refuses while a journal is open.

The oracle is the state an uninterrupted rollback of the same pair leaves.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from netorch.deployment import install_bundle, recover_install
from netorch.deployment_config import DeploymentError
from netorch.storage import Store
from tests.test_deployment import config, fake_platform, manifest
from tests.test_deployment_rollback_reentrant import Lab, uninterrupted

__all__ = ["config", "fake_platform", "manifest"]

JOURNAL = "installation-journal.json"


@pytest.mark.parametrize("scope", ["user", "root"])
@pytest.mark.parametrize(
    ("failure", "written"),
    [(OSError, False), (KeyboardInterrupt, False), (KeyboardInterrupt, True)],
    ids=["write-fails", "interrupted-before-the-write", "interrupted-after-the-write"],
)
def test_rollback_whose_closing_journal_write_did_not_complete_is_closed_by_its_repeat(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    failure: type[BaseException],
    written: bool,
) -> None:
    lab = Lab(tmp_path, manifest, config, scope, monkeypatch)
    expected = uninterrupted(lab)
    runner = lab.prepare()
    write = Store.write
    stopped: list[str] = []

    def closing_write_stops(self: Store, name: str, value: Any) -> None:
        closing = name == JOURNAL and value.get("phase") == "rolled-back" and not stopped
        if closing:
            stopped.append(name)
            if not written:
                raise failure("the closing journal write did not complete")
        write(self, name, value)
        if closing:
            # The entry is on disk; the interrupt arrives before the call returns.
            raise failure("the closing journal write did not return")

    with monkeypatch.context() as patch:
        patch.setattr(Store, "write", closing_write_stops)
        with pytest.raises(failure):
            lab.rollback(runner)
    assert stopped == [JOURNAL]
    # The handler ran: the rollback is recorded as failed in its one open phase.
    journal = Store(lab.state_dir).read(JOURNAL)
    assert (journal["phase"], journal["failed_phase"]) == ("failed", "rolling-back")
    # Everything else is already what a finished rollback leaves.
    assert {**lab.state(), "journal": "rolled-back"} == expected
    # Recovery and installation still leave a rollback's journal to the rollback.
    for digest in (lab.new["bundle_digest"], lab.old["bundle_digest"]):
        with pytest.raises(DeploymentError, match="does not match a failed installation"):
            recover_install(lab.state_dir, scope, expected_failed_digest=digest, runner=runner)
    with pytest.raises(DeploymentError, match="unfinished installation"):
        install_bundle(lab.second, scope, expected_digest=lab.new["bundle_digest"], runner=runner)
    # The same command with the same digest closes the journal and changes nothing else.
    calls = len(lab.tools.calls)
    assert lab.rollback(runner) == {
        "phase": "rolled-back",
        "release_id": lab.old["release_id"],
        "preserved_intent": True,
    }
    assert lab.state() == expected
    assert len(lab.tools.calls) == calls

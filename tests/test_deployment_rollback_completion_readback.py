"""A retained receipt cannot replace fresh verification after a rollback crash.

Disposable stores and fake launchd/root owners only. Each rollback is stopped
immediately after writing its predecessor receipt, before releasing its hold.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from netorch.deployment_config import DeploymentError
from netorch.storage import Store
from tests.test_deployment import config, fake_platform, manifest
from tests.test_deployment_rollback_reentrant import Lab

__all__ = ["config", "fake_platform", "manifest"]


@pytest.mark.parametrize("scope", ["user", "root"])
@pytest.mark.parametrize("drift", ["unloaded", "installed-bytes", "retained-bytes"])
def test_resumed_completion_rechecks_current_jobs_before_releasing_hold(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    drift: str,
) -> None:
    lab = Lab(tmp_path, manifest, config, scope, monkeypatch)
    runner = lab.prepare()
    write = Store.write
    stopped = False

    def stop_after_receipt(self: Store, name: str, value: Any) -> None:
        nonlocal stopped
        write(self, name, value)
        if self.directory == lab.state_dir and name == "installation-receipt.json" and not stopped:
            stopped = True
            raise KeyboardInterrupt("process stopped after restoring predecessor receipt")

    with monkeypatch.context() as patch:
        patch.setattr(Store, "write", stop_after_receipt)
        with pytest.raises(KeyboardInterrupt):
            lab.rollback(runner)
    before = lab.state()
    assert before["receipt"]["bundle_digest"] == lab.old["bundle_digest"]
    assert before["journal"] == "failed"
    assert before["holds"]["installation"] == lab.new["bundle_digest"]
    job = before["receipt"]["jobs"][0]
    if drift == "unloaded":
        lab.tools.loaded.remove(job["label"])
    elif drift == "installed-bytes":
        (lab.jobs / f"{job['label']}.plist").write_bytes(b"changed after interruption")
    else:
        directory = Path(manifest[scope]["directory"])
        (
            directory / "releases" / lab.old["release_id"] / "launchd" / f"{job['label']}.plist"
        ).write_bytes(b"changed retained release")
    recorded = lab.state()
    calls = len(lab.tools.calls)
    with pytest.raises((DeploymentError, OSError)):
        lab.rollback(runner)
    assert lab.state() == recorded
    assert all(call[1] == "print" for call in lab.tools.calls[calls:])

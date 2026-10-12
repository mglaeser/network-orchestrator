"""Unknown old-job removal cannot commit a successor or delete recovery evidence."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch.deployment import install_bundle, recover_install, rollback_install
from netorch.deployment_config import DeploymentError
from netorch.process import ProcessTimeout, Result
from netorch.state import intent_from_dict, intent_to_dict
from netorch.storage import Store
from tests.test_deployment import config, fake_platform, make_bundle, manifest
from tests.test_deployment_bootout_wait import (
    BOUND,
    FAILED,
    UNCONFIRMED,
    Clock,
    Launchd,
    changed,
    label_of,
    with_second_user_job,
)

__all__ = ["config", "fake_platform", "manifest"]


@pytest.mark.parametrize("operation", ["upgrade", "rollback", "recover", "first-recover"])
@pytest.mark.parametrize("observation", ["present", "denied", "timeout"])
def test_uncertain_retired_job_preserves_files_receipt_hold_and_explicit_recovery(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    operation: str,
    observation: str,
) -> None:
    tools, clock = Launchd(), Clock()
    kept = label_of(manifest, "user")
    retired = kept + "-second"
    agents = Path(manifest["user"]["launchd_directory"])
    state = Store(Path(manifest["user"]["state_directory"]))
    timing = {"clock": clock, "sleep": clock.sleep}
    invoke: Callable[[], dict[str, Any]]

    if operation == "upgrade":
        first, old = make_bundle(tmp_path, with_second_user_job(manifest), config, "first")
        install_bundle(first, "user", expected_digest=old["bundle_digest"], runner=tools)
        second, new = make_bundle(tmp_path, changed(manifest, "user"), config, "second")
        holder = new["bundle_digest"]

        def invoke() -> dict[str, Any]:
            return install_bundle(second, "user", expected_digest=holder, runner=runner, **timing)

    else:
        if operation != "first-recover":
            first, old = make_bundle(tmp_path, manifest, config, "first")
            install_bundle(first, "user", expected_digest=old["bundle_digest"], runner=tools)
        second, new = make_bundle(
            tmp_path, with_second_user_job(changed(manifest, "user"), first=True), config, "second"
        )
        holder = new["bundle_digest"]
        if operation == "rollback":
            install_bundle(second, "user", expected_digest=holder, runner=tools)

            def invoke() -> dict[str, Any]:
                return rollback_install(
                    state.directory, "user", expected_current_digest=holder, runner=runner, **timing
                )

        else:
            # The added job loads; the kept job fails to start. Recovery must
            # retire the added job before deleting files or restoring anything.
            tools.fail = str(agents / f"{kept}.plist")
            with pytest.raises(DeploymentError, match=FAILED):
                install_bundle(second, "user", expected_digest=holder, runner=tools)
            tools.fail = None

            def invoke() -> dict[str, Any]:
                return recover_install(
                    state.directory, "user", expected_failed_digest=holder, runner=runner, **timing
                )

    intent = (
        intent_from_dict(state.read("intent.json")).pause().suspend("other-operation", "a" * 64)
    )
    state.write("intent.json", intent_to_dict(intent))
    before_files = {path.name: path.read_bytes() for path in agents.glob("*.plist")}
    receipt = state.directory / "installation-receipt.json"
    before_receipt = receipt.read_bytes() if receipt.exists() else None
    tools.calls.clear()
    blocked = True

    def runner(argv: tuple[str, ...]) -> Result:
        if argv[1] == "bootout":
            tools.linger = None if blocked and argv[2].endswith("/" + retired) else 0
        if argv[1] == "print" and argv[2].endswith("/" + retired) and blocked:
            tools.calls.append(argv)
            if observation == "timeout":
                raise ProcessTimeout("private diagnostic must not become success")
            return Result(0 if observation == "present" else 1, b"", b"")
        return tools(argv)

    with pytest.raises(DeploymentError, match=UNCONFIRMED):
        invoke()
    assert sum(clock.slept) == BOUND
    assert {path.name: path.read_bytes() for path in agents.glob("*.plist")} == before_files
    assert (receipt.read_bytes() if receipt.exists() else None) == before_receipt
    assert not any(argv[1] == "bootstrap" for argv in tools.calls)
    held = intent_from_dict(state.read("intent.json"))
    assert held.operator_paused
    assert held.suspensions == {"other-operation": "a" * 64, "installation": holder}
    assert state.read("installation-journal.json")["phase"] == "failed"

    # An explicit recovery is a new caller action, not automatic rollback.
    # The fake job now genuinely disappears. Its second bootout says absent,
    # so a fresh print is still required rather than trusting that exit status.
    blocked = False
    tools.leaving.clear()
    tools.calls.clear()
    if operation == "upgrade":
        result = recover_install(
            state.directory, "user", expected_failed_digest=holder, runner=runner, **timing
        )
    else:
        result = invoke()
    assert result["phase"] == "rolled-back"
    assert tools.about(retired)[:2] == ["bootout", "print"]
    retained = intent_from_dict(state.read("intent.json"))
    assert retained.operator_paused and retained.suspensions == {"other-operation": "a" * 64}


@pytest.mark.parametrize("already_absent", [False, True])
def test_absence_returned_after_the_polling_window_does_not_authorize_progress(
    already_absent: bool,
) -> None:
    clock = Clock()
    calls = []

    def runner(argv: tuple[str, ...]) -> Result:
        calls.append(argv)
        if argv[1] == "bootout":
            return Result(113 if already_absent else 0, b"", b"")
        clock.now += BOUND + 1
        return Result(113, b"", b"")

    with pytest.raises(DeploymentError, match=UNCONFIRMED):
        implementation._bootout(
            runner, "/bin/launchctl", "system/example.owner", clock=clock, sleep=clock.sleep
        )
    assert [argv[1] for argv in calls] == ["bootout", "print"]
    assert not clock.slept


def test_already_absent_bootout_does_not_hide_a_lingering_job() -> None:
    tools, clock = Launchd(), Clock()
    tools.leaving["example.owner"] = None
    with pytest.raises(DeploymentError, match=UNCONFIRMED):
        implementation._bootout(
            tools, "/bin/launchctl", "system/example.owner", clock=clock, sleep=clock.sleep
        )
    assert sum(clock.slept) == BOUND
    assert tools.leaving == {"example.owner": None}

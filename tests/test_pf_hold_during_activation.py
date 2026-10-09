"""A hold that arrives between a pass's plan and its activation of that service.

A hold on one service is read again before each activation, like a pause: the
profile is deferred with the reason `inhibited`, nothing is written for it, the
pass does not fail and no acknowledgement is owed, and the pass after the
release activates it. A hold stored after that read, while the activation's
other checks run, is noticed by the next pass, which retires the rule.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from netorch.pf_owner import reconcile
from netorch.state import Intent, intent_to_dict
from netorch.storage import Store
from tests.test_pf_owner import STAMP, FakeBackend, approve_all, environment, run_pass
from tests.test_service_holds import holding

__all__ = ["environment"]


def test_a_hold_that_lands_after_the_plan_defers_the_activation(
    environment: Any, tmp_path: Path
) -> None:
    root, _, _, backend, snapshots = environment
    approve_all(environment)
    user = Store(tmp_path / "user-state")
    user.write("intent.json", intent_to_dict(Intent()))
    installation = root.read("installation.json")
    installation["intent_path"] = str(user.directory / "intent.json")
    root.write("installation.json", installation)
    observed = 0

    def observe(config: Any, settings: Any) -> Any:
        nonlocal observed
        observed += 1
        if observed == 1:
            # The pass has read the intent it plans with; the hold lands now.
            held = holding(Intent(1), "resolver", "restart", "manager")
            user.write("intent.json", intent_to_dict(held))
        return snapshots[-1]

    result = reconcile(
        root,
        observe,
        lambda root, settings: backend,
        now=lambda: STAMP,
        report=lambda settings, snapshot: None,
    )

    assert result["phase"] == "inhibited"
    assert result["deferred"] == {"dns-tcp": "inhibited", "dns-udp": "inhibited"}
    assert root.read("journal.json")["phase"] == "inhibited"
    # The profiles of the other services were activated in the same pass.
    assert {"media-udp:activate", "proxy-standard:activate"} <= set(result["changed"])
    assert not any(item.startswith("dns-") for item in result["changed"])
    assert "dns-" not in backend.rules

    # Released: the next pass activates the resolver's profiles; nothing was owed.
    user.write("intent.json", intent_to_dict(Intent(2)))
    released = run_pass(environment)
    assert released["phase"] == "committed"
    assert {"dns-tcp:activate", "dns-udp:activate"} <= set(released["changed"])


def test_a_hold_stored_during_the_activation_checks_is_retired_by_the_next_pass(
    environment: Any, tmp_path: Path
) -> None:
    root, config, settings, _, snapshots = environment
    user = Store(tmp_path / "user-state")
    user.write("intent.json", intent_to_dict(Intent()))

    class LateHold(FakeBackend):
        """Stores the hold while the first resolver profile's endpoint is checked."""

        stored = False

        def endpoint(self, scope: Any, ipv4: str, mac: Any, *, direct: bool) -> bool:
            if ipv4 == "198.51.100.10" and not self.stored:
                self.stored = True
                held = holding(Intent(1), "resolver", "restart", "manager")
                user.write("intent.json", intent_to_dict(held))
            return super().endpoint(scope, ipv4, mac, direct=direct)

    backend = LateHold()
    environment = (root, config, settings, backend, snapshots)
    approve_all(environment)
    installation = root.read("installation.json")
    installation["intent_path"] = str(user.directory / "intent.json")
    root.write("installation.json", installation)

    result = run_pass(environment)

    # The first resolver profile had read the inhibition before the hold was
    # stored: it is loaded. The second reads it afterwards and is deferred.
    assert "dns-tcp:activate" in result["changed"]
    assert "netorch:dns-tcp" in backend.rules
    assert result["deferred"] == {"dns-udp": "inhibited"}

    following = run_pass(environment)

    assert following["phase"] == "inhibited"
    assert following["changed"] == ["dns-tcp:withdraw", "dns-tcp:drain"]
    assert "netorch:dns-" not in backend.rules

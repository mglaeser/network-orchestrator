"""A hold that arrives between a pass's plan and its activation (#78 beside #77).

#78 holds one service in the durable intent. #77 reads the inhibition again before
each activation and defers that profile instead of failing the pass. Together, a
hold that lands after the plan was made stops the activation the way a pause does:
the profile is deferred as `inhibited`, the pass does not fail, no acknowledgement
is owed, and the pass after the release activates it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from netorch.pf_owner import reconcile
from netorch.state import Intent, intent_to_dict
from netorch.storage import Store
from tests.test_pf_owner import STAMP, approve_all, environment, run_pass  # noqa: F401
from tests.test_service_holds import holding


def test_a_hold_that_lands_after_the_plan_defers_the_activation(
    environment: Any,  # noqa: F811
    tmp_path: Path,
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

    # Released: the next pass activates the resolver's profiles; nothing was owed.
    user.write("intent.json", intent_to_dict(Intent(2)))
    released = run_pass(environment)
    assert released["phase"] == "committed"
    assert {"dns-tcp:activate", "dns-udp:activate"} <= set(released["changed"])

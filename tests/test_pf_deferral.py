"""A precondition that is not met defers one profile; a write in doubt still fails the pass.

Every kernel and runtime tool is a fake. Addresses are documentation values.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Any

import pytest

import netorch.pf_owner as owner
from netorch.codec import canonical_bytes
from netorch.config import to_dict
from netorch.model import Config, Profile, Scope
from netorch.pf_owner import PFError, reconcile
from netorch.state import Intent, Observation, Snapshot, intent_to_dict, snapshot_to_dict
from tests.test_pf_own_states import Kernel
from tests.test_pf_owner import STAMP, FakeBackend, approve_all, environment
from tests.test_pf_withdraw_order import active, address, owned

__all__ = ["environment"]

EVERY_PROFILE = ("dns-tcp", "dns-udp", "media-udp", "proxy-standard")
CLIENT_STATE = "all udp 192.0.2.77:54321 -> {guest}:53 NO_TRAFFIC:SINGLE"


def observed_pass(environment: Any, observe: Any = None) -> tuple[dict[str, Any], Snapshot]:
    """One pass: its result and the snapshot it handed to its report writer."""
    root, _, _, backend, snapshots = environment
    reports: list[Snapshot] = []
    result = reconcile(
        root,
        observe or (lambda config, settings: snapshots[-1]),
        lambda root, settings: backend,
        now=lambda: STAMP,
        report=lambda settings, snapshot: reports.append(snapshot),
    )
    return result, reports[-1]


def assert_deferred(
    environment: Any, result: dict[str, Any], report: Snapshot, expected: dict[str, str]
) -> None:
    """The journal, the result and the report name the same profiles and reasons.

    A deferred profile has no rule loaded and is not reported ready.
    """
    root, _, _, backend, _ = environment
    assert result["deferred"] == expected
    assert set(result) == {"schema_version", "phase", "changed", "pending", "deferred"}
    journal = root.read("journal.json")
    assert journal["deferred"] == expected and journal["phase"] == result["phase"]
    assert set(journal) == {"schema_version", "phase", "actions", "finished_at", "deferred"}
    assert expected and set(expected.values()) <= owner.DEFERRAL_REASONS
    assert {
        key: item.data["deferred"]
        for key, item in report.profiles.items()
        if "deferred" in item.data
    } == expected
    assert result["phase"] != "committed"
    for key in expected:
        assert key in result["pending"]
        assert key not in owned(backend)
        assert report.profiles[key].state == "absent"
        assert report.profiles[key].data["root_ready"] is False


def assert_nothing_deferred(environment: Any, result: dict[str, Any], report: Snapshot) -> None:
    assert "deferred" not in result
    assert "deferred" not in environment[0].read("journal.json")
    assert all("deferred" not in item.data for item in report.profiles.values())


def acknowledge(root: Any) -> None:
    journal = root.read("journal.json")
    assert journal["phase"] == "failed"
    journal["phase"] = "acknowledged"
    root.write("journal.json", journal)


def test_deferral_reasons_are_one_closed_vocabulary() -> None:
    assert sorted(owner.DEFERRAL_REASONS) == [
        "endpoint-unverified",
        "evidence-unavailable",
        "inhibited",
        "not-admitted",
        "ports-unverified",
        "states-retained",
        "target-changed",
    ]
    assert isinstance(owner.DEFERRAL_REASONS, frozenset)
    assert list(owner._deferrals({"b": "inhibited", "a": "states-retained"}).items()) == [
        ("a", "states-retained"),
        ("b", "inhibited"),
    ]
    assert owner._deferrals({}) == {}
    with pytest.raises(PFError, match="unknown deferral reason"):
        owner._deferrals({"a": "failed"})


def test_one_unverified_target_defers_only_its_profiles(environment: Any) -> None:
    approve_all(environment)
    root, _, _, backend, _ = environment
    backend.unavailable_guests = {address(environment, "resolver")}

    result, report = observed_pass(environment)

    assert result["phase"] == "inhibited"
    assert_deferred(
        environment,
        result,
        report,
        {"dns-tcp": "endpoint-unverified", "dns-udp": "endpoint-unverified"},
    )
    assert result["pending"] == ["dns-tcp", "dns-udp"]
    # The pass went on with the other profiles: they are loaded and ready.
    assert owned(backend) == ["media-udp", "media-udp", "proxy-standard"]
    assert sorted(result["changed"]) == ["media-udp:activate", "proxy-standard:activate"]
    for key in ("media-udp", "proxy-standard"):
        assert report.profiles[key].data["root_ready"] is True
    assert root.read("journal.json")["phase"] == "inhibited"
    # Each target was checked once: nothing is retried inside a pass.
    assert sum(command[0] == "endpoint" for command in backend.commands) == 4

    # No acknowledgement is owed. The next pass reads everything again.
    backend.unavailable_guests = set()
    result, report = observed_pass(environment)

    assert result["phase"] == "committed" and result["pending"] == []
    assert_nothing_deferred(environment, result, report)
    assert sorted(result["changed"]) == ["dns-tcp:activate", "dns-udp:activate"]
    assert all(item.data["root_ready"] is True for item in report.profiles.values())


def test_an_occupied_port_defers_and_reports_why(environment: Any) -> None:
    approve_all(environment)
    root, _, _, backend, _ = environment
    backend.clear = False

    result, report = observed_pass(environment)

    assert result["phase"] == "inhibited" and backend.rules == ""
    assert_deferred(environment, result, report, dict.fromkeys(EVERY_PROFILE, "ports-unverified"))
    assert result["pending"] == list(EVERY_PROFILE) and result["changed"] == []
    assert not any(command[0] in {"replace", "reference"} for command in backend.commands)
    # Nothing was written for any profile: no record was ever stored.
    assert not (root.directory / "live.json").exists()


def test_pending_lists_the_plans_own_entries_before_the_deferred_profiles(
    environment: Any,
) -> None:
    approve_all(environment)
    root, _, _, backend, _ = environment
    admissions = root.read("admissions.json")
    del admissions["profiles"]["proxy-standard"]
    root.write("admissions.json", admissions)
    backend.clear = False

    result, report = observed_pass(environment)

    assert_deferred(
        environment,
        result,
        report,
        dict.fromkeys(("dns-tcp", "dns-udp", "media-udp"), "ports-unverified"),
    )
    assert result["pending"] == ["proxy-standard", "dns-tcp", "dns-udp", "media-udp"]


class FailingChecks(FakeBackend):
    """A kernel check that raises instead of answering."""

    def __init__(self, failing: str, error: Exception) -> None:
        super().__init__()
        self.failing: str | None = failing
        self.error = error

    def endpoint(self, scope: Scope, ipv4: str, mac: str | None, *, direct: bool) -> bool:
        if self.failing == "endpoint":
            raise self.error
        return super().endpoint(scope, ipv4, mac, direct=direct)

    def ports_clear(self, scope: Scope, profile: Profile, *, apple_dns: bool) -> bool:
        if self.failing == "ports":
            raise self.error
        return super().ports_clear(scope, profile, apple_dns=apple_dns)


@pytest.mark.parametrize("failing", ["endpoint", "ports"])
@pytest.mark.parametrize(
    "error",
    [PFError("native kernel observation is unknown"), OSError("no such tool"), ValueError("x")],
    ids=["owner-error", "os-error", "value-error"],
)
def test_a_check_that_raises_is_a_check_that_did_not_pass(
    environment: Any, failing: str, error: Exception
) -> None:
    root, config, settings, _, snapshots = environment
    backend = FailingChecks(failing, error)
    environment = (root, config, settings, backend, snapshots)
    approve_all(environment)

    result, report = observed_pass(environment)

    assert result["phase"] == "inhibited" and backend.rules == ""
    assert_deferred(
        environment, result, report, dict.fromkeys(EVERY_PROFILE, f"{failing}-unverified")
    )
    assert not any(command[0] in {"replace", "reference"} for command in backend.commands)

    backend.failing = None
    result, report = observed_pass(environment)
    assert result["phase"] == "committed"
    assert_nothing_deferred(environment, result, report)


def test_a_pause_that_arrives_during_a_pass_defers_the_rest(environment: Any) -> None:
    approve_all(environment)
    root, _, _, backend, snapshots = environment
    calls = 0

    def observe(config: Config, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        if calls == 3:  # the fresh read before the second activation
            root.write("operator-intent.json", intent_to_dict(Intent().pause()))
        return snapshots[-1]

    result, report = observed_pass(environment, observe)

    assert result["phase"] == "inhibited"
    assert_deferred(
        environment,
        result,
        report,
        {"dns-udp": "inhibited", "media-udp": "inhibited", "proxy-standard": "inhibited"},
    )
    # The first activation preceded the pause. The second read its evidence
    # and then found the pause; the others stopped before reading any.
    assert owned(backend) == ["dns-tcp"] and result["changed"] == ["dns-tcp:activate"]
    assert calls == 4
    assert report.profiles["dns-tcp"].state == "present"
    assert not any(item.data["root_ready"] for item in report.profiles.values())
    assert root.read("journal.json")["phase"] == "inhibited"

    # The next pass applies the pause to what was activated before it arrived.
    result, report = observed_pass(environment)
    assert result["phase"] == "inhibited" and backend.rules == ""
    assert result["changed"] == ["dns-tcp:withdraw", "dns-tcp:drain"]
    assert_nothing_deferred(environment, result, report)


def test_a_profile_whose_admission_is_withdrawn_during_a_pass_is_deferred(
    environment: Any,
) -> None:
    approve_all(environment)
    root, _, _, backend, snapshots = environment
    calls = 0

    def observe(config: Config, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        if calls == 2:  # while the first activation reads its evidence
            admissions = root.read("admissions.json")
            del admissions["profiles"]["dns-udp"]
            root.write("admissions.json", admissions)
        return snapshots[-1]

    result, report = observed_pass(environment, observe)

    assert result["phase"] == "inhibited"
    assert_deferred(environment, result, report, {"dns-udp": "not-admitted"})
    assert report.profiles["dns-udp"].data["admitted"] is False
    assert owned(backend) == ["dns-tcp", "media-udp", "media-udp", "proxy-standard"]

    result, report = observed_pass(environment)
    assert result["phase"] == "inhibited" and result["pending"] == ["dns-udp"]
    assert_nothing_deferred(environment, result, report)
    assert len(owned(backend)) == 4


@pytest.mark.parametrize(
    "error", [PFError("runtime inaccessible"), OSError("x")], ids=["owner", "os"]
)
def test_a_fresh_observation_that_fails_defers_one_profile(
    environment: Any, error: Exception
) -> None:
    approve_all(environment)
    _, _, _, backend, snapshots = environment
    calls = 0

    def observe(config: Config, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise error
        return snapshots[-1]

    result, report = observed_pass(environment, observe)

    assert result["phase"] == "inhibited"
    assert_deferred(environment, result, report, {"dns-tcp": "evidence-unavailable"})
    assert owned(backend) == ["dns-udp", "media-udp", "media-udp", "proxy-standard"]

    result, report = observed_pass(environment)
    assert result["phase"] == "committed" and result["changed"] == ["dns-tcp:activate"]
    assert_nothing_deferred(environment, result, report)


class FlickeringTable(FakeBackend):
    """A state table that cannot be read at the chosen reads of one pass."""

    def __init__(self, unreadable: set[int]) -> None:
        super().__init__()
        self.unreadable = unreadable
        self.reads = 0

    def states(self) -> str:
        self.reads += 1
        if self.reads in self.unreadable:
            return "WARNING: state inventory truncated"
        return super().states()


def test_a_state_table_that_cannot_be_read_before_one_activation_defers_it(
    environment: Any,
) -> None:
    root, config, settings, _, snapshots = environment
    backend = FlickeringTable({2})  # the fresh read before the first activation
    environment = (root, config, settings, backend, snapshots)
    approve_all(environment)

    result, report = observed_pass(environment)

    assert result["phase"] == "inhibited"
    assert_deferred(environment, result, report, {"dns-tcp": "evidence-unavailable"})
    assert owned(backend) == ["dns-udp", "media-udp", "media-udp", "proxy-standard"]


def test_a_state_table_that_stays_unreadable_is_unknown_for_every_profile(
    environment: Any,
) -> None:
    root, config, settings, _, snapshots = environment
    backend = FlickeringTable(set(range(2, 100)))  # readable at the start only
    environment = (root, config, settings, backend, snapshots)
    approve_all(environment)

    # No profile gets a rule, and the pass cannot end as a readable one.
    with pytest.raises(PFError, match="unsupported PF state observation"):
        observed_pass(environment)

    assert backend.rules == "" and root.read("journal.json")["phase"] == "failed"
    assert "deferred" not in root.read("journal.json")

    # From the first read of the next pass on it is the whole table that is unknown.
    backend.reads = 1
    result, report = observed_pass(environment)
    assert result["phase"] == "failed" and result["pending"] == sorted(EVERY_PROFILE)
    assert root.read("journal.json")["reason"] == "kernel-state-unknown"
    assert all(item.state == "unknown" for item in report.profiles.values())
    assert "deferred" not in result and "deferred" not in root.read("journal.json")


def test_a_target_that_changes_before_its_activation_is_deferred(environment: Any) -> None:
    approve_all(environment)
    _, _, _, backend, snapshots = environment
    current = snapshots[-1]
    services = dict(current.services)
    services["resolver"] = Observation(
        "present",
        "verified",
        STAMP,
        "instance-2",
        {**current.services["resolver"].data, "ipv4": "198.51.100.50"},
    )
    restarted = replace(current, services=services)
    calls = 0

    def observe(config: Config, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        if calls == 2:  # the guest restarts after the pass planned its actions
            snapshots.append(restarted)
        return snapshots[-1]

    result, report = observed_pass(environment, observe)

    assert result["phase"] == "inhibited"
    assert_deferred(
        environment, result, report, {"dns-tcp": "target-changed", "dns-udp": "target-changed"}
    )
    assert owned(backend) == ["media-udp", "media-udp", "proxy-standard"]

    result, report = observed_pass(environment)
    assert result["phase"] == "committed"
    assert_nothing_deferred(environment, result, report)
    assert backend.rules.count("-> 198.51.100.50 port 53") == 2


def test_a_state_that_cannot_be_invalidated_defers_only_its_profile(environment: Any) -> None:
    resolver = address(environment, "resolver")
    backend = Kernel({resolver}, lasting=[CLIENT_STATE.format(guest=resolver)])
    environment = active(environment, backend)
    root = environment[0]
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))

    result, report = observed_pass(environment)

    assert result["phase"] == "inhibited"
    assert_deferred(environment, result, report, {"dns-udp": "states-retained"})
    assert owned(backend) == []
    # The retired record stays, so the profile is at "drain only".
    records = root.read("live.json")["records"]
    assert set(records) == {"dns-udp"} and records["dns-udp"]["active"] is False
    assert report.profiles["dns-udp"].data["states"] == ("retained",)
    assert backend.kills == [resolver]

    # Resumed: the other profiles return at once. This one is still required
    # to be free of its client's state, and is invalidated again on each pass.
    root.write("operator-intent.json", intent_to_dict(Intent(2, False)))
    for attempt in (2, 3):
        result, report = observed_pass(environment)
        assert result["phase"] == "inhibited"
        assert_deferred(environment, result, report, {"dns-udp": "states-retained"})
        assert owned(backend) == ["dns-tcp", "media-udp", "media-udp", "proxy-standard"]
        assert backend.kills == [resolver] * attempt
        for key in ("dns-tcp", "media-udp", "proxy-standard"):
            assert report.profiles[key].data["root_ready"] is True

    backend.lasting.clear()
    result, report = observed_pass(environment)
    assert result["phase"] == "committed" and result["changed"] == ["dns-udp:activate"]
    assert_nothing_deferred(environment, result, report)
    assert len(owned(backend)) == 5 and backend.kills == [resolver] * 3


def test_a_retained_state_of_a_removed_profile_keeps_the_pass_uncommitted(
    environment: Any,
) -> None:
    resolver = address(environment, "resolver")
    backend = Kernel(lasting=[CLIENT_STATE.format(guest=resolver)])
    environment = active(environment, backend)
    root, config, _, _, _ = environment
    policy = to_dict(config)
    policy["profiles"] = [item for item in policy["profiles"] if item["id"] != "dns-udp"]
    root.write("policy.json", policy)

    result, report = observed_pass(environment)

    # Every profile the policy still has is verified, yet the pass is not
    # complete: the removed profile's record waits for its state to go.
    assert result["phase"] == "inhibited" and result["pending"] == ["dns-udp"]
    assert result["deferred"] == {"dns-udp": "states-retained"}
    assert root.read("journal.json")["deferred"] == {"dns-udp": "states-retained"}
    assert "dns-udp" not in report.profiles
    assert all(item.data["root_ready"] is True for item in report.profiles.values())
    assert owned(backend) == ["dns-tcp", "media-udp", "media-udp", "proxy-standard"]
    assert set(root.read("live.json")["records"]) == set(EVERY_PROFILE)

    backend.lasting.clear()
    result, report = observed_pass(environment)
    assert result["phase"] == "committed" and "dns-udp" not in root.read("live.json")["records"]
    assert_nothing_deferred(environment, result, report)


def test_a_pause_is_resumed_while_a_guest_keeps_a_connection_of_its_own(
    environment: Any,
) -> None:
    resolver = address(environment, "resolver")
    backend = Kernel({resolver})  # the guest is simply still running
    environment = active(environment, backend)
    root = environment[0]
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))

    for _ in range(3):
        result, report = observed_pass(environment)
        assert result["phase"] == "inhibited"
        assert_nothing_deferred(environment, result, report)
        assert owned(backend) == [] and root.read("live.json")["records"] == {}
        assert root.read("journal.json")["phase"] == "inhibited"
    # The pause emptied the anchor without one invalidation.
    assert backend.kills == [] and not any(c[0] == "drain" for c in backend.commands)

    root.write("operator-intent.json", intent_to_dict(Intent(2, False)))
    result, report = observed_pass(environment)

    # The first pass after the resume commits; no acknowledgement was owed.
    assert result["phase"] == "committed" and result["pending"] == []
    assert owned(backend) == ["dns-tcp", "dns-udp", "media-udp", "media-udp", "proxy-standard"]
    assert all(item.data["root_ready"] is True for item in report.profiles.values())
    assert backend.kills == []
    assert observed_pass(environment)[0]["phase"] == "committed"


def test_an_unavailable_final_observation_is_not_an_interrupted_write(environment: Any) -> None:
    approve_all(environment)
    root, _, _, backend, snapshots = environment
    assert observed_pass(environment)[0]["phase"] == "committed"
    calls = 0

    def observe(config: Config, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        if calls % 2 == 0:  # the final read of each pass
            raise PFError("runtime inaccessible")
        return snapshots[-1]

    result, report = observed_pass(environment, observe)

    assert result["phase"] == "inhibited" and result["changed"] == []
    assert result["pending"] == list(EVERY_PROFILE)
    assert_nothing_deferred(environment, result, report)
    journal = root.read("journal.json")
    assert journal["phase"] == "inhibited" and "failed_at" not in journal
    # The rules are as recorded; nothing is reported verified or ready.
    assert len(owned(backend)) == 5
    assert report.network_generation is None
    assert all(item.state == "present" for item in report.profiles.values())
    assert not any(item.data["root_ready"] for item in report.profiles.values())

    # A following healthy pass is an ordinary one: nothing was retired.
    replaces = sum(command[0] == "replace" for command in backend.commands)
    result, report = observed_pass(environment)
    assert result["phase"] == "committed" and result["changed"] == []
    assert sum(command[0] == "replace" for command in backend.commands) == replaces
    assert all(item.data["root_ready"] is True for item in report.profiles.values())


def test_a_runtime_that_stays_unreachable_retires_exposure_and_owes_nothing(
    environment: Any,
) -> None:
    approve_all(environment)
    root, _, _, backend, _ = environment
    assert observed_pass(environment)[0]["phase"] == "committed"

    def observe(config: Config, settings: Any) -> Snapshot:
        raise PFError("runtime inaccessible")

    # The first observation of a pass is unknown: known exposure is retired.
    for _ in range(2):
        result, report = observed_pass(environment, observe)
        assert result["phase"] == "inhibited" and backend.rules == ""
        assert root.read("live.json")["records"] == {}
        assert root.read("journal.json")["phase"] == "inhibited"
        assert_nothing_deferred(environment, result, report)

    # Reachable again, the profiles return from fresh evidence alone.
    assert observed_pass(environment)[0]["phase"] == "committed"
    assert len(owned(backend)) == 5


def test_an_admission_given_under_another_implementation_is_not_honoured(
    environment: Any, monkeypatch: Any
) -> None:
    """A release that changes what a pass does voids every earlier admission."""
    root, _, _, backend, _ = environment
    monkeypatch.setattr(owner, "implementation_digest", lambda: "e" * 64)
    approve_all(environment)  # approvals of the release that ran before
    monkeypatch.undo()

    result, report = observed_pass(environment)

    assert result["phase"] == "inhibited" and result["pending"] == list(EVERY_PROFILE)
    assert backend.rules == "" and not (root.directory / "live.json").exists()
    assert not any(item.data["admitted"] for item in report.profiles.values())
    assert_nothing_deferred(environment, result, report)

    approve_all(environment)
    assert observed_pass(environment)[0]["phase"] == "committed"


# case -> the error that ends the pass
WRITES_IN_DOUBT = {
    "interrupted-replace": "simulated interrupted write",
    "replace-readback-differs": "PF write readback did not match candidate",
    "candidate-not-journalled": "no space left on device",
    "records-not-written": "no space left on device",
    "reference-not-identified": "enable reference could not be identified",
    "protected-input-changed": "protected desired snapshot changed during pass",
    "admissions-unreadable": "root admission record is damaged",
    "final-readback-differs": "owned rules changed before final readback",
    "final-table-unreadable": "unsupported PF state observation",
    "report-not-written": "owner report destination is unsafe",
}


@pytest.mark.parametrize("case", WRITES_IN_DOUBT)
def test_a_write_in_doubt_still_ends_failed_and_needs_its_acknowledgement(
    environment: Any, monkeypatch: Any, case: str
) -> None:
    approve_all(environment)
    root, _, _, backend, snapshots = environment
    calls = 0
    original_write = root.write
    original_inspect = backend.inspect

    def observe(config: Config, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        if calls == 2 and case == "protected-input-changed":
            installation = root.read("installation.json")
            installation["interval_seconds"] = 11
            original_write("installation.json", installation)
        if calls == 2 and case == "admissions-unreadable":
            original_write("admissions.json", {"schema_version": True})
        if calls == 6 and case == "final-readback-differs":
            backend.rules += "rdr on lo0 inet proto tcp from any to any port 9 -> 192.0.2.99\n"
        if calls == 6 and case == "final-table-unreadable":
            backend.flow_states = "WARNING: state inventory truncated"
        return snapshots[-1]

    def write(name: str, value: Any) -> None:
        if case == "candidate-not-journalled" and "candidate_records" in value:
            raise OSError("no space left on device")
        if case == "records-not-written" and name == "live.json":
            raise OSError("no space left on device")
        original_write(name, value)

    def inspect() -> str:
        text = original_inspect()
        loaded = any(command[0] == "replace" for command in backend.commands)
        return text + "\nrdr unexpected" if case == "replace-readback-differs" and loaded else text

    def reference() -> None:
        raise PFError("new PF enable reference could not be identified")

    def report(settings: Any, snapshot: Snapshot) -> None:
        if case == "report-not-written":
            raise OSError("owner report destination is unsafe")

    if case == "interrupted-replace":
        backend.fail_after_replace = True
    if case == "reference-not-identified":
        monkeypatch.setattr(backend, "ensure_reference", reference)
    monkeypatch.setattr(root, "write", write)
    monkeypatch.setattr(backend, "inspect", inspect)

    with pytest.raises((PFError, OSError), match=WRITES_IN_DOUBT[case]):
        reconcile(root, observe, lambda root, settings: backend, now=lambda: STAMP, report=report)

    monkeypatch.undo()
    journal = root.read("journal.json")
    assert journal["phase"] == "failed" and "deferred" not in journal

    # Only an acknowledgement ends it: until then every pass retires what is
    # known and activates nothing, whatever a fake check would now answer.
    if case == "protected-input-changed":
        root.write("installation.json", environment[2].to_dict())
    if case == "admissions-unreadable":
        root.write(
            "admissions.json", {"schema_version": 1, "strategy": owner.STRATEGY, "profiles": {}}
        )
        approve_all(environment)
    if case == "final-readback-differs":
        backend.rules = "\n".join(line for line in backend.rules.splitlines() if "netorch:" in line)
    backend.flow_states = ""
    for _ in range(2):
        result, report_snapshot = observed_pass(environment)
        assert result["phase"] == "failed" and backend.rules == ""
        assert not any(item.data["root_ready"] for item in report_snapshot.profiles.values())
    acknowledge(root)
    assert observed_pass(environment)[0]["phase"] == "committed"


def test_a_deferral_is_recorded_beside_an_owed_acknowledgement(environment: Any) -> None:
    resolver = address(environment, "resolver")
    backend = Kernel(lasting=[CLIENT_STATE.format(guest=resolver)])
    environment = active(environment, backend)
    root = environment[0]
    journal = root.read("journal.json")
    journal["phase"] = "failed"
    root.write("journal.json", journal)

    result, report = observed_pass(environment)

    assert result["phase"] == "failed" and owned(backend) == []
    assert_deferred(environment, result, report, {"dns-udp": "states-retained"})
    assert root.read("journal.json")["phase"] == "failed"


# pass -> SHA-256 of journal.json, of the report payload and of the canonical result
BYTES_BEFORE = {
    "unadmitted": (
        "c2c57c6ac01c16d5102c93a9831c5b0be745a32e4a5ec22d2bc5f8bae66b1989",
        "d8dca26c30699c649d95b096c659be577249caab474f6b5198425642921ccccd",
        "ff4613bba64767cdb284841268d72b0ce2d0c69116797aa91d4bcb3f34b8aed9",
    ),
    "activating": (
        "94b9902c2845cc8e76b7c3555c1eab14579ac908a312ae73c2925ca09a2b7ad1",
        "44233b60b48edbcf8cb4d0feee20ca92f5209a6f0048cdbd00290f5718a8e29f",
        "d9dbca574e2061e1396a68a14b79cf71549913133f1ee2bc292f68b29a0b579b",
    ),
    "healthy": (
        "be3ba7d4eca7aa6122eab6172f7b918436a69b1c4fa013a03d1b9f77866df637",
        "44233b60b48edbcf8cb4d0feee20ca92f5209a6f0048cdbd00290f5718a8e29f",
        "4c96bade3c9b52d8d3f4959d358b558bc6b561998a22a3d77efd8cd9db518b2c",
    ),
    "pausing": (
        "9466c6fd4f2559d9fa2e22b72ba462f00c7e6328df3ed01df5ebcb8ec6b8cea9",
        "f350976d31df3ec0c1700ebeab14283626a27d49b5227733d0f33c8f56b5d712",
        "fdbaab8b6a39c3a158c4df7d77c3a2bece2b4647250ea5da74433bf3a9fb331e",
    ),
}


def digest_of(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def test_a_pass_without_a_deferral_writes_the_bytes_it_wrote_before(
    environment: Any, monkeypatch: Any
) -> None:
    """Journal, report and result of four ordinary passes, as literal digests.

    The digests were computed with this test body on the commit this change
    starts from. Two inputs that differ between source trees are pinned first:
    the implementation fingerprint and the digest of the backend script.
    """
    root, config, settings, backend, snapshots = environment
    monkeypatch.setattr(owner, "implementation_digest", lambda: "1" * 64)
    settings = replace(settings, backend_sha256="2" * 64)
    root.write("installation.json", settings.to_dict())
    environment = (root, config, settings, backend, snapshots)
    seen: dict[str, tuple[str, str, str]] = {}

    def record(name: str) -> None:
        result, report = observed_pass(environment)
        assert_nothing_deferred(environment, result, report)
        seen[name] = (
            digest_of((root.directory / "journal.json").read_bytes()),
            digest_of(canonical_bytes(snapshot_to_dict(report)) + b"\n"),
            digest_of(canonical_bytes(result)),
        )

    record("unadmitted")
    approve_all(environment)
    record("activating")
    record("healthy")
    resolver = address(environment, "resolver")
    backend.flow_states = CLIENT_STATE.format(guest=resolver)
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    record("pausing")

    assert backend.rules == "" and backend.flow_states == ""
    assert seen == BYTES_BEFORE

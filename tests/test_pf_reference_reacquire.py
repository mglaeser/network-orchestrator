"""Taking a lost PF enable reference again is the administrator's explicit choice.

Without the choice a pass only reads its reference back, as before. With it, a
pass that reads the reference back as not held takes it again once, under the
conditions of an activation. Everything native is a fake here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

import netorch.pf_owner as module
from netorch.codec import canonical_bytes, strict_loads
from netorch.model import Config
from netorch.pf_owner import Installation, PFError, admit, admitted_digest, reconcile
from netorch.state import Intent, Observation, Snapshot, intent_to_dict
from tests.test_pf_enable_reference import UNVERIFIED, Kernel, acquisitions, one_pass
from tests.test_pf_owner import STAMP, approve_all, environment, shell_backend

__all__ = ["environment"]

PROFILES = ["dns-tcp", "dns-udp", "media-udp", "proxy-standard"]

# Taken from the tree this change is based on: the stored form of the
# installation below, and its admitted digest for one profile with the
# implementation fingerprint and the profile digest pinned to the values used in
# `test_an_installation_without_the_decision_keeps_its_stored_form`.
PLAIN = (
    "site-forwarding",
    "com.apple/netorch.site-forwarding",
    {"schema_version": 1, "account": "example"},
    "0" * 64,
    "/reports/site-forwarding.json",
)
BASE_BYTES = (
    b'{"allow_apple_dns_coexistence":false,"anchor":"com.apple/netorch.site-forwarding",'
    b'"backend_sha256":"' + b"0" * 64 + b'","intent_path":null,"interval_seconds":10,'
    b'"observer":{"account":"example","schema_version":1},"owner":"site-forwarding",'
    b'"report_path":"/reports/site-forwarding.json","schema_version":1}'
)
BASE_DIGEST = "3e1c997edddc964857c42e6a3630cef1cffc9ad768bcee593690e9008c9762f7"


class Disabling(Kernel):
    """Another tool disabled PF: the reference stays gone until it is taken again."""

    def __init__(self, outcome: bool | BaseException = True) -> None:
        super().__init__()
        # What an acquisition does: the reference is held again, or nothing
        # changes, or the acquisition raises.
        self.outcome = outcome

    def ensure_reference(self) -> None:
        super().ensure_reference()
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        if self.outcome:
            self.held = True


def converged(environment: Any, kernel: Kernel, *, reacquire: bool = True) -> Any:
    root, config, settings, _, snapshots = environment
    if reacquire:
        settings = replace(settings, enable_reference="reacquire")
        root.write("installation.json", settings.to_dict())
    environment = (root, config, settings, kernel, snapshots)
    approve_all(environment)
    result, report = one_pass(environment, kernel)
    assert result["phase"] == "committed" and len(result["changed"]) == 4
    assert ready(report) == PROFILES and acquisitions(kernel) == 4
    return environment


def ready(report: Snapshot) -> list[str]:
    return sorted(key for key, item in report.profiles.items() if item.data["root_ready"] is True)


def observed_pass(
    environment: Any, kernel: Kernel, observe: Callable[[int], Snapshot | None]
) -> tuple[dict[str, Any], Snapshot]:
    """One pass whose observer may answer each of its calls differently."""
    root, _, _, _, snapshots = environment
    reports: list[Snapshot] = []
    calls = 0

    def observer(config: Config, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        return observe(calls) or snapshots[-1]

    result = reconcile(
        root,
        observer,
        lambda root, settings: kernel,
        now=lambda: STAMP,
        report=lambda settings, snapshot: reports.append(snapshot),
    )
    return result, reports[-1]


def unverified(environment: Any, kernel: Kernel, result: dict[str, Any], report: Snapshot) -> None:
    """Exactly the outcome of a readback that does not verify, without the setting."""
    journal = environment[0].read("journal.json")
    assert result["phase"] == "inhibited" and result["changed"] == []
    assert sorted(result) in (
        ["changed", "pending", "phase", "schema_version"],
        ["changed", "pending", "phase", "reference", "schema_version"],
    )
    assert journal["phase"] == "inhibited" and journal["reason"] == UNVERIFIED
    assert ready(report) == []
    assert all(item.data["admitted"] is True for item in report.profiles.values())


# ------------------------------------------------------------------ the stored decision


def test_an_installation_without_the_decision_keeps_its_stored_form(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = environment[1]
    profile = config.profile("dns-udp")
    monkeypatch.setattr(module, "implementation_digest", lambda: "f" * 64)
    monkeypatch.setattr(module, "profile_digest", lambda config, profile: "e" * 64)
    plain = Installation(*PLAIN)

    assert plain.enable_reference == "verify"
    assert len(plain.to_dict()) == 9 and "enable_reference" not in plain.to_dict()
    assert canonical_bytes(plain.to_dict()) == BASE_BYTES
    assert Installation.from_dict(strict_loads(BASE_BYTES)) == plain
    assert admitted_digest(config, profile, plain) == BASE_DIGEST

    chosen = replace(plain, enable_reference="reacquire")
    assert chosen.to_dict() == {**plain.to_dict(), "enable_reference": "reacquire"}
    assert Installation.from_dict(strict_loads(canonical_bytes(chosen.to_dict()))) == chosen
    assert admitted_digest(config, profile, chosen) != BASE_DIGEST


@pytest.mark.parametrize(
    "value",
    ["verify", None, "never", "Reacquire", "reacquire ", "", True, 1, ["reacquire"], {}],
)
def test_reacquire_is_the_only_decision_that_can_be_written(environment: Any, value: Any) -> None:
    raw = environment[2].to_dict()
    with pytest.raises(PFError, match="unsupported installation schema"):
        Installation.from_dict({**raw, "enable_reference": value})
    with pytest.raises(PFError, match="unsupported installation schema"):
        Installation.from_dict({**raw, "enable_reference": "reacquire", "reference": "reacquire"})
    if value != "verify":
        with pytest.raises(PFError, match="enable-reference"):
            Installation(*PLAIN, enable_reference=value)


@pytest.mark.parametrize("chosen", [True, False], ids=["chosen", "taken back"])
def test_changing_the_decision_voids_every_admission(environment: Any, chosen: bool) -> None:
    kernel = Disabling()
    environment = converged(environment, kernel, reacquire=not chosen)
    root, _, settings, _, _ = environment
    changed = replace(settings, enable_reference="reacquire" if chosen else "verify")
    root.write("installation.json", changed.to_dict())

    result, report = one_pass(environment, kernel)

    assert result["phase"] == "inhibited" and sorted(result["pending"]) == PROFILES
    assert kernel.rules == "" and ready(report) == []
    assert all(item.data["admitted"] is False for item in report.profiles.values())


def test_an_admission_shows_the_decision_it_covers(environment: Any) -> None:
    root, _, settings, _, _ = environment
    shown = admit(root, "dns-udp", acknowledge_bounded_risk=True)["resolved"]
    # Without the decision the admission prints what it printed before.
    assert "enable_reference" not in shown
    root.write("installation.json", replace(settings, enable_reference="reacquire").to_dict())
    shown = admit(root, "dns-udp", acknowledge_bounded_risk=True)["resolved"]
    assert shown["enable_reference"] == "reacquire"


def test_the_review_shows_the_decision_only_where_it_was_made(
    environment: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import netorch.storage as storage

    root, _, settings, _, _ = environment
    # The entry point's boundary is replaced as the existing test of this command does.
    monkeypatch.setattr(module, "require_mutation_qualified", lambda _capability: None)
    monkeypatch.setattr(module.sys, "platform", "darwin")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module, "Store", lambda directory: root)
    monkeypatch.setattr(module, "protected_ancestors", lambda *a, **kw: None)
    monkeypatch.setattr(module, "protected_code", lambda *a, **kw: None)
    monkeypatch.setattr(storage.Store, "_check_directory_info", staticmethod(lambda info: None))
    monkeypatch.setattr(storage, "_check_file", lambda fd: None)
    command = ["review-admission", "--root-dir", str(root.directory), "--profile", "dns-udp"]

    assert module.main(command) == 0
    plain = strict_loads(capsys.readouterr().out)
    root.write("installation.json", replace(settings, enable_reference="reacquire").to_dict())
    assert module.main(command) == 0
    chosen = strict_loads(capsys.readouterr().out)

    # Without the decision the review prints the members it printed before.
    assert "enable_reference" not in plain
    assert chosen["enable_reference"] == "reacquire"
    assert chosen["expected_digest"] != plain["expected_digest"]
    assert {**chosen, "expected_digest": plain["expected_digest"]} == {
        **plain,
        "enable_reference": "reacquire",
    }


# ------------------------------------------------------------------ without the decision


@pytest.mark.parametrize("outcome", [True, False], ids=["would help", "would not help"])
def test_without_the_decision_a_pass_still_acquires_nothing(
    environment: Any, outcome: bool
) -> None:
    kernel = Disabling(outcome)
    environment = converged(environment, kernel, reacquire=False)
    loaded = kernel.rules
    kernel.held = False

    for _ in range(2):
        result, report = one_pass(environment, kernel)
        unverified(environment, kernel, result, report)
    assert acquisitions(kernel) == 4 and kernel.rules == loaded


# ------------------------------------------------------------------ with the decision


def test_a_reference_that_is_not_held_is_taken_again_once_and_the_pass_is_ready(
    environment: Any,
) -> None:
    kernel = Disabling()
    environment = converged(environment, kernel)
    root = environment[0]
    loaded = kernel.rules
    kernel.held = False  # another tool disabled PF: the kernel lists no token any more
    mark, reads = len(kernel.commands), kernel.readbacks

    result, report = one_pass(environment, kernel)

    assert result == {
        "schema_version": 1,
        "phase": "committed",
        "changed": [],
        "pending": [],
        "reference": "reacquired",
    }
    journal = root.read("journal.json")
    assert journal["phase"] == "committed" and "reason" not in journal
    assert ready(report) == PROFILES
    # One acquisition between two readbacks, and nothing else was changed.
    assert kernel.commands[mark:].count(("reference",)) == 1
    assert kernel.readbacks == reads + 2
    assert kernel.rules == loaded
    assert not any(command[0] in {"replace", "drain"} for command in kernel.commands[mark:])

    mark = len(kernel.commands)
    assert one_pass(environment, kernel)[0] == {
        "schema_version": 1,
        "phase": "committed",
        "changed": [],
        "pending": [],
    }
    assert ("reference",) not in kernel.commands[mark:]


def test_an_acquisition_that_does_not_help_leaves_the_unverified_outcome(environment: Any) -> None:
    kernel = Disabling()
    environment = converged(environment, kernel)
    loaded = kernel.rules
    kernel.held, kernel.outcome = False, False
    start = len(kernel.commands)

    for attempt in (1, 2):
        mark, reads = len(kernel.commands), kernel.readbacks
        result, report = one_pass(environment, kernel)
        unverified(environment, kernel, result, report)
        assert result["reference"] == "reacquired"
        # Never more than one acquisition in a pass.
        assert kernel.commands[mark:].count(("reference",)) == 1, attempt
        assert kernel.readbacks == reads + 2
    assert kernel.rules == loaded
    assert not any(command[0] in {"replace", "drain"} for command in kernel.commands[start:])

    kernel.outcome = True
    result, report = one_pass(environment, kernel)
    assert result["phase"] == "committed" and ready(report) == PROFILES


@pytest.mark.parametrize(
    "error",
    [PFError("new PF enable reference could not be identified"), OSError("no space left")],
    ids=["unidentified token", "record not written"],
)
def test_an_acquisition_that_raises_ends_the_pass_like_a_failed_activation(
    environment: Any, error: BaseException
) -> None:
    kernel = Disabling()
    environment = converged(environment, kernel)
    root = environment[0]
    loaded = kernel.rules
    kernel.held, kernel.outcome = False, error

    with pytest.raises(type(error), match=str(error)):
        one_pass(environment, kernel)

    journal = root.read("journal.json")
    assert journal["phase"] == "failed" and "failed_at" in journal
    assert kernel.rules == loaded and acquisitions(kernel) == 5
    # A reference may have been taken without being recorded: no pass tries
    # again by itself. The failure is retired and waits for its acknowledgement.
    for _ in range(3):
        result, report = one_pass(environment, kernel)
        assert result["phase"] == "failed" and ready(report) == []
    assert kernel.rules == "" and acquisitions(kernel) == 5

    kernel.outcome = True
    journal = root.read("journal.json")
    journal["phase"] = "acknowledged"
    root.write("journal.json", journal)
    result, report = one_pass(environment, kernel)
    assert result["phase"] == "committed" and ready(report) == PROFILES


@pytest.mark.parametrize(
    "answer",
    [
        True,
        PFError("bounded PF backend operation failed"),
        OSError("backend unavailable"),
        ValueError("undecodable backend output"),
        0,
        None,
        "no",
    ],
    ids=[
        "held",
        "read failed or PF not enabled",
        "unavailable",
        "undecodable",
        "0",
        "null",
        "text",
    ],
)
def test_only_a_complete_read_that_shows_the_reference_as_not_held_acquires(
    environment: Any, answer: Any
) -> None:
    kernel = Disabling()
    environment = converged(environment, kernel)
    loaded = kernel.rules
    kernel.held = answer

    for _ in range(2):
        result, report = one_pass(environment, kernel)
        if answer is True:
            assert result["phase"] == "committed" and ready(report) == PROFILES
        else:
            unverified(environment, kernel, result, report)
    assert acquisitions(kernel) == 4 and kernel.rules == loaded


@pytest.mark.parametrize(
    "intent",
    [
        intent_to_dict(Intent().pause()),
        intent_to_dict(Intent().suspend("upgrade", "holder")),
        {"schema_version": 999},
    ],
    ids=["paused", "suspended", "damaged"],
)
def test_a_pass_that_ends_inhibited_does_not_take_the_reference(
    environment: Any, intent: dict[str, Any]
) -> None:
    kernel = Disabling()
    environment = converged(environment, kernel)
    root = environment[0]
    loaded = kernel.rules
    kernel.held = False

    def observe(call: int) -> None:
        # The inhibition arrives while the pass runs: its final read sees it.
        if call == 2:
            root.write("operator-intent.json", intent)

    result, report = observed_pass(environment, kernel, observe)

    # The rules are retired by the next pass; this one must not enable PF for them.
    assert result["phase"] == "inhibited" and ready(report) == []
    assert root.read("journal.json")["reason"] == UNVERIFIED
    assert acquisitions(kernel) == 4 and kernel.rules == loaded
    result, _ = one_pass(environment, kernel)
    assert result["phase"] == "inhibited" and kernel.rules == ""
    assert acquisitions(kernel) == 4


def test_an_inhibition_that_appears_after_the_final_plan_still_prevents_the_acquisition(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = Disabling()
    environment = converged(environment, kernel)
    root = environment[0]
    kernel.held = False
    readback = kernel.reference_held

    def pausing() -> bool:
        root.write("operator-intent.json", intent_to_dict(Intent().pause()))
        return readback()

    monkeypatch.setattr(kernel, "reference_held", pausing)

    result, report = one_pass(environment, kernel)

    unverified(environment, kernel, result, report)
    assert acquisitions(kernel) == 4


@pytest.mark.parametrize("state", ["nothing admitted", "paused"])
def test_a_pass_that_leaves_no_rule_loaded_neither_reads_nor_takes_the_reference(
    environment: Any, state: str
) -> None:
    root, config, settings, _, snapshots = environment
    kernel = Disabling()
    kernel.held = False
    root.write("installation.json", replace(settings, enable_reference="reacquire").to_dict())
    environment = (root, config, settings, kernel, snapshots)
    if state == "paused":
        approve_all(environment)
        root.write("operator-intent.json", intent_to_dict(Intent().pause()))

    result, _ = one_pass(environment, kernel)

    assert result["phase"] == "inhibited" and sorted(result["pending"]) == PROFILES
    assert kernel.readbacks == 0 and acquisitions(kernel) == 0
    assert "reason" not in root.read("journal.json")


def test_a_pass_that_owes_an_acknowledgement_does_not_take_the_reference(environment: Any) -> None:
    kernel = Disabling()
    environment = converged(environment, kernel)
    root = environment[0]
    kernel.held = False
    journal = root.read("journal.json")
    journal["phase"] = "failed"
    root.write("journal.json", journal)

    for _ in range(2):
        result, report = one_pass(environment, kernel)
        assert result["phase"] == "failed" and ready(report) == []
    assert kernel.rules == "" and acquisitions(kernel) == 4


def without(snapshot: Snapshot, service: str | None) -> Snapshot:
    """The same observation with one service, or all of them, no longer verified."""
    if service is None:
        unknown = {
            key: Observation("unknown", "inaccessible", STAMP, None) for key in snapshot.services
        }
        return Snapshot(STAMP, None, unknown, {})
    services = dict(snapshot.services)
    services[service] = Observation("absent", "confirmed-absent", STAMP, None)
    return replace(snapshot, services=services)


@pytest.mark.parametrize(
    "lost,kept",
    [(None, []), ("resolver", ["media-udp", "proxy-standard"])],
    ids=["runtime unknown", "one guest absent"],
)
def test_pf_is_not_enabled_for_a_rule_that_the_final_evidence_no_longer_verifies(
    environment: Any, lost: str | None, kept: list[str]
) -> None:
    kernel = Disabling()
    environment = converged(environment, kernel)
    snapshots = environment[4]
    loaded = kernel.rules
    kernel.held = False
    changed = without(snapshots[-1], lost)

    # The evidence changes during the pass: only its final observation sees it.
    result, report = observed_pass(environment, kernel, lambda call: changed if call == 2 else None)

    assert result["phase"] == "inhibited" and ready(report) == []
    assert acquisitions(kernel) == 4 and kernel.rules == loaded
    # The next pass retires what is no longer verified, and only then, with
    # every rule it leaves loaded verified, takes the reference for the rest.
    snapshots.append(changed)
    result, report = one_pass(environment, kernel)
    assert ready(report) == kept
    assert acquisitions(kernel) == (5 if kept else 4)
    assert any(command[0] == "drain" for command in kernel.commands)


def test_a_pass_that_acquired_at_an_activation_does_not_acquire_again(environment: Any) -> None:
    root, config, settings, _, snapshots = environment
    kernel = Disabling(False)
    kernel.held = False
    root.write("installation.json", replace(settings, enable_reference="reacquire").to_dict())
    environment = (root, config, settings, kernel, snapshots)
    approve_all(environment)

    result, report = one_pass(environment, kernel)

    # Four activations, each with its acquisition; the readback then fails.
    assert len(result["changed"]) == 4 and result["phase"] == "inhibited"
    assert root.read("journal.json")["reason"] == UNVERIFIED and ready(report) == []
    assert acquisitions(kernel) == 4
    kernel.outcome = True
    result, report = one_pass(environment, kernel)
    assert result["phase"] == "committed" and ready(report) == PROFILES
    assert acquisitions(kernel) == 5


# ------------------------------------------------------------------ the owner's own reference code


class ShellReference(Kernel):
    """The owner's real reference methods over a fake `pfctl`: tokens and an enabled flag.

    Synthetic rows in the shape the owner's reader expects; not a capture of pfctl.
    """

    def __init__(self, environment: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        super().__init__()
        self.shell = shell_backend(environment, monkeypatch)
        monkeypatch.setattr(self.shell, "_call", self.call)
        self.tokens: list[str] = []
        self.enabled = False
        self.calls: list[str] = []

    def call(self, operation: str, *arguments: str) -> str:
        self.calls.append(operation)
        if operation == "references":
            return "\n".join(f"123 owner {token} 0 days 00:00:00" for token in self.tokens)
        if operation == "enabled":
            if not self.enabled:
                raise PFError("bounded PF backend operation failed")
            return ""
        assert operation == "enable" and not arguments
        token = str(4001 + len(self.calls))
        self.tokens.append(token)
        self.enabled = True
        return f"pf enabled\nToken : {token}"

    def disable(self) -> None:
        """What disabling PF does in the kernel: it stops and every token is void."""
        self.tokens.clear()
        self.enabled = False

    def ensure_reference(self) -> None:
        self.commands.append(("reference",))
        self.shell.ensure_reference()

    def reference_held(self) -> bool:
        self.readbacks += 1
        return bool(self.shell.reference_held())


@pytest.mark.parametrize("reacquire", [True, False], ids=["reacquire", "default"])
def test_after_pf_was_disabled_the_owner_reference_code_takes_one_new_token(
    environment: Any, monkeypatch: pytest.MonkeyPatch, reacquire: bool
) -> None:
    kernel = ShellReference(environment, monkeypatch)
    environment = converged(environment, kernel, reacquire=reacquire)
    root = environment[0]
    first = root.read("reference.json")["token"]
    assert kernel.tokens == [first] and kernel.calls.count("enable") == 1
    kernel.disable()
    kernel.calls.clear()

    result, report = one_pass(environment, kernel)

    if reacquire:
        assert kernel.calls == [
            "references",
            "references",
            "enable",
            "references",
            "enabled",
            "references",
            "enabled",
        ]
        second = root.read("reference.json")["token"]
        assert second != first and kernel.tokens == [second] and kernel.enabled
        assert result["phase"] == "committed" and ready(report) == PROFILES
    else:
        assert kernel.calls == ["references"]
        assert root.read("reference.json")["token"] == first and not kernel.enabled
        unverified(environment, kernel, result, report)


def test_a_listed_token_while_pf_is_not_shown_enabled_is_a_failed_read_not_a_lost_reference(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = ShellReference(environment, monkeypatch)
    environment = converged(environment, kernel)
    kernel.enabled = False
    kernel.calls.clear()

    result, report = one_pass(environment, kernel)

    assert kernel.calls == ["references", "enabled"]
    unverified(environment, kernel, result, report)


@pytest.mark.parametrize("reacquired", [True, False], ids=["reacquired", "healthy"])
def test_the_scheduled_job_logs_a_pass_that_took_the_reference_again(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Any,
    reacquired: bool,
) -> None:
    result = {"schema_version": 1, "phase": "committed", "changed": [], "pending": []}
    if reacquired:
        result["reference"] = "reacquired"
    # Only the output rule of the entry point is under test: the stage gate, the
    # root boundary and the pass itself are replaced, as other tests of `main` do.
    monkeypatch.setattr(module, "require_mutation_qualified", lambda operation: None)
    monkeypatch.setattr(module.sys, "platform", "darwin")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module, "protected_code", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "protected_ancestors", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "Store", lambda directory: object())
    monkeypatch.setattr(module, "reconcile", lambda root, observer, backend: result)

    assert module.main(["reconcile", "--root-dir", str(tmp_path)]) == 0

    printed = capsys.readouterr().out
    # A healthy pass that changed nothing stays silent, as before.
    assert (strict_loads(printed) == result) if reacquired else (printed == "")

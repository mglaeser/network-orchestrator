"""Every pass that leaves a rule loaded reads the owner's PF enable reference back."""

from __future__ import annotations

from typing import Any

import pytest

from netorch.pf_owner import PFError, admit, reconcile
from netorch.state import Intent, Snapshot, intent_to_dict
from tests.test_pf_owner import (
    STAMP,
    FakeBackend,
    approve_all,
    environment,
    shell_backend,
)

__all__ = ["environment"]

TOKEN = "18446744073709551615"
# Synthetic rows in the shape the owner's reader expects; not a capture of pfctl.
LISTED = f"TOKENS:\nPID Process Name TOKEN TIMESTAMP\n123 owner {TOKEN} 0 days 00:00:00"
UNVERIFIED = "enable-reference-unverified"


class Kernel(FakeBackend):
    """Fake kernel whose answer to the reference readback a test decides."""

    def __init__(self) -> None:
        super().__init__()
        self.held: bool | BaseException = True
        self.readbacks = 0

    def reference_held(self) -> bool:
        self.readbacks += 1
        if isinstance(self.held, BaseException):
            raise self.held
        return self.held


def one_pass(environment: Any, backend: Kernel) -> tuple[dict[str, Any], Snapshot]:
    """One pass against `backend`; returns its result and the report it published."""
    root, _, _, _, snapshots = environment
    reports: list[Snapshot] = []
    result = reconcile(
        root,
        lambda config, settings: snapshots[-1],
        lambda root, settings: backend,
        now=lambda: STAMP,
        report=lambda settings, snapshot: reports.append(snapshot),
    )
    return result, reports[-1]


def converged(environment: Any) -> Kernel:
    backend = Kernel()
    approve_all(environment)
    result, report = one_pass(environment, backend)
    assert result["phase"] == "committed" and len(result["changed"]) == 4
    assert all(item.data["root_ready"] is True for item in report.profiles.values())
    return backend


def acquisitions(backend: Kernel) -> int:
    return backend.commands.count(("reference",))


def test_a_healthy_pass_reads_the_reference_back_and_never_acquires_one(
    environment: Any,
) -> None:
    backend = converged(environment)
    # The activating pass acquired at each activation and read back once at its end.
    assert acquisitions(backend) == 4 and backend.readbacks == 1

    for expected in (2, 3, 4):
        result, report = one_pass(environment, backend)
        assert result == {"schema_version": 1, "phase": "committed", "changed": [], "pending": []}
        assert backend.readbacks == expected
        assert all(item.data["root_ready"] is True for item in report.profiles.values())
    assert acquisitions(backend) == 4
    assert "reason" not in environment[0].read("journal.json")


@pytest.mark.parametrize(
    "answer",
    [
        False,
        PFError("bounded PF backend operation failed"),
        OSError("backend unavailable"),
        ValueError("undecodable backend output"),
    ],
    ids=["not listed", "read failed or PF not enabled", "backend unavailable", "undecodable"],
)
def test_an_unverified_reference_leaves_no_profile_ready_and_the_journal_says_why(
    environment: Any, answer: bool | BaseException
) -> None:
    backend = converged(environment)
    root = environment[0]
    loaded = backend.rules
    backend.held = answer
    mark = len(backend.commands)

    for _ in range(2):
        result, report = one_pass(environment, backend)

        assert result == {"schema_version": 1, "phase": "inhibited", "changed": [], "pending": []}
        journal = root.read("journal.json")
        assert journal["phase"] == "inhibited" and journal["reason"] == UNVERIFIED
        assert len(report.profiles) == 4
        for item in report.profiles.values():
            # The rules are still loaded and still approved; they are only not ready.
            assert item.state == "present" and item.data["admitted"] is True
            assert item.data["root_ready"] is False
    # Not a reason to withdraw, to kill states or to acquire a reference.
    assert backend.rules == loaded
    assert not {("replace",), ("reference",)} & set(backend.commands[mark:])
    assert not any(command[0] == "drain" for command in backend.commands[mark:])


def test_the_first_pass_that_verifies_again_is_ready_again(environment: Any) -> None:
    backend = converged(environment)
    backend.held = False
    assert one_pass(environment, backend)[0]["phase"] == "inhibited"

    backend.held = True
    result, report = one_pass(environment, backend)

    assert result["phase"] == "committed"
    assert "reason" not in environment[0].read("journal.json")
    assert all(item.data["root_ready"] is True for item in report.profiles.values())
    assert acquisitions(backend) == 4


def test_a_pass_that_leaves_no_rule_loaded_does_not_read_the_reference(
    environment: Any,
) -> None:
    root = environment[0]
    backend = Kernel()
    backend.held = PFError("never asked")

    # Nothing admitted, nothing loaded.
    result, _ = one_pass(environment, backend)
    assert result["phase"] == "inhibited" and len(result["pending"]) == 4
    assert backend.readbacks == 0 and "reason" not in root.read("journal.json")

    # A pause withdraws everything in one pass; nothing is loaded at its end.
    backend.held = True
    approve_all(environment)
    assert one_pass(environment, backend)[0]["phase"] == "committed"
    backend.held = PFError("never asked")
    before = backend.readbacks
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    result, report = one_pass(environment, backend)
    assert result["phase"] == "inhibited" and backend.rules == ""
    assert backend.readbacks == before and "reason" not in root.read("journal.json")
    assert all(item.data["root_ready"] is False for item in report.profiles.values())


def test_one_loaded_rule_is_enough_to_require_the_readback(environment: Any) -> None:
    root = environment[0]
    backend = Kernel()
    backend.held = False
    # Only one of the four owned profiles is admitted.
    admit(root, "proxy-standard", acknowledge_bounded_risk=True, now=STAMP - 1)

    result, report = one_pass(environment, backend)

    assert result["changed"] == ["proxy-standard:activate"]
    assert backend.readbacks == 1
    assert root.read("journal.json")["reason"] == UNVERIFIED
    assert report.profiles["proxy-standard"].state == "present"
    assert all(item.data["root_ready"] is False for item in report.profiles.values())
    assert sorted(result["pending"]) == ["dns-tcp", "dns-udp", "media-udp"]


def recording(backend: Any, monkeypatch: Any, answers: dict[str, Any]) -> list[str]:
    """Replace the shell call; an exception among `answers` is raised."""
    calls: list[str] = []

    def call(operation: str, *arguments: str) -> str:
        calls.append(operation)
        answer = answers[operation]
        if isinstance(answer, BaseException):
            raise answer
        return str(answer)

    monkeypatch.setattr(backend, "_call", call)
    return calls


def test_shell_readback_uses_only_the_two_existing_reads(
    environment: Any, monkeypatch: Any
) -> None:
    backend = shell_backend(environment, monkeypatch)
    environment[0].write("reference.json", {"token": TOKEN})
    calls = recording(backend, monkeypatch, {"references": LISTED, "enabled": ""})

    assert backend.reference_held() is True
    assert calls == ["references", "enabled"]
    assert environment[0].read("reference.json") == {"token": TOKEN}


def test_shell_readback_without_a_saved_token_asks_nothing(
    environment: Any, monkeypatch: Any
) -> None:
    backend = shell_backend(environment, monkeypatch)
    calls = recording(backend, monkeypatch, {})

    assert backend.reference_held() is False
    assert calls == []
    assert not (environment[0].directory / "reference.json").exists()


@pytest.mark.parametrize(
    "listing",
    [
        "",
        "TOKENS:\nPID Process Name TOKEN TIMESTAMP",
        "123 owner 42 0 days 00:00:00",
        f"123 owner {TOKEN}1 0 days 00:00:00",
        f"123 owner 0 days 00:00:00 {TOKEN}",
        TOKEN,
    ],
    ids=["empty", "header only", "another token", "longer token", "other column", "bare"],
)
def test_shell_readback_of_an_unlisted_token_is_false_and_acquires_nothing(
    environment: Any, monkeypatch: Any, listing: str
) -> None:
    backend = shell_backend(environment, monkeypatch)
    environment[0].write("reference.json", {"token": TOKEN})
    calls = recording(backend, monkeypatch, {"references": listing})

    assert backend.reference_held() is False
    assert calls == ["references"]
    assert environment[0].read("reference.json") == {"token": TOKEN}


def test_shell_readback_raises_when_pf_is_not_shown_enabled(
    environment: Any, monkeypatch: Any
) -> None:
    backend = shell_backend(environment, monkeypatch)
    environment[0].write("reference.json", {"token": TOKEN})
    calls = recording(
        backend, monkeypatch, {"references": LISTED, "enabled": PFError("status is not Enabled")}
    )

    with pytest.raises(PFError, match="not Enabled"):
        backend.reference_held()
    assert calls == ["references", "enabled"]


def test_shell_readback_raises_when_the_listing_cannot_be_read(
    environment: Any, monkeypatch: Any
) -> None:
    backend = shell_backend(environment, monkeypatch)
    environment[0].write("reference.json", {"token": TOKEN})
    calls = recording(backend, monkeypatch, {"references": PFError("listing failed")})

    with pytest.raises(PFError, match="listing failed"):
        backend.reference_held()
    assert calls == ["references"]


@pytest.mark.parametrize(
    "saved",
    [{"token": "invalid"}, {"token": 42}, {"token": TOKEN, "pid": 1}, {}, [TOKEN], TOKEN],
    ids=["not numeric", "number", "extra field", "empty", "list", "bare text"],
)
def test_shell_readback_refuses_a_damaged_record_before_any_call(
    environment: Any, monkeypatch: Any, saved: Any
) -> None:
    backend = shell_backend(environment, monkeypatch)
    environment[0].write("reference.json", saved)
    calls = recording(backend, monkeypatch, {})

    with pytest.raises(PFError, match="damaged"):
        backend.reference_held()
    assert calls == []

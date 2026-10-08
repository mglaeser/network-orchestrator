"""A listing refused for an unexpected notice is told apart from a listing that failed.

The backend script runs as in `tests/test_pf_backend_script.py`: a private copy
in which only the root check and the paths of three tools are replaced, under
`/bin/bash` or the shell that `NETORCH_TEST_BASH` names. The owner's own backend
class runs over that same copy, so the status the script ends with and the
reason the owner records are read from one run. The fake `pfctl` models control
flow only: none of its output is Darwin PF grammar, the notice it "writes" is
invented here, and no real pfctl is called.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import netorch.pf_owner as owner
from netorch.codec import canonical_bytes, strict_loads
from netorch.model import Profile, Scope
from netorch.pf_owner import (
    PFError,
    ShellBackend,
    admit,
    compose_rules,
    reconcile,
    withdraw,
)
from netorch.process import Result
from netorch.state import Intent, Snapshot, intent_to_dict, snapshot_to_dict
from netorch.storage import Store
from tests.test_pf_backend_script import ANCHOR, BASH, NOTICES, Sandbox, bare
from tests.test_pf_owner import STAMP, FakeBackend, environment

__all__ = ["environment"]

# The notice's own error type is read from the module when a test runs, so that
# this file also loads, and its cases fail one by one, where the type is missing.

pytestmark = pytest.mark.skipif(not BASH.exists(), reason="the backend needs bash")

# Invented text. If it shows up anywhere outside the fake tool's own standard
# error, something carried the tool's words out of the script.
UNKNOWN = "pfctl: a notice this test invented 5f1c\n"
SECOND = "pfctl: and a second invented line 9e2b\n"
FIRST_NOTICE, SECOND_NOTICE = NOTICES.splitlines(keepends=True)
TOKEN = "18446744073709551615"
FAILED = "bounded PF backend operation failed"
REFUSED = "a PF listing carried an unexpected notice; nothing was read"
# The one line main wrote for every failed command before this change.
GENERIC_LINE = (
    '{"error":"PFError","reason":"independent owner operation failed; '
    'inspect protected journal","schema_version":1}\n'
)

# backend operation -> the name of the fake's listing behind it
LISTINGS = {"inspect": "nat", "states": "states", "enabled": "info", "references": "References"}
EVERY_PROFILE = ("dns-tcp", "dns-udp", "media-udp", "proxy-standard")

# case -> the fake's answer, the script's status, what the script writes to standard error
CASES: dict[str, tuple[dict[str, Any], int, str]] = {
    # (a) nothing but the two notices: an answer
    "the two notices": ({}, 0, ""),
    "the two notices twice": ({"stderr": NOTICES}, 0, ""),
    "no line at all": ({"bare": True}, 0, ""),
    "empty lines only": ({"bare": True, "stderr": "\n\n"}, 0, ""),
    # (b) one unknown line
    "an unknown line": ({"bare": True, "stderr": UNKNOWN}, 76, "1\n"),
    "an unknown line and no output": ({"bare": True, "stderr": UNKNOWN, "stdout": ""}, 76, "1\n"),
    "a line of blanks": ({"bare": True, "stderr": "  \n"}, 76, "1\n"),
    "a notice spelled differently": (
        {"bare": True, "stderr": FIRST_NOTICE.lower() + SECOND_NOTICE},
        76,
        "1\n",
    ),
    "a notice with more text": ({"bare": True, "stderr": FIRST_NOTICE.strip() + ".\n"}, 76, "1\n"),
    # (c) an unknown line beside the known ones
    "unknown after the notices": ({"stderr": UNKNOWN}, 76, "1\n"),
    "unknown before the notices": ({"bare": True, "stderr": UNKNOWN + NOTICES}, 76, "1\n"),
    "unknown between the notices": (
        {"bare": True, "stderr": FIRST_NOTICE + UNKNOWN + SECOND_NOTICE},
        76,
        "1\n",
    ),
    "two unknown lines": ({"stderr": UNKNOWN + "\n" + SECOND}, 76, "2\n"),
    # (d) a non-zero status, with and without text: a listing that failed
    "failed": ({"exit": 1}, 1, ""),
    "failed without a line": ({"exit": 1, "bare": True}, 1, ""),
    "failed with text": ({"exit": 1, "stderr": UNKNOWN}, 1, ""),
    "failed with the script's own status": ({"exit": 76, "stderr": UNKNOWN}, 1, ""),
    "failed with that status and no text": ({"exit": 76, "bare": True}, 1, ""),
}

READS: dict[str, Callable[[ShellBackend], str]] = {
    "inspect": lambda backend: backend.inspect(),
    "states": lambda backend: backend.states(),
    "enabled": lambda backend: backend._call("enabled"),
    "references": lambda backend: backend._call("references"),
}


class ScriptBackend(ShellBackend):
    """The owner's real backend over the sandboxed script; only the host probes are fakes."""

    def __init__(self, root: Store, installation: Any, script: Path) -> None:
        # Not the parent's constructor: that one checks a root-owned installed file.
        self.root = root
        self.installation = installation
        self.script = script

    def endpoint(self, scope: Scope, ipv4: str, mac: str | None, *, direct: bool) -> bool:
        return True

    def ports_clear(self, scope: Scope, profile: Profile, *, apple_dns: bool) -> bool:
        return True

    def boot_session(self) -> str:
        raise PFError("no boot session is read in these tests")


class Scripted:
    """One sandbox, the owner's backend over it and every result the script returned."""

    def __init__(self, directory: Path, environment: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        directory.mkdir(mode=0o700)
        self.sandbox = Sandbox(directory)
        # The fake of the script tests writes the two notices on every call.
        # Here an answer may also leave them out.
        tool = directory / "tools" / "pfctl"
        always = 'if "-n" not in rest:'
        assert tool.read_text().count(always) == 1
        tool.write_text(tool.read_text().replace(always, always[:-1] + ' and "bare" not in fault:'))
        self.sandbox.kernel("References", f"11 pfctl {TOKEN} 0 days 00:00:01\n")
        self.root: Store = environment[0]
        self.environment = environment
        self.backend = ScriptBackend(self.root, environment[2], self.sandbox.script)
        self.results: list[Result] = []
        self.reports: list[Snapshot] = []
        monkeypatch.setattr(owner, "run", self.run)

    def run(self, argv: list[str], **kwargs: Any) -> Result:
        assert argv[:2] == ["/bin/bash", str(self.sandbox.script)], argv
        done = subprocess.run(
            [str(BASH), *argv[1:]],
            env={"NETORCH_FAKE_PF": str(self.sandbox.state), "PATH": "/usr/bin:/bin"},
            capture_output=True,
            timeout=120,
            check=False,
        )
        self.results.append(Result(done.returncode, done.stdout, done.stderr))
        return self.results[-1]

    def one_pass(self) -> dict[str, Any]:
        snapshots = self.environment[4]
        return reconcile(
            self.root,
            lambda config, settings: snapshots[-1],
            lambda root, settings: self.backend,
            now=lambda: STAMP,
            report=lambda settings, snapshot: self.reports.append(snapshot),
        )

    def loaded(self, *profiles: str) -> None:
        """Hand over an installation that converged with these profiles admitted.

        The pass that loads the rules runs over the in-memory fake of the owner
        tests; the fake kernel behind the script then holds exactly those rules
        and the reference, as it would after the same pass over the script.
        """
        root, snapshots = self.environment[0], self.environment[4]
        for profile in profiles:
            admit(root, profile, acknowledge_bounded_risk=True, now=STAMP - 1)
        fake = FakeBackend()
        result = reconcile(
            root,
            lambda config, settings: snapshots[-1],
            lambda root, settings: fake,
            now=lambda: STAMP,
            report=lambda settings, snapshot: None,
        )
        assert sorted(result["changed"]) == sorted(f"{profile}:activate" for profile in profiles)
        records = root.read("live.json")["records"]
        self.sandbox.kernel("live", "".join(map(bare, compose_rules(records).splitlines())))
        root.write("reference.json", {"token": TOKEN})

    def journal(self) -> dict[str, Any]:
        document = self.root.read("journal.json")
        assert isinstance(document, dict)
        return document

    def no_tool_text(self, *more: Any) -> None:
        """Neither a stored record nor the published report nor a result carries the line."""
        for marker in ("invented", "5f1c", "9e2b", "pfctl:"):
            for path in sorted(self.root.directory.iterdir()):
                if path.is_file():
                    assert marker.encode() not in path.read_bytes(), (marker, path.name)
            for report in self.reports:
                assert marker.encode() not in canonical_bytes(snapshot_to_dict(report))
            for item in more:
                assert marker not in repr(item), (marker, item)


@pytest.fixture
def scripted(tmp_path: Path, environment: Any, monkeypatch: pytest.MonkeyPatch) -> Scripted:
    return Scripted(tmp_path / "script", environment, monkeypatch)


def variant(kind: str) -> dict[str, Any]:
    """The same read, once refused for a notice and once failed."""
    return {
        "notice": {"stderr": UNKNOWN},
        "notice alone": {"bare": True, "stderr": UNKNOWN},
        "failed": {"exit": 1},
        "failed with text": {"exit": 1, "stderr": UNKNOWN},
    }[kind]


KINDS = ["notice", "notice alone", "failed", "failed with text"]
# A whole pass over the script is slow; the other two spellings are covered above.
PAIR = ["notice", "failed"]


# ---- the script's status and the owner's error, for each listing and each answer


@pytest.mark.parametrize("operation", LISTINGS)
@pytest.mark.parametrize("case", CASES)
def test_each_answer_of_a_listing_has_one_status_and_one_reason(
    scripted: Scripted, operation: str, case: str
) -> None:
    fault, status, counted = CASES[case]
    sandbox = scripted.sandbox
    rows = "all udp 192.0.2.77:54321 -> 198.51.100.12:53 NO_TRAFFIC:SINGLE\n"
    sandbox.kernel("states", rows)
    sandbox.faults(**{LISTINGS[operation]: fault})
    caught: PFError | None = None

    try:
        answer = READS[operation](scripted.backend)
    except PFError as error:
        caught, answer = error, ""

    # One call of the script; its status and its own standard error.
    (result,) = scripted.results
    assert (result.returncode, result.stderr.decode()) == (status, counted)
    if status == 0:
        assert caught is None
        if "stdout" not in fault and operation in {"states", "references"}:
            assert answer == sandbox.state.joinpath(LISTINGS[operation]).read_text().strip()
    elif status == 76:
        # The owner's reason: a notice, with the operation and the number of lines.
        assert isinstance(caught, owner.PFListingNotice)
        assert (caught.operation, caught.unexpected_lines) == (operation, int(counted))
        assert str(caught) == REFUSED
    else:
        # The owner's reason: a failed read, worded as before.
        assert type(caught) is PFError and str(caught) == FAILED
    # The script's standard error is a number or nothing, never the tool's line.
    assert result.stderr in {b"", b"1\n", b"2\n"}
    assert "invented" not in repr(caught)
    # Nothing was loaded, killed or enabled on the strength of a refused read.
    assert not any(call.split()[0] in {"-k", "-E", "-X"} for call in sandbox.calls)
    assert sandbox.loads == []


@pytest.mark.parametrize("kind", KINDS)
def test_a_replacement_passes_the_status_of_its_hook_listing_on_and_loads_nothing(
    scripted: Scripted, kind: str
) -> None:
    sandbox = scripted.sandbox
    old, new = sandbox.rules("expected.rules", ""), sandbox.rules("candidate.rules", "rdr own\n")
    sandbox.faults(nat=variant(kind))

    result = sandbox.run("replace", ANCHOR, old, new)

    assert result.returncode == (76 if kind.startswith("notice") else 1)
    assert (result.stdout, result.stderr) == ("", "1\n" if kind.startswith("notice") else "")
    assert sandbox.loads == [] and sandbox.live == ""


def test_warnings_that_could_not_be_examined_are_a_failed_listing_not_a_notice(
    tmp_path: Path,
) -> None:
    sandbox = Sandbox(tmp_path, broken_filter=True)
    sandbox.faults(states={"stderr": UNKNOWN})

    result = sandbox.run("states", ANCHOR)

    assert (result.returncode, result.stderr) == (1, "")


def test_a_notice_whose_lines_could_not_be_counted_is_a_failed_listing(tmp_path: Path) -> None:
    """The script's own status never comes without its count."""
    sandbox = Sandbox(tmp_path)
    text = sandbox.script.read_text()
    counter = "counted() { /usr/bin/awk"
    assert text.count(counter) == 1
    sandbox.script.write_text(text.replace(counter, "counted() { /usr/bin/false"))
    sandbox.faults(states={"stderr": UNKNOWN})

    result = sandbox.run("states", ANCHOR)

    assert (result.returncode, result.stderr) == (1, "")
    # With the two notices only there is nothing to count and nothing fails.
    sandbox.faults()
    assert sandbox.run("states", ANCHOR).returncode == 0


# ---- what the owner's backend reads from the script


@pytest.mark.parametrize(
    "written,count",
    [
        (b"1\n", 1),
        (b"37\n", 37),
        (b"999999\n", 999999),
        (b"", None),
        (b"0\n", None),
        (b"03\n", None),
        (b"3", None),
        (b" 3\n", None),
        (b"3\n4\n", None),
        (b"1000000\n", None),
        (b"-1\n", None),
        (b"3\n" + UNKNOWN.encode(), None),
        (UNKNOWN.encode(), None),
        (UNKNOWN.encode() + b"3\n", None),
    ],
)
def test_only_a_count_is_read_from_the_script(
    scripted: Scripted, monkeypatch: pytest.MonkeyPatch, written: bytes, count: int | None
) -> None:
    monkeypatch.setattr(owner, "run", lambda argv, **kwargs: Result(76, UNKNOWN.encode(), written))

    with pytest.raises(owner.PFListingNotice) as caught:
        scripted.backend.states()

    notice = caught.value
    assert (notice.operation, notice.unexpected_lines) == ("states", count)
    assert str(notice) == REFUSED and notice.args == (REFUSED,)
    assert "invented" not in repr(vars(notice))


@pytest.mark.parametrize("status", [1, 2, 9, 64, 73, 74, 75, 77, 78, 141, -9])
def test_every_other_status_of_the_script_is_a_failure_as_before(
    scripted: Scripted, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    monkeypatch.setattr(owner, "run", lambda argv, **kwargs: Result(status, b"x", b"1\n"))

    for read in READS.values():
        with pytest.raises(PFError) as caught:
            read(scripted.backend)
        assert type(caught.value) is PFError and str(caught.value) == FAILED


@pytest.mark.parametrize("operation", ["normalize", "drain", "enable"])
def test_the_status_means_a_notice_only_for_an_operation_that_reads_a_listing(
    scripted: Scripted, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    monkeypatch.setattr(owner, "run", lambda argv, **kwargs: Result(76, b"", b"1\n"))
    calls: dict[str, Callable[[], Any]] = {
        "normalize": lambda: scripted.backend.normalize("rdr own\n"),
        "drain": lambda: scripted.backend.drain("198.51.100.12"),
        "enable": lambda: scripted.backend._call("enable"),
    }

    with pytest.raises(PFError) as caught:
        calls[operation]()

    assert type(caught.value) is PFError and str(caught.value) == FAILED


def test_the_reason_is_not_a_deferral_reason() -> None:
    """A notice is a fact about the tool on that pass, not a precondition of one profile."""
    assert owner.LISTING_NOTICE == "listing-notice"
    assert owner.LISTING_NOTICE not in owner.DEFERRAL_REASONS
    with pytest.raises(PFError, match="unknown deferral reason"):
        owner._deferrals({"dns-udp": owner.LISTING_NOTICE})
    assert issubclass(owner.PFListingNotice, PFError)


# ---- what a pass records, for each place a failed read is recorded


@pytest.mark.parametrize("kind", KINDS)
def test_the_hook_listing_ends_the_pass_before_any_record_either_way(
    scripted: Scripted, kind: str
) -> None:
    scripted.sandbox.faults(nat=variant(kind))

    with pytest.raises(PFError) as caught:
        scripted.one_pass()

    if kind.startswith("notice"):
        assert isinstance(caught.value, owner.PFListingNotice)
        assert (caught.value.operation, caught.value.unexpected_lines) == ("inspect", 1)
    else:
        assert type(caught.value) is PFError and str(caught.value) == FAILED
    # The first read of a pass precedes its first journal record, as before.
    names = {path.name for path in scripted.root.directory.iterdir()}
    assert "journal.json" not in names and "live.json" not in names
    assert scripted.reports == [] and scripted.sandbox.loads == []
    scripted.no_tool_text(caught.value)


@pytest.mark.parametrize("kind", KINDS)
def test_a_state_table_refused_when_the_pass_starts_is_recorded_with_its_reason(
    scripted: Scripted, kind: str
) -> None:
    scripted.sandbox.faults(states=variant(kind))

    result = scripted.one_pass()

    # The outcome is that of a state table that cannot be read ...
    assert result == {
        "schema_version": 1,
        "phase": "failed",
        "changed": [],
        "pending": list(EVERY_PROFILE),
    }
    (report,) = scripted.reports
    assert all(
        (item.state, item.reason) == ("unknown", "incomplete") for item in report.profiles.values()
    )
    # ... and only the reason of the record tells the two apart.
    assert scripted.journal() == {
        "schema_version": 1,
        "phase": "failed",
        "candidate_records": {},
        "failed_at": STAMP,
        "reason": "listing-notice" if kind.startswith("notice") else "kernel-state-unknown",
    }
    scripted.no_tool_text(result)


@pytest.mark.parametrize("listing", ["References", "info"])
@pytest.mark.parametrize("kind", PAIR)
def test_a_reference_readback_refused_for_a_notice_is_recorded_with_its_reason(
    scripted: Scripted, listing: str, kind: str
) -> None:
    scripted.loaded(*EVERY_PROFILE)
    live = scripted.sandbox.live
    scripted.sandbox.faults(**{listing: variant(kind)})

    result = scripted.one_pass()

    # Not verified, as after a readback that failed: nothing ready, nothing touched.
    assert result == {"schema_version": 1, "phase": "inhibited", "changed": [], "pending": []}
    (report,) = scripted.reports
    assert all(item.state == "present" for item in report.profiles.values())
    assert not any(item.data["root_ready"] for item in report.profiles.values())
    assert scripted.sandbox.live == live and scripted.sandbox.loads == []
    assert not any(call.split()[0] in {"-k", "-E"} for call in scripted.sandbox.calls)
    journal = scripted.journal()
    assert journal["phase"] == "inhibited"
    assert journal["reason"] == (
        "listing-notice" if kind.startswith("notice") else "enable-reference-unverified"
    )
    assert set(journal) == {"schema_version", "phase", "actions", "finished_at", "reason"}
    scripted.no_tool_text(result)

    # The read answers again: the next pass is an ordinary one.
    scripted.sandbox.faults()
    assert scripted.one_pass()["phase"] == "committed"
    assert "reason" not in scripted.journal()
    assert all(item.data["root_ready"] is True for item in scripted.reports[-1].profiles.values())


@pytest.mark.parametrize("kind", PAIR)
def test_a_deferral_for_evidence_keeps_its_reason_and_the_record_names_the_notice(
    scripted: Scripted, kind: str
) -> None:
    root = scripted.root
    admit(root, "proxy-standard", acknowledge_bounded_risk=True, now=STAMP - 1)
    # The first read of the pass answers; the fresh read before the activation does not.
    scripted.sandbox.faults(states={**variant(kind), "calls": [2]})

    result = scripted.one_pass()

    deferred = {"proxy-standard": "evidence-unavailable"}
    assert result["phase"] == "inhibited" and result["deferred"] == deferred
    assert set(result) == {"schema_version", "phase", "changed", "pending", "deferred"}
    (report,) = scripted.reports
    assert report.profiles["proxy-standard"].data["deferred"] == "evidence-unavailable"
    assert scripted.sandbox.loads == [] and "-E" not in scripted.sandbox.calls
    journal = scripted.journal()
    assert journal["phase"] == "inhibited" and journal["deferred"] == deferred
    if kind.startswith("notice"):
        assert journal["reason"] == "listing-notice"
    else:
        assert "reason" not in journal
    scripted.no_tool_text(result)


@pytest.mark.parametrize("kind", PAIR)
def test_a_drain_readback_refused_for_a_notice_stays_retained_and_is_named(
    scripted: Scripted, kind: str
) -> None:
    scripted.loaded("dns-udp")
    root = scripted.root
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    # The read when the pass starts answers; the read of the drain does not.
    scripted.sandbox.faults(states={**variant(kind), "calls": [2]})

    result = scripted.one_pass()

    deferred = {"dns-udp": "states-retained"}
    assert result["phase"] == "inhibited" and result["deferred"] == deferred
    assert result["changed"] == ["dns-udp:withdraw"]
    # The rule is retired and its record waits, as after a readback that failed.
    assert scripted.sandbox.live == ""
    records = root.read("live.json")["records"]
    assert set(records) == {"dns-udp"} and records["dns-udp"]["active"] is False
    assert not any(call.startswith("-k") for call in scripted.sandbox.calls)
    journal = scripted.journal()
    assert journal["phase"] == "inhibited" and journal["deferred"] == deferred
    if kind.startswith("notice"):
        assert journal["reason"] == "listing-notice"
    else:
        assert "reason" not in journal
    scripted.no_tool_text(result)


@pytest.mark.parametrize("kind", PAIR)
def test_a_final_state_read_refused_for_a_notice_fails_the_pass_and_is_named(
    scripted: Scripted, kind: str
) -> None:
    # The read when the pass starts answers; the final read of the same pass does not.
    scripted.sandbox.faults(states={**variant(kind), "calls": [2]})

    with pytest.raises(PFError) as caught:
        scripted.one_pass()

    if kind == "notice":
        assert isinstance(caught.value, owner.PFListingNotice)
    else:
        assert type(caught.value) is PFError and str(caught.value) == FAILED
    journal = scripted.journal()
    assert journal.pop("actions")
    assert journal == {
        "schema_version": 1,
        "phase": "failed",
        "started_at": STAMP,
        "failed_at": STAMP,
        **({"reason": "listing-notice"} if kind.startswith("notice") else {}),
    }
    scripted.no_tool_text(caught.value)

    # Either way the acknowledgement is owed: the next pass stays failed.
    scripted.sandbox.faults()
    assert scripted.one_pass()["phase"] == "failed"
    assert "reason" not in scripted.journal()


@pytest.mark.parametrize("kind", PAIR)
def test_a_load_refused_at_its_hook_listing_is_a_write_in_doubt_and_is_named(
    scripted: Scripted, kind: str
) -> None:
    admit(scripted.root, "proxy-standard", acknowledge_bounded_risk=True, now=STAMP - 1)
    # The hooks answer when the pass starts and not when the load reads them again.
    scripted.sandbox.faults(nat={**variant(kind), "calls": [2]})

    with pytest.raises(PFError) as caught:
        scripted.one_pass()

    if kind == "notice":
        assert isinstance(caught.value, owner.PFListingNotice)
        assert (caught.value.operation, caught.value.unexpected_lines) == ("replace", 1)
    else:
        assert type(caught.value) is PFError
    assert scripted.sandbox.loads == [] and scripted.sandbox.live == ""
    journal = scripted.journal()
    assert journal["phase"] == "failed" and "candidate_records" in journal
    assert journal.get("reason") == ("listing-notice" if kind == "notice" else None)
    scripted.no_tool_text(caught.value)


@pytest.mark.parametrize("kind", PAIR)
def test_an_administrator_withdrawal_fails_either_way_and_its_record_is_unchanged(
    scripted: Scripted, kind: str
) -> None:
    scripted.loaded("dns-udp")
    scripted.sandbox.faults(states=variant(kind))

    with pytest.raises(PFError) as caught:
        withdraw(scripted.root, lambda root, settings: scripted.backend)

    if kind == "notice":
        assert isinstance(caught.value, owner.PFListingNotice)
    else:
        assert type(caught.value) is PFError and str(caught.value) == FAILED
    # The rule is retired; the drain could not be read back. The record of a
    # withdrawal keeps the reason that names it: the command's error line reports.
    assert scripted.sandbox.live == ""
    journal = scripted.journal()
    assert (journal["phase"], journal["reason"]) == ("failed", "administrator-withdrawal")
    scripted.no_tool_text(caught.value)


# ---- one reason per record: a notice never takes the place of a finding

# what the reference readback of the pass meets -> the fake's answer for that listing
READBACKS: dict[str, dict[str, Any]] = {
    "verified": {},
    "token not listed": {"stdout": "12 pfctl 1 0 days 00:00:01\n"},
    "failed": {"exit": 1},
    "refused for a notice": {"stderr": UNKNOWN},
}
# the read a deferral absorbed, the reference readback -> the reason of the final record
PRECEDENCE = {
    ("notice", "verified"): "listing-notice",
    ("notice", "token not listed"): "enable-reference-unverified",
    ("notice", "failed"): "enable-reference-unverified",
    ("notice", "refused for a notice"): "listing-notice",
    ("failed", "verified"): None,
    ("failed", "token not listed"): "enable-reference-unverified",
    ("failed", "failed"): "enable-reference-unverified",
    ("failed", "refused for a notice"): "listing-notice",
}


@pytest.mark.parametrize("readback", READBACKS)
@pytest.mark.parametrize("kind", PAIR)
def test_a_notice_never_takes_the_place_of_what_the_reference_readback_found(
    scripted: Scripted, kind: str, readback: str
) -> None:
    """One profile is loaded; a second is deferred for a read that was refused or failed."""
    scripted.loaded("dns-udp")
    admit(scripted.root, "proxy-standard", acknowledge_bounded_risk=True, now=STAMP - 1)
    # The fresh state read before the activation, and the reference readback of the pass.
    faults = {"states": {**variant(kind), "calls": [2]}}
    if READBACKS[readback]:
        faults["References"] = READBACKS[readback]
    scripted.sandbox.faults(**faults)

    result = scripted.one_pass()

    deferred = {"proxy-standard": "evidence-unavailable"}
    assert result["phase"] == "inhibited" and result["deferred"] == deferred
    journal = scripted.journal()
    assert journal["phase"] == "inhibited" and journal["deferred"] == deferred
    # A readback that completed without the token, or that failed, keeps its
    # reason whatever the other read was refused for; the notice is the reason
    # where the readback itself was refused, or verified and so found nothing.
    assert journal.get("reason") == PRECEDENCE[kind, readback]
    (report,) = scripted.reports
    ready = sorted(key for key, item in report.profiles.items() if item.data["root_ready"])
    assert ready == (["dns-udp"] if readback == "verified" else [])
    # Nothing was loaded, invalidated or acquired on the strength of either read.
    assert scripted.sandbox.loads == []
    assert not any(call.split()[0] in {"-k", "-E"} for call in scripted.sandbox.calls)
    scripted.no_tool_text(result)


def reacquiring(scripted: Scripted) -> None:
    """The installation chose to take a lost reference again; every profile is loaded under it."""
    root, settings = scripted.root, scripted.environment[2]
    decided = replace(settings, enable_reference="reacquire")
    root.write("installation.json", decided.to_dict())
    scripted.backend.installation = decided
    scripted.loaded(*EVERY_PROFILE)


@pytest.mark.parametrize("kind", PAIR)
def test_a_readback_after_a_reacquisition_that_is_refused_for_a_notice_is_named(
    scripted: Scripted, kind: str
) -> None:
    reacquiring(scripted)
    root = scripted.root
    # The saved token is not the one the kernel lists: a complete read, not held.
    root.write("reference.json", {"token": "1"})
    # The reference listing is read four times: by the readback, twice by the
    # acquisition, and by the second readback, which is the one that is refused.
    scripted.sandbox.faults(References={**variant(kind), "calls": [4]})

    result = scripted.one_pass()

    assert result == {
        "schema_version": 1,
        "phase": "inhibited",
        "changed": [],
        "pending": [],
        "reference": "reacquired",
    }
    assert scripted.sandbox.calls.count("-E") == 1
    assert root.read("reference.json") == {"token": TOKEN}
    # The acquisition replaced what the first readback found; the last readback decides.
    assert scripted.journal()["reason"] == (
        "listing-notice" if kind == "notice" else "enable-reference-unverified"
    )
    (report,) = scripted.reports
    assert not any(item.data["root_ready"] for item in report.profiles.values())
    scripted.no_tool_text(result)


@pytest.mark.parametrize("listing", ["References", "info"])
@pytest.mark.parametrize("kind", PAIR)
def test_a_refused_readback_is_no_evidence_that_the_reference_is_gone(
    scripted: Scripted, listing: str, kind: str
) -> None:
    """Only a complete read that does not list the token takes the reference again."""
    reacquiring(scripted)
    scripted.sandbox.faults(**{listing: variant(kind)})

    result = scripted.one_pass()

    # Unknown, not "not held": nothing is acquired and the result names no acquisition.
    assert result == {"schema_version": 1, "phase": "inhibited", "changed": [], "pending": []}
    assert "-E" not in scripted.sandbox.calls
    assert scripted.journal()["reason"] == (
        "listing-notice" if kind == "notice" else "enable-reference-unverified"
    )
    scripted.no_tool_text(result)


# ---- the job's standard error


@pytest.mark.parametrize(
    "error,line",
    [
        (lambda: PFError(FAILED), GENERIC_LINE),
        (lambda: OSError("anything"), GENERIC_LINE.replace("PFError", "OSError")),
        (
            lambda: owner.PFListingNotice("states", 2),
            '{"error":"PFListingNotice","operation":"states","reason":"listing-notice",'
            '"schema_version":1,"unexpected_lines":2}\n',
        ),
        (
            lambda: owner.PFListingNotice("inspect", None),
            '{"error":"PFListingNotice","operation":"inspect","reason":"listing-notice",'
            '"schema_version":1}\n',
        ),
    ],
    ids=["failed", "another error", "notice", "notice without a count"],
)
def test_the_job_error_line_names_reason_operation_and_count_and_no_tool_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    error: Callable[[], Exception],
    line: str,
) -> None:
    def failing(root: Any, observer: Any, backend: Any) -> dict[str, Any]:
        raise error()

    # Only the output rule of the entry point is under test: the stage gate, the
    # root boundary and the pass itself are replaced, as other tests of `main` do.
    monkeypatch.setattr(owner, "require_mutation_qualified", lambda operation: None)
    monkeypatch.setattr(owner.sys, "platform", "darwin")
    monkeypatch.setattr(owner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(owner, "protected_code", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner, "protected_ancestors", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner, "Store", lambda directory: object())
    monkeypatch.setattr(owner, "reconcile", failing)

    assert owner.main(["reconcile", "--root-dir", str(tmp_path)]) == 65

    printed = capsys.readouterr()
    assert (printed.out, printed.err) == ("", line)
    assert isinstance(strict_loads(printed.err), dict)


def test_the_pass_that_a_notice_ends_reaches_the_job_error_line_with_its_count(
    scripted: Scripted, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The error of a real pass over the script, printed by the entry point."""
    scripted.sandbox.faults(nat={"stderr": UNKNOWN + SECOND})
    with pytest.raises(owner.PFListingNotice) as caught:
        scripted.one_pass()
    raised = caught.value

    def failing(root: Any, observer: Any, backend: Any) -> dict[str, Any]:
        raise raised

    monkeypatch.setattr(owner, "require_mutation_qualified", lambda operation: None)
    monkeypatch.setattr(owner.sys, "platform", "darwin")
    monkeypatch.setattr(owner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(owner, "protected_code", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner, "protected_ancestors", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner, "Store", lambda directory: object())
    monkeypatch.setattr(owner, "reconcile", failing)

    assert owner.main(["reconcile", "--root-dir", str(scripted.root.directory)]) == 65

    printed = capsys.readouterr()
    assert printed.out == ""
    assert strict_loads(printed.err) == {
        "schema_version": 1,
        "error": "PFListingNotice",
        "reason": "listing-notice",
        "operation": "inspect",
        "unexpected_lines": 2,
    }
    assert "invented" not in printed.err and "pfctl" not in printed.err

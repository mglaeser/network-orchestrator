"""Readiness record of 9 October 2026 for release and migration, findings R-O1 to R-O8.

The record is `docs/reviews/2026-10-09-readiness-migration.md`. Two tests stand
behind it.

The first passes. It reads the record's one table of procedures, which must lie
outside every code fence and HTML comment, and requires exactly one row for
each requirement of the registry whose minimum tier is 3 or more, and none for
another. Each row must give the registry's methods, tier and applicability; its
evidence cell must state the scope of a record, the capture context and a kind
as the host report requires them (`evidence_terms`); its measure cell must name
one of the command classes the record lists. The baseline and the pass
criterion are only required to be present: the test does not judge them.

The second asserts a change the record proposes and is a strict expected
failure. It fails today with an AssertionError that shows what the code does
now. A set-up that does not hold ends it through `pytest.fail`, which is no
AssertionError and therefore a failure of the suite, never the expected one.
Once the change is made it passes, the strict marker turns that pass into a
failure of the suite, and the marker has to go in the same change.

Everything native is a fake from the existing runtime tests. Nothing here says
anything about a real host.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.process import Result
from netorch.requirements import REQUIREMENTS, Requirement, requirement
from netorch.runtime_settings import parse_settings, settings_to_dict
from tests.test_apple_runtime import enrolled
from tests.test_runtime_start_vendor_runtime import World, command

__all__ = ["enrolled"]

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "docs/reviews/2026-10-09-readiness-migration.md"
# The head of the one table in the record that holds a procedure per requirement.
HEADER = [
    "Requirement",
    "Method and tier",
    "Applicability",
    "Baseline on the existing site",
    "Measure (read-only command class)",
    "Pass criterion",
    "Evidence fields",
]
# How `host_report._acceptance` scopes a record by the applicability of its row:
# one record per transport profile, one per discovery selection, or else one
# record for the whole instance, with no profile.
TRANSPORT_SCOPES = frozenset(
    {"transport", "root-transport", "any-source", "bounded", "bounded-udp"}
)
DISCOVERY_SCOPES = frozenset({"discovery", "imports", "media-audio", "exports"})
# The capture context that `host_report._acceptance` requires for a method, where it requires one.
CONTEXTS = {
    "heard-audio": "host-person",
    "local-network-consent": "user-launchagent",
    "root-runtime-observer": "root-launchdaemon",
}
# The kinds of the acceptance schema that the report counts (it refuses `synthetic`).
KINDS = ("`kind` `native-capture`", "`kind` `owner-attestation`")
# The read-only command classes the record lists above its table.
COMMAND_CLASSES = (
    r"packet capture",
    r"`pfctl\b",
    r"`dns-sd\b",
    r"\bdns client\b",
    r"\bservice manager\b",
    r"\bruntime cli\b",
    r"\bperson\b",
)
# The example of the runtime guide's section on the restart budget.
STARTS, WINDOW = 3, 600
# The refusal of `runtime_settings` for a member that a closed object does not know.
UNKNOWN_MEMBER = "invalid runtime settings object"


def cells(line: str) -> list[str]:
    """The cells of one table row; a cell of this table never holds a vertical bar."""
    return [cell.strip() for cell in line.strip().removeprefix("|").removesuffix("|").split("|")]


def comment_open_after(line: str, open_before: bool) -> bool:
    """Whether an HTML comment is still open at the end of this line."""
    is_open, position = open_before, 0
    while True:
        marker = "-->" if is_open else "<!--"
        found = line.find(marker, position)
        if found < 0:
            return is_open
        is_open, position = not is_open, found + len(marker)


def visible_lines(text: str) -> list[str | None]:
    """Each line of the record, or None where it lies in a code fence or an HTML comment.

    A line that opens or closes either is hidden as well. Hiding too much can only
    make the table go missing, never let a hidden table count.
    """
    result: list[str | None] = []
    fence: str | None = None
    comment = False
    for line in text.splitlines():
        stripped = line.lstrip()
        if fence is not None:
            result.append(None)
            if stripped.startswith(fence):
                fence = None
        elif comment or "<!--" in line:
            result.append(None)
            comment = comment_open_after(line, comment)
        elif stripped.startswith(("```", "~~~")):
            result.append(None)
            fence = stripped[:3]
        else:
            result.append(line)
    return result


def procedure_rows() -> list[list[str]]:
    """The rows of the procedure table, below its head and its separator line."""
    lines = visible_lines(RECORD.read_text(encoding="utf-8"))
    heads = [
        index
        for index, line in enumerate(lines)
        if line is not None and line.startswith("|") and cells(line) == HEADER
    ]
    assert len(heads) == 1, f"the record shows {len(heads)} procedure tables"
    separator = lines[heads[0] + 1]
    assert separator is not None
    assert len(cells(separator)) == len(HEADER)
    assert all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells(separator))
    rows = []
    for line in lines[heads[0] + 2 :]:
        if line is None or not line.startswith("|"):
            break
        rows.append(cells(line))
    return rows


def method_and_tier(item: Requirement) -> str:
    """The second cell of a row as the registry states it."""
    methods = " or ".join(f"`{method}`" for method in item.acceptance_methods)
    return f"{methods}, tier {item.minimum_tier}"


def evidence_terms(item: Requirement) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """What the evidence cell of a row must say, and what it must not.

    The scope of a record as the report applies it to the applicability, the
    capture context the report requires for each method where it requires one,
    and no requirement of a context where it requires none.
    """
    per_profile = ("One record per transport profile", "One record per discovery selection")
    whole = "`profile` `null`"
    if item.applicability in TRANSPORT_SCOPES:
        wanted, refused = [per_profile[0]], [per_profile[1], whole]
    elif item.applicability in DISCOVERY_SCOPES:
        wanted, refused = [per_profile[1]], [per_profile[0], whole]
    else:
        wanted, refused = [whole], list(per_profile)
    contexts = [CONTEXTS[method] for method in item.acceptance_methods if method in CONTEXTS]
    wanted += [f"`capture_context` must be `{context}`" for context in contexts]
    if not contexts:
        refused.append("`capture_context` must be")
    return tuple(wanted), tuple(refused)


def test_r_o4_every_requirement_of_tier_three_or_more_has_exactly_one_procedure_row() -> None:
    rows = procedure_rows()
    assert rows and all(len(row) == len(HEADER) and all(row) for row in rows)
    named = [re.fullmatch(r"`([A-Z][A-Z0-9-]+)`", row[0]) for row in rows]
    assert all(named), [row[0] for row, match in zip(rows, named, strict=True) if not match]
    listed = [match.group(1) for match in named if match]
    wanted = {item.id for item in REQUIREMENTS if item.minimum_tier >= 3}
    missing = sorted(wanted - set(listed))
    extra = sorted(set(listed) - wanted)
    repeated = sorted({identifier for identifier in listed if listed.count(identifier) > 1})
    assert (missing, extra, repeated) == ([], [], [])
    for row, identifier in zip(rows, listed, strict=True):
        item = requirement(identifier)
        assert row[1] == method_and_tier(item), identifier
        assert row[2] == f"`{item.applicability}`", identifier
        measure, evidence = row[4], row[6]
        assert any(re.search(term, measure, re.IGNORECASE) for term in COMMAND_CLASSES), identifier
        terms, refused = evidence_terms(item)
        assert [term for term in terms if term not in evidence] == [], identifier
        assert [term for term in refused if term in evidence] == [], identifier
        assert any(kind in evidence for kind in KINDS), identifier


def with_start_budget(world: World) -> bool:
    """Give the declared start of the runtime the proposed member `start_budget`.

    True where the loader takes it. Today's loader refuses it, as it refuses every
    member the closed `runtime_start` object does not know; on exactly that
    refusal, and only where the same settings without the member load, the world
    keeps its settings without it and the answer is False. Every other refusal
    is a set-up that does not hold.
    """
    plain = settings_to_dict(world.settings)
    declared = copy.deepcopy(plain)
    declared["fleet_start"]["runtime_start"]["start_budget"] = {
        "starts": STARTS,
        "window_seconds": WINDOW,
    }
    try:
        budgeted = parse_settings(declared)
    except ValueError as refusal:
        if str(refusal) != UNKNOWN_MEMBER:
            pytest.fail(f"set-up: the loader refuses start_budget for another reason: {refusal}")
        try:
            parse_settings(plain)
        except ValueError as other:
            pytest.fail(f"set-up: the settings without start_budget are refused too: {other}")
        return False
    world.settings = world.runner.settings = budgeted
    return True


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "readiness R-O8: a new runtime_start.start_budget bounds the vendor starts of "
        "runtime-start and holds the runtime once it is spent"
    ),
)
def test_r_o8_runtime_start_stops_and_holds_once_the_start_budget_is_spent(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The user database of the machine that runs the tests is no part of this test.
    monkeypatch.setattr(runtime, "_listed_home", lambda _uid: None)
    world = World(enrolled, tmp_path)
    # The declared start of the runtime with a budget of three starts in ten minutes.
    budgeted = with_start_budget(world)
    # A runtime that cannot come up: the vendor's start command fails and leaves
    # no job loaded, so every later read finds the runtime absent again.
    world.runner.start_answer = Result(1, b"", b"failed\n")
    world.runner.after_start = lambda: setattr(world.runner, "job", None)

    # The supervisor's rule, repeated with `recovery_repeat_cycles`, runs the
    # start whenever the probe answers 42. Within the budget every firing is one
    # failed vendor start, today and with the change.
    for firing in range(1, STARTS + 1):
        if command(monkeypatch, world, "runtime-probe") != runtime.STOPPED:
            pytest.fail(f"set-up: the probe does not answer 42 before firing {firing}")
        if command(monkeypatch, world, "runtime-start") != runtime.UNKNOWN:
            pytest.fail(f"set-up: firing {firing} does not end as unknown")
        if world.vendor_calls() != [world.start_arguments()] * firing:
            pytest.fail(f"set-up: firing {firing} is not exactly one more vendor start")
    # One cycle more. Whether the probe or the start notices the spent budget is
    # left to the change; the supervisor fires only on 42.
    if command(monkeypatch, world, "runtime-probe") == runtime.STOPPED:
        command(monkeypatch, world, "runtime-start")

    issued = len(world.vendor_calls())
    assert issued == STARTS, (
        f"R-O8 today: runtime-start issued {issued} vendor starts within one window of "
        f"{WINDOW} seconds for a start budget of {STARTS}; "
        + (
            "runtime-start does not honour start_budget"
            if budgeted
            else "the settings loader does not know start_budget, so nothing bounds the start"
        )
    )
    # Held: the probe no longer answers 42, so the supervisor's rule stops firing.
    assert command(monkeypatch, world, "runtime-probe") == runtime.UNKNOWN, (
        "R-O8 today: the runtime probe still answers 42 after the budget is spent"
    )

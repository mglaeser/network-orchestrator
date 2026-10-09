"""The UDP return pair is activated, and reported ready, only while nothing can translate before it.

That is a decision of the installation, `translation_order: "verified"`. Without
it nothing below is read. With it the check gates an activation and the
readiness of a loaded pair; it never withdraws one. Three layers are tested: the
pure judgement, the owner
over the in-memory kernel of the owner tests, and the backend script over a fake
`pfctl` (a private copy of the shipped script, under `/bin/bash` or the shell
that `NETORCH_TEST_BASH` names). Hook lines and anchor listings are synthetic:
they have the shape the checker reads, not the shape of a capture, and no real
pfctl is called except by the one hosted dry run at the end.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import re
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import netorch.pf_owner as owner
from netorch.codec import canonical_bytes, strict_loads
from netorch.pf_owner import Installation, PFError, admit, admitted_digest
from netorch.process import Result
from netorch.state import Intent, Snapshot, intent_to_dict
from tests.test_pf_backend_script import ANCHOR, BASH, SCRIPT, Sandbox
from tests.test_pf_deferral import (
    EVERY_PROFILE,
    assert_deferred,
    assert_nothing_deferred,
    observed_pass,
)
from tests.test_pf_listing_notice import UNKNOWN, Scripted
from tests.test_pf_own_states import Kernel
from tests.test_pf_owner import STAMP, approve_all, environment
from tests.test_pf_withdraw_order import address, owned

__all__ = ["environment"]

needs_bash = pytest.mark.skipif(not BASH.exists(), reason="the backend needs bash")

REASON = "translation-order-unverified"
PAIR = "media-udp"
OTHERS = ["dns-tcp", "dns-udp", "proxy-standard"]
PARENT = "com.apple"
SIBLING = "com.apple/example-sibling"
SECOND_SIBLING = "com.apple/another.sibling"
# A name the owned anchor's form refuses (a digit first, a capital), and one no listing may hold.
PLATFORM_SIBLING = "com.apple/250.Example"
OUTSIDE = "com.apple/example sibling"

# sibling name -> whether it has the form of a sibling (the owned anchor is refused separately)
SIBLING_NAMES = {
    SIBLING: True,
    SECOND_SIBLING: True,
    PLATFORM_SIBLING: True,
    "com.apple/Example": True,
    "com.apple/example_one": True,
    "com.apple/9": True,
    "com.apple/netorch.other-owner": True,
    "com.apple/" + "a" * 63: True,
    "com.apple/" + "a" * 64: False,
    OUTSIDE: False,
    "com.apple/example-sibling/child": False,
    "com.apple//example": False,
    "com.apple/": False,
    "com.apple": False,
    "com.apple/-example": False,
    "com.apple/.example": False,
    "com.apple/_example": False,
    "com.apple/..": False,
    "com.apple/example;id": False,
    "com.apple/example$(id)": False,
    "com.apple/*": False,
    "com.apple/exampl\u00e9": False,
    "com.apple/example\n": False,
    "comXapple/example": False,
    "example-sibling": False,
    "x" + SIBLING: False,
    "-a": False,
    "": False,
}
# The four hook lines without the trailing word the printer may add.
N, NS = 'nat-anchor "com.apple/*"', 'nat-anchor "com.apple.internet-sharing"'
R, RS = 'rdr-anchor "com.apple/*"', 'rdr-anchor "com.apple.internet-sharing"'
ACCEPTED = [(N, R), (N, NS, R), (N, R, RS), (N, NS, R, RS)]
STOCK = f"{N} all\n{R} all"
FOREIGN_TRANSLATION = "rdr on lo0 inet proto udp from any to 192.0.2.10 port 45000 -> 192.0.2.20"
CLIENT_STATE = "all udp {guest}:45001 -> 192.0.2.77:7000 SINGLE:MULTIPLE"

# Taken from the tree this change is based on: the stored form of the
# installation below, and its admitted digest for one profile with the
# implementation fingerprint and the profile digest pinned as in the test.
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
# SHA-256 over three passes without translation-order reads (activating,
# healthy, pausing). Refreshed for the independent loaded endpoint checks.
BASE_CALLS = "8efa35de0b00bae058d3b2b5aa081de97aa3a18a5fb3c148b29bef2824a641f3"


class Ordered(Kernel):
    """The in-memory kernel of the owner tests with a main ruleset and sibling anchors."""

    def __init__(self, *, lasting: tuple[str, ...] = ()) -> None:
        super().__init__(lasting=lasting)
        self.hooks = STOCK
        self.children: list[str] = [ANCHOR, SIBLING]
        self.siblings: dict[str, str] = {}
        self.failing: dict[str, Exception] = {}
        self.reads: list[tuple[str, ...]] = []

    def _read(self, *read: str) -> None:
        self.reads.append(read)
        if read[-1] in self.failing:
            raise self.failing[read[-1]]

    def translation_hooks(self) -> str:
        self._read("hooks")
        return self.hooks

    def sibling_anchors(self) -> str:
        self._read("children")
        # As the printer writes its children: two spaces, the path, a line feed.
        return "".join(f"  {name}\n" for name in self.children)

    def sibling(self, anchor: str) -> str:
        self._read("sibling", anchor)
        return self.siblings.get(anchor, "")


ROUND = [("hooks",), ("children",), ("sibling", SIBLING)]


def chosen(environment: Any, backend: Any, *, decision: bool = True) -> Any:
    """The fixture's installation with the decision made, every profile admitted under it."""
    root, config, settings, _, snapshots = environment
    if decision:
        settings = replace(settings, translation_order="verified")
        root.write("installation.json", settings.to_dict())
    environment = (root, config, settings, backend, snapshots)
    approve_all(environment)
    return environment


def ready(report: Snapshot) -> list[str]:
    return sorted(key for key, item in report.profiles.items() if item.data["root_ready"] is True)


# ---- the judgement of the hook listing


def test_the_accepted_hooks_are_these_four_in_this_order() -> None:
    assert [f'{kind} "{anchor}"' for kind, anchor, _ in owner._TRANSLATION_HOOKS] == [N, NS, R, RS]
    # The two hooks of the parent anchor are required, the two sharing hooks are not.
    assert [required for _, _, required in owner._TRANSLATION_HOOKS] == [True, False, True, False]
    assert "translation-order-unverified" in owner.DEFERRAL_REASONS


def spelled(lines: tuple[str, ...]) -> list[str]:
    """Every way to print these lines with and without the trailing word."""
    return [
        "\n".join(line + tail for line, tail in zip(lines, tails, strict=True))
        for tails in itertools.product(("", " all"), repeat=len(lines))
    ]


@pytest.mark.parametrize("lines", ACCEPTED, ids=["stock", "sharing nat", "sharing rdr", "both"])
def test_the_stock_hooks_alone_or_with_the_sharing_hooks_in_place_are_in_order(
    lines: tuple[str, ...],
) -> None:
    for listing in spelled(lines):
        assert owner.translation_hooks_in_order(listing), listing
        # Empty lines are not hooks.
        assert owner.translation_hooks_in_order("\n" + listing.replace("\n", "\n\n") + "\n")


def test_every_other_listing_of_up_to_four_lines_is_not_in_order() -> None:
    """All sequences over the eight spellings and one foreign line, against the four accepted."""
    foreign = 'nat-anchor "com.apple.example/*" all'
    symbols = [line + tail for line in (N, NS, R, RS) for tail in ("", " all")] + [foreign]
    accepted = {tuple(sequence) for sequence in ACCEPTED}
    checked = 0
    for length in range(5):
        for sequence in itertools.product(symbols, repeat=length):
            expected = tuple(line.removesuffix(" all") for line in sequence) in accepted
            assert owner.translation_hooks_in_order("\n".join(sequence)) is expected, sequence
            checked += 1
    assert checked == 1 + 9 + 81 + 729 + 6561


@pytest.mark.parametrize(
    "listing",
    [
        "",
        N,
        R,
        f"{R}\n{N}",
        f"{NS}\n{N}\n{R}",
        f"{N}\n{R}\n{NS}",
        f"{N}\n{RS}\n{R}",
        f"{N}\n{N}\n{R}",
        f"{N}\n{R}\n{R}",
        f"{N}\n{NS}\n{NS}\n{R}",
        f"{N}\n{R}\n{RS}\n{RS}",
        f"{N}\n{R}\n{N}",
        f"{N} all all\n{R}",
        f"{N}  all\n{R}",
        f" {N}\n{R}",
        f"{N} \n{R}",
        f"{N}\t\n{R}",
        f"{N.upper()}\n{R}",
        f"{N.replace('"', "'")}\n{R}",
        f"{N}\n{R}\n ",
        f'{N}\n{R}\nbinat-anchor "com.apple/*" all',
        f"{N}\n{R}\n{FOREIGN_TRANSLATION}",
        f"{FOREIGN_TRANSLATION}\n{N}\n{R}",
        'nat-anchor "com.apple/*" all\rrdr-anchor "com.apple/*" all',
        f'{N}\n{R}\nnat-anchor "com.apple.internet-sharing/*" all',
        f"No ALTQ support in kernel\n{N}\n{R}",
    ],
)
def test_a_missing_repeated_misplaced_or_unknown_line_is_not_in_order(listing: str) -> None:
    assert owner.translation_hooks_in_order(listing) is False


@pytest.mark.parametrize("listing", [None, b"", STOCK.encode(), 0, [N, R], (N, R)])
def test_a_listing_that_is_not_text_is_not_in_order(listing: Any) -> None:
    assert owner.translation_hooks_in_order(listing) is False


# ---- the judgement of the siblings


def test_stock_hooks_and_an_empty_sibling_are_verified_from_one_read_each() -> None:
    backend = Ordered()

    assert owner._translation_order_verified(backend, ANCHOR) == (True, None)
    # The owned anchor is a child of the parent and is not read as a sibling.
    assert backend.reads == ROUND


def test_an_owned_anchor_that_does_not_exist_yet_and_no_sibling_are_verified() -> None:
    backend = Ordered()
    backend.children = []

    assert owner._translation_order_verified(backend, ANCHOR) == (True, None)
    assert backend.reads == [("hooks",), ("children",)]


@pytest.mark.parametrize(
    "listing",
    [FOREIGN_TRANSLATION, "  com.apple/example-sibling/child", " ", "\n", "anything"],
    ids=["translation", "child", "blank", "line feed", "text"],
)
def test_a_sibling_with_a_translation_or_a_child_is_not_verified(listing: str) -> None:
    backend = Ordered()
    backend.children = [SIBLING, ANCHOR, SECOND_SIBLING]
    backend.siblings[SECOND_SIBLING] = listing

    assert owner._translation_order_verified(backend, ANCHOR) == (False, None)
    assert ("sibling", ANCHOR) not in backend.reads


def test_sixty_four_children_are_read_and_sixty_five_are_not() -> None:
    backend = Ordered()
    backend.children = [ANCHOR] + [f"com.apple/sibling-{index}" for index in range(63)]

    assert owner._translation_order_verified(backend, ANCHOR) == (True, None)
    assert len(backend.reads) == 2 + 63

    backend.reads.clear()
    backend.children.append("com.apple/sibling-63")
    assert owner._translation_order_verified(backend, ANCHOR) == (False, None)
    # The bound is judged before any sibling is read.
    assert backend.reads == [("hooks",), ("children",)]


@pytest.mark.parametrize(
    "name",
    [
        "com.apple/_example",
        "com.apple/.example",
        "com.apple/example sibling",
        "com.apple/example-sibling/child",
        "com.apple/",
        "com.apple",
        "example-sibling",
        "-a",
        "com.apple/" + "a" * 64,
        "com.apple/example;id",
        "com.apple/*",
    ],
)
def test_a_child_whose_name_is_not_an_anchor_form_is_not_verified_and_nothing_is_read(
    name: str,
) -> None:
    backend = Ordered()
    backend.children = [SIBLING, name, ANCHOR]

    assert owner._translation_order_verified(backend, ANCHOR) == (False, None)
    # Not that name, and no other sibling either.
    assert backend.reads == [("hooks",), ("children",)]


def test_a_sibling_with_a_name_of_the_platforms_kind_is_read_like_any_other() -> None:
    backend = Ordered()
    backend.children = [PLATFORM_SIBLING, ANCHOR, "com.apple/Example_One"]

    assert owner._translation_order_verified(backend, ANCHOR) == (True, None)
    assert backend.reads[2:] == [
        ("sibling", PLATFORM_SIBLING),
        ("sibling", "com.apple/Example_One"),
    ]

    backend.siblings[PLATFORM_SIBLING] = FOREIGN_TRANSLATION
    assert owner._translation_order_verified(backend, ANCHOR) == (False, None)


@pytest.mark.parametrize("name", SIBLING_NAMES)
def test_the_owner_reads_a_sibling_only_under_a_name_of_the_sibling_form(name: str) -> None:
    assert (owner._SIBLING.fullmatch(name) is not None) is SIBLING_NAMES[name]
    # The form of the owned anchor is inside it: an owner's own form is a sibling's too.
    assert owner._SIBLING.fullmatch(ANCHOR) is not None


def test_a_child_that_is_listed_twice_is_not_verified() -> None:
    backend = Ordered()
    backend.children = [ANCHOR, SIBLING, SIBLING]

    assert owner._translation_order_verified(backend, ANCHOR) == (False, None)
    assert backend.reads == [("hooks",), ("children",)]


@pytest.mark.parametrize("read", ["hooks", "children", SIBLING])
@pytest.mark.parametrize(
    "error",
    [PFError("bounded PF backend operation failed"), OSError("no such tool"), ValueError("x")],
    ids=["owner-error", "os-error", "value-error"],
)
def test_a_listing_that_cannot_be_read_is_not_verified(read: str, error: Exception) -> None:
    backend = Ordered()
    backend.failing[read] = error

    assert owner._translation_order_verified(backend, ANCHOR) == (False, None)


@pytest.mark.parametrize("read", ["hooks", "children", SIBLING])
def test_a_listing_refused_for_a_notice_is_not_verified_and_says_so(read: str) -> None:
    backend = Ordered()
    notice = owner.PFListingNotice("siblings", 1)
    backend.failing[read] = notice

    # The notice itself is handed back: it names the listing that was refused.
    assert owner._translation_order_verified(backend, ANCHOR) == (False, notice)


# ---- the decision in the installation


def test_an_installation_without_the_decision_keeps_its_stored_form(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = environment[1]
    profile = config.profile("dns-udp")
    monkeypatch.setattr(owner, "implementation_digest", lambda: "f" * 64)
    monkeypatch.setattr(owner, "profile_digest", lambda config, profile: "e" * 64)
    plain = Installation(*PLAIN)

    assert plain.translation_order == "present"
    assert len(plain.to_dict()) == 9 and "translation_order" not in plain.to_dict()
    assert canonical_bytes(plain.to_dict()) == BASE_BYTES
    assert Installation.from_dict(strict_loads(BASE_BYTES)) == plain
    assert admitted_digest(config, profile, plain) == BASE_DIGEST

    decided = replace(plain, translation_order="verified")
    assert decided.to_dict() == {**plain.to_dict(), "translation_order": "verified"}
    assert Installation.from_dict(strict_loads(canonical_bytes(decided.to_dict()))) == decided
    assert admitted_digest(config, profile, decided) != BASE_DIGEST
    # Beside the two earlier decisions: each is stored and bound by itself.
    every = replace(decided, enable_reference="reacquire", cold_start="self-heal")
    assert Installation.from_dict(strict_loads(canonical_bytes(every.to_dict()))) == every
    assert len({admitted_digest(config, profile, item) for item in (plain, decided, every)}) == 3


@pytest.mark.parametrize(
    "value",
    ["present", None, "unverified", "Verified", "verified ", "", True, 1, ["verified"], {}],
)
def test_verified_is_the_only_decision_that_can_be_written(environment: Any, value: Any) -> None:
    raw = environment[2].to_dict()
    with pytest.raises(PFError, match="unsupported installation schema"):
        Installation.from_dict({**raw, "translation_order": value})
    with pytest.raises(PFError, match="unsupported installation schema"):
        Installation.from_dict({**raw, "translation_order": "verified", "order": "verified"})
    if value != "present":
        with pytest.raises(PFError, match="translation-order"):
            Installation(*PLAIN, translation_order=value)


def test_an_admission_shows_the_decision_it_covers(environment: Any) -> None:
    root, _, settings, _, _ = environment
    shown = admit(root, PAIR, acknowledge_bounded_risk=True)["resolved"]
    # Without the decision the admission prints what it printed before.
    assert "translation_order" not in shown
    root.write("installation.json", replace(settings, translation_order="verified").to_dict())
    shown = admit(root, PAIR, acknowledge_bounded_risk=True)["resolved"]
    assert shown["translation_order"] == "verified"


def test_the_review_shows_the_decision_only_where_it_was_made(
    environment: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import netorch.storage as storage

    root, _, settings, _, _ = environment
    # The entry point's boundary is replaced as the existing test of this command does.
    monkeypatch.setattr(owner, "require_mutation_qualified", lambda _capability: None)
    monkeypatch.setattr(owner.sys, "platform", "darwin")
    monkeypatch.setattr(owner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(owner, "Store", lambda directory: root)
    monkeypatch.setattr(owner, "protected_ancestors", lambda *a, **kw: None)
    monkeypatch.setattr(owner, "protected_code", lambda *a, **kw: None)
    monkeypatch.setattr(storage.Store, "_check_directory_info", staticmethod(lambda info: None))
    monkeypatch.setattr(storage, "_check_file", lambda fd: None)
    command = ["review-admission", "--root-dir", str(root.directory), "--profile", PAIR]

    assert owner.main(command) == 0
    plain = strict_loads(capsys.readouterr().out)
    root.write("installation.json", replace(settings, translation_order="verified").to_dict())
    assert owner.main(command) == 0
    decided = strict_loads(capsys.readouterr().out)

    # Without the decision the review prints the members it printed before.
    assert "translation_order" not in plain
    assert decided["translation_order"] == "verified"
    assert decided["expected_digest"] != plain["expected_digest"]
    assert {**decided, "expected_digest": plain["expected_digest"]} == {
        **plain,
        "translation_order": "verified",
    }


@pytest.mark.parametrize("decided", [True, False], ids=["chosen", "taken back"])
def test_changing_the_decision_voids_every_admission(environment: Any, decided: bool) -> None:
    backend = Ordered()
    environment = chosen(environment, backend, decision=not decided)
    root, _, settings, _, _ = environment
    assert observed_pass(environment)[0]["phase"] == "committed"
    changed = replace(settings, translation_order="verified" if decided else "present")
    root.write("installation.json", changed.to_dict())

    result, report = observed_pass(environment)

    assert result["phase"] == "inhibited" and sorted(result["pending"]) == list(EVERY_PROFILE)
    assert backend.rules == "" and ready(report) == []
    assert all(item.data["admitted"] is False for item in report.profiles.values())


# ---- without the decision


def test_without_the_decision_no_translation_order_reads_or_stored_setting_changes(
    environment: Any,
) -> None:
    backend = Ordered()
    # Everything the check would refuse, were it made.
    backend.hooks = f"{NS} all\n{R} all\n{FOREIGN_TRANSLATION}"
    backend.children = [SIBLING, OUTSIDE] * 40
    backend.siblings[SIBLING] = FOREIGN_TRANSLATION
    backend.failing = dict.fromkeys(("hooks", "children", SIBLING), PFError("unreadable"))
    environment = chosen(environment, backend, decision=False)
    root = environment[0]
    stored = (root.directory / "installation.json").read_bytes()
    assert b"translation_order" not in stored
    admissions = (root.directory / "admissions.json").read_bytes()

    result, report = observed_pass(environment)
    assert result["phase"] == "committed" and len(result["changed"]) == 4
    assert_nothing_deferred(environment, result, report)
    assert ready(report) == list(EVERY_PROFILE)
    result, report = observed_pass(environment)
    assert result["phase"] == "committed" and result["changed"] == []
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    assert observed_pass(environment)[0]["phase"] == "inhibited" and backend.rules == ""

    assert backend.reads == []
    assert (root.directory / "installation.json").read_bytes() == stored
    assert (root.directory / "admissions.json").read_bytes() == admissions
    assert hashlib.sha256(repr(backend.commands).encode()).hexdigest() == BASE_CALLS


# ---- with the decision: activation


@pytest.mark.parametrize("lines", ACCEPTED, ids=["stock", "sharing nat", "sharing rdr", "both"])
@pytest.mark.parametrize("tail", ["", " all"], ids=["bare", "all"])
def test_an_accepted_listing_activates_the_pair_and_keeps_it(
    environment: Any, lines: tuple[str, ...], tail: str
) -> None:
    backend = Ordered()
    backend.hooks = "\n".join(line + tail for line in lines)
    environment = chosen(environment, backend)

    result, report = observed_pass(environment)

    assert result["phase"] == "committed" and len(result["changed"]) == 4
    assert_nothing_deferred(environment, result, report)
    assert owned(backend) == ["dns-tcp", "dns-udp", PAIR, PAIR, "proxy-standard"]
    assert ready(report) == list(EVERY_PROFILE)
    # Checked twice, for the one profile that renders an outbound translation:
    # immediately before its activation, and once after the actions of the pass
    # for the pair that is then loaded.
    assert backend.reads == ROUND * 2

    # A healthy pass checks once, for the pair it keeps, and reloads nothing.
    replaces = sum(command[0] == "replace" for command in backend.commands)
    result, report = observed_pass(environment)
    assert result["phase"] == "committed" and result["changed"] == []
    assert backend.reads == ROUND * 3
    assert sum(command[0] == "replace" for command in backend.commands) == replaces


VIOLATIONS = {
    "nat hook missing": f"{R} all",
    "rdr hook missing": f"{N} all",
    "no hooks": "",
    "nat hook repeated": f"{N} all\n{N} all\n{R} all",
    "rdr hook repeated": f"{N} all\n{R} all\n{R} all",
    "rdr before nat": f"{R} all\n{N} all",
    "sharing nat before the stock hook": f"{NS} all\n{N} all\n{R} all",
    "sharing nat after the rdr hook": f"{N} all\n{R} all\n{NS} all",
    "sharing rdr before the stock rdr hook": f"{N} all\n{RS} all\n{R} all",
    "sharing nat repeated": f"{N} all\n{NS} all\n{NS} all\n{R} all",
    "unknown line": f"{N} all\n{R} all\n{FOREIGN_TRANSLATION}",
    "unknown first line": f'nat-anchor "com.apple.example/*" all\n{N} all\n{R} all',
    "other spacing": f"{N}  all\n{R} all",
}


@pytest.mark.parametrize("violation", VIOLATIONS)
def test_each_violation_of_the_hook_order_defers_the_pair_and_loads_the_others(
    environment: Any, violation: str
) -> None:
    backend = Ordered()
    backend.hooks = VIOLATIONS[violation]
    environment = chosen(environment, backend)

    result, report = observed_pass(environment)

    assert result["phase"] == "inhibited"
    assert_deferred(environment, result, report, {PAIR: REASON})
    assert owned(backend) == OTHERS and ready(report) == OTHERS
    assert sorted(result["changed"]) == [f"{key}:activate" for key in OTHERS]
    # The hooks decided: no sibling was read.
    assert backend.reads == [("hooks",)]
    # Nothing was written for the pair, and no reference was taken for it.
    assert PAIR not in environment[0].read("live.json")["records"]
    assert backend.commands.count(("reference",)) == 3

    # No acknowledgement is owed. The next pass that verifies activates it.
    backend.hooks = STOCK
    result, report = observed_pass(environment)
    assert result["phase"] == "committed" and result["changed"] == [f"{PAIR}:activate"]
    assert_nothing_deferred(environment, result, report)
    assert ready(report) == list(EVERY_PROFILE)


SIBLING_FAULTS = {
    "translation rule": lambda backend: backend.siblings.update({SIBLING: FOREIGN_TRANSLATION}),
    "child anchor": lambda backend: backend.siblings.update({SIBLING: f"  {SIBLING}/child"}),
    "sixty-five children": lambda backend: backend.children.extend(
        f"com.apple/sibling-{index}" for index in range(63)
    ),
    "name outside the form": lambda backend: backend.children.append(OUTSIDE),
    "unreadable sibling": lambda backend: backend.failing.update({SIBLING: PFError("x")}),
    "unreadable children": lambda backend: backend.failing.update({"children": OSError("x")}),
    "unreadable hooks": lambda backend: backend.failing.update({"hooks": PFError("x")}),
}


@pytest.mark.parametrize("fault", SIBLING_FAULTS)
def test_a_competing_or_unreadable_sibling_defers_the_pair_and_loads_the_others(
    environment: Any, fault: str
) -> None:
    backend = Ordered()
    SIBLING_FAULTS[fault](backend)
    environment = chosen(environment, backend)

    result, report = observed_pass(environment)

    assert result["phase"] == "inhibited"
    assert_deferred(environment, result, report, {PAIR: REASON})
    assert owned(backend) == OTHERS and ready(report) == OTHERS
    assert ("sibling", OUTSIDE) not in backend.reads
    assert ("sibling", ANCHOR) not in backend.reads


def test_a_host_redirect_and_a_guest_direct_profile_are_never_checked(environment: Any) -> None:
    backend = Ordered()
    backend.hooks = VIOLATIONS["no hooks"]
    backend.siblings[SIBLING] = FOREIGN_TRANSLATION
    root, config, settings, _, snapshots = environment
    settings = replace(settings, translation_order="verified")
    root.write("installation.json", settings.to_dict())
    environment = (root, config, settings, backend, snapshots)
    for key in OTHERS:  # the pair itself stays unadmitted
        admit(root, key, acknowledge_bounded_risk=True, now=STAMP - 1)

    for changed in (3, 0):
        result, report = observed_pass(environment)
        assert result["phase"] == "inhibited" and result["pending"] == [PAIR]
        assert len(result["changed"]) == changed
        assert_nothing_deferred(environment, result, report)
        assert owned(backend) == OTHERS and ready(report) == OTHERS
    assert backend.reads == []


def test_a_refused_read_of_the_check_is_recorded_with_the_notice_reason(environment: Any) -> None:
    backend = Ordered()
    backend.failing["children"] = owner.PFListingNotice("siblings", 1)
    environment = chosen(environment, backend)

    result, report = observed_pass(environment)

    assert result["deferred"] == {PAIR: REASON} and result["phase"] == "inhibited"
    # Which listing it was is handed back with the result.
    assert result["listing_notice"] == {"operation": "siblings", "unexpected_lines": 1}
    journal = environment[0].read("journal.json")
    assert journal["deferred"] == {PAIR: REASON} and journal["reason"] == "listing-notice"
    assert report.profiles[PAIR].data["deferred"] == REASON
    assert owned(backend) == OTHERS


# ---- with the decision: a pair that is already loaded


def converged(environment: Any, backend: Ordered) -> Any:
    environment = chosen(environment, backend)
    result, report = observed_pass(environment)
    assert result["phase"] == "committed" and ready(report) == list(EVERY_PROFILE)
    backend.reads.clear()
    return environment


def assert_withheld(
    environment: Any, result: dict[str, Any], report: Snapshot, expected: dict[str, str]
) -> None:
    """The journal, the result and the report name the same pairs and reasons.

    A withheld pair keeps its rules. It is not reported ready, it is not
    deferred and it is not pending.
    """
    root, _, _, backend, _ = environment
    assert result["withheld"] == expected and "deferred" not in result
    assert result["phase"] == "inhibited"
    journal = root.read("journal.json")
    assert journal["withheld"] == expected and journal["phase"] == "inhibited"
    assert "deferred" not in journal
    assert expected and set(expected.values()) <= owner.WITHHOLDING_REASONS
    assert {
        key: item.data["withheld"]
        for key, item in report.profiles.items()
        if "withheld" in item.data
    } == expected
    for key in expected:
        assert key not in result["pending"]
        assert key in owned(backend)
        assert report.profiles[key].state == "present"
        assert report.profiles[key].data["root_ready"] is False
        assert "deferred" not in report.profiles[key].data


def test_withholding_reasons_are_a_second_closed_vocabulary() -> None:
    assert (
        frozenset({REASON, "runtime-unknown", "endpoint-unverified", "ports-unverified"})
        == owner.WITHHOLDING_REASONS
    )
    assert isinstance(owner.WITHHOLDING_REASONS, frozenset)
    assert list(owner._withholdings({"b": REASON, "a": REASON})) == ["a", "b"]
    assert owner._withholdings({}) == {}
    # No other word, not even another deferral reason, is a reason to withhold.
    for reason in [*sorted(owner.DEFERRAL_REASONS - owner.WITHHOLDING_REASONS), "withheld", ""]:
        with pytest.raises(PFError, match="unknown withholding reason"):
            owner._withholdings({PAIR: reason})


# what stops the check from passing -> how the fake kernel gets there
LOADED_FAULTS = {
    "hook order": lambda backend: setattr(
        backend, "hooks", VIOLATIONS["sharing nat before the stock hook"]
    ),
    **SIBLING_FAULTS,
}


@pytest.mark.parametrize("fault", LOADED_FAULTS)
def test_a_loaded_pair_is_withheld_and_never_withdrawn_while_the_check_does_not_pass(
    environment: Any, fault: str
) -> None:
    backend = Ordered()
    environment = converged(environment, backend)
    root = environment[0]
    live = (root.directory / "live.json").read_bytes()
    rules, commands = backend.rules, len(backend.commands)
    LOADED_FAULTS[fault](backend)

    for _ in range(3):
        result, report = observed_pass(environment)

        # Its rules stay loaded and unchanged: nothing is written, withdrawn,
        # invalidated or pending for it, and every other profile stays ready.
        assert set(result) == {"schema_version", "phase", "changed", "pending", "withheld"}
        assert result["changed"] == [] and result["pending"] == []
        assert_withheld(environment, result, report, {PAIR: REASON})
        assert backend.rules == rules and ready(report) == OTHERS
        assert (root.directory / "live.json").read_bytes() == live
        journal = root.read("journal.json")
        assert set(journal) == {"schema_version", "phase", "actions", "finished_at", "withheld"}
        assert {item["operation"] for item in journal["actions"]} == {"noop"}
    assert backend.kills == []
    assert not any(command[0] in {"replace", "drain"} for command in backend.commands[commands:])

    # The check passes again: the pair is ready again, from the rules it kept,
    # and a pass without a withheld pair writes what it wrote before.
    backend.hooks, backend.children = STOCK, [ANCHOR, SIBLING]
    backend.siblings, backend.failing = {}, {}
    result, report = observed_pass(environment)
    assert result == {"schema_version": 1, "phase": "committed", "changed": [], "pending": []}
    assert ready(report) == list(EVERY_PROFILE) and backend.rules == rules
    assert set(root.read("journal.json")) == {"schema_version", "phase", "actions", "finished_at"}
    assert all("withheld" not in item.data for item in report.profiles.values())


def test_a_loaded_pair_withheld_for_a_refused_read_names_the_notice_and_its_listing(
    environment: Any,
) -> None:
    backend = Ordered()
    environment = converged(environment, backend)
    rules = backend.rules
    backend.failing["hooks"] = owner.PFListingNotice("translation-hooks", 2)

    result, report = observed_pass(environment)

    assert result == {
        "schema_version": 1,
        "phase": "inhibited",
        "changed": [],
        "pending": [],
        "withheld": {PAIR: REASON},
        "listing_notice": {"operation": "translation-hooks", "unexpected_lines": 2},
    }
    journal = environment[0].read("journal.json")
    assert (journal["phase"], journal["reason"]) == ("inhibited", "listing-notice")
    assert journal["withheld"] == {PAIR: REASON} and "listing_notice" not in journal
    assert backend.rules == rules and ready(report) == OTHERS


def test_a_withheld_pair_keeps_its_states(environment: Any) -> None:
    guest = address(environment, "media-controller")
    backend = Ordered(lasting=(CLIENT_STATE.format(guest=guest),))
    environment = converged(environment, backend)
    backend.hooks = VIOLATIONS["sharing nat before the stock hook"]

    for _ in range(3):
        result, report = observed_pass(environment)
        assert result["changed"] == []
        assert_withheld(environment, result, report, {PAIR: REASON})

    # A state of the pair is in the table on each of these passes, and no state
    # of that guest was invalidated: the check never retires anything.
    assert backend.kills == [] and not any(command[0] == "drain" for command in backend.commands)

    backend.hooks = STOCK
    result, report = observed_pass(environment)
    assert result["phase"] == "committed" and result["changed"] == []
    assert ready(report) == list(EVERY_PROFILE)


class Moving(Ordered):
    """The main ruleset changes right after the last read of the first check of a pass."""

    def sibling(self, anchor: str) -> str:
        answer = super().sibling(anchor)
        self.hooks = VIOLATIONS["sharing nat before the stock hook"]
        return answer


def test_a_pair_whose_order_changes_between_its_check_and_its_load_is_not_reported_ready(
    environment: Any,
) -> None:
    backend = Moving()
    environment = chosen(environment, backend)

    result, report = observed_pass(environment)

    # The check immediately before the activation passed, so the pair is loaded.
    # The check after the actions of the same pass did not: it is withheld.
    assert sorted(result["changed"]) == [f"{key}:activate" for key in EVERY_PROFILE]
    assert_withheld(environment, result, report, {PAIR: REASON})
    assert ready(report) == OTHERS
    assert backend.reads == [*ROUND, ("hooks",)]

    # The following passes keep it loaded and withheld; nothing retires it.
    result, report = observed_pass(environment)
    assert result["changed"] == []
    assert_withheld(environment, result, report, {PAIR: REASON})


class Watching(Ordered):
    """Notes, at each read of the check, what the pass had recorded and issued by then."""

    def __init__(self, root: Any) -> None:
        super().__init__()
        self.root = root
        self.noted: list[tuple[str, bool, list[str]]] = []

    def _read(self, *read: str) -> None:
        journal = self.root.read("journal.json")
        issued = [command[0] for command in self.commands if command[0] in {"replace", "drain"}]
        self.noted.append((journal["phase"], "started_at" in journal, issued))
        super()._read(*read)


def test_no_read_of_the_check_precedes_the_record_of_the_planned_actions(
    environment: Any,
) -> None:
    backend = Watching(environment[0])
    environment = chosen(environment, backend)

    observed_pass(environment)  # activates the pair: one check before it, one after the actions
    observed_pass(environment)  # keeps it: one check after the actions

    assert len(backend.noted) == 3 * len(ROUND)
    # At every read the journal held the record this pass wrote at its start.
    assert all((phase, started) == ("applying", True) for phase, started, _ in backend.noted)


def test_no_withdrawal_and_no_drain_waits_for_the_reads_of_the_check(environment: Any) -> None:
    backend = Watching(environment[0])
    environment = converged(environment, backend)
    root = environment[0]
    resolver = address(environment, "resolver")
    # The resolver is held: its two rules are withdrawn and a client's state of
    # one of them is invalidated. The pair is not concerned and stays loaded.
    backend.flow_states = f"all udp 192.0.2.77:54321 -> {resolver}:53 NO_TRAFFIC:SINGLE"
    root.write(
        "operator-intent.json", intent_to_dict(Intent().hold("resolver", "maintenance", "holder-1"))
    )
    backend.noted.clear()
    backend.commands.clear()

    result, report = observed_pass(environment)

    assert result["changed"] == [
        "dns-tcp:withdraw",
        "dns-udp:withdraw",
        "dns-tcp:drain",
        "dns-udp:drain",
    ]
    assert backend.kills == [resolver] and PAIR in ready(report)
    # One check, and each of its reads came after every withdrawal and the invalidation.
    assert [issued for _, _, issued in backend.noted] == [["replace", "replace", "drain"]] * 3


def test_a_pair_that_a_pause_retires_anyway_is_not_checked(environment: Any) -> None:
    backend = Ordered()
    environment = converged(environment, backend)
    backend.hooks = VIOLATIONS["no hooks"]
    environment[0].write("operator-intent.json", intent_to_dict(Intent().pause()))

    result, report = observed_pass(environment)

    assert result["phase"] == "inhibited" and backend.rules == ""
    assert_nothing_deferred(environment, result, report)
    assert backend.reads == []


# ---- with the decision: more than one pair


def every_profile_a_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fixture's policy has one pair with an outbound translation; here every profile is one."""
    monkeypatch.setattr(owner, "_translates_outbound", lambda rules: bool(rules))


def test_each_loaded_pair_is_withheld_by_the_one_check_of_a_pass(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    every_profile_a_pair(monkeypatch)
    backend = Ordered()
    environment = converged(environment, backend)
    rules = backend.rules
    backend.hooks = VIOLATIONS["sharing nat before the stock hook"]

    result, report = observed_pass(environment)

    assert_withheld(environment, result, report, dict.fromkeys(EVERY_PROFILE, REASON))
    assert ready(report) == [] and backend.rules == rules
    # One check for all of them, not one each: the hooks decided and were read once.
    assert backend.reads == [("hooks",)]


class Refusing(Ordered):
    """Once switched on, each read of the hooks is refused for a notice with one more line."""

    refusing = False
    refused = 0

    def translation_hooks(self) -> str:
        if self.refusing:
            self.refused += 1
            raise owner.PFListingNotice("translation-hooks", self.refused)
        return super().translation_hooks()


def test_a_pass_that_defers_and_withholds_hands_back_its_first_refused_read(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    every_profile_a_pair(monkeypatch)
    backend = Refusing()
    root, config, settings, _, snapshots = environment
    settings = replace(settings, translation_order="verified")
    root.write("installation.json", settings.to_dict())
    environment = (root, config, settings, backend, snapshots)
    admit(root, "dns-tcp", acknowledge_bounded_risk=True, now=STAMP - 1)
    result, report = observed_pass(environment)
    assert owned(backend) == ["dns-tcp"] and ready(report) == ["dns-tcp"]
    approve_all(environment)
    backend.refusing = True

    result, report = observed_pass(environment)

    # One check before each of three activations, then the one for the loaded profile.
    assert backend.refused == 4
    waiting = dict.fromkeys(["dns-udp", PAIR, "proxy-standard"], REASON)
    assert (result["deferred"], result["withheld"]) == (waiting, {"dns-tcp": REASON})
    assert result["pending"] == list(waiting) and result["changed"] == []
    journal = root.read("journal.json")
    assert (journal["deferred"], journal["withheld"]) == (waiting, {"dns-tcp": REASON})
    assert (journal["phase"], journal["reason"]) == ("inhibited", "listing-notice")
    assert owned(backend) == ["dns-tcp"] and ready(report) == []
    assert {key: item.data.get("deferred") for key, item in report.profiles.items()} == {
        "dns-tcp": None,
        **waiting,
    }
    assert report.profiles["dns-tcp"].data["withheld"] == REASON
    # Of the four refused reads the first is the one handed back.
    assert result["listing_notice"] == {"operation": "translation-hooks", "unexpected_lines": 1}


# ---- with the decision: the bound of one whole check


class Slow(Ordered):
    """Every read of the check takes this long, on a clock of its own."""

    def __init__(self, cost: float) -> None:
        super().__init__()
        self.children = [ANCHOR, SIBLING, SECOND_SIBLING]
        self.cost, self.time = cost, 0.0

    def _read(self, *read: str) -> None:
        super()._read(*read)
        self.time += self.cost


def test_the_bound_of_a_check_is_chosen_from_the_calls_it_can_make() -> None:
    # The hooks, the children and one call per sibling: at most 66.
    assert owner._MAX_SIBLINGS + 2 == 66
    assert owner._TRANSLATION_CHECK_SECONDS == 8.0


@pytest.mark.parametrize(
    "cost,verdict,reads",
    [
        (1.5, True, 4),  # ends after 6 of 8 seconds
        (2.0, False, 4),  # ends exactly when the bound is used up
        (3.0, False, 3),  # the second sibling is not read any more
        (4.0, False, 2),  # no sibling is read
        (9.0, False, 1),  # the children are not read
    ],
)
def test_a_check_stops_when_its_bound_is_used_up_and_has_then_not_passed(
    cost: float, verdict: bool, reads: int
) -> None:
    backend = Slow(cost)

    passed = owner._translation_order_verified(backend, ANCHOR, clock=lambda: backend.time)

    assert passed == (verdict, None)
    assert backend.reads == [*ROUND, ("sibling", SECOND_SIBLING)][:reads]


def test_a_check_whose_bound_is_used_up_before_its_first_call_reads_nothing() -> None:
    backend = Ordered()
    ticks = iter([0.0, owner._TRANSLATION_CHECK_SECONDS])

    assert owner._translation_order_verified(backend, ANCHOR, clock=lambda: next(ticks)) == (
        False,
        None,
    )
    assert backend.reads == []


def test_a_used_up_bound_defers_an_activation_and_withholds_a_loaded_pair(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = Ordered()
    environment = chosen(environment, backend)
    monkeypatch.setattr(owner, "_TRANSLATION_CHECK_SECONDS", 0.0)

    result, report = observed_pass(environment)
    assert_deferred(environment, result, report, {PAIR: REASON})
    assert owned(backend) == OTHERS and backend.reads == []

    monkeypatch.undo()
    result, report = observed_pass(environment)
    assert result["phase"] == "committed" and ready(report) == list(EVERY_PROFILE)
    backend.reads.clear()
    monkeypatch.setattr(owner, "_TRANSLATION_CHECK_SECONDS", 0.0)

    result, report = observed_pass(environment)
    assert_withheld(environment, result, report, {PAIR: REASON})
    assert backend.reads == []


# ---- with the decision: a lost enable reference beside a refused read of the check


class Lossy(Ordered):
    """Another tool can take the enable reference away: a complete read, not listed."""

    reference_listed = True

    def reference_held(self) -> bool:
        return self.reference_listed


@pytest.mark.parametrize("loaded", [True, False], ids=["pair loaded", "pair not loaded"])
def test_a_lost_enable_reference_is_named_while_a_read_of_the_check_is_refused_on_every_pass(
    environment: Any, loaded: bool
) -> None:
    backend = Lossy()
    notice = owner.PFListingNotice("siblings", 1)
    if loaded:
        environment = converged(environment, backend)
        backend.failing["children"] = notice
        kept = {"withheld": {PAIR: REASON}}
    else:
        backend.failing["children"] = notice
        environment = chosen(environment, backend)
        kept = {"deferred": {PAIR: REASON}}
    root = environment[0]

    result, report = observed_pass(environment)
    # With the reference verified the notice is the one reason of the record.
    assert root.read("journal.json")["reason"] == "listing-notice" and ready(report) == OTHERS

    backend.reference_listed = False
    for _ in range(3):
        result, report = observed_pass(environment)
        journal = root.read("journal.json")
        # The notice does not take the place of the finding, on any pass ...
        assert journal["reason"] == "enable-reference-unverified" and ready(report) == []
        assert {key: journal[key] for key in kept} == kept
        # ... and the listing that was refused is still handed back.
        assert result["listing_notice"] == {"operation": "siblings", "unexpected_lines": 1}


# ---- the backend script: three read-only operations


def at(anchor: str, listing: str) -> str:
    """The fake's file and fault name for a listing of an anchor other than the owned one."""
    return "at-" + anchor.replace("/", "+") + "-" + listing


def anchor_aware(sandbox: Sandbox) -> Sandbox:
    """Let the fake of the script tests answer for anchors other than the owned one."""
    tool = sandbox.script.parent / "tools" / "pfctl"
    text = tool.read_text()
    named = '    name = ("anchor-" if anchored else "") + rest[1]\n'
    answered = 'elif name == "parse":\n'
    assert text.count(named) == 1 and text.count(answered) == 1
    text = text.replace(
        named,
        named
        + f"    if anchored and arguments[1] != {ANCHOR!r}:\n"
        + '        name = "at-" + arguments[1].replace("/", "+") + "-" + rest[1]\n',
    )
    text = text.replace(
        answered, 'elif name.startswith("at-"):\n    sys.stdout.write(stored(name))\n' + answered
    )
    tool.write_text(text)
    return sandbox


@pytest.fixture
def sandbox(tmp_path: Path) -> Sandbox:
    return anchor_aware(Sandbox(tmp_path))


def fault(sandbox: Sandbox, name: str, value: dict[str, Any]) -> None:
    sandbox.kernel("faults", json.dumps({name: value}))


@needs_bash
def test_the_three_operations_print_listings_and_change_nothing(sandbox: Sandbox) -> None:
    hooks = f"{N} all\n{NS} all\n{R} all\n"
    children = f"  {ANCHOR}\n  {SIBLING}\n"
    sandbox.kernel("main-nat", hooks)
    sandbox.kernel(at(PARENT, "Anchors"), children)

    assert (sandbox.run("translation-hooks", ANCHOR).stdout, sandbox.calls) == (hooks, ["-s nat"])
    result = sandbox.run("siblings", ANCHOR)
    assert (result.returncode, result.stdout) == (0, children)
    assert sandbox.calls[1:] == [f"-a {PARENT} -s Anchors"]
    result = sandbox.run("sibling", ANCHOR, SIBLING)
    assert (result.returncode, result.stdout) == (0, "")
    assert sandbox.calls[2:] == [f"-a {SIBLING} -s nat", f"-a {SIBLING} -s Anchors"]

    # A sibling's translations and children are printed, whichever it has.
    sandbox.kernel(at(SIBLING, "nat"), FOREIGN_TRANSLATION + "\n")
    assert sandbox.run("sibling", ANCHOR, SIBLING).stdout == FOREIGN_TRANSLATION + "\n"
    sandbox.kernel(at(SIBLING, "nat"), "")
    sandbox.kernel(at(SIBLING, "Anchors"), f"  {SIBLING}/child\n")
    assert sandbox.run("sibling", ANCHOR, SIBLING).stdout == f"  {SIBLING}/child\n"
    # Listings only: nothing was parsed, loaded, killed or enabled.
    assert all(re.fullmatch(r"(-a \S+ )?-s \w+", call) for call in sandbox.calls)
    assert sandbox.loads == [] and sandbox.live == ""


@needs_bash
@pytest.mark.parametrize(
    "arguments",
    [
        ("translation-hooks", "extra"),
        ("siblings", "extra"),
        ("sibling",),
        ("sibling", SIBLING, SECOND_SIBLING),
        ("sibling", ANCHOR),
    ],
    ids=["hooks extra", "siblings extra", "no sibling", "two siblings", "the owned anchor"],
)
def test_wrong_arguments_of_the_three_operations_are_refused_before_any_pfctl_call(
    sandbox: Sandbox, arguments: tuple[str, ...]
) -> None:
    result = sandbox.run(arguments[0], ANCHOR, *arguments[1:])

    assert (result.returncode, result.stdout) == (64, "")
    assert sandbox.calls == []


@needs_bash
@pytest.mark.parametrize("name", [*SIBLING_NAMES, ANCHOR])
def test_a_sibling_name_is_given_to_pfctl_only_in_the_form_the_owner_accepts(
    sandbox: Sandbox, name: str
) -> None:
    """One table through the script and through the owner's expression: equal answers."""
    result = sandbox.run("sibling", ANCHOR, name)

    if SIBLING_NAMES.get(name, False):
        assert (result.returncode, result.stdout) == (0, "")
        assert sandbox.calls == [f"-a {name} -s nat", f"-a {name} -s Anchors"]
    else:
        assert (result.returncode, result.stdout) == (64, "")
        assert sandbox.calls == []


def test_the_script_has_one_expression_for_its_anchor_and_one_for_a_sibling() -> None:
    lines = [line.strip() for line in SCRIPT.read_text().splitlines() if "=~ ^com" in line]
    form = r'\[\[ .*"\$[12]" =~ (\S+) \]\] \|\| exit 64'
    found = [matched[1] for line in lines if (matched := re.fullmatch(form, line)) is not None]
    assert len(lines) == len(found) == 2
    # The same expression as the owner's, in the script's spelling.
    assert found[1] == "^" + owner._SIBLING.pattern.removesuffix("\\Z") + "$"


@needs_bash
@pytest.mark.parametrize(
    "operation,listing",
    [
        (("translation-hooks",), "nat"),
        (("siblings",), at(PARENT, "Anchors")),
        (("sibling", SIBLING), at(SIBLING, "nat")),
        (("sibling", SIBLING), at(SIBLING, "Anchors")),
    ],
    ids=["hooks", "children", "sibling translations", "sibling children"],
)
@pytest.mark.parametrize(
    "answer,status,written",
    [
        ({"stderr": UNKNOWN}, 76, "1\n"),
        ({"stderr": UNKNOWN, "stdout": ""}, 76, "1\n"),
        ({"exit": 1}, 1, ""),
        ({"exit": 1, "stderr": UNKNOWN}, 1, ""),
    ],
    ids=["notice", "notice and nothing", "failed", "failed with text"],
)
def test_each_read_of_the_check_is_refused_for_a_warning_and_for_a_failure(
    sandbox: Sandbox,
    operation: tuple[str, ...],
    listing: str,
    answer: dict[str, Any],
    status: int,
    written: str,
) -> None:
    """An empty answer is the one that counts as proof here, so a warning must not pass."""
    fault(sandbox, listing, answer)

    result = sandbox.run(operation[0], ANCHOR, *operation[1:])

    assert (result.returncode, result.stderr) == (status, written)


# ---- the owner's backend over the script


@pytest.fixture
def scripted(tmp_path: Path, environment: Any, monkeypatch: pytest.MonkeyPatch) -> Scripted:
    made = Scripted(tmp_path / "script", environment, monkeypatch)
    anchor_aware(made.sandbox)
    root, _, settings, _, _ = environment
    decided = replace(settings, translation_order="verified")
    root.write("installation.json", decided.to_dict())
    made.backend.installation = decided
    made.sandbox.kernel(at(PARENT, "Anchors"), f"  {ANCHOR}\n  {SIBLING}\n")
    admit(root, PAIR, acknowledge_bounded_risk=True, now=STAMP - 1)
    return made


@needs_bash
def test_over_the_script_a_verified_order_loads_the_pair(scripted: Scripted) -> None:
    result = scripted.one_pass()

    assert result["changed"] == [f"{PAIR}:activate"] and "deferred" not in result
    live = scripted.sandbox.live.splitlines()
    assert [line.split()[0] for line in live] == ["nat", "rdr"]
    calls = scripted.sandbox.calls
    order = [f"-a {PARENT} -s Anchors", f"-a {SIBLING} -s nat", f"-a {SIBLING} -s Anchors"]
    # Once immediately before the activation and once after the actions of the pass.
    assert [call for call in calls if call in order] == order * 2
    # The owned anchor is not read as a sibling: its own shape check lists its children.
    assert calls.count(f"-a {ANCHOR} -s Anchors") == calls.count(f"-a {ANCHOR} -s Tables")
    assert scripted.reports[-1].profiles[PAIR].data["root_ready"] is True


@needs_bash
def test_over_the_script_an_empty_sibling_of_the_platforms_kind_does_not_defer(
    scripted: Scripted,
) -> None:
    sandbox = scripted.sandbox
    sandbox.kernel(at(PARENT, "Anchors"), f"  {PLATFORM_SIBLING}\n  {ANCHOR}\n")

    result = scripted.one_pass()

    assert result["changed"] == [f"{PAIR}:activate"] and "deferred" not in result
    read = [f"-a {PLATFORM_SIBLING} -s nat", f"-a {PLATFORM_SIBLING} -s Anchors"]
    assert [call for call in sandbox.calls if call in read] == read * 2


@needs_bash
@pytest.mark.parametrize(
    "case",
    [
        "name outside the form",
        "sibling translation",
        "platform sibling translation",
        "sibling child",
        "hooks",
        "notice",
    ],
)
def test_over_the_script_each_unverified_order_defers_the_pair(
    scripted: Scripted, case: str
) -> None:
    sandbox = scripted.sandbox
    outside = OUTSIDE
    if case == "name outside the form":
        sandbox.kernel(at(PARENT, "Anchors"), f"  {ANCHOR}\n  {SIBLING}\n  {outside}\n")
    elif case == "sibling translation":
        sandbox.kernel(at(SIBLING, "nat"), FOREIGN_TRANSLATION + "\n")
    elif case == "platform sibling translation":
        sandbox.kernel(at(PARENT, "Anchors"), f"  {PLATFORM_SIBLING}\n  {ANCHOR}\n")
        sandbox.kernel(at(PLATFORM_SIBLING, "nat"), FOREIGN_TRANSLATION + "\n")
    elif case == "sibling child":
        sandbox.kernel(at(SIBLING, "Anchors"), f"  {SIBLING}/child\n")
    elif case == "hooks":
        sandbox.kernel("main-nat", f"{NS} all\n{N} all\n{R} all\n")
    else:
        fault(sandbox, at(PARENT, "Anchors"), {"stderr": UNKNOWN})

    result = scripted.one_pass()

    assert result["phase"] == "inhibited" and result["deferred"] == {PAIR: REASON}
    assert result["changed"] == [] and sandbox.live == "" and sandbox.loads == []
    assert "-E" not in sandbox.calls
    journal = scripted.journal()
    assert journal["deferred"] == {PAIR: REASON}
    assert journal.get("reason") == ("listing-notice" if case == "notice" else None)
    assert scripted.reports[-1].profiles[PAIR].data["deferred"] == REASON
    # A name of another form was never given to pfctl, and then no sibling was read.
    assert not any(outside in call for call in sandbox.calls)
    if case == "name outside the form":
        assert not any(call.startswith(f"-a {SIBLING} ") for call in sandbox.calls)
    scripted.no_tool_text(result)


def test_the_owners_backend_refuses_a_sibling_name_before_it_calls_the_script(
    scripted: Scripted,
) -> None:
    for name in (OUTSIDE, ANCHOR, "com.apple/a/b", "com.apple/_x", "-s", "", None):
        with pytest.raises(PFError, match="sibling anchor has no accepted form"):
            scripted.backend.sibling(name)  # type: ignore[arg-type]
    assert scripted.results == []


# ---- a listed name is taken as the printer prints it


class Raw(Ordered):
    """The children of the parent anchor, given as the text a tool would print."""

    listing = ""

    def sibling_anchors(self) -> str:
        self._read("children")
        return self.listing


# White space other than the printer's own two spaces and its line feed, by code point.
POINTS = (0x20, 0x09, 0x0D, 0x0B, 0x0C, 0x1C, 0x1D, 0x1E, 0x1F, 0x85, 0xA0, 0x2028, 0x2029, 0x3000)
SPACES = [chr(point) for point in POINTS]


@pytest.mark.parametrize(
    "listing,names",
    [
        ("", []),
        (f"  {ANCHOR}\n", [ANCHOR]),
        (f"  {ANCHOR}\n  {SIBLING}\n", [ANCHOR, SIBLING]),
        (f"  {PLATFORM_SIBLING}\n  {ANCHOR}\n", [PLATFORM_SIBLING, ANCHOR]),
        # A last line without its line feed is still a line.
        (f"  {ANCHOR}\n  {SIBLING}", [ANCHOR, SIBLING]),
    ],
    ids=["no child", "one", "two", "platform kind", "no final line feed"],
)
def test_a_listing_of_children_is_read_line_by_line_as_it_was_printed(
    listing: str, names: list[str]
) -> None:
    assert owner._listed_children(listing) == names


@pytest.mark.parametrize(
    "listing",
    [
        # the indentation is exactly the printer's two spaces
        f"{SIBLING}\n",
        f" {SIBLING}\n",
        f"   {SIBLING}\n",
        f"\t{SIBLING}\n",
        f" \t{SIBLING}\n",
        # an empty line is not a name, wherever it stands
        "\n",
        f"\n  {SIBLING}\n",
        f"  {ANCHOR}\n\n  {SIBLING}\n",
        f"  {SIBLING}\n\n",
        "  \n",
        # one name per line
        f"  {SIBLING} {ANCHOR}\n",
        f"  {SIBLING}  {ANCHOR}\n",
        # what remains must be a sibling's name exactly
        f"  {OUTSIDE}\n",
        f"  {SIBLING}/child\n",
        "  example-sibling\n",
        f"  {ANCHOR}\n  com.apple/_example\n",
    ],
)
def test_a_line_that_is_not_two_spaces_and_one_name_makes_the_listing_unusable(
    listing: str,
) -> None:
    assert owner._listed_children(listing) is None


@pytest.mark.parametrize("listing", [None, b"", f"  {SIBLING}\n".encode(), 0, [f"  {SIBLING}"]])
def test_a_listing_of_children_that_is_not_text_is_unusable(listing: Any) -> None:
    assert owner._listed_children(listing) is None


@pytest.mark.parametrize("space", SPACES, ids=[repr(space) for space in SPACES])
def test_a_name_with_any_other_white_space_is_not_verified_and_never_handed_on(space: str) -> None:
    """The child that exists holds a translation; no anchor of the trimmed name exists."""
    for odd in (SIBLING + space, space + SIBLING, f"{SIBLING}{space}{space}"):
        backend = Raw()
        backend.listing = f"  {odd}\n  {ANCHOR}\n"
        backend.siblings[odd] = FOREIGN_TRANSLATION

        assert owner._listed_children(backend.listing) is None
        assert owner._translation_order_verified(backend, ANCHOR) == (False, None)
        # Neither that child under another spelling nor any other sibling was read.
        assert backend.reads == [("hooks",), ("children",)]


@pytest.mark.parametrize("space", SPACES, ids=[repr(space) for space in SPACES])
def test_white_space_between_two_names_never_makes_two_lines(space: str) -> None:
    """Only a line feed ends a line: nothing else may split one printed line into two names."""
    backend = Raw()
    backend.listing = f"  {SIBLING}{space}  {SECOND_SIBLING}\n  {ANCHOR}\n"

    assert owner._translation_order_verified(backend, ANCHOR) == (False, None)
    assert backend.reads == [("hooks",), ("children",)]


def test_the_owners_backend_hands_the_listing_of_children_on_untrimmed(
    scripted: Scripted, monkeypatch: pytest.MonkeyPatch
) -> None:
    printed = f"  {SIBLING} \n  {ANCHOR}\n"
    monkeypatch.setattr(owner, "run", lambda argv, **kwargs: Result(0, printed.encode(), b""))

    assert scripted.backend.sibling_anchors() == printed
    assert owner._listed_children(scripted.backend.sibling_anchors()) is None


@needs_bash
@pytest.mark.parametrize("space", [" ", "\t", "\x0b", "\xa0"], ids=repr)
def test_over_the_script_a_child_named_with_other_white_space_defers_the_pair(
    scripted: Scripted, space: str
) -> None:
    sandbox = scripted.sandbox
    odd = SIBLING + space
    sandbox.kernel(at(PARENT, "Anchors"), f"  {odd}\n  {ANCHOR}\n")
    # The child that exists holds a translation; no anchor of the trimmed name exists.
    sandbox.kernel(at(odd, "nat"), FOREIGN_TRANSLATION + "\n")

    result = scripted.one_pass()

    assert result["phase"] == "inhibited" and result["deferred"] == {PAIR: REASON}
    assert sandbox.live == "" and sandbox.loads == []
    # The tool was asked for the children, and for no sibling under any spelling.
    assert f"-a {PARENT} -s Anchors" in sandbox.calls
    assert not any(call.startswith("-a com.apple/example") for call in sandbox.calls)
    scripted.no_tool_text(result)


# ---- a refused read of the check leaves the trace of every other refused listing

NOTICE_LINE = (
    '{"error":"PFListingNotice","operation":"siblings","reason":"listing-notice",'
    '"schema_version":1,"unexpected_lines":2}\n'
)


@needs_bash
@pytest.mark.parametrize(
    "operation,listing,calls",
    [
        # `inspect` reads the hooks first; the check's own read is the second.
        ("translation-hooks", "nat", [2]),
        ("siblings", at(PARENT, "Anchors"), [1]),
        ("sibling", at(SIBLING, "nat"), [1]),
        ("sibling", at(SIBLING, "Anchors"), [1]),
    ],
    ids=["hooks", "children", "sibling translations", "sibling children"],
)
def test_over_the_script_a_refused_read_of_the_check_names_its_operation_and_count(
    scripted: Scripted, operation: str, listing: str, calls: list[int]
) -> None:
    fault(scripted.sandbox, listing, {"stderr": UNKNOWN + UNKNOWN, "calls": calls})

    result = scripted.one_pass()

    assert result["deferred"] == {PAIR: REASON}
    assert result["listing_notice"] == {"operation": operation, "unexpected_lines": 2}
    assert scripted.journal()["reason"] == "listing-notice"
    assert "listing_notice" not in scripted.journal()
    scripted.no_tool_text(result)


@pytest.mark.parametrize("operation", ["translation-hooks", "siblings", "sibling"])
def test_each_read_of_the_check_can_be_refused_for_a_notice(
    scripted: Scripted, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    """The script's own status for a notice means one for each of the three reads."""
    monkeypatch.setattr(owner, "run", lambda argv, **kwargs: Result(76, b"", b"3\n"))
    reads = {
        "translation-hooks": scripted.backend.translation_hooks,
        "siblings": scripted.backend.sibling_anchors,
        "sibling": lambda: scripted.backend.sibling(SIBLING),
    }

    with pytest.raises(owner.PFListingNotice) as caught:
        reads[operation]()

    assert (caught.value.operation, caught.value.unexpected_lines) == (operation, 3)


def test_a_refused_read_whose_lines_were_not_counted_hands_back_its_operation_only(
    environment: Any,
) -> None:
    backend = Ordered()
    backend.failing[SIBLING] = owner.PFListingNotice("sibling", None)
    environment = chosen(environment, backend)

    result, _ = observed_pass(environment)

    assert result["listing_notice"] == {"operation": "sibling"}


def entry_point(monkeypatch: pytest.MonkeyPatch, outcome: Any) -> None:
    """Only the output rule of the entry point is under test, as in the first tree's file."""

    def passed(root: Any, observer: Any, backend: Any) -> dict[str, Any]:
        if isinstance(outcome, Exception):
            raise outcome
        return dict(outcome)

    monkeypatch.setattr(owner, "require_mutation_qualified", lambda operation: None)
    monkeypatch.setattr(owner.sys, "platform", "darwin")
    monkeypatch.setattr(owner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(owner, "protected_code", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner, "protected_ancestors", lambda *args, **kwargs: None)
    monkeypatch.setattr(owner, "Store", lambda directory: object())
    monkeypatch.setattr(owner, "reconcile", passed)


def test_the_entry_point_writes_the_refused_listing_of_a_completed_pass_to_standard_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    result = {
        "schema_version": 1,
        "phase": "inhibited",
        "changed": [],
        "pending": [],
        "withheld": {PAIR: REASON},
        "listing_notice": {"operation": "siblings", "unexpected_lines": 2},
    }
    command = ["reconcile", "--root-dir", str(tmp_path)]

    entry_point(monkeypatch, result)
    assert owner.main(command) == 0
    absorbed = capsys.readouterr()
    # The pass completed: its result goes to standard output as before ...
    assert strict_loads(absorbed.out) == result
    # ... and the refused listing to standard error, in closed words and a number.
    assert absorbed.err == NOTICE_LINE

    # The same line as when that refused listing ends a command.
    entry_point(monkeypatch, owner.PFListingNotice("siblings", 2))
    assert owner.main(command) == 65
    ended = capsys.readouterr()
    assert (ended.out, ended.err) == ("", NOTICE_LINE)

    # A pass that absorbed no such read writes nothing there.
    del result["listing_notice"]
    entry_point(monkeypatch, result)
    assert owner.main(command) == 0
    plain = capsys.readouterr()
    assert strict_loads(plain.out) == result and plain.err == ""


# ---- one hosted dry run, and what it printed

# What the parser of the hosted macOS runner image printed for the four hook lines
# N, NS, R, RS in a dry run (`pfctl -n -v -f`, unprivileged), as the hosted test below
# recorded it in CI. A wildcard hook is printed without its parent anchor.
DRY_RUN_PRINT = (
    'nat-anchor "/*" all\n'
    'nat-anchor "com.apple.internet-sharing" all\n'
    'rdr-anchor "/*" all\n'
    'rdr-anchor "com.apple.internet-sharing" all\n'
)


def printed_hooks(printed: str) -> list[tuple[str, str]]:
    """The kind and the quoted anchor of each line of a dry-run print, in order."""
    lines = printed.split("\n")
    if lines[-1] == "":
        lines.pop()
    hooks = []
    for line in lines:
        match = re.fullmatch(r'(nat-anchor|rdr-anchor) "([^"]*)" all', line)
        assert match is not None, line
        hooks.append((match[1], match[2]))
    return hooks


def test_a_dry_run_print_is_not_the_form_of_a_live_listing() -> None:
    """The checker reads the live main ruleset, never a dry run.

    A dry run prints the hooks in the order given, the sharing hooks in full
    and a wildcard hook without its parent anchor. That is a form the checker
    refuses: it shows the hook kinds and their order, not the anchor a live
    listing names. With the parent anchor that a live listing of the main
    ruleset carries (the form the backend script's `hooks` check requires),
    the same lines are accepted.
    """
    assert printed_hooks(DRY_RUN_PRINT) == [
        ("nat-anchor", "/*"),
        ("nat-anchor", "com.apple.internet-sharing"),
        ("rdr-anchor", "/*"),
        ("rdr-anchor", "com.apple.internet-sharing"),
    ]
    assert not owner.translation_hooks_in_order(DRY_RUN_PRINT.strip())
    live = DRY_RUN_PRINT.replace('"/*"', '"com.apple/*"')
    assert live.splitlines() == [f"{line} all" for line in (N, NS, R, RS)]
    assert owner.translation_hooks_in_order(live.strip())


def recorded(capsys: Any, title: str, seen: str) -> None:
    """On the hosted runner, keep what the tool answered as a warning of the job.

    A warning, not a notice: the runner shows at most ten notices of one step,
    and the hosted tests of earlier changes use all ten.
    """
    if os.environ.get("GITHUB_ACTIONS") == "true":
        text = seen.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        # Capture is lifted for one line of its own: the runner reads commands at line starts.
        with capsys.disabled():
            print(f"\n::warning title={title}::{text}")


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
def test_platform_parser_takes_the_four_hook_lines_in_order(tmp_path: Path, capsys: Any) -> None:
    """`pfctl -n -v -f` only parses a file; run unprivileged it can load nothing.

    It shows that this system's grammar takes the four hook lines and prints
    them in the order given, each with ` all` added, and the sharing hooks in
    full. It does not show the form of a live listing: a dry run prints a
    wildcard hook with or without its parent anchor (the hosted image prints it
    without, `DRY_RUN_PRINT`), while the checker compares the live main ruleset
    of `pfctl -s nat`, which needs `/dev/pf` and cannot be read here. Every
    call with `-f` writes a notice to standard error, so only the status and
    standard output are read. Evidence for one hosted runner image.
    """
    rules = tmp_path / "hooks.pf"
    rules.write_text("".join(f"{line}\n" for line in (N, NS, R, RS)))
    result = subprocess.run(
        ["/sbin/pfctl", "-n", "-v", "-f", str(rules)], capture_output=True, timeout=10, check=False
    )
    recorded(
        capsys,
        "pfctl dry run of the four translation hooks",
        f"status {result.returncode}, out {result.stdout[:400]!r}, err {result.stderr[:300]!r}",
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    hooks = printed_hooks(result.stdout.decode("utf-8"))
    assert [kind for kind, _ in hooks] == ["nat-anchor", "nat-anchor", "rdr-anchor", "rdr-anchor"]
    assert [anchor for _, anchor in hooks[1::2]] == ["com.apple.internet-sharing"] * 2
    assert all(anchor in {"/*", "com.apple/*"} for _, anchor in hooks[0::2]), hooks

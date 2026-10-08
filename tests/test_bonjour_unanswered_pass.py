"""A scanner pass in which no listed instance answered counts as a miss, by one rule.

A pass leaves instances of a policy out only beside one that it read, and a scan
fails at its fifth instance left out; either failure carries `incomplete`. Under
`failed_pass: "miss"` a pass counts as a miss where its read did not complete.
A pass of a policy in which the browse listed instances and none of them printed
a reply line to its resolve is such a pass, at either of the two endings and
whatever another scan of it did. An instance that answered with what cannot be
used keeps the pass failing, also beside another scan whose read did not
complete. Without the setting nothing changes. The fake clients, names and
addresses are the synthetic ones of the test files these build on.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.model import Config
from tests.test_bonjour_failed_pass_as_miss import Link, counting, shown, stopped
from tests.test_bonjour_miss_tolerance import IMPORT, leased
from tests.test_bonjour_owner import config, settings
from tests.test_bonjour_record_isolation import (
    KITCHEN,
    RAOP,
    STUDY,
    UNUSABLE,
    Client,
    Device,
    names,
    scanned,
)

__all__ = ["config", "settings"]


def silent(device: Device) -> Device:
    """The same instance, listed by the browse, whose resolve prints no reply line."""
    return replace(device, replies=0)


SILENT = (silent(KITCHEN), silent(STUDY))
FIVE = tuple(
    silent(replace(KITCHEN, name=f"Quiet speaker {number}", host=f"quiet-{number}.local."))
    for number in range(5)
)
# Instances that answered their resolve, with what cannot be used. The stale
# browse entry is the one that did not answer at all.
ANSWERED = {key: value for key, value in UNUSABLE.items() if key != "stale-browse-entry"}
ODD = ANSWERED["replies-that-differ"]


def plain(settings: owner.BonjourSettings) -> owner.BonjourSettings:
    """The same tolerance, without the setting."""
    return replace(settings, miss_tolerance=3)


# The reader


def test_reader_names_the_instances_left_out_without_any_reply_line() -> None:
    skipped: list[str] = []
    unanswered: list[str] = []
    client = Client(silent(KITCHEN), ODD, STUDY)
    records = scanned(client, skipped=skipped, unanswered=unanswered)
    assert names(records) == [STUDY.name]
    assert skipped == [KITCHEN.name, ODD.name] and unanswered == [KITCHEN.name]


@pytest.mark.parametrize(
    ("devices", "marked"),
    [
        (FIVE, True),
        # The fifth instance left out answered with what cannot be used.
        ((*FIVE[:4], ODD), False),
        # An instance was read before the fifth one was left out.
        ((KITCHEN, *FIVE), False),
    ],
    ids=["none-answered", "one-answered", "one-read-before"],
)
def test_fifth_instance_left_out_is_marked_only_where_none_answered_and_none_was_read(
    devices: tuple[Device, ...], marked: bool
) -> None:
    with pytest.raises(native.DiscoveryFailure) as caught:
        scanned(Client(*devices))
    failure = caught.value
    assert (failure.reason, failure.unanswered, failure.unfinished) == ("incomplete", marked, False)


@pytest.mark.parametrize(
    ("reason", "unfinished", "unanswered", "counts"),
    [
        ("incomplete", True, True, True),
        ("incomplete", False, True, False),
        ("incomplete", True, False, False),
        ("timed-out", True, True, False),
        ("local-network-denied", True, True, False),
        ("malformed", True, False, True),
    ],
)
def test_a_pass_marked_unanswered_counts_only_with_its_own_reason(
    reason: str, unfinished: bool, unanswered: bool, counts: bool
) -> None:
    failure = native.DiscoveryFailure(reason, unfinished=unfinished, unanswered=unanswered)
    assert owner.counts_as_miss(failure) is counts


# The pass


@pytest.mark.parametrize("left", [SILENT, FIVE], ids=["none-read", "fifth-left-out"])
@pytest.mark.parametrize("setting", [True, False], ids=["with-the-setting", "without-it"])
def test_pass_in_which_no_listed_instance_answered_counts_as_a_miss(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    left: tuple[Device, ...],
    setting: bool,
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings) if setting else plain(settings))
    link.lan.devices = (KITCHEN, STUDY)
    link.requested()
    seen = link.run()[IMPORT]
    assert len(seen["records"]) == 2
    link.lan.devices = left
    failed = link.run()[IMPORT]
    if setting:
        assert failed["records"] == seen["records"] and "reason" not in failed
        # Named as the candidate reader names every read that did not complete.
        assert failed["tolerated_failure"] == "malformed"
        assert set((link.counts() or {}).values()) == {1}
        assert shown(link.tick()[IMPORT]) == ("present", "verified", 2, "malformed")
    else:
        assert (failed["records"], failed["reason"]) == ([], "incomplete")
        assert "tolerated_failure" not in failed and link.counts() is None


@pytest.mark.parametrize("odd", ANSWERED.values(), ids=ANSWERED)
@pytest.mark.parametrize("ending", ["none-read", "fifth-left-out"])
def test_pass_with_an_instance_that_answered_with_what_cannot_be_used_keeps_failing(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    odd: Device,
    ending: str,
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN, STUDY)
    link.run()
    link.lan.devices = (silent(KITCHEN), odd) if ending == "none-read" else (*FIVE[:4], odd)
    failed = link.run()[IMPORT]
    assert (failed["records"], failed["reason"]) == ([], "incomplete")
    assert "tolerated_failure" not in failed and link.counts() is None


@pytest.mark.parametrize("beside", [False, True], ids=["alone", "beside-an-unfinished-browse"])
@pytest.mark.parametrize(
    ("left", "carried"),
    [(SILENT, True), ((silent(KITCHEN), ODD), False)],
    ids=["none-answered", "one-answered"],
)
def test_one_rule_whatever_another_scan_of_the_pass_did(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    beside: bool,
    left: tuple[Device, ...],
    carried: bool,
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN, STUDY)
    seen = link.run()[IMPORT]
    link.lan.devices = left
    if beside:
        # Another type's browse is stopped at its own limit before it showed anything.
        link.lan.fail("-B", RAOP, stopped)
    failed = link.run()[IMPORT]
    if carried:
        assert failed["records"] == seen["records"] and "reason" not in failed
        assert failed["tolerated_failure"] == "malformed"
    else:
        # The reason is that of the first scan that failed, as before.
        expected = "malformed" if beside else "incomplete"
        assert (failed["records"], failed["reason"]) == ([], expected)
        assert "tolerated_failure" not in failed and link.counts() is None


def test_scan_at_its_fifth_unanswered_instance_beside_one_that_read_keeps_failing(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, leased(config), counting(settings))
    link.lan.devices = (KITCHEN, STUDY)
    link.run()
    # Another type's scan reads an instance: the pass is not one in which none answered.
    link.lan.devices = (*FIVE, replace(STUDY, kind=RAOP))
    failed = link.run()[IMPORT]
    assert (failed["records"], failed["reason"]) == ([], "incomplete")
    assert "tolerated_failure" not in failed and link.counts() is None

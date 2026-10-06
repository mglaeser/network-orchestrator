"""A record that completed passes miss can be kept for a set number of them.

The owner setting `miss_tolerance` is 1 unless given, which withdraws on the
first miss as before. Addresses are RFC 5737, names are invented, the clock and
every native read are fakes.
"""

from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch import owners
from netorch.config import config_digest, to_dict
from netorch.discovery import Record
from netorch.discovery_plan import discovery_digest
from netorch.model import Config
from netorch.process import Result
from netorch.state import Intent, Snapshot
from netorch.storage import Store
from tests.test_bonjour_owner import (
    FakeRegistration,
    config,
    expected_settings,
    media_record,
    policy,
    publisher,
    settings,
    snapshot,
    write_private,
)

__all__ = ["config", "settings"]

LEASE = 600
START = 1000.0
STEP = 10.0
MONOTONIC = 50.0
READY = frozenset({"media-udp", "camera-web"})
IMPORT, EXPORT = "media-import", "camera-export"


def leased(config: Config, seconds: int = LEASE, only: str | None = None) -> Config:
    """The example policy with discovery leases long enough to carry a record."""
    return replace(
        config,
        discovery=tuple(
            replace(item, max_age_seconds=seconds) if only in (None, item.id) else item
            for item in config.discovery
        ),
    )


def observed(config: Config, now: float) -> Snapshot:
    """What the other owners report, read at the time of the pass."""
    base = snapshot(config)
    return replace(
        base,
        observed_at=now,
        services={key: replace(item, observed_at=now) for key, item in base.services.items()},
        profiles={key: replace(item, observed_at=now) for key, item in base.profiles.items()},
    )


def regenerated(current: Snapshot, config: Config, service: str, generation: str) -> Snapshot:
    """The same report after the guest of one service was replaced."""
    return replace(
        current,
        services={
            **current.services,
            service: replace(current.services[service], generation=generation),
        },
        profiles={
            key: replace(
                item, generation=generation, data={**item.data, "target_generation": generation}
            )
            if config.profile(key).service == service
            else item
            for key, item in current.profiles.items()
        },
    )


def renumbered(current: Snapshot, generation: str) -> Snapshot:
    """The same report after the guest network was replaced."""
    return replace(
        current,
        network_generation=generation,
        profiles={
            key: replace(item, data={**item.data, "network_generation": generation})
            for key, item in current.profiles.items()
        },
    )


def speaker(**changes: Any) -> Record:
    record: Record = media_record(**changes)
    return record


def camera(**changes: Any) -> Record:
    record: Record = media_record(
        name="Camera",
        service_type="_hap._tcp",
        hostname="camera.local.",
        ipv4="198.51.100.13",
        port=9443,
    )
    return replace(record, **changes)


class Passes:
    """Scanner passes with a clock, reports and scan results that the test sets."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, config: Config, settings: owner.BonjourSettings
    ) -> None:
        self.config = config
        self.settings = settings
        self.now = START - STEP
        self.report: Snapshot | None = None
        self.ready = READY
        self.read: dict[str, Any] = {}
        self.store = Store(settings.state_dir)
        # As serve builds it: only a tolerance above one remembers anything. Read with a
        # default, so that the unchanged default is also tested on a tree without the setting.
        tolerance = getattr(settings, "miss_tolerance", 1)
        self.memory = owner.MissMemory(tolerance) if tolerance > 1 else None
        clock = type(
            "Clock",
            (),
            {
                "time": staticmethod(lambda: self.now),
                "monotonic": staticmethod(lambda: MONOTONIC + self.now - START),
            },
        )()
        monkeypatch.setattr(owner, "time", clock)
        monkeypatch.setattr(
            owner, "independent_snapshot", lambda *_args: (self.current(), Intent(), self.ready)
        )
        monkeypatch.setattr(owner, "_interfaces", lambda *_args: {"wired-lan": (7, 9)})
        monkeypatch.setattr(owner, "scan", self.scan)

    def current(self) -> Snapshot:
        return self.report or observed(self.config, self.now)

    def scan(
        self,
        interface: str,
        _index: int,
        kind: str,
        _limit: int,
        _seconds: int,
        now: float,
        **_keywords: Any,
    ) -> tuple[Record, ...]:
        result = self.read.get(kind, ())
        if isinstance(result, Exception):
            raise result
        return tuple(replace(record, interface=interface, seen_at=now) for record in result)

    def run(self, *records: Record, at: float | None = None) -> dict[str, Any]:
        """One pass, STEP seconds after the last unless told when; returns its candidates."""
        self.now = self.now + STEP if at is None else at
        if records:
            self.read = {}
            for record in records:
                self.read[record.service_type] = (*self.read.get(record.service_type, ()), record)
        if self.memory is None:
            owner.scan_pass(self.config, self.settings, self.store)
        else:
            owner.scan_pass(self.config, self.settings, self.store, self.memory)
        policies: dict[str, Any] = self.store.read("candidates.json")["policies"]
        return policies

    def miss(self, at: float | None = None) -> dict[str, Any]:
        """One pass whose browse answers nothing."""
        self.read = {}
        return self.run(at=at)


def names(candidate: dict[str, Any]) -> list[str]:
    return sorted(item["name"] for item in candidate["records"])


def tolerant(settings: owner.BonjourSettings, tolerance: int) -> owner.BonjourSettings:
    return replace(settings, miss_tolerance=tolerance)


def settings_file(
    tmp_path: Path, config: Config, settings: owner.BonjourSettings, **keys: Any
) -> Path:
    write_private(settings.config, to_dict(config))
    return write_private(tmp_path / "bonjour.json", {**expected_settings(settings), **keys})


# The setting


def test_settings_without_the_key_tolerate_no_miss(
    settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    loaded = owner.load_settings(
        write_private(tmp_path / "bonjour.json", expected_settings(settings))
    )
    assert loaded == settings
    assert loaded.miss_tolerance == 1
    assert loaded.pass_interval == loaded.poll_seconds == 5


@pytest.mark.parametrize("value", [1, 2, 3, 8])
def test_tolerance_from_one_to_eight_is_accepted(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path, value: int
) -> None:
    path = settings_file(tmp_path, leased(config), settings, miss_tolerance=value)
    assert owner.load_settings(path) == tolerant(settings, value)


@pytest.mark.parametrize("value", [0, 9, -1, True, 2.0, "3", None, [3]])
def test_tolerance_outside_its_range_or_type_is_refused(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path, value: Any
) -> None:
    assert owner.load_settings(settings_file(tmp_path, leased(config), settings, miss_tolerance=2))
    with pytest.raises(ValueError):
        owner.load_settings(settings_file(tmp_path, leased(config), settings, miss_tolerance=value))


def test_tolerance_is_refused_where_no_owned_lease_could_ever_carry(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    # A missed record is at least one rest old and must outlast a rest and two passes.
    least = settings.pass_interval + owner.carry_horizon(config, settings)
    assert all(item.max_age_seconds <= least for item in config.discovery)
    assert owner.load_settings(settings_file(tmp_path, config, settings, miss_tolerance=1))
    with pytest.raises(ValueError, match="outlasts two passes"):
        owner.load_settings(settings_file(tmp_path, config, settings, miss_tolerance=2))
    with pytest.raises(ValueError, match="outlasts two passes"):
        owner.load_settings(
            settings_file(tmp_path, leased(config, least), settings, miss_tolerance=2)
        )
    # One owned lease with room is enough; the others then withdraw on the first miss.
    one = leased(config, least + 1, only=EXPORT)
    assert owner.load_settings(settings_file(tmp_path, one, settings, miss_tolerance=2))


def test_horizon_is_a_rest_and_two_pass_budgets(
    config: Config, settings: owner.BonjourSettings
) -> None:
    # The numbers the owner guide gives for the example policy and default settings.
    assert owner.pass_budget(config, settings) == 119
    assert owner.carry_horizon(config, settings) == 5 + 2 * 119 == 243
    slower = replace(settings, poll_seconds=10)
    assert slower.pass_interval == 10
    assert owner.carry_horizon(config, slower) == 10 + 2 * 119


def test_budget_counts_the_limit_of_one_report_for_each_other_owner(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    limits: list[float] = []

    def report(_argv: list[str], *, timeout: float, **_rest: Any) -> Result:
        limits.append(timeout)
        return Result(1, b"", b"")

    monkeypatch.setattr(owners.os, "geteuid", lambda: 501)
    monkeypatch.setattr(owners, "run", report)
    owners.ProcessOwner(config, "camera-manager", ["/example/owner"]).observe()
    assert limits == [owner._OWNER_READ_LIMIT]
    fewer = replace(config, owners=config.owners[:-1])
    assert owner.pass_budget(config, settings) - owner.pass_budget(fewer, settings) == limits[0]


def test_budget_counts_two_interface_checks_for_each_scope(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    limits: list[float] = []

    def ifconfig(argv: list[str], timeout: float) -> Result:
        limits.append(timeout)
        return Result(0, argv[1].encode() + b": flags=0\n\tinet 192.0.2.10 netmask 0\n", b"")

    monkeypatch.setattr(native.socket, "if_nametoindex", lambda _name: 7)
    assert native.interface_index("example0", "192.0.2.10", ifconfig) == 7
    assert limits == [owner._INTERFACE_CHECK_LIMIT]
    checked: list[str] = []
    monkeypatch.setattr(owner, "interface_index", lambda name, _address: checked.append(name) or 7)
    owner._interfaces(config, settings)
    assert len(checked) == 2 * len(settings.scopes)
    doubled = replace(settings, scopes=settings.scopes * 2)
    assert (
        owner.pass_budget(config, doubled) - owner.pass_budget(config, settings)
        == len(checked) * limits[0]
    )


def test_budget_counts_one_scan_limit_for_each_batch_of_service_types(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert inspect.signature(native.scan).parameters["max_seconds"].default == owner._SCAN_LIMIT
    pools: list[int] = []

    class Pool:
        def __init__(self, max_workers: int) -> None:
            pools.append(max_workers)

        def __enter__(self) -> Pool:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def submit(self, *_args: Any, **_keywords: Any) -> Any:
            return type("Done", (), {"result": lambda self, timeout: ()})()

    monkeypatch.setattr(owner, "ThreadPoolExecutor", Pool)
    many = tuple(f"_example{index}._tcp" for index in range(owner._SCAN_BATCH + 1))
    wide = replace(policy(config, EXPORT), types=many)
    owner.scan_policy(
        config, settings, wide, snapshot(config), frozenset(), {"wired-lan": (7, 9)}, START
    )
    # One type more than a batch is read in a second round.
    assert pools == [owner._SCAN_BATCH]
    wider = replace(
        config,
        discovery=tuple(wide if item.id == EXPORT else item for item in config.discovery),
    )
    assert (
        owner.pass_budget(wider, settings) - owner.pass_budget(config, settings)
        == owner._SCAN_LIMIT
    )


# What a pass lists


def test_without_tolerance_a_missed_record_is_withdrawn_in_that_pass(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = Passes(monkeypatch, leased(config), settings)
    seen = passes.run(speaker(), camera())
    assert names(seen[IMPORT]) == ["Example speaker"] and names(seen[EXPORT]) == ["Camera"]
    missed = passes.miss()
    assert missed[IMPORT]["records"] == [] and missed[EXPORT]["records"] == []
    assert "reason" not in missed[IMPORT] and "reason" not in missed[EXPORT]


@pytest.mark.parametrize("identifier", [IMPORT, EXPORT])
def test_tolerance_three_keeps_a_record_for_two_missing_passes(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    identifier: str,
) -> None:
    passes = Passes(monkeypatch, leased(config), tolerant(settings, 3))
    first = passes.run(speaker(), camera())[identifier]
    assert len(first["records"]) == 1
    for _ in range(2):
        carried = passes.miss()[identifier]
        # The same record, with the time it was seen: nothing is refreshed.
        assert carried["records"] == first["records"]
        assert carried["records"][0]["seen_at"] == START
        assert carried["observed_at"] == passes.now and "reason" not in carried
    assert passes.miss()[identifier]["records"] == []
    assert passes.miss()[identifier]["records"] == []


def test_tolerance_two_keeps_a_record_for_one_missing_pass(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = Passes(monkeypatch, leased(config), tolerant(settings, 2))
    passes.run(speaker())
    assert names(passes.miss()[IMPORT]) == ["Example speaker"]
    assert passes.miss()[IMPORT]["records"] == []


def test_record_seen_again_starts_a_new_count(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = Passes(monkeypatch, leased(config), tolerant(settings, 3))
    passes.run(speaker())
    assert names(passes.miss()[IMPORT]) == ["Example speaker"]
    assert names(passes.miss()[IMPORT]) == ["Example speaker"]
    again = passes.run(speaker())[IMPORT]
    assert again["records"][0]["seen_at"] == passes.now == START + 3 * STEP
    assert names(passes.miss()[IMPORT]) == ["Example speaker"]
    assert names(passes.miss()[IMPORT]) == ["Example speaker"]
    assert passes.miss()[IMPORT]["records"] == []


def test_failed_pass_carries_nothing_over(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = Passes(monkeypatch, leased(config), tolerant(settings, 3))
    passes.run(speaker(), camera())
    passes.read = {"_airplay._tcp": native.DiscoveryFailure("timed-out")}
    failed = passes.run()
    assert failed[IMPORT]["records"] == [] and failed[IMPORT]["reason"] == "timed-out"
    # The sibling policy completed its pass and keeps its own memory.
    assert names(failed[EXPORT]) == ["Camera"]
    after = passes.miss()
    assert after[IMPORT]["records"] == [] and "reason" not in after[IMPORT]
    assert names(after[EXPORT]) == ["Camera"]


def test_pass_that_fails_after_reading_carries_nothing_over(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = Passes(monkeypatch, leased(config), tolerant(settings, 3))
    passes.run(speaker())
    # Two instances of one name and type are refused by the projection, after the read.
    failed = passes.run(speaker(name="Other"), speaker(name="Other"))
    assert failed[IMPORT]["records"] == [] and failed[IMPORT]["reason"] == "incomplete"
    assert passes.miss()[IMPORT]["records"] == []


def test_skipped_pass_carries_nothing_over(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = Passes(monkeypatch, leased(config), tolerant(settings, 3))
    passes.run(speaker(), camera())
    passes.ready = frozenset({"camera-web"})
    skipped = passes.miss()
    assert skipped[IMPORT]["records"] == [] and "reason" not in skipped[IMPORT]
    assert names(skipped[EXPORT]) == ["Camera"]
    passes.ready = READY
    assert passes.miss()[IMPORT]["records"] == []


@pytest.mark.parametrize("change", ["guest", "network", "policy"])
def test_changed_generation_or_policy_drops_the_memory(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    passes = Passes(monkeypatch, leased(config), tolerant(settings, 3))
    passes.run(camera())
    assert names(passes.miss()[EXPORT]) == ["Camera"]
    passes.now += STEP
    report = observed(passes.config, passes.now)
    if change == "guest":
        passes.report = regenerated(report, passes.config, "camera", "mock-camera-2")
    elif change == "network":
        passes.report = renumbered(report, "mock-network-2")
    else:
        passes.config = replace(
            passes.config,
            discovery=tuple(
                replace(item, max_records=item.max_records - 1) for item in passes.config.discovery
            ),
        )
    after = passes.miss(at=passes.now)[EXPORT]
    assert after["records"] == [] and "reason" not in after
    assert after["policy_digest"] == discovery_digest(passes.config, policy(passes.config, EXPORT))


def test_record_seen_now_takes_the_place_of_the_carried_one_of_its_name_and_type(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = Passes(monkeypatch, leased(config), tolerant(settings, 3))
    passes.run(
        speaker(), speaker(name="Second speaker", hostname="second.local.", ipv4="192.0.2.83")
    )
    moved = passes.run(speaker(ipv4="192.0.2.84"))[IMPORT]
    assert names(moved) == ["Example speaker", "Second speaker"]
    by_name = {item["name"]: item for item in moved["records"]}
    assert by_name["Example speaker"]["ipv4"] == "192.0.2.84"
    assert by_name["Example speaker"]["seen_at"] == passes.now
    assert by_name["Second speaker"]["seen_at"] == START


def test_carried_records_never_push_a_pass_over_its_record_bound(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    bounded = replace(
        leased(config),
        discovery=tuple(replace(item, max_records=2) for item in leased(config).discovery),
    )
    passes = Passes(monkeypatch, bounded, tolerant(settings, 3))
    first = speaker(name="First", hostname="first.local.", ipv4="192.0.2.81")
    second = speaker(name="Second", hostname="second.local.", ipv4="192.0.2.82")
    third = speaker(name="Third", hostname="third.local.", ipv4="192.0.2.83")
    fourth = speaker(name="Fourth", hostname="fourth.local.", ipv4="192.0.2.84")
    assert names(passes.run(first, second)[IMPORT]) == ["First", "Second"]
    one_free = passes.run(third)[IMPORT]
    assert "reason" not in one_free and len(one_free["records"]) == 2
    assert "Third" in names(one_free)
    full = passes.run(third, fourth)[IMPORT]
    assert names(full) == ["Fourth", "Third"] and "reason" not in full
    # What had to give way is forgotten; it does not come back when there is room again.
    assert names(passes.run(third)[IMPORT]) == ["Fourth", "Third"]


# The lease


def test_record_is_carried_only_while_its_lease_outlasts_the_next_candidate(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_config = leased(config)
    own = tolerant(settings, 8)
    horizon = owner.carry_horizon(policy_config, own)
    last = START + LEASE - horizon
    passes = Passes(monkeypatch, policy_config, own)
    passes.run(speaker(), at=START)
    assert names(passes.miss(at=last - 1)[IMPORT]) == ["Example speaker"]
    # Seen once and missed twice of eight: the lease decides, not the tolerance.
    assert passes.miss(at=last)[IMPORT]["records"] == []
    assert passes.miss(at=last + 1)[IMPORT]["records"] == []


def test_lease_ends_a_carried_record_whatever_the_tolerance(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A record that is never seen again, the largest tolerance, the slowest passes.

    Every pass takes its whole time budget. The publisher may read a candidate
    at any time until the next one is written: none is refused in that time,
    the record leaves the candidates before its lease ends, and nothing
    refreshes the time it was seen.
    """
    policy_config = leased(config)
    own = tolerant(settings, 8)
    item = policy(policy_config)
    budget = owner.pass_budget(policy_config, own)
    passes = Passes(monkeypatch, policy_config, own)
    in_force = passes.run(speaker(), at=START)[IMPORT]
    written = START + budget
    request = {
        "active": True,
        "policy_digest": discovery_digest(policy_config, item),
        "service_generation": passes.current().services[item.service].generation,
        "network_generation": passes.current().network_generation,
        "requested_at": START,
    }

    def leased_at(candidate: dict[str, Any], when: float) -> tuple[Record, ...] | None:
        return owner.lease_records(
            policy_config,
            item,
            request,
            candidate,
            observed(policy_config, when),
            Intent(),
            READY,
            when,
        )

    carrying = []
    while in_force["records"]:
        assert [record["seen_at"] for record in in_force["records"]] == [START]
        begun = written + own.pass_interval
        following = passes.miss(at=begun)[IMPORT]
        for when in (written, begun, begun + budget):
            assert leased_at(in_force, when) is not None
        if following["records"]:
            carrying.append(following)
        in_force, written = following, begun + budget
    # Carried, but for fewer passes than the tolerance alone would allow.
    assert 1 <= len(carrying) < own.miss_tolerance - 1
    assert written <= START + LEASE
    # The fence itself is unchanged: one expired record refuses its whole candidate.
    assert leased_at(carrying[0], START + LEASE) is not None
    assert leased_at(carrying[0], START + LEASE + 1) is None


def test_publisher_deadline_and_client_lifetime_of_a_carried_record_are_its_first_lease(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_config = leased(config)
    item = policy(policy_config)
    passes = Passes(monkeypatch, policy_config, tolerant(settings, 3))
    seen = owner.record_from_dict(passes.run(speaker())[IMPORT]["records"][0])
    carried = owner.record_from_dict(passes.miss()[IMPORT]["records"][0])
    assert carried == seen and passes.now == START + STEP
    manager = publisher()
    passes.now = START
    manager.reconcile(item, (seen,), 9, passes.now)
    deadline = dict(manager.deadlines)
    assert list(deadline.values()) == [MONOTONIC + LEASE]
    passes.now = START + STEP
    manager.reconcile(item, (carried,), 9, passes.now)
    # One client, not a second one, and its deadline did not move.
    assert len(FakeRegistration.made) == 1 and manager.deadlines == deadline
    manager.expire(MONOTONIC + LEASE - 1)
    assert not FakeRegistration.made[0].closed
    manager.expire(MONOTONIC + LEASE)
    assert FakeRegistration.made[0].closed and not manager.children
    # A client started for a carried record lives for the lease that is left.
    late = publisher()
    late.reconcile(item, (carried,), 9, START + LEASE - 30)
    assert FakeRegistration.made[0].lifetime_seconds == 30


def test_publisher_keeps_one_client_through_tolerated_misses(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_config = leased(config)
    own = tolerant(settings, 3)
    item = policy(policy_config)
    passes = Passes(monkeypatch, policy_config, own)
    passes.store.write(
        "requests.json",
        {
            "schema_version": 1,
            "policies": {
                item.id: {
                    "active": True,
                    "policy_digest": discovery_digest(policy_config, item),
                    "service_generation": snapshot(policy_config).services[item.service].generation,
                    "network_generation": snapshot(policy_config).network_generation,
                    "requested_at": START,
                }
            },
        },
    )
    manager = publisher()

    def tick() -> tuple[str, int]:
        proof = (observed(policy_config, passes.now), Intent(), READY, {"wired-lan": (7, 9)})
        result = owner.publisher_tick(
            policy_config, own, passes.store, manager, proof, 0, passes.now
        ).profiles[item.id]
        return result.state, result.data["record_count"]

    passes.run(speaker())
    assert tick() == ("present", 1)
    client = FakeRegistration.made[0]
    for _ in range(2):
        passes.miss()
        assert tick() == ("present", 1)
        assert FakeRegistration.made == [client] and not client.closed
    passes.miss()
    assert tick() == ("present", 0)
    assert client.closed and not manager.children


# The pass judges a carried source as it judges one it read


def test_missed_anchor_keeps_the_records_related_to_it(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = Passes(monkeypatch, leased(config), tolerant(settings, 3))
    related = speaker(name="Example@Speaker", service_type="_raop._tcp", port=5000)
    assert names(passes.run(speaker(), related)[IMPORT]) == ["Example speaker", "Example@Speaker"]
    # The browse for the type that decides eligibility answers nothing this time.
    partly = passes.run(related)[IMPORT]
    by_name = {item["name"]: item["seen_at"] for item in partly["records"]}
    assert by_name == {"Example speaker": START, "Example@Speaker": passes.now}


def test_record_read_again_but_no_longer_eligible_is_not_carried(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = Passes(monkeypatch, leased(config), tolerant(settings, 3))
    passes.run(speaker())
    changed = passes.run(speaker(txt=(b"model=Unrelated",)))[IMPORT]
    assert changed["records"] == [] and "reason" not in changed
    # It was read, so it was not missed, and what it was before is not remembered.
    assert passes.miss()[IMPORT]["records"] == []


def test_carried_source_is_judged_by_the_report_of_the_current_pass(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_config = leased(config)
    passes = Passes(monkeypatch, policy_config, tolerant(settings, 3))
    passes.run(camera())
    # The guest now has another address under the same generation: the record
    # that was read at the old address is no record of this guest any more.
    passes.now += STEP
    report = observed(policy_config, passes.now)
    guest = report.services["camera"]
    passes.report = replace(
        report,
        services={
            **report.services,
            "camera": replace(guest, data={**guest.data, "ipv4": "198.51.100.99"}),
        },
        profiles={
            key: replace(item, data={**item.data, "target_ipv4": "198.51.100.99"})
            if key == "camera-web"
            else item
            for key, item in report.profiles.items()
        },
    )
    moved = passes.miss(at=passes.now)[EXPORT]
    assert moved["records"] == [] and "reason" not in moved
    # Not listed by a completed pass, so not remembered when the old address returns.
    passes.report = None
    assert passes.miss()[EXPORT]["records"] == []


# The scanner process


class Child:
    """A publisher child that lets the scanner make a set number of passes."""

    def __init__(self, passes: int) -> None:
        self.left = passes

    def poll(self) -> int | None:
        self.left -= 1
        return None if self.left >= 0 else 0

    def terminate(self) -> None:
        return None

    def wait(self, timeout: float) -> int:
        return 0


def serve(
    monkeypatch: pytest.MonkeyPatch,
    config: Config,
    settings: owner.BonjourSettings,
    scan_pass: Any,
    passes: int,
) -> list[float]:
    rests: list[float] = []
    monkeypatch.setattr(owner.subprocess, "Popen", lambda *_args, **_kwargs: Child(passes))
    monkeypatch.setattr(owner, "_signal_stop", lambda _function: None)
    monkeypatch.setattr(owner.time, "sleep", rests.append)
    monkeypatch.setattr(owner, "scan_pass", scan_pass)
    owner.serve(config, settings, settings.config)
    return rests


def test_scanner_keeps_the_memory_in_its_own_process_only(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    given: list[Any] = []

    def scan_pass(*arguments: Any) -> None:
        given.append(arguments[3])

    rests = serve(monkeypatch, leased(config), tolerant(settings, 3), scan_pass, 2)
    assert rests == [settings.pass_interval] * 2
    first = given[0]
    assert isinstance(first, owner.MissMemory) and first.tolerance == 3
    assert given[1] is first
    # A restarted scanner starts with nothing remembered.
    serve(monkeypatch, leased(config), tolerant(settings, 3), scan_pass, 1)
    assert given[2] is not first and given[2].listed == {}
    # Without a tolerance nothing is remembered at all.
    serve(monkeypatch, leased(config), settings, scan_pass, 1)
    assert given[3] is None
    assert sorted(path.name for path in settings.state_dir.iterdir() if path.is_file()) == [
        "scanner-heartbeat.json"
    ]


def test_pass_that_fails_as_a_whole_clears_the_memory(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_config = leased(config)
    own = tolerant(settings, 3)
    held: list[owner.MissMemory] = []

    def scan_pass(_config: Config, _settings: Any, _store: Store, memory: owner.MissMemory) -> None:
        held.append(memory)
        if len(held) == 1:
            memory.listed[IMPORT] = (("digest", "guest", "network"), {})
            return
        assert memory.listed
        raise OSError("bindings unreadable")

    serve(monkeypatch, policy_config, own, scan_pass, 2)
    assert held[0] is held[1] and held[0].listed == {}
    written = Store(own.state_dir).read("candidates.json")
    assert written["policies"] == {} and written["config_digest"] == config_digest(policy_config)

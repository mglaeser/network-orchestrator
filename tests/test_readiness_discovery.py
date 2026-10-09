"""Readiness flags of the discovery owner, as strict expected failures.

Each test states the behaviour that the readiness record
`docs/reviews/2026-10-09-readiness-discovery.md` proposes for one finding, and
fails on the code it was written against with an AssertionError whose message
shows what the owner does now. The mark `xfail(strict=True,
raises=AssertionError)` keeps the suite passing while that behaviour is
unchanged and fails it once the proposal is implemented, so that the record is
followed up. `pytest tests/test_readiness_discovery.py --runxfail` shows each
failure. What a test sets up is checked with `pytest.fail`, never with an
assertion: a set-up that no longer holds fails the suite instead of passing as
the expected failure.

The fake clients, clocks and registrations are those of the Bonjour test files
these build on: formats derived from the vendor client's source, invented names
and RFC 5737 addresses, nothing captured from a host. No test changes the code.
"""

from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch import owners
from netorch.config import config_digest, to_dict
from netorch.discovery_plan import DiscoveryAction, plan_discovery
from netorch.executor import execute
from netorch.mock import mock_admissions
from netorch.model import Config
from netorch.owners import OwnerFailure
from netorch.planner import Action, plan
from netorch.process import Result
from netorch.state import (
    Intent,
    Observation,
    Snapshot,
    intent_from_dict,
    intent_to_dict,
    observation_from_dict,
    snapshot_from_dict,
)
from netorch.storage import Store
from tests.test_bonjour_failed_pass_as_miss import CAMERA, Link, counting
from tests.test_bonjour_miss_tolerance import (
    EXPORT,
    IMPORT,
    STEP,
    leased,
    names,
    observed,
    regenerated,
)
from tests.test_bonjour_miss_tolerance import serve as serving
from tests.test_bonjour_owner import FakeRegistration, config, settings, write_private
from tests.test_bonjour_record_expiry import Child
from tests.test_bonjour_record_expiry import publisher as expiring_publisher
from tests.test_bonjour_record_isolation import (
    GUEST,
    GUEST_INDEX,
    HAP,
    INTERFACE,
    KITCHEN,
    LAN_INDEX,
    STUDY,
    Client,
    Device,
    rdata,
    tick,
)
from tests.test_bonjour_record_isolation import scan_pass as scanner_pass

__all__ = ["config", "settings"]

# The owner's own functions, before a test replaces them.
SCAN_PASS = owner.scan_pass
INTERFACES = owner._interfaces


def require(condition: bool, what: str) -> None:
    """A set-up check: it fails the test outright, never as its expected failure."""
    if not condition:
        pytest.fail(f"set-up no longer holds: {what}")


# R-D3: instances that never answer, beside a usable instance of the same import.

COMPANION = "_companion-link._tcp"


def quiet(count: int) -> tuple[Device, ...]:
    """Instances of another type of the import that the browse lists and that print no reply."""
    return tuple(
        Device(
            f"Quiet device {number}",
            f"quiet-{number}.local.",
            (f"192.0.2.{120 + number}",),
            kind=COMPANION,
            replies=0,
        )
        for number in range(count)
    )


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="readiness R-D3: instances that never answered have a bound of their own; "
    "the import keeps its usable records",
)
@pytest.mark.parametrize("silent", [5, 6])
def test_r_d3_instances_that_never_answer_leave_the_import_of_another_type(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    silent: int,
) -> None:
    # Only a bound of their own may let them pass: five instances whose answers cannot be
    # used (a reply with a port that cannot be published) still fail the scan of their type.
    answering = Client(*(replace(device, replies=1, port=0) for device in quiet(5)))
    try:
        native.scan(INTERFACE, LAN_INDEX, COMPANION, 8, 2, 1000.0, answering)
    except native.DiscoveryFailure as failure:
        bounded = failure.reason == "incomplete"
    else:
        bounded = False
    require(bounded, "five instances whose answers cannot be used still fail their scan")
    lan = Client(KITCHEN, *quiet(silent))
    candidate = scanner_pass(config, settings, monkeypatch, lan, Client(index=GUEST_INDEX))[IMPORT]
    resolved = [subject for operation, subject in lan.asked if operation == "-L"]
    require(KITCHEN.name in resolved, "the eligible AirPlay instance was resolved in the pass")
    require(
        sum(name.startswith("Quiet device") for name in resolved) >= 5,
        "the scan of the other type asked about the instances that print no reply",
    )
    imported = tick(config, settings)[IMPORT]
    written = [item["name"] for item in candidate["records"]]
    assert (
        candidate.get("reason"),
        written,
        candidate.get("skipped"),
        imported.state,
        imported.data["skipped_count"],
    ) == (None, [KITCHEN.name], silent, "present", silent), (
        f"the pass writes the reason {candidate.get('reason')!r}, the records {written} and "
        f"the count {candidate.get('skipped')!r}; the publisher reads "
        f"{imported.state} / {imported.reason}"
    )


# R-D8: an endpoint URL that names another address of the guest network.

HOME = "_home-assistant._tcp"
# An address of the guest network that is not the guest's current one (GUEST):
# an earlier address of the same guest, say, or another guest's.
ELSEWHERE = "198.51.100.20"


def exporting_urls(config: Config) -> Config:
    """The example export with the one type whose endpoint URLs the owner projects."""
    return replace(
        config,
        discovery=tuple(
            replace(item, types=(HAP, HOME)) if item.id == EXPORT else item
            for item in config.discovery
        ),
    )


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="readiness R-D8: a URL that names another guest-network address is not "
    "published as it is",
)
@pytest.mark.parametrize(
    "entry",
    [f"internal_url=http://{ELSEWHERE}:9443", f"base_url=https://{ELSEWHERE}:9443/ui"],
)
def test_r_d8_url_naming_another_guest_network_address_is_not_published(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    entry: str,
) -> None:
    policy_config = exporting_urls(config)
    guest = Device(
        "Example", "example.local.", (GUEST,), kind=HOME, port=9443, txt=(rdata(entry.encode()),)
    )
    candidate = scanner_pass(
        policy_config, settings, monkeypatch, Client(), Client(guest, index=GUEST_INDEX)
    )[EXPORT]
    records = candidate["records"]
    require(
        len(records) == 1
        and (records[0]["ipv4"], records[0]["port"])
        == (policy_config.scope("wired-lan").host_ipv4, 9443),
        "the guest's record is exported with the verified publication's LAN endpoint",
    )
    published = [base64.b64decode(item) for item in records[0]["txt"]]
    assert [item for item in published if ELSEWHERE.encode() in item] == [], (
        f"the exported record's TXT is {published}"
    )


# R-D9: a guest interface that is absent for one pass.


class Interfaces:
    """ifconfig and the interface index of the example's two interfaces; the guest's can go."""

    def __init__(self, config: Config, settings: owner.BonjourSettings) -> None:
        scope = config.scope("wired-lan")
        guest = settings.scopes[0]
        self.addresses = {
            scope.interface: scope.host_ipv4,
            guest.guest_interface: guest.guest_ipv4,
        }
        self.indexes = {scope.interface: LAN_INDEX, guest.guest_interface: GUEST_INDEX}
        self.guest = guest.guest_interface
        self.absent = False

    def ifconfig(self, argv: list[str], _timeout: float) -> Result:
        name = argv[1]
        if self.absent and name == self.guest:
            # ifconfig's answer for an interface that does not exist, with status 1.
            return Result(1, b"", f"ifconfig: interface {name} does not exist\n".encode())
        return Result(
            0,
            f"{name}: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"
            f"\tinet {self.addresses[name]} netmask 0xffffff00\n".encode(),
            b"",
        )

    def check(self, name: str, address: str) -> int:
        return native.interface_index(name, address, self.ifconfig)


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="readiness R-D9: a guest interface absent for one pass is a miss within the "
    "tolerance; the export stays",
)
def test_r_d9_guest_interface_absent_for_one_pass_keeps_the_export(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_config = leased(config)
    # A tolerance of three passes, and a pass whose read did not complete counted as a miss.
    own = counting(settings)
    # The installed policy that the publisher's proof collection compares with its own.
    write_private(own.config, to_dict(policy_config))
    link = Link(monkeypatch, policy_config, own)
    interfaces = Interfaces(policy_config, own)
    monkeypatch.setattr(owner, "_interfaces", INTERFACES)
    monkeypatch.setattr(owner, "interface_index", interfaces.check)
    monkeypatch.setattr(native.socket, "if_nametoindex", interfaces.indexes.__getitem__)
    link.guests.devices = (CAMERA,)
    link.requested()

    def published() -> Observation:
        """One turn of the publisher, with the proof that it collects itself."""
        try:
            proof = owner.collect_proof(policy_config, own, link.clock.now)
        except Exception:
            # publisher_loop keeps no proof from a collection that failed.
            proof = None
        return owner.publisher_tick(
            policy_config, own, link.store, link.manager, proof, 0, link.clock.now
        ).profiles[EXPORT]

    seen: list[Observation] = []

    def scanner(*arguments: Any) -> None:
        # The scanner process's own passes: the guest interface is there for the first.
        link.clock.now += STEP
        interfaces.absent = bool(seen)
        SCAN_PASS(*arguments)
        seen.append(published())

    serving(monkeypatch, policy_config, own, scanner, 2)
    require(
        [(item.state, item.data["record_count"]) for item in seen[:1]] == [("present", 1)],
        "the publisher registered the guest's record after the first pass",
    )
    require(len(FakeRegistration.made) == 1, "one registration was made for the record")
    written = link.store.read("candidates.json")
    kept = [item["name"] for item in written["policies"].get(EXPORT, {}).get("records", [])]
    after = published()
    closed = FakeRegistration.made[0].closed
    assert (kept, written.get("reason"), after.state, after.data["record_count"], closed) == (
        ["Camera"],
        None,
        "present",
        1,
        False,
    ), (
        f"the pass without the guest interface writes the reason {written.get('reason')!r} "
        f"and the export records {kept}; the publisher reads {after.state} / {after.reason} "
        f"and {'closed' if closed else 'kept'} the registration"
    )


# R-D10: a guest restart.

RESTARTED = "mock-camera-2"


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="readiness R-D10: after a guest restart the coordinator's next run activates "
    "the export, not a cleanup",
)
def test_r_d10_guest_restart_is_activated_by_the_next_coordinator_run(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = Link(monkeypatch, config, settings)
    link.guests.devices = (CAMERA,)
    # The coordinator's request, for the guest's generation before the restart.
    link.requested()
    require(
        names(link.run()[EXPORT]) == ["Camera"] and link.tick()[EXPORT].state == "present",
        "the export is published for the first generation",
    )
    # The guest restarts at the same address: its owner reports a new generation.
    link.clock.now += STEP
    link.report = regenerated(observed(config, link.clock.now), config, "camera", RESTARTED)
    again = link.run(at=link.clock.now)[EXPORT]
    require(
        again["service_generation"] == RESTARTED and names(again) == ["Camera"],
        "the scanner reads the guest again under its new generation",
    )
    publisher = link.tick()[EXPORT]

    def decided(readback: Observation) -> DiscoveryAction:
        """The coordinator's decision on what the owners report, with this readback."""
        current = link.current()
        current = replace(current, profiles={**current.profiles, EXPORT: readback})
        transport = plan(config, current, mock_admissions(config), Intent(), link.clock.now)
        actions = plan_discovery(config, current, transport, Intent(), link.clock.now)
        return next(item for item in actions if item.id == EXPORT)

    absent = Observation(
        "absent",
        "confirmed-absent",
        link.clock.now,
        None,
        {**publisher.data, "interface_confirmed": True, "service_generation": RESTARTED},
    )
    require(
        decided(absent).reason == "ready",
        "every gate but the publisher's readback is verified for the new generation",
    )
    decision = decided(publisher)
    assert (decision.active, decision.service_generation) == (True, RESTARTED), (
        f"the coordinator plans {decision.reason}; the publisher reads "
        f"{publisher.state} / {publisher.reason} with "
        f"{publisher.data['record_count']} records"
    )


# R-D14 and R-D15: runs of the coordinator against the discovery owner's endpoint.


class Reports:
    """An owner that reports its part of the link's report and is asked for nothing else."""

    simulation = False

    def __init__(self, link: Link, identifier: str) -> None:
        self.link = link
        self.owner = identifier

    def observe(self) -> Snapshot:
        config = self.link.config
        current = self.link.current()
        return Snapshot(
            current.observed_at,
            current.network_generation,
            {
                key: item
                for key, item in current.services.items()
                if config.service(key).owner == self.owner
            },
            {
                key: item
                for key, item in current.profiles.items()
                if config.profile_owner(config.profile(key)).id == self.owner
            },
        )

    def apply(self, action: Action) -> Observation:
        pytest.fail(f"set-up no longer holds: no transport action was expected, {action}")

    def reconcile_discovery(self, action: DiscoveryAction) -> Observation:
        pytest.fail(f"set-up no longer holds: {self.owner} owns no discovery, {action}")


class Endpoint:
    """The discovery owner's own endpoint, sent what the coordinator's process client sends."""

    simulation = False

    def __init__(self, link: Link) -> None:
        self.link = link

    def call(self, operation: str, **members: Any) -> Any:
        link = self.link
        request = {
            "protocol_version": 1,
            "operation": operation,
            "owner": link.settings.owner,
            "config": to_dict(link.config),
            **members,
        }
        return owner.endpoint(link.config, link.settings, link.store, request)["result"]

    def observe(self) -> Snapshot:
        return snapshot_from_dict(self.call("observe"))

    def apply(self, action: Action) -> Observation:
        pytest.fail(f"set-up no longer holds: no transport action was expected, {action}")

    def reconcile_discovery(self, action: DiscoveryAction) -> Observation:
        return observation_from_dict(
            self.call(
                "reconcile-discovery",
                policy_digest=config_digest(self.link.config),
                discovery_digest=action.policy_digest,
                discovery=action.id,
                active=action.active,
                service_generation=action.service_generation,
                network_generation=action.network_generation,
            )
        )


class Coordinator:
    """Runs of `reconcile --execute-user-owners`: the real planner and executor.

    The discovery owner answers through its real endpoint; the other owners report
    the link's report. While the endpoint waits for its readback, the publisher
    process turns every quarter of a second on the link's clock, so the endpoint's
    seven seconds pass on that clock.
    """

    def __init__(self, link: Link, monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
        self.link = link
        self.store = Store(directory)
        self.store.write("intent.json", intent_to_dict(Intent()))
        self.clients: dict[str, Any] = {
            item.id: Endpoint(link) if item.id == link.settings.owner else Reports(link, item.id)
            for item in link.config.owners
        }
        # Admitted before the first run.
        self.admissions = mock_admissions(link.config, now=link.clock.now - 1)
        # Whether the publisher holds proof; publisher_loop turns without any where its
        # last collection failed or its first one has not ended.
        self.proven = True
        self.since = 0.0
        monkeypatch.setattr(owners, "time", link.clock)
        monkeypatch.setattr(link.clock, "sleep", self.wait)

    def turn(self) -> dict[str, Observation]:
        """One turn of the publisher process."""
        if self.proven:
            return self.link.tick()
        link = self.link
        observed = owner.publisher_tick(
            link.config, link.settings, link.store, link.manager, None, 0, link.clock.now
        )
        return dict(observed.profiles)

    def wait(self, seconds: float) -> None:
        self.link.clock.now += seconds
        self.since += seconds
        if self.since >= 0.25:
            self.since = 0.0
            self.turn()

    def run(self) -> str:
        """One run; the phase its journal ends in, or the failure it raised."""
        config = self.link.config
        snapshot = owners.observe(config, self.clients)
        intent = intent_from_dict(self.store.read("intent.json"))
        admissions = self.admissions
        reviewed = plan(config, snapshot, admissions, intent, self.link.clock.now)
        try:
            result = execute(
                config,
                reviewed,
                snapshot,
                intent,
                self.clients,
                self.store,
                admissions=admissions,
                now=self.link.clock.now,
                observe_now=lambda: owners.observe(config, self.clients),
                clock=lambda: self.link.clock.now,
            )
        except OwnerFailure as failure:
            return f"raised: {failure}"
        return result.phase

    def journal(self) -> dict[str, Any]:
        journal: dict[str, Any] = self.store.read("journal.json")
        return journal


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="readiness R-D14: a coordinator run in a renewal gap the publisher names does "
    "not clean the policy up",
)
def test_r_d14_coordinator_run_in_a_renewal_gap_keeps_the_sibling_record(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    link = Link(monkeypatch, config, settings)
    # Registration clients that the test ends on their own timer.
    link.manager = expiring_publisher()
    link.lan.devices = (KITCHEN, STUDY)
    link.requested()
    link.run()
    first = link.tick()[IMPORT]
    require(
        (first.state, first.data["record_count"]) == ("present", 2),
        "both records of the import are registered and confirmed",
    )
    coordinator = Coordinator(link, monkeypatch, tmp_path / "coordinator")
    require(coordinator.run() == "committed", "a run while both are confirmed changes nothing")
    renewed = next(item for item in Child.made if item.record.name == KITCHEN.name)
    sibling = next(item for item in Child.made if item.record.name == STUDY.name)
    # One client ends on its own timer; the publisher starts its replacement at once.
    renewed.end = native.RegistrationExpired()
    gap = link.tick()[IMPORT]
    require(
        gap.state == "unknown",
        "the policy reads unknown while the replacement has not confirmed (amendment of #43)",
    )
    phase = coordinator.run()
    planned = {item["id"]: item for item in coordinator.journal()["discovery"]}[IMPORT]
    assert not sibling.closed, (
        f"the run in the gap plans {planned['reason']} (active {planned['active']}) and "
        f"ends {phase!r}; the sibling record's client was closed"
    )


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="readiness R-D15: an activation before the scanner's first candidate does not "
    "leave a failed journal that blocks the next run",
)
def test_r_d15_activation_before_the_first_candidate_does_not_block_the_coordinator(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    link = Link(monkeypatch, config, settings)
    link.guests.devices = (CAMERA,)
    # A cold start: the publisher turns, the scanner has not finished a pass yet.
    link.tick()
    require(
        not (settings.state_dir / "candidates.json").exists(),
        "no candidate has been written before the first coordinator run",
    )
    coordinator = Coordinator(link, monkeypatch, tmp_path / "coordinator")
    first = coordinator.run()
    journal = coordinator.journal()["phase"]
    # The scanner's first pass ends, and the publisher turns.
    exported = link.run()[EXPORT]
    require(names(exported) == ["Camera"], "the scanner's first pass reads the guest's record")
    held = link.tick()[EXPORT]
    second = coordinator.run()
    assert journal != "failed" and not second.startswith("raised"), (
        f"the first run ends {first!r} with the journal {journal!r}; after the scanner's "
        f"pass the publisher reads {held.state} / {held.reason}; the next run ends {second!r}"
    )


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="readiness R-D15: a cleanup while the publisher has no proof does not leave a "
    "failed journal that blocks the next run",
)
def test_r_d15_cleanup_while_the_publisher_has_no_proof_does_not_block_the_coordinator(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    link = Link(monkeypatch, config, settings)
    link.guests.devices = (CAMERA,)
    link.requested()
    link.run()
    require(link.tick()[EXPORT].state == "present", "the export is published")
    coordinator = Coordinator(link, monkeypatch, tmp_path / "coordinator")
    require(coordinator.run() == "committed", "a run while the export is confirmed changes nothing")
    # The publisher's proof collection fails (an absent guest interface, R-D9), or has not
    # ended after a boot: the publisher turns without proof.
    coordinator.proven = False
    link.clock.now += 1
    require(
        coordinator.turn()[EXPORT].state == "unknown",
        "without proof the publisher reads the export unknown",
    )
    during = coordinator.run()
    journal = coordinator.journal()["phase"]
    # The proof returns.
    coordinator.proven = True
    link.clock.now += 1
    coordinator.turn()
    after = coordinator.run()
    assert journal != "failed" and not after.startswith("raised"), (
        f"the run without proof ends {during!r} with the journal {journal!r}; the run after "
        f"the proof returned ends {after!r}"
    )

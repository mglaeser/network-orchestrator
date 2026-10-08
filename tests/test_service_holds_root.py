"""Holds in the packet-rule owner: its own file, the user-side gate and the report.

No native network operation and no root: the kernel backend, the runtime
observer and the report writer are the fakes of the owner's own test module.
"""

from __future__ import annotations

import contextlib
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import netorch.pf_owner as module
from netorch.codec import strict_loads
from netorch.config import to_dict
from netorch.model import Config
from netorch.pf_owner import PFError, reconcile, withdraw
from netorch.state import Intent, Snapshot, intent_from_dict, intent_to_dict
from netorch.storage import Store
from netorch.workflow_gate import NOT_QUALIFIED
from tests.test_pf_owner import STAMP, approve_all, environment, run_pass
from tests.test_service_holds import holding

__all__ = ["environment"]

OWNED = ("dns-tcp", "dns-udp", "media-udp", "proxy-standard")
RESOLVER = ("dns-tcp", "dns-udp")
ADMINISTRATOR = ("maintenance", "administrator")
MANAGER = ("maintenance", "manager")
EXACT = 2**53 - 1


def loaded(environment: Any) -> set[str]:
    rules = environment[3].rules
    return {profile for profile in OWNED if f"# netorch:{profile}" in rules}


def drains(environment: Any) -> list[str]:
    return [command[1] for command in environment[3].commands if command[0] == "drain"]


def own(environment: Any, intent: Intent) -> None:
    environment[0].write("operator-intent.json", intent_to_dict(intent))


def gate(environment: Any, tmp_path: Path, document: Intent | dict[str, Any]) -> Store:
    """The user-side file that the installation names as its additive gate."""
    user = Store(tmp_path / "user-state")
    user.write(
        "intent.json", intent_to_dict(document) if isinstance(document, Intent) else document
    )
    installation = environment[0].read("installation.json")
    installation["intent_path"] = str(user.directory / "intent.json")
    environment[0].write("installation.json", installation)
    return user


def reported(environment: Any, observer: Any = None) -> tuple[dict[str, Any], Snapshot]:
    root, _config, _settings, backend, snapshots = environment
    reports: list[Snapshot] = []
    result = reconcile(
        root,
        observer or (lambda config, settings: snapshots[-1]),
        lambda root, settings: backend,
        now=lambda: STAMP,
        report=lambda settings, snapshot: reports.append(snapshot),
    )
    return result, reports[-1]


def test_root_owner_retires_only_the_held_service_and_external_gate_only_adds(
    environment: Any, tmp_path: Path
) -> None:
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    assert loaded(environment) == set(OWNED)
    resolver = environment[4][-1].services["resolver"].data["ipv4"]
    # An invalidation is issued only while a state of the retired rule exists:
    # one client state through each of the two rules of that guest.
    environment[3].flow_states = (
        f"all tcp 192.0.2.77:54321 -> {resolver}:53 ESTABLISHED:ESTABLISHED\n"
        f"all udp 192.0.2.77:54322 -> {resolver}:53 NO_TRAFFIC:SINGLE"
    )
    own(environment, holding(Intent(), "resolver", *ADMINISTRATOR))
    result = run_pass(environment)
    # Every withdrawal first, then the states of that one guest; nothing else moves.
    assert result["changed"] == [
        "dns-tcp:withdraw",
        "dns-udp:withdraw",
        "dns-tcp:drain",
        "dns-udp:drain",
    ]
    assert result["phase"] == "inhibited" and result["pending"] == list(RESOLVER)
    assert loaded(environment) == {"media-udp", "proxy-standard"}
    # The fake removes every row of an address at once: one invalidation.
    assert drains(environment) == [resolver]
    assert environment[0].read("journal.json")["phase"] == "inhibited"
    again = run_pass(environment)
    assert again["changed"] == [] and again["pending"] == list(RESOLVER)
    # A user-side file with fewer holds than root's own removes nothing.
    user = gate(environment, tmp_path, Intent())
    assert run_pass(environment)["changed"] == []
    assert loaded(environment) == {"media-udp", "proxy-standard"}
    # What it holds is added, under its own service only.
    user.write("intent.json", intent_to_dict(holding(Intent(), "web-proxy", *MANAGER)))
    assert run_pass(environment)["changed"] == ["proxy-standard:withdraw", "proxy-standard:drain"]
    assert loaded(environment) == {"media-udp"}
    # A structural host redirect has no guest states of its own to invalidate.
    assert drains(environment) == [resolver]
    # The same operation and holder in the user's file is a second record: when
    # the user takes it away again, root's own record still holds the service.
    user.write("intent.json", intent_to_dict(holding(Intent(5), "resolver", *ADMINISTRATOR)))
    assert run_pass(environment)["changed"] == ["proxy-standard:activate"]
    user.write("intent.json", intent_to_dict(Intent(7)))
    assert run_pass(environment)["changed"] == []
    assert loaded(environment) == {"media-udp", "proxy-standard"}
    # Only the holder's own release in root's own file brings the service back.
    own(
        environment,
        intent_from_dict(environment[0].read("operator-intent.json")).unhold(
            "resolver", *ADMINISTRATOR
        ),
    )
    assert run_pass(environment)["changed"] == ["dns-tcp:activate", "dns-udp:activate"]
    assert run_pass(environment)["phase"] == "committed"
    assert loaded(environment) == set(OWNED)


OWN = {
    "open": Intent(),
    "hold": holding(Intent(), "resolver", *ADMINISTRATOR),
    "pause": Intent().pause(),
    "suspension": Intent().suspend("installation", "bundle"),
    "damaged": {"schema_version": 999},
}
EXTERNAL = {
    "none": None,
    "open": Intent(),
    "other-hold": holding(Intent(), "web-proxy", *MANAGER),
    "same-hold": holding(Intent(), "resolver", *ADMINISTRATOR),
    "pause": Intent().pause(),
    "suspension": Intent().suspend("installation", "bundle"),
    "damaged": {"schema_version": 2, "holds": {}},
    "unknown-service": holding(Intent(), "retired-service", *MANAGER),
}


@pytest.mark.parametrize("external", sorted(EXTERNAL))
@pytest.mark.parametrize("mine", sorted(OWN))
def test_the_user_side_file_can_only_add_inhibition(
    environment: Any, tmp_path: Path, mine: str, external: str
) -> None:
    root, config, _settings, _backend, _snapshots = environment
    document = OWN[mine]
    root.write(
        "operator-intent.json",
        intent_to_dict(document) if isinstance(document, Intent) else document,
    )
    alone = module._attributed(
        config,
        module._inhibition(root, module.Installation.from_dict(root.read("installation.json"))),
    )
    theirs = EXTERNAL[external]
    if theirs is not None:
        gate(environment, tmp_path, theirs)
    installation = module.Installation.from_dict(root.read("installation.json"))
    merged = module._attributed(config, module._inhibition(root, installation))
    read = module._gate(installation)
    for service in config.services:
        assert merged.blocks(service.id) >= alone.blocks(service.id)
        if read is not None:
            assert merged.blocks(service.id) >= module._attributed(config, read).blocks(service.id)
    assert merged.blocked >= alone.blocked
    assert set(merged.holds) >= set(alone.holds)
    for service, records in alone.holds.items():
        assert dict(merged.holds[service]).items() >= dict(records).items()
    # The user's operation names are never keys of the merged view.
    if isinstance(theirs, Intent) and theirs.holds and isinstance(document, Intent):
        for service, records in theirs.holds.items():
            added = set(merged.holds[service]) - set(document.holds.get(service, {}))
            assert len(added) == len(records)
            assert all(key.startswith("external:") and len(key) == 73 for key in added)


def test_a_full_user_gate_and_a_full_root_file_still_hold(environment: Any, tmp_path: Path) -> None:
    approve_all(environment)
    run_pass(environment)
    mine, theirs = Intent(), Intent()
    for index in range(8):
        mine = holding(mine, "resolver", f"root-operation-{index}", "administrator")
        theirs = holding(theirs, "resolver", f"user-operation-{index}", "manager")
    own(environment, mine)
    gate(environment, tmp_path, theirs)
    root = environment[0]
    merged = module._inhibition(root, module.Installation.from_dict(root.read("installation.json")))
    assert len(merged.holds["resolver"]) == 16 and not merged.damaged
    result, report = reported(environment)
    assert result["phase"] == "inhibited" and loaded(environment) == {"media-udp", "proxy-standard"}
    for profile in OWNED:
        data = report.profiles[profile].data
        assert data.get("held") is (True if profile in RESOLVER else None)
        assert data["gate_revision"] == theirs.revision == 8


def test_root_report_names_the_hold_and_the_gate_revision(environment: Any, tmp_path: Path) -> None:
    approve_all(environment)
    _result, report = reported(environment)
    # Without a hold and without a gate the report has neither key.
    for profile in OWNED:
        assert report.profiles[profile].data["root_ready"] is True
        assert not {"held", "gate_revision"} & set(report.profiles[profile].data)
    own(environment, holding(Intent(), "resolver", *ADMINISTRATOR))
    _result, report = reported(environment)
    for profile in OWNED:
        data = report.profiles[profile].data
        assert ("held" in data) is (profile in RESOLVER) and "gate_revision" not in data
        assert data["root_ready"] is (profile not in RESOLVER)
    # Root's own revision is far ahead of the user's file from here on: the
    # reported number is the revision of the file the manager wrote, never the
    # larger of the two, which a pass could show without having read the hold.
    own(environment, Intent(1000))
    reported(environment)
    assert reported(environment)[0]["phase"] == "committed"
    # A manager's planned stop: place the hold, keep its revision, wait for the report.
    placed = holding(Intent(40), "web-proxy", *MANAGER)
    user = gate(environment, tmp_path, placed)
    _result, report = reported(environment)
    waited = report.profiles["proxy-standard"]
    assert waited.state == "absent" and waited.data["states"] == ()
    assert waited.data["held"] is True and waited.data["root_ready"] is False
    assert waited.data["gate_revision"] == placed.revision == 41
    for profile in ("dns-tcp", "dns-udp", "media-udp"):
        data = report.profiles[profile].data
        assert "held" not in data and data["gate_revision"] == 41
        assert data["root_ready"] is True and report.profiles[profile].state == "present"
    # A gate that cannot be read undamaged, or whose revision a JSON reader could
    # not hold exactly, has no revision to report.
    for document, shown in (
        ({"schema_version": 2, "holds": {}}, None),
        (intent_to_dict(Intent(EXACT + 1)), None),
        (intent_to_dict(Intent(EXACT)), EXACT),
    ):
        user.write("intent.json", document)
        _result, report = reported(environment)
        assert {item.data.get("gate_revision") for item in report.profiles.values()} == {shown}
    (user.directory / "intent.json").unlink()
    _result, report = reported(environment)
    assert all("gate_revision" not in item.data for item in report.profiles.values())
    assert all(item.data["root_ready"] is False for item in report.profiles.values())


def test_a_hold_that_arrives_after_the_plan_is_reported_with_the_truthful_state(
    environment: Any, tmp_path: Path
) -> None:
    approve_all(environment)
    run_pass(environment)
    user = gate(environment, tmp_path, Intent())
    assert run_pass(environment)["phase"] == "committed"
    snapshots = environment[4]
    calls = 0

    def observe(config: Config, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        if calls == 2:
            user.write("intent.json", intent_to_dict(holding(Intent(), "resolver", *MANAGER)))
        return snapshots[-1]

    result, report = reported(environment, observe)
    # This pass planned without the hold: the rules are loaded and the report says
    # so. It also ended knowing the hold, so the profile is no longer ready.
    assert result["changed"] == [] and loaded(environment) == set(OWNED)
    for profile in RESOLVER:
        observed = report.profiles[profile]
        assert observed.state == "present" and observed.data["held"] is True
        assert observed.data["root_ready"] is False and observed.data["gate_revision"] == 1
    _result, report = reported(environment)
    for profile in RESOLVER:
        observed = report.profiles[profile]
        assert observed.state == "absent" and observed.data["states"] == ()
        assert observed.data["held"] is True and observed.data["gate_revision"] == 1


@pytest.mark.parametrize("side", ["own", "user"])
def test_a_hold_on_an_unknown_service_inhibits_everything_for_root(
    environment: Any, tmp_path: Path, side: str
) -> None:
    approve_all(environment)
    run_pass(environment)
    unknown = holding(Intent(), "retired-service", *MANAGER)
    user = gate(environment, tmp_path, Intent())
    if side == "own":
        own(environment, unknown)
    else:
        user.write("intent.json", intent_to_dict(unknown))
    result, report = reported(environment)
    # Root does not guess which of its services was meant: damage for this pass.
    assert result["phase"] == "inhibited" and result["pending"] == list(OWNED)
    assert not environment[3].rules
    for profile in OWNED:
        observed = report.profiles[profile]
        assert observed.state == "absent" and observed.data["root_ready"] is False
        assert "held" not in observed.data
    # Not an interrupted write: once the hold is gone the next pass activates again.
    own(environment, Intent())
    user.write("intent.json", intent_to_dict(Intent(2)))
    assert sorted(run_pass(environment)["changed"]) == [f"{profile}:activate" for profile in OWNED]
    assert run_pass(environment)["phase"] == "committed"


def test_a_hold_that_arrives_before_an_activation_stops_that_service_only(
    environment: Any, tmp_path: Path
) -> None:
    approve_all(environment)
    user = gate(environment, tmp_path, Intent())
    snapshots = environment[4]
    arriving = [holding(Intent(), "camera", *MANAGER)]
    calls = 0

    def observe(config: Config, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        if calls == 1:
            # After the pass read its gates and before it re-reads them for a rule.
            user.write("intent.json", intent_to_dict(arriving[0]))
        return snapshots[-1]

    # A hold on another service does not stand in the way of this pass.
    result, _report = reported(environment, observe)
    assert result["phase"] == "committed" and loaded(environment) == set(OWNED)
    own(environment, Intent().pause())
    run_pass(environment)
    own(environment, Intent(2))
    assert loaded(environment) == set()
    # A hold on the service whose rule is about to be loaded keeps that rule out.
    arriving[0], calls = holding(Intent(1), "web-proxy", *MANAGER), 0
    with contextlib.suppress(PFError):
        reported(environment, observe)
    assert loaded(environment) == {"dns-tcp", "dns-udp", "media-udp"}
    with contextlib.suppress(PFError):
        run_pass(environment)
    assert "proxy-standard" not in loaded(environment)


@pytest.mark.parametrize("fault", ["journal", "admissions"])
def test_a_pass_that_owes_an_acknowledgement_still_reports_the_hold(
    environment: Any, fault: str
) -> None:
    approve_all(environment)
    run_pass(environment)
    own(environment, holding(Intent(), "resolver", *ADMINISTRATOR))
    root = environment[0]
    if fault == "journal":
        root.write("journal.json", {"schema_version": 1, "phase": "failed"})
    else:
        root.write("admissions.json", {"schema_version": 1, "strategy": "other", "profiles": {}})
    result, report = reported(environment)
    assert result["phase"] == "failed" and not environment[3].rules
    for profile in OWNED:
        data = report.profiles[profile].data
        assert data["root_ready"] is False and ("held" in data) is (profile in RESOLVER)


def test_administrator_withdrawal_keeps_the_holds(environment: Any) -> None:
    approve_all(environment)
    run_pass(environment)
    root, _config, _settings, backend, _snapshots = environment
    before = holding(Intent().suspend("upgrade", "runtime-manager"), "resolver", *ADMINISTRATOR)
    own(environment, before)
    assert withdraw(root, lambda root, installation: backend)["withdrawn"]
    after = intent_from_dict(root.read("operator-intent.json"))
    assert after.operator_paused and after.holds == before.holds
    assert after.suspensions == before.suspensions and not backend.rules
    # The installer's own withdrawal leaves the pause value and the holds as they are.
    own(
        environment,
        holding(Intent().suspend("installation", "bundle-1"), "resolver", *ADMINISTRATOR),
    )
    withdraw(root, lambda root, installation: backend, operation="installation", holder="bundle-1")
    kept = intent_from_dict(root.read("operator-intent.json"))
    assert not kept.operator_paused and kept.holds == before.holds


def fake_root(monkeypatch: pytest.MonkeyPatch, values: dict[str, Any]) -> None:
    fake = SimpleNamespace(lock=nullcontext, read=values.__getitem__, write=values.__setitem__)
    monkeypatch.setattr(module.sys, "platform", "darwin")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module, "protected_code", lambda *_args: None)
    monkeypatch.setattr(module, "protected_ancestors", lambda *_args: None)
    monkeypatch.setattr(module, "Store", lambda _path: fake)


def test_root_hold_command_needs_no_gate_and_refuses_an_unknown_service(
    environment: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    before = intent_to_dict(Intent().suspend("restore", "other"))
    values = {"operator-intent.json": before, "policy.json": to_dict(environment[1])}
    fake_root(monkeypatch, values)
    base = ["--root-dir", str(tmp_path), "--operation", "maintenance", "--holder", "administrator"]
    # The real gate is in place: adding inhibition is never a gated command.
    assert module.main(["hold", *base, "--service", "resolvr"]) == 65
    assert values["operator-intent.json"] == before
    assert strict_loads(capsys.readouterr().err)["error"] == "PFError"
    assert module.main(["hold", *base, "--service", "resolver"]) == 0
    stored = intent_from_dict(values["operator-intent.json"])
    assert stored.holds == {"resolver": {"maintenance": "administrator"}}
    assert stored.suspensions == {"restore": "other"} and stored.revision == 2
    assert strict_loads(capsys.readouterr().out) == values["operator-intent.json"]
    assert values["operator-intent.json"]["schema_version"] == 2
    # Another holder cannot replace it, and without an installed policy nothing is placed.
    kept = dict(values["operator-intent.json"])
    assert module.main(["hold", *base[:-1], "someone-else", "--service", "resolver"]) == 65
    del values["policy.json"]
    assert module.main(["hold", *base, "--service", "camera"]) == 65
    assert values["operator-intent.json"] == kept


def must_not_call(*_args: Any, **_kwargs: Any) -> Any:
    pytest.fail("a denied command reached state, code checks or a native operation")


def test_root_unhold_is_gated_like_release(
    environment: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = ["unhold", "--root-dir", str(tmp_path / "absent"), "--service", "resolver"]
    arguments += ["--operation", "maintenance"]
    with monkeypatch.context() as denied:
        for name in ("protected_code", "protected_ancestors", "Store", "run", "ShellBackend"):
            denied.setattr(module, name, must_not_call)
        denied.setattr(module.os, "geteuid", must_not_call)
        assert module.main([*arguments, "--holder", "administrator"]) == NOT_QUALIFIED
        refusal = strict_loads(capsys.readouterr().err)
        assert refusal["error"] == "stage-not-qualified"
        assert refusal["capability"] == "privileged-owner-mutation"
        assert not (tmp_path / "absent").exists()
    # Behind the gate only the holder releases, and the last release restores version 1.
    held = holding(Intent().pause(), "resolver", *ADMINISTRATOR)
    values = {"operator-intent.json": intent_to_dict(held), "policy.json": to_dict(environment[1])}
    fake_root(monkeypatch, values)
    monkeypatch.setattr(module, "require_mutation_qualified", lambda _capability: None)
    assert module.main([*arguments, "--holder", "someone-else"]) == 65
    assert values["operator-intent.json"] == intent_to_dict(held)
    assert module.main([*arguments, "--holder", "administrator"]) == 0
    assert values["operator-intent.json"] == intent_to_dict(Intent(3, True))
    assert values["operator-intent.json"]["schema_version"] == 1

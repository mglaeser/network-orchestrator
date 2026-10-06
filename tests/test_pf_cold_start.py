"""What the packet-rule owner does after a reboot is the administrator's explicit choice.

Rules and states are kernel memory; the owner's records are files. A reboot is
modelled as exactly that: the fake kernel loses its rules and states and gets
another boot session, the protected store keeps every file, and the runtime
hands its addresses out afresh. Nothing here runs a native tool, except the one
hosted-macOS contract test at the end, which only reads.
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from dataclasses import replace
from itertools import takewhile
from pathlib import Path
from typing import Any

import pytest

import netorch.pf_owner as module
from netorch.codec import canonical_bytes, strict_loads
from netorch.config import to_dict
from netorch.model import Config
from netorch.pf_owner import (
    STRATEGY,
    Installation,
    PFError,
    ShellBackend,
    admit,
    admitted_digest,
    install,
    main,
    withdraw,
)
from netorch.process import ProcessTimeout, Result
from netorch.state import Intent, Observation, Snapshot, intent_to_dict
from netorch.storage import Store
from tests.test_pf_noop_pass_interruption import Photo, acknowledge, die_at, photographed_pass
from tests.test_pf_owner import ROOT, STAMP, FakeBackend, approve_all, environment, run_pass
from tests.test_pf_withdraw_order import LiveKernel, owned

__all__ = ["environment"]

CLIENT = "192.0.2.77"
ALL = ["dns-tcp", "dns-udp", "media-udp", "media-udp", "proxy-standard"]
PROFILES = ["dns-tcp", "dns-udp", "media-udp", "proxy-standard"]


def boot(number: int) -> str:
    """A boot session as the kernel prints it: one upper-case UUID."""
    return str(uuid.UUID(int=(0xABCDEF << 104) + number)).upper()


FIRST, SECOND, THIRD = boot(1), boot(2), boot(3)

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


def reboot(kernel: FakeBackend, session: str | None = SECOND) -> None:
    """Rules and states are kernel memory; the owner's files are not."""
    kernel.rules = ""
    kernel.flow_states = ""
    kernel.session = session
    kernel.commands.clear()


def new_boot(environment: Any, session: str | None = SECOND) -> None:
    """The host restarts: an empty kernel, new guests, addresses handed out afresh."""
    _, config, _, kernel, snapshots = environment
    reboot(kernel, session)
    current = snapshots[0]
    order = sorted(current.services)
    addresses = [str(current.services[key].data["ipv4"]) for key in order]
    addresses = addresses[1:] + addresses[:1]
    generation, network = f"instance-{len(snapshots) + 1}", f"network-{len(snapshots) + 1}"
    services = {
        key: Observation(
            "present",
            "verified",
            STAMP,
            generation,
            {**current.services[key].data, "ipv4": address},
        )
        for key, address in zip(order, addresses, strict=True)
    }
    publications = {
        key: Observation(
            value.state,
            value.reason,
            STAMP,
            generation,
            {
                **value.data,
                "target_ipv4": services[config.profile(key).service].data["ipv4"],
                "target_generation": generation,
                "network_generation": network,
            },
        )
        for key, value in current.profiles.items()
    }
    snapshots.append(Snapshot(STAMP, network, services, publications))


def decided(environment: Any, *, heal: bool, kernel: FakeBackend | None = None) -> Any:
    """Install the decision, admit every profile under it, and name the first boot."""
    root, config, settings, backend, snapshots = environment
    backend = backend if kernel is None else kernel
    backend.session = FIRST
    if heal:
        settings = replace(settings, cold_start="self-heal")
        root.write("installation.json", settings.to_dict())
    environment = (root, config, settings, backend, snapshots)
    approve_all(environment)
    return environment


def converged(environment: Any, *, heal: bool = False, kernel: FakeBackend | None = None) -> Any:
    environment = decided(environment, heal=heal, kernel=kernel)
    assert run_pass(environment)["phase"] == "committed"
    assert owned(environment[3]) == ALL
    return environment


def records(root: Store) -> dict[str, Any]:
    try:
        return dict(root.read("live.json")["records"])
    except FileNotFoundError:
        return {}


def client_states(remembered: dict[str, Any], *keys: str) -> str:
    """One state that a LAN client made through each named guest rule (all three by default).

    An invalidation is issued only while a state of the retired rule exists, so a
    test that expects one gives the kernel such a state. The fake removes every
    row of an address at once: one invalidation for each distinct guest address.
    """
    rules = {"dns-tcp": ("tcp", 53), "dns-udp": ("udp", 53), "media-udp": ("udp", 45001)}
    rows = []
    for index, key in enumerate(keys or sorted(rules)):
        protocol, port = rules[key]
        status = "ESTABLISHED:ESTABLISHED" if protocol == "tcp" else "NO_TRAFFIC:SINGLE"
        target = remembered[key]["target_ipv4"]
        rows.append(f"all {protocol} {CLIENT}:{54321 + index} -> {target}:{port} {status}")
    return "\n".join(rows)


def guest_addresses(remembered: dict[str, Any]) -> list[str]:
    return sorted(
        {
            record["target_ipv4"]
            for record in remembered.values()
            if record["kind"] != "host-redirect"
        }
    )


def stored(root: Store) -> dict[str, bytes]:
    """Every protected document, byte for byte."""
    return {path.name: path.read_bytes() for path in sorted(root.directory.glob("*.json"))}


def issued(kernel: FakeBackend, *operations: str) -> list[tuple[str, ...]]:
    return [command for command in kernel.commands if command[0] in operations]


def foreign_rule(config: Config) -> str:
    """A rule in the owned anchor that no record of this owner explains."""
    scope = config.scopes[0]
    return (
        f"rdr on {scope.interface} inet proto tcp from any to {scope.host_ipv4} port 80"
        " -> 192.0.2.99\n"
    )


def unknown_runtime(environment: Any) -> None:
    snapshots = environment[4]
    snapshots.append(
        Snapshot(
            STAMP,
            None,
            {
                key: Observation("unknown", "inaccessible", STAMP, None)
                for key in snapshots[0].services
            },
            {},
        )
    )


# ------------------------------------------------------------------ the stored decision


def test_an_installation_without_the_decision_keeps_its_stored_form(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = environment[1]
    profile = config.profile("dns-udp")
    monkeypatch.setattr(module, "implementation_digest", lambda: "f" * 64)
    monkeypatch.setattr(module, "profile_digest", lambda config, profile: "e" * 64)
    plain = Installation(*PLAIN)

    assert plain.cold_start == "administrator"
    assert len(plain.to_dict()) == 9 and "cold_start" not in plain.to_dict()
    assert canonical_bytes(plain.to_dict()) == BASE_BYTES
    assert Installation.from_dict(strict_loads(BASE_BYTES)) == plain
    assert admitted_digest(config, profile, plain) == BASE_DIGEST

    chosen = replace(plain, cold_start="self-heal")
    assert chosen.to_dict() == {**plain.to_dict(), "cold_start": "self-heal"}
    assert Installation.from_dict(strict_loads(canonical_bytes(chosen.to_dict()))) == chosen
    assert admitted_digest(config, profile, chosen) != BASE_DIGEST


@pytest.mark.parametrize(
    "value",
    ["administrator", None, "never", "Self-Heal", "self-heal ", "", True, 1, ["self-heal"], {}],
)
def test_self_heal_is_the_only_decision_that_can_be_written(environment: Any, value: Any) -> None:
    raw = environment[2].to_dict()
    with pytest.raises(PFError, match="unsupported installation schema"):
        Installation.from_dict({**raw, "cold_start": value})
    with pytest.raises(PFError, match="unsupported installation schema"):
        Installation.from_dict({**raw, "cold_start": "self-heal", "cold_boot": "self-heal"})
    if value != "administrator":
        with pytest.raises(PFError, match="cold-start"):
            Installation(*PLAIN, cold_start=value)


@pytest.mark.parametrize("heal", [True, False], ids=["chosen", "taken back"])
def test_changing_the_decision_voids_every_admission(
    environment: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, heal: bool
) -> None:
    environment = converged(environment, heal=not heal)
    root, config, settings, kernel, _ = environment
    changed = replace(settings, cold_start="self-heal" if heal else "administrator")
    monkeypatch.setattr(module, "protected_ancestors", lambda *args, **kwargs: None)
    policy, setting = tmp_path / "policy", tmp_path / "settings"
    policy.write_bytes(canonical_bytes(to_dict(config)))
    setting.write_bytes(canonical_bytes(changed.to_dict()))

    installed = install(root.directory, policy, setting, ROOT / "platform/macos/pf/backend.sh")

    # The installer keeps the approvals and says that none of them holds now.
    assert installed["admissions_preserved"] and sorted(installed["pending"]) == PROFILES
    result = run_pass(environment)
    assert result["phase"] == "inhibited" and sorted(result["pending"]) == PROFILES
    assert kernel.rules == ""


def test_admission_and_its_review_show_the_decision(
    environment: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import netorch.storage as storage

    root, _, settings, _, _ = environment
    # The administrator command, with the root boundary replaced by the fixture.
    monkeypatch.setattr(module.sys, "platform", "darwin")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module, "Store", lambda directory: root)
    monkeypatch.setattr(module, "protected_ancestors", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "protected_code", lambda *args, **kwargs: None)
    monkeypatch.setattr(storage.Store, "_check_directory_info", staticmethod(lambda info: None))
    monkeypatch.setattr(storage, "_check_file", lambda fd: None)
    base = ["--root-dir", str(root.directory)]
    # Without the decision the admission and its review print what they printed before.
    assert "cold_start" not in admit(root, "dns-udp", acknowledge_bounded_risk=True)["resolved"]
    assert main(["review-admission", *base, "--profile", "dns-udp"]) == 0
    plain = strict_loads(capsys.readouterr().out)
    assert "cold_start" not in plain

    root.write("installation.json", replace(settings, cold_start="self-heal").to_dict())
    assert admit(root, "dns-udp", acknowledge_bounded_risk=True)["resolved"]["cold_start"] == (
        "self-heal"
    )
    assert main(["review-admission", *base, "--profile", "dns-udp"]) == 0
    review = strict_loads(capsys.readouterr().out)
    assert review["cold_start"] == "self-heal"
    assert set(review) == {*plain, "cold_start"}
    assert (
        review["expected_digest"] == root.read("admissions.json")["profiles"]["dns-udp"]["digest"]
    )
    root.write("journal.json", {"schema_version": 1, "phase": "inhibited", "boot_session": FIRST})
    assert main(["status", *base]) == 0
    status = strict_loads(capsys.readouterr().out)
    assert status["installation"]["cold_start"] == "self-heal"
    assert status["journal"]["boot_session"] == FIRST


# ------------------------------------------------------------------ the boot session


@pytest.mark.parametrize(
    "answer,session",
    [
        (FIRST + "\n", FIRST),
        (FIRST, FIRST),
        ("", None),
        ("\n", None),
        (FIRST.lower() + "\n", None),
        (FIRST + "\n\n", None),
        (FIRST + "\n" + FIRST + "\n", None),
        (" " + FIRST + "\n", None),
        (FIRST + " \n", None),
        (FIRST + "\r\n", None),
        ("{" + FIRST + "}\n", None),
        (FIRST[:-1] + "\n", None),
        (FIRST + "0\n", None),
        (FIRST.replace("-", "") + "\n", None),
        (FIRST[:-1] + "G\n", None),
        ("kern.bootsessionuuid: " + FIRST + "\n", None),
    ],
)
def test_exactly_one_upper_case_uuid_is_a_read_of_the_boot_session(
    monkeypatch: pytest.MonkeyPatch, answer: str, session: str | None
) -> None:
    backend = object.__new__(ShellBackend)
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake(argv: list[str], **bounds: Any) -> Result:
        calls.append((argv, bounds))
        return Result(0, answer.encode(), b"")

    monkeypatch.setattr(module, "run", fake)
    if session is None:
        with pytest.raises(PFError, match="boot session"):
            backend.boot_session()
    else:
        assert backend.boot_session() == session
    # One bounded read of one fixed kernel value by its absolute path.
    assert calls == [
        (["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"], {"timeout": 2.0, "max_output": 262144})
    ]


@pytest.mark.parametrize(
    "result",
    [
        Result(1, (FIRST + "\n").encode(), b""),
        Result(0, (FIRST + "\n").encode(), b"sysctl: unknown oid\n"),
        Result(0, b"\xff\xfe", b""),
        ProcessTimeout("command did not complete within its deadline"),
        FileNotFoundError("/usr/sbin/sysctl"),
    ],
    ids=["exit status", "standard error", "undecodable", "timed out", "no tool"],
)
def test_a_failed_read_of_the_boot_session_is_no_session(
    monkeypatch: pytest.MonkeyPatch, result: Result | Exception
) -> None:
    def fake(argv: list[str], **bounds: Any) -> Result:
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(module, "run", fake)
    backend = object.__new__(ShellBackend)
    with pytest.raises((OSError, RuntimeError, ValueError)):
        backend.boot_session()
    assert module._boot_session(backend) is None


class Answering(FakeBackend):
    """A backend whose boot session read answers, or raises, whatever a test says."""

    def __init__(self, answer: Any) -> None:
        super().__init__()
        self.answer = answer

    def boot_session(self) -> Any:
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


@pytest.mark.parametrize(
    "answer",
    [
        OSError("unavailable"),
        ProcessTimeout("deadline"),
        ValueError("undecodable"),
        FIRST.lower(),
        FIRST + "\n",
        "",
        None,
        FIRST.encode(),
        [FIRST],
    ],
    ids=["os", "timeout", "value", "lower", "newline", "empty", "null", "bytes", "list"],
)
def test_a_pass_whose_boot_session_is_unknown_runs_as_before_and_records_none(
    environment: Any, answer: Any
) -> None:
    root, config, settings, _, snapshots = environment
    kernel = Answering(answer)
    environment = (root, config, settings, kernel, snapshots)
    approve_all(environment)

    result, photos = photographed_pass(environment)

    assert result["phase"] == "committed" and owned(kernel) == ALL
    journals = [photo.journal for photo in photos if photo.journal is not None]
    assert len(journals) > 8
    assert all("boot_session" not in journal for journal in journals)
    result = withdraw(root, lambda root, settings: kernel)
    assert result["guest_states_drained"] is True and "cold_start" not in result
    assert "boot_session" not in root.read("journal.json")


def journals_of(photos: list[Photo]) -> list[dict[str, Any]]:
    return [photo.journal for photo in photos if photo.journal is not None]


def test_every_journal_record_names_the_boot_it_was_written_in(environment: Any) -> None:
    """The same passes, once with a known boot and once without: one key differs."""
    root, _, _, kernel, snapshots = environment
    approve_all(environment)
    start = Photo({name: strict_loads(payload) for name, payload in stored(root).items()}, "", "")

    def scenario(session: str | None) -> list[dict[str, Any]]:
        die_at(environment, start)
        del snapshots[1:]
        kernel.session = session
        written: list[dict[str, Any]] = []
        # Four activations, a healthy pass, then a pause that retires them all.
        for _ in range(2):
            written += journals_of(photographed_pass(environment)[1])
        root.write("operator-intent.json", intent_to_dict(Intent().pause()))
        written += journals_of(photographed_pass(environment)[1])
        root.write("operator-intent.json", intent_to_dict(Intent()))
        written += journals_of(photographed_pass(environment)[1])
        # A write that fails, then the state table cannot be read at all.
        unknown_runtime(environment)
        kernel.fail_after_replace = True
        with pytest.raises(PFError, match="simulated interrupted write"):
            run_pass(environment)
        written.append(root.read("journal.json"))
        kernel.flow_states = "WARNING: state inventory truncated"
        written += journals_of(photographed_pass(environment)[1])
        kernel.flow_states = ""
        return written

    unnamed = scenario(None)
    named = scenario(FIRST)

    assert {journal["phase"] for journal in named} == {
        "applying",
        "committed",
        "inhibited",
        "failed",
    }
    assert any(journal.get("reason") == "kernel-state-unknown" for journal in named)
    assert all(journal["boot_session"] == FIRST for journal in named)
    assert all("boot_session" not in journal for journal in unnamed)
    assert [{**journal, "boot_session": FIRST} for journal in unnamed] == named


# ------------------------------------------------------------------ self-heal


def test_self_heal_returns_after_a_boot_without_invalidating_remembered_addresses(
    environment: Any,
) -> None:
    environment = converged(environment, heal=True)
    root, config, _, kernel, snapshots = environment
    remembered = records(root)
    assert root.read("journal.json")["boot_session"] == FIRST
    new_boot(environment)
    # Another guest has the resolver's former address now, and a client of its own.
    kernel.flow_states = (
        f"all udp {CLIENT}:54321 -> {remembered['dns-udp']['target_ipv4']}:53 NO_TRAFFIC:SINGLE"
    )

    result = run_pass(environment)

    assert result["phase"] == "committed" and result["pending"] == []
    assert sorted(result["changed"]) == [f"{key}:activate" for key in PROFILES]
    assert owned(kernel) == ALL
    assert issued(kernel, "drain") == [] and kernel.flow_states
    journal = root.read("journal.json")
    assert journal["phase"] == "committed" and journal["boot_session"] == SECOND
    services = snapshots[-1].services
    for key, record in records(root).items():
        assert record["network_generation"] == snapshots[-1].network_generation
        assert record["target_generation"] == services[config.profile(key).service].generation
        assert record["target_ipv4"] != remembered[key]["target_ipv4"] or key == "proxy-standard"
    # The next pass is an ordinary healthy pass of this boot.
    mark = len(kernel.commands)
    assert run_pass(environment)["phase"] == "committed"
    assert ("replace",) not in kernel.commands[mark:]


def test_a_self_heal_that_stops_before_its_first_candidate_is_simply_repeated(
    environment: Any,
) -> None:
    """The records go before the journal record that ends the proof of the cold start."""
    environment = converged(environment, heal=True)
    kernel = environment[3]
    new_boot(environment)

    result, photos = photographed_pass(environment)

    assert result["phase"] == "committed" and owned(kernel) == ALL
    early = list(takewhile(lambda photo: "candidate_records" not in photo.journal, photos))
    assert [(photo.journal["phase"], photo.journal.get("reason")) for photo in early] == [
        ("committed", None),
        ("committed", None),
        ("inhibited", "cold-start"),
        ("applying", None),
    ]
    assert [len(photo.files["live.json"]["records"]) for photo in early] == [4, 0, 0, 0]
    assert early[2].journal == {
        "schema_version": 1,
        "phase": "inhibited",
        "reason": "cold-start",
        "boot_session": SECOND,
    }
    for photo in early:
        die_at(environment, photo)
        kernel.commands.clear()
        assert run_pass(environment)["phase"] == "committed", photo.journal
        assert owned(kernel) == ALL and issued(kernel, "drain") == []


def test_self_heal_discharges_a_write_that_the_previous_boot_cut_short(environment: Any) -> None:
    environment = decided(environment, heal=True)
    root, _, _, kernel, _ = environment

    result, photos = photographed_pass(environment)

    assert result["phase"] == "committed"
    unfinished = [
        photo for photo in photos if photo.journal and photo.journal["phase"] != "committed"
    ]
    assert sum("candidate_records" in photo.journal for photo in unfinished) == 12
    assert {photo.journal["phase"] for photo in unfinished} == {"applying"}
    for photo in unfinished:
        die_at(environment, photo)
        new_boot(environment)
        result = run_pass(environment)
        assert result["phase"] == "committed" and len(result["changed"]) == 4, photo.journal
        assert owned(kernel) == ALL and issued(kernel, "drain") == []
        assert root.read("journal.json")["boot_session"] == SECOND


def test_the_same_interruption_within_one_boot_still_needs_an_acknowledgement(
    environment: Any,
) -> None:
    environment = decided(environment, heal=True)
    root, _, _, kernel, _ = environment
    _, photos = photographed_pass(environment)
    journalled = [photo for photo in photos if "candidate_records" in (photo.journal or {})]
    assert len(journalled) == 12
    for photo in journalled:
        die_at(environment, photo)
        for _ in range(2):
            assert run_pass(environment)["phase"] == "failed"
            assert kernel.rules == ""
        acknowledge(root)
        assert run_pass(environment)["phase"] == "committed"


def test_self_heal_keeps_an_acknowledgement_that_was_owed_before_the_boot(
    environment: Any,
) -> None:
    environment = decided(environment, heal=True)
    root, _, _, kernel, _ = environment
    kernel.fail_after_replace = True
    with pytest.raises(PFError, match="simulated interrupted write"):
        run_pass(environment)
    assert root.read("journal.json")["phase"] == "failed" and kernel.rules

    for session in (SECOND, THIRD):
        new_boot(environment, session)
        for _ in range(2):
            assert run_pass(environment)["phase"] == "failed"
        assert kernel.rules == "" and issued(kernel, "drain", "replace", "reference") == []
        journal = root.read("journal.json")
        assert journal["phase"] == "failed" and journal["boot_session"] == session
        assert "candidate_records" not in journal
        assert records(root) == {}
    acknowledge(root)
    assert run_pass(environment)["phase"] == "committed"
    assert owned(kernel) == ALL


@pytest.mark.parametrize("states", ["", "WARNING: state inventory truncated"])
def test_an_owed_acknowledgement_survives_a_power_loss_at_any_point_of_a_later_pass(
    environment: Any, states: str
) -> None:
    """Every record of a pass that owes an acknowledgement says so, not only its first."""
    environment = decided(environment, heal=True)
    root, _, _, kernel, _ = environment
    kernel.fail_after_replace = True
    with pytest.raises(PFError, match="simulated interrupted write"):
        run_pass(environment)
    assert kernel.rules

    photos: list[Photo] = []
    # The pass that retires the partial write, by its plan or because the state
    # table cannot be read; then one that has nothing left to retire.
    for unreadable in (states, ""):
        kernel.flow_states = unreadable
        result, taken = photographed_pass(environment)
        assert result["phase"] == "failed"
        photos += taken
    assert kernel.rules == ""
    # Among them: a candidate journalled while a rule was still loaded.
    assert any("candidate_records" in photo.journal and photo.rules for photo in photos)

    for photo in photos:
        assert photo.journal["phase"] == "failed", photo.journal
        die_at(environment, photo)
        new_boot(environment)
        assert run_pass(environment)["phase"] == "failed", photo.journal
        assert kernel.rules == "" and issued(kernel, "drain", "replace") == []
        assert "candidate_records" not in root.read("journal.json")
    acknowledge(root)
    assert run_pass(environment)["phase"] == "committed"


@pytest.mark.parametrize(
    "case",
    [
        "earlier release",
        "unread before the boot",
        "malformed record",
        "same boot",
        "unread after the boot",
        "malformed answer",
        "foreign content",
    ],
)
def test_self_heal_needs_the_whole_proof(environment: Any, case: str) -> None:
    root, config, settings, _, snapshots = environment
    kernel = Answering(FIRST)
    environment = converged((root, config, settings, kernel, snapshots), heal=True, kernel=kernel)
    journal = root.read("journal.json")
    if case == "earlier release":
        del journal["boot_session"]
    elif case == "unread before the boot":
        kernel.answer = OSError("unavailable")
        assert run_pass(environment)["phase"] == "committed"
        journal = root.read("journal.json")
        assert "boot_session" not in journal
    elif case == "malformed record":
        journal["boot_session"] = FIRST.lower()
    root.write("journal.json", journal)
    new_boot(environment)
    kernel.answer = SECOND
    if case == "same boot":
        kernel.answer = FIRST
    elif case == "unread after the boot":
        kernel.answer = ProcessTimeout("deadline")
    elif case == "malformed answer":
        kernel.answer = SECOND.lower()
    elif case == "foreign content":
        kernel.rules = foreign_rule(config)
    before = stored(root)

    for _ in range(2):
        with pytest.raises(PFError, match="drifted"):
            run_pass(environment)

    assert stored(root) == before and len(records(root)) == 4
    assert issued(kernel, "drain", "replace", "reference") == []


def fresh_installation(environment: Any, directory: Path) -> Any:
    """The same protected inputs in a store that never recorded anything."""
    root, config, settings, kernel, snapshots = environment
    fresh = Store(directory)
    for name in ("installation.json", "policy.json", "admissions.json", "operator-intent.json"):
        fresh.write(name, root.read(name))
    empty = FakeBackend()
    empty.session = kernel.session
    return fresh, config, settings, empty, snapshots


@pytest.mark.parametrize(
    "inhibition,loaded",
    [
        ("none", ALL),
        ("paused", []),
        ("suspended", []),
        ("intent damaged", []),
        ("one profile not admitted", ["dns-tcp", "dns-udp", "proxy-standard"]),
        ("no profile admitted", []),
        ("runtime unknown", []),
        ("one guest absent", ["media-udp", "media-udp", "proxy-standard"]),
    ],
)
def test_self_heal_activates_only_what_a_pass_from_an_empty_installation_activates(
    environment: Any, tmp_path: Path, inhibition: str, loaded: list[str]
) -> None:
    environment = converged(environment, heal=True)
    root, _, _, kernel, snapshots = environment
    new_boot(environment)
    if inhibition == "paused":
        root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    elif inhibition == "suspended":
        root.write("operator-intent.json", intent_to_dict(Intent().suspend("upgrade", "holder")))
    elif inhibition == "intent damaged":
        root.write("operator-intent.json", {"schema_version": 999})
    elif inhibition == "one profile not admitted":
        admissions = root.read("admissions.json")
        del admissions["profiles"]["media-udp"]
        root.write("admissions.json", admissions)
    elif inhibition == "no profile admitted":
        root.write("admissions.json", {"schema_version": 1, "strategy": STRATEGY, "profiles": {}})
    elif inhibition == "runtime unknown":
        unknown_runtime(environment)
    elif inhibition == "one guest absent":
        services = dict(snapshots[-1].services)
        services["resolver"] = Observation("absent", "confirmed-absent", STAMP, None)
        snapshots.append(replace(snapshots[-1], services=services))
    fresh = fresh_installation(environment, tmp_path / "fresh")

    for _ in range(2):
        healed, expected = run_pass(environment), run_pass(fresh)
        assert healed == expected
        assert owned(kernel) == owned(fresh[3]) == loaded
        assert kernel.commands == fresh[3].commands
        assert root.read("journal.json") == fresh[0].read("journal.json")
        assert records(root) == records(fresh[0])
    assert issued(kernel, "drain") == []
    assert healed["phase"] == ("committed" if loaded == ALL else "inhibited")


def test_a_pause_set_before_the_boot_is_still_a_pause_after_it(environment: Any) -> None:
    environment = converged(environment, heal=True)
    root, _, _, kernel, _ = environment
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    new_boot(environment)

    for _ in range(2):
        result = run_pass(environment)
        assert result["phase"] == "inhibited" and sorted(result["pending"]) == PROFILES
        assert kernel.rules == ""
    assert issued(kernel, "drain", "replace", "reference") == []
    assert records(root) == {}
    root.write("operator-intent.json", intent_to_dict(Intent()))
    assert run_pass(environment)["phase"] == "committed"


# ------------------------------------------------------------------ the default


def test_the_default_keeps_the_administrator_in_charge_after_a_boot(environment: Any) -> None:
    environment = converged(environment)
    root, _, _, kernel, _ = environment
    remembered = records(root)
    new_boot(environment)
    kernel.flow_states = (
        f"all udp {CLIENT}:54321 -> {remembered['dns-udp']['target_ipv4']}:53 NO_TRAFFIC:SINGLE"
    )
    before = stored(root)

    for _ in range(3):
        with pytest.raises(PFError, match="drifted"):
            run_pass(environment)
    assert stored(root) == before and kernel.rules == ""
    assert root.read("journal.json")["boot_session"] == FIRST

    result = withdraw(root, lambda root, settings: kernel)

    assert result == {
        "schema_version": 1,
        "withdrawn": True,
        "guest_states_drained": False,
        "operator_paused": True,
        "reference_preserved": True,
        "cold_start": True,
    }
    assert issued(kernel, "drain", "replace") == [] and kernel.flow_states
    assert root.read("live.json") == {"schema_version": 1, "records": {}}
    assert root.read("journal.json") == {
        "schema_version": 1,
        "phase": "inhibited",
        "reason": "administrator-withdrawal",
        "boot_session": SECOND,
    }
    # Nothing was edited by hand: after the operator resumes, passes are ordinary.
    assert run_pass(environment)["phase"] == "inhibited"
    root.write("operator-intent.json", intent_to_dict(Intent()))
    assert run_pass(environment)["phase"] == "committed"
    assert owned(kernel) == ALL and issued(kernel, "drain") == []


def test_a_pause_pass_that_the_boot_cut_short_is_handled_at_every_point(environment: Any) -> None:
    """Default mode: an active record stays with the administrator, the rest is dropped."""
    environment = converged(environment)
    root, _, _, kernel, _ = environment
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))

    result, photos = photographed_pass(environment)

    assert result["phase"] == "inhibited" and owned(kernel) == []
    seen: set[str] = set()
    for photo in photos:
        die_at(environment, photo)
        new_boot(environment)
        before = stored(root)
        active = any(record["active"] for record in records(root).values())
        journal = photo.journal
        if active:
            with pytest.raises(PFError, match="drifted"):
                run_pass(environment)
            assert stored(root) == before
            seen.add("left to the administrator")
        elif "candidate_records" in journal:
            # No rule is remembered as loaded, but the pass did not finish.
            assert journal["phase"] == "applying"
            assert run_pass(environment)["phase"] == "failed"
            assert "candidate_records" not in root.read("journal.json")
            seen.add("owed as before")
        else:
            assert run_pass(environment)["phase"] == "inhibited"
            seen.add("nothing owed")
        assert kernel.rules == "" and issued(kernel, "drain", "replace") == []
        if not active:
            assert records(root) == {}
    assert seen == {"left to the administrator", "owed as before", "nothing owed"}


@pytest.mark.parametrize("heal", [False, True], ids=["default", "self-heal"])
def test_a_drain_left_over_from_the_previous_boot_is_dropped_in_either_mode(
    environment: Any, heal: bool
) -> None:
    resolver = str(environment[4][-1].services["resolver"].data["ipv4"])
    # The resolver guest keeps one connection of its own, and one client's state
    # of the DNS rule survives its invalidation.
    kernel = LiveKernel({resolver}, held={resolver: 53})
    environment = converged(environment, heal=heal, kernel=kernel)
    root = environment[0]
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    assert run_pass(environment)["deferred"] == {"dns-udp": "states-retained"}
    assert owned(kernel) == [] and list(records(root)) == ["dns-udp"]
    assert root.read("journal.json")["phase"] == "inhibited"
    # The pause is lifted, but the retired record is still waiting for its
    # state to go when the host restarts. Another guest then holds the
    # resolver's former address, with a connection too.
    root.write("operator-intent.json", intent_to_dict(Intent()))
    new_boot(environment)
    kernel.held = {}
    kernel.kills.clear()

    result = run_pass(environment)

    assert result["phase"] == "committed" and len(result["changed"]) == 4
    assert owned(kernel) == ALL
    assert kernel.kills == [] and issued(kernel, "drain") == []


@pytest.mark.parametrize("heal", [False, True], ids=["default", "self-heal"])
def test_a_failed_drain_of_the_previous_boot_is_not_repeated_but_stays_owed(
    environment: Any, heal: bool
) -> None:
    resolver = str(environment[4][-1].services["resolver"].data["ipv4"])
    kernel = LiveKernel({resolver}, held={resolver: 53})
    environment = converged(environment, heal=heal, kernel=kernel)
    root = environment[0]
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    # An open drain is not a failure. The acknowledgement is owed for a write in
    # doubt, and the drain that a client's state keeps open is left over as well.
    kernel.fail_after_replace = True
    with pytest.raises(PFError, match="interrupted write"):
        run_pass(environment)
    result = run_pass(environment)
    assert result["phase"] == "failed" and result["deferred"] == {"dns-udp": "states-retained"}
    root.write("operator-intent.json", intent_to_dict(Intent()))
    new_boot(environment)
    kernel.held = {}
    kernel.kills.clear()

    result, photos = photographed_pass(environment)

    assert result["phase"] == "failed"
    assert photos[1].files["live.json"]["records"] == {}
    assert photos[2].journal == {
        "schema_version": 1,
        "phase": "failed",
        "reason": "cold-start",
        "boot_session": SECOND,
    }
    # Wherever that pass stops, the next one neither invalidates nor forgets.
    for photo in photos:
        die_at(environment, photo)
        for _ in range(2):
            assert run_pass(environment)["phase"] == "failed", photo.journal
        assert kernel.kills == [] and owned(kernel) == [] and records(root) == {}
        assert "candidate_records" not in root.read("journal.json")
    acknowledge(root)
    assert run_pass(environment)["phase"] == "committed"


def test_a_candidate_of_another_boot_is_not_adopted_in_the_default_mode(environment: Any) -> None:
    """An active record with an all-retired candidate: neither is acted on after a boot."""
    environment = converged(environment)
    root, _, _, kernel, _ = environment
    remembered = records(root)
    retired = {key: {**value, "active": False, "rules": ""} for key, value in remembered.items()}
    journal = {
        "schema_version": 1,
        "phase": "applying",
        "actions": [],
        "candidate_records": retired,
        "started_at": STAMP,
        "boot_session": FIRST,
    }
    root.write("journal.json", journal)

    # Within one boot the candidate is what the kernel may hold, as before.
    kernel.rules = ""
    kernel.flow_states = client_states(remembered)
    assert run_pass(environment)["phase"] == "failed"
    assert sorted(command[1] for command in issued(kernel, "drain")) == guest_addresses(remembered)

    root.write("live.json", {"schema_version": 1, "records": remembered})
    root.write("journal.json", journal)
    new_boot(environment)
    before = stored(root)
    with pytest.raises(PFError, match="drifted"):
        run_pass(environment)
    assert stored(root) == before and issued(kernel, "drain") == []
    assert withdraw(root, lambda root, settings: kernel)["cold_start"] is True
    assert issued(kernel, "drain") == [] and records(root) == {}


# ------------------------------------------------------------------ the first record of a pass


def test_the_first_record_of_a_pass_is_exempt_with_its_boot_session(environment: Any) -> None:
    environment = converged(environment)
    root, _, _, kernel, _ = environment
    loaded = kernel.rules

    result, photos = photographed_pass(environment)

    first = next(photo for photo in photos if photo.unfinished_without_candidate)
    assert sorted(first.journal) == [
        "actions",
        "boot_session",
        "phase",
        "schema_version",
        "started_at",
    ]
    assert first.journal["boot_session"] == FIRST
    die_at(environment, first)
    mark = len(kernel.commands)
    assert run_pass(environment) == result
    assert kernel.rules == loaded and ("replace",) not in kernel.commands[mark:]

    for malformed in (FIRST.lower(), FIRST + "\n", "", None, 1, [FIRST]):
        root.write("journal.json", {**first.journal, "boot_session": malformed})
        assert run_pass(environment)["phase"] == "failed", malformed
        assert kernel.rules == ""
        acknowledge(root)
        assert run_pass(environment)["phase"] == "committed"
        assert kernel.rules


# ------------------------------------------------------------------ withdrawal on an empty anchor


def test_withdrawal_succeeds_on_an_anchor_that_was_emptied_in_the_same_boot(
    environment: Any,
) -> None:
    environment = converged(environment)
    root, _, _, kernel, _ = environment
    remembered = records(root)
    kernel.flow_states = client_states(remembered)
    kernel.rules = ""  # somebody flushed the anchor; states of the old rules can remain
    kernel.commands.clear()
    with pytest.raises(PFError, match="drifted"):
        run_pass(environment)

    result = withdraw(root, lambda root, settings: kernel)

    assert result["withdrawn"] and result["guest_states_drained"] is True
    assert "cold_start" not in result
    assert issued(kernel, "replace") == []
    # Same boot: every remembered guest address that still has a state of its
    # rule is invalidated, the host's is not.
    assert sorted(command[1] for command in issued(kernel, "drain")) == guest_addresses(remembered)
    assert kernel.flow_states == "" and records(root) == {}
    assert root.read("journal.json") == {
        "schema_version": 1,
        "phase": "inhibited",
        "reason": "administrator-withdrawal",
        "boot_session": FIRST,
    }


def test_withdrawal_in_the_same_boot_still_fails_while_a_state_remains(environment: Any) -> None:
    environment = converged(environment)
    root, _, _, kernel, _ = environment
    kernel.rules = ""
    kernel.flow_states = client_states(records(root))
    kernel.undrainable = True

    with pytest.raises(PFError, match="remaining states"):
        withdraw(root, lambda root, settings: kernel)

    journal = root.read("journal.json")
    assert journal["phase"] == "failed" and journal["boot_session"] == FIRST
    assert all(not record["active"] for record in records(root).values())
    kernel.undrainable = False
    assert withdraw(root, lambda root, settings: kernel)["guest_states_drained"] is True
    assert records(root) == {}


def test_withdrawal_never_adopts_or_empties_a_populated_anchor(environment: Any) -> None:
    environment = converged(environment)
    root, config, _, kernel, _ = environment
    foreign = foreign_rule(config)
    for session in (FIRST, SECOND):
        kernel.session = session
        kernel.rules = foreign
        kernel.commands.clear()
        with pytest.raises(PFError, match="cannot independently identify"):
            withdraw(root, lambda root, settings: kernel)
        assert kernel.rules == foreign and len(records(root)) == 4
        assert issued(kernel, "drain", "replace") == []


@pytest.mark.parametrize("heal", [False, True], ids=["default", "self-heal"])
def test_a_loaded_anchor_is_never_a_cold_start_whatever_the_journal_says(
    environment: Any, heal: bool
) -> None:
    """For example a protected directory that was restored from another boot's copy."""
    environment = converged(environment, heal=heal)
    root, _, _, kernel, _ = environment
    remembered = records(root)
    journal = root.read("journal.json")
    root.write("journal.json", {**journal, "boot_session": SECOND})
    kernel.commands.clear()

    assert run_pass(environment) == {
        "schema_version": 1,
        "phase": "committed",
        "changed": [],
        "pending": [],
    }
    assert owned(kernel) == ALL and records(root) == remembered
    assert root.read("journal.json")["boot_session"] == FIRST

    root.write("journal.json", {**journal, "boot_session": SECOND})
    kernel.flow_states = client_states(remembered)
    result = withdraw(root, lambda root, settings: kernel)

    assert result["guest_states_drained"] is True and "cold_start" not in result
    assert len(issued(kernel, "replace")) == 1
    assert sorted(command[1] for command in issued(kernel, "drain")) == guest_addresses(remembered)
    assert kernel.rules == "" and records(root) == {}


def test_a_withdrawal_after_a_boot_that_fails_half_way_is_still_proven_when_repeated(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = converged(environment)
    root, _, _, kernel, _ = environment
    remembered = records(root)
    new_boot(environment)
    write = root.write

    def failing(name: str, value: Any) -> None:
        if name == "live.json":
            raise OSError("no space left on device")
        write(name, value)

    monkeypatch.setattr(root, "write", failing)
    with pytest.raises(OSError, match="no space"):
        withdraw(root, lambda root, settings: kernel)
    monkeypatch.undo()

    journal = root.read("journal.json")
    assert journal["phase"] == "failed" and journal["reason"] == "administrator-withdrawal"
    # The record that proved the cold start is gone; this one keeps its boot.
    assert journal["boot_session"] == FIRST
    assert records(root) == remembered
    # A scheduled pass in between leaves it to the administrator and writes nothing.
    before = stored(root)
    with pytest.raises(PFError, match="drifted"):
        run_pass(environment)
    assert stored(root) == before

    result = withdraw(root, lambda root, settings: kernel)

    assert result["cold_start"] is True and result["guest_states_drained"] is False
    assert issued(kernel, "drain", "replace") == [] and records(root) == {}
    assert root.read("journal.json")["boot_session"] == SECOND


def test_withdrawal_without_proof_of_a_boot_invalidates_as_before(environment: Any) -> None:
    """An earlier release left no boot session: the empty anchor is accepted, not the boot."""
    environment = converged(environment)
    root, _, _, kernel, _ = environment
    remembered = records(root)
    journal = root.read("journal.json")
    del journal["boot_session"]
    root.write("journal.json", journal)
    new_boot(environment)
    # Without proof of a boot a state of a remembered rule is invalidated as in one boot.
    kernel.flow_states = client_states(remembered)

    result = withdraw(root, lambda root, settings: kernel)

    assert result["guest_states_drained"] is True and "cold_start" not in result
    assert sorted(command[1] for command in issued(kernel, "drain")) == guest_addresses(remembered)
    assert issued(kernel, "replace") == [] and records(root) == {}


def test_withdrawal_still_prefers_a_matching_candidate_of_the_journal(environment: Any) -> None:
    """Unchanged: when the journal's candidate explains the anchor, it is what is retired."""
    environment = converged(environment)
    root, _, _, kernel, _ = environment
    remembered = records(root)
    kept = {"dns-udp": {**remembered["dns-udp"], "active": False, "rules": ""}}
    root.write(
        "journal.json",
        {"schema_version": 1, "phase": "applying", "candidate_records": kept, "started_at": STAMP},
    )
    kernel.rules = ""
    kernel.flow_states = client_states(remembered, "dns-udp")
    kernel.commands.clear()

    assert withdraw(root, lambda root, settings: kernel)["guest_states_drained"] is True

    assert issued(kernel, "drain") == [("drain", remembered["dns-udp"]["target_ipv4"])]


def test_a_candidate_that_was_never_loaded_does_not_stop_a_withdrawal_on_an_empty_anchor(
    environment: Any,
) -> None:
    environment = converged(environment)
    root, config, _, kernel, _ = environment
    remembered = records(root)
    # The journal's candidate still has a rule; the anchor has none.
    root.write(
        "journal.json",
        {
            "schema_version": 1,
            "phase": "applying",
            "candidate_records": {"dns-udp": remembered["dns-udp"]},
            "started_at": STAMP,
            "boot_session": FIRST,
        },
    )
    kernel.rules = foreign_rule(config)
    with pytest.raises(PFError, match="foreign PF drift prevents quiescence"):
        withdraw(root, lambda root, settings: kernel)
    assert kernel.rules == foreign_rule(config) and records(root) == remembered

    kernel.rules = ""
    kernel.flow_states = client_states(remembered)
    kernel.commands.clear()
    result = withdraw(root, lambda root, settings: kernel)

    assert result["guest_states_drained"] is True and "cold_start" not in result
    assert issued(kernel, "replace") == []
    assert sorted(command[1] for command in issued(kernel, "drain")) == guest_addresses(remembered)
    assert records(root) == {}


@pytest.mark.parametrize("damage", [b"{not json", b"[]", None], ids=["text", "list", "missing"])
def test_an_unreadable_journal_does_not_stop_a_withdrawal_that_matches_its_records(
    environment: Any, damage: bytes | None
) -> None:
    environment = converged(environment)
    root, _, _, kernel, _ = environment
    if damage is None:
        (root.directory / "journal.json").unlink()
    else:
        (root.directory / "journal.json").write_bytes(damage)

    result = withdraw(root, lambda root, settings: kernel)

    assert result["guest_states_drained"] is True and "cold_start" not in result
    assert kernel.rules == "" and records(root) == {}
    assert root.read("journal.json")["boot_session"] == FIRST
    # Nor does it prove a reboot once the anchor is empty.
    kernel.session = SECOND
    if damage is None:
        (root.directory / "journal.json").unlink()
    else:
        (root.directory / "journal.json").write_bytes(damage)
    assert "cold_start" not in withdraw(root, lambda root, settings: kernel)


# ------------------------------------------------------------------ hosted macOS userspace


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
def test_darwin_sysctl_prints_the_boot_session_as_one_upper_case_uuid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Evidence for the runner image it ran on, nothing more: two unprivileged reads."""
    backend = object.__new__(ShellBackend)
    answers = []
    for _ in range(2):
        read = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert read.returncode == 0
        assert read.stderr == b""
        answer = read.stdout.decode("utf-8")
        assert answer.endswith("\n") and answer.count("\n") == 1
        monkeypatch.setattr(backend, "_native", lambda argv, answer=answer: answer)
        assert backend.boot_session() == answer[:-1]
        answers.append(answer)
    assert answers[0] == answers[1]

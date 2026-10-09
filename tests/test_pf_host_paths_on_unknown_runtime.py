"""Rules that end at the host's own address survive a pass without runtime evidence.

That is a decision of the installation, `runtime_unknown: "keep-host-paths"`.
Without it nothing below changes: the first pass whose runtime evidence is
unknown retires every rule. With it a pass that only lacks the evidence for a
service, because its read ran out of time or because evidence that verifies the
rule is merely too old, keeps and withholds a loaded host redirect and a loaded
fallback form while the owner's enable reference is held and root's own socket
inventory lists a listener behind them. It judges that before it acts. It never
activates anything, it never takes the enable reference while it keeps a rule,
and every rule that names a guest is retired as before. So is a host path
whenever the pass learned something definite about its service, or an authority
that it rests on is gone.

Every kernel and runtime tool is a fake. Addresses are documentation values and
the names of processes are invented.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

import netorch.pf_owner as owner
import netorch.planner as planner
from netorch.codec import canonical_bytes, strict_loads
from netorch.config import backing_publication, profile_digest, to_dict, validate_config
from netorch.model import Config, PortRange, Profile, Safety, Scope
from netorch.pf_owner import (
    Installation,
    PFError,
    admit,
    admitted_digest,
    install,
    render_profile,
)
from netorch.planner import Action
from netorch.state import (
    OBSERVATION_REASONS,
    Intent,
    Observation,
    Snapshot,
    intent_to_dict,
    snapshot_to_dict,
)
from tests.test_pf_cold_start import FIRST, reboot
from tests.test_pf_deferral import observed_pass
from tests.test_pf_own_states import Kernel
from tests.test_pf_owner import (
    HEADER,
    ROOT,
    STAMP,
    approve_all,
    environment,
    shell_backend,
    socket_fixture,
)
from tests.test_pf_translation_order import (
    BASE_BYTES,
    BASE_DIGEST,
    FOREIGN_TRANSLATION,
    PLAIN,
    SIBLING,
    Ordered,
    assert_withheld,
)
from tests.test_pf_withdraw_order import address, owned

__all__ = ["environment"]

KEY = "keep-host-paths"
REASON = "runtime-unknown"
HOST = "192.0.2.10"
# The four kinds of rule a site can have loaded at once.
WEB = "proxy-standard"  # a host redirect: the web port to the host's own published socket
NAMES = "dns-udp"  # the name-service path in its fallback form, recorded as a host redirect
DIRECT = "dns-tcp"  # a guest-direct rule
PAIR = "media-udp"  # the UDP return pair
NATIVE = "dns-native-udp"  # the native publication behind the fallback form
BACKING = "proxy-high"  # the native publication behind the host redirect
PUBLICATION = {WEB: BACKING, NAMES: NATIVE}
SERVICE = {WEB: "web-proxy", NAMES: "resolver"}
HOST_PATHS = {NAMES: REASON, WEB: REASON}
GUEST_PATHS = [DIRECT, PAIR]
EVERY_PROFILE = (DIRECT, NAMES, PAIR, WEB)
Row = tuple[str, int, int, str, str]
# The interface of the fixture's scope and that of a second scope, put together
# here: no interface name stands in this file.
INTERFACE, SECOND_INTERFACE = (f"en{number}" for number in (0, 1))
# What the plan of a pass has for a rule it retires, and what the owner did of it.
RETIRED = [f"{DIRECT}:withdraw", f"{PAIR}:withdraw", f"{DIRECT}:drain", f"{PAIR}:drain"]


class Inventory:
    """Root's socket inventory for a fake kernel: one listener behind each host path."""

    def __init__(self, *arguments: Any, **options: Any) -> None:
        super().__init__(*arguments, **options)
        # As a forwarder of published ports holds them: on the host's own address.
        self.sockets: dict[str, list[Row]] = {
            "tcp": [(HOST, 8080, 501, "forwarder", "IPv4")],
            "udp": [(HOST, 1053, 501, "forwarder", "IPv4")],
        }
        self.unreadable: dict[str, Exception] = {}

    def socket_inventory(self, protocol: str) -> tuple[Row, ...]:
        self.commands.append(("inventory", protocol))  # type: ignore[attr-defined]
        if protocol in self.unreadable:
            raise self.unreadable[protocol]
        return tuple(self.sockets[protocol])


class Sockets(Inventory, Kernel):
    """The in-memory kernel of the owner tests with a socket inventory."""


def site(
    environment: Any,
    backend: Any,
    *,
    decision: bool = True,
    ages: dict[str, int] | None = None,
) -> Any:
    """The fixture's site with a fallback for the name-service path, every profile admitted."""
    root, config, settings, _, snapshots = environment
    profiles = list(config.profiles)
    # Keep a genuinely independent direct path: the fallback setup below makes
    # the resolver address unverifiable. A direct rule to that same address
    # cannot truthfully remain ready alongside its fallback after loaded
    # endpoint checks were added. The existing camera guest keeps this path
    # independent of tests that stop the media guest or the web proxy and is
    # already enrolled in the bundled observer's matching synthetic fixture.
    direct_index = next(index for index, profile in enumerate(profiles) if profile.id == DIRECT)
    profiles[direct_index] = replace(profiles[direct_index], service="camera")
    index = next(index for index, profile in enumerate(profiles) if profile.id == NAMES)
    profiles[index] = replace(profiles[index], fallback_publication=NATIVE)
    profiles.append(
        Profile(
            NATIVE,
            profiles[index].service,
            profiles[index].scope,
            "publication",
            "udp",
            PortRange(1053, 1053),
            PortRange(53, 53),
            Safety("structural", 30, 1),
            "camera-manager",
        )
    )
    for key, seconds in (ages or {}).items():
        index = next(index for index, profile in enumerate(profiles) if profile.id == key)
        profiles[index] = replace(
            profiles[index], safety=replace(profiles[index].safety, max_age_seconds=seconds)
        )
    config = replace(config, profiles=tuple(profiles))
    validate_config(config)
    root.write("policy.json", to_dict(config))
    current = snapshots[-1]
    observed = {
        key: replace(item, data={**item.data, "policy_digest": profile_digest(config, profile)})
        for key, item in current.profiles.items()
        if (profile := config.profile(key))
    }
    observed[NATIVE] = replace(
        observed[BACKING],
        data={
            **observed[BACKING].data,
            "target_ipv4": current.services["resolver"].data["ipv4"],
            "policy_digest": profile_digest(config, config.profile(NATIVE)),
        },
    )
    snapshots.append(replace(current, profiles=observed))
    if decision:
        settings = replace(settings, runtime_unknown=KEY)
        root.write("installation.json", settings.to_dict())
    environment = (root, config, settings, backend, snapshots)
    approve_all(environment)
    return environment


def decided(environment: Any, **decisions: str) -> Any:
    """The same site with further decisions of the installation, every profile admitted again."""
    root, config, settings, backend, snapshots = environment
    settings = replace(settings, **decisions)
    root.write("installation.json", settings.to_dict())
    environment = (root, config, settings, backend, snapshots)
    approve_all(environment)
    return environment


def loaded(environment: Any, *more: str) -> Any:
    """Three verified passes: a host redirect, a fallback form, a guest-direct rule and the pair.

    And each further host redirect that the site was given.
    """
    root, _, _, backend, _ = environment
    assert observed_pass(environment)[0]["phase"] == "committed"
    # The direct path to the resolver stops being verifiable: the name-service
    # path is retired and, by the next verified pass, loaded in its fallback form.
    backend.unavailable_guests = {address(environment, "resolver")}
    assert observed_pass(environment)[0]["changed"] == [f"{NAMES}:withdraw", f"{NAMES}:drain"]
    result, report = observed_pass(environment)
    assert (result["phase"], result["changed"]) == ("committed", [f"{NAMES}:activate"])
    records = root.read("live.json")["records"]
    assert {key: (item["kind"], item["effective_strategy"]) for key, item in records.items()} == {
        WEB: ("host-redirect", None),
        NAMES: ("host-redirect", "degraded-fallback"),
        DIRECT: ("guest-direct", None),
        PAIR: ("udp-return", None),
        **dict.fromkeys(more, ("host-redirect", None)),
    }
    assert ready(report) == sorted((*EVERY_PROFILE, *more))
    backend.commands.clear()
    return environment


def ready(report: Snapshot) -> list[str]:
    return sorted(key for key, item in report.profiles.items() if item.data["root_ready"] is True)


def unknown(snapshot: Snapshot, *services: str, reason: str = "timed-out") -> Snapshot:
    """The snapshot with these services unknown (every one by default), and their publications."""
    names = services or tuple(snapshot.services)
    return replace(
        snapshot,
        services={
            key: Observation("unknown", reason, snapshot.observed_at, None)
            if key in names
            else item
            for key, item in snapshot.services.items()
        },
        profiles={
            key: Observation("unknown", reason, snapshot.observed_at, None, {"states": ()})
            if {NATIVE: "resolver", BACKING: "web-proxy"}.get(key) in names
            else item
            for key, item in snapshot.profiles.items()
        },
    )


def unread(snapshot: Snapshot) -> Snapshot:
    """What an observer returns when a read of the whole runtime fails: no generation at all."""
    return replace(unknown(snapshot), network_generation=None)


def without_evidence(environment: Any, *services: str) -> tuple[dict[str, Any], Snapshot]:
    """One more pass, in which the runtime evidence for these services is unknown."""
    snapshots = environment[4]
    snapshots.append(unknown(snapshots[-1], *services))
    return observed_pass(environment)


def planned(environment: Any, key: str) -> list[tuple[str, str]]:
    """What the last pass had planned for one profile: (operation, reason) in order."""
    actions = environment[0].read("journal.json")["actions"]
    return [(item["operation"], item["reason"]) for item in actions if item["profile"] == key]


def inventory_reads(backend: Any) -> list[str]:
    return [command[1] for command in backend.commands if command[0] == "inventory"]


def written(backend: Any) -> list[tuple[str, ...]]:
    return [command for command in backend.commands if command[0] in {"replace", "drain"}]


# ---- the gap, on an installation without the decision


def test_without_the_decision_one_pass_without_evidence_retires_every_rule(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend, decision=False))

    result, report = without_evidence(environment)

    # The web port and name resolution are gone with the guest rules, although
    # the listeners behind them are still there.
    assert result == {
        "schema_version": 1,
        "phase": "inhibited",
        "changed": [
            *(f"{key}:withdraw" for key in EVERY_PROFILE),
            *(f"{key}:drain" for key in EVERY_PROFILE),
        ],
        "pending": list(EVERY_PROFILE),
    }
    assert backend.rules == "" and environment[0].read("live.json")["records"] == {}
    assert ready(report) == [] and inventory_reads(backend) == []
    assert all(
        planned(environment, key)[0] == ("withdraw", "endpoint-unknown") for key in HOST_PATHS
    )


# SHA-256 over everything three passes of an installation without the decision
# hand back, publish, store and ask of the kernel (a verified pass, a pass
# without evidence, a verified pass again), computed with this test body on the
# current fixture with independently reachable direct and fallback guests and
# fresh checks of loaded endpoints.
BASE_PASSES = "0a900a6dcfefae46b33fd8373ee23695c7edb2eac0ca3f5850664cc0c4943fb9"


def test_without_the_keep_decision_no_host_path_inventory_reads_and_stored_setting_unchanged(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The two inputs of an admission that differ from tree to tree by design are
    # pinned: the implementation fingerprint and the digest of the backend script.
    monkeypatch.setattr(owner, "implementation_digest", lambda: "f" * 64)
    root, config, settings, _, snapshots = environment
    settings = replace(settings, backend_sha256="0" * 64)
    root.write("installation.json", settings.to_dict())
    backend = Sockets()
    environment = loaded(
        site((root, config, settings, backend, snapshots), backend, decision=False)
    )
    stored = (root.directory / "installation.json").read_bytes()
    assert b"runtime_unknown" not in stored
    seen: list[Any] = []

    def note(result: dict[str, Any], report: Snapshot) -> None:
        seen.append(
            [
                result,
                snapshot_to_dict(report),
                root.read("journal.json"),
                root.read("live.json"),
                root.read("admissions.json"),
                backend.commands,
                backend.rules,
            ]
        )

    note(*observed_pass(environment))
    note(*without_evidence(environment))
    environment[4].append(environment[4][-2])
    note(*observed_pass(environment))

    assert inventory_reads(backend) == []
    assert (root.directory / "installation.json").read_bytes() == stored
    assert hashlib.sha256(canonical_bytes(strict_loads(canonical_bytes(seen)))).hexdigest() == (
        BASE_PASSES
    )


# ---- the decision in the installation


def test_an_installation_without_the_decision_keeps_its_stored_form(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = environment[1]
    profile = config.profile("dns-udp")
    monkeypatch.setattr(owner, "implementation_digest", lambda: "f" * 64)
    monkeypatch.setattr(owner, "profile_digest", lambda config, profile: "e" * 64)
    plain = Installation(*PLAIN)

    assert plain.runtime_unknown == "retire"
    assert len(plain.to_dict()) == 9 and "runtime_unknown" not in plain.to_dict()
    # Literals of the tree this change is based on.
    assert canonical_bytes(plain.to_dict()) == BASE_BYTES
    assert Installation.from_dict(strict_loads(BASE_BYTES)) == plain
    assert admitted_digest(config, profile, plain) == BASE_DIGEST

    decided = replace(plain, runtime_unknown=KEY)
    assert decided.to_dict() == {**plain.to_dict(), "runtime_unknown": KEY}
    assert Installation.from_dict(strict_loads(canonical_bytes(decided.to_dict()))) == decided
    assert admitted_digest(config, profile, decided) != BASE_DIGEST
    # Beside the three earlier decisions: each is stored and bound by itself.
    earlier = replace(
        plain, enable_reference="reacquire", cold_start="self-heal", translation_order="verified"
    )
    every = replace(earlier, runtime_unknown=KEY)
    assert Installation.from_dict(strict_loads(canonical_bytes(every.to_dict()))) == every
    assert every.to_dict() == {**earlier.to_dict(), "runtime_unknown": KEY}
    digests = {admitted_digest(config, profile, item) for item in (plain, decided, earlier, every)}
    assert len(digests) == 4


@pytest.mark.parametrize(
    "value",
    ["retire", None, "keep", "Keep-host-paths", "keep-host-paths ", "", True, 1, [KEY], {}],
)
def test_keep_host_paths_is_the_only_decision_that_can_be_written(
    environment: Any, value: Any
) -> None:
    raw = environment[2].to_dict()
    with pytest.raises(PFError, match="unsupported installation schema"):
        Installation.from_dict({**raw, "runtime_unknown": value})
    with pytest.raises(PFError, match="unsupported installation schema"):
        Installation.from_dict({**raw, "runtime_unknown": KEY, "runtime": KEY})
    if value != "retire":
        with pytest.raises(PFError, match="runtime-unknown"):
            Installation(*PLAIN, runtime_unknown=value)


def test_an_admission_shows_the_decision_it_covers(environment: Any) -> None:
    root, _, settings, _, _ = environment
    shown = admit(root, WEB, acknowledge_bounded_risk=True)["resolved"]
    # Without the decision the admission prints what it printed before.
    assert "runtime_unknown" not in shown
    root.write("installation.json", replace(settings, runtime_unknown=KEY).to_dict())
    decided = admit(root, WEB, acknowledge_bounded_risk=True)["resolved"]
    assert decided == {**shown, "runtime_unknown": KEY}


def as_administrator(monkeypatch: pytest.MonkeyPatch, root: Any) -> None:
    """Replace the entry point's boundary as the existing tests of its commands do."""
    import netorch.storage as storage

    monkeypatch.setattr(owner, "require_mutation_qualified", lambda _capability: None)
    monkeypatch.setattr(owner.sys, "platform", "darwin")
    monkeypatch.setattr(owner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(owner, "Store", lambda directory: root)
    monkeypatch.setattr(owner, "protected_ancestors", lambda *a, **kw: None)
    monkeypatch.setattr(owner, "protected_code", lambda *a, **kw: None)
    monkeypatch.setattr(storage.Store, "_check_directory_info", staticmethod(lambda info: None))
    monkeypatch.setattr(storage, "_check_file", lambda fd: None)


def test_the_review_shows_the_decision_only_where_it_was_made(
    environment: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root, _, settings, _, _ = environment
    as_administrator(monkeypatch, root)
    command = ["review-admission", "--root-dir", str(root.directory), "--profile", WEB]

    assert owner.main(command) == 0
    plain = strict_loads(capsys.readouterr().out)
    root.write("installation.json", replace(settings, runtime_unknown=KEY).to_dict())
    assert owner.main(command) == 0
    decided = strict_loads(capsys.readouterr().out)

    # Without the decision the review prints the members it printed before.
    assert "runtime_unknown" not in plain
    assert decided["expected_digest"] != plain["expected_digest"]
    assert {**decided, "expected_digest": plain["expected_digest"]} == {
        **plain,
        "runtime_unknown": KEY,
    }


# ---- with the decision: what a pass without runtime evidence keeps


def test_with_the_decision_exactly_the_host_paths_are_kept_and_withheld(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root = environment[0]
    before = root.read("live.json")["records"]
    rules = backend.rules.splitlines()

    result, report = without_evidence(environment)

    # The guest rules are retired as they always were, in the order they always
    # were. Nothing is written for the two host paths.
    assert result == {
        "schema_version": 1,
        "phase": "inhibited",
        "changed": RETIRED,
        "pending": GUEST_PATHS,
        "withheld": HOST_PATHS,
    }
    assert_withheld(environment, result, report, HOST_PATHS)
    assert root.read("live.json")["records"] == {key: before[key] for key in HOST_PATHS}
    assert backend.rules.splitlines() == [
        line for line in rules if line.endswith((f"# netorch:{NAMES}", f"# netorch:{WEB}"))
    ]
    assert ready(report) == []
    for key in GUEST_PATHS:
        assert (
            report.profiles[key].state == "absent" and "withheld" not in report.profiles[key].data
        )
    # The plan itself is unchanged, in its reasons and in its order: it would
    # retire them where it retires every rule, and for the same reason.
    for key in HOST_PATHS:
        assert planned(environment, key) == [
            ("withdraw", "endpoint-unknown"),
            ("drain", "endpoint-unknown"),
            ("blocked", "endpoint-unknown"),
        ]
    journal = root.read("journal.json")
    assert set(journal) == {"schema_version", "phase", "actions", "finished_at", "withheld"}


def test_status_shows_the_decision_and_what_the_last_pass_withheld(
    environment: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root = environment[0]
    without_evidence(environment)
    as_administrator(monkeypatch, root)

    assert owner.main(["status", "--root-dir", str(root.directory)]) == 0
    shown = strict_loads(capsys.readouterr().out)

    assert shown["installation"]["runtime_unknown"] == KEY
    assert shown["journal"]["withheld"] == HOST_PATHS and shown["journal"]["phase"] == "inhibited"


def test_the_judgement_is_made_again_on_every_pass_and_nothing_is_written(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root = environment[0]
    first, _ = without_evidence(environment)
    live = (root.directory / "live.json").read_bytes()
    rules = backend.rules
    backend.commands.clear()

    for _ in range(3):
        result, report = observed_pass(environment)
        assert result == {
            "schema_version": 1,
            "phase": "inhibited",
            "changed": [],
            "pending": GUEST_PATHS,
            "withheld": HOST_PATHS,
        }
        assert_withheld(environment, result, report, HOST_PATHS)
        assert (root.directory / "live.json").read_bytes() == live and backend.rules == rules
    # One inventory of each protocol per pass, and no write in any of them.
    assert inventory_reads(backend) == ["udp", "tcp"] * 3 and written(backend) == []
    assert first["changed"] == RETIRED


def test_evidence_that_returns_ends_the_withholding_without_a_write(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root, _, _, _, snapshots = environment
    verified = snapshots[-1]
    without_evidence(environment)
    live = root.read("live.json")["records"]
    backend.commands.clear()

    snapshots.append(verified)
    result, report = observed_pass(environment)

    # The two host paths are ready again from the rules they kept. What was
    # retired is activated again, which is the only thing this pass writes.
    assert "withheld" not in result and "withheld" not in root.read("journal.json")
    assert all("withheld" not in item.data for item in report.profiles.values())
    assert sorted(set(HOST_PATHS) & set(ready(report))) == sorted(HOST_PATHS)
    assert not any(change.startswith((NAMES, WEB)) for change in result["changed"])
    assert {key: root.read("live.json")["records"][key] for key in HOST_PATHS} == live
    assert inventory_reads(backend) == []


def test_evidence_that_returns_within_the_pass_leaves_a_kept_rule_withheld(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    verified = environment[4][-1]
    # The pass plans without evidence; its final observation has all of it again.
    observations = [unknown(verified), verified]

    result, report = observed_pass(environment, lambda config, settings: observations.pop(0))

    # A rule is judged before the first action, on the evidence the pass was
    # planned from. The final plan verifies both rules, and it is the next pass
    # that reports them ready.
    assert observations == [] and result == {
        "schema_version": 1,
        "phase": "inhibited",
        "changed": RETIRED,
        "pending": [],
        "withheld": HOST_PATHS,
    }
    assert_withheld(environment, result, report, HOST_PATHS)
    assert ready(report) == []
    result, report = observed_pass(environment, lambda config, settings: verified)
    assert "withheld" not in result and set(HOST_PATHS) <= set(ready(report))


def every_source(environment: Any) -> Any:
    """The same site with the web redirect declared for every source, and admitted as that."""
    root, config, settings, backend, snapshots = environment
    config = replace(
        config,
        profiles=tuple(
            replace(profile, source_scope="any") if profile.id == WEB else profile
            for profile in config.profiles
        ),
    )
    validate_config(config)
    root.write("policy.json", to_dict(config))
    admit(root, WEB, acknowledge_bounded_risk=False, acknowledge_any_source=True, now=STAMP - 1)
    return root, config, settings, backend, snapshots


def test_a_host_redirect_that_matches_every_source_is_kept_like_the_others(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = loaded(every_source(site(environment, backend)))
    root = environment[0]
    rule = root.read("live.json")["records"][WEB]["rules"]
    assert f" from any to {HOST} port 80 -> {HOST} port 8080 " in rule

    result, report = without_evidence(environment)

    # The five conditions do not look at the source a rule matches: this one
    # is kept as well, for traffic from every source.
    assert_withheld(environment, result, report, HOST_PATHS)
    assert rule in backend.rules


def test_one_service_without_evidence_concerns_the_profiles_of_that_service_only(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))

    result, report = without_evidence(environment, "web-proxy")

    assert (result["changed"], result["pending"]) == ([], [])
    assert_withheld(environment, result, report, {WEB: REASON})
    assert ready(report) == [DIRECT, NAMES, PAIR]
    assert inventory_reads(backend) == ["tcp"]


# ---- condition 1: the record and its rules end at the host's own address


def rewritten(environment: Any, key: str, **changes: Any) -> None:
    """Change one stored record by hand, and the kernel's rules with it where they differ."""
    root, _, _, backend, _ = environment
    records = root.read("live.json")["records"]
    if "rules" in changes:
        backend.rules = backend.rules.replace(records[key]["rules"], changes["rules"])
    records[key] = {**records[key], **changes}
    root.write("live.json", {"schema_version": 1, "records": records})


GUEST_RULE = (
    f"rdr on {INTERFACE} inet proto tcp from 192.0.2.0/24 to 192.0.2.10 port 80 "
    f"-> 198.51.100.11 port 8080 # netorch:{WEB}\n"
)
NOT_A_HOST_PATH: dict[str, tuple[str, dict[str, Any]]] = {
    "another kind": (WEB, {"kind": "guest-direct"}),
    "a guest as the recorded target": (WEB, {"target_ipv4": "198.51.100.11"}),
    "rendered from another policy": (WEB, {"policy_digest": "a" * 64}),
    "a rule that names a guest": (WEB, {"rules": GUEST_RULE}),
    "another source than the policy's": (
        WEB,
        {"rules": GUEST_RULE.replace("198.51.100.11", HOST).replace("192.0.2.0/24", "any")},
    ),
    "a second rule": (
        WEB,
        {
            "rules": GUEST_RULE.replace("198.51.100.11", HOST)
            + GUEST_RULE.replace("port 80 ", "port 81 ")
        },
    ),
    "a fallback form of a host redirect": (WEB, {"effective_strategy": "degraded-fallback"}),
    "a fallback profile without its form": (NAMES, {"effective_strategy": None}),
    "a fallback rule to the guest's port": (
        NAMES,
        {
            "rules": f"rdr on {INTERFACE} inet proto udp from 192.0.2.0/24 to 192.0.2.10 "
            f"port 53 -> 192.0.2.10 port 53 # netorch:{NAMES}\n"
        },
    ),
    "that rule recorded as the direct form": (
        NAMES,
        {
            "effective_strategy": None,
            "rules": f"rdr on {INTERFACE} inet proto udp from 192.0.2.0/24 to 192.0.2.10 "
            f"port 53 -> 192.0.2.10 port 53 # netorch:{NAMES}\n",
        },
    ),
}


@pytest.mark.parametrize("case", NOT_A_HOST_PATH)
def test_a_record_that_is_not_exactly_a_host_path_is_retired(environment: Any, case: str) -> None:
    key, changes = NOT_A_HOST_PATH[case]
    backend = Sockets()
    environment = loaded(site(environment, backend))
    rewritten(environment, key, **changes)
    other = next(item for item in HOST_PATHS if item != key)

    result, report = without_evidence(environment)

    # Retired with the guest rules, in the plan's own order, and never judged:
    # the inventory is read for the other host path alone.
    assert key not in owned(backend) and key not in result["withheld"]
    assert result["withheld"] == {other: REASON}
    assert f"{key}:withdraw" in result["changed"][:3]
    assert inventory_reads(backend) == [environment[1].profile(other).protocol]
    assert report.profiles[key].state == "absent"


def test_the_rules_of_a_host_path_are_what_the_renderer_writes_for_the_host_address(
    environment: Any,
) -> None:
    environment = loaded(site(environment, Sockets()))
    root, config, _, _, _ = environment
    records = root.read("live.json")["records"]

    for key, ports, publication in ((WEB, 8080, BACKING), (NAMES, 1053, NATIVE)):
        profile = config.profile(key)
        path = owner._host_path(config, profile, records[key])
        assert path == (PortRange(ports, ports), config.profile(publication))
        strategy = records[key]["effective_strategy"]
        rendered = render_profile(config, profile, HOST, effective_strategy=strategy)
        # One rule, and its translation ends at the host's own address and that port.
        assert records[key]["rules"] == rendered and rendered.count("\n") == 1
        assert rendered.split(" -> ")[1] == f"{HOST} port {ports} # netorch:{key}\n"
    assert backing_publication(config, config.profile(WEB)) == config.profile(BACKING)
    # A rule that names a guest, and the pair, are never host paths.
    for key in GUEST_PATHS:
        assert owner._host_path(config, config.profile(key), records[key]) is None


def test_a_record_that_was_withdrawn_is_not_a_host_path(environment: Any) -> None:
    environment = loaded(site(environment, Sockets()))
    root, config, _, _, _ = environment
    record = root.read("live.json")["records"][WEB]

    assert owner._host_path(config, config.profile(WEB), record) is not None
    retired = {**record, "active": False, "rules": ""}
    assert owner._host_path(config, config.profile(WEB), retired) is None
    # The stored form cannot hold a withdrawn record with rules. The check does
    # not rest on that: a record that is not active is no host path whatever
    # else it says.
    assert owner._host_path(config, config.profile(WEB), {**record, "active": False}) is None
    assert owner._host_path(config, config.profile(WEB), {**record, "active": 1}) is None


# ---- condition 2: the pass only lacks the evidence, by its plan and by its observation


def test_the_reasons_that_keep_are_two_closed_lists() -> None:
    # Of the planner's reasons for a retirement ...
    assert (
        frozenset({"endpoint-unknown", "snapshot-stale", "network-unknown"})
        == owner._EVIDENCE_MISSING
    )
    assert isinstance(owner._EVIDENCE_MISSING, frozenset)
    assert owner._EVIDENCE_MISSING < planner.ACTION_REASONS
    # ... and of the reasons an observation can have for being unknown, the one
    # with which a read says only that it ran out of time.
    assert frozenset({"timed-out"}) == owner._NO_ANSWER
    assert isinstance(owner._NO_ANSWER, frozenset)
    assert owner._NO_ANSWER < OBSERVATION_REASONS
    # Kept host paths have a distinct withholding reason; loaded precondition
    # checks add reasons that do not change the runtime-unknown keep decision.
    assert (
        frozenset(
            {"translation-order-unverified", REASON, "endpoint-unverified", "ports-unverified"}
        )
        == owner.WITHHOLDING_REASONS
    )
    assert REASON not in owner.DEFERRAL_REASONS and REASON not in planner.ACTION_REASONS
    assert REASON not in OBSERVATION_REASONS


# An observation with which a read says only that it ran out of time.
SILENT = Observation("unknown", "timed-out", STAMP, None)


def actions(key: str, reason: str, *, retire: bool = True) -> tuple[Action, ...]:
    """What the planner emits for a loaded profile that it inhibits for one reason."""
    target = (HOST, "instance-1")
    return (
        *(
            (
                Action(key, "owner", "withdraw", reason, *target),
                Action(key, "owner", "drain", reason, *target),
            )
            if retire
            else ()
        ),
        Action(key, "owner", "blocked", reason),
    )


def verified_then(key: str = WEB) -> tuple[Action, ...]:
    """What a snapshot's plan at its own time has for a rule it leaves untouched and verified."""
    return (Action(key, "owner", "noop", "verified", HOST, "instance-1"),)


@pytest.mark.parametrize("reason", sorted(planner.ACTION_REASONS))
def test_every_reason_of_the_planner_keeps_or_retires_as_the_list_says(
    environment: Any, reason: str
) -> None:
    config = site(environment, Sockets())[1]
    profile, publication = config.profile(WEB), config.profile(BACKING)
    kept = reason in {"endpoint-unknown", "snapshot-stale", "network-unknown"}
    # A present service whose evidence verifies the rule at its own time: the
    # same list without the reason of a snapshot that has no network generation.
    present = Observation("present", "verified", STAMP, "instance-1", {"ipv4": HOST})
    aged_only = reason in {"endpoint-unknown", "snapshot-stale"}
    assert (
        owner._evidence_missing(
            profile, publication, actions(WEB, reason), present, verified_then()
        )
        is aged_only
    )

    # The profile's own reason.
    assert owner._evidence_missing(profile, publication, actions(WEB, reason), SILENT) is kept
    # The same reason for the publication behind it, which the profile inherits ...
    inherited = (*actions(WEB, "publication-not-ready"), *actions(BACKING, reason))
    assert owner._evidence_missing(profile, publication, inherited, SILENT) is kept
    # ... also where the plan has nothing to retire of that publication.
    unseen = (*actions(WEB, "publication-not-ready"), *actions(BACKING, reason, retire=False))
    assert owner._evidence_missing(profile, publication, unseen, SILENT) is kept
    # A reason of the publication counts only where the profile's own is the inherited one.
    if reason != "publication-not-ready":
        mixed = (*actions(WEB, reason), *actions(BACKING, "endpoint-unknown"))
        assert owner._evidence_missing(profile, publication, mixed, SILENT) is kept


def test_a_profile_the_plan_does_not_retire_is_no_candidate() -> None:
    profile = Profile(
        WEB, "web-proxy", "wired-lan", "host-redirect", "tcp", PortRange(80, 80), None,
        Safety("structural", 30, 1),
    )  # fmt: skip
    kept = (Action(WEB, "owner", "noop", "verified", HOST, "instance-1"),)
    blocked = actions(WEB, "endpoint-unknown", retire=False)
    other = actions(BACKING, "endpoint-unknown")

    assert not owner._evidence_missing(profile, profile, (), SILENT)
    assert not owner._evidence_missing(profile, profile, kept, SILENT)
    # Blocked without a withdrawal: nothing of it is loaded.
    assert not owner._evidence_missing(profile, profile, blocked, SILENT)
    assert not owner._evidence_missing(profile, profile, other, SILENT)
    # A publication with a reason of its own beside one that only lacks evidence.
    mixed = (
        *actions(WEB, "publication-not-ready"),
        Action(BACKING, "owner", "withdraw", "endpoint-unknown", HOST, "instance-1"),
        Action(BACKING, "owner", "blocked", "contract-mismatch"),
    )
    assert not owner._evidence_missing(profile, replace(profile, id=BACKING), mixed, SILENT)
    # Both members of the list at once are still nothing but missing evidence.
    both = (
        *actions(WEB, "publication-not-ready"),
        *actions(BACKING, "endpoint-unknown"),
        *actions(BACKING, "snapshot-stale", retire=False),
    )
    assert owner._evidence_missing(profile, replace(profile, id=BACKING), both, SILENT)
    # So is every member of the list at once.
    every = (*both, *actions(BACKING, "network-unknown", retire=False))
    assert owner._evidence_missing(profile, replace(profile, id=BACKING), every, SILENT)
    # The inherited reason beside another one of the profile's own is not inherited.
    beside = (
        *actions(WEB, "publication-not-ready"),
        *actions(WEB, "contract-mismatch"),
        *actions(BACKING, "endpoint-unknown"),
    )
    assert not owner._evidence_missing(profile, replace(profile, id=BACKING), beside, SILENT)


OBSERVED: dict[str, tuple[Observation | None, bool]] = {
    "present": (Observation("present", "verified", STAMP, "instance-1", {"ipv4": HOST}), True),
    "the read ran out of time": (Observation("unknown", "timed-out", STAMP, None), True),
    "absent": (Observation("absent", "confirmed-absent", STAMP, None), False),
    "not observed at all": (None, False),
    # Among them `unavailable`: a tool that answered with an error.
    **{
        f"unknown, {reason}": (Observation("unknown", reason, STAMP, None), False)
        for reason in sorted(OBSERVATION_REASONS - {"verified", "confirmed-absent"})
        if reason != "timed-out"
    },
}


@pytest.mark.parametrize("case", OBSERVED)
def test_the_observation_of_the_service_must_state_no_finding(case: str) -> None:
    observed, kept = OBSERVED[case]
    profile = Profile(
        WEB, "web-proxy", "wired-lan", "host-redirect", "tcp", PortRange(80, 80), None,
        Safety("structural", 30, 1),
    )  # fmt: skip
    # What the same snapshot says at the time it was taken: the rule is verified
    # and untouched. Only a present observation is asked that.
    then = verified_then()

    # The plan has one and the same reason for all of them.
    for reason in ("endpoint-unknown", "snapshot-stale"):
        assert (
            owner._evidence_missing(profile, profile, actions(WEB, reason), observed, then) is kept
        )
    inherited = (*actions(WEB, "publication-not-ready"), *actions(BACKING, "endpoint-unknown"))
    backing = replace(profile, id=BACKING)
    assert owner._evidence_missing(profile, backing, inherited, observed, then) is kept
    # A snapshot without a network generation counts only with a service whose
    # read ran out of time: a present service beside it is not what such a read
    # leaves.
    silent = kept and observed is not None and observed.state == "unknown"
    for planned_for in (
        actions(WEB, "network-unknown"),
        (*actions(WEB, "publication-not-ready"), *actions(BACKING, "network-unknown")),
    ):
        assert owner._evidence_missing(profile, backing, planned_for, observed, then) is silent
    # Without a plan for its own time, present evidence is no reason to keep.
    for reason in ("endpoint-unknown", "snapshot-stale"):
        assert owner._evidence_missing(profile, profile, actions(WEB, reason), observed) is silent


# what the plan of a snapshot at its own time has for a profile -> whether present
# evidence that the plan of the pass found too old is a reason to keep its rule
THEN: dict[str, tuple[tuple[Action, ...], bool]] = {
    "untouched and verified": (verified_then(), True),
    "no plan for that time": ((), False),
    "nothing for this profile": (verified_then(BACKING), False),
    "retired for a finding": (actions(WEB, "target-replaced")[:2], False),
    "retired and blocked": (actions(WEB, "contract-mismatch"), False),
    "blocked": (actions(WEB, "publication-not-ready", retire=False), False),
    "an activation": ((Action(WEB, "owner", "activate", "ready", HOST, "instance-1"),), False),
    "a drain of retained states": (
        (Action(WEB, "owner", "drain", "retained-states", HOST, "instance-1"),),
        False,
    ),
    "verified beside a second action": (
        (*verified_then(), *actions(WEB, "endpoint-unknown", retire=False)),
        False,
    ),
    "a second action before the verified one": (
        (*actions(WEB, "endpoint-unknown", retire=False), *verified_then()),
        False,
    ),
    "a no-op for another reason": ((Action(WEB, "owner", "noop", "ready"),), False),
    "pending, with the word verified": ((Action(WEB, "owner", "pending", "verified"),), False),
}


@pytest.mark.parametrize("case", THEN)
def test_present_evidence_keeps_only_where_its_own_time_leaves_the_rule_verified(case: str) -> None:
    earlier, kept = THEN[case]
    profile = Profile(
        WEB, "web-proxy", "wired-lan", "host-redirect", "tcp", PortRange(80, 80), None,
        Safety("structural", 30, 1),
    )  # fmt: skip
    present = Observation("present", "verified", STAMP, "instance-1", {"ipv4": HOST})

    for reason in ("endpoint-unknown", "snapshot-stale"):
        assert (
            owner._evidence_missing(profile, profile, actions(WEB, reason), present, earlier)
            is kept
        )
    # A read that ran out of time is not asked what an earlier plan said.
    assert owner._evidence_missing(
        profile, profile, actions(WEB, "endpoint-unknown"), SILENT, earlier
    )


def aged(snapshot: Snapshot, seconds: float, *services: str) -> Snapshot:
    """The snapshot with the observations of these services (every one by default) this old."""
    names = services or tuple(snapshot.services)
    return replace(
        snapshot,
        services={
            key: replace(item, observed_at=STAMP - seconds) if key in names else item
            for key, item in snapshot.services.items()
        },
    )


def taken(snapshot: Snapshot, seconds: float) -> Snapshot:
    """The same snapshot taken that long ago: its own time and every observation in it.

    As the runtime observer dates what it returns: one time for the snapshot,
    the services and the publications.
    """
    at = STAMP - seconds
    return replace(
        snapshot,
        observed_at=at,
        services={key: replace(item, observed_at=at) for key, item in snapshot.services.items()},
        profiles={key: replace(item, observed_at=at) for key, item in snapshot.profiles.items()},
    )


def admitted_earlier(environment: Any, seconds: float = 90.0) -> Any:
    """Every profile of the owner admitted that long ago: before any evidence a test ages."""
    root, config, settings, _, _ = environment
    for profile in config.profiles:
        if config.profile_owner(profile).id == settings.owner:
            admit(
                root,
                profile.id,
                acknowledge_bounded_risk=True,
                acknowledge_any_source=profile.source_scope != "lan",
                now=STAMP - seconds,
            )
    return environment


# evidence of a pass -> the reason the plan then has for retiring the two host paths
MISSING: dict[str, tuple[Callable[[Snapshot], Snapshot], str]] = {
    "every read ran out of time": (lambda snapshot: unknown(snapshot), "endpoint-unknown"),
    "the whole read ran out of time": (lambda snapshot: unread(snapshot), "network-unknown"),
    "verified evidence half a second too old": (
        lambda snapshot: taken(snapshot, 30.5),
        "snapshot-stale",
    ),
    "an observation that was not too old when its snapshot was taken": (
        # The services were observed 20 seconds before the snapshot of 20 seconds ago.
        lambda snapshot: aged(taken(snapshot, 20.0), 40.0),
        "endpoint-unknown",
    ),
    "a read that ran out of time, in a snapshot that is too old": (
        lambda snapshot: taken(unknown(snapshot), 30.5),
        "snapshot-stale",
    ),
    "a read that ran out of time, in a snapshot dated ahead of the clock": (
        lambda snapshot: taken(unknown(snapshot), -0.5),
        "snapshot-stale",
    ),
}


@pytest.mark.parametrize("evidence", MISSING)
def test_each_way_of_only_lacking_evidence_keeps_the_host_paths(
    environment: Any, evidence: str
) -> None:
    change, reason = MISSING[evidence]
    backend = Sockets()
    environment = admitted_earlier(loaded(site(environment, backend)))
    snapshots = environment[4]

    snapshots.append(change(snapshots[-1]))
    result, report = observed_pass(environment)

    assert_withheld(environment, result, report, HOST_PATHS)
    assert owned(backend) == sorted(HOST_PATHS)
    for key in HOST_PATHS:
        assert planned(environment, key)[0] == ("withdraw", reason)


# evidence of a pass that is not merely missing -> the plan's reason, which is one
# of the three all the same
NOT_MISSING: dict[str, tuple[Callable[[Snapshot], Snapshot], str]] = {
    "the tool answered with an error": (
        lambda snapshot: unknown(snapshot, reason="unavailable"),
        "endpoint-unknown",
    ),
    "the tool answered with an error, for the runtime as a whole": (
        lambda snapshot: replace(unknown(snapshot, reason="unavailable"), network_generation=None),
        "network-unknown",
    ),
    "observations half a second too old in a snapshot of this moment": (
        lambda snapshot: aged(snapshot, 30.5),
        "endpoint-unknown",
    ),
    "observations dated ahead of the clock": (
        lambda snapshot: aged(snapshot, -0.5),
        "endpoint-unknown",
    ),
    "observations dated ahead of their snapshot": (
        lambda snapshot: replace(snapshot, observed_at=STAMP - 30.5),
        "snapshot-stale",
    ),
    "observations too old when their snapshot was taken": (
        lambda snapshot: aged(taken(snapshot, 30.5), 61.0),
        "snapshot-stale",
    ),
    "a snapshot dated ahead of the clock": (
        lambda snapshot: taken(snapshot, -0.5),
        "snapshot-stale",
    ),
}


@pytest.mark.parametrize("evidence", NOT_MISSING)
def test_evidence_that_is_not_merely_missing_retires_the_host_paths(
    environment: Any, evidence: str
) -> None:
    change, reason = NOT_MISSING[evidence]
    backend = Sockets()
    environment = admitted_earlier(loaded(site(environment, backend)))
    snapshots = environment[4]

    snapshots.append(change(snapshots[-1]))
    result, report = observed_pass(environment)

    # Retired with every other rule, where the plan has them, and never judged.
    assert backend.rules == "" and "withheld" not in result and ready(report) == []
    assert result["changed"][:4] == [f"{key}:withdraw" for key in EVERY_PROFILE]
    for key in HOST_PATHS:
        assert planned(environment, key)[0] == ("withdraw", reason)
    assert inventory_reads(backend) == []


# Every reason an observation can have for being unknown, other than the one
# with which a read says only that it ran out of time. `unavailable` is among
# them: a tool that answered with an error.
FINDINGS = sorted(OBSERVATION_REASONS - {"verified", "confirmed-absent", "timed-out"})


@pytest.mark.parametrize("key", HOST_PATHS)
@pytest.mark.parametrize("reason", FINDINGS)
def test_an_unknown_that_says_what_a_read_found_retires_a_host_path(
    environment: Any, reason: str, key: str
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    snapshots = environment[4]

    # The runtime observer has `identity-mismatch` for a container that is not
    # the enrolled one or that its listing does not have, `generation-mismatch`
    # for one that two reads describe differently, and `unavailable` for one
    # that the tool answers with an error for. The plan's reason is the one it
    # has for a read that ran out of time.
    snapshots.append(unknown(snapshots[-1], SERVICE[key], reason=reason))
    result, report = observed_pass(environment)

    assert planned(environment, key)[0] == ("withdraw", "endpoint-unknown")
    assert key not in owned(backend) and "withheld" not in result
    assert f"{key}:withdraw" in result["changed"] and f"{key}:drain" in result["changed"]
    assert report.profiles[key].state == "absent" and "withheld" not in report.profiles[key].data
    # It was never a candidate: nothing was read to judge it.
    assert inventory_reads(backend) == []


def test_a_service_last_seen_absent_is_a_finding_however_old_the_snapshot(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = admitted_earlier(loaded(site(environment, backend)))
    snapshots = environment[4]

    # The snapshot is too old for every profile. Of the web proxy it says that
    # the service was absent; of the resolver, that it was present.
    snapshots.append(taken(absent(snapshots[-1], WEB), 30.5))
    result, _ = observed_pass(environment)

    assert ("withdraw", "snapshot-stale") in planned(environment, WEB)
    assert ("withdraw", "snapshot-stale") in planned(environment, NAMES)
    assert owned(backend) == [NAMES] and result["withheld"] == {NAMES: REASON}


def test_a_service_the_snapshot_does_not_have_is_not_missing_evidence(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    snapshots = environment[4]
    current = snapshots[-1]

    snapshots.append(
        replace(
            current,
            services={key: item for key, item in current.services.items() if key != "web-proxy"},
        )
    )
    result, _ = observed_pass(environment)

    assert planned(environment, WEB)[0] == ("withdraw", "endpoint-unknown")
    assert WEB not in owned(backend) and "withheld" not in result
    assert inventory_reads(backend) == []


def test_evidence_exactly_as_old_as_a_profile_allows_is_still_evidence(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    snapshots = environment[4]

    snapshots.append(
        replace(aged(snapshots[-1], 30.0, *SERVICE.values()), observed_at=STAMP - 30.0)
    )
    result, report = observed_pass(environment)

    assert "withheld" not in result and set(HOST_PATHS) <= set(ready(report))
    assert inventory_reads(backend) == []


def absent(snapshot: Snapshot, key: str) -> Snapshot:
    service = SERVICE[key]
    return replace(
        snapshot,
        services={
            **snapshot.services,
            service: Observation("absent", "confirmed-absent", snapshot.observed_at, None),
        },
    )


def service_data(snapshot: Snapshot, key: str, **changes: Any) -> Snapshot:
    service = SERVICE[key]
    item = snapshot.services[service]
    generation = changes.pop("generation", item.generation)
    changed = replace(item, generation=generation, data={**item.data, **changes})
    return replace(snapshot, services={**snapshot.services, service: changed})


def publication(snapshot: Snapshot, key: str, item: Observation | None) -> Snapshot:
    profiles = dict(snapshot.profiles)
    if item is None:
        del profiles[PUBLICATION[key]]
    else:
        profiles[PUBLICATION[key]] = item
    return replace(snapshot, profiles=profiles)


def publication_data(snapshot: Snapshot, key: str, **changes: Any) -> Snapshot:
    item = snapshot.profiles[PUBLICATION[key]]
    return publication(snapshot, key, replace(item, data={**item.data, **changes}))


# what a pass learns about the service of a host path, or fails to learn about the
# runtime as a whole -> the plan's reason for retiring it, none of which is on the list
DEFINITE: dict[str, tuple[Callable[[Snapshot, str], Snapshot], str]] = {
    "the service is absent": (absent, "endpoint-absent"),
    "another contract": (
        lambda snapshot, key: service_data(snapshot, key, contract_sha256="9" * 64),
        "contract-mismatch",
    ),
    "no instance generation": (
        lambda snapshot, key: service_data(snapshot, key, generation=None),
        "endpoint-invalid",
    ),
    "an address outside the guest network": (
        lambda snapshot, key: service_data(snapshot, key, ipv4="203.0.113.9"),
        "endpoint-invalid",
    ),
    "another instance": (
        lambda snapshot, key: publication_data(
            service_data(snapshot, key, generation="instance-2"),
            key,
            target_generation="instance-2",
        ),
        "target-replaced",
    ),
    "the publication is absent": (
        lambda snapshot, key: publication(
            snapshot,
            key,
            Observation("absent", "confirmed-absent", snapshot.observed_at, None, {"states": ()}),
        ),
        "publication-not-ready",
    ),
    "the publication is unknown": (
        lambda snapshot, key: publication(
            snapshot, key, Observation("unknown", "malformed", snapshot.observed_at, None)
        ),
        "publication-not-ready",
    ),
    "the publication was not observed": (
        lambda snapshot, key: publication(snapshot, key, None),
        "publication-not-ready",
    ),
    "the publication is of another policy": (
        lambda snapshot, key: publication_data(snapshot, key, policy_digest="c" * 64),
        "publication-not-ready",
    ),
    "the publication has another target": (
        lambda snapshot, key: publication_data(snapshot, key, target_generation="instance-9"),
        "publication-not-ready",
    ),
    "no network generation": (
        lambda snapshot, key: replace(snapshot, network_generation=None),
        "network-unknown",
    ),
}


@pytest.mark.parametrize("key", HOST_PATHS)
@pytest.mark.parametrize("finding", DEFINITE)
def test_a_reason_outside_the_list_retires_a_host_path(
    environment: Any, finding: str, key: str
) -> None:
    change, reason = DEFINITE[finding]
    backend = Sockets()
    environment = loaded(site(environment, backend))
    snapshots = environment[4]

    snapshots.append(change(snapshots[-1], key))
    result, report = observed_pass(environment)

    assert planned(environment, key)[0] == ("withdraw", reason)
    assert key not in owned(backend) and key not in result.get("withheld", {})
    assert f"{key}:withdraw" in result["changed"] and f"{key}:drain" in result["changed"]
    assert report.profiles[key].state == "absent" and "withheld" not in report.profiles[key].data
    # Nothing was read to judge it: it was never a candidate.
    assert inventory_reads(backend) == []


@pytest.mark.parametrize("reason", FINDINGS)
def test_a_whole_read_that_failed_for_a_finding_retires_every_rule(
    environment: Any, reason: str
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    snapshots = environment[4]

    # The observer has `identity-mismatch` for a version, a helper, a network or
    # settings that are not the accepted ones, `generation-mismatch` for a
    # runtime that changed during the read, and `unavailable` for a job, an
    # interface or a network that the tools say does not exist. The plan's
    # reason is the one it has for a whole read that ran out of time.
    snapshots.append(replace(unknown(snapshots[-1], reason=reason), network_generation=None))
    result, _ = observed_pass(environment)

    assert backend.rules == "" and "withheld" not in result
    assert {reason for key in EVERY_PROFILE for _, reason in planned(environment, key)} == {
        "network-unknown"
    }
    assert sorted(result["pending"]) == list(EVERY_PROFILE) and inventory_reads(backend) == []


# The same findings in evidence that is half a second too old: the plan's reason
# is then the age of the snapshot, and what the snapshot says is a finding still.
STALE_FINDINGS = [finding for finding in DEFINITE if finding != "no network generation"]


@pytest.mark.parametrize("key", HOST_PATHS)
@pytest.mark.parametrize("finding", STALE_FINDINGS)
def test_a_finding_in_evidence_that_is_too_old_retires_a_host_path(
    environment: Any, finding: str, key: str
) -> None:
    change, _ = DEFINITE[finding]
    backend = Sockets()
    environment = admitted_earlier(loaded(site(environment, backend)))
    snapshots = environment[4]
    other = next(item for item in HOST_PATHS if item != key)

    snapshots.append(taken(change(snapshots[-1], key), 30.5))
    result, report = observed_pass(environment)

    # Both host paths have the same reason in the plan. The one whose evidence
    # verifies it at its own time is kept; the other is retired with the guest
    # rules and was never judged: the inventory is read for the kept one alone.
    for item in HOST_PATHS:
        assert planned(environment, item)[0] == ("withdraw", "snapshot-stale")
    assert result["withheld"] == {other: REASON} and owned(backend) == [other]
    assert f"{key}:withdraw" in result["changed"] and f"{key}:drain" in result["changed"]
    assert report.profiles[key].state == "absent" and "withheld" not in report.profiles[key].data
    assert inventory_reads(backend) == [environment[1].profile(other).protocol]


def test_another_network_generation_in_evidence_that_is_too_old_retires_every_rule(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = admitted_earlier(loaded(site(environment, backend)))
    snapshots = environment[4]
    current = snapshots[-1]
    renewed = replace(
        current,
        network_generation="network-2",
        profiles={
            key: replace(item, data={**item.data, "network_generation": "network-2"})
            for key, item in current.profiles.items()
        },
    )

    # Taken now it is a replaced target; half a second too old it is the same.
    for stale, reason in ((False, "target-replaced"), (True, "snapshot-stale")):
        snapshots.append(taken(renewed, 30.5) if stale else renewed)
        result, _ = observed_pass(environment)
        assert planned(environment, WEB)[0] == ("withdraw", reason)
        assert backend.rules == "" and "withheld" not in result
        assert inventory_reads(backend) == []
        # Loaded again for the second half.
        snapshots.append(current)
        observed_pass(environment)
        observed_pass(environment)
        backend.commands.clear()


def test_an_admission_given_after_the_evidence_was_taken_does_not_keep(environment: Any) -> None:
    backend = Sockets()
    environment = admitted_earlier(loaded(site(environment, backend)))
    root, _, _, _, snapshots = environment
    verified = snapshots[-1]
    # The web path was admitted again ten seconds ago; the evidence is older.
    admit(root, WEB, acknowledge_bounded_risk=True, now=STAMP - 10)

    snapshots.append(taken(verified, 30.5))
    result, _ = observed_pass(environment)

    # At the time the snapshot was taken that admission did not hold yet, and
    # the plan of that time would not have left the rule verified.
    assert planned(environment, WEB)[0] == ("withdraw", "snapshot-stale")
    assert result["withheld"] == {NAMES: REASON} and owned(backend) == [NAMES]
    earlier = owner._planned_then(
        environment[1],
        owner._snapshot(environment[1], snapshots[-1], {}, backend, STAMP, "site-forwarding"),
        owner._effective_admissions(environment[1], environment[2], root.read("admissions.json")),
        Intent(),
        set(EVERY_PROFILE),
        STAMP,
    )
    assert ("pending", "admission-future") in {
        (action.operation, action.reason) for action in earlier if action.profile == WEB
    }


def test_the_direct_path_of_a_fallback_form_is_not_probed_for_evidence_that_is_too_old(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = admitted_earlier(loaded(site(environment, backend)))
    snapshots = environment[4]
    verified = snapshots[-1]
    # The direct path to the resolver could be verified again.
    backend.unavailable_guests = set()

    snapshots.append(taken(verified, 30.5))
    result, _ = observed_pass(environment)

    # The owner probes the direct path only for evidence that is present and
    # not too old. This pass did not probe it: the form that is loaded is the
    # one that is judged, and it is kept like the web path.
    assert not [command for command in backend.commands if command[0] == "endpoint"]
    assert result["withheld"] == HOST_PATHS and result["changed"] == RETIRED
    # A pass with current evidence probes it, and replaces the fallback form.
    snapshots.append(verified)
    result, _ = observed_pass(environment)
    assert planned(environment, NAMES)[0] == ("withdraw", "target-replaced")
    assert f"{NAMES}:withdraw" in result["changed"] and "withheld" not in result


def test_the_plan_of_a_snapshot_at_its_own_time(environment: Any) -> None:
    backend = Sockets()
    environment = admitted_earlier(loaded(site(environment, backend)))
    root, config, settings, _, snapshots = environment
    records = root.read("live.json")["records"]
    admissions = owner._effective_admissions(config, settings, root.read("admissions.json"))
    for profile in config.profiles:
        if profile.kind == "publication":
            admissions[profile.id] = owner.Admission(
                profile.id, profile_digest(config, profile), "runtime-observation", STAMP, False
            )
    owned_profiles = set(EVERY_PROFILE)

    def then(evidence: Snapshot, now: float = STAMP) -> dict[str, list[tuple[str, str]]]:
        # As a pass builds its snapshot: the owner's own readback is dated now.
        snapshot = owner._snapshot(config, evidence, records, backend, STAMP, settings.owner)
        plan: dict[str, list[tuple[str, str]]] = {}
        for action in owner._planned_then(
            config, snapshot, admissions, Intent(), owned_profiles, now
        ):
            plan.setdefault(action.profile, []).append((action.operation, action.reason))
        return plan

    # Half a minute and more ago every rule was verified: the owner's readback
    # of this pass and its admissions of the publications are dated at that time.
    assert then(taken(snapshots[-1], 30.5)) == {
        key: [("noop", "verified")] for key in (*EVERY_PROFILE, BACKING, NATIVE, "camera-web")
    }
    # The clock of that plan is the snapshot's time and no other.
    late = then(aged(taken(snapshots[-1], 30.5), 61.0))
    assert late[WEB][0] == ("withdraw", "endpoint-unknown")
    # A snapshot dated ahead of the clock names no time at which it was taken.
    assert then(taken(snapshots[-1], -0.5)) == {}
    assert then(taken(snapshots[-1], 0.0)) != {}
    assert then(taken(snapshots[-1], 30.5), now=STAMP - 30.5) != {}
    assert then(taken(snapshots[-1], 30.5), now=STAMP - 30.6) == {}


def test_the_plan_of_another_time_is_asked_only_for_present_evidence_that_the_plan_retires(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = Sockets()
    environment = admitted_earlier(loaded(site(environment, backend)))
    snapshots = environment[4]
    verified = snapshots[-1]
    asked: list[float] = []
    planned_then = owner._planned_then

    def noting(config: Config, snapshot: Snapshot, *arguments: Any) -> tuple[Action, ...]:
        asked.append(snapshot.observed_at)
        return planned_then(config, snapshot, *arguments)

    monkeypatch.setattr(owner, "_planned_then", noting)

    # Not by a pass with verified evidence, which retires nothing, and not for
    # a service whose read ran out of time.
    observed_pass(environment)
    without_evidence(environment, "web-proxy")
    assert asked == []
    # Once for a pass, however many host paths have evidence that is too old.
    snapshots.append(taken(verified, 30.5))
    assert observed_pass(environment)[0]["withheld"] == HOST_PATHS
    assert asked == [STAMP - 30.5]


def test_an_observer_that_raises_retires_every_rule(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))

    def raising(config: Config, settings: Any) -> Snapshot:
        raise PFError("simulated runtime inspection exception")

    result, report = observed_pass(environment, raising)

    # The owner records every service as unknown and `unavailable`, without a
    # network generation. That is not a read that ran out of time: the observer
    # raises when it refuses to run at all, and whatever else made it raise is
    # not known. Every rule is retired, as without the decision.
    assert {reason for key in EVERY_PROFILE for _, reason in planned(environment, key)} == {
        "network-unknown"
    }
    assert result["changed"] == [
        *(f"{key}:withdraw" for key in EVERY_PROFILE),
        *(f"{key}:drain" for key in EVERY_PROFILE),
    ]
    assert backend.rules == "" and "withheld" not in result and ready(report) == []
    assert sorted(result["pending"]) == list(EVERY_PROFILE) and inventory_reads(backend) == []


AUTHORITY: dict[str, tuple[Callable[[Any, str], None], str]] = {
    "an operator pause": (
        lambda environment, key: environment[0].write(
            "operator-intent.json", intent_to_dict(Intent().pause())
        ),
        "paused",
    ),
    "a suspension": (
        lambda environment, key: environment[0].write(
            "operator-intent.json", intent_to_dict(Intent().suspend("maintenance", "holder-1"))
        ),
        "suspended",
    ),
    "a hold on its service": (
        lambda environment, key: environment[0].write(
            "operator-intent.json",
            intent_to_dict(Intent().hold(SERVICE[key], "maintenance", "holder-1")),
        ),
        "held",
    ),
    "a damaged intent": (
        lambda environment, key: environment[0].write(
            "operator-intent.json", {"schema_version": 9}
        ),
        "intent-damaged",
    ),
    "no admission": (
        lambda environment, key: environment[0].write(
            "admissions.json",
            {
                **environment[0].read("admissions.json"),
                "profiles": {
                    name: record
                    for name, record in environment[0].read("admissions.json")["profiles"].items()
                    if name != key
                },
            },
        ),
        "not-admitted",
    ),
    "an admission of another digest": (
        lambda environment, key: environment[0].write(
            "admissions.json",
            {
                **environment[0].read("admissions.json"),
                "profiles": {
                    **environment[0].read("admissions.json")["profiles"],
                    key: {
                        **environment[0].read("admissions.json")["profiles"][key],
                        "digest": "d" * 64,
                    },
                },
            },
        ),
        "not-admitted",
    ),
    "an admission dated ahead of the clock": (
        lambda environment, key: (
            admit(environment[0], key, acknowledge_bounded_risk=True, now=STAMP + 0.5) and None
        ),
        "admission-future",
    ),
}


@pytest.mark.parametrize("key", HOST_PATHS)
@pytest.mark.parametrize("authority", AUTHORITY)
def test_an_authority_retires_a_host_path_also_while_evidence_is_unknown(
    environment: Any, authority: str, key: str
) -> None:
    change, reason = AUTHORITY[authority]
    backend = Sockets()
    environment = loaded(site(environment, backend))
    without_evidence(environment)
    assert key in owned(backend)

    # The profile is withheld; then the authority it rests on goes.
    change(environment, key)
    result, report = observed_pass(environment)

    assert planned(environment, key)[0] == ("withdraw", reason)
    assert key not in owned(backend) and key not in result.get("withheld", {})
    assert f"{key}:withdraw" in result["changed"]
    assert report.profiles[key].state == "absent"


def test_an_unacknowledged_risk_retires_the_fallback_form(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root = environment[0]
    without_evidence(environment)
    admissions = root.read("admissions.json")
    admissions["profiles"][NAMES]["risk_acknowledged"] = False
    root.write("admissions.json", admissions)

    result, _ = observed_pass(environment)

    assert planned(environment, NAMES)[0] == ("withdraw", "risk-unacknowledged")
    assert owned(backend) == [WEB] and result["withheld"] == {WEB: REASON}


@pytest.mark.parametrize("key", HOST_PATHS)
def test_a_publication_that_only_aged_out_is_inherited_as_missing_evidence(
    environment: Any, key: str
) -> None:
    # This host path tolerates evidence of a minute, its publication of half a minute.
    backend = Sockets()
    environment = admitted_earlier(loaded(site(environment, backend, ages={key: 60})))
    snapshots = environment[4]
    other = next(item for item in HOST_PATHS if item != key)

    snapshots.append(taken(snapshots[-1], 45.0))
    result, report = observed_pass(environment)

    assert planned(environment, key)[0] == ("withdraw", "publication-not-ready")
    assert planned(environment, PUBLICATION[key]) == []  # not this owner's profile
    assert result["withheld"] == HOST_PATHS and key in owned(backend)
    assert report.profiles[key].data["withheld"] == REASON
    # Every rule whose own tolerance is half a minute sees a stale snapshot itself.
    assert planned(environment, other)[0] == ("withdraw", "snapshot-stale")


# ---- condition 3: the rules that are live are the recorded ones


def test_a_drifted_anchor_stops_the_pass_as_before_and_nothing_is_judged(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root, _, _, _, snapshots = environment
    journal = root.read("journal.json")
    backend.rules += f"{FOREIGN_TRANSLATION}\n"
    snapshots.append(unknown(snapshots[-1]))

    with pytest.raises(PFError, match="owned PF rules drifted"):
        observed_pass(environment)

    assert root.read("journal.json") == journal and inventory_reads(backend) == []
    assert written(backend) == []


class Flushed(Sockets):
    """Another tool empties the anchor while a pass reads the socket inventory."""

    flush = False

    def socket_inventory(self, protocol: str) -> tuple[Row, ...]:
        rows = super().socket_inventory(protocol)
        if self.flush:
            self.rules = ""
        return rows


def test_rules_that_change_after_the_judgement_are_never_reported_as_kept(
    environment: Any,
) -> None:
    backend = Flushed()
    environment = loaded(site(environment, backend))
    root = environment[0]
    # Only the two host paths are loaded, so the next pass writes nothing.
    without_evidence(environment)
    assert owned(backend) == sorted(HOST_PATHS)
    backend.flush = True

    with pytest.raises(PFError, match="owned rules changed before final readback"):
        observed_pass(environment)

    journal = root.read("journal.json")
    assert journal["phase"] == "failed" and "withheld" not in journal
    # The acknowledgement that is now owed retires everything on the next pass.
    backend.rules = owner.compose_rules(root.read("live.json")["records"])
    result, _ = observed_pass(environment)
    assert result["phase"] == "failed" and backend.rules == ""
    assert planned(environment, WEB)[0] == ("withdraw", "intent-damaged")


# ---- condition 4: a listener behind the rule, in root's own socket inventory

LISTENERS: dict[str, tuple[list[Row], bool]] = {
    "on the host address": ([(HOST, 8080, 501, "forwarder", "IPv4")], True),
    "on the wildcard": ([("*", 8080, 501, "forwarder", "IPv4")], True),
    "of an unidentified process": ([(HOST, 8080, 0, "", "IPv4")], True),
    "beside others": (
        [
            ("*", 22, 1, "other", "IPv4"),
            ("127.0.0.1", 8080, 7, "other", "IPv4"),
            (HOST, 8080, 501, "forwarder", "IPv4"),
        ],
        True,
    ),
    "none at all": ([], False),
    "on another port": ([(HOST, 8081, 501, "forwarder", "IPv4")], False),
    "on the port before": ([(HOST, 8079, 501, "forwarder", "IPv4")], False),
    "on the loopback address": ([("127.0.0.1", 8080, 501, "forwarder", "IPv4")], False),
    "on another address of the LAN": ([("192.0.2.11", 8080, 501, "forwarder", "IPv4")], False),
    "on an address that begins like the host's": (
        [("192.0.2.100", 8080, 501, "forwarder", "IPv4")],
        False,
    ),
    "an IPv6-only wildcard": ([("*", 8080, 501, "forwarder", "IPv6")], False),
    "the IPv6 wildcard": ([("::", 8080, 501, "forwarder", "IPv6")], False),
    "the unspecified address spelled out": ([("0.0.0.0", 8080, 501, "forwarder", "IPv4")], False),
    "the host address as a mapped one": (
        [(f"::ffff:{HOST}", 8080, 501, "forwarder", "IPv4")],
        False,
    ),
    "an unbound socket": ([("*", 0, 501, "forwarder", "IPv4")], False),
}


@pytest.mark.parametrize("listener", LISTENERS)
def test_a_host_path_is_kept_only_with_a_listener_behind_it(
    environment: Any, listener: str
) -> None:
    rows, kept = LISTENERS[listener]
    backend = Sockets()
    environment = loaded(site(environment, backend))
    backend.sockets["tcp"] = rows

    result, report = without_evidence(environment)

    assert owner._listening(tuple(rows), HOST, PortRange(8080, 8080)) is kept
    assert (WEB in owned(backend)) is kept and (WEB in result["withheld"]) is kept
    # The other host path has its own listener and is judged by itself.
    assert result["withheld"][NAMES] == REASON
    if not kept:
        # Retired as it always was, where the plan has it among the others.
        assert result["changed"] == [
            *(f"{key}:withdraw" for key in (DIRECT, PAIR, WEB)),
            *(f"{key}:drain" for key in (DIRECT, PAIR, WEB)),
        ]
        assert result["pending"] == [DIRECT, PAIR, WEB]
        assert report.profiles[WEB].state == "absent"
        assert WEB not in environment[0].read("live.json")["records"]


def test_a_listener_of_the_other_protocol_is_not_a_listener(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    # The two forwarders change places: each port is heard, on the wrong protocol.
    backend.sockets = {"tcp": backend.sockets["udp"], "udp": backend.sockets["tcp"]}

    result, _ = without_evidence(environment)

    assert backend.rules == "" and "withheld" not in result
    assert inventory_reads(backend) == ["udp", "tcp"]


@pytest.mark.parametrize(
    "error",
    [PFError("native kernel observation is unknown"), OSError("no such tool"), ValueError("x")],
    ids=["owner-error", "os-error", "value-error"],
)
def test_an_inventory_that_cannot_be_read_establishes_no_listener(
    environment: Any, error: Exception
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    backend.unreadable["udp"] = error

    result, report = without_evidence(environment)

    # Retired as today; the pass goes on and judges the other protocol by itself.
    assert result["phase"] == "inhibited" and result["withheld"] == {WEB: REASON}
    assert result["changed"] == [
        *(f"{key}:withdraw" for key in (DIRECT, NAMES, PAIR)),
        *(f"{key}:drain" for key in (DIRECT, NAMES, PAIR)),
    ]
    assert owned(backend) == [WEB] and report.profiles[NAMES].state == "absent"
    assert environment[0].read("journal.json")["phase"] == "inhibited"


def test_an_error_of_another_kind_is_not_taken_for_an_unreadable_inventory(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root, _, _, _, snapshots = environment
    backend.unreadable["udp"] = LookupError("none of the errors a failed read raises")
    snapshots.append(unknown(snapshots[-1]))

    with pytest.raises(LookupError):
        observed_pass(environment)

    # As at every other read of a pass, only the three kinds of error that a
    # failed read raises are absorbed. Anything else ends the pass failed. The
    # judgement stands before the first action, so nothing was written, and the
    # acknowledgement that is owed now retires every rule on the next pass.
    assert root.read("journal.json")["phase"] == "failed"
    assert written(backend) == [] and sorted(set(owned(backend))) == list(EVERY_PROFILE)
    del backend.unreadable["udp"]
    result, _ = observed_pass(environment)
    assert result["phase"] == "failed" and backend.rules == "" and "withheld" not in result


SECOND = "proxy-second"  # the web port of a second scope, on that scope's own host address
SECOND_HOST = "203.0.113.10"


def second_scope(environment: Any) -> Any:
    """The site with a second scope that redirects its own web port, every profile admitted."""
    root, config, settings, backend, snapshots = environment
    scope = Scope("second-lan", SECOND_INTERFACE, SECOND_HOST, "203.0.113.0/24", "198.51.100.0/24")
    backing = replace(config.profile(BACKING), id="proxy-high-second", scope=scope.id)
    redirect = replace(config.profile(WEB), id=SECOND, scope=scope.id)
    config = replace(
        config, scopes=(*config.scopes, scope), profiles=(*config.profiles, backing, redirect)
    )
    validate_config(config)
    root.write("policy.json", to_dict(config))
    current = snapshots[-1]
    observed = replace(
        current.profiles[BACKING],
        data={**current.profiles[BACKING].data, "policy_digest": profile_digest(config, backing)},
    )
    snapshots.append(replace(current, profiles={**current.profiles, backing.id: observed}))
    environment = (root, config, settings, backend, snapshots)
    approve_all(environment)
    return environment


@pytest.mark.parametrize(
    "listeners,kept",
    [
        ([(HOST, 8080, 501, "forwarder", "IPv4")], [WEB]),
        ([(SECOND_HOST, 8080, 502, "forwarder", "IPv4")], [SECOND]),
        ([("*", 8080, 501, "forwarder", "IPv4")], [SECOND, WEB]),
        (
            [(HOST, 8080, 501, "forwarder", "IPv4"), (SECOND_HOST, 8080, 502, "forwarder", "IPv4")],
            [SECOND, WEB],
        ),
    ],
    ids=["the first scope's address", "the second scope's address", "the wildcard", "both"],
)
def test_a_listener_counts_for_the_scope_whose_host_address_it_is_on(
    environment: Any, listeners: list[Row], kept: list[str]
) -> None:
    backend = Sockets()
    environment = loaded(second_scope(site(environment, backend)), SECOND)
    rule = environment[0].read("live.json")["records"][SECOND]["rules"]
    assert rule == (
        f"rdr on {SECOND_INTERFACE} inet proto tcp from 203.0.113.0/24 to {SECOND_HOST} port 80 "
        f"-> {SECOND_HOST} port 8080 # netorch:{SECOND}\n"
    )
    backend.sockets["tcp"] = listeners

    result, _ = without_evidence(environment)

    # Two rules of one protocol and one port, each ending at its own scope's
    # host address: a listener on one of the two addresses is behind one rule.
    assert sorted(set(result["withheld"]) - {NAMES}) == kept
    assert [key for key in (SECOND, WEB) if key in owned(backend)] == kept
    # One inventory of the protocol serves both.
    assert inventory_reads(backend) == ["udp", "tcp"]


def test_the_listener_that_goes_retires_the_rule_and_its_return_does_not_bring_it_back(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    without_evidence(environment)
    forwarder = backend.sockets["udp"]

    backend.sockets["udp"] = []
    result, _ = observed_pass(environment)
    assert result["changed"] == [f"{NAMES}:withdraw", f"{NAMES}:drain"]
    assert owned(backend) == [WEB]

    # The listener is back and evidence is still unknown: nothing is activated.
    backend.sockets["udp"] = forwarder
    for _ in range(2):
        result, report = observed_pass(environment)
        assert result["changed"] == [] and owned(backend) == [WEB]
        assert result["pending"] == [DIRECT, NAMES, PAIR]
        assert report.profiles[NAMES].state == "absent"


@pytest.mark.parametrize(
    "ports,heard,kept",
    [
        ((8080, 8080), [8080], True),
        ((8080, 8082), [8080, 8081, 8082], True),
        ((8080, 8082), [8082, 8080, 8081, 8083], True),
        ((8080, 8082), [8080, 8082], False),
        ((8080, 8082), [8081, 8082], False),
        ((8080, 8082), [8080, 8081], False),
        ((8080, 8081), [], False),
        ((1, 1), [1], True),
        ((65535, 65535), [65535], True),
    ],
)
def test_every_port_of_a_range_needs_its_listener(
    ports: tuple[int, int], heard: list[int], kept: bool
) -> None:
    rows = tuple((HOST, port, 501, "forwarder", "IPv4") for port in heard)

    assert owner._listening(rows, HOST, PortRange(*ports)) is kept


def test_one_inventory_per_protocol_serves_every_host_path_of_a_pass() -> None:
    backend = Sockets()
    cache: dict[str, tuple[Row, ...] | None] = {}

    assert owner._inventory(backend, cache, "tcp") == tuple(backend.sockets["tcp"])
    backend.sockets["tcp"] = []
    # Read once: the second question is answered from the same inventory.
    assert owner._inventory(backend, cache, "tcp") == ((HOST, 8080, 501, "forwarder", "IPv4"),)
    backend.unreadable["udp"] = PFError("unreadable")
    assert owner._inventory(backend, cache, "udp") is None
    del backend.unreadable["udp"]
    # An inventory that could not be read is not read again in that pass either.
    assert owner._inventory(backend, cache, "udp") is None
    assert inventory_reads(backend) == ["tcp", "udp"]


# ---- the reader of the inventory is the one the port check uses

LISTENING = "0 0 0 0 forwarder:501 00000 00000000 0000000000000000 00000000 00000000 0 0 000000\n"


def inventory_text(*rows: str) -> str:
    return "Active Internet connections (including servers)\n" + HEADER + "\n" + "".join(rows)


def test_the_backend_reads_the_inventory_with_the_reader_of_the_port_check(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = shell_backend(environment, monkeypatch)
    asked: list[list[str]] = []

    def native(arguments: list[str]) -> str:
        asked.append(arguments)
        return socket_fixture(arguments[-1], f"{HOST}.8080", "forwarder:501")

    monkeypatch.setattr(backend, "_native", native)
    scope, profile = environment[1].scopes[0], environment[1].profile(WEB)

    assert backend.socket_inventory("tcp") == ((HOST, 8080, 501, "forwarder", "IPv4"),)
    assert backend.ports_clear(scope, profile, apple_dns=False)
    # The same call of the same tool, once for each question.
    assert asked == [["/usr/sbin/netstat", "-anlv", "-W", "-p", "tcp"]] * 2
    assert backend.socket_inventory("udp") == ((HOST, 8080, 501, "forwarder", "IPv4"),)
    assert asked[-1] == ["/usr/sbin/netstat", "-anlv", "-W", "-p", "udp"]
    # The port check of a UDP profile asks for the UDP inventory, as it did.
    del asked[:]
    assert backend.ports_clear(scope, environment[1].profile(PAIR), apple_dns=False)
    assert asked == [["/usr/sbin/netstat", "-anlv", "-W", "-p", "udp"]]


@pytest.mark.parametrize(
    "rows,kept",
    [
        ([f"tcp4 0 0 {HOST}.8080 *.* LISTEN " + LISTENING], True),
        (["tcp4 0 0 *.8080 *.* LISTEN " + LISTENING], True),
        (["tcp46 0 0 *.8080 *.* LISTEN " + LISTENING], True),
        (["tcp6 0 0 *.8080 *.* LISTEN " + LISTENING], False),
        ([f"tcp4 0 0 {HOST}.8080 192.0.2.77.50000 ESTABLISHED " + LISTENING], False),
        ([f"tcp4 0 0 {HOST}.8080 *.* CLOSED " + LISTENING], False),
        (["tcp4 0 0 127.0.0.1.8080 *.* LISTEN " + LISTENING], False),
        ([f"tcp6 0 0 ::ffff:{HOST}.8080 *.* LISTEN " + LISTENING], False),
        ([], False),
    ],
    ids=[
        "host address",
        "wildcard",
        "dual-stack wildcard",
        "IPv6-only wildcard",
        "a connection, not a listener",
        "a closed socket",
        "loopback",
        "mapped address on an IPv6 socket",
        "no socket",
    ],
)
def test_what_the_tool_lists_as_a_listener_for_the_host_address(
    environment: Any, monkeypatch: pytest.MonkeyPatch, rows: list[str], kept: bool
) -> None:
    backend = shell_backend(environment, monkeypatch)
    monkeypatch.setattr(backend, "_native", lambda arguments: inventory_text(*rows))

    inventory = backend.socket_inventory("tcp")

    assert owner._listening(inventory, HOST, PortRange(8080, 8080)) is kept


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "Active Internet connections (including servers)\n",
        inventory_text("tcp4 0 0 *.8080 *.* LISTEN 0 0 0 0 forwarder:501\n"),
        inventory_text("tcp4 0 0 *.8080 *.* LISTEN " + LISTENING, "netstat: a warning\n"),
    ],
    ids=["nothing", "no header", "a short row", "a line that is no row"],
)
def test_an_inventory_the_reader_refuses_is_unreadable_not_empty(
    environment: Any, monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    backend = shell_backend(environment, monkeypatch)
    monkeypatch.setattr(backend, "_native", lambda arguments: raw)

    with pytest.raises(PFError):
        backend.socket_inventory("tcp")
    assert owner._inventory(backend, {}, "tcp") is None


# ---- never activated


def test_a_host_path_that_is_not_loaded_is_never_activated_without_evidence(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = site(environment, backend)
    snapshots = environment[4]
    verified = snapshots[-1]
    snapshots.append(unknown(verified))

    # Admitted, a listener behind each host path, and never a verified pass.
    for _ in range(3):
        result, report = observed_pass(environment)
        assert result == {
            "schema_version": 1,
            "phase": "inhibited",
            "changed": [],
            "pending": list(EVERY_PROFILE),
        }
        assert backend.rules == "" and ready(report) == []
    assert backend.commands.count(("reference",)) == 0 and inventory_reads(backend) == []

    # Only verified evidence brings a rule into existence.
    snapshots.append(verified)
    result, _ = observed_pass(environment)
    assert sorted(result["changed"]) == [f"{key}:activate" for key in EVERY_PROFILE]


def test_a_host_path_admitted_while_evidence_is_unknown_stays_unloaded(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root, _, _, _, snapshots = environment
    # The web path loses its admission and is retired; evidence then goes.
    admissions = root.read("admissions.json")
    kept_admission = admissions["profiles"].pop(WEB)
    root.write("admissions.json", admissions)
    observed_pass(environment)
    assert WEB not in owned(backend)
    without_evidence(environment)

    admissions = root.read("admissions.json")
    admissions["profiles"][WEB] = kept_admission
    root.write("admissions.json", admissions)
    result, report = observed_pass(environment)

    assert owned(backend) == [NAMES] and result["withheld"] == {NAMES: REASON}
    assert WEB in result["pending"] and report.profiles[WEB].state == "absent"
    assert snapshots[-1].services["web-proxy"].state == "unknown"


# ---- the authority a kept rule rests on: admission, policy, installation


def test_a_policy_change_during_withholding_retires_the_rule(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root, config, _, _, _ = environment
    without_evidence(environment)
    policy = to_dict(config)
    for profile in policy["profiles"]:
        if profile["id"] == WEB:
            profile["safety"]["max_age_seconds"] = 29
    root.write("policy.json", policy)

    result, _ = observed_pass(environment)

    assert planned(environment, WEB)[0] == ("withdraw", "not-admitted")
    assert owned(backend) == [NAMES] and result["withheld"] == {NAMES: REASON}


def test_a_policy_change_that_is_admitted_again_still_retires_the_old_rule(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root, config, _, _, _ = environment
    without_evidence(environment)
    backend.commands.clear()
    policy = to_dict(config)
    for profile in policy["profiles"]:
        if profile["id"] == WEB:
            profile["safety"]["max_age_seconds"] = 29
    root.write("policy.json", policy)
    admit(root, WEB, acknowledge_bounded_risk=True, now=STAMP - 1)

    result, _ = observed_pass(environment)

    # The plan cannot see it without evidence; the record's own policy digest says so.
    assert planned(environment, WEB)[0] == ("withdraw", "endpoint-unknown")
    assert f"{WEB}:withdraw" in result["changed"] and owned(backend) == [NAMES]
    assert inventory_reads(backend) == ["udp"]


def redeclared(environment: Any, key: str) -> None:
    """Change the declaration of one profile in the installed policy; admit nothing."""
    root, config = environment[0], environment[1]
    policy = to_dict(config)
    for profile in policy["profiles"]:
        if profile["id"] == key:
            profile["safety"]["max_age_seconds"] = 29
    root.write("policy.json", policy)


def test_a_change_of_the_publication_behind_a_fallback_form_retires_it(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    without_evidence(environment)

    redeclared(environment, NATIVE)
    result, _ = observed_pass(environment)

    # The digest of a fallback profile binds its publication: the admission of
    # the name-service path no longer matches.
    assert planned(environment, NAMES)[0] == ("withdraw", "not-admitted")
    assert owned(backend) == [WEB] and result["withheld"] == {WEB: REASON}


@pytest.mark.parametrize("unrestricted", [False, True], ids=["LAN source", "every source"])
def test_a_change_of_the_publication_behind_a_redirect_retires_it_where_its_digest_binds_it(
    environment: Any, unrestricted: bool
) -> None:
    backend = Sockets()
    environment = site(environment, backend)
    environment = loaded(every_source(environment) if unrestricted else environment)
    without_evidence(environment)

    redeclared(environment, BACKING)
    result, _ = observed_pass(environment)

    if unrestricted:
        # A redirect for every source is admitted together with its publication.
        assert planned(environment, WEB)[0] == ("withdraw", "not-admitted")
        assert owned(backend) == [NAMES] and result["withheld"] == {NAMES: REASON}
    else:
        # The digest of a redirect for the LAN does not bind the publication, and
        # without runtime evidence nothing else shows the change: it is kept.
        assert ("withdraw", "endpoint-unknown") in planned(environment, WEB)
        assert owned(backend) == sorted(HOST_PATHS) and result["withheld"] == HOST_PATHS


def test_a_policy_change_that_a_pass_with_evidence_sees_retires_for_that_reason(
    environment: Any,
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root, _, _, _, snapshots = environment
    verified = snapshots[-1]
    without_evidence(environment)
    redeclared(environment, WEB)
    admit(root, WEB, acknowledge_bounded_risk=True, now=STAMP - 1)

    # Evidence is back: the plan itself sees the rule of the earlier policy.
    snapshots.append(verified)
    result, _ = observed_pass(environment)

    assert planned(environment, WEB) == [
        ("withdraw", "policy-changed"),
        ("drain", "policy-changed"),
    ]
    assert f"{WEB}:withdraw" in result["changed"] and WEB not in owned(backend)
    assert "withheld" not in result and inventory_reads(backend)[2:] == []


def test_a_profile_removed_from_the_policy_during_withholding_is_retired(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root, config, _, _, _ = environment
    without_evidence(environment)
    policy = to_dict(config)
    policy["profiles"] = [profile for profile in policy["profiles"] if profile["id"] != WEB]
    root.write("policy.json", policy)

    result, _ = observed_pass(environment)

    assert planned(environment, WEB) == [("withdraw", "not-admitted"), ("drain", "not-admitted")]
    assert owned(backend) == [NAMES] and result["withheld"] == {NAMES: REASON}


@pytest.mark.parametrize(
    "change",
    [
        {"runtime_unknown": "retire"},
        {"interval_seconds": 11},
        {"cold_start": "self-heal"},
        {"allow_apple_dns_coexistence": True},
    ],
    ids=["the decision taken back", "another interval", "another decision", "the DNS exception"],
)
def test_an_installation_change_during_withholding_retires_every_rule(
    environment: Any, change: dict[str, Any]
) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root, _, settings, _, _ = environment
    without_evidence(environment)
    assert owned(backend) == sorted(HOST_PATHS)
    changed = replace(settings, **change)
    root.write("installation.json", changed.to_dict())

    result, report = observed_pass(environment)

    kept = "interval_seconds" in change
    # The interval is not part of an admission; everything else voids every one.
    assert (owned(backend) == sorted(HOST_PATHS)) is kept
    if not kept:
        assert backend.rules == "" and "withheld" not in result
        assert planned(environment, WEB)[0] == ("withdraw", "not-admitted")
        assert all(item.data["admitted"] is False for item in report.profiles.values())


@pytest.mark.parametrize("decided", [True, False], ids=["chosen", "taken back"])
def test_changing_the_decision_voids_every_admission(
    environment: Any, tmp_path: Any, monkeypatch: pytest.MonkeyPatch, decided: bool
) -> None:
    backend = Sockets()
    environment = site(environment, backend, decision=not decided)
    root, config, settings, _, _ = environment
    assert observed_pass(environment)[0]["phase"] == "committed"
    changed = replace(settings, runtime_unknown=KEY if decided else "retire")
    # Through the installer, as an administrator changes an installation.
    monkeypatch.setattr(owner, "protected_ancestors", lambda *args, **kwargs: None)
    policy, setting = tmp_path / "policy", tmp_path / "settings"
    policy.write_bytes(canonical_bytes(to_dict(config)))
    setting.write_bytes(canonical_bytes(changed.to_dict()))

    installed = install(root.directory, policy, setting, ROOT / "platform/macos/pf/backend.sh")

    # The installer stores the decision, keeps the approvals and says that none
    # of them holds now.
    assert (b"runtime_unknown" in (root.directory / "installation.json").read_bytes()) is decided
    assert installed["admissions_preserved"]
    assert sorted(installed["pending"]) == list(EVERY_PROFILE)
    result, report = observed_pass(environment)

    assert result["phase"] == "inhibited" and sorted(result["pending"]) == list(EVERY_PROFILE)
    assert backend.rules == "" and ready(report) == []
    assert all(item.data["admitted"] is False for item in report.profiles.values())


# ---- the order of a pass: the judgement stands before every action


class Watching(Sockets):
    """Notes, at each read of the judgement, what the pass had recorded and issued by then."""

    def __init__(self, root: Any) -> None:
        super().__init__()
        self.root = root
        self.noted: list[tuple[str, str, bool, list[tuple[str, ...]]]] = []

    def note(self, read: str) -> None:
        journal = self.root.read("journal.json")
        self.noted.append((read, journal["phase"], "started_at" in journal, written(self)))

    def reference_held(self) -> bool:
        self.note("reference")
        return super().reference_held()

    def socket_inventory(self, protocol: str) -> tuple[Row, ...]:
        self.note(protocol)
        return super().socket_inventory(protocol)


def test_the_judgement_precedes_every_action_of_the_pass(environment: Any) -> None:
    backend = Watching(environment[0])
    environment = loaded(site(environment, backend))
    direct, media = (
        address(environment, "camera"),
        address(environment, "media-controller"),
    )
    root = environment[0]
    # A LAN client's state of each guest rule: both are invalidated by the pass.
    backend.flow_states = "\n".join(
        [
            f"all tcp 192.0.2.77:54321 -> {direct}:53 ESTABLISHED:ESTABLISHED",
            f"all udp {media}:45001 -> 192.0.2.77:7000 SINGLE:MULTIPLE",
        ]
    )
    backend.noted.clear()

    result, _ = without_evidence(environment)

    assert result["changed"] == RETIRED and result["withheld"] == HOST_PATHS
    # What a pass reads to judge: the enable reference, then one inventory for
    # each protocol of a candidate. Nothing had been written at any of the
    # three: the journal held the first record of the pass, its plan.
    assert backend.noted[:3] == [
        ("reference", "applying", True, []),
        ("udp", "applying", True, []),
        ("tcp", "applying", True, []),
    ]
    # Both withdrawals and both invalidations follow. The read after them is
    # the reference readback that ends every pass.
    everything = [("replace",), ("replace",), ("drain", direct), ("drain", media)]
    assert backend.noted[3:] == [("reference", "applying", True, everything)]
    # The plan of record has the order it always had: every withdrawal, then
    # every drain, the two host paths among the others.
    operations = [
        (item["profile"], item["operation"]) for item in root.read("journal.json")["actions"]
    ]
    assert [item for item in operations if item[1] != "blocked"] == [
        *((key, "withdraw") for key in EVERY_PROFILE),
        *((key, "drain") for key in EVERY_PROFILE),
    ]


def test_the_judgement_precedes_an_activation_of_another_profile_too(environment: Any) -> None:
    backend = Watching(environment[0])
    environment = loaded(site(environment, backend))
    snapshots = environment[4]
    verified = snapshots[-1]
    # The pair is retired by a pass that has no evidence for its service alone ...
    snapshots.append(unknown(verified, "media-controller"))
    assert observed_pass(environment)[0]["changed"] == [f"{PAIR}:withdraw", f"{PAIR}:drain"]
    backend.commands.clear()
    backend.noted.clear()

    # ... and activated again by a pass that has none for the web proxy.
    snapshots.append(unknown(verified, "web-proxy"))
    result, report = observed_pass(environment)

    assert result["changed"] == [f"{PAIR}:activate"] and result["withheld"] == {WEB: REASON}
    # The web path was judged before the pair was loaded, and kept.
    assert backend.noted[:2] == [("reference", "applying", True, []), ("tcp", "applying", True, [])]
    assert written(backend) == [("replace",)]
    assert ready(report) == [DIRECT, NAMES, PAIR]


@pytest.mark.parametrize("decision", [False, True], ids=["without", "with the decision"])
def test_a_pass_without_a_candidate_has_the_order_it_always_had(
    environment: Any, decision: bool
) -> None:
    backend = Watching(environment[0])
    environment = loaded(site(environment, backend, decision=decision))
    root = environment[0]
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    backend.noted.clear()

    result, _ = observed_pass(environment)

    # A pause retires the host paths with everything else: every withdrawal, then
    # every drain, each in the order of the plan, with or without the decision.
    assert result["changed"] == [
        *(f"{key}:withdraw" for key in EVERY_PROFILE),
        *(f"{key}:drain" for key in EVERY_PROFILE),
    ]
    operations = [
        (item["profile"], item["operation"]) for item in root.read("journal.json")["actions"]
    ]
    assert operations == [
        *((key, "withdraw") for key in EVERY_PROFILE),
        *((key, operation) for key in EVERY_PROFILE for operation in ("drain", "blocked")),
    ]
    assert written(backend) == [("replace",)] * 4 and inventory_reads(backend) == []
    # Nothing is read for a judgement that is not made: neither the inventory
    # nor the reference, which a pass that leaves no rule loaded does not read.
    assert backend.noted == []


# ---- the other ways a pass ends


class Failing(Sockets):
    """A kernel whose next rule load fails."""

    fail = False

    def replace(self, expected: str, candidate: str) -> str:
        if self.fail:
            self.fail = False
            raise PFError("bounded PF backend operation failed")
        return super().replace(expected, candidate)


def test_a_pass_that_fails_after_the_judgement_reports_nothing_as_kept(
    environment: Any,
) -> None:
    backend = Failing()
    environment = loaded(site(environment, backend))
    root, _, _, _, snapshots = environment
    rules = backend.rules
    snapshots.append(unknown(snapshots[-1]))
    backend.fail = True

    with pytest.raises(PFError, match="bounded PF backend operation failed"):
        observed_pass(environment)

    # The two host paths were judged, and kept. Then the first withdrawal of a
    # guest rule failed. Nothing is reported as kept: the journal is `failed`
    # and names no withheld profile, and every rule is loaded as it was.
    assert inventory_reads(backend) == ["udp", "tcp"] and backend.rules == rules
    journal = root.read("journal.json")
    assert journal["phase"] == "failed" and "withheld" not in journal
    # The acknowledgement that is owed now retires every rule on the next pass.
    backend.commands.clear()
    result, _ = observed_pass(environment)
    assert result["phase"] == "failed" and backend.rules == "" and "withheld" not in result
    assert inventory_reads(backend) == []


def test_a_state_table_that_cannot_be_read_retires_every_rule_as_before(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root = environment[0]
    backend.flow_states = "not a state row"

    result, _ = without_evidence(environment)

    assert result["phase"] == "failed" and backend.rules == ""
    assert root.read("journal.json")["reason"] == "kernel-state-unknown"
    assert inventory_reads(backend) == []


def test_a_journal_that_awaits_its_acknowledgement_retires_every_rule(environment: Any) -> None:
    backend = Sockets()
    environment = loaded(site(environment, backend))
    root = environment[0]
    without_evidence(environment)
    assert owned(backend) == sorted(HOST_PATHS)
    root.write("journal.json", {"schema_version": 1, "phase": "failed"})

    result, report = observed_pass(environment)

    assert result["phase"] == "failed" and backend.rules == "" and "withheld" not in result
    assert planned(environment, WEB)[0] == ("withdraw", "intent-damaged")
    assert ready(report) == [] and inventory_reads(backend)[2:] == []


# ---- condition 5: the owner's enable reference is held, and is never taken for a kept rule


class Lossy(Sockets):
    """Another tool can take the enable reference away: a complete read, not listed.

    Each readback is noted. A readback can be made to fail, from a chosen one
    on, and the reference can be made to go right after a chosen readback that
    still lists it. A reference that is taken is noted with the rules that were
    loaded at that moment.
    """

    def __init__(self) -> None:
        super().__init__()
        self.reference_listed = True
        self.readbacks = 0
        self.unread: Exception | None = None
        self.unread_from = 1
        self.unread_once = False
        self.last_listing: int | None = None
        self.taken: list[list[str]] = []

    def lose_after(self, readbacks: int) -> None:
        """The reference goes right after that many further readbacks, the last that lists it."""
        self.readbacks, self.last_listing = 0, readbacks

    def fail_from(self, readback: int, error: Exception, *, once: bool = False) -> None:
        """Every readback from that further one on fails, or that one alone."""
        self.readbacks, self.unread, self.unread_from = 0, error, readback
        self.unread_once = once

    def reference_held(self) -> bool:
        self.readbacks += 1
        self.commands.append(("held",))
        if self.unread is not None and (
            self.readbacks == self.unread_from
            if self.unread_once
            else self.readbacks >= self.unread_from
        ):
            raise self.unread
        listed = self.reference_listed
        if self.last_listing == self.readbacks:
            self.reference_listed = False
        return listed

    def ensure_reference(self) -> None:
        super().ensure_reference()
        if not self.reference_listed:
            self.taken.append(owned(self))
        self.reference_listed = True


def reads(backend: Any) -> list[str]:
    """The reads of the judgement and the writes of a pass, in the order they were made."""
    return [
        command[0]
        for command in backend.commands
        if command[0] in {"held", "inventory", "reference", "replace"}
    ]


UNREAD: dict[str, Exception | None] = {
    "not listed": None,
    "owner-error": PFError("bounded PF backend operation failed"),
    "os-error": OSError("no such tool"),
    "value-error": ValueError("not a listing"),
}


@pytest.mark.parametrize("reacquire", [False, True], ids=["verify", "reacquire"])
@pytest.mark.parametrize("readback", UNREAD)
def test_a_host_path_is_kept_only_under_a_held_enable_reference(
    environment: Any, readback: str, reacquire: bool
) -> None:
    backend = Lossy()
    environment = site(environment, backend)
    if reacquire:
        environment = decided(environment, enable_reference="reacquire")
    environment = loaded(environment)
    root = environment[0]
    # Another tool disabled PF, or the readback of the reference fails.
    backend.reference_listed = UNREAD[readback] is not None
    backend.unread = UNREAD[readback]
    backend.commands.clear()

    result, report = without_evidence(environment)

    # A loaded rule carries nothing while PF is disabled, and the owner does not
    # enable PF for a rule it has no evidence for. A reference that is not held,
    # and one that could not be read, keep nothing: both host paths are retired
    # with the guest rules, where the plan has them.
    assert result == {
        "schema_version": 1,
        "phase": "inhibited",
        "changed": [
            *(f"{key}:withdraw" for key in EVERY_PROFILE),
            *(f"{key}:drain" for key in EVERY_PROFILE),
        ],
        "pending": list(EVERY_PROFILE),
    }
    assert backend.rules == "" and ready(report) == []
    # One readback, before anything was written; the inventory is not read after
    # it, and nothing is taken, whatever the installation chose for a lost one.
    assert reads(backend)[0] == "held" and backend.commands.count(("held",)) == 1
    assert inventory_reads(backend) == [] and backend.taken == []
    assert ("reference",) not in backend.commands and "reference" not in result
    assert "reason" not in root.read("journal.json")


def test_a_reference_read_that_was_refused_for_a_notice_keeps_nothing_and_is_named(
    environment: Any,
) -> None:
    backend = Lossy()
    environment = loaded(site(environment, backend))
    root = environment[0]
    backend.unread = owner.PFListingNotice("references", 3)

    result, _ = without_evidence(environment)

    # The outcome is that of a read that failed, and the journal says which it was.
    assert backend.rules == "" and "withheld" not in result
    assert inventory_reads(backend) == []
    assert root.read("journal.json")["reason"] == owner.LISTING_NOTICE


def retired_pair(environment: Any) -> Snapshot:
    """The pair retired by a pass without evidence for its service; the verified snapshot."""
    snapshots = environment[4]
    verified: Snapshot = snapshots[-1]
    snapshots.append(unknown(verified, "media-controller"))
    assert observed_pass(environment)[0]["changed"] == [f"{PAIR}:withdraw", f"{PAIR}:drain"]
    environment[3].commands.clear()
    return verified


def test_an_activation_beside_a_kept_rule_takes_no_reference(environment: Any) -> None:
    backend = Lossy()
    environment = loaded(site(environment, backend))
    verified = retired_pair(environment)

    # The pair is activated again by a pass that has no evidence for the web proxy.
    environment[4].append(unknown(verified, "web-proxy"))
    result, report = observed_pass(environment)

    assert result["changed"] == [f"{PAIR}:activate"] and result["withheld"] == {WEB: REASON}
    assert ready(report) == [DIRECT, NAMES, PAIR]
    # The reference is read back for the judgement, again right before the pair
    # is loaded, and at the end of the pass. It is held each time, and the one
    # call that can take it is not made while the web path is kept.
    assert reads(backend) == ["held", "inventory", "held", "replace", "held"]
    assert backend.taken == [] and "reference" not in result


LOST: dict[str, Callable[[Lossy], None]] = {
    "not listed any more": lambda backend: backend.lose_after(1),
    "a readback that fails": lambda backend: backend.fail_from(
        2, PFError("bounded PF backend operation failed")
    ),
}


@pytest.mark.parametrize("how", LOST)
def test_a_reference_lost_before_an_activation_retires_the_kept_rules_first(
    environment: Any, how: str
) -> None:
    backend = Lossy()
    environment = loaded(site(environment, backend))
    direct = address(environment, "camera")
    root = environment[0]
    verified = retired_pair(environment)
    # A LAN client's state of the guest rule that this pass retires, and a
    # connection of the host itself, which is nobody's to invalidate.
    backend.flow_states = "\n".join(
        [
            f"all tcp 192.0.2.77:54321 -> {direct}:53 ESTABLISHED:ESTABLISHED",
            f"all tcp {HOST}:50000 -> 203.0.113.9:443 ESTABLISHED:ESTABLISHED",
        ]
    )
    # The reference is held when the pass judges, and gone before the pair is loaded.
    LOST[how](backend)

    environment[4].append(unknown(verified, "resolver", "web-proxy", "camera"))
    result, report = observed_pass(environment)

    # Both host paths were kept at first. Before the reference is taken for the
    # pair they are retired: it is taken with no rule loaded that the pass has
    # no evidence for, as without the decision.
    assert result["changed"] == [
        f"{DIRECT}:withdraw",
        f"{DIRECT}:drain",
        f"{NAMES}:withdraw",
        f"{NAMES}:drain",
        f"{WEB}:withdraw",
        f"{WEB}:drain",
        f"{PAIR}:activate",
    ]
    assert "withheld" not in result and "withheld" not in root.read("journal.json")
    assert result["pending"] == [DIRECT, NAMES, WEB]
    assert reads(backend)[:3] == ["held", "inventory", "inventory"]
    assert reads(backend)[3:8] == ["replace", "held", "replace", "reference", "replace"]
    assert set(root.read("live.json")["records"]) == {PAIR} and owned(backend) == [PAIR, PAIR]
    for key in HOST_PATHS:
        assert report.profiles[key].state == "absent"
        assert "withheld" not in report.profiles[key].data
    # No state of the host's own address is invalidated for a host redirect,
    # also not by the drain that the plan has for the web path behind the pair.
    assert [command for command in backend.commands if command[0] == "drain"] == [("drain", direct)]
    if how == "not listed any more":
        # Taken once, with nothing loaded.
        assert backend.taken == [[]]


def test_a_readback_before_an_activation_that_was_refused_for_a_notice_is_named(
    environment: Any,
) -> None:
    backend = Lossy()
    environment = loaded(site(environment, backend))
    root = environment[0]
    verified = retired_pair(environment)
    # The readback before the pair is loaded, and that one alone, is refused.
    backend.fail_from(2, owner.PFListingNotice("references", 3), once=True)

    environment[4].append(unknown(verified, "web-proxy"))
    result, _ = observed_pass(environment)

    # As after a readback that failed: the kept rule is retired first. The pass
    # ends with the reference verified, and its journal names the notice.
    assert result["changed"] == [f"{WEB}:withdraw", f"{WEB}:drain", f"{PAIR}:activate"]
    assert "withheld" not in result and backend.taken == []
    assert root.read("journal.json")["reason"] == owner.LISTING_NOTICE


class Stopping(Lossy):
    """A kernel whose rule load fails at a chosen one."""

    loads = 0
    fail_at = 0

    def replace(self, expected: str, candidate: str) -> str:
        self.loads += 1
        if self.loads == self.fail_at:
            raise PFError("bounded PF backend operation failed")
        return super().replace(expected, candidate)


def test_kept_rules_that_were_retired_for_the_reference_are_recorded_before_the_next_write(
    environment: Any,
) -> None:
    backend = Stopping()
    environment = loaded(site(environment, backend))
    root = environment[0]
    verified = retired_pair(environment)
    backend.lose_after(1)
    # The web path is kept, then retired before the reference is taken for the
    # pair; and the load of the pair, the write after that, fails.
    backend.loads, backend.fail_at = 0, 2
    environment[4].append(unknown(verified, "web-proxy"))

    with pytest.raises(PFError, match="bounded PF backend operation failed"):
        observed_pass(environment)

    # The records say what the kernel holds: the web path went with its rule.
    assert WEB not in owned(backend) and WEB not in root.read("live.json")["records"]
    assert backend.normalize(owner.compose_rules(root.read("live.json")["records"])) == (
        backend.normalize(backend.rules)
    )
    assert backend.taken == [[DIRECT, NAMES]]
    # So the next pass is not stopped by a drift of its own making: it owes an
    # acknowledgement and retires what is left.
    result, _ = observed_pass(environment)
    assert result["phase"] == "failed" and backend.rules == ""


class Died(BaseException):
    """The process is gone: nothing of the pass runs after it."""


class Dying(Lossy):
    """A kernel that takes a chosen rule load, right after which the process dies.

    The two files of the pass are noted as they are at that moment. The handler
    of a pass that fails runs for an exception, not for a process that was
    killed, so a test puts them back.
    """

    loads = 0
    die_at = 0
    disk: Any = None
    left: dict[str, Any]

    def replace(self, expected: str, candidate: str) -> str:
        taken = super().replace(expected, candidate)
        self.loads += 1
        if self.loads == self.die_at:
            self.left = {name: self.disk.read(name) for name in ("journal.json", "live.json")}
            raise Died
        return taken


def test_a_pass_that_dies_right_after_retiring_the_kept_rules_is_taken_up_by_the_next(
    environment: Any,
) -> None:
    backend = Dying()
    environment = loaded(site(environment, backend))
    root = environment[0]
    verified = retired_pair(environment)
    backend.lose_after(1)
    # The web path is kept, then retired before the reference is taken for the
    # pair. The kernel takes that load, and the process dies.
    backend.disk, backend.loads, backend.die_at = root, 0, 1
    environment[4].append(unknown(verified, "web-proxy"))
    with pytest.raises(Died):
        observed_pass(environment)
    for name, content in backend.left.items():
        root.write(name, content)

    # The journal named the records without the web path before the kernel was
    # given the rules without it; the records still hold it.
    journal = root.read("journal.json")
    assert journal["phase"] == "applying"
    assert set(journal["candidate_records"]) == {DIRECT, NAMES}
    assert WEB in root.read("live.json")["records"] and WEB not in owned(backend)
    assert backend.taken == []
    # So the next pass takes the records from the journal instead of stopping
    # for a drift of the owner's own making. It owes an acknowledgement and
    # retires what is left.
    backend.die_at = 0
    result, _ = observed_pass(environment)
    assert result["phase"] == "failed" and backend.rules == ""
    assert not any(item["active"] for item in root.read("live.json")["records"].values())


class Ignoring(Lossy):
    """A kernel that answers a chosen rule load as done and has not taken it."""

    loads = 0
    ignore_at = 0

    def replace(self, expected: str, candidate: str) -> str:
        self.loads += 1
        if self.loads == self.ignore_at:
            self.commands.append(("replace",))
            return self.normalize(candidate)
        return super().replace(expected, candidate)


def test_kept_rules_whose_retirement_the_kernel_did_not_take_end_the_pass_before_the_reference(
    environment: Any,
) -> None:
    backend = Ignoring()
    environment = loaded(site(environment, backend))
    root = environment[0]
    verified = retired_pair(environment)
    backend.lose_after(1)
    # The web path is kept, and the load that retires it before the reference
    # is taken for the pair leaves the kernel as it was.
    backend.loads, backend.ignore_at = 0, 1
    environment[4].append(unknown(verified, "web-proxy"))

    with pytest.raises(PFError, match="PF write readback did not match candidate"):
        observed_pass(environment)

    # The retirement is read back like every write. The web path is still
    # loaded and recorded, and the reference was not taken beside it.
    assert WEB in owned(backend) and WEB in root.read("live.json")["records"]
    assert backend.taken == [] and ("reference",) not in backend.commands
    assert root.read("journal.json")["phase"] == "failed"
    # The next pass owes an acknowledgement and retires every rule.
    backend.ignore_at = 0
    result, _ = observed_pass(environment)
    assert result["phase"] == "failed" and backend.rules == ""


@pytest.mark.parametrize("reacquire", [False, True], ids=["verify", "reacquire"])
def test_a_reference_that_goes_after_its_readback_is_not_taken_beside_a_kept_rule(
    environment: Any, reacquire: bool
) -> None:
    backend = Lossy()
    environment = site(environment, backend)
    if reacquire:
        environment = decided(environment, enable_reference="reacquire")
    environment = loaded(environment)
    root = environment[0]
    verified = retired_pair(environment)
    # The readback before the pair is loaded is the last one that lists it.
    backend.lose_after(2)

    environment[4].append(unknown(verified, "web-proxy"))
    result, report = observed_pass(environment)

    # The pair is loaded, the web path is kept, and nothing was taken: the one
    # call that can take the reference is not made beside a kept rule, and the
    # end of a pass that keeps a rule does not take it either. The reference is
    # named as unverified and nothing is ready.
    assert result["changed"] == [f"{PAIR}:activate"] and result["withheld"] == {WEB: REASON}
    assert reads(backend) == ["held", "inventory", "held", "replace", "held"]
    assert backend.taken == [] and "reference" not in result
    assert root.read("journal.json")["reason"] == "enable-reference-unverified"
    assert ready(report) == []
    # The next pass finds the reference not held: the web path is retired.
    backend.commands.clear()
    result, _ = observed_pass(environment)
    assert result["changed"] == [f"{WEB}:withdraw", f"{WEB}:drain"] and "withheld" not in result
    assert inventory_reads(backend) == []
    # Then every rule that is loaded is verified, and the reference is taken
    # again where the installation chose that, and nowhere else.
    assert ("reference" in result) is reacquire
    assert backend.taken == ([[DIRECT, NAMES, PAIR, PAIR]] if reacquire else [])


def test_a_pass_that_keeps_a_rule_does_not_take_the_reference_at_its_end(
    environment: Any,
) -> None:
    backend = Lossy()
    environment = loaded(decided(site(environment, backend), enable_reference="reacquire"))
    root = environment[0]
    verified = environment[4][-1]
    backend.commands.clear()
    # Held when the pass judges, gone right after; and the final observation of
    # the pass has every piece of evidence again.
    backend.lose_after(1)
    observations = [unknown(verified), verified]

    result, report = observed_pass(environment, lambda config, settings: observations.pop(0))

    # The final plan verifies the two kept rules, which is what taking a lost
    # reference again needs. A pass that kept a rule does not take it all the
    # same: the two rules stay withheld and the reference is named.
    assert result["withheld"] == HOST_PATHS and result["changed"] == RETIRED
    assert backend.taken == [] and "reference" not in result
    assert ("reference",) not in backend.commands
    assert root.read("journal.json")["reason"] == "enable-reference-unverified"
    assert ready(report) == []
    # The next pass has that evidence from its start: nothing is kept, the two
    # independent guest paths activate again. The first takes the reference
    # with only rules loaded that this pass verified; the second reuses it.
    result, report = observed_pass(environment, lambda config, settings: verified)
    assert "withheld" not in result
    assert backend.taken == [sorted(HOST_PATHS)]
    assert result["changed"] == [f"{DIRECT}:activate", f"{PAIR}:activate"]
    assert set(HOST_PATHS) <= set(ready(report))


@pytest.mark.parametrize("heal", [False, True], ids=["administrator", "self-heal"])
def test_a_reboot_leaves_no_kept_rule_and_nothing_brings_one_back(
    environment: Any, heal: bool
) -> None:
    backend = Sockets()
    backend.session = FIRST
    environment = site(environment, backend)
    if heal:
        environment = decided(environment, cold_start="self-heal")
    environment = loaded(environment)
    root = environment[0]
    without_evidence(environment)
    assert owned(backend) == sorted(HOST_PATHS)
    assert root.read("journal.json")["boot_session"] == FIRST
    backend.commands.clear()

    # Another boot: the kernel has no rule, and the two records are still active.
    reboot(backend)
    if not heal:
        # As for every loaded rule, the administrator decides; nothing is written.
        with pytest.raises(PFError, match="owned PF rules drifted"):
            observed_pass(environment)
        assert written(backend) == [] and inventory_reads(backend) == []
        return
    result, report = observed_pass(environment)

    # The records go with the kernel that held their rules. Nothing is kept,
    # because nothing is loaded, and nothing is activated without evidence.
    assert root.read("live.json")["records"] == {} and backend.rules == ""
    assert result == {
        "schema_version": 1,
        "phase": "inhibited",
        "changed": [],
        "pending": list(EVERY_PROFILE),
    }
    assert ready(report) == [] and inventory_reads(backend) == [] and written(backend) == []


class Both(Inventory, Ordered):
    """The kernel of the translation-order tests with a socket inventory."""


def test_both_withholding_reasons_are_reported_in_one_shape(environment: Any) -> None:
    backend = Both()
    environment = loaded(decided(site(environment, backend), translation_order="verified"))
    # A sibling anchor translates, and the web proxy cannot be read.
    backend.siblings[SIBLING] = FOREIGN_TRANSLATION

    result, report = without_evidence(environment, "web-proxy")

    expected = {PAIR: "translation-order-unverified", WEB: REASON}
    assert result["changed"] == [] and list(result["withheld"]) == [PAIR, WEB]
    assert_withheld(environment, result, report, expected)
    assert ready(report) == [DIRECT, NAMES]


@pytest.mark.parametrize("decision", [False, True], ids=["without", "with the decision"])
def test_a_withheld_pair_that_the_final_plan_blocks_is_pending_as_it_was(
    environment: Any, decision: bool
) -> None:
    backend = Both()
    environment = loaded(
        decided(site(environment, backend, decision=decision), translation_order="verified")
    )
    verified = environment[4][-1]
    backend.siblings[SIBLING] = FOREIGN_TRANSLATION
    # The pass starts with verified evidence and ends without any for the pair's service.
    observations = [verified, unknown(verified, "media-controller")]

    result, _ = observed_pass(environment, lambda config, settings: observations.pop(0))

    # The pair keeps its rules and is withheld for its translation order. The
    # final plan of the pass blocks it, and it is listed as pending, as every
    # blocked profile is: only a kept host path is taken out of that list.
    assert observations == [] and result == {
        "schema_version": 1,
        "phase": "inhibited",
        "changed": [],
        "pending": [PAIR],
        "withheld": {PAIR: "translation-order-unverified"},
    }


# ---- seeded sequences


class Faulty(Lossy):
    """A kernel whose reference, state table and inventory can each fail on a pass."""


def evidence(rng: random.Random, verified: Snapshot) -> tuple[Snapshot, set[str]]:
    """What an observer hands back on one pass, and the host paths whose evidence only aged.

    Verified, or lacking in one of many ways. The second value names the host
    paths for which the snapshot holds verified evidence that is merely too
    old, each part of it taken at one time: the only evidence with a present
    service that can keep a rule.
    """
    kind = rng.choice(
        ["verified"] * 4 + ["service"] * 4 + ["services", "all", "unread", "aged", "aged", "stale"]
    )
    # A read that ran out of time twice as often as every finding together.
    reason = rng.choice(["timed-out"] * 2 * len(FINDINGS) + FINDINGS)
    if kind == "verified":
        return verified, set()
    if kind == "service":
        return unknown(verified, rng.choice(sorted(verified.services)), reason=reason), set()
    if kind == "services":
        return unknown(verified, *rng.sample(sorted(verified.services), 2), reason=reason), set()
    if kind == "all":
        return unknown(verified, reason=reason), set()
    if kind == "unread":
        return replace(unknown(verified, reason=reason), network_generation=None), set()
    if kind == "aged":
        return taken(verified, rng.choice([30.5, 45.0])), set(HOST_PATHS)
    # Too old or dated ahead in a way that is not merely age: a finding in it for
    # one host path, parts of it taken at different times, or no time at which
    # it was taken.
    key = rng.choice(sorted(HOST_PATHS))
    return rng.choice(
        [
            (
                taken(DEFINITE[rng.choice(STALE_FINDINGS)][0](verified, key), 30.5),
                set(HOST_PATHS) - {key},
            ),
            (replace(verified, observed_at=STAMP - rng.choice([30.5, 45.0])), set()),
            (aged(verified, rng.choice([30.5, -0.5])), set()),
            (taken(verified, -1.0), set()),
        ]
    )


def disturb(rng: random.Random, environment: Any, backend: Faulty) -> None:
    """One change of everything else a pass depends on."""
    root = environment[0]
    choice = rng.choice(
        [
            *["none"] * 5,
            *["restore"] * 3,
            *["listeners", "reference"] * 2,
            *["inventory", "pause", "resume", "hold", "admit", "lapse", "direct"],
        ]
    )
    if choice == "restore":
        # Everything a kept rule rests on is as it should be again.
        backend.sockets = {
            "tcp": [(HOST, 8080, 501, "forwarder", "IPv4")],
            "udp": [("*", 1053, 501, "forwarder", "IPv4")],
        }
        backend.unreadable = {}
        backend.reference_listed, backend.unread = True, None
        root.write("operator-intent.json", intent_to_dict(Intent()))
        admitted_earlier(environment)
    elif choice == "listeners":
        protocol = rng.choice(["tcp", "udp"])
        port = {"tcp": 8080, "udp": 1053}[protocol]
        backend.sockets[protocol] = rng.choice(
            [
                [(HOST, port, 501, "forwarder", "IPv4")],
                [("*", port, 501, "forwarder", "IPv4")],
                [],
                [("*", port, 501, "forwarder", "IPv6")],
                [("127.0.0.1", port, 501, "forwarder", "IPv4")],
                [(HOST, port + 1, 501, "forwarder", "IPv4")],
            ]
        )
    elif choice == "inventory":
        backend.unreadable = rng.choice([{}, {"tcp": PFError("x")}, {"udp": OSError("y")}])
    elif choice == "pause":
        root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    elif choice == "resume":
        root.write("operator-intent.json", intent_to_dict(Intent()))
    elif choice == "hold":
        service = rng.choice(["resolver", "web-proxy"])
        root.write(
            "operator-intent.json", intent_to_dict(Intent().hold(service, "maintenance", "h-1"))
        )
    elif choice == "reference":
        # Taken away by another tool; a readback that fails; or held again.
        listed, unread = rng.choice(
            [(False, None), (True, PFError("x")), (False, OSError("y")), (True, None)]
        )
        backend.reference_listed, backend.unread = listed, unread
    elif choice == "admit":
        # Long ago, or a moment ago: then after any evidence that is too old.
        admit(
            root,
            rng.choice(EVERY_PROFILE),
            acknowledge_bounded_risk=True,
            now=STAMP - rng.choice([90, 1]),
        )
    elif choice == "lapse":
        admissions = root.read("admissions.json")
        admissions["profiles"].pop(rng.choice(EVERY_PROFILE), None)
        root.write("admissions.json", admissions)
    elif choice == "direct":
        resolver = "198.51.100.10"
        backend.unavailable_guests = rng.choice([set(), {resolver}])


def guest_rules(backend: Any) -> list[str]:
    """The loaded rules that translate to an address other than the host's own."""
    return [
        line
        for line in backend.rules.splitlines()
        if f" -> {HOST} " not in line.split(" # netorch:")[0] + " "
    ]


REACHED = (
    "kept on a read that ran out of time",
    "kept on evidence that only aged",
    "judged and retired",
    "retired for the reference",
    "retired for what its evidence says",
    "activated",
    "activated beside a kept rule",
    "guest rule retired",
    "reference taken",
)


def sequence(environment: Any, seed: int, steps: int | None = None) -> dict[str, int]:
    """One seeded sequence of passes, every pass checked; what the sequence reached."""
    rng = random.Random(seed)
    backend = Faulty()
    environment = site(environment, backend)
    root, config, _, _, snapshots = environment
    verified = snapshots[-1]
    if rng.random() < 0.8:
        environment = admitted_earlier(loaded(environment))
    reached = dict.fromkeys(REACHED, 0)
    for step in range(steps or rng.randint(8, 14)):
        disturb(rng, environment, backend)
        seen, only_aged = evidence(rng, verified)
        snapshots.append(seen)
        before = owned(backend)
        held = backend.reference_listed and backend.unread is None
        approved = {
            key: item["approved_at"]
            for key, item in root.read("admissions.json")["profiles"].items()
        }
        backend.commands.clear()
        del backend.taken[:]
        try:
            result, report = observed_pass(environment)
        except PFError:
            continue
        context = (seed, step, result)
        withheld = result.get("withheld", {})
        assert root.read("journal.json").get("withheld", {}) == withheld, context
        for key in withheld:
            # A kept rule was loaded before, is a host path by its record and by
            # its rule, and is neither ready nor pending nor deferred nor written.
            record = root.read("live.json")["records"][key]
            assert withheld[key] == REASON and key in HOST_PATHS and key in before, context
            assert record["kind"] == "host-redirect" and record["target_ipv4"] == HOST, context
            assert owner._host_path(config, config.profile(key), record) is not None, context
            assert report.profiles[key].data["root_ready"] is False, context
            assert report.profiles[key].data["withheld"] == REASON, context
            assert key not in result["pending"] and key not in result.get("deferred", {}), context
            assert not any(change.startswith(f"{key}:") for change in result["changed"]), context
            # Of the rule's service the pass knew only that its read ran out of
            # time; or it had verified evidence that was merely too old, taken
            # after the profile's admission was given. Without a network
            # generation only the former.
            service = seen.services[config.profile(key).service]
            if service.state == "unknown":
                assert service.reason == "timed-out", context
                reached["kept on a read that ran out of time"] += 1
            else:
                assert service.state == "present" and key in only_aged, context
                assert seen.network_generation is not None, context
                assert approved[key] <= seen.observed_at < STAMP, context
                reached["kept on evidence that only aged"] += 1
            # Never under a reference that is not held, or that could not be read.
            assert held, context
        marked = {key for key, item in report.profiles.items() if "withheld" in item.data}
        assert marked == set(withheld), context
        # What the first observation of the pass verifies, taken at this moment.
        fresh = {
            key
            for key in EVERY_PROFILE
            if seen.network_generation is not None
            and seen.observed_at == STAMP
            and seen.services[config.profile(key).service].state == "present"
            and seen.services[config.profile(key).service].observed_at == STAMP
        }
        for change in result["changed"]:
            key, operation = change.split(":")
            if operation == "activate":
                # Only under verified evidence of its own service, never while kept.
                assert key in fresh and key not in withheld, context
                reached["activated"] += 1
                reached["activated beside a kept rule"] += bool(withheld)
            elif operation == "withdraw" and key in GUEST_PATHS:
                reached["guest rule retired"] += 1
            elif operation == "withdraw":
                judged = bool(inventory_reads(backend))
                reached["judged and retired"] += judged
                reached["retired for the reference"] += not judged and ("held",) in backend.commands
                reached["retired for what its evidence says"] += key not in only_aged and (
                    seen.services[config.profile(key).service].state == "present"
                    and seen.observed_at != STAMP
                )
        # The reference is taken only while every loaded rule has evidence of
        # this pass: never beside a kept rule, and never beside one that the
        # pass kept at first.
        for loaded_then in backend.taken:
            assert set(loaded_then) <= fresh, context
            reached["reference taken"] += 1
        if withheld:
            assert backend.taken == [] and ("reference",) not in backend.commands, context
        # Every rule that outlasts a pass which lacked the evidence for its
        # service is a kept host path: no rule that names a guest does.
        lacking = set(owned(backend)) - fresh
        assert lacking <= set(withheld), context
        for key in withheld:
            assert not any(line.endswith(f"netorch:{key}") for line in guest_rules(backend)), (
                context
            )
        if result["phase"] == "committed":
            assert not withheld, context
    return reached


@pytest.mark.parametrize("seed", range(30))
def test_seeded_passes_never_report_a_kept_rule_ready_keep_a_guest_rule_or_activate(
    environment: Any, seed: int
) -> None:
    sequence(environment, seed)


def test_one_long_seeded_sequence_reaches_every_outcome(environment: Any) -> None:
    reached = sequence(environment, 1, steps=120)

    assert all(count >= 1 for count in reached.values()), reached

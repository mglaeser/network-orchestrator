"""Isolated privileged-owner tests; no native network operations or root needed."""

from __future__ import annotations

import hashlib
import os
import plistlib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from netorch.codec import canonical_bytes, strict_loads
from netorch.config import load_config, profile_digest, to_dict
from netorch.model import Config, PortRange, Profile, Safety, Scope
from netorch.pf_owner import (
    STRATEGY,
    Installation,
    PFError,
    admit,
    admitted_digest,
    compose_rules,
    install,
    launchd_job,
    main,
    parse_socket_inventory,
    protected_ancestors,
    read_once,
    reconcile,
    render_profile,
    state_addresses,
)
from netorch.state import Intent, Observation, Snapshot, intent_to_dict
from netorch.storage import Busy, Store, UnsafeState

ROOT = Path(__file__).parents[1]
STAMP = 100.0


class FakeBackend:
    def __init__(self) -> None:
        self.rules = ""
        self.flow_states = ""
        self.commands: list[tuple[str, ...]] = []
        self.endpoint_valid = True
        self.unavailable_guests: set[str] = set()
        self.clear = True
        self.fail_after_replace = False
        self.undrainable = False

    def normalize(self, rules: str) -> str:
        return "\n".join(" ".join(line.split()) for line in rules.splitlines() if line.strip())

    def inspect(self) -> str:
        self.commands.append(("inspect",))
        return self.normalize(self.rules)

    def replace(self, expected: str, candidate: str) -> str:
        assert self.normalize(expected) == self.normalize(self.rules)
        self.rules = candidate
        self.commands.append(("replace",))
        if self.fail_after_replace:
            self.fail_after_replace = False
            raise PFError("simulated interrupted write")
        return self.normalize(candidate)

    def states(self) -> str:
        return self.flow_states

    def drain(self, ipv4: str) -> None:
        self.commands.append(("drain", ipv4))
        if self.undrainable:
            raise PFError("remaining states")
        self.flow_states = "\n".join(
            line for line, addresses in state_addresses(self.flow_states) if ipv4 not in addresses
        )

    def ensure_reference(self) -> None:
        self.commands.append(("reference",))

    def endpoint(self, scope: Scope, ipv4: str, mac: str | None, *, direct: bool) -> bool:
        self.commands.append(("endpoint", ipv4))
        return self.endpoint_valid and (not direct or ipv4 not in self.unavailable_guests)

    def ports_clear(self, scope: Scope, profile: Profile, *, apple_dns: bool) -> bool:
        return self.clear


@pytest.fixture
def environment(tmp_path: Path) -> tuple[Store, Config, Installation, FakeBackend, list[Snapshot]]:
    config = load_config(ROOT / "examples/network.json")
    backend_hash = hashlib.sha256((ROOT / "platform/macos/pf/backend.sh").read_bytes()).hexdigest()
    settings = Installation(
        "site-forwarding",
        "com.apple/netorch.site-forwarding",
        {"schema_version": 1, "account": "example"},
        backend_hash,
        str(tmp_path / "report.json"),
    )
    root = Store(tmp_path / "root")
    root.write("installation.json", settings.to_dict())
    root.write("policy.json", to_dict(config))
    root.write("admissions.json", {"schema_version": 1, "strategy": STRATEGY, "profiles": {}})
    root.write("operator-intent.json", intent_to_dict(Intent()))
    services = {
        service.id: Observation(
            "present",
            "verified",
            STAMP,
            "instance-1",
            {
                "ipv4": f"198.51.100.{10 + index}",
                "mac": "02:00:00:00:00:01",
                "contract_sha256": service.contract_sha256,
            },
        )
        for index, service in enumerate(config.services)
    }
    publications = {
        profile.id: Observation(
            "present",
            "verified",
            STAMP,
            "instance-1",
            {
                "target_ipv4": services[profile.service].data["ipv4"],
                "target_generation": "instance-1",
                "network_generation": "network-1",
                "policy_digest": profile_digest(config, profile),
                "states": (),
            },
        )
        for profile in config.profiles
        if profile.kind == "publication"
    }
    snapshots = [Snapshot(STAMP, "network-1", services, publications)]
    return root, config, settings, FakeBackend(), snapshots


def run_pass(
    environment: tuple[Store, Config, Installation, FakeBackend, list[Snapshot]],
) -> dict[str, Any]:
    root, _, _, backend, snapshots = environment
    return reconcile(
        root,
        lambda config, settings: snapshots[-1],
        lambda root, settings: backend,
        now=lambda: STAMP,
        report=lambda settings, snapshot: None,
    )


def approve_all(
    environment: tuple[Store, Config, Installation, FakeBackend, list[Snapshot]],
) -> None:
    root, config, settings, _, _ = environment
    for profile in config.profiles:
        if config.profile_owner(profile).id == settings.owner:
            admit(root, profile.id, acknowledge_bounded_risk=True, now=STAMP - 1)


def test_unadmitted_never_mutates(environment: Any) -> None:
    result = run_pass(environment)
    assert result["phase"] == "inhibited"
    assert len(result["pending"]) == 4
    assert not environment[3].rules
    assert not any(command[0] == "replace" for command in environment[3].commands)


def test_admitted_owner_converges_and_healthy_ticks_do_not_reload(environment: Any) -> None:
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    assert "static-port" in environment[3].rules
    before = sum(command[0] == "replace" for command in environment[3].commands)
    assert run_pass(environment)["phase"] == "committed"
    assert sum(command[0] == "replace" for command in environment[3].commands) == before


def test_changed_resolved_content_pending_not_id_only(environment: Any) -> None:
    approve_all(environment)
    run_pass(environment)
    root, config, _, backend, _ = environment
    changed = to_dict(config)
    changed["scopes"][0]["host_ipv4"] = "192.0.2.11"
    root.write("policy.json", changed)
    result = run_pass(environment)
    assert result["phase"] == "inhibited"
    assert backend.rules == ""
    assert len(result["pending"]) == 4


@pytest.mark.parametrize(
    "field,value",
    [
        ("interface", "example1"),
        ("lan_cidr", "192.0.2.0/25"),
        ("guest_cidr", "198.51.100.0/25"),
        ("contract_sha256", "f" * 64),
        ("ports", {"first": 54, "last": 54}),
        ("target_ports", {"first": 54, "last": 54}),
        ("max_age_seconds", 31),
        ("unknown_limit", 2),
        ("statement", "Changed bounded address-reuse residual requires its own review."),
    ],
)
def test_review_rule2_root_preserves_approval_but_not_changed_effective_authority(
    environment: Any, field: str, value: Any
) -> None:
    approve_all(environment)
    run_pass(environment)
    root, config, _, backend, _ = environment
    approvals = root.read("admissions.json")
    changed = to_dict(config)
    if field in {"interface", "lan_cidr", "guest_cidr"}:
        changed["scopes"][0][field] = value
    elif field == "contract_sha256":
        changed["services"][0][field] = value
    elif field in {"ports", "target_ports"}:
        changed["profiles"][0][field] = value
    else:
        changed["profiles"][0]["safety"][field] = value
    root.write("policy.json", changed)
    result = run_pass(environment)
    assert result["phase"] == "inhibited"
    assert root.read("admissions.json") == approvals
    assert "dns-udp" in result["pending"]
    assert "# netorch:dns-udp" not in backend.rules


def test_review_rule2_single_sourced_range_widening_cannot_amplify_root_admission(
    environment: Any,
) -> None:
    approve_all(environment)
    run_pass(environment)
    root, config, _, backend, _ = environment
    approvals = root.read("admissions.json")
    changed = to_dict(config)
    widened = {"first": 45000, "last": 45511}
    # This is the review's counterexample: renderer updates workload and root
    # parameters together, so cross-owner equality alone no longer protects it.
    next(item for item in changed["services"] if item["id"] == "media-controller")[
        "automatic_ports"
    ] = widened
    next(item for item in changed["profiles"] if item["id"] == "media-udp")["ports"] = widened
    root.write("policy.json", changed)
    result = run_pass(environment)
    assert result["phase"] == "inhibited" and "media-udp" in result["pending"]
    assert root.read("admissions.json") == approvals
    assert "static-port" not in backend.rules
    assert "45511" not in backend.rules


@pytest.mark.parametrize(
    "field,value",
    [
        ("backend_sha256", "e" * 64),
        ("observer", {"schema_version": 2}),
        ("allow_apple_dns_coexistence", True),
    ],
)
def test_root_strategy_observer_backend_change_invalidates_admission(
    environment: Any, field: str, value: Any
) -> None:
    approve_all(environment)
    run_pass(environment)
    root = environment[0]
    raw = root.read("installation.json")
    raw[field] = value
    root.write("installation.json", raw)
    assert run_pass(environment)["phase"] == "inhibited"
    assert not environment[3].rules


def test_unknown_runtime_withdraws_and_drains_both_directions(environment: Any) -> None:
    approve_all(environment)
    run_pass(environment)
    backend, snapshots = environment[3:]
    backend.flow_states = (
        "all udp 198.51.100.12:45001 -> 192.0.2.82:7000 NO_TRAFFIC:SINGLE\n"
        "all udp 192.0.2.82:7000 -> 198.51.100.12:45002 SINGLE:NO_TRAFFIC"
    )
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
    result = run_pass(environment)
    assert result["phase"] == "inhibited"
    assert not backend.rules and not backend.flow_states
    assert any(command == ("drain", "198.51.100.12") for command in backend.commands)


def test_network_generation_change_retires_before_new_activation(environment: Any) -> None:
    approve_all(environment)
    run_pass(environment)
    root, _, _, backend, snapshots = environment
    current = snapshots[-1]
    snapshots.append(replace(current, network_generation="network-2", profiles={}))
    first = run_pass(environment)
    assert not backend.rules
    assert not any("activate" in action for action in first["changed"])
    # Publication evidence must be refreshed by the independent runtime owner.
    fresh_profiles = {
        key: Observation(
            value.state,
            value.reason,
            value.observed_at,
            value.generation,
            {**value.data, "network_generation": "network-2"},
        )
        for key, value in current.profiles.items()
    }
    snapshots.append(replace(snapshots[-1], profiles=fresh_profiles))
    assert run_pass(environment)["phase"] == "committed"
    assert root.read("live.json")["records"]["media-udp"]["network_generation"] == "network-2"


def test_review_rule4_rebuilt_pool_redeals_old_target_but_retires_rules_and_states_first(
    environment: Any,
) -> None:
    from netorch.safety_contract import RotatingAllocatorModel

    root, config, _, backend, snapshots = environment
    first_pool = RotatingAllocatorModel(config.scopes[0].guest_cidr)
    current = snapshots[-1]
    services = {
        service.id: Observation(
            "present",
            "verified",
            STAMP,
            "instance-1",
            {
                **current.services[service.id].data,
                "ipv4": first_pool.allocate(service.id),
            },
        )
        for service in config.services
    }
    publications = {
        key: Observation(
            value.state,
            value.reason,
            STAMP,
            "instance-1",
            {
                **value.data,
                "target_ipv4": services[config.profile(key).service].data["ipv4"],
            },
        )
        for key, value in current.profiles.items()
    }
    snapshots.append(Snapshot(STAMP, "network-1", services, publications))
    approve_all(environment)
    run_pass(environment)
    old_target = services["media-controller"].data["ipv4"]
    assert isinstance(old_target, str)
    backend.flow_states = (
        f"all udp {old_target}:45001 -> 192.0.2.82:80 NO_TRAFFIC:SINGLE\n"
        f"all udp 192.0.2.82:80 -> {old_target}:45001 SINGLE:NO_TRAFFIC"
    )
    rebuilt = RotatingAllocatorModel(config.scopes[0].guest_cidr)
    replacement_addresses = {
        service.id: rebuilt.allocate(service.id) for service in reversed(config.services)
    }
    assert replacement_addresses["media-controller"] != old_target
    assert old_target in replacement_addresses.values()
    new_services = {
        service.id: Observation(
            "present",
            "verified",
            STAMP,
            "instance-2",
            {
                **services[service.id].data,
                "ipv4": replacement_addresses[service.id],
            },
        )
        for service in config.services
    }
    new_publications = {
        key: Observation(
            value.state,
            value.reason,
            STAMP,
            "instance-2",
            {
                **value.data,
                "target_generation": "instance-2",
                "network_generation": "network-2",
                "target_ipv4": new_services[config.profile(key).service].data["ipv4"],
            },
        )
        for key, value in publications.items()
    }
    snapshots.append(Snapshot(STAMP, "network-2", new_services, new_publications))
    first = run_pass(environment)
    assert not backend.rules and not backend.flow_states
    assert ("drain", old_target) in backend.commands
    assert not any("activate" in action for action in first["changed"])
    assert run_pass(environment)["phase"] == "committed"
    assert (
        root.read("live.json")["records"]["media-udp"]["target_ipv4"]
        == (replacement_addresses["media-controller"])
    )


@pytest.mark.parametrize("reason", ["timed-out", "stale", "local-network-denied", "busy"])
def test_review_rule6_uncertainty_retires_without_becoming_recovery(
    environment: Any, reason: str
) -> None:
    approve_all(environment)
    run_pass(environment)
    root, _, _, backend, snapshots = environment
    backend.flow_states = (
        "all udp 198.51.100.12:45001 -> 192.0.2.82:80 NO_TRAFFIC:SINGLE\n"
        "all udp 192.0.2.82:80 -> 198.51.100.12:45001 SINGLE:NO_TRAFFIC"
    )
    snapshots.append(
        Snapshot(
            STAMP,
            None,
            {key: Observation("unknown", reason, STAMP, None) for key in snapshots[-1].services},
            {},
        )
    )
    result = run_pass(environment)
    assert result["phase"] == "inhibited"
    assert not backend.rules and not backend.flow_states
    assert all(
        command[0] in {"inspect", "replace", "drain", "reference", "endpoint"}
        for command in backend.commands
    )
    assert root.read("journal.json")["phase"] == "inhibited"


def test_paused_intent_survives_suspension_release(environment: Any) -> None:
    approve_all(environment)
    run_pass(environment)
    root = environment[0]
    intent = Intent().pause().suspend("maintenance", "manager").release("maintenance", "manager")
    root.write("operator-intent.json", intent_to_dict(intent))
    assert run_pass(environment)["phase"] == "inhibited"
    assert root.read("operator-intent.json")["operator_paused"]
    assert not environment[3].rules


def test_external_intent_can_only_inhibit_already_admitted_authority(
    environment: Any, tmp_path: Path
) -> None:
    approve_all(environment)
    root = environment[0]
    external = Store(tmp_path / "user")
    external.write("intent.json", intent_to_dict(Intent().pause()))
    raw = root.read("installation.json")
    raw["intent_path"] = str(external.directory / "intent.json")
    root.write("installation.json", raw)
    assert run_pass(environment)["phase"] == "inhibited"
    assert not environment[3].rules
    external.write("intent.json", intent_to_dict(Intent().resume()))
    assert run_pass(environment)["phase"] == "committed"


def test_partial_pf_write_is_retired_and_requires_ack(environment: Any) -> None:
    approve_all(environment)
    root, _, _, backend, _ = environment
    backend.fail_after_replace = True
    with pytest.raises(PFError):
        run_pass(environment)
    assert root.read("journal.json")["phase"] == "failed"
    assert backend.rules
    assert run_pass(environment)["phase"] == "failed"
    assert not backend.rules
    assert run_pass(environment)["phase"] == "failed"
    journal = root.read("journal.json")
    journal["phase"] = "acknowledged"
    root.write("journal.json", journal)
    assert run_pass(environment)["phase"] == "committed"


def test_drift_is_not_overwritten(environment: Any) -> None:
    approve_all(environment)
    environment[3].rules = "rdr on en9 inet proto tcp from any to any port 12 -> 192.0.2.20\n"
    with pytest.raises(PFError, match="drift"):
        run_pass(environment)
    assert not any(command[0] == "replace" for command in environment[3].commands)


@pytest.mark.parametrize("failure", ["endpoint", "ports"])
def test_unverified_kernel_endpoint_or_coexistence_blocks_activation(
    environment: Any, failure: str
) -> None:
    approve_all(environment)
    if failure == "endpoint":
        environment[3].endpoint_valid = False
    else:
        environment[3].clear = False
    with pytest.raises(PFError):
        run_pass(environment)
    assert not environment[3].rules
    assert environment[0].read("journal.json")["phase"] == "failed"


def test_observer_exception_becomes_unknown_and_never_recovers(environment: Any) -> None:
    approve_all(environment)
    run_pass(environment)
    root, _, _, backend, snapshots = environment
    calls = 0

    def observe(config: Config, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise PFError("runtime inaccessible")
        return Snapshot(
            STAMP,
            None,
            {
                key: Observation("unknown", "inaccessible", STAMP, None)
                for key in snapshots[-1].services
            },
            {},
        )

    result = reconcile(
        root,
        observe,
        lambda root, settings: backend,
        now=lambda: STAMP,
        report=lambda settings, snapshot: None,
    )
    assert result["phase"] == "inhibited"
    assert not backend.rules


def test_root_owner_cannot_claim_publication(environment: Any) -> None:
    root, config, _, _, _ = environment
    raw = to_dict(config)
    raw["profiles"][2]["owner"] = "site-forwarding"
    root.write("policy.json", raw)
    with pytest.raises(PFError, match="publication"):
        run_pass(environment)


def test_removed_profile_retires_old_rules_and_states(environment: Any) -> None:
    approve_all(environment)
    run_pass(environment)
    root, config, _, _backend, _ = environment
    raw = to_dict(config)
    raw["profiles"] = [p for p in raw["profiles"] if p["id"] != "dns-tcp"]
    root.write("policy.json", raw)
    result = run_pass(environment)
    assert "dns-tcp:withdraw" in result["changed"]
    assert "dns-tcp" not in root.read("live.json")["records"]
    assert "dns-tcp" not in root.read("live.json")["records"]


@pytest.mark.parametrize(
    "field,value", [("schema_version", True), ("extra", 1), ("strategy", "unknown")]
)
def test_damaged_admission_is_not_trusted(environment: Any, field: str, value: Any) -> None:
    raw = environment[0].read("admissions.json")
    raw[field] = value
    environment[0].write("admissions.json", raw)
    assert run_pass(environment)["phase"] == "failed"
    assert not environment[3].rules


def test_bounded_admission_needs_explicit_risk_ack(environment: Any) -> None:
    with pytest.raises(PFError, match="risk"):
        admit(environment[0], "media-udp", acknowledge_bounded_risk=False)
    assert environment[0].read("admissions.json")["profiles"] == {}


def test_foreign_publication_cannot_be_admitted(environment: Any) -> None:
    with pytest.raises(PFError):
        admit(environment[0], "camera-web", acknowledge_bounded_risk=True)


def test_kernel_lock_cannot_be_stolen(environment: Any) -> None:
    with environment[0].lock(), pytest.raises(Busy):
        run_pass(environment)


def test_rule_renderer_static_port_and_targetless_rdr(environment: Any) -> None:
    config = environment[1]
    rules = render_profile(config, config.profile("media-udp"), "198.51.100.12")
    assert "static-port" in rules
    assert "-> 198.51.100.12 # netorch:media-udp\n" in rules
    assert "-> 198.51.100.12 port" not in rules
    with pytest.raises(PFError):
        render_profile(config, config.profile("camera-web"), "198.51.100.12")


def test_compose_keeps_nat_before_rdr() -> None:
    output = compose_rules({"z": {"rules": "nat x\nrdr y\n"}, "a": {"rules": "rdr z\n"}})
    assert output == "nat x\nrdr z\nrdr y\n"


@pytest.mark.parametrize(
    "raw",
    [
        "warning: kernel generation changed",
        "all udp 999.0.0.1:2 -> 192.0.2.1:3 X:Y",
        "all udp x y z",
        "all nonsense 192.0.2.1:2 -> 192.0.2.2:3 X:Y",
    ],
)
def test_incomplete_states_are_unknown(raw: str) -> None:
    with pytest.raises(PFError):
        state_addresses(raw)


def test_valid_empty_state_read_is_absent() -> None:
    assert state_addresses("") == ()


def test_no_live_entrypoint_without_its_native_owner(capsys: Any, tmp_path: Path) -> None:
    assert main(["reconcile", "--root-dir", str(tmp_path)]) == 78
    assert "stage-not-qualified" in capsys.readouterr().err


def test_launchd_schedule_has_no_rpc_or_sudo_grant(environment: Any) -> None:
    job = plistlib.loads(
        launchd_job(
            environment[2],
            Path("/Library/Application Support/netorch/pf"),
            Path("/opt/netorch/bin/python"),
        )
    )
    assert job["StartInterval"] == 10 and job["RunAtLoad"]
    assert job["ProgramArguments"][1:5] == ["-I", "-m", "netorch.pf_owner", "reconcile"]
    assert "Sockets" not in job and "MachServices" not in job
    assert "sudo" not in str(job)


def test_read_once_rejects_symlink_and_hardlink(tmp_path: Path) -> None:
    original = tmp_path / "original"
    original.write_bytes(b"data")
    link = tmp_path / "link"
    link.symlink_to(original)
    with pytest.raises((UnsafeState, OSError)):
        read_once(link)
    link.unlink()
    os.link(original, link)
    with pytest.raises(UnsafeState):
        read_once(original)


def test_read_once_detects_path_swap(monkeypatch: Any, tmp_path: Path) -> None:
    original = tmp_path / "data"
    original.write_bytes(b"reviewed")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"unreviewed")
    actual = os.fdopen

    def swapping(fd: int, mode: str) -> Any:
        os.replace(replacement, original)
        return actual(fd, mode)

    monkeypatch.setattr(os, "fdopen", swapping)
    with pytest.raises(UnsafeState, match="changed"):
        read_once(original)


def test_read_once_bound_and_mode(tmp_path: Path) -> None:
    path = tmp_path / "input"
    path.write_bytes(b"12345")
    with pytest.raises(UnsafeState):
        read_once(path, maximum=4)
    path.chmod(0o600)
    assert read_once(path, uid=os.geteuid(), mode=0o600) == b"12345"
    with pytest.raises(UnsafeState):
        read_once(path, uid=os.geteuid() + 1)
    with pytest.raises(UnsafeState):
        read_once(path, mode=0o644)


def test_read_once_ignores_only_modeled_atime_updates(tmp_path: Path, monkeypatch: Any) -> None:
    path = tmp_path / "fresh-input"
    path.write_bytes(b"reviewed")
    actual = os.fstat
    calls = 0

    def metadata(fd: int) -> Any:
        nonlocal calls
        calls += 1
        original = actual(fd)
        if calls == 1:
            return original
        fields = {name: getattr(original, name) for name in dir(original) if name.startswith("st_")}
        fields["st_atime"] += 1.0
        fields["st_atime_ns"] += 1_000_000_000
        return SimpleNamespace(**fields)

    monkeypatch.setattr(os, "fstat", metadata)
    assert read_once(path) == b"reviewed"
    assert calls == 2


@pytest.mark.parametrize("mutation", ["content", "permission"])
def test_read_once_rejects_same_inode_mutations(
    tmp_path: Path, monkeypatch: Any, mutation: str
) -> None:
    path = tmp_path / "input"
    path.write_bytes(b"reviewed")
    initial = path.stat()
    actual = os.fdopen

    def mutate(fd: int, mode: str) -> Any:
        if mutation == "content":
            path.write_bytes(b"changed!")
            os.utime(path, ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000))
        else:
            path.chmod(0o666)
        assert path.stat().st_ino == initial.st_ino
        return actual(fd, mode)

    monkeypatch.setattr(os, "fdopen", mutate)
    with pytest.raises(UnsafeState, match="changed while being read"):
        read_once(path)


def test_read_once_fences_final_path_metadata_not_only_its_inode(
    tmp_path: Path, monkeypatch: Any
) -> None:
    path = tmp_path / "input"
    path.write_bytes(b"reviewed")
    actual = Path.lstat
    calls = 0

    def metadata(selected: Path) -> Any:
        nonlocal calls
        original = actual(selected)
        if selected != path:
            return original
        calls += 1
        if calls == 1:
            return original
        fields = {name: getattr(original, name) for name in dir(original) if name.startswith("st_")}
        fields["st_mode"] |= 0o020
        return SimpleNamespace(**fields)

    monkeypatch.setattr(Path, "lstat", metadata)
    with pytest.raises(UnsafeState, match="changed while being read"):
        read_once(path)


def test_installer_preserves_exact_admitted_set_and_intent(
    monkeypatch: Any, environment: Any, tmp_path: Path
) -> None:
    import netorch.pf_owner as module

    monkeypatch.setattr(module, "protected_ancestors", lambda *args, **kwargs: None)
    approve_all(environment)
    root, config, settings, _, _ = environment
    old_admissions = (root.directory / "admissions.json").read_bytes()
    root.write(
        "operator-intent.json", intent_to_dict(Intent().pause().suspend("operation", "holder"))
    )
    old_intent = (root.directory / "operator-intent.json").read_bytes()
    policy = tmp_path / "policy.json"
    changed = to_dict(config)
    changed["scopes"][0]["host_ipv4"] = "192.0.2.11"
    policy.write_bytes(canonical_bytes(changed))
    setting = tmp_path / "settings.json"
    setting.write_bytes(canonical_bytes(settings.to_dict()))
    result = install(root.directory, policy, setting, ROOT / "platform/macos/pf/backend.sh")
    assert result["admissions_preserved"] and len(result["pending"]) == 4
    assert (root.directory / "admissions.json").read_bytes() == old_admissions
    assert (root.directory / "operator-intent.json").read_bytes() == old_intent


def test_new_install_starts_paused_and_unadmitted(
    monkeypatch: Any, environment: Any, tmp_path: Path
) -> None:
    import netorch.pf_owner as module

    monkeypatch.setattr(module, "protected_ancestors", lambda *args, **kwargs: None)
    policy, settings = tmp_path / "policy", tmp_path / "settings"
    policy.write_bytes(canonical_bytes(to_dict(environment[1])))
    settings.write_bytes(canonical_bytes(environment[2].to_dict()))
    destination = tmp_path / "new-root"
    result = install(destination, policy, settings, ROOT / "platform/macos/pf/backend.sh")
    store = Store(destination)
    assert result["installed"]
    assert store.read("operator-intent.json")["operator_paused"]
    assert store.read("admissions.json")["profiles"] == {}


def test_installer_rejects_changed_backend_before_new_admission(
    monkeypatch: Any, environment: Any, tmp_path: Path
) -> None:
    import netorch.pf_owner as module

    monkeypatch.setattr(module, "protected_ancestors", lambda *args, **kwargs: None)
    policy, settings, backend = tmp_path / "policy", tmp_path / "settings", tmp_path / "backend"
    policy.write_bytes(canonical_bytes(to_dict(environment[1])))
    settings.write_bytes(canonical_bytes(environment[2].to_dict()))
    backend.write_bytes(b"malicious")
    with pytest.raises(PFError, match="digest"):
        install(tmp_path / "new-root", policy, settings, backend)
    assert not (tmp_path / "new-root").exists()


HEADER = (
    "Proto Recv-Q Send-Q Local Address Foreign Address (state) rxbytes txbytes "
    "rhiwat shiwat process:pid state options gencnt flags flags1 usecnt rtncnt fltrs"
)


def socket_fixture(
    protocol: str = "udp", endpoint: str = "*.53", process: str = "mDNSResponder:555"
) -> str:
    prefix = f"{protocol}4 0 0 {endpoint} *.* "
    if protocol == "tcp":
        prefix += "LISTEN "
    return (
        "Active Internet connections (including servers)\n"
        + HEADER
        + "\n"
        + prefix
        + f"0 0 0 0 {process} 00000 00000000 0000000000000000 00000000 00000000 0 0 000000\n"
    )


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_socket_inventory_complete_numeric_rows(protocol: str) -> None:
    assert parse_socket_inventory(socket_fixture(protocol), protocol) == (
        ("*", 53, 555, "mDNSResponder", "IPv4"),
    )


@pytest.mark.parametrize(
    "mutation", ["warning", "bad-counter", "pid", "malformed-address", "short", "duplicate-header"]
)
def test_socket_schema_drift_never_means_absent(mutation: str) -> None:
    raw = socket_fixture()
    if mutation == "warning":
        raw += "WARNING socket generation changed\n"
    elif mutation == "bad-counter":
        raw = raw.replace("udp4 0 0", "udp4 nope 0")
    elif mutation == "pid":
        raw = raw.replace("mDNSResponder:555", "mDNSResponder:missing")
    elif mutation == "malformed-address":
        raw = raw.replace("*.53", "999.0.0.1.53")
    elif mutation == "short":
        raw = "Active Internet connections (including servers)"
    else:
        raw += HEADER
    with pytest.raises(PFError):
        parse_socket_inventory(raw, "udp")


def test_protected_ancestors_rejects_user_parent(tmp_path: Path) -> None:
    with pytest.raises(UnsafeState):
        protected_ancestors(tmp_path)


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"interval_seconds": 0},
        {"anchor": "com.apple/foreign"},
        {"owner": "foreign"},
        {"backend_sha256": "invalid"},
        {"report_path": "relative"},
        {"allow_apple_dns_coexistence": "yes"},
    ],
)
def test_installation_closed_and_validated(environment: Any, change: dict[str, Any]) -> None:
    raw = {**environment[2].to_dict(), **change}
    with pytest.raises((PFError, ValueError)):
        Installation.from_dict(raw)


def test_corrupt_admission_with_existing_rules_fails_closed(environment: Any) -> None:
    approve_all(environment)
    run_pass(environment)
    environment[0].write("admissions.json", {"schema_version": True})
    assert run_pass(environment)["phase"] == "failed"
    assert not environment[3].rules


def test_structural_host_redirect_never_kills_hostwide_states(environment: Any) -> None:
    approve_all(environment)
    run_pass(environment)
    backend = environment[3]
    backend.flow_states = "all tcp 192.0.2.10:8123 <- 192.0.2.50:50000 ESTABLISHED:ESTABLISHED"
    environment[0].write("operator-intent.json", intent_to_dict(Intent().pause()))
    run_pass(environment)
    assert not any(command == ("drain", "192.0.2.10") for command in backend.commands)
    assert backend.flow_states


def test_admission_checks_the_operator_reviewed_digest(environment: Any) -> None:
    root, config, settings, _, _ = environment
    wanted = admitted_digest(config, config.profile("media-udp"), settings)
    with pytest.raises(PFError, match="digest"):
        admit(root, "media-udp", acknowledge_bounded_risk=True, expected_digest="f" * 64)
    assert root.read("admissions.json")["profiles"] == {}
    result = admit(root, "media-udp", acknowledge_bounded_risk=True, expected_digest=wanted, now=99)
    assert result["admitted"]["digest"] == wanted


def shell_backend(environment: Any, monkeypatch: Any) -> Any:
    from netorch.pf_owner import ShellBackend

    backend = object.__new__(ShellBackend)
    backend.root = environment[0]
    backend.installation = environment[2]
    backend.script = environment[0].directory / "backend.sh"
    return backend


def test_shellbackend_parses_rules_and_invokes_fixed_arguments(
    environment: Any, monkeypatch: Any
) -> None:
    import netorch.pf_owner as module
    from netorch.process import Result

    backend = shell_backend(environment, monkeypatch)
    seen: list[list[str]] = []

    def fake(argv: list[str], **kwargs: Any) -> Result:
        seen.append(argv)
        return Result(0, b"normalized\n", b"")

    monkeypatch.setattr(module, "run", fake)
    assert backend.normalize("rdr test\n") == "normalized"
    assert backend.replace("old\n", "new\n") == "normalized"
    assert backend.inspect() == "normalized"
    assert backend.states() == "normalized"
    assert all(command[:2] == ["/bin/bash", str(backend.script)] for command in seen)
    assert all(command[3] == "com.apple/netorch.site-forwarding" for command in seen)
    assert (environment[0].directory / "candidate.rules").read_text() == "new\n"
    monkeypatch.setattr(module, "run", lambda *a, **kw: Result(9, b"private", b"private"))
    with pytest.raises(PFError) as caught:
        backend.inspect()
    assert "private" not in str(caught.value)


def test_shellbackend_validates_installed_digest(environment: Any, monkeypatch: Any) -> None:
    import netorch.pf_owner as module
    from netorch.pf_owner import ShellBackend

    payload = (ROOT / "platform/macos/pf/backend.sh").read_bytes()
    original = module.read_once
    monkeypatch.setattr(module, "read_once", lambda path, **kwargs: payload)
    assert ShellBackend(environment[0], environment[2]).installation.owner == "site-forwarding"
    monkeypatch.setattr(module, "read_once", lambda path, **kwargs: b"changed")
    with pytest.raises(PFError, match="changed"):
        ShellBackend(environment[0], environment[2])
    monkeypatch.setattr(module, "read_once", original)


def test_shellbackend_reference_only_owns_its_exact_token(
    environment: Any, monkeypatch: Any
) -> None:
    backend = shell_backend(environment, monkeypatch)
    calls: list[str] = []

    def call(operation: str, *args: str) -> str:
        calls.append(operation)
        if operation == "enable":
            return "pf enabled\nToken : 18446744073709551615"
        return "123 owner 18446744073709551615 0 days 00:00:00"

    monkeypatch.setattr(backend, "_call", call)
    backend.ensure_reference()
    assert environment[0].read("reference.json")["token"] == "18446744073709551615"
    backend.ensure_reference()
    assert calls.count("enable") == 1
    environment[0].write("reference.json", {"token": "invalid"})
    with pytest.raises(PFError):
        backend.ensure_reference()


def test_shellbackend_unrecognized_reference_is_not_guessed(
    environment: Any, monkeypatch: Any
) -> None:
    backend = shell_backend(environment, monkeypatch)
    monkeypatch.setattr(backend, "_call", lambda *args: "pf enabled without token")
    with pytest.raises(PFError):
        backend.ensure_reference()


def test_shellbackend_state_drain_requires_absent_readback(
    environment: Any, monkeypatch: Any
) -> None:
    backend = shell_backend(environment, monkeypatch)
    calls: list[tuple[str, ...]] = []

    def call(*args: str) -> str:
        calls.append(args)
        return "all udp 198.51.100.12:45001 -> 192.0.2.82:7000 X:Y" if args[0] == "states" else ""

    monkeypatch.setattr(backend, "_call", call)
    with pytest.raises(PFError, match="remain"):
        backend.drain("198.51.100.12")
    assert calls[0] == ("drain", "198.51.100.12")


@pytest.mark.parametrize("failure", ["interface", "forwarding", "route", "mac", "arp"])
def test_native_endpoint_invariants_use_only_bounded_mocked_commands(
    environment: Any, monkeypatch: Any, failure: str
) -> None:
    backend = shell_backend(environment, monkeypatch)
    scope = environment[1].scopes[0]
    outputs = {
        "/sbin/ifconfig": "en0: flags=1\n inet 192.0.2.10 netmask 0xffffff00\n",
        "/usr/sbin/sysctl": "1\n",
        "/sbin/route": "route to: 198.51.100.12\ninterface: bridge100\nflags: <HOST,LLINFO>\n",
        "/usr/sbin/arp": "? (198.51.100.12) at 2:0:0:0:0:1 on bridge100 ifscope [ethernet]\n",
    }
    monkeypatch.setattr(backend, "_native", lambda args: outputs[args[0]])
    assert backend.endpoint(scope, "198.51.100.12", "02:00:00:00:00:01", direct=True)
    assert backend.endpoint(scope, "192.0.2.10", None, direct=False)
    if failure == "interface":
        outputs["/sbin/ifconfig"] = "inet 192.0.2.11"
    elif failure == "forwarding":
        outputs["/usr/sbin/sysctl"] = "0"
    elif failure == "route":
        outputs["/sbin/route"] = "route to: 198.51.100.12\ninterface: en0\nflags: <GATEWAY>"
    elif failure == "arp":
        outputs["/usr/sbin/arp"] = "? (198.51.100.12) at 2:0:0:0:0:2 on bridge100 [ethernet]"
    mac = None if failure == "mac" else "02:00:00:00:00:01"
    assert not backend.endpoint(scope, "198.51.100.12", mac, direct=True)


def test_ports_clear_dns_exception_requires_verified_native_identity(
    environment: Any, monkeypatch: Any
) -> None:
    backend = shell_backend(environment, monkeypatch)
    profile = environment[1].profile("dns-udp")
    scope = environment[1].scopes[0]
    monkeypatch.setattr(backend, "_native", lambda args: socket_fixture())
    monkeypatch.setattr(backend, "_apple_dns_pid", lambda pid: pid == 555)
    assert not backend.ports_clear(scope, profile, apple_dns=False)
    assert backend.ports_clear(scope, profile, apple_dns=True)
    monkeypatch.setattr(backend, "_apple_dns_pid", lambda pid: False)
    assert not backend.ports_clear(scope, profile, apple_dns=True)
    monkeypatch.setattr(backend, "_native", lambda args: socket_fixture(endpoint="192.0.2.10.53"))
    assert not backend.ports_clear(scope, profile, apple_dns=True)


def test_native_observation_stderr_is_unknown(monkeypatch: Any) -> None:
    import netorch.pf_owner as module
    from netorch.pf_owner import ShellBackend
    from netorch.process import Result

    monkeypatch.setattr(module, "run", lambda *args, **kwargs: Result(0, b"partial", b"warning"))
    with pytest.raises(PFError):
        ShellBackend._native(["/absolute/fake"])
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: Result(0, b"complete", b""))
    assert ShellBackend._native(["/absolute/fake"]) == "complete"


@pytest.mark.usefixtures("legacy_cli_conformance")
def test_cli_live_boundary_isolated_and_exact_admission(
    environment: Any, monkeypatch: Any, capsys: Any
) -> None:
    import netorch.pf_owner as module

    root, _, _, _backend, _snapshots = environment
    monkeypatch.setattr(module.sys, "platform", "darwin")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    # The temporary root deliberately remains a CI user-owned fixture. This is
    # direct dependency injection, never a flag/environment bypass in live code.
    monkeypatch.setattr(module, "Store", lambda directory: root)
    monkeypatch.setattr(module, "protected_ancestors", lambda *a, **kw: None)
    monkeypatch.setattr(module, "protected_code", lambda *a, **kw: None)
    # Store validates current UID, so simulate metadata UID only within this test.
    import netorch.storage as storage

    original = storage.Store._check_directory_info
    monkeypatch.setattr(storage.Store, "_check_directory_info", staticmethod(lambda info: None))
    monkeypatch.setattr(storage, "_check_file", lambda fd: None)
    base = ["--root-dir", str(root.directory)]
    assert main(["review-admission", *base, "--profile", "media-udp"]) == 0
    review = strict_loads(capsys.readouterr().out)
    unchanged = root.read("admissions.json")
    assert (
        main(
            [
                "admit",
                *base,
                "--profile",
                "media-udp",
                "--expected-digest",
                "f" * 64,
                "--acknowledge-bounded-risk",
            ]
        )
        == 65
    )
    assert root.read("admissions.json") == unchanged
    capsys.readouterr()
    assert (
        main(
            [
                "admit",
                *base,
                "--profile",
                "media-udp",
                "--expected-digest",
                review["expected_digest"],
                "--acknowledge-bounded-risk",
            ]
        )
        == 0
    )
    assert main(["pause", *base]) == 0
    assert main(["suspend", *base, "--operation", "maint", "--holder", "manager"]) == 0
    assert main(["release", *base, "--operation", "maint", "--holder", "manager"]) == 0
    assert main(["resume", *base]) == 0
    root.write("journal.json", {"phase": "failed"})
    assert main(["acknowledge-journal", *base]) == 0
    assert main(["status", *base]) == 0
    assert main(["acknowledge-journal", *base]) == 65
    monkeypatch.setattr(storage.Store, "_check_directory_info", original)


def test_unknown_kernel_states_withdraws_known_rules_without_claiming_drained(
    environment: Any,
) -> None:
    approve_all(environment)
    run_pass(environment)
    environment[3].flow_states = "WARNING: state inventory truncated"
    result = run_pass(environment)
    assert result["phase"] == "failed"
    assert not environment[3].rules
    assert environment[0].read("journal.json")["reason"] == "kernel-state-unknown"


@pytest.mark.parametrize("failure", ["signature", "process", "job", "none"])
def test_apple_dns_identity_is_not_just_a_process_name(
    environment: Any, monkeypatch: Any, failure: str
) -> None:
    import netorch.pf_owner as module
    from netorch.process import Result

    backend = shell_backend(environment, monkeypatch)

    def native(argv: list[str]) -> str:
        if argv[0] == "/usr/bin/id":
            return "65\n"
        return (
            "65 1 /usr/sbin/mDNSResponder\n"
            if failure != "process"
            else "65 9 /usr/sbin/mDNSResponder\n"
        )

    def command(argv: list[str], **kwargs: Any) -> Result:
        if argv[0] == "/usr/bin/codesign":
            return Result(1 if failure == "signature" else 0, b"", b"")
        if failure == "none":
            return Result(1, b"", b"")
        payload = (
            b"job {\n program = /usr/sbin/mDNSResponder\n"
            b" username = _mdnsresponder\n pid = 555\n}\n"
        )
        if failure == "job":
            payload = payload.replace(b"pid = 555", b"pid = 556")
        return Result(0, payload, b"")

    monkeypatch.setattr(backend, "_native", native)
    monkeypatch.setattr(module, "run", command)
    assert not backend._apple_dns_pid(555)
    failure = "ok"
    assert backend._apple_dns_pid(555)


def test_published_report_is_atomic_snapshot_and_refuses_userowned_existing_file(
    environment: Any, monkeypatch: Any
) -> None:
    import netorch.pf_owner as module
    from netorch.state import snapshot_from_dict

    monkeypatch.setattr(module, "protected_ancestors", lambda *args, **kwargs: None)
    settings, snapshot = environment[2], environment[4][-1]
    previous_umask = os.umask(0o077)
    try:
        module._write_report(settings, snapshot)
    finally:
        os.umask(previous_umask)
    path = Path(settings.report_path)
    assert snapshot_from_dict(strict_loads(path.read_bytes())) == snapshot
    assert path.stat().st_mode & 0o777 == 0o644
    if os.geteuid() != 0:
        with pytest.raises(UnsafeState):
            module._write_report(settings, snapshot)
    path.unlink()
    path.symlink_to(environment[0].directory / "policy.json")
    with pytest.raises(UnsafeState):
        module._write_report(settings, snapshot)


def test_inhibition_damaged_and_missing_external_gate_never_enables(
    environment: Any, tmp_path: Path
) -> None:
    approve_all(environment)
    root = environment[0]
    raw = root.read("installation.json")
    raw["intent_path"] = str(tmp_path / "missing")
    root.write("installation.json", raw)
    assert run_pass(environment)["phase"] == "inhibited"
    root.write("operator-intent.json", {"schema_version": 999})
    assert run_pass(environment)["phase"] == "inhibited"
    assert not environment[3].rules


def test_entrypoint_never_accepts_a_planner_action_or_target() -> None:
    with pytest.raises(SystemExit):
        main(["reconcile", "--root-dir", "/protected", "--target", "192.0.2.20"])
    with pytest.raises(SystemExit):
        main(["activate", "--root-dir", "/protected"])


def test_native_pf_backend_has_no_global_reload_filter_or_state_flush() -> None:
    source = "\n".join(
        line
        for line in (ROOT / "platform/macos/pf/backend.sh").read_text().splitlines()
        if not line.lstrip().startswith("#")
    )
    assert 'pf -a "$anchor" -f' in source
    assert 'pf -k "$1"' in source and 'pf -k 0.0.0.0/0 -k "$1"' in source
    for forbidden in ("/etc/pf.conf", " -F ", " -d", "sudoers", "eval ", "source ", "pf -f "):
        assert forbidden not in source


def test_real_and_preview_renderers_use_darwin_translation_grammar(environment: Any) -> None:
    from netorch.mock import initial_snapshot, mock_admissions
    from netorch.pf import render

    config = environment[1]
    snapshot = initial_snapshot(config, STAMP)
    preview = render(config, snapshot, mock_admissions(config, STAMP - 1), Intent(), STAMP)
    for line in preview.splitlines():
        if line.startswith(("nat ", "rdr ")):
            # Darwin grammar allows comments; filter options such as label cannot
            # be appended to translation rules. No filter authority is generated.
            effective = line.split("#", 1)[0]
            assert " label " not in effective and " pass " not in effective
    media = config.profile("media-udp")
    target = snapshot.services[media.service].data["ipv4"]
    assert isinstance(target, str)
    for line in render_profile(config, media, target).splitlines():
        assert line in preview


def test_admin_withdraw_quiesces_before_scheduler_stops_and_preserves_gates(
    environment: Any,
) -> None:
    from netorch.pf_owner import withdraw

    approve_all(environment)
    run_pass(environment)
    root, _, _, backend, _ = environment
    root.write(
        "operator-intent.json", intent_to_dict(Intent().suspend("upgrade", "runtime-manager"))
    )
    result = withdraw(root, lambda root, installation: backend)
    assert result["withdrawn"] and result["reference_preserved"]
    assert root.read("operator-intent.json")["operator_paused"]
    assert root.read("operator-intent.json")["suspensions"] == {"upgrade": "runtime-manager"}
    assert not backend.rules and not root.read("live.json")["records"]


def test_admin_withdraw_refuses_foreign_anchor_drift(environment: Any) -> None:
    from netorch.pf_owner import withdraw

    backend = environment[3]
    backend.rules = "rdr foreign\n"
    with pytest.raises(PFError):
        withdraw(environment[0], lambda root, settings: backend)
    assert backend.rules == "rdr foreign\n"
    assert environment[0].read("operator-intent.json")["operator_paused"]


def test_admin_withdraw_draining_failure_retains_failed_journal(environment: Any) -> None:
    from netorch.pf_owner import withdraw

    approve_all(environment)
    run_pass(environment)
    backend = environment[3]
    backend.undrainable = True
    with pytest.raises(PFError):
        withdraw(environment[0], lambda root, settings: backend)
    assert not backend.rules
    assert environment[0].read("journal.json")["phase"] == "failed"


def test_installation_withdraw_preserves_unpaused_operator_intent(environment: Any) -> None:
    from netorch.pf_owner import withdraw

    approve_all(environment)
    run_pass(environment)
    root = environment[0]
    root.write("operator-intent.json", intent_to_dict(Intent().suspend("installation", "bundle-1")))
    result = withdraw(
        root, lambda root, settings: environment[3], operation="installation", holder="bundle-1"
    )
    assert not result["operator_paused"]
    assert not root.read("operator-intent.json")["operator_paused"]
    assert root.read("operator-intent.json")["suspensions"] == {"installation": "bundle-1"}
    with pytest.raises(PFError):
        withdraw(
            root,
            lambda root, settings: environment[3],
            operation="installation",
            holder="someone-else",
        )


def configure_fallback(environment: Any) -> Config:
    root, config, _, _, snapshots = environment
    profiles = list(config.profiles)
    for index, profile in enumerate(profiles[:2]):
        identifier = f"dns-native-{profile.protocol}"
        profiles[index] = replace(profile, fallback_publication=identifier)
        profiles.append(
            Profile(
                identifier,
                profile.service,
                profile.scope,
                "publication",
                profile.protocol,
                PortRange(1053, 1053),
                PortRange(53, 53),
                Safety("structural", 30, 1),
                "camera-manager",
            )
        )
    updated = replace(config, profiles=tuple(profiles))
    from netorch.config import validate_config

    validate_config(updated)
    root.write("policy.json", to_dict(updated))
    current = snapshots[-1]
    observed = dict(current.profiles)
    for profile in profiles:
        if profile.id.startswith("dns-native"):
            observed[profile.id] = Observation(
                "present",
                "verified",
                STAMP,
                "instance-1",
                {
                    "target_ipv4": "198.51.100.10",
                    "target_generation": "instance-1",
                    "network_generation": "network-1",
                    "policy_digest": profile_digest(updated, profile),
                    "states": (),
                },
            )
    snapshots.append(replace(current, profiles=observed))
    for profile in profiles:
        if updated.profile_owner(profile).id == "site-forwarding":
            admit(root, profile.id, acknowledge_bounded_risk=True, now=99)
    return updated


def test_native_dns_fallback_supports_tcp_and_udp_and_reports_degradation(environment: Any) -> None:
    configure_fallback(environment)
    environment[3].unavailable_guests.add("198.51.100.10")
    assert run_pass(environment)["phase"] == "committed"
    records = environment[0].read("live.json")["records"]
    for identifier in ("dns-tcp", "dns-udp"):
        assert records[identifier]["effective_strategy"] == "degraded-fallback"
        assert records[identifier]["target_ipv4"] == "192.0.2.10"
        assert "port 53 -> 192.0.2.10 port 1053" in records[identifier]["rules"]
    assert run_pass(environment)["phase"] == "committed"


def test_dns_mode_changes_retire_guest_states_then_later_restore_direct(environment: Any) -> None:
    configure_fallback(environment)
    assert run_pass(environment)["phase"] == "committed"
    backend = environment[3]
    backend.flow_states = "all udp 198.51.100.10:53 -> 192.0.2.50:53000 X:Y"
    backend.unavailable_guests.add("198.51.100.10")
    first = run_pass(environment)
    assert "dns-udp:withdraw" in first["changed"]
    assert "dns-udp:activate" not in first["changed"]
    assert not backend.flow_states
    assert run_pass(environment)["phase"] == "committed"
    assert (
        environment[0].read("live.json")["records"]["dns-udp"]["effective_strategy"]
        == "degraded-fallback"
    )
    backend.unavailable_guests.clear()
    first = run_pass(environment)
    assert "dns-udp:withdraw" in first["changed"] and "dns-udp:activate" not in first["changed"]
    assert run_pass(environment)["phase"] == "committed"
    assert environment[0].read("live.json")["records"]["dns-udp"]["effective_strategy"] is None
    assert not any(command == ("drain", "192.0.2.10") for command in backend.commands)


def test_fallback_cannot_use_unknown_native_backing(environment: Any) -> None:
    configure_fallback(environment)
    environment[3].unavailable_guests.add("198.51.100.10")
    current = environment[4][-1]
    environment[4].append(
        replace(
            current,
            profiles={
                key: value
                for key, value in current.profiles.items()
                if not key.startswith("dns-native")
            },
        )
    )
    result = run_pass(environment)
    assert {"dns-tcp", "dns-udp"}.issubset(result["pending"])
    assert "dns-udp" not in environment[0].read("live.json")["records"]


def test_changed_fallback_contract_does_not_inherit_root_admission(environment: Any) -> None:
    config = configure_fallback(environment)
    assert run_pass(environment)["phase"] == "committed"
    changed = to_dict(config)
    for profile in changed["profiles"]:
        if profile["id"].startswith("dns-native"):
            profile["ports"] = {"first": 2053, "last": 2053}
    environment[0].write("policy.json", changed)
    result = run_pass(environment)
    assert {"dns-udp", "dns-tcp"}.issubset(result["pending"])
    assert "dns-udp" not in environment[0].read("live.json")["records"]


def test_fallback_pure_planner_requires_independently_admitted_native_publication(
    environment: Any,
) -> None:
    from netorch.planner import plan
    from netorch.state import Admission

    config = configure_fallback(environment)
    snapshot = environment[4][-1]
    observations = dict(snapshot.profiles)
    observations["dns-udp"] = Observation(
        "absent", "confirmed-absent", STAMP, None, {"states": (), "direct_available": False}
    )
    snapshot = replace(snapshot, profiles=observations)
    admissions = {
        "dns-udp": Admission(
            "dns-udp", profile_digest(config, config.profile("dns-udp")), "admin", 99, True
        )
    }
    action = next(
        a
        for a in plan(config, snapshot, admissions, Intent(), STAMP).actions
        if a.profile == "dns-udp"
    )
    assert action.operation == "blocked" and action.reason == "publication-not-ready"
    backing = config.profile("dns-native-udp")
    admissions[backing.id] = Admission(
        backing.id, profile_digest(config, backing), "admin", 99, False
    )
    action = next(
        a
        for a in plan(config, snapshot, admissions, Intent(), STAMP).actions
        if a.profile == "dns-udp"
    )
    assert action.operation == "activate" and action.effective_strategy == "degraded-fallback"
    assert action.target_ipv4 == "192.0.2.10"
    from netorch.pf import render
    from netorch.planner import plan_from_dict, plan_to_dict

    proposed = plan(config, snapshot, admissions, Intent(), STAMP)
    round_trip = plan_from_dict(plan_to_dict(proposed))
    assert round_trip == proposed
    assert next(a for a in round_trip.actions if a.profile == "dns-udp").effective_strategy == (
        "degraded-fallback"
    )
    preview = render(config, snapshot, admissions, Intent(), STAMP)
    assert "-> 192.0.2.10 port 1053" in preview


@pytest.mark.parametrize(
    "field,value",
    [
        ("service", "camera"),
        ("protocol", "tcp"),
        ("kind", "guest-direct"),
        ("target_ports", {"first": 54, "last": 54}),
    ],
)
def test_fallback_must_be_exact_same_service_native_publication(
    environment: Any, field: str, value: Any
) -> None:
    from netorch.config import ConfigError, parse_config

    configured = to_dict(configure_fallback(environment))
    for profile in configured["profiles"]:
        if profile["id"] == "dns-native-udp":
            profile[field] = value
    with pytest.raises(ConfigError):
        parse_config(canonical_bytes(configured))


def test_root_report_proof_tracks_exact_admission_and_invalidates_changed_observer(
    environment: Any,
) -> None:
    approve_all(environment)
    root, config, installation, backend, snapshots = environment
    reports: list[Snapshot] = []

    def execute() -> None:
        reconcile(
            root,
            lambda config, settings: snapshots[-1],
            lambda root, settings: backend,
            now=lambda: STAMP,
            report=lambda settings, snapshot: reports.append(snapshot),
        )

    execute()
    assert not reports[-1].services
    assert set(reports[-1].profiles) == {"dns-udp", "dns-tcp", "proxy-standard", "media-udp"}
    for key, value in reports[-1].profiles.items():
        assert value.data["admitted"] is True
        assert value.data["root_ready"] is True
        assert value.data["admission_digest"] == admitted_digest(
            config, config.profile(key), installation
        )
        assert value.data["policy_digest"] == profile_digest(config, config.profile(key))
    raw = root.read("installation.json")
    raw["observer"] = {"schema_version": 2}
    root.write("installation.json", raw)
    execute()
    for value in reports[-1].profiles.values():
        assert value.state == "absent"
        assert value.data["admitted"] is False
        assert value.data["root_ready"] is False
        assert value.data["admission_digest"] is None


def test_implementation_changes_invalidate_root_admission(
    environment: Any, monkeypatch: Any
) -> None:
    import netorch.pf_owner as module

    approve_all(environment)
    run_pass(environment)
    monkeypatch.setattr(module, "implementation_digest", lambda: "f" * 64)
    assert run_pass(environment)["phase"] == "inhibited"
    assert not environment[3].rules


def test_installer_cannot_replace_existing_negative_authority_path(
    monkeypatch: Any, environment: Any, tmp_path: Path
) -> None:
    import netorch.pf_owner as module

    monkeypatch.setattr(module, "protected_ancestors", lambda *a, **kw: None)
    root, config, settings, _, _ = environment
    changed = settings.to_dict()
    changed["intent_path"] = str(tmp_path / "different-intent")
    policy, setup = tmp_path / "policy", tmp_path / "settings"
    policy.write_bytes(canonical_bytes(to_dict(config)))
    setup.write_bytes(canonical_bytes(changed))
    with pytest.raises(PFError, match="identity"):
        install(root.directory, policy, setup, ROOT / "platform/macos/pf/backend.sh")
    assert root.read("installation.json")["intent_path"] is None


def test_ipv4_mapped_ipv6_wildcard_cannot_hide_dns_collision(
    environment: Any, monkeypatch: Any
) -> None:
    backend = shell_backend(environment, monkeypatch)
    fixture = socket_fixture(endpoint="::ffff:0.0.0.0.53").replace("udp4", "udp6")
    monkeypatch.setattr(backend, "_native", lambda args: fixture)
    monkeypatch.setattr(backend, "_apple_dns_pid", lambda pid: True)
    assert not backend.ports_clear(
        environment[1].scopes[0], environment[1].profile("dns-udp"), apple_dns=True
    )


@pytest.mark.parametrize(
    "observation", ["flags-missing", "arp-link-missing", "multicast-mac", "zero-mac"]
)
def test_native_endpoint_unrecognized_topology_cannot_be_admitted(
    environment: Any, monkeypatch: Any, observation: str
) -> None:
    backend = shell_backend(environment, monkeypatch)
    route = "route to: 198.51.100.12\ninterface: bridge100\nflags: <HOST,LLINFO>\n"
    arp = "? (198.51.100.12) at 02:00:00:00:00:01 on bridge100 [ethernet]"
    mac = "02:00:00:00:00:01"
    if observation == "flags-missing":
        route = "route to: 198.51.100.12\ninterface: bridge100\n"
    elif observation == "arp-link-missing":
        arp = "? (198.51.100.12) at 02:00:00:00:00:01 on bridge100 ifscope"
    elif observation == "multicast-mac":
        mac = "01:00:00:00:00:01"
    else:
        mac = "00:00:00:00:00:00"
    values = {
        "/sbin/route": route,
        "/usr/sbin/arp": arp,
        "/sbin/ifconfig": "inet 192.0.2.10 netmask 0xffffff00",
        "/usr/sbin/sysctl": "1",
    }
    monkeypatch.setattr(backend, "_native", lambda args: values[args[0]])
    assert not backend.endpoint(environment[1].scopes[0], "198.51.100.12", mac, direct=True)


def test_long_external_operation_identifier_still_fails_closed(
    environment: Any, tmp_path: Path
) -> None:
    root = environment[0]
    gate = Store(tmp_path / "user-gate")
    gate.write("intent.json", intent_to_dict(Intent().suspend("a" * 128, "manager")))
    installation = root.read("installation.json")
    installation["intent_path"] = str(gate.directory / "intent.json")
    root.write("installation.json", installation)
    approve_all(environment)
    assert run_pass(environment)["phase"] == "inhibited"
    assert not environment[3].rules


@pytest.mark.parametrize(
    "key,value", [("owner", 5), ("anchor", None), ("backend_sha256", False), ("report_path", 3.14)]
)
def test_installation_wrong_json_types_are_redacted_errors(
    environment: Any, key: str, value: Any
) -> None:
    raw = environment[2].to_dict()
    raw[key] = value
    with pytest.raises(PFError):
        Installation.from_dict(raw)


def test_drift_during_final_runtime_read_cannot_be_reported_present(environment: Any) -> None:
    approve_all(environment)
    root, _, _, backend, snapshots = environment
    run_pass(environment)
    calls = 0

    def observe(config: Config, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        if calls == 2:
            backend.rules = "rdr foreign\n"
        return snapshots[-1]

    with pytest.raises(PFError, match="final"):
        reconcile(
            root,
            observe,
            lambda root, settings: backend,
            now=lambda: STAMP,
            report=lambda *args: pytest.fail("drift was incorrectly published as fresh present"),
        )
    assert backend.rules == "rdr foreign\n"
    assert root.read("journal.json")["phase"] == "failed"


def test_privileged_implementation_fingerprint_binds_schema_python_and_dependencies(
    tmp_path: Path, monkeypatch: Any
) -> None:
    import netorch.pf_owner as module

    package = tmp_path / "src" / "netorch"
    package.mkdir(parents=True)
    code = package / "pf_owner.py"
    code.write_text("# implementation\n")
    schema_directory = tmp_path / "schemas"
    schema_directory.mkdir()
    for name in ("network.schema.json", "deployment.schema.json"):
        (schema_directory / name).write_text("{}")
    monkeypatch.setattr(module, "__file__", str(code))
    versions = {
        name: "1.0"
        for name in ("jsonschema", "attrs", "jsonschema-specifications", "referencing", "rpds-py")
    }
    monkeypatch.setattr(module, "version", versions.__getitem__)
    runtime = SimpleNamespace(version="tested-python-1")
    monkeypatch.setattr(module, "sys", runtime)

    def fingerprint() -> str:
        module.implementation_digest.cache_clear()
        return module.implementation_digest()

    try:
        original = fingerprint()
        assert fingerprint() == original
        (schema_directory / "network.schema.json").write_text('{"changed": true}')
        schema_changed = fingerprint()
        assert schema_changed != original
        runtime.version = "tested-python-2"
        python_changed = fingerprint()
        assert python_changed != schema_changed
        versions["jsonschema"] = "2.0"
        dependency_changed = fingerprint()
        assert dependency_changed != python_changed
        code.write_text("# new implementation\n")
        assert fingerprint() != dependency_changed
        # Wheel-bundled files, rather than source fallback, are fingerprinted.
        for name in ("network.schema.json", "deployment.schema.json"):
            (package / name).write_text('{"bundled": true}')
        assert fingerprint() != dependency_changed
    finally:
        module.implementation_digest.cache_clear()


def test_protected_code_explicit_uid_isolates_file_boundary(
    tmp_path: Path, monkeypatch: Any
) -> None:
    import netorch.pf_owner as module

    executable, package = tmp_path / "python", tmp_path / "pf_owner.py"
    executable.write_text("executable")
    package.write_text("package")
    calls: list[Path] = []
    monkeypatch.setattr(module, "protected_ancestors", lambda path, **kw: calls.append(path))
    monkeypatch.setattr(module, "reject_acl", lambda path: None)
    monkeypatch.setattr(module, "_batch_code_acls", lambda *args: None)
    module.protected_code(executable, package, uid=os.geteuid())
    assert calls == [tmp_path] * 4
    executable.chmod(0o666)
    with pytest.raises(UnsafeState, match="replaceable"):
        module.protected_code(executable, package, uid=os.geteuid())


def test_live_privileged_code_checks_prefix_paths_dependencies_and_schemas(
    tmp_path: Path, monkeypatch: Any
) -> None:
    import netorch.pf_owner as module

    package = tmp_path / "netorch"
    package.mkdir()
    interpreter = tmp_path / "python"
    interpreter.write_text("executable")
    owner = package / "pf_owner.py"
    owner.write_text("implementation")
    dependency = tmp_path / "validator.so"
    dependency.write_text("dependency")
    zipped = tmp_path / "python.zip"
    zipped.write_text("stdlib")
    schemas = [package / name for name in ("network.schema.json", "deployment.schema.json")]
    for schema in schemas:
        schema.write_text("{}")
    prefix = tmp_path / "base"
    prefix.mkdir()
    calls: list[Path] = []
    monkeypatch.setattr(module, "protected_ancestors", lambda path, **kw: calls.append(path))
    monkeypatch.setattr(module, "reject_acl", lambda path: None)
    monkeypatch.setattr(module, "_batch_code_acls", lambda *args: None)
    runtime = SimpleNamespace(
        prefix=str(tmp_path),
        base_prefix=str(prefix),
        path=[str(package), str(zipped), str(tmp_path / "absent.zip")],
        modules={"validator": SimpleNamespace(__file__=str(dependency))},
    )
    monkeypatch.setattr(module, "sys", runtime)
    actual_lstat = Path.lstat

    def root_owned(path: Path) -> os.stat_result:
        fields = list(actual_lstat(path))
        fields[4] = 0  # Mock root ownership; all physical files remain isolated.
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "lstat", root_owned)
    module.protected_code(interpreter, owner)
    assert tmp_path in calls and prefix in calls and package in calls
    dependency.chmod(0o666)
    with pytest.raises(UnsafeState, match="replaceable"):
        module.protected_code(interpreter, owner)
    dependency.chmod(0o644)
    schemas[0].chmod(0o666)
    with pytest.raises(UnsafeState, match="replaceable"):
        module.protected_code(interpreter, owner)
    schemas[0].chmod(0o644)
    runtime.path = ["relative"]
    with pytest.raises(UnsafeState, match="absolute"):
        module.protected_code(interpreter, owner)


def test_unrelated_unbound_or_kernel_sockets_do_not_block_selected_ports(
    environment: Any, monkeypatch: Any
) -> None:
    backend = shell_backend(environment, monkeypatch)
    raw = socket_fixture(endpoint="*.*", process=":0")
    assert parse_socket_inventory(raw, "udp") == (("*", 0, 0, "", "IPv4"),)
    monkeypatch.setattr(backend, "_native", lambda args: raw)
    assert backend.ports_clear(
        environment[1].scopes[0], environment[1].profile("dns-udp"), apple_dns=True
    )
    # A kernel/unidentified binding on the selected DNS port is never exempt.
    monkeypatch.setattr(backend, "_native", lambda args: socket_fixture(process=":0"))
    assert not backend.ports_clear(
        environment[1].scopes[0], environment[1].profile("dns-udp"), apple_dns=True
    )
    monkeypatch.setattr(backend, "_native", lambda args: socket_fixture(process="mDNSResponder:0"))
    monkeypatch.setattr(backend, "_apple_dns_pid", lambda pid: True)
    assert not backend.ports_clear(
        environment[1].scopes[0], environment[1].profile("dns-udp"), apple_dns=True
    )


@pytest.mark.parametrize("inhibition", ["pause", "suspend"])
def test_final_inhibition_never_reports_existing_exposure_as_operationally_ready(
    environment: Any, inhibition: str
) -> None:
    approve_all(environment)
    root, _, _, backend, snapshots = environment
    run_pass(environment)
    reports: list[Snapshot] = []
    calls = 0

    def observe(config: Config, settings: Any) -> Snapshot:
        nonlocal calls
        calls += 1
        if calls == 2:
            intent = (
                Intent().pause()
                if inhibition == "pause"
                else Intent().suspend("maintenance", "administrator")
            )
            root.write("operator-intent.json", intent_to_dict(intent))
        return snapshots[-1]

    result = reconcile(
        root,
        observe,
        lambda root, settings: backend,
        now=lambda: STAMP,
        report=lambda settings, snapshot: reports.append(snapshot),
    )
    assert result["phase"] == "inhibited"
    assert backend.rules  # Readback remains truthful until independent withdrawal.
    for observed in reports[-1].profiles.values():
        assert observed.state == "present"
        assert observed.data["admitted"] is True
        assert observed.data["root_ready"] is False
    assert run_pass(environment)["phase"] == "inhibited"
    assert not backend.rules


def test_code_acl_batches_are_bounded_and_deduplicated(monkeypatch: Any) -> None:
    import netorch.pf_owner as module
    from netorch.process import Result

    paths = tuple(Path(f"/Library/ExampleRuntime/file-{index}") for index in range(600))
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(module.time, "monotonic", lambda: 0.0)
    calls: list[tuple[list[str], float, int]] = []

    def command(argv: list[str], *, timeout: float, max_output: int) -> Result:
        calls.append((argv, timeout, max_output))
        assert argv[:2] == ["/bin/ls", "-lde"]
        assert len(argv[2:]) <= 256 and sum(len(item) + 1 for item in argv[2:]) <= 65536
        return Result(0, b"metadata\n" * len(argv[2:]), b"")

    monkeypatch.setattr(module, "run", command)
    module._batch_code_acls(paths, 8.0)
    assert len(calls) == 3
    assert [Path(item) for argv, _, _ in calls for item in argv[2:]] == list(paths)
    assert all(timeout == 8.0 and maximum == 524288 for _, timeout, maximum in calls)


@pytest.mark.parametrize("fault", ["acl", "stderr", "exit", "short"])
def test_code_acl_batch_incomplete_or_acl_results_are_unknown(monkeypatch: Any, fault: str) -> None:
    import netorch.pf_owner as module
    from netorch.process import Result

    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(module.time, "monotonic", lambda: 0.0)
    stdout = b"metadata\n 0: group:everyone allow write\n" if fault == "acl" else b"metadata\n"
    if fault == "short":
        stdout = b""
    monkeypatch.setattr(
        module,
        "run",
        lambda *args, **kwargs: Result(
            1 if fault == "exit" else 0, stdout, b"warning" if fault == "stderr" else b""
        ),
    )
    with pytest.raises(UnsafeState, match="ACL-bearing or unknown"):
        module._batch_code_acls((Path("/Library/ExampleRuntime/file"),), 8.0)


def test_code_acl_batches_share_an_aggregate_deadline(monkeypatch: Any) -> None:
    import netorch.pf_owner as module
    from netorch.process import Result

    elapsed = [0.0]
    calls = []
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(module.time, "monotonic", lambda: elapsed[0])

    def command(argv: list[str], **kwargs: Any) -> Result:
        calls.append(argv)
        elapsed[0] = 9.0
        return Result(0, b"metadata\n" * len(argv[2:]), b"")

    monkeypatch.setattr(module, "run", command)
    paths = tuple(Path(f"/Library/ExampleRuntime/file-{index}") for index in range(300))
    with pytest.raises(UnsafeState, match="aggregate deadline"):
        module._batch_code_acls(paths, 8.0)
    assert len(calls) == 1


def test_code_metadata_capture_is_bounded_and_rejects_path_or_inode_changes(
    tmp_path: Path,
) -> None:
    import netorch.pf_owner as module

    path = tmp_path / "file"
    path.write_text("original")
    info = path.lstat()
    captures: dict[Path, os.stat_result] = {}
    module._capture_code_metadata(path, info, captures)
    module._capture_code_metadata(path, info, captures)
    assert len(captures) == 1
    path.write_text("changed-content")
    with pytest.raises(UnsafeState, match="changed during capture"):
        module._capture_code_metadata(path, path.lstat(), captures)
    with pytest.raises(UnsafeState, match="invalid"):
        module._capture_code_metadata(Path("/invalid\npath"), info, {})
    oversized = {Path(f"/Library/file-{index}"): info for index in range(4096)}
    with pytest.raises(UnsafeState, match="bounded capacity"):
        module._capture_code_metadata(path, info, oversized)


def test_code_metadata_is_fenced_after_acl_read(tmp_path: Path, monkeypatch: Any) -> None:
    import netorch.pf_owner as module

    executable, package = tmp_path / "python", tmp_path / "pf_owner.py"
    executable.write_text("executable")
    package.write_text("original")
    monkeypatch.setattr(module, "protected_ancestors", lambda *args, **kwargs: None)

    def mutate_after_capture(*args: Any) -> None:
        replacement = tmp_path / "replacement"
        replacement.write_text("new code")
        replacement.replace(package)

    monkeypatch.setattr(module, "_batch_code_acls", mutate_after_capture)
    with pytest.raises(UnsafeState, match="changed during bounded inspection"):
        module.protected_code(executable, package, uid=os.geteuid())


def test_batched_ancestor_capture_still_rejects_writable_or_foreign_ancestors(
    tmp_path: Path,
) -> None:
    with pytest.raises(UnsafeState, match="protected ancestor"):
        protected_ancestors(tmp_path, _captures={})


def test_native_observer_guard_checks_links_targets_and_metadata_before_use(
    tmp_path: Path, monkeypatch: Any
) -> None:
    import netorch.pf_owner as module

    native, helper = tmp_path / "container", tmp_path / "helper"
    native.write_text("native")
    helper.write_text("helper")
    link = tmp_path / "container-link"
    link.symlink_to(native)
    captured: list[Path] = []
    monkeypatch.setattr(module, "protected_ancestors", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "_batch_code_acls", lambda paths, deadline: captured.extend(paths))
    module.protected_native_code((link, helper, helper), uid=os.geteuid())
    assert set(captured) == {native, helper, link}
    native.chmod(0o666)
    with pytest.raises(UnsafeState, match="replaceable"):
        module.protected_native_code((link, helper), uid=os.geteuid())
    with pytest.raises(UnsafeState, match="inventory"):
        module.protected_native_code(())
    with pytest.raises(UnsafeState, match="inventory"):
        module.protected_native_code((native,) * 35)


def test_root_runtime_observer_must_prove_native_binaries_before_reading(
    monkeypatch: Any, environment: Any
) -> None:
    import netorch.apple_runtime as runtime
    import netorch.pf_owner as module

    raw = strict_loads((ROOT / "examples/runtime-settings.json").read_bytes())
    checks: list[tuple[Path, ...]] = []
    monkeypatch.setattr(module, "protected_native_code", lambda paths: checks.append(paths))

    def observe(config: Config, settings: Any, runner: Any) -> Snapshot:
        assert checks == [
            (
                Path(raw["executable"]),
                Path(raw["networks"][0]["helper_executable"]),
                Path(module.__file__).with_name("observer_child.py"),
            )
        ]
        return environment[4][-1]

    monkeypatch.setattr(runtime, "observe_runtime", observe)
    assert module._runtime_observer(environment[1], raw) == environment[4][-1]

    def refuse(paths: tuple[Path, ...]) -> None:
        raise UnsafeState("untrusted native executable")

    monkeypatch.setattr(module, "protected_native_code", refuse)
    monkeypatch.setattr(runtime, "observe_runtime", lambda *args: pytest.fail("unsafe code read"))
    with pytest.raises(UnsafeState, match="untrusted native"):
        module._runtime_observer(environment[1], raw)


@pytest.fixture
def legacy_cli_conformance(monkeypatch):
    """Explicit CI-only seam for preserved owner internals; never qualification."""
    import netorch.pf_owner as module

    monkeypatch.setattr(module, "require_mutation_qualified", lambda _capability: None)

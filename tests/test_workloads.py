import copy
import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from netorch.apple_runtime import RuntimeReadError, capture_enrollment, observe_runtime
from netorch.codec import canonical_bytes, digest
from netorch.config import load_config
from netorch.model import Service
from netorch.process import Result
from netorch.runtime_settings import (
    FileIdentity,
    RuntimeAccount,
    RuntimeContract,
    RuntimeNetwork,
    RuntimeSettings,
    contract_digest,
)
from netorch.state import Intent, intent_from_dict, intent_to_dict
from netorch.storage import Busy, Store, UnsafeState
from netorch.workloads import (
    Option,
    Workload,
    acknowledge_workload_operation,
    create_arguments,
    main,
    parse_workloads,
    plan_workloads,
    provision_digest,
    provision_workloads,
    recipe_digest,
)


class NativeFleet:
    """Actual CLI envelopes, synthetic IPv4s, no subprocess or networking."""

    def __init__(self, config, settings):
        self.config, self.settings = config, settings
        self.calls = []
        self.existing = {}
        self.configurations = {}
        for contract in settings.contracts:
            pubs = []
            for profile in config.profiles:
                if profile.kind == "publication" and profile.service == contract.service:
                    pubs.append(
                        {
                            "hostAddress": config.scope(profile.scope).host_ipv4,
                            "hostPort": profile.ports.first,
                            "containerPort": profile.target_ports.first,
                            "count": profile.ports.width,
                            "proto": profile.protocol,
                        }
                    )
            self.configurations[contract.name] = {
                "id": contract.name,
                "mounts": [],
                "publishedPorts": pubs,
                "resources": {"cpus": 2, "memoryInBytes": 4294967296},
                "platform": {"os": "linux", "architecture": "arm64"},
            }
        self.failure = None

    def snapshot(self, name, state="running"):
        network = self.settings.networks[0]
        return {
            "id": name,
            "configuration": copy.deepcopy(self.configurations[name]),
            "status": {
                "state": state,
                "startedDate": "2000-01-01T00:00:00Z" if state == "running" else None,
                "networks": [
                    {
                        "network": network.name,
                        "ipv4Address": "198.51.100.5/24",
                        "ipv4Gateway": network.gateway,
                    }
                ]
                if state == "running"
                else [],
            },
        }

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.failure and self.failure(argv):
            return Result(1, b"", b"redacted failure")
        if argv[0] == self.settings.executable:
            assert kwargs["run_uid"] == self.settings.account.uid
            assert kwargs["run_gid"] == self.settings.account.gid
            args = argv[1:]
            if args == ["--version"]:
                return Result(
                    0,
                    (
                        f"container CLI version {self.settings.accepted_version}"
                        + " (build: release)\n"
                    ).encode(),
                    b"",
                )
            if args == ["list", "--all", "--format", "json"]:
                result = list(self.existing.values())
            elif args[:2] == ["network", "inspect"]:
                net = self.settings.networks[0]
                result = [
                    {
                        "id": net.name,
                        "configuration": {
                            "name": net.name,
                            "mode": "nat",
                            "plugin": "container-network-vmnet",
                        },
                        "status": {"ipv4Subnet": "198.51.100.0/24", "ipv4Gateway": net.gateway},
                    }
                ]
            elif args[0] == "inspect":
                result = [self.existing[args[1]]]
            elif args[0] == "create":
                name = args[args.index("--name") + 1]
                self.existing[name] = self.snapshot(name, "stopped")
                return Result(0, b"created", b"")
            elif args[0] == "start":
                self.existing[args[1]] = self.snapshot(args[1])
                return Result(0, b"started", b"")
            elif args[0] == "exec":
                return Result(0, b"45000 45127\n", b"")
            elif args[:2] == ["image", "inspect"]:
                result = [{"reference": args[2]}]
            else:
                raise AssertionError(argv)
            return Result(0, canonical_bytes(result), b"")
        if argv[0] == "/usr/sbin/sysctl":
            return Result(0, b"{ sec = 100, usec = 0 }\n", b"")
        if argv[0] == "/bin/launchctl":
            return Result(0, b"state = running\npid = 100\nprogram = /vendor/network-helper\n", b"")
        if argv[0] == "/bin/ps":
            return Result(0, b"0 Mon Jan  1 00:00:00 2000 /vendor/network-helper\n", b"")
        if argv[0] == "/sbin/ifconfig":
            return Result(0, b"en0: flags=UP\n inet 192.0.2.10 netmask 0xffffff00\n", b"")
        raise AssertionError(argv)


def fleet(tmp_path):
    config = load_config(Path(__file__).parents[1] / "examples/network.json")
    extra = tuple(
        Service(name, "camera-manager", "0" * 64) for name in ("dashboard", "compute", "control")
    )
    config = replace(config, services=(*config.services, *extra))
    directory = tmp_path.resolve() / "state"
    store = Store(directory)
    store.write("intent.json", intent_to_dict(Intent(operator_paused=True)))
    contracts = tuple(
        RuntimeContract(service.id, service.id, "wired-lan", "0" * 64, ())
        for service in config.services
    )
    settings = RuntimeSettings(
        1,
        "camera-manager",
        "/vendor/container",
        "1.5.0",
        RuntimeAccount(os.geteuid(), os.getegid(), str(tmp_path.resolve())),
        (
            RuntimeNetwork(
                "wired-lan",
                "default",
                "198.51.100.1",
                "system",
                "vendor.network-helper",
                "/vendor/network-helper",
                0,
            ),
        ),
        contracts,
        intent=str(directory / "intent.json"),
        state_dir=str(directory),
    )
    fake = NativeFleet(config, settings)
    contracts = tuple(
        replace(contract, configuration_sha256=digest(fake.configurations[contract.name]))
        for contract in contracts
    )
    settings = replace(settings, contracts=contracts)
    config = replace(
        config,
        services=tuple(
            replace(service, contract_sha256=contract_digest(settings.contract(service.id)))
            for service in config.services
        ),
    )
    fake.config, fake.settings = config, settings
    workloads = tuple(
        Workload(service.id, "example.invalid/service@sha256:" + "1" * 64, (), ())
        for service in config.services
    )
    return config, settings, fake, workloads, store


def test_seven_workloads_initial_create_start_enroll_then_observe(tmp_path):
    config, settings, fake, workloads, store = fleet(tmp_path)
    planned = plan_workloads(config, settings, workloads, fake)
    assert len(planned["steps"]) == 7
    assert {item["action"] for item in planned["steps"]} == {"create-stopped"}
    result = provision_workloads(
        config,
        settings,
        workloads,
        expected_digest=provision_digest(config, settings, workloads, start_initial=True),
        start_initial=True,
        runner=fake,
    )
    assert result["enrollment_required"] and not result["admitted"]
    assert intent_from_dict(store.read("intent.json")).operator_paused
    assert not intent_from_dict(store.read("intent.json")).suspensions
    enrolled = capture_enrollment(settings, fake)
    snapshot = observe_runtime(config, enrolled, fake)
    assert len(snapshot.services) == 7
    assert {item.state for item in snapshot.services.values()} == {"present"}
    assert all(item.state == "present" for item in snapshot.profiles.values())
    assert not any(
        argv[1] in {"delete", "stop", "system"}
        for argv, _ in fake.calls
        if argv[0] == settings.executable
    )


def test_existing_running_contract_is_preserved_without_calls_to_create(tmp_path):
    config, settings, fake, workloads, _ = fleet(tmp_path)
    fake.existing = {item.name: fake.snapshot(item.name) for item in settings.contracts}
    assert all(
        step["action"] == "retain"
        for step in plan_workloads(config, settings, workloads, fake)["steps"]
    )
    provision_workloads(
        config,
        settings,
        workloads,
        expected_digest=provision_digest(config, settings, workloads),
        runner=fake,
    )
    assert not any(
        argv[1] in {"create", "start", "stop", "delete"}
        for argv, _ in fake.calls
        if argv[0] == settings.executable
    )
    fake.existing[settings.contracts[0].name]["configuration"]["resources"]["cpus"] = 8
    with pytest.raises(RuntimeError):
        plan_workloads(config, settings, workloads, fake)


def test_provision_failure_retains_suspension_and_partial_journal(tmp_path):
    config, settings, fake, workloads, store = fleet(tmp_path)
    fake.failure = lambda argv: (
        len(argv) > 1 and argv[1] == "create" and workloads[1].service in argv
    )
    with pytest.raises(RuntimeError):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=provision_digest(config, settings, workloads, start_initial=True),
            start_initial=True,
            runner=fake,
        )
    assert store.read("workload-journal.json")["phase"] == "failed"
    assert store.read("workload-journal.json")["completed"] == [workloads[0].service]
    assert intent_from_dict(store.read("intent.json")).suspensions
    assert len(fake.existing) == 1


def test_provision_authority_gates_and_native_ports_single_author(tmp_path):
    config, settings, fake, workloads, store = fleet(tmp_path)
    with pytest.raises(ValueError):
        provision_workloads(config, settings, workloads, expected_digest="0" * 64, runner=fake)
    store.write("intent.json", intent_to_dict(Intent()))
    with pytest.raises(ValueError):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=provision_digest(config, settings, workloads),
            runner=fake,
        )
    args = create_arguments(
        config, settings, next(item for item in workloads if item.service == "web-proxy")
    )
    assert "192.0.2.10:8080:80/tcp" in args


@pytest.mark.parametrize(
    "change",
    [
        lambda x: x.update(extra=1),
        lambda x: x.update(schema_version=True),
        lambda x: x["workloads"][0].update(image="unversioned:latest"),
        lambda x: x["workloads"][0]["options"].append(
            {"flag": "--publish", "value": "0.0.0.0:1:1"}
        ),
        lambda x: x["workloads"][0]["options"].append({"flag": "--env", "value": "SECRET"}),
        lambda x: x["workloads"][0]["options"].append({"flag": "--init", "value": "yes"}),
        lambda x: x["workloads"][0].update(arguments=[None]),
    ],
)
def test_recipe_closed_schema(change):
    value = {
        "schema_version": 1,
        "workloads": [
            {
                "service": "example",
                "image": "example.invalid/a@sha256:" + "1" * 64,
                "options": [],
                "arguments": [],
            }
        ],
    }
    change(value)
    with pytest.raises(ValueError):
        parse_workloads(value)


def test_recipe_preserves_literal_values_and_no_secret_in_plan(tmp_path):
    from netorch.workloads import Option

    config, settings, fake, workloads, _ = fleet(tmp_path)
    workload = replace(
        workloads[0],
        options=(Option("--env", "PRIVATE=$(false);`false`"),),
        arguments=("$(false)",),
    )
    args = create_arguments(config, settings, workload)
    assert "PRIVATE=$(false);`false`" in args
    assert args[-1] == "$(false)"
    plan = plan_workloads(config, settings, (workload, *workloads[1:]), fake)
    assert "PRIVATE" not in str(plan)


def test_recipe_cli_error_is_redacted(tmp_path, capsys):
    assert (
        main(
            [
                "--settings",
                str(tmp_path / "missing-private.json"),
                "--recipes",
                str(tmp_path / "recipes.json"),
                "plan",
            ]
        )
        == 69
    )
    assert str(tmp_path) not in capsys.readouterr().err


def test_default_initial_provision_creates_stopped_and_preserves_pause(tmp_path):
    config, settings, fake, workloads, store = fleet(tmp_path)
    result = provision_workloads(
        config,
        settings,
        workloads,
        expected_digest=provision_digest(config, settings, workloads),
        runner=fake,
    )
    assert result["started_initial"] is False
    assert len(fake.existing) == 7
    assert all(item["status"]["state"] == "stopped" for item in fake.existing.values())
    assert not any(argv[1:2] == ["start"] for argv, _ in fake.calls)
    intent = intent_from_dict(store.read("intent.json"))
    assert intent.operator_paused and not intent.suspensions and not intent.damaged
    observed = observe_runtime(config, settings, fake)
    assert all(item.state == "unknown" for item in observed.services.values())


def test_explicit_initial_start_can_start_existing_stopped_without_recreation(tmp_path):
    config, settings, fake, workloads, store = fleet(tmp_path)
    for contract in settings.contracts:
        fake.existing[contract.name] = fake.snapshot(contract.name, "stopped")
    assert all(
        step["action"] == "start-existing"
        for step in plan_workloads(config, settings, workloads, fake)["steps"]
    )
    provision_workloads(
        config,
        settings,
        workloads,
        expected_digest=provision_digest(config, settings, workloads, start_initial=True),
        start_initial=True,
        runner=fake,
    )
    assert sum(argv[1:2] == ["start"] for argv, _ in fake.calls) == 7
    assert not any(argv[1:2] == ["create"] for argv, _ in fake.calls)
    assert intent_from_dict(store.read("intent.json")).operator_paused


@pytest.mark.parametrize("state", ["stopping", "unknown"])
def test_unknown_existing_state_never_creates_or_starts(tmp_path, state):
    config, settings, fake, workloads, store = fleet(tmp_path)
    contract = settings.contracts[0]
    fake.existing[contract.name] = fake.snapshot(contract.name, state)
    candidate = plan_workloads(config, settings, workloads, fake)
    assert candidate["steps"][0]["action"] == "blocked"
    with pytest.raises(RuntimeReadError):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=provision_digest(config, settings, workloads),
            runner=fake,
        )
    assert not (store.directory / "workload-journal.json").exists()
    assert not any(argv[1:2] in (["create"], ["start"]) for argv, _ in fake.calls)


@pytest.mark.parametrize("raw", [[], {}, [None], [{}, {}]])
def test_cached_image_inspection_must_be_complete_before_any_write(tmp_path, raw):
    config, settings, fake, workloads, _ = fleet(tmp_path)

    def image_failure(argv, **kwargs):
        if argv[1:3] == ["image", "inspect"]:
            return Result(0, canonical_bytes(raw), b"")
        return fake(argv, **kwargs)

    with pytest.raises(RuntimeReadError):
        plan_workloads(config, settings, workloads, image_failure)
    assert not fake.existing
    assert not any(argv[1:2] in (["create"], ["start"]) for argv, _ in fake.calls)


def test_recipe_service_coverage_must_exactly_match_private_enrollment(tmp_path):
    config, settings, fake, workloads, _ = fleet(tmp_path)
    with pytest.raises(ValueError):
        plan_workloads(config, settings, workloads[:-1], fake)
    assert not fake.calls


@pytest.mark.parametrize("which", ["created-running", "start-not-running", "identity-drift"])
def test_native_success_without_verified_result_retains_failure_gate(tmp_path, which):
    config, settings, fake, workloads, store = fleet(tmp_path)
    first = settings.contracts[0].name
    second = settings.contracts[1].name

    def changed_runtime(argv, **kwargs):
        result = fake(argv, **kwargs)
        if which == "created-running" and argv[1:2] == ["create"]:
            fake.existing[first] = fake.snapshot(first)
        if which == "start-not-running" and argv[1:2] == ["start"]:
            fake.existing[first] = fake.snapshot(first, "stopped")
        if (
            which == "identity-drift"
            and argv[1:3] == ["inspect", first]
            and first in fake.existing
            and second not in fake.existing
        ):
            # Change occurs after the first successful inspection. The next
            # complete inventory must fence the second guest's creation.
            fake.existing[first]["configuration"]["resources"]["cpus"] = 8
        return result

    with pytest.raises(RuntimeReadError):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=provision_digest(
                config, settings, workloads, start_initial=which == "start-not-running"
            ),
            start_initial=which == "start-not-running",
            runner=changed_runtime,
        )
    assert store.read("workload-journal.json")["phase"] == "failed"
    assert intent_from_dict(store.read("intent.json")).suspensions
    assert second not in fake.existing
    assert not any(argv[1:2] in (["stop"], ["delete"], ["run"]) for argv, _ in fake.calls)


def test_foreign_creation_between_plan_and_execution_never_replaces_guest(tmp_path):
    config, settings, fake, workloads, store = fleet(tmp_path)
    inventory_calls = 0
    first = settings.contracts[0].name

    def raced_runtime(argv, **kwargs):
        nonlocal inventory_calls
        if argv[1:] == ["list", "--all", "--format", "json"]:
            inventory_calls += 1
            if inventory_calls == 2:
                fake.existing[first] = fake.snapshot(first)
        return fake(argv, **kwargs)

    with pytest.raises(RuntimeReadError):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=provision_digest(config, settings, workloads),
            runner=raced_runtime,
        )
    assert store.read("workload-journal.json")["phase"] == "failed"
    assert not any(argv[1:2] in (["create"], ["start"]) for argv, _ in fake.calls)


@pytest.mark.parametrize("reason", ["damaged", "competing", "unfinished", "wrong-user", "root"])
def test_initial_provision_gate_failures_make_no_native_calls(tmp_path, monkeypatch, reason):
    config, settings, fake, workloads, store = fleet(tmp_path)
    if reason == "damaged":
        store.write("intent.json", intent_to_dict(Intent(operator_paused=True, damaged=True)))
    elif reason == "competing":
        store.write(
            "intent.json",
            intent_to_dict(Intent(operator_paused=True).suspend("backup", "different-owner")),
        )
    elif reason == "unfinished":
        store.write("workload-journal.json", {"phase": "failed"})
    else:
        monkeypatch.setattr(
            "netorch.workloads.os.geteuid",
            lambda: 0 if reason == "root" else settings.account.uid + 1,
        )
    with pytest.raises((ValueError, PermissionError)):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=provision_digest(config, settings, workloads),
            runner=fake,
        )
    assert not fake.calls


def enrolled_input(settings, source, *, receipt=False):
    meta = source.stat()
    identity = FileIdentity(
        str(source),
        "file" if source.is_file() else "directory",
        meta.st_uid,
        meta.st_dev,
        meta.st_ino,
        hashlib.sha256(source.read_bytes()).hexdigest() if receipt else None,
    )
    first = settings.contracts[0]
    updated = (
        replace(first, receipts=(identity,)) if receipt else replace(first, mounts=(identity,))
    )
    return replace(settings, contracts=(updated, *settings.contracts[1:]))


@pytest.mark.parametrize("mount_kind", ["--volume", "--mount"])
def test_bind_mounts_preserve_explicit_data_paths(tmp_path, mount_kind):
    config, settings, _, workloads, _ = fleet(tmp_path)
    source = tmp_path / "data"
    source.mkdir(mode=0o700)
    settings = enrolled_input(settings, source)
    argument = (
        f"{source}:/config:rw"
        if mount_kind == "--volume"
        else f"type=bind,source={source},target=/config,readonly"
    )
    workload = replace(workloads[0], options=(Option(mount_kind, argument), Option("--init", None)))
    rendered = create_arguments(config, settings, workload)
    assert argument in rendered
    assert rendered[-2:] == ["--init", workload.image]


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--volume", "relative:/config"),
        ("--volume", "/host:relative"),
        ("--volume", "/host:/config:unsupported"),
        ("--mount", "type=bind,source=/host,source=/other,target=/config"),
        ("--mount", "type=volume,source=/host,target=/config"),
        ("--mount", "type=bind,source=relative,target=/config"),
        ("--mount", "type=bind,source=/host,target=/config,unparsed"),
        ("--env-file", "/host/private-env"),
        ("--kernel", "/host/kernel"),
        ("--init-image", "example.invalid/unpinned:latest"),
    ],
)
def test_unenrolled_or_ambiguous_workload_inputs_are_rejected(tmp_path, flag, value):
    config, settings, _, workloads, _ = fleet(tmp_path)
    with pytest.raises(ValueError):
        create_arguments(config, settings, replace(workloads[0], options=(Option(flag, value),)))


def test_kernel_arguments_require_reviewed_vendor_version(tmp_path):
    config, settings, _, workloads, _ = fleet(tmp_path)
    workload = replace(
        workloads[0], options=(Option("--kernel-arg", "net.ipv4.ip_local_port_range=45000 45127"),)
    )
    with pytest.raises(ValueError):
        create_arguments(config, replace(settings, accepted_version="1.4.1"), workload)
    assert "--kernel-arg" in create_arguments(config, settings, workload)


def test_hashed_external_receipt_is_fenced_before_native_creation(tmp_path):
    config, settings, fake, workloads, _ = fleet(tmp_path)
    source = tmp_path / "kernel"
    source.write_bytes(b"verified")
    source.chmod(0o600)
    settings = enrolled_input(settings, source, receipt=True)
    workload = replace(workloads[0], options=(Option("--kernel", str(source)),))
    assert str(source) in create_arguments(config, settings, workload)
    source.write_bytes(b"drifted")
    with pytest.raises(RuntimeReadError):
        plan_workloads(config, settings, (workload, *workloads[1:]), fake)
    assert not fake.existing


def test_parse_round_trip_and_duplicate_service_rejected():
    value = {
        "schema_version": 1,
        "workloads": [
            {
                "service": "example",
                "image": "example.invalid/a@sha256:" + "1" * 64,
                "options": [{"flag": "--cpus", "value": "2"}, {"flag": "--init", "value": None}],
                "arguments": ["--application-option"],
            }
        ],
    }
    parsed = parse_workloads(value)
    assert parsed[0].options == (Option("--cpus", "2"), Option("--init", None))
    value["workloads"].append(copy.deepcopy(value["workloads"][0]))
    with pytest.raises(ValueError):
        parse_workloads(value)


@pytest.mark.parametrize(
    "raw",
    [
        None,
        {"flag": "--init"},
        {"flag": True, "value": None},
        {"flag": "--cpus", "value": ""},
        {"flag": "--memory", "value": "1\n2"},
    ],
)
def test_recipe_option_shape_and_bounds_rejected(raw):
    with pytest.raises(ValueError):
        parse_workloads(
            {
                "schema_version": 1,
                "workloads": [
                    {
                        "service": "example",
                        "image": "example.invalid/a@sha256:" + "1" * 64,
                        "options": [raw],
                        "arguments": [],
                    }
                ],
            }
        )


@pytest.mark.parametrize("mode", [0o620, 0o602])
def test_receipt_second_writer_is_refused_even_when_checksum_matches(tmp_path, monkeypatch, mode):
    config, settings, fake, workloads, _ = fleet(tmp_path)
    source = tmp_path / "private-env"
    source.write_bytes(b"PRIVATE=unchanged")
    source.chmod(mode)
    settings = enrolled_input(settings, source, receipt=True)
    workload = replace(workloads[0], options=(Option("--env-file", str(source)),))
    monkeypatch.setattr("netorch.apple_runtime.reject_acl", lambda path, **kwargs: None)
    with pytest.raises(RuntimeReadError):
        plan_workloads(config, settings, (workload, *workloads[1:]), fake)
    assert not fake.existing


@pytest.mark.parametrize(
    "failure", [PermissionError("private ACL probe denied"), UnsafeState("unknown ACL")]
)
def test_receipt_acl_unknown_or_denied_never_provisions(tmp_path, monkeypatch, failure):
    config, settings, fake, workloads, _ = fleet(tmp_path)
    source = tmp_path / "private-env"
    source.write_bytes(b"PRIVATE=unchanged")
    source.chmod(0o600)
    settings = enrolled_input(settings, source, receipt=True)
    workload = replace(workloads[0], options=(Option("--env-file", str(source)),))

    def inaccessible_acl(path, **kwargs):
        if path == source:
            raise failure

    monkeypatch.setattr("netorch.apple_runtime.reject_acl", inaccessible_acl)
    with pytest.raises(RuntimeReadError):
        plan_workloads(config, settings, (workload, *workloads[1:]), fake)
    assert not fake.existing


def test_recipe_mount_source_coverage_is_exact(tmp_path):
    config, settings, _, workloads, _ = fleet(tmp_path)
    with pytest.raises(ValueError):
        create_arguments(
            config,
            settings,
            replace(workloads[0], options=(Option("--volume", "/unrelated:/config:rw"),)),
        )


def cli_settings(tmp_path, monkeypatch):
    from dataclasses import asdict

    import netorch.workloads as module

    config, settings, fake, workloads, store = fleet(tmp_path)
    settings = replace(settings, policy=str(tmp_path / "private-policy.json"))
    recipes = tmp_path / "recipes.json"
    recipes.write_bytes(
        canonical_bytes({"schema_version": 1, "workloads": [asdict(item) for item in workloads]})
    )
    monkeypatch.setattr(module, "load_settings", lambda path: settings)
    monkeypatch.setattr(module, "load_config", lambda path: config)
    return module, config, settings, fake, workloads, store, recipes


@pytest.mark.usefixtures("legacy_cli_conformance")
def test_cli_plan_and_provision_use_reviewed_digest_and_explicit_start(
    tmp_path, monkeypatch, capsys
):
    module, config, _settings, fake, workloads, store, recipes = cli_settings(tmp_path, monkeypatch)
    plan_impl, provision_impl = module.plan_workloads, module.provision_workloads
    monkeypatch.setattr(
        module,
        "plan_workloads",
        lambda config, settings, workloads, _runner=None, **kwargs: plan_impl(
            config, settings, workloads, fake, **kwargs
        ),
    )
    monkeypatch.setattr(
        module,
        "provision_workloads",
        lambda config, settings, workloads, **kwargs: provision_impl(
            config, settings, workloads, runner=fake, **kwargs
        ),
    )
    prefix = ["--settings", str(tmp_path / "private-settings.json"), "--recipes", str(recipes)]
    assert main([*prefix, "plan", "--start-initial"]) == 0
    from netorch.codec import strict_loads

    candidate = strict_loads(capsys.readouterr().out)
    assert candidate["recipe_digest"] == recipe_digest(workloads)
    assert not fake.existing
    assert (
        main(
            [
                *prefix,
                "provision",
                "--expected-digest",
                candidate["provision_digest"],
                "--start-initial",
            ]
        )
        == 0
    )
    result = strict_loads(capsys.readouterr().out)
    assert result["started_initial"] and result["enrollment_required"]
    assert intent_from_dict(store.read("intent.json")).operator_paused
    assert len(fake.existing) == len(config.services)


@pytest.mark.parametrize(
    "failure,code",
    [(Busy("private lock path"), 75), (UnsafeState("private corrupt intent path"), 69)],
)
def test_cli_lock_and_unsafe_state_errors_do_not_leak_private_paths(
    tmp_path, monkeypatch, capsys, failure, code
):
    module, _, _, fake, _, _, recipes = cli_settings(tmp_path, monkeypatch)

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(module, "plan_workloads", fail)
    assert (
        main(
            [
                "--settings",
                str(tmp_path / "private-settings.json"),
                "--recipes",
                str(recipes),
                "plan",
            ]
        )
        == code
    )
    captured = capsys.readouterr()
    assert not captured.out
    assert "private" not in captured.err
    assert str(tmp_path) not in captured.err
    assert not fake.calls


def test_cli_missing_policy_is_closed_failure_before_runtime(tmp_path, monkeypatch, capsys):
    module, _, settings, fake, _, _, recipes = cli_settings(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "load_settings", lambda path: replace(settings, policy=None))
    assert (
        main(
            [
                "--settings",
                str(tmp_path / "private-settings.json"),
                "--recipes",
                str(recipes),
                "plan",
            ]
        )
        == 69
    )
    assert "private" not in capsys.readouterr().err
    assert not fake.calls


@pytest.mark.parametrize("change", ["policy", "network", "identity", "recipe", "start", "compiler"])
def test_resolved_creation_authority_changes_require_new_review(tmp_path, monkeypatch, change):
    import netorch.workloads as module

    config, settings, fake, workloads, store = fleet(tmp_path)
    approved = provision_digest(config, settings, workloads)
    start_initial = False
    if change == "policy":
        config = replace(config, scopes=(replace(config.scopes[0], host_ipv4="192.0.2.11"),))
    elif change == "network":
        settings = replace(
            settings, networks=(replace(settings.networks[0], name="different-network"),)
        )
    elif change == "identity":
        settings = replace(
            settings, account=replace(settings.account, home=str(tmp_path / "different-home"))
        )
    elif change == "recipe":
        workloads = (replace(workloads[0], options=(Option("--cpus", "3"),)), *workloads[1:])
    elif change == "start":
        start_initial = True
    else:
        compiler = module.create_arguments
        monkeypatch.setattr(
            module, "create_arguments", lambda *args: [*compiler(*args), "changed-cli-semantics"]
        )
    resolved = provision_digest(config, settings, workloads, start_initial=start_initial)
    assert resolved != approved
    with pytest.raises(ValueError):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=approved,
            start_initial=start_initial,
            runner=fake,
        )
    assert not fake.calls and not fake.existing
    assert not (store.directory / "workload-journal.json").exists()
    assert intent_from_dict(store.read("intent.json")).operator_paused


def test_approval_of_stopped_plan_cannot_start_guests(tmp_path):
    config, settings, fake, workloads, _ = fleet(tmp_path)
    stopped = plan_workloads(config, settings, workloads, fake)
    started = plan_workloads(config, settings, workloads, fake, start_initial=True)
    assert stopped["recipe_digest"] == started["recipe_digest"]
    assert stopped["provision_digest"] != started["provision_digest"]
    fake.calls.clear()
    with pytest.raises(ValueError):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=stopped["provision_digest"],
            start_initial=True,
            runner=fake,
        )
    assert not fake.calls and not fake.existing


def test_recipe_digest_alone_never_authorizes_initial_provision(tmp_path):
    config, settings, fake, workloads, _ = fleet(tmp_path)
    with pytest.raises(ValueError):
        provision_workloads(
            config, settings, workloads, expected_digest=recipe_digest(workloads), runner=fake
        )
    assert not fake.calls


def test_initial_start_mode_must_be_explicit_boolean(tmp_path):
    config, settings, _, workloads, _ = fleet(tmp_path)
    with pytest.raises(ValueError):
        provision_digest(config, settings, workloads, start_initial=1)


def test_plan_shares_bounded_acl_cache_for_unchanged_receipt_identity(tmp_path, monkeypatch):
    config, settings, fake, workloads, _ = fleet(tmp_path)
    source = tmp_path / "shared-read-only-kernel"
    source.write_bytes(b"verified kernel")
    source.chmod(0o600)
    settings = enrolled_input(settings, source, receipt=True)
    receipt = settings.contracts[0].receipts[0]
    settings = replace(
        settings,
        contracts=(
            settings.contracts[0],
            replace(settings.contracts[1], receipts=(receipt,)),
            *settings.contracts[2:],
        ),
    )
    workloads = tuple(
        replace(item, options=(Option("--kernel", str(source)),)) if index < 2 else item
        for index, item in enumerate(workloads)
    )
    acl_calls = []

    def acl_read(path, *, timeout):
        assert 0 < timeout <= 2
        acl_calls.append(path)

    monkeypatch.setattr("netorch.apple_runtime.reject_acl", acl_read)
    plan_workloads(config, settings, workloads, fake)
    assert acl_calls.count(source) == 1
    assert all(acl_calls.count(parent) == 1 for parent in source.parents)


def interrupted_provision(tmp_path):
    config, settings, fake, workloads, store = fleet(tmp_path)
    failed_name = settings.contracts[1].name
    fake.failure = lambda argv: argv[1:2] == ["create"] and failed_name in argv
    approved = provision_digest(config, settings, workloads)
    with pytest.raises(RuntimeReadError):
        provision_workloads(config, settings, workloads, expected_digest=approved, runner=fake)
    return config, settings, fake, workloads, store, store.read("workload-journal.json")


def acknowledge(settings, journal, **changes):
    kwargs = {
        "expected_digest": journal["provision_digest"],
        "holder": journal["holder"],
        "expected_phase": "failed",
    }
    kwargs.update(changes)
    return acknowledge_workload_operation(settings, **kwargs)


def test_acknowledgement_keeps_partial_workloads_and_completed_history(tmp_path):
    config, settings, fake, workloads, store, journal = interrupted_provision(tmp_path)
    before_native_calls = list(fake.calls)
    before_workloads = copy.deepcopy(fake.existing)
    outcome = acknowledge(settings, journal)
    current = store.read("workload-journal.json")
    assert current["phase"] == "acknowledged"
    assert current["acknowledgement_phase"] == "failed"
    assert current["completed"] == journal["completed"] == [workloads[0].service]
    assert current["recipe_digest"] == journal["recipe_digest"]
    assert current["provision_digest"] == journal["provision_digest"]
    assert current["operator_acknowledged"] is True
    intent = intent_from_dict(store.read("intent.json"))
    assert intent.operator_paused and not intent.suspensions
    assert outcome["lifecycle_changed"] is False and outcome["admitted"] is False
    assert fake.calls == before_native_calls and fake.existing == before_workloads
    # The next reviewed plan can retain that exact stopped definition, then
    # create only the missing definitions. No guessed rollback or recreation.
    fake.failure = None
    candidate = plan_workloads(config, settings, workloads, fake)
    assert candidate["steps"][0]["action"] == "start-existing"
    provision_workloads(
        config, settings, workloads, expected_digest=candidate["provision_digest"], runner=fake
    )
    assert len(fake.existing) == 7
    assert intent_from_dict(store.read("intent.json")).operator_paused


def test_acknowledgement_preserves_foreign_holds_and_next_provision_remains_blocked(tmp_path):
    config, settings, fake, workloads, store, journal = interrupted_provision(tmp_path)
    intent = intent_from_dict(store.read("intent.json")).suspend("backup", "backup-owner")
    store.write("intent.json", intent_to_dict(intent))
    before = copy.deepcopy(fake.existing)
    result = acknowledge(settings, journal)
    current = intent_from_dict(store.read("intent.json"))
    assert current.operator_paused and dict(current.suspensions) == {"backup": "backup-owner"}
    assert result["remaining_suspensions"] == ["backup"]
    calls = len(fake.calls)
    with pytest.raises(ValueError):
        provision_workloads(
            config, settings, workloads, expected_digest=journal["provision_digest"], runner=fake
        )
    assert len(fake.calls) == calls and fake.existing == before


@pytest.mark.parametrize("phase", ["applying", "failed"])
def test_interrupted_phase_must_be_explicitly_acknowledged(tmp_path, phase):
    _, settings, fake, _, store, journal = interrupted_provision(tmp_path)
    journal["phase"] = phase
    store.write("workload-journal.json", journal)
    before = len(fake.calls)
    acknowledge(settings, journal, expected_phase=phase)
    assert store.read("workload-journal.json")["acknowledgement_phase"] == phase
    assert len(fake.calls) == before


@pytest.mark.parametrize(
    "fault",
    [
        "digest",
        "holder",
        "phase",
        "not-paused",
        "damaged",
        "foreign-holder",
        "missing-holder",
        "committed",
        "wrong-user",
        "root",
    ],
)
def test_acknowledgement_authority_failures_change_nothing(tmp_path, monkeypatch, fault):
    _, settings, fake, _, store, journal = interrupted_provision(tmp_path)
    kwargs = {}
    intent = intent_from_dict(store.read("intent.json"))
    if fault == "digest":
        kwargs = {"expected_digest": "b" * 64, "holder": "provision-" + "b" * 32}
    elif fault == "holder":
        kwargs = {"holder": "some-other-holder"}
    elif fault == "phase":
        kwargs = {"expected_phase": "applying"}
    elif fault == "not-paused":
        intent = intent.resume()
    elif fault == "damaged":
        intent = replace(intent, damaged=True)
    elif fault == "foreign-holder":
        intent = replace(intent, suspensions={"initial-provision": "another-owner"})
    elif fault == "missing-holder":
        intent = intent.release("initial-provision", journal["holder"])
    elif fault == "committed":
        journal["phase"] = "committed"
        store.write("workload-journal.json", journal)
    store.write("intent.json", intent_to_dict(intent))
    before = {p.name: p.read_bytes() for p in store.directory.iterdir() if p.is_file()}
    calls = len(fake.calls)
    if fault in {"wrong-user", "root"}:
        monkeypatch.setattr(
            "netorch.workloads.os.geteuid",
            lambda: 0 if fault == "root" else settings.account.uid + 1,
        )
    with pytest.raises((ValueError, PermissionError)):
        acknowledge(settings, journal, **kwargs)
    assert {p.name: p.read_bytes() for p in store.directory.iterdir() if p.is_file()} == before
    assert len(fake.calls) == calls


@pytest.mark.parametrize(
    "fault",
    [
        "schema",
        "extra",
        "missing",
        "phase",
        "recipe-digest",
        "holder",
        "completed",
        "duplicate-completed",
        "updated",
        "negative-time",
        "start-mode",
    ],
)
def test_corrupt_workload_journal_cannot_be_acknowledged_or_reused(tmp_path, fault):
    config, settings, fake, workloads, store, journal = interrupted_provision(tmp_path)
    broken = copy.deepcopy(journal)
    if fault == "schema":
        broken["schema_version"] = True
    elif fault == "extra":
        broken["unchecked"] = "private"
    elif fault == "missing":
        broken.pop("holder")
    elif fault == "phase":
        broken["phase"] = []
    elif fault == "recipe-digest":
        broken["recipe_digest"] = "invalid"
    elif fault == "holder":
        broken["holder"] = "foreign-holder"
    elif fault == "completed":
        broken["completed"] = [None]
    elif fault == "duplicate-completed":
        broken["completed"] *= 2
    elif fault == "updated":
        broken["updated_at"] = True
    elif fault == "negative-time":
        broken["updated_at"] = -1
    elif fault == "start-mode":
        broken["start_initial"] = 1
    store.write("workload-journal.json", broken)
    before = {p.name: p.read_bytes() for p in store.directory.iterdir() if p.is_file()}
    calls = len(fake.calls)
    with pytest.raises(ValueError):
        acknowledge(settings, journal)
    assert {p.name: p.read_bytes() for p in store.directory.iterdir() if p.is_file()} == before
    # Even a corrupted terminal phase may not authorize an unrelated new run.
    if fault != "phase":
        broken["phase"] = "committed"
        store.write("workload-journal.json", broken)
        store.write("intent.json", intent_to_dict(Intent(operator_paused=True)))
        with pytest.raises(ValueError):
            provision_workloads(
                config,
                settings,
                workloads,
                expected_digest=journal["provision_digest"],
                runner=fake,
            )
    assert len(fake.calls) == calls


def test_failed_acknowledgement_write_retains_hold_and_exact_retry_finishes(tmp_path, monkeypatch):
    _, settings, fake, _, store, journal = interrupted_provision(tmp_path)
    original_write = Store.write
    fail_once = True

    def write(self, name, value):
        nonlocal fail_once
        if name == "intent.json" and fail_once:
            fail_once = False
            raise UnsafeState("private write failure")
        original_write(self, name, value)

    monkeypatch.setattr(Store, "write", write)
    calls = len(fake.calls)
    with pytest.raises(UnsafeState):
        acknowledge(settings, journal)
    acknowledged = store.read("workload-journal.json")
    assert acknowledged["phase"] == "acknowledged"
    assert (
        intent_from_dict(store.read("intent.json")).suspensions["initial-provision"]
        == journal["holder"]
    )
    acknowledge(settings, journal)
    assert store.read("workload-journal.json") == acknowledged
    assert not intent_from_dict(store.read("intent.json")).suspensions
    assert len(fake.calls) == calls


def test_completed_acknowledgement_is_not_authority_to_clear_another_operation(tmp_path):
    _, settings, _, _, store, journal = interrupted_provision(tmp_path)
    acknowledge(settings, journal)
    store.write(
        "intent.json", intent_to_dict(Intent(operator_paused=True).suspend("installation", "other"))
    )
    before = store.read("intent.json")
    with pytest.raises(ValueError):
        acknowledge(settings, journal)
    assert store.read("intent.json") == before


@pytest.mark.usefixtures("legacy_cli_conformance")
def test_cli_acknowledgement_needs_no_recipe_policy_or_native_command(
    tmp_path, monkeypatch, capsys
):
    import netorch.workloads as module

    _, settings, fake, _, store, journal = interrupted_provision(tmp_path)
    monkeypatch.setattr(module, "load_settings", lambda path: replace(settings, policy=None))
    calls = len(fake.calls)
    assert (
        main(
            [
                "--settings",
                str(tmp_path / "private-settings.json"),
                "acknowledge",
                "--expected-digest",
                journal["provision_digest"],
                "--holder",
                journal["holder"],
                "--phase",
                "failed",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert not captured.err and "private" not in captured.out and str(tmp_path) not in captured.out
    assert store.read("workload-journal.json")["phase"] == "acknowledged"
    assert len(fake.calls) == calls


@pytest.mark.usefixtures("legacy_cli_conformance")
def test_cli_acknowledgement_busy_is_closed_no_mutation(tmp_path, monkeypatch, capsys):
    from contextlib import contextmanager

    import netorch.workloads as module

    _, settings, _, _, store, journal = interrupted_provision(tmp_path)
    monkeypatch.setattr(module, "load_settings", lambda path: settings)

    @contextmanager
    def held(self):
        raise Busy("private lock path")
        yield

    monkeypatch.setattr(Store, "lock", held)
    before = store.read("workload-journal.json")
    assert (
        main(
            [
                "--settings",
                str(tmp_path / "private-settings.json"),
                "acknowledge",
                "--expected-digest",
                journal["provision_digest"],
                "--holder",
                journal["holder"],
                "--phase",
                "failed",
            ]
        )
        == 75
    )
    captured = capsys.readouterr()
    assert not captured.out and "private" not in captured.err
    assert store.read("workload-journal.json") == before


@pytest.fixture
def legacy_cli_conformance(monkeypatch):
    """Explicit CI-only seam for preserved owner internals; never qualification."""
    import netorch.workloads as module

    monkeypatch.setattr(module, "require_mutation_qualified", lambda _capability: None)

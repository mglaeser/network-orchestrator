"""A fully stopped fleet is read as stopped only on the service manager's own word.

Without `fleet_start` the all-stopped guard is unchanged. With it, a guest that
the API lists as stopped is absent only while the vendor API job is the declared
one before and after the pass and the service manager has no runtime job for
that guest. Everything native is faked here; the last six tests are contract
checks of the real service manager and run only on a hosted macOS runner.
"""

from __future__ import annotations

import copy
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch import owners, pf_owner
from netorch.codec import canonical_bytes, digest, strict_load
from netorch.config import load_config, to_dict
from netorch.process import Result
from netorch.runtime_settings import (
    RuntimeAccount,
    RuntimeNetwork,
    load_settings,
    parse_settings,
    settings_to_dict,
)
from netorch.safety_contract import recovery_exit_code
from netorch.state import Intent, Observation, Snapshot, intent_to_dict
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_runtime_settings import authored

__all__ = ["enrolled"]

ROOT = Path(__file__).resolve().parents[1]
# Assembled at run time: the public host-data guard reads a literal as a site namespace.
NAMESPACE = ".".join(["org", "example"])
API_LABEL = f"{NAMESPACE}.vendor-api"
API_PROGRAM = "/usr/libexec/example-api"
JOB_PREFIX = f"{NAMESPACE}.runtime."
JOB = f"{NAMESPACE}.job"
HANDLER = "example-runtime"
DECLARATION = {
    "api_label": API_LABEL,
    "api_executable": API_PROGRAM,
    "runtime_label_prefix": JOB_PREFIX,
}
STARTED = "Mon Oct  5 08:00:00 2026"
# Taken from the tree before the declaration existed: the same inputs must keep them.
AUTHORED_SETTINGS_DIGEST = "6dd79016779aa6e1ef2a82ce99dd40e315faffbd13cb71c1f65ae2df72d1bde9"
EXAMPLE_SETTINGS_DIGEST = "d1307ffc7cb45fb28b71c4cd190e57a4f8548b76b28a66fad9c4eec52cc28ab8"
UNDECLARED_GENERATION = "network-c4339c5f1af8b87bc98c7f91a88cbff5e9d2aef359c054252331bd709567b4e5"
NOT_LOADED = Result(113, b"", b"Could not find service\n")


def job_report(pid: int, program: str = API_PROGRAM, state: str = "running") -> bytes:
    """A synthetic service print in the shape the reader assumes, nested blocks included."""
    return (
        f"gui/501/{API_LABEL} = {{\n"
        "\tactive count = 1\n"
        "\ttype = LaunchAgent\n"
        f"\tstate = {state}\n"
        "\n"
        f"\tprogram = {program}\n"
        "\targuments = {\n"
        f"\t\t{program}\n"
        "\t\tstart\n"
        "\t}\n"
        "\n"
        "\truns = 1\n"
        f"\tpid = {pid}\n"
        "\n"
        "\tjetsam coalition = {\n"
        "\t\tID = 584\n"
        "\t\tstate = active\n"
        "\t}\n"
        "}\n"
    ).encode()


class FleetRunner(FakeRunner):
    """The shared fake plus the service manager's view of the API job and the runtime jobs."""

    def __init__(self, settings: Any, items: dict[str, Any]) -> None:
        super().__init__(settings, items)
        self.domain = settings.networks[0].helper_domain
        # Per domain, the guests whose runtime job the service manager has loaded.
        self.jobs: dict[str, set[str]] = {
            self.domain: {
                name for name, item in items.items() if item["status"]["state"] != "stopped"
            }
        }
        self.api_pid = 222
        self.api_started = STARTED
        self.api_print: Result | None = None
        self.api_process: str | None = None
        self.job_print: Result | None = None
        self.passes = 0
        self.api_reads = 0
        # The API job's process id as a function of the pass or of the read, to restart it.
        self.pid_at_pass: Callable[[int], int] | None = None
        self.pid_at_read: Callable[[int], int] | None = None

    def stop_everything(self, *, jobs_too: bool = True) -> None:
        for item in self.items.values():
            item["status"]["state"] = "stopped"
        if jobs_too:
            self.jobs = {}

    def __call__(self, argv: list[str], **kwargs: Any) -> Result:
        if argv[1:] == ["--version"]:
            # Every observation pass begins with exactly one version read.
            self.passes += 1
            if self.pid_at_pass is not None:
                self.api_pid = self.pid_at_pass(self.passes)
        if argv[:2] == ["/bin/launchctl", "print"]:
            domain, _, label = argv[2].rpartition("/")
            if label == API_LABEL:
                self.calls.append((argv, kwargs))
                assert domain == self.domain
                self.api_reads += 1
                if self.pid_at_read is not None:
                    self.api_pid = self.pid_at_read(self.api_reads)
                return self.api_print or Result(0, job_report(self.api_pid), b"")
            if label.startswith(JOB_PREFIX):
                self.calls.append((argv, kwargs))
                assert kwargs["max_output"] == 262_144 and 0 < kwargs["timeout"] <= 3
                name = label.removeprefix(f"{JOB_PREFIX}{HANDLER}.")
                assert name in self.items, argv
                if self.job_print is not None:
                    return self.job_print
                if name in self.jobs.get(domain, set()):
                    return Result(0, job_report(333), b"")
                return NOT_LOADED
        if argv[0] == "/bin/ps" and argv[2] == str(self.api_pid):
            self.calls.append((argv, kwargs))
            line = self.api_process or "{uid} {started} {program}\n"
            values = {
                "uid": self.settings.account.uid,
                "started": self.api_started,
                "program": API_PROGRAM,
            }
            return Result(0, line.format(**values).encode(), b"")
        result = super().__call__(argv, **kwargs)
        if argv[0] == self.settings.executable and argv[1:2] == ["start"]:
            self.jobs.setdefault(self.domain, set()).add(argv[2])
        return result


def declared(enrolled: Any, **changes: Any) -> tuple[Any, Any, FleetRunner]:
    """The enrolled fixture with the declaration, read back through the closed loader."""
    config, settings, items = enrolled
    for item in items.values():
        item["configuration"].update({"id": item["id"], "runtimeHandler": HANDLER, **changes})
        for key in [key for key, value in changes.items() if value is None]:
            del item["configuration"][key]
    settings = replace(
        settings,
        contracts=tuple(
            replace(c, configuration_sha256=digest(items[c.name]["configuration"]))
            for c in settings.contracts
        ),
    )
    settings = parse_settings({**settings_to_dict(settings), "fleet_start": dict(DECLARATION)})
    config = runtime.derive_policy(config, settings)
    Path(settings.policy).write_bytes(canonical_bytes(to_dict(config)))
    return config, settings, FleetRunner(settings, items)


def states(snapshot: Any) -> dict[str, tuple[str, str]]:
    return {key: (item.state, item.reason) for key, item in snapshot.services.items()}


def starts(runner: FakeRunner) -> list[str]:
    return [
        argv[2]
        for argv, _ in runner.calls
        if argv[0] == runner.settings.executable and argv[1:2] == ["start"]
    ]


def job_reads(runner: FakeRunner) -> list[str]:
    return [
        argv[2]
        for argv, _ in runner.calls
        if argv[:2] == ["/bin/launchctl", "print"] and f"/{JOB_PREFIX}" in argv[2]
    ]


def observe(config: Any, settings: Any, runner: FakeRunner) -> Any:
    return runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)


def probe(monkeypatch: Any, config: Any, settings: Any, runner: FakeRunner) -> dict[str, int]:
    """The supervisor's check for every workload, from a real observation to the exit code."""
    real = runtime.observe_runtime
    with monkeypatch.context() as patch:
        patch.setattr(runtime, "load_settings", lambda _path: settings)
        patch.setattr(runtime, "observe_runtime", lambda c, s: real(c, s, runner))
        return {
            service.id: runtime.main(["--settings", "/unused", "probe", "--service", service.id])
            for service in config.services
        }


def test_boot_all_stopped_with_no_runtime_job_is_proven_and_the_fleet_starts(
    enrolled: Any, monkeypatch: Any
) -> None:
    config, settings, runner = declared(enrolled)
    runner.stop_everything()
    observed = observe(config, settings, runner)
    assert states(observed) == {s.id: ("absent", "confirmed-absent") for s in config.services}
    assert observed.network_generation is not None
    assert set(probe(monkeypatch, config, settings, runner).values()) == {runtime.STOPPED}
    for service in config.services:
        result = runtime.recover_service(config, settings, service.id, runner)
        assert result.services[service.id].state == "present"
    assert sorted(starts(runner)) == sorted(contract.name for contract in settings.contracts)
    assert set(states(observe(config, settings, runner)).values()) == {("present", "verified")}


def test_api_restart_all_stopped_while_runtime_jobs_live_is_unknown(
    enrolled: Any, monkeypatch: Any
) -> None:
    config, settings, runner = declared(enrolled)
    # A restarted API lists every stored definition as stopped; the guests' own
    # runtime jobs are still loaded.
    runner.stop_everything(jobs_too=False)
    runner.api_pid = 223
    observed = observe(config, settings, runner)
    assert states(observed) == {s.id: ("unknown", "generation-mismatch") for s in config.services}
    assert set(probe(monkeypatch, config, settings, runner).values()) == {runtime.UNKNOWN}
    for service in config.services:
        with pytest.raises(runtime.RuntimeReadError):
            runtime.recover_service(config, settings, service.id, runner)
    assert starts(runner) == []


def test_the_gap_of_the_fleet_guard_is_closed_per_workload(enrolled: Any) -> None:
    config, settings, runner = declared(enrolled)
    for name, item in runner.items.items():
        if name != "example-resolver":
            item["status"]["state"] = "stopped"
    # One row runs, so the all-stopped guard would not have applied: each other
    # row is judged by its own runtime job.
    observed = states(observe(config, settings, runner))
    assert observed["resolver"] == ("present", "verified")
    assert {observed[key] for key in observed if key != "resolver"} == {
        ("unknown", "generation-mismatch")
    }
    runner.jobs[runner.domain].discard("example-camera")
    observed = states(observe(config, settings, runner))
    assert observed["camera"] == ("absent", "confirmed-absent")
    assert observed["web-proxy"] == ("unknown", "generation-mismatch")
    assert observed["resolver"] == ("present", "verified")
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "web-proxy", runner)
    assert starts(runner) == []
    runtime.recover_service(config, settings, "camera", runner)
    assert starts(runner) == ["example-camera"]


def test_a_runtime_job_in_the_account_s_other_domain_is_as_live(enrolled: Any) -> None:
    config, settings, runner = declared(enrolled)
    runner.stop_everything()
    uid = settings.account.uid
    runner.jobs = {f"user/{uid}": {"example-resolver"}}
    observed = states(observe(config, settings, runner))
    assert observed["resolver"] == ("unknown", "generation-mismatch")
    assert {observed[key] for key in observed if key != "resolver"} == {
        ("absent", "confirmed-absent")
    }
    label = f"{JOB_PREFIX}{HANDLER}.example-camera"
    assert {f"gui/{uid}/{label}", f"user/{uid}/{label}"} <= set(job_reads(runner))
    assert {read.rpartition("/")[0] for read in job_reads(runner)} == {f"gui/{uid}", f"user/{uid}"}


# Each fault: what the fake answers instead, and the reason every workload then carries.
API_FAULTS: dict[str, tuple[dict[str, Any], str]] = {
    "api-not-loaded": ({"api_print": NOT_LOADED}, "unavailable"),
    "api-not-running": (
        {"api_print": Result(0, job_report(222, state="waiting"), b"")},
        "identity-mismatch",
    ),
    "api-without-a-process": (
        {"api_print": Result(0, job_report(222).replace(b"\tpid = 222\n", b""), b"")},
        "identity-mismatch",
    ),
    "api-other-program": (
        {"api_print": Result(0, job_report(222, "/usr/libexec/another"), b"")},
        "identity-mismatch",
    ),
    "api-process-of-another-account": (
        {"api_process": "0 {started} {program}\n"},
        "identity-mismatch",
    ),
    "api-process-runs-another-program": (
        {"api_process": "{uid} {started} /usr/libexec/another\n"},
        "identity-mismatch",
    ),
    "api-process-unreadable": ({"api_process": "malformed process\n"}, "identity-mismatch"),
}
JOB_FAULTS: dict[str, Result] = {
    "job-read-fails": Result(1, b"", b"launchctl failed\n"),
    "job-absent-under-another-status": Result(3, b"", b"No such process\n"),
    "job-absent-with-output": Result(113, b"state = running\n", b""),
    "job-printed-with-an-error": Result(0, job_report(333), b"warning\n"),
    "job-print-is-empty": Result(0, b"", b""),
}
DEFINITION_FAULTS: dict[str, dict[str, Any]] = {
    "no-handler": {"runtimeHandler": None},
    "handler-is-not-text": {"runtimeHandler": 7},
    "handler-in-an-unfamiliar-spelling": {"runtimeHandler": "Example.Runtime"},
    "definition-names-another-guest": {"id": "example-other"},
    "definition-without-its-name": {"id": None},
}


@pytest.mark.parametrize("fault", [*API_FAULTS, *JOB_FAULTS, *DEFINITION_FAULTS])
def test_missing_evidence_is_unknown(enrolled: Any, fault: str) -> None:
    config, settings, runner = declared(enrolled, **DEFINITION_FAULTS.get(fault, {}))
    runner.stop_everything()
    if fault in API_FAULTS:
        answers, reason = API_FAULTS[fault]
        for name, value in answers.items():
            setattr(runner, name, value)
    elif fault in JOB_FAULTS:
        runner.job_print, reason = JOB_FAULTS[fault], "unavailable"
    else:
        reason = "identity-mismatch"
    observed = observe(config, settings, runner)
    assert states(observed) == {s.id: ("unknown", reason) for s in config.services}
    # Evidence about the API job fails the pass; evidence about one job fails one workload.
    assert (observed.network_generation is None) == (fault in API_FAULTS)
    if fault in DEFINITION_FAULTS:
        assert job_reads(runner) == []
    for service in config.services:
        with pytest.raises(runtime.RuntimeReadError):
            runtime.recover_service(config, settings, service.id, runner)
    assert starts(runner) == []


def test_api_restart_between_the_two_observations_refuses_the_start(enrolled: Any) -> None:
    config, settings, runner = declared(enrolled)
    runner.stop_everything()
    first = observe(config, settings, runner)
    runner.api_pid = 223
    second = observe(config, settings, runner)
    runner.api_pid, runner.api_started = 222, "Mon Oct  5 08:00:01 2026"
    third = observe(config, settings, runner)
    # Each read alone is a proven stop, but they are three generations.
    for snapshot in (first, second, third):
        assert set(states(snapshot).values()) == {("absent", "confirmed-absent")}
    assert len({first.network_generation, second.network_generation, third.network_generation}) == 3

    runner.api_started, runner.passes = STARTED, 0
    runner.pid_at_pass = lambda number: 222 if number == 1 else 223
    with pytest.raises(runtime.RuntimeReadError) as refused:
        runtime.recover_service(config, settings, "camera", runner)
    assert refused.value.reason == "generation-mismatch"
    assert runner.passes == 2 and starts(runner) == []


def test_api_restart_within_one_pass_is_no_generation(enrolled: Any) -> None:
    config, settings, runner = declared(enrolled)
    runner.stop_everything()
    # The job is read before the inventory and again at the end of the pass.
    runner.pid_at_read = lambda number: 222 if number == 1 else 223
    observed = observe(config, settings, runner)
    assert runner.api_reads == 2
    assert observed.network_generation is None
    assert states(observed) == {s.id: ("unknown", "generation-mismatch") for s in config.services}


def test_pause_keeps_a_proven_stopped_fleet_stopped(enrolled: Any, monkeypatch: Any) -> None:
    config, settings, runner = declared(enrolled)
    runner.stop_everything()
    assert set(states(observe(config, settings, runner)).values()) == {
        ("absent", "confirmed-absent")
    }
    Path(settings.intent).write_bytes(canonical_bytes(intent_to_dict(Intent().pause())))
    assert set(probe(monkeypatch, config, settings, runner).values()) == {runtime.UNKNOWN}
    for service in config.services:
        with pytest.raises(runtime.RuntimeReadError):
            runtime.recover_service(config, settings, service.id, runner)
    assert starts(runner) == []


def test_settings_without_the_declaration_keep_their_bytes_and_the_guard(enrolled: Any) -> None:
    plain = parse_settings(authored())
    assert "fleet_start" not in settings_to_dict(plain)
    assert digest(settings_to_dict(plain)) == AUTHORED_SETTINGS_DIGEST
    example = load_settings(ROOT / "examples/runtime-settings.json")
    assert digest(settings_to_dict(example)) == EXAMPLE_SETTINGS_DIGEST

    # A fixed account, so that the literal does not depend on who runs the suite.
    config, settings, items = enrolled
    network = replace(settings.networks[0], helper_domain="gui/501", helper_uid=501)
    settings = replace(
        settings, account=RuntimeAccount(501, 20, settings.account.home), networks=(network,)
    )
    runner = FakeRunner(settings, items)
    observed = observe(config, settings, runner)
    assert observed.network_generation == UNDECLARED_GENERATION
    assert set(states(observed).values()) == {("present", "verified")}
    assert len(runner.calls) == 16
    for item in runner.items.values():
        item["status"]["state"] = "stopped"
    guarded = observe(config, settings, runner)
    assert states(guarded) == {s.id: ("unknown", "incomplete") for s in config.services}
    assert guarded.network_generation is None
    # No service-manager read beyond the network helper's own two.
    assert sum(argv[0] == "/bin/launchctl" for argv, _ in runner.calls) == 2 + 1


def test_the_declaration_changes_the_generation_and_reads_the_job_twice(enrolled: Any) -> None:
    config, settings, items = enrolled
    undeclared = observe(config, settings, FakeRunner(settings, copy.deepcopy(items)))
    config, settings, runner = declared(enrolled)
    observed = observe(config, settings, runner)
    assert set(states(observed).values()) == {("present", "verified")}
    assert observed.network_generation not in {None, undeclared.network_generation}
    # A running guest needs no runtime-job read. The API job is read twice: before
    # the inventory it vouches for, and last of all.
    assert runner.api_reads == 2 and job_reads(runner) == []
    order = [
        "api" if argv[:2] == ["/bin/launchctl", "print"] and argv[2].endswith(API_LABEL) else argv
        for argv, _ in runner.calls
    ]
    inventory = order.index([settings.executable, "list", "--all", "--format", "json"])
    assert order.index("api") < inventory and order[-2:] == [
        "api",
        ["/bin/ps", "-p", "222", "-o", "uid=", "-o", "lstart=", "-o", "comm="],
    ]
    assert runtime.Reader(settings, runner).api(settings.fleet_start, runner.domain) == {
        "pid": 222,
        "started": STARTED,
        "uid": settings.account.uid,
        "executable": API_PROGRAM,
    }


def test_owners_that_disagree_about_the_declaration_share_no_generation(enrolled: Any) -> None:
    config, settings, items = enrolled
    undeclared = observe(config, settings, FakeRunner(settings, copy.deepcopy(items)))
    config, settings, runner = declared(enrolled)
    user = observe(config, settings, runner)

    class Endpoint:
        def __init__(self, snapshot: Snapshot) -> None:
            self.snapshot = snapshot

        def observe(self) -> Snapshot:
            return self.snapshot

    def merged(root_generation: str | None) -> str | None:
        forwarding = {
            profile.id: Observation("absent", "confirmed-absent", 1000, None, {"states": ()})
            for profile in config.profiles
            if config.profile_owner(profile).id == "site-forwarding"
        }
        root = Snapshot(1000, root_generation, {}, forwarding)
        clients: Any = {settings.owner: Endpoint(user), "site-forwarding": Endpoint(root)}
        return owners.observe(config, clients).network_generation

    # The root owner's observer must carry the declaration too: the API job's
    # identity is part of the generation that every owner has to agree on.
    assert merged(user.network_generation) == user.network_generation
    assert merged(undeclared.network_generation) is None


def test_a_stopped_guest_costs_one_job_read_per_domain(enrolled: Any) -> None:
    config, settings, runner = declared(enrolled)
    runner.stop_everything()
    assert set(states(observe(config, settings, runner)).values()) == {
        ("absent", "confirmed-absent")
    }
    uid = settings.account.uid
    assert sorted(job_reads(runner)) == sorted(
        f"{domain}/{JOB_PREFIX}{HANDLER}.{contract.name}"
        for contract in settings.contracts
        for domain in (f"gui/{uid}", f"user/{uid}")
    )


def test_a_system_helper_domain_is_the_only_domain_asked(enrolled: Any) -> None:
    config, settings, items = enrolled
    system = replace(settings.networks[0], helper_domain="system")
    config, settings, runner = declared((config, replace(settings, networks=(system,)), items))
    assert runner.domain == "system"
    runner.stop_everything()
    runner.jobs = {
        f"user/{settings.account.uid}": {"example-camera"},
        "system": {"example-resolver"},
    }
    observed = states(observe(config, settings, runner))
    assert observed["resolver"] == ("unknown", "generation-mismatch")
    assert observed["camera"] == ("absent", "confirmed-absent")
    assert {read.rpartition("/")[0] for read in job_reads(runner)} == {"system"}


def test_a_reader_given_two_helper_domains_reads_nothing_as_stopped(enrolled: Any) -> None:
    config, settings, runner = declared(enrolled)
    runner.stop_everything()
    other = replace(settings.networks[0], scope="other-lan", helper_domain="system")
    # The loader refuses this; a settings object built without it is refused again.
    settings = replace(settings, networks=(settings.networks[0], other))
    scopes = (*config.scopes, replace(config.scopes[0], id="other-lan"))
    observed = observe(replace(config, scopes=scopes), settings, runner)
    assert set(states(observed).values()) == {("unknown", "identity-mismatch")}
    assert runner.api_reads == 0 and job_reads(runner) == []


def test_fleet_start_needs_one_helper_domain() -> None:
    raw = authored()
    second = {**raw["networks"][0], "scope": "other-lan", "helper_domain": "system"}
    raw["networks"].append(second)
    # Two helper domains are accepted today and stay accepted without the declaration.
    assert len(parse_settings(raw).networks) == 2
    with pytest.raises(ValueError, match="one helper domain"):
        parse_settings({**raw, "fleet_start": dict(DECLARATION)})
    second["helper_domain"] = raw["networks"][0]["helper_domain"]
    assert parse_settings({**raw, "fleet_start": dict(DECLARATION)}).fleet_start is not None


def test_unused_fleet_start_is_left_out() -> None:
    raw = authored()
    plain = parse_settings(raw)
    assert plain.fleet_start is None and "fleet_start" not in settings_to_dict(plain)
    with pytest.raises(ValueError):
        parse_settings({**raw, "fleet_start": None})
    parsed = parse_settings({**raw, "fleet_start": dict(DECLARATION)})
    assert settings_to_dict(parsed)["fleet_start"] == DECLARATION
    assert settings_to_dict(parsed) == {**settings_to_dict(plain), "fleet_start": DECLARATION}
    assert parse_settings(settings_to_dict(parsed)) == parsed
    assert (parsed.fleet_start.api_label, parsed.fleet_start.api_executable) == (
        API_LABEL,
        API_PROGRAM,
    )
    assert parsed.fleet_start.runtime_label_prefix == JOB_PREFIX


REFUSED_MEMBERS: dict[str, dict[str, Any]] = {
    "label-empty": {"api_label": ""},
    "label-leading-hyphen": {"api_label": "-leading"},
    "label-with-space": {"api_label": "has space"},
    "label-with-slash": {"api_label": "with/slash"},
    "label-too-long": {"api_label": "a" * 129},
    "label-not-text": {"api_label": 7},
    "program-relative": {"api_executable": "relative/api"},
    "program-not-canonical": {"api_executable": "/usr/../api"},
    "program-null": {"api_executable": None},
    "prefix-without-final-dot": {"runtime_label_prefix": JOB_PREFIX.removesuffix(".")},
    "prefix-only-a-dot": {"runtime_label_prefix": "."},
    "prefix-with-underscore": {"runtime_label_prefix": f"{NAMESPACE}_runtime."},
    "prefix-with-slash": {"runtime_label_prefix": "org/example."},
    "prefix-too-long": {"runtime_label_prefix": "a" * 97 + "."},
    "prefix-null": {"runtime_label_prefix": None},
    "unknown-member": {"runtime_start_timeout_seconds": 20},
}


@pytest.mark.parametrize("case", sorted(REFUSED_MEMBERS))
def test_the_declaration_is_closed_and_strict(case: str) -> None:
    with pytest.raises(ValueError):
        parse_settings({**authored(), "fleet_start": {**DECLARATION, **REFUSED_MEMBERS[case]}})


def test_the_declaration_accepts_its_bounds() -> None:
    longest = {"api_label": "a" * 128, "runtime_label_prefix": "a" * 96 + "."}
    parsed = parse_settings({**authored(), "fleet_start": {**DECLARATION, **longest}})
    assert settings_to_dict(parsed)["fleet_start"] == {**DECLARATION, **longest}
    shortest = {"api_label": "a", "runtime_label_prefix": "a."}
    assert parse_settings({**authored(), "fleet_start": {**DECLARATION, **shortest}}).fleet_start


@pytest.mark.parametrize("missing", sorted(DECLARATION))
def test_the_declaration_needs_all_three_members(missing: str) -> None:
    partial = {key: value for key, value in DECLARATION.items() if key != missing}
    with pytest.raises(ValueError):
        parse_settings({**authored(), "fleet_start": partial})
    with pytest.raises(ValueError):
        parse_settings({**authored(), "fleet_start": [DECLARATION]})


JOB_REPORTS: dict[str, tuple[bytes, bool]] = {
    "nested-print": (job_report(7), True),
    "three-lines": (f"state = running\npid = 7\nprogram = {API_PROGRAM}\n".encode(), True),
    "other-order-and-spacing": (
        f"  pid = 7  \n\tprogram = {API_PROGRAM}\t\n state = running \n".encode(),
        True,
    ),
    "not-running": (job_report(7, state="waiting"), False),
    "no-process": (job_report(7).replace(b"\tpid = 7\n", b""), False),
    "process-zero": (job_report(7).replace(b"pid = 7", b"pid = 0"), False),
    "process-with-a-leading-zero": (job_report(7).replace(b"pid = 7", b"pid = 07"), False),
    "another-program": (job_report(7, "/usr/libexec/another"), False),
    "program-under-another-key": (
        job_report(7).replace(b"\tprogram = ", b"\tprogram identifier = "),
        False,
    ),
    "empty": (b"", False),
}


@pytest.mark.parametrize("sample", sorted(JOB_REPORTS))
def test_the_api_job_is_read_with_the_grammar_of_the_network_helper(
    enrolled: Any, sample: str
) -> None:
    report, accepted = JOB_REPORTS[sample]
    _config, settings, _runner = declared(enrolled)
    uid = settings.account.uid

    def runner(argv: list[str], **_kwargs: Any) -> Result:
        if argv[0] == "/bin/launchctl":
            return Result(0, report, b"")
        assert argv[:3] == ["/bin/ps", "-p", "7"]
        return Result(0, f"{uid} {STARTED} {API_PROGRAM}\n".encode(), b"")

    reader = runtime.Reader(settings, runner)
    as_helper = RuntimeNetwork("scope", "name", "gateway", "gui/1", API_LABEL, API_PROGRAM, uid)
    expected = {"pid": 7, "started": STARTED, "uid": uid, "executable": API_PROGRAM}
    for read in (
        lambda: reader.api(settings.fleet_start, "gui/1"),
        lambda: reader.helper(as_helper),
    ):
        if accepted:
            assert read() == expected
        else:
            with pytest.raises(runtime.RuntimeReadError) as refused:
                read()
            assert refused.value.reason == "identity-mismatch"


JOB_ANSWERS: dict[str, tuple[Result, bool | None]] = {
    "no-such-job": (NOT_LOADED, True),
    "no-such-job-and-no-message": (Result(113, b"", b""), True),
    "job-printed": (Result(0, job_report(333), b""), False),
    **{name: (result, None) for name, result in JOB_FAULTS.items()},
}


@pytest.mark.parametrize("answer", sorted(JOB_ANSWERS))
def test_only_the_service_manager_s_own_answers_count(enrolled: Any, answer: str) -> None:
    result, outcome = JOB_ANSWERS[answer]
    _config, settings, _runner = declared(enrolled)
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def runner(argv: list[str], **kwargs: Any) -> Result:
        calls.append((argv, kwargs))
        return result

    reader = runtime.Reader(settings, runner)
    if outcome is None:
        with pytest.raises(runtime.RuntimeReadError) as refused:
            reader.job_absent("gui/1", JOB)
        assert refused.value.reason == "unavailable"
    else:
        assert reader.job_absent("gui/1", JOB) is outcome
    (argv, kwargs), *rest = calls
    assert not rest and argv == ["/bin/launchctl", "print", f"gui/1/{JOB}"]
    assert set(kwargs) == {"timeout", "max_output"} and 0 < kwargs["timeout"] <= 3


def test_a_proven_fleet_start_is_the_cold_start_that_may_return_42() -> None:
    absent = Observation("absent", "confirmed-absent", 100, None)
    assert recovery_exit_code(absent, now=100, max_age_seconds=30) == 1
    assert recovery_exit_code(absent, now=100, max_age_seconds=30, fleet_start_proven=True) == 42
    assert recovery_exit_code(absent, now=131, max_age_seconds=30, fleet_start_proven=True) == 1
    unknown = Observation("unknown", "generation-mismatch", 100, None)
    assert recovery_exit_code(unknown, now=100, max_age_seconds=30, fleet_start_proven=True) == 1
    present = Observation("present", "verified", 100, "synthetic-1")
    assert recovery_exit_code(present, now=100, max_age_seconds=30, fleet_start_proven=True) == 0
    with pytest.raises(ValueError):
        recovery_exit_code(absent, now=100, max_age_seconds=30, fleet_start_proven=1)  # type: ignore[arg-type]


def test_the_root_observer_takes_the_declaration_and_reads_jobs_as_itself(
    monkeypatch: Any,
) -> None:
    raw = {**strict_load(ROOT / "examples/runtime-settings.json"), "fleet_start": DECLARATION}
    config = load_config(ROOT / "examples/network.json")
    protected: list[tuple[Path, ...]] = []
    monkeypatch.setattr(pf_owner, "protected_native_code", protected.append)
    calls: list[tuple[list[str], dict[str, Any]]] = []
    monkeypatch.setattr(
        pf_owner, "run", lambda argv, **kwargs: calls.append((argv, kwargs)) or NOT_LOADED
    )

    def stub(_config: Any, settings: Any, runner: Any) -> Any:
        assert settings_to_dict(settings)["fleet_start"] == DECLARATION
        assert runtime.Reader(settings, runner).job_absent("gui/501", JOB) is True
        return observe_result

    observe_result = object()
    monkeypatch.setattr(runtime, "observe_runtime", stub)
    assert pf_owner._runtime_observer(config, raw) is observe_result
    # The print is not a vendor operation: no account switch, no wrapper.
    assert [argv for argv, _ in calls] == [["/bin/launchctl", "print", f"gui/501/{JOB}"]]
    # The root owner places no new trust in the API program: it is evidence
    # towards unknown or absent only, never towards a present guest.
    assert protected == [
        (
            Path(raw["executable"]),
            Path(raw["networks"][0]["helper_executable"]),
            Path(pf_owner.__file__).with_name("observer_child.py"),
        )
    ]


# Hosted macOS userspace contract: what the real service manager answers. These
# are evidence for the recorded runner image only; they qualify no macOS build.

GUI = pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true", reason="a remote shell may have no gui domain"
)
DOMAINS = ["user", pytest.param("gui", marks=GUI)]


class Hosted:
    """One bounded, read-only call of the real tool per request; keeps the answers."""

    def __init__(self) -> None:
        self.seen: list[tuple[list[str], Result]] = []

    def __call__(self, argv: list[str], **_kwargs: Any) -> Result:
        done = subprocess.run(argv, capture_output=True, timeout=10, check=False)
        result = Result(done.returncode, done.stdout, done.stderr)
        self.seen.append((argv, result))
        return result


def recorded(capsys: Any, title: str, seen: str) -> None:
    """On the hosted runner, keep what the service manager answered as a notice of the job."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        text = seen.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        # Capture is lifted for one line of its own: the runner reads commands at line starts.
        with capsys.disabled():
            print(f"\n::notice title={title}::{text}")


def answer(result: Result) -> str:
    """One call's outcome, short enough for a notice: a long output is only counted."""
    out = repr(result.stdout) if len(result.stdout) <= 120 else f"{len(result.stdout)} bytes"
    return f"status {result.returncode}, out {out}, err {result.stderr[:160]!r}"


def job_lines(report: str) -> str:
    """The lines of a service print that the production expressions read."""
    wanted = ("state = ", "pid = ", "program = ")
    return " | ".join(
        line.strip() for line in report.splitlines() if line.strip().startswith(wanted)
    )


def running_services(listing: str) -> dict[str, int]:
    """Label and process id of every running service in a domain print's `services` block."""
    found: dict[str, int] = {}
    inside = False
    for line in listing.splitlines():
        if not inside:
            inside = line.strip() == "services = {"
        elif line.strip() == "}":
            break
        else:
            fields = line.split()
            if len(fields) >= 2 and fields[0].isdigit() and int(fields[0]) > 0:
                found[fields[-1]] = int(fields[0])
    return found


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
@pytest.mark.parametrize("kind", DOMAINS)
def test_hosted_missing_job_is_what_job_absent_reads_as_not_loaded(kind: str, capsys: Any) -> None:
    hosted = Hosted()
    label = ".".join(["org", "example", "netorch", "contract", "no-such-job"])
    reader = runtime.Reader(parse_settings(authored()), hosted)
    try:
        absent: bool | None = reader.job_absent(f"{kind}/{os.getuid()}", label)
    except runtime.RuntimeReadError:
        absent = None
    recorded(capsys, f"missing job in {kind}", answer(hosted.seen[0][1]))
    assert absent is True, hosted.seen
    assert (hosted.seen[0][1].returncode, hosted.seen[0][1].stdout) == (113, b"")


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
@pytest.mark.parametrize("kind", DOMAINS)
def test_hosted_domain_itself_answers(kind: str, capsys: Any) -> None:
    done = subprocess.run(
        ["/bin/launchctl", "print", f"{kind}/{os.getuid()}"],
        capture_output=True,
        timeout=10,
        check=False,
    )
    recorded(capsys, f"domain {kind}", answer(Result(done.returncode, done.stdout, done.stderr)))
    assert done.returncode == 0 and done.stdout, (done.returncode, done.stderr)


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
def test_hosted_loaded_job_is_printed_in_the_grammar_the_reader_uses(capsys: Any) -> None:
    domain = f"user/{os.getuid()}"
    listing = subprocess.run(
        ["/bin/launchctl", "print", domain], capture_output=True, timeout=10, check=False
    )
    assert listing.returncode == 0, (listing.returncode, listing.stderr)
    text = listing.stdout.decode("utf-8", "replace")
    services = running_services(text)
    if not services:
        recorded(capsys, "domain listing not understood", "\n".join(text.splitlines()[:40]))
    assert services, "no running service was found in the domain's `services` block"
    # The longest-lived candidate is the least likely to exit between the two reads.
    label, pid = min(services.items(), key=lambda row: row[1])
    hosted = Hosted()
    try:
        report = runtime.Reader(parse_settings(authored()), hosted).tool(
            ["/bin/launchctl", "print", f"{domain}/{label}"]
        )
    except runtime.RuntimeReadError:
        recorded(capsys, "loaded job did not print cleanly", answer(hosted.seen[0][1]))
        pytest.fail(f"a loaded job did not print cleanly: {hosted.seen}")
    recorded(capsys, "loaded job", f"{len(services)} running; {label}: {job_lines(report)}")
    assert runtime._JOB_RUNNING.search(report) is not None, report
    found = runtime._JOB_PID.search(report)
    assert found is not None and int(found[1]) == pid, (pid, report)
    program = runtime._JOB_PROGRAM.search(report)
    assert program is not None and program[1].startswith("/"), report


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
def test_hosted_running_job_passes_the_reader_of_the_api_job(capsys: Any) -> None:
    """`Reader.api` whole, `ps` included, on real jobs declared with their own label and program.

    Which job's process shows the program the service manager prints is that
    job's affair, so the claim is one of existence: among the oldest running
    services of the domain there is one the unchanged reader accepts.
    """
    # Imported here: the module must still load on a tree without the declaration.
    from netorch.runtime_settings import FleetStart

    domain = f"user/{os.getuid()}"
    listing = subprocess.run(
        ["/bin/launchctl", "print", domain], capture_output=True, timeout=10, check=False
    )
    assert listing.returncode == 0, (listing.returncode, listing.stderr)
    services = running_services(listing.stdout.decode("utf-8", "replace"))
    settings = parse_settings(authored())
    settings = replace(settings, account=replace(settings.account, uid=os.getuid()))
    accepted: list[str] = []
    refused: list[str] = []
    for label, _pid in sorted(services.items(), key=lambda row: row[1])[:8]:
        hosted = Hosted()
        printed = hosted(["/bin/launchctl", "print", f"{domain}/{label}"])
        program = runtime._JOB_PROGRAM.search(printed.stdout.decode("utf-8", "replace"))
        if printed.returncode or program is None or not program[1].startswith("/"):
            refused.append(f"{label}: {answer(printed)}")
            continue
        fleet = FleetStart(label, program[1], "example.")
        try:
            found = runtime.Reader(settings, hosted).api(fleet, domain)
        except runtime.RuntimeReadError as exc:
            process = hosted.seen[-1][1]
            refused.append(f"{label}: {exc.reason}, program {program[1]}, last {answer(process)}")
            continue
        assert found["uid"] == os.getuid() and found["executable"] == program[1]
        assert len(found["started"]) == 24, found
        accepted.append(f"{label} started {found['started']!r}")
    recorded(
        capsys,
        "reader of the api job",
        f"accepted {len(accepted)}, refused {len(refused)}; "
        + "; ".join([*accepted[:2], *refused[:3]]),
    )
    assert accepted, refused

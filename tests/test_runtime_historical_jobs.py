"""Historical vendor jobs cannot become absent evidence after re-enrollment.

Only synthetic files and injected runners are used. A loaded historical job is
modeled; this does not claim that lifecycle occurred on a physical host.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.codec import canonical_bytes, digest
from netorch.config import to_dict
from netorch.mock import mock_admissions
from netorch.process import OutputLimit, ProcessTimeout, Result
from netorch.state import admissions_to_dict
from tests.test_apple_runtime import FakeRunner, domain_report, enrolled
from tests.test_runtime_start_vendor_runtime import LABEL, World, declared_job, job_print
from tests.test_runtime_tolerated_stopped_peer import RETAINED, retain, tolerating

__all__ = ["enrolled"]
PRIMARY = "example-camera"
PREFIX = "com.apple.container."
NEW_HANDLER = "example-new-runtime"


class HistoricalRunner(FakeRunner):
    """Vendor state plus independently loaded launchd jobs, indexed by domain."""

    def __init__(self, settings: Any, items: Any) -> None:
        super().__init__(settings, items)
        self.domains = ("system", f"gui/{settings.account.uid}", f"user/{settings.account.uid}")
        self.loaded: dict[str, set[str]] = {domain: set() for domain in self.domains}
        self.reads = dict.fromkeys(self.domains, 0)
        self.on_read: Callable[[str, int], None] | None = None
        self.failure: Any = None
        self.domain_failure: tuple[str, Result | Exception | str] | None = None

    def __call__(self, argv: list[str], **kwargs: Any) -> Result:
        if argv[:2] == ["/bin/launchctl", "print"] and argv[2] in self.domains:
            domain = argv[2]
            self.calls.append((argv, kwargs))
            assert 0 < kwargs["timeout"] <= 3
            assert 0 < kwargs["max_output"] <= 4_194_304
            self.reads[domain] += 1
            if self.on_read:
                self.on_read(domain, self.reads[domain])
            if self.domain_failure and self.domain_failure[0] == domain:
                failure = self.domain_failure[1]
                if isinstance(failure, Exception):
                    raise failure
                if failure == "stderr":
                    return Result(0, domain_report(domain), b"warning")
                assert isinstance(failure, Result)
                return failure
            return Result(0, domain_report(domain, self.loaded[domain]), b"")
        return super().__call__(argv, **kwargs)


def recreated(enrolled: Any, *, peer: bool = False) -> tuple[Any, Any, HistoricalRunner, str]:
    config, settings, items = enrolled
    runner = HistoricalRunner(settings, items)
    name = RETAINED if peer else PRIMARY
    if peer:
        retain(runner)
        config, settings = tolerating(config, settings, "camera", RETAINED)
    else:
        runner.items[name]["status"]["state"] = "stopped"
    old_handler = runner.items[name]["configuration"]["runtimeHandler"]
    runner.items[name]["configuration"]["runtimeHandler"] = NEW_HANDLER
    if not peer:
        settings = replace(
            settings,
            contracts=tuple(
                replace(c, configuration_sha256=digest(runner.items[name]["configuration"]))
                if c.name == name
                else c
                for c in settings.contracts
            ),
        )
    config = runtime.derive_policy(config, settings)
    Path(settings.policy).write_bytes(canonical_bytes(to_dict(config)))
    Path(settings.admissions).write_bytes(
        canonical_bytes(admissions_to_dict(mock_admissions(config)))
    )
    runner.settings = settings
    return config, settings, runner, f"{PREFIX}{old_handler}.{name}"


def starts(runner: FakeRunner) -> list[list[str]]:
    return [
        argv
        for argv, _ in runner.calls
        if argv[0] == runner.settings.executable and argv[1:2] == ["start"]
    ]


@pytest.mark.parametrize("domain_index", range(3))
@pytest.mark.parametrize("peer", [False, True], ids=["reenrolled-workload", "retained-peer"])
def test_recreated_handler_never_hides_a_loaded_historical_job(
    enrolled: Any, domain_index: int, peer: bool
) -> None:
    config, settings, runner, old_label = recreated(enrolled, peer=peer)
    runner.loaded[runner.domains[domain_index]].add(old_label)
    observed = runtime.observe_runtime(config, settings, runner)
    assert observed.services["camera"].state == "unknown"
    runner.items[PRIMARY]["status"]["state"] = "stopped"
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert starts(runner) == []
    assert runner.reads[runner.domains[domain_index]] >= 1


def test_all_domains_empty_preserves_supported_recovery(enrolled: Any) -> None:
    config, settings, runner, _ = recreated(enrolled)
    observed = runtime.observe_runtime(config, settings, runner)
    assert observed.services["camera"].state == "absent"
    assert all(count >= 2 for count in runner.reads.values())
    recovered = runtime.recover_service(config, settings, "camera", runner)
    assert recovered.services["camera"].state == "present"
    assert starts(runner) == [[settings.executable, "start", PRIMARY]]


@pytest.mark.parametrize("suffix", ["-other", ".child"])
def test_another_container_does_not_collide_with_the_watched_name(
    enrolled: Any, suffix: str
) -> None:
    config, settings, runner, old_label = recreated(enrolled)
    runner.loaded["system"].add(old_label + suffix)
    assert runtime.observe_runtime(config, settings, runner).services["camera"].state == "absent"


@pytest.mark.parametrize("read_number", [2, 4], ids=["final-read", "second-observation-final-read"])
@pytest.mark.parametrize("peer", [False, True], ids=["workload", "retained-peer"])
def test_late_historical_job_blocks_readiness_or_recovery(
    enrolled: Any, read_number: int, peer: bool
) -> None:
    config, settings, runner, old_label = recreated(enrolled, peer=peer)
    domain = runner.domains[-1]

    def appear(current: str, count: int) -> None:
        if current == domain and count >= read_number:
            runner.loaded[domain].add(old_label)

    runner.on_read = appear
    if read_number == 2:
        assert (
            runtime.observe_runtime(config, settings, runner).services["camera"].state == "unknown"
        )
    else:
        runner.items[PRIMARY]["status"]["state"] = "stopped"
        with pytest.raises(runtime.RuntimeReadError):
            runtime.recover_service(config, settings, "camera", runner)
    assert runner.reads[domain] >= read_number
    assert starts(runner) == []


@pytest.mark.parametrize("domain_index", range(3))
@pytest.mark.parametrize(
    "failure",
    [
        Result(1, b"", b"permission denied"),
        Result(0, b"", b""),
        Result(0, b"unexpected output\n", b""),
        Result(0, b"system = {\n\tservices = {\n", b""),
        "stderr",
        ProcessTimeout("bounded test timeout"),
        OutputLimit("bounded test output"),
    ],
    ids=["error", "empty", "malformed", "truncated", "stderr", "timeout", "output-limit"],
)
def test_unavailable_historical_inventory_never_allows_a_start(
    enrolled: Any, domain_index: int, failure: Result | Exception | str
) -> None:
    config, settings, runner, _ = recreated(enrolled)
    runner.domain_failure = (runner.domains[domain_index], failure)
    assert runtime.observe_runtime(config, settings, runner).services["camera"].state == "unknown"
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", runner)
    assert starts(runner) == []


@pytest.mark.parametrize(
    "answer", [Result(0, b"loaded historical API\n", b""), Result(1, b"", b"denied")]
)
def test_system_api_job_or_unknown_read_prevents_a_second_api_start(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: Result
) -> None:
    monkeypatch.setattr(runtime, "_listed_home", lambda _uid: None, raising=False)
    world = World(enrolled, tmp_path)
    system_reads: list[list[str]] = []

    def model(argv: list[str], **kwargs: Any) -> Result:
        if argv == ["/bin/launchctl", "print", f"system/{LABEL}"]:
            system_reads.append(argv)
            if answer.returncode == 0:
                return Result(0, job_print("system", declared_job(world)), b"")
            return answer
        return world.runner(argv, **kwargs)

    with pytest.raises(runtime.RuntimeReadError):
        runtime.runtime_state(world.settings, model)
    with pytest.raises(runtime.RuntimeReadError):
        runtime.start_runtime(world.settings, model)
    assert system_reads
    assert world.vendor_calls() == []


@pytest.mark.parametrize("old_handler", ["legacy-runtime", "Old_Handler", "old.runtime"])
def test_historical_handler_is_not_limited_to_the_current_handler_grammar(
    enrolled: Any, old_handler: str
) -> None:
    config, settings, runner, _ = recreated(enrolled)
    runner.loaded["system"].add(f"{PREFIX}{old_handler}.{PRIMARY}")
    assert runtime.observe_runtime(config, settings, runner).services["camera"].state == "unknown"
    assert starts(runner) == []


def test_unchanged_enrollment_still_refuses_changed_configuration_before_job_evidence(
    enrolled: Any,
) -> None:
    config, settings, items = enrolled
    runner = HistoricalRunner(settings, items)
    runner.items[PRIMARY]["configuration"]["runtimeHandler"] = NEW_HANDLER
    runner.items[PRIMARY]["status"]["state"] = "stopped"
    observed = runtime.observe_runtime(config, settings, runner).services["camera"]
    assert (observed.state, observed.reason) == ("unknown", "identity-mismatch")
    assert not any(runner.reads.values())


def test_expired_observation_budget_does_not_start_another_domain_read(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import types

    config, settings, runner, _ = recreated(enrolled)
    clock = [1000.0]
    monkeypatch.setattr(runtime, "time", types.SimpleNamespace(monotonic=lambda: clock[0]))

    def exhaust(_domain: str, _count: int) -> None:
        clock[0] += 8.0

    runner.on_read = exhaust
    observed = runtime.observe_runtime(config, settings, runner).services["camera"]
    assert (observed.state, observed.reason) == ("unknown", "timed-out")
    assert sum(runner.reads.values()) == 1
    assert starts(runner) == []

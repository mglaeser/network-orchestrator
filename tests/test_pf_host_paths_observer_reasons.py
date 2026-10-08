"""Which answers of the bundled runtime observer keep a host path, and which retire it.

With `runtime_unknown: "keep-host-paths"` the root owner keeps a loaded host
path without runtime evidence only where the observation of its service says
that a read ran out of time. This file binds that sentence to the observer the
owner ships: every place where a read of that observer can run out of time, and
the answers it reports as `unavailable`, which are answers with an error and
retire every rule as they do without the decision. So does an observer that
refuses to run.

Every runtime and kernel tool is a fake. Addresses are documentation values.
"""

from __future__ import annotations

import json
import types
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import netorch.pf_owner as owner
from netorch import apple_runtime as runtime
from netorch.process import ProcessTimeout, Result
from netorch.state import Observation, Snapshot
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_pf_deferral import observed_pass
from tests.test_pf_host_paths_on_unknown_runtime import (
    DIRECT,
    EVERY_PROFILE,
    HOST_PATHS,
    NAMES,
    PAIR,
    REASON,
    WEB,
    Sockets,
    inventory_reads,
    loaded,
    planned,
    ready,
    site,
)
from tests.test_pf_owner import ROOT, STAMP, environment
from tests.test_pf_withdraw_order import owned
from tests.test_runtime_fleet_start import API_LABEL, JOB_PREFIX, declared

__all__ = ["enrolled", "environment"]

Call = Callable[[list[str]], bool]
PROXY = "example-web-proxy"  # the enrolled container of the web proxy
RESOLVER = "example-resolver"  # that of the resolver


class Answering:
    """A runner in front of the fake runtime: one chosen call runs out of time or fails.

    From the `nth` call that `match` selects on. `answer` is what such a call
    returns; without one it does not return within its bound.
    """

    def __init__(
        self, inner: Any, match: Call, answer: Result | None = None, *, nth: int = 1
    ) -> None:
        self.inner, self.match, self.answer, self.nth = inner, match, answer, nth
        self.matched = 0

    def __call__(self, argv: list[str], **kwargs: Any) -> Result:
        if self.match(argv):
            self.matched += 1
            if self.matched >= self.nth:
                if self.answer is None:
                    raise ProcessTimeout("command did not complete within its deadline")
                return self.answer
        return self.inner(argv, **kwargs)  # type: ignore[no-any-return]


def tool(*words: str) -> Call:
    """A call of the vendor's tool, as the enrolled fixture names it, with these first arguments."""
    return lambda argv: argv[0].endswith("-container") and argv[1 : 1 + len(words)] == list(words)


def native(program: str, *contains: str) -> Call:
    """A call of a system tool, optionally one whose arguments hold a word."""
    return lambda argv: (
        argv[0] == program
        and all(any(word in argument for argument in argv[1:]) for word in contains)
    )


def as_seen(config: Any, observed: Snapshot, verified: Snapshot) -> Snapshot:
    """The site's verified snapshot with what the observer said of each service.

    The observer ran against its own enrolled fixture. What it said is carried
    over as it is: per service the state and the reason of an observation that
    is not present, and whether the snapshot has a network generation.
    """
    services = {
        key: item
        if observed.services[key].state == "present"
        else Observation(observed.services[key].state, observed.services[key].reason, STAMP, None)
        for key, item in verified.services.items()
    }
    profiles = {
        key: item
        if services[config.profile(key).service].state == "present"
        else Observation(
            services[config.profile(key).service].state,
            services[config.profile(key).service].reason,
            STAMP,
            None,
            {"states": ()},
        )
        for key, item in verified.profiles.items()
    }
    generation = None if observed.network_generation is None else verified.network_generation
    return Snapshot(STAMP, generation, services, profiles)


def said(observed: Snapshot) -> dict[str, tuple[str, str]]:
    return {key: (item.state, item.reason) for key, item in observed.services.items()}


def one_pass(environment: Any, observed: Snapshot) -> tuple[dict[str, Any], Snapshot, Any]:
    """A loaded site with the decision, and one pass that has this evidence."""
    backend = Sockets()
    environment = loaded(site(environment, backend))
    environment[4].append(as_seen(environment[1], observed, environment[4][-1]))
    result, report = observed_pass(environment)
    return result, report, environment


# where a read of the observer runs out of time -> the services it then cannot speak
# for: all of them, without a network generation, or the one whose read it was
WHOLE: dict[str, tuple[Call, int]] = {
    "the tool's version": (tool("--version"), 1),
    "the boot session": (native("/usr/sbin/sysctl"), 1),
    "the helper's job": (native("/bin/launchctl"), 1),
    "the helper's process": (native("/bin/ps"), 1),
    "the network": (tool("network", "inspect"), 1),
    "the interface": (native("/sbin/ifconfig"), 1),
    "the listing": (tool("list"), 1),
    "the second read of the helper's job": (native("/bin/launchctl"), 2),
    "the second read of the network": (tool("network", "inspect"), 2),
}


@pytest.mark.parametrize("read", WHOLE)
def test_a_read_of_the_runtime_as_a_whole_that_runs_out_of_time_keeps_the_host_paths(
    environment: Any, enrolled: Any, read: str
) -> None:
    config, settings, items = enrolled
    match, nth = WHOLE[read]
    runner = Answering(FakeRunner(settings, items), match, nth=nth)

    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: STAMP)

    assert runner.matched >= nth and observed.network_generation is None
    assert set(said(observed).values()) == {("unknown", "timed-out")}
    result, report, environment = one_pass(environment, observed)
    assert {reason for key in EVERY_PROFILE for _, reason in planned(environment, key)} == {
        "network-unknown"
    }
    assert result["withheld"] == HOST_PATHS and owned(environment[3]) == sorted(HOST_PATHS)
    assert ready(report) == []


def test_the_eight_seconds_of_an_observation_used_up_keep_the_host_paths(
    environment: Any, enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, settings, items = enrolled
    clock = [1000.0]
    monkeypatch.setattr(runtime, "time", types.SimpleNamespace(monotonic=lambda: clock[0]))
    inner = FakeRunner(settings, items)

    def slow(argv: list[str], **kwargs: Any) -> Result:
        # The listing answers, and takes all the time the observation has.
        if argv[1:2] == ["list"]:
            clock[0] += 8.0
        return inner(argv, **kwargs)  # type: ignore[no-any-return]

    observed = runtime.observe_runtime(config, settings, slow, clock=lambda: STAMP)

    # No call starts once the deadline of the whole observation is used up: the
    # first read of the first container is refused, and so is every read after it.
    assert observed.network_generation is None
    assert set(said(observed).values()) == {("unknown", "timed-out")}
    assert not any(argv[1:2] == ["inspect"] for argv, _ in inner.calls)
    result, _, environment = one_pass(environment, observed)
    assert result["withheld"] == HOST_PATHS


def test_the_job_of_the_vendor_api_that_is_not_read_in_time_keeps_the_host_paths(
    environment: Any, enrolled: Any
) -> None:
    config, settings, inner = declared(enrolled)
    for nth in (1, 2):
        runner = Answering(inner, native("/bin/launchctl", API_LABEL), nth=nth)
        observed = runtime.observe_runtime(config, settings, runner, clock=lambda: STAMP)
        assert runner.matched == nth and observed.network_generation is None
        assert set(said(observed).values()) == {("unknown", "timed-out")}
    result, _, environment = one_pass(environment, observed)
    assert result["withheld"] == HOST_PATHS


# a read that belongs to one container -> that container's service, and the host
# path of that service, if it has one
ONE: dict[str, tuple[Call, str, str | None]] = {
    "the inspection of the web proxy": (tool("inspect", PROXY), "web-proxy", WEB),
    "the inspection of the resolver": (tool("inspect", RESOLVER), "resolver", NAMES),
    "the port range read inside the guest": (tool("exec"), "media-controller", None),
}


@pytest.mark.parametrize("read", ONE)
def test_a_read_of_one_container_that_runs_out_of_time_keeps_the_host_path_of_its_service(
    environment: Any, enrolled: Any, read: str
) -> None:
    config, settings, items = enrolled
    match, service, key = ONE[read]
    runner = Answering(FakeRunner(settings, items), match)

    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: STAMP)

    # The rest of the observation succeeded: every other service is present.
    assert runner.matched == 1 and observed.network_generation is not None
    assert said(observed) == {
        name: ("unknown", "timed-out") if name == service else ("present", "verified")
        for name in said(observed)
    }
    result, report, environment = one_pass(environment, observed)
    if key is None:
        # No host path belongs to that service: its pair is retired as always.
        assert result["changed"] == [f"{PAIR}:withdraw", f"{PAIR}:drain"]
        assert "withheld" not in result and ready(report) == [DIRECT, NAMES, WEB]
        return
    assert planned(environment, key)[0] == ("withdraw", "endpoint-unknown")
    assert result["withheld"] == {key: REASON} and key in owned(environment[3])
    assert key not in ready(report)


def test_the_identity_check_of_a_mount_that_runs_out_of_time_keeps_the_host_path(
    environment: Any, enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, settings, items = enrolled
    mount = next(c for c in settings.contracts if c.service == "web-proxy").mounts[0].path
    checked: list[str] = []

    def slow(path: Path, *, timeout: float = 2.0) -> None:
        checked.append(str(path))
        if str(path) == mount:
            raise ProcessTimeout("command did not complete within its deadline")

    monkeypatch.setattr(runtime, "reject_acl", slow)

    observed = runtime.observe_runtime(
        config, settings, FakeRunner(settings, items), clock=lambda: STAMP
    )

    # The container's configuration was the enrolled one; the check of its
    # enrolled directory did not end within its bound.
    assert mount in checked and observed.network_generation is not None
    assert said(observed)["web-proxy"] == ("unknown", "timed-out")
    result, _, environment = one_pass(environment, observed)
    assert result["withheld"] == {WEB: REASON}


def stopped_proxy(enrolled: Any) -> tuple[Any, Any, Any]:
    """The enrolled fleet with the web proxy listed as stopped and no job loaded for it."""
    config, settings, inner = declared(enrolled)
    inner.items[PROXY]["status"]["state"] = "stopped"
    inner.jobs[inner.domain].discard(PROXY)
    return config, settings, inner


def test_a_stopped_guest_whose_job_is_not_read_in_time_is_kept_only_with_a_listener(
    environment: Any, enrolled: Any
) -> None:
    config, settings, inner = stopped_proxy(enrolled)
    proven = runtime.observe_runtime(config, settings, inner, clock=lambda: STAMP)
    assert said(proven)["web-proxy"] == ("absent", "confirmed-absent")
    runner = Answering(inner, native("/bin/launchctl", JOB_PREFIX))

    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: STAMP)

    # The vendor lists the container as stopped, and the service manager's
    # answer about its job did not come in time: the observer says neither that
    # the service is absent nor that it runs.
    assert runner.matched == 1 and said(observed)["web-proxy"] == ("unknown", "timed-out")
    result, _, kept = one_pass(environment, observed)
    assert result["withheld"] == {WEB: REASON}
    # A stopped container holds no port. The fourth condition is what then
    # retires the rule: without a listener behind it nothing is kept.
    kept[3].sockets["tcp"] = []
    result, _ = observed_pass(kept)
    assert planned(kept, WEB)[0] == ("withdraw", "endpoint-unknown")
    assert result["changed"] == [f"{WEB}:withdraw", f"{WEB}:drain"] and "withheld" not in result


# an answer with an error -> all services, or the one container's
ERRORS: dict[str, tuple[Call, Result, str | None]] = {
    "the service manager has no job of the helper": (
        native("/bin/launchctl"),
        Result(113, b"", b"Bad request.\nCould not find service\n"),
        None,
    ),
    "the interface does not exist": (
        native("/sbin/ifconfig"),
        Result(1, b"", b"ifconfig: interface does not exist\n"),
        None,
    ),
    "the helper's process is gone": (native("/bin/ps"), Result(1, b"", b""), None),
    "the tool does not know the network": (
        tool("network", "inspect"),
        Result(1, b"", b"Error: not found\n"),
        None,
    ),
    "the listing fails": (tool("list"), Result(1, b"", b"Error: no answer\n"), None),
    "the account's session could not be entered": (
        tool("--version"),
        Result(69, b"", b'{"error":"observer-bootstrap-or-credentials-unavailable"}\n'),
        None,
    ),
    "the tool has an error for one container": (
        tool("inspect", PROXY),
        Result(1, b"", b"Error: not found\n"),
        "web-proxy",
    ),
    "the tool writes a line beside its answer for one container": (
        tool("inspect", RESOLVER),
        Result(0, b"[]", b"warning\n"),
        "resolver",
    ),
}


@pytest.mark.parametrize("answer", ERRORS)
def test_an_answer_with_an_error_is_unavailable_and_retires_as_without_the_decision(
    environment: Any, enrolled: Any, answer: str
) -> None:
    config, settings, items = enrolled
    match, error, service = ERRORS[answer]
    runner = Answering(FakeRunner(settings, items), match, error)

    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: STAMP)

    assert runner.matched >= 1
    assert (observed.network_generation is None) is (service is None)
    assert said(observed) == {
        name: ("unknown", "unavailable") if service in (None, name) else ("present", "verified")
        for name in said(observed)
    }
    result, report, environment = one_pass(environment, observed)
    # Not a read that ran out of time: no host path is a candidate, nothing is
    # read to judge one, and every rule of an unknown service is retired.
    assert "withheld" not in result and inventory_reads(environment[3]) == []
    if service is None:
        assert environment[3].rules == "" and ready(report) == []
        assert sorted(result["pending"]) == list(EVERY_PROFILE)
    else:
        key = {"web-proxy": WEB, "resolver": NAMES}[service]
        assert key not in owned(environment[3]) and f"{key}:withdraw" in result["changed"]
        assert planned(environment, key)[0] == ("withdraw", "endpoint-unknown")


def test_a_job_the_service_manager_gives_no_clear_answer_for_is_unavailable(
    environment: Any, enrolled: Any
) -> None:
    config, settings, inner = stopped_proxy(enrolled)
    # Neither its "no such job" nor a job it prints: an error of another kind.
    runner = Answering(inner, native("/bin/launchctl", JOB_PREFIX), Result(1, b"", b"x\n"))

    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: STAMP)

    assert said(observed)["web-proxy"] == ("unknown", "unavailable")
    result, _, environment = one_pass(environment, observed)
    assert WEB not in owned(environment[3]) and "withheld" not in result


REFUSALS = ["the tool's directory is writable by a user", "the settings are not valid"]


@pytest.mark.parametrize("case", REFUSALS)
def test_an_observer_that_refuses_to_run_retires_every_rule(
    environment: Any, tmp_path: Path, case: str
) -> None:
    root, config, settings, _, snapshots = environment
    observer = json.loads((ROOT / "examples/forwarding-settings.json").read_text())["observer"]
    directory = tmp_path / "vendor"
    directory.mkdir()
    directory.chmod(0o777)
    program = directory / "container"
    program.write_bytes(b"#!/bin/sh\n")
    observer["executable"] = str(program)
    if case == "the settings are not valid":
        observer["accepted_version"] = 7
    settings = replace(settings, observer=observer)
    root.write("installation.json", settings.to_dict())
    backend = Sockets()
    environment = loaded(site((root, config, settings, backend, snapshots), backend))
    raised: list[BaseException] = []

    def bundled(config: Any, raw: Any) -> Snapshot:
        try:
            return owner._runtime_observer(config, raw)
        except BaseException as error:
            raised.append(error)
            raise

    result, report = observed_pass(environment, bundled)

    # The observer the owner ships did not read the runtime at all: it found the
    # code it would run replaceable, or its own settings unusable. The owner
    # records that as `unavailable`, and nothing is kept on it.
    expected = owner.UnsafeState if case == REFUSALS[0] else ValueError
    # (At the first observation of the pass and at its last.)
    assert [type(error) for error in raised] == [expected, expected]
    assert backend.rules == "" and "withheld" not in result and ready(report) == []
    assert inventory_reads(backend) == []
    assert {reason for key in EVERY_PROFILE for _, reason in planned(environment, key)} == {
        "network-unknown"
    }

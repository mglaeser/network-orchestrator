"""The network helper may be registered in the enrolled account's `user/<uid>` domain.

The vendor's service manager registers a job in `gui/<uid>` from a login
session and in `user/<uid>` from a background session, so an API service that
was started from a background session has its network helper there. The
settings loader accepts that domain under the rule it has for `gui/<uid>`: the
uid is the enrolled account's. Every reader takes the domain as it is written;
a stopped guest's runtime job is asked for in system and both account domains.
The current helper domain does not constrain a previous runtime registration.
Everything native is faked here.
"""

from __future__ import annotations

import copy
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch import pf_owner
from netorch.codec import canonical_bytes, digest, strict_load
from netorch.config import load_config
from netorch.process import Result
from netorch.runtime_settings import (
    RuntimeAccount,
    contract_digest,
    load_settings,
    parse_settings,
    settings_to_dict,
)
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_runtime_fleet_start import (
    API_LABEL,
    DECLARATION,
    HANDLER,
    JOB_PREFIX,
    UNDECLARED_GENERATION,
    FleetRunner,
    declared,
    job_reads,
    job_report,
    observe,
    probe,
    starts,
    states,
)
from tests.test_runtime_settings import authored

__all__ = ["enrolled"]

ROOT = Path(__file__).resolve().parents[1]
# Computed on the tree before the third domain was accepted: the same inputs keep them.
AUTHORED_GUI_DIGEST = "6dd79016779aa6e1ef2a82ce99dd40e315faffbd13cb71c1f65ae2df72d1bde9"
AUTHORED_SYSTEM_DIGEST = "0305ff242453e52ad5a74f0dab5c1c66acea1de0f5acf7e976077006fe9efc5a"
AUTHORED_CONTRACT_DIGEST = "0ccf3c6325fb34f89e2f2a1f971c6df6fedee8cebfb2636ebd1568576e412daf"
EXAMPLE_DIGEST = "d1307ffc7cb45fb28b71c4cd190e57a4f8548b76b28a66fad9c4eec52cc28ab8"
# The helper label of the shared fixture, assembled at run time: the public
# host-data guard reads a literal as a site namespace.
HELPER = ".".join(["org", "example", "network"])


def with_domain(domain: Any, *, second: Any = None) -> dict[str, Any]:
    """The authored settings (account 1001) with the helper domain replaced."""
    raw = authored()
    raw["networks"][0]["helper_domain"] = domain
    if second is not None:
        raw["networks"].append(
            {**raw["networks"][0], "scope": "other-lan", "helper_domain": second}
        )
    return raw


def in_user_domain(enrolled: Any) -> tuple[Any, Any, Any]:
    """The enrolled fixture with its helper in `user/<uid>`, read back through the loader."""
    config, settings, items = enrolled
    raw = settings_to_dict(settings)
    raw["networks"][0]["helper_domain"] = f"user/{settings.account.uid}"
    return config, parse_settings(raw), items


def helper_reads(runner: FakeRunner) -> list[str]:
    return [
        argv[2]
        for argv, _ in runner.calls
        if argv[:2] == ["/bin/launchctl", "print"] and argv[2].endswith(f"/{HELPER}")
    ]


def test_the_account_s_user_domain_is_accepted(tmp_path: Path) -> None:
    raw = with_domain("user/1001")
    parsed = parse_settings(raw)
    assert parsed.networks[0].helper_domain == "user/1001"
    stored = settings_to_dict(parsed)
    assert stored["networks"][0]["helper_domain"] == "user/1001"
    assert parse_settings(stored) == parsed
    path = tmp_path / "runtime.json"
    path.write_bytes(canonical_bytes(raw))
    assert load_settings(path) == parsed
    # The domain is one of the settings and nothing of the enrolled contract.
    assert digest(stored) not in {AUTHORED_GUI_DIGEST, AUTHORED_SYSTEM_DIGEST}
    assert contract_digest(parsed.contracts[0]) == AUTHORED_CONTRACT_DIGEST


def test_settings_that_were_valid_before_keep_their_digests() -> None:
    assert digest(settings_to_dict(parse_settings(with_domain("gui/1001")))) == AUTHORED_GUI_DIGEST
    assert digest(settings_to_dict(parse_settings(with_domain("system")))) == AUTHORED_SYSTEM_DIGEST
    example = load_settings(ROOT / "examples/runtime-settings.json")
    assert digest(settings_to_dict(example)) == EXAMPLE_DIGEST
    assert contract_digest(parse_settings(authored()).contracts[0]) == AUTHORED_CONTRACT_DIGEST


@pytest.mark.parametrize(
    "domain",
    [
        "user/1002",
        "gui/1002",
        "user/0",
        "user/",
        "user",
        "user/01001",
        "user/+1001",
        "user/1001/",
        "user/1001 ",
        " user/1001",
        "User/1001",
        f"user/1001/{HELPER}",
        "background/1001",
        "login/1001",
        "pid/1001",
        "session/1001",
        "user/1001\n",
        "",
        1001,
        None,
        ["user/1001"],
    ],
)
def test_another_account_and_every_other_spelling_stay_refused(domain: Any) -> None:
    with pytest.raises(ValueError):
        parse_settings(with_domain(domain))


@pytest.mark.parametrize("kind", ["user", "gui"])
@pytest.mark.parametrize("helper_uid", [0, 1002])
def test_the_domain_names_the_account_and_never_the_helper_s_own_uid(
    kind: str, helper_uid: int
) -> None:
    """The helper's uid is a field of its own (account 1001 here); the domain does not follow it."""
    raw = with_domain(f"{kind}/{helper_uid}")
    raw["networks"][0]["helper_uid"] = helper_uid
    # The uid itself is a valid one, so the refusal is the domain's.
    with pytest.raises(ValueError, match="invalid helper ownership"):
        parse_settings(raw)


@pytest.mark.parametrize("first", ["gui/1001", "user/1001", "system"])
@pytest.mark.parametrize("second", ["gui/1001", "user/1001", "system"])
def test_fleet_start_still_needs_one_helper_domain(first: str, second: str) -> None:
    raw = with_domain(first, second=second)
    assert [item.helper_domain for item in parse_settings(raw).networks] == [first, second]
    if first == second:
        assert parse_settings({**raw, "fleet_start": dict(DECLARATION)}).fleet_start is not None
    else:
        with pytest.raises(ValueError, match="one helper domain"):
            parse_settings({**raw, "fleet_start": dict(DECLARATION)})


def test_the_helper_is_read_in_the_domain_the_settings_name(enrolled: Any) -> None:
    config, settings, items = in_user_domain(enrolled)
    uid = settings.account.uid
    runner = FakeRunner(settings, items)
    observed = observe(config, settings, runner)
    assert set(states(observed).values()) == {("present", "verified")}
    assert observed.network_generation is not None
    # Once at the beginning of the pass and once at its end, nowhere else.
    assert helper_reads(runner) == [f"user/{uid}/{HELPER}"] * 2
    assert not any(argv[:2] == ["/bin/launchctl", "asuser"] for argv, _ in runner.calls)


@pytest.mark.parametrize("kind", ["gui", "user"])
def test_the_domain_is_where_the_helper_is_read_and_no_part_of_the_generation(
    enrolled: Any, kind: str
) -> None:
    """A fixed account, so that the literal does not depend on who runs the suite."""
    config, settings, items = enrolled
    raw = settings_to_dict(
        replace(settings, account=RuntimeAccount(501, 20, settings.account.home))
    )
    raw["networks"][0].update(helper_domain=f"{kind}/501", helper_uid=501)
    settings = parse_settings(raw)
    runner = FakeRunner(settings, items)
    observed = observe(config, settings, runner)
    assert helper_reads(runner) == [f"{kind}/501/{HELPER}"] * 2
    assert observed.network_generation == UNDECLARED_GENERATION
    assert len(runner.calls) == 16


def test_such_an_installation_can_be_enrolled(enrolled: Any, tmp_path: Path) -> None:
    config, settings, items = in_user_domain(enrolled)
    path = tmp_path / "runtime-input.json"
    path.write_bytes(canonical_bytes(settings_to_dict(settings)))
    captured = runtime.capture_enrollment(load_settings(path), FakeRunner(settings, items))
    assert parse_settings(settings_to_dict(captured)) == captured
    assert captured.networks == settings.networks
    assert runtime.derive_policy(config, captured) == config


def stopped_fleet(enrolled: Any) -> tuple[Any, Any, FleetRunner]:
    """`fleet_start` declared, the helper in `user/<uid>`, every guest stopped, no job loaded."""
    config, settings, items = in_user_domain(enrolled)
    config, settings, runner = declared((config, settings, items))
    assert runner.domain == f"user/{settings.account.uid}"
    runner.stop_everything()
    return config, settings, runner


def test_a_stopped_guest_requires_absence_in_system_and_both_account_domains(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, settings, runner = stopped_fleet(enrolled)
    uid = settings.account.uid
    observed = observe(config, settings, runner)
    assert set(states(observed).values()) == {("absent", "confirmed-absent")}
    assert sorted(job_reads(runner)) == sorted(
        f"{domain}/{JOB_PREFIX}{HANDLER}.{contract.name}"
        for contract in settings.contracts
        for domain in ("system", f"gui/{uid}", f"user/{uid}")
    )
    # The API job is looked up in the one helper domain, like the helper itself.
    api_reads = [argv[2] for argv, _ in runner.calls if argv[2:] and argv[2].endswith(API_LABEL)]
    assert api_reads == [f"user/{uid}/{API_LABEL}"] * 2
    assert set(probe(monkeypatch, config, settings, runner).values()) == {runtime.STOPPED}
    result = runtime.recover_service(config, settings, "camera", runner)
    assert result.services["camera"].state == "present" and starts(runner) == ["example-camera"]


@pytest.mark.parametrize("kind", ["gui", "user"])
def test_a_runtime_job_in_either_domain_keeps_its_guest_unknown(enrolled: Any, kind: str) -> None:
    config, settings, runner = stopped_fleet(enrolled)
    runner.jobs = {f"{kind}/{settings.account.uid}": {"example-resolver"}}
    observed = states(observe(config, settings, runner))
    assert observed["resolver"] == ("unknown", "generation-mismatch")
    assert {observed[key] for key in observed if key != "resolver"} == {
        ("absent", "confirmed-absent")
    }
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "resolver", runner)
    assert starts(runner) == []


def test_the_root_observer_prints_the_helper_itself_and_runs_the_vendor_tool_as_the_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = copy.deepcopy(strict_load(ROOT / "examples/runtime-settings.json"))
    raw["networks"][0]["helper_domain"] = "user/501"
    network = raw["networks"][0]
    config = load_config(ROOT / "examples/network.json")
    monkeypatch.setattr(pf_owner, "protected_native_code", lambda _paths: None)
    calls: list[list[str]] = []

    def native(argv: list[str], **_kwargs: Any) -> Result:
        calls.append(argv)
        if argv[:2] == ["/bin/launchctl", "print"]:
            return Result(0, job_report(444, network["helper_executable"]), b"")
        if argv[0] == "/bin/ps":
            line = f"501 Mon Oct  5 08:00:00 2026 {network['helper_executable']}\n"
            return Result(0, line.encode(), b"")
        return Result(0, b"container CLI version 1.5.0\n", b"")

    monkeypatch.setattr(pf_owner, "run", native)
    helper: dict[str, Any] = {}

    def stub(_config: Any, settings: Any, runner: Any) -> Any:
        reader = runtime.Reader(settings, runner)
        helper.update(reader.helper(settings.networks[0]))
        reader.version()
        return helper

    monkeypatch.setattr(runtime, "observe_runtime", stub)
    assert pf_owner._runtime_observer(config, raw) is helper
    assert (helper["pid"], helper["uid"]) == (444, 501)
    child = str(Path(pf_owner.__file__).with_name("observer_child.py"))
    assert calls == [
        # A print names its domain; root asks the service manager directly.
        ["/bin/launchctl", "print", f"user/501/{network['helper_label']}"],
        ["/bin/ps", "-p", "444", "-o", "uid=", "-o", "lstart=", "-o", "comm="],
        # The vendor tool runs in the account's own bootstrap, whatever the domain.
        [
            "/bin/launchctl",
            "asuser",
            "501",
            sys.executable,
            "-I",
            "-S",
            child,
            "501",
            "20",
            raw["account"]["home"],
            raw["executable"],
            "--version",
        ],
    ]

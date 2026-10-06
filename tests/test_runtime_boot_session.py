"""The network generation names the boot by its session identifier, not by its time.

The kernel moves its stored boot time whenever the calendar clock is set, and
the text of that value also carries a date in the local time zone. A generation
built from it changes although nothing about the runtime did. The session
identifier is made once per boot. Everything native is faked here; the last
test asks the real kernel and runs only on a hosted macOS runner.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import replace
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.process import Result
from netorch.runtime_settings import RuntimeAccount
from tests.test_apple_runtime import FakeRunner, enrolled

__all__ = ["enrolled"]

SESSION = "5E7A1B3C-9D2F-4A6B-8C1D-0123456789AB"
ANOTHER = "5E7A1B3C-9D2F-4A6B-8C1D-0123456789AC"
READ = ["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"]
# One fixed set of faked inputs, read by the tree that hashed the boot time and by this one.
BOOT_TIME_GENERATION = "network-029aaad30a0fef5a38015a88b0486bb23fdd53ad37fcdb881332b8c25954832b"
BOOT_SESSION_GENERATION = "network-c4339c5f1af8b87bc98c7f91a88cbff5e9d2aef359c054252331bd709567b4e5"


class Host(FakeRunner):
    """The shared fake with a kernel that knows both values: only the boot time moves."""

    def __init__(self, settings: Any, items: dict[str, Any]) -> None:
        super().__init__(settings, items)
        self.session = SESSION.encode() + b"\n"
        self.failure_of_read: Result | None = None
        self.boot_seconds = 1_759_700_000
        self.local_date = "Mon Oct  5 21:33:20 2026"
        self.passes = 0
        self.step_at_pass: int | None = None

    def step_clock(self, seconds: int, local_date: str) -> None:
        # Setting the calendar clock shifts the stored boot time by the same amount.
        self.boot_seconds += seconds
        self.local_date = local_date

    def __call__(self, argv: list[str], **kwargs: Any) -> Result:
        if argv[1:] == ["--version"]:
            # Every observation pass begins with exactly one version read.
            self.passes += 1
            if self.passes == self.step_at_pass:
                self.step_clock(37, "Mon Oct  5 21:33:57 2026")
        if argv[0] != "/usr/sbin/sysctl":
            return super().__call__(argv, **kwargs)
        self.calls.append((argv, kwargs))
        if argv[1:] == ["-n", "kern.boottime"]:
            text = f"{{ sec = {self.boot_seconds}, usec = 0 }} {self.local_date}\n"
            return Result(0, text.encode(), b"")
        assert argv == READ, argv
        return self.failure_of_read or Result(0, self.session, b"")


def observe(config: Any, settings: Any, host: Host) -> Any:
    return runtime.observe_runtime(config, settings, host, clock=lambda: 1000)


def generations(snapshot: Any) -> tuple[Any, ...]:
    """Every string that another owner stores and later compares."""
    return (
        snapshot.network_generation,
        *(item.generation for item in snapshot.services.values()),
        *(item.generation for item in snapshot.profiles.values()),
        *(item.data.get("network_generation") for item in snapshot.profiles.values()),
    )


def kernel_reads(host: Host) -> list[tuple[list[str], dict[str, Any]]]:
    return [(argv, kwargs) for argv, kwargs in host.calls if argv[0] == "/usr/sbin/sysctl"]


def starts(host: Host) -> list[str]:
    return [
        argv[2]
        for argv, _ in host.calls
        if argv[0] == host.settings.executable and argv[1:2] == ["start"]
    ]


CLOCK_CHANGES = {
    "stepped-forward": (37, "Mon Oct  5 21:33:57 2026"),
    "stepped-back": (-3600, "Mon Oct  5 20:33:20 2026"),
    "time-zone-changed": (0, "Tue Oct  6 06:33:20 2026"),
}


@pytest.mark.parametrize("change", sorted(CLOCK_CHANGES))
def test_setting_the_clock_does_not_change_the_generation(enrolled: Any, change: str) -> None:
    config, settings, items = enrolled
    host = Host(settings, items)
    before = observe(config, settings, host)
    host.step_clock(*CLOCK_CHANGES[change])
    after = observe(config, settings, host)
    assert before.network_generation is not None
    assert all(item.state == "present" for item in before.services.values())
    assert all(value is not None for value in generations(before))
    # The packet-rule owner stores these strings with each rule and retires,
    # drains and re-activates a profile when one of them differs.
    assert generations(after) == generations(before)


def test_a_clock_step_between_the_two_observations_does_not_refuse_the_start(
    enrolled: Any,
) -> None:
    config, settings, items = enrolled
    host = Host(settings, items)
    host.items["example-camera"]["status"]["state"] = "stopped"
    host.step_at_pass = 2
    result = runtime.recover_service(config, settings, "camera", host)
    assert result.services["camera"].state == "present"
    assert host.passes == 3 and starts(host) == ["example-camera"]


def test_another_boot_is_another_generation(enrolled: Any) -> None:
    config, settings, items = enrolled
    host = Host(settings, items)
    before = observe(config, settings, host)
    host.session = ANOTHER.encode() + b"\n"
    after = observe(config, settings, host)
    assert after.network_generation not in {None, before.network_generation}
    assert not set(generations(after)) & set(generations(before))


def test_a_reboot_between_the_two_observations_still_refuses_the_start(enrolled: Any) -> None:
    config, settings, items = enrolled
    inner = Host(settings, items)
    inner.items["example-camera"]["status"]["state"] = "stopped"

    def rebooted(argv: list[str], **kwargs: Any) -> Result:
        if argv[1:] == ["--version"] and inner.passes == 1:
            inner.session = ANOTHER.encode() + b"\n"
        return inner(argv, **kwargs)

    with pytest.raises(runtime.RuntimeReadError) as refused:
        runtime.recover_service(config, settings, "camera", rebooted)
    assert refused.value.reason == "generation-mismatch"
    assert inner.passes == 2 and starts(inner) == []


def test_one_bounded_read_of_the_session_identifier_per_pass(enrolled: Any) -> None:
    config, settings, items = enrolled
    host = Host(settings, items)
    assert observe(config, settings, host).network_generation is not None
    ((argv, kwargs),) = kernel_reads(host)
    assert argv == READ
    assert set(kwargs) == {"timeout", "max_output"} and 0 < kwargs["timeout"] <= 3


REFUSED_ANSWERS: dict[str, bytes] = {
    "lower-case": SESSION.lower().encode() + b"\n",
    "mixed-case": SESSION.replace("AB", "ab").encode() + b"\n",
    "no-final-newline": SESSION.encode(),
    "carriage-return": SESSION.encode() + b"\r\n",
    "leading-space": b" " + SESSION.encode() + b"\n",
    "trailing-space": SESSION.encode() + b" \n",
    "blank-line-after": SESSION.encode() + b"\n\n",
    "two-identifiers": SESSION.encode() + b"\n" + ANOTHER.encode() + b"\n",
    "empty": b"",
    "only-a-newline": b"\n",
    "nil-identifier": b"00000000-0000-0000-0000-000000000000\n",
    "in-braces": b"{" + SESSION.encode() + b"}\n",
    "one-digit-short": SESSION[:-1].encode() + b"\n",
    "one-digit-long": SESSION.encode() + b"0\n",
    "not-hexadecimal": SESSION.replace("5E7A", "5G7A").encode() + b"\n",
    "without-hyphens": SESSION.replace("-", "").encode() + b"\n",
    "named-value": b"kern.bootsessionuuid: " + SESSION.encode() + b"\n",
    "boot-time-text": b"{ sec = 1759700000, usec = 0 } Mon Oct  5 21:33:20 2026\n",
    "not-text": b"\xff\xfe\n",
}


@pytest.mark.parametrize("answer", sorted(REFUSED_ANSWERS))
def test_anything_but_one_upper_case_identifier_is_an_unknown_read(
    enrolled: Any, answer: str
) -> None:
    config, settings, items = enrolled
    host = Host(settings, items)
    host.items["example-camera"]["status"]["state"] = "stopped"
    host.session = REFUSED_ANSWERS[answer]
    observed = observe(config, settings, host)
    assert observed.network_generation is None
    assert {(item.state, item.reason) for item in observed.services.values()} == {
        ("unknown", "malformed")
    }
    with pytest.raises(runtime.RuntimeReadError):
        runtime.recover_service(config, settings, "camera", host)
    assert starts(host) == []


@pytest.mark.parametrize(
    "result",
    [Result(1, b"", b"sysctl: unknown oid\n"), Result(0, SESSION.encode() + b"\n", b"warning\n")],
    ids=["failed", "standard-error"],
)
def test_a_failed_read_is_unavailable_as_before(enrolled: Any, result: Result) -> None:
    config, settings, items = enrolled
    host = Host(settings, items)
    host.failure_of_read = result
    observed = observe(config, settings, host)
    assert observed.network_generation is None
    assert {(item.state, item.reason) for item in observed.services.values()} == {
        ("unknown", "unavailable")
    }


def test_the_parser_returns_the_identifier_alone() -> None:
    assert runtime._boot_session(SESSION + "\n") == SESSION
    for text in (
        "00000000-0000-0000-0000-00000000000A\n",
        "A0000000-0000-0000-0000-000000000000\n",
    ):
        assert runtime._boot_session(text) == text[:-1]
    with pytest.raises(runtime.RuntimeReadError) as refused:
        runtime._boot_session(SESSION.lower() + "\n")
    assert refused.value.reason == "malformed"


def test_every_generation_string_changes_once(enrolled: Any) -> None:
    # A fixed account, so that the literals do not depend on who runs the suite.
    config, settings, items = enrolled
    network = replace(settings.networks[0], helper_domain="gui/501", helper_uid=501)
    settings = replace(
        settings, account=RuntimeAccount(501, 20, settings.account.home), networks=(network,)
    )
    observed = observe(config, settings, FakeRunner(settings, items))
    assert all(item.state == "present" for item in observed.services.values())
    # The same helpers and networks no longer give the string of the earlier scheme:
    # a record that still carries one is retired, never matched.
    assert observed.network_generation != BOOT_TIME_GENERATION
    assert observed.network_generation == BOOT_SESSION_GENERATION


# Hosted macOS userspace contract: what the real kernel answers. It is evidence
# for the recorded runner image only; it qualifies no macOS build.


def recorded(capsys: Any, title: str, seen: str) -> None:
    """On the hosted runner, keep what was observed as a notice of the job."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        text = seen.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        # Capture is lifted for one line of its own: the runner reads commands at line starts.
        with capsys.disabled():
            print(f"\n::notice title={title}::{text}")


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
def test_hosted_kernel_prints_one_stable_boot_session_identifier(capsys: Any) -> None:
    reads = [subprocess.run(READ, capture_output=True, timeout=10, check=False) for _ in range(2)]
    # The form of the answer, never the value: every hexadecimal digit as it is cased.
    form = re.sub(
        rb"[0-9]", b"9", re.sub(rb"[A-F]", b"X", re.sub(rb"[a-f]", b"x", reads[0].stdout))
    )
    recorded(
        capsys,
        "boot session identifier",
        f"status {reads[0].returncode}, form {form[:80]!r}, err {reads[0].stderr[:120]!r}, "
        f"two reads agree: {reads[0].stdout == reads[1].stdout}",
    )
    for done in reads:
        assert (done.returncode, done.stderr) == (0, b""), (done.returncode, done.stderr)
        # The value itself differs between machines and boots; only its form is asserted.
        try:
            runtime._boot_session(done.stdout.decode("utf-8", "strict"))
        except (runtime.RuntimeReadError, UnicodeError):
            pytest.fail(f"the production parser refuses {done.stdout!r}")
    assert reads[0].stdout == reads[1].stdout

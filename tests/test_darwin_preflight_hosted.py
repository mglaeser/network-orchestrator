"""Hosted macOS userspace contract of the local preflight collector.

`netorch-host preflight --collect-local` runs fixed read-only macOS commands and
parses what they print. Every other test of those parsers feeds them synthetic
text. The hosted cases below run the real collection once on a Darwin host and
look at each fact on its own: it was read as a value of its documented form, or
it is unknown for a reason a hosted runner can honestly have. It is never
`malformed`, the reason the collector gives when a parser refused the output.

The collection makes no network call, needs no privilege and writes nothing. A
pass is evidence for the runner image that ran it and qualifies no production
macOS build. A failure names the fact and how it was classified, never what a
tool printed. On the hosted runner the first line of a failure is also written
as a workflow annotation, and how every fact was classified as one notice, so
that both can be read on the pull request itself.

Two further tests run everywhere and feed the same expectations a synthetic
collection, so that the table itself is exercised without a Mac.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from netorch import host_cli
from netorch import macos_preflight as preflight
from netorch.host_report import parse_host_evidence
from netorch.process import Result
from tests.test_macos_preflight import SAMPLES

HOSTED = "hosted macOS userspace contract"
ROOT = Path(__file__).resolve().parents[1]
INSTANCE = str(ROOT / "examples" / "instance.json")


def _text(pattern: str) -> Callable[[Any], bool]:
    return lambda value: isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _one_of(*values: str) -> Callable[[Any], bool]:
    return lambda value: isinstance(value, str) and value in values


def _boolean(value: Any) -> bool:
    return type(value) is bool


def _names(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def _ipv4(value: Any) -> bool:
    try:
        return isinstance(value, str) and bool(ipaddress.IPv4Address(value))
    except ValueError:
        return False


@dataclass(frozen=True)
class Expected:
    """What one fact may be on a hosted runner."""

    source: str
    value: Callable[[Any], bool]
    # Reasons for which the fact may be unknown there; the comment at each use says why.
    unknown: tuple[str, ...] = ()


OBSERVED: dict[str, Expected] = {
    "macos_version": Expected("/usr/bin/sw_vers -productVersion", _text(r"[0-9]+(\.[0-9]+){1,2}")),
    "macos_build": Expected("/usr/bin/sw_vers -buildVersion", _text(r"[0-9A-Za-z]+")),
    "hardware_class": Expected("/usr/bin/uname -m", _one_of("apple-silicon", "intel")),
    "hardware_model": Expected("/usr/sbin/sysctl -n hw.model", _text(r"[A-Za-z0-9]+,[0-9]+")),
    "filevault": Expected("/usr/bin/fdesetup status", _one_of("on", "off")),
    # The key exists only where automatic login is configured. Without it
    # `defaults read` exits non-zero, which is "inaccessible" and never `False`.
    "automatic_login": Expected(
        "/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser",
        lambda value: value is True,
        ("inaccessible",),
    ),
    # A virtual machine may list no `autorestart` under "AC Power:"; the collector
    # then has a complete inventory without the setting, which is "incomplete".
    "power_restart": Expected("/usr/bin/pmset -g custom", _boolean, ("incomplete",)),
    "application_firewall": Expected(
        "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate", _boolean
    ),
    "network_extensions": Expected("/usr/bin/systemextensionsctl list", _names),
    "proxies": Expected("/usr/sbin/scutil --proxy", _boolean),
    # Without any VPN service the tool prints its header only. The collector
    # cannot tell that from a failed list read and reports "incomplete".
    "vpns": Expected("/usr/sbin/scutil --nc list", _boolean, ("incomplete",)),
    # Where Internet Sharing was never configured the preference file does not
    # exist: an empty export has no `NAT` dictionary ("incomplete"), and an
    # export that fails is "inaccessible".
    "internet_sharing": Expected(
        "/usr/bin/defaults export /Library/Preferences/SystemConfiguration/com.apple.nat -",
        _boolean,
        ("incomplete", "inaccessible"),
    ),
    # One command, three facts. No unknown reason is accepted: a runner has one
    # addressed Ethernet interface. The collector also says "malformed" when it
    # finds none or more than one, so a failure here can mean either.
    "lan_interface": Expected("/sbin/ifconfig -a", _text(r"[A-Za-z][A-Za-z0-9]*")),
    "lan_hardware_id": Expected("/sbin/ifconfig -a", _text(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")),
    "lan_ipv4": Expected("/sbin/ifconfig -a", _ipv4),
    # No container runtime is installed at either fixed location of a hosted
    # runner, so nothing is executed and both facts are "incomplete". Where one
    # is installed its `--version` is read; a method that the path alone does
    # not establish is "not-checked".
    "runtime_version": Expected(
        "<fixed location>/container --version", _text(r"[0-9]+\.[0-9]+\.[0-9]+"), ("incomplete",)
    ),
    "runtime_install_method": Expected(
        "the same file's location", _one_of("homebrew"), ("incomplete", "not-checked")
    ),
    "pf_baseline_sha256": Expected("reads /etc/pf.conf", _text(r"[0-9a-f]{64}")),
    "pf_anchors": Expected("lists /etc/pf.anchors", _names),
}
# Facts the collector names and never reads: they need an owner's own evidence.
NOT_CHECKED = (
    "anchor_order",
    "runtime_domain",
    "socktainer_version",
    "socktainer_install_method",
    "local_network_identity",
    "kernel_references",
    "runtime_dns_domain",
    "runtime_resolvers",
    "udp_sockets_idle",
    "udp_sockets_loaded",
    "installed_framework_sha256",
    "installed_framework_version",
)


@contextlib.contextmanager
def annotated() -> Iterator[None]:
    """On the hosted runner, also write the first line of a failure as an annotation."""
    try:
        yield
    except AssertionError as failure:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::error title={HOSTED}::{str(failure).splitlines()[0]}")
        raise


def recorded(capsys: pytest.CaptureFixture[str], title: str, seen: str) -> None:
    """On the hosted runner, keep what was observed as a notice of the job."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        text = seen.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        # Capture is lifted for one line of its own: the runner reads commands at line starts.
        with capsys.disabled():
            print(f"\n::notice title={title}::{text}")


def classification(fact: dict[str, Any]) -> str:
    """How a fact was collected, without its value."""
    if fact["state"] == "present" and fact["reason"] == "complete":
        return f"a value of type {type(fact['value']).__name__}"
    return f"{fact['state']} / {fact['reason']}"


def fact_of(document: dict[str, Any], key: str) -> dict[str, Any]:
    found = [item for item in document["facts"] if item["key"] == key]
    assert len(found) == 1, f"{key}: reported {len(found)} times"
    return found[0]


def check(document: dict[str, Any], key: str) -> None:
    expected = OBSERVED[key]
    fact = fact_of(document, key)
    allowed = " or ".join(["a value of its documented form", *expected.unknown])
    if fact["state"] == "present" and fact["reason"] == "complete":
        assert expected.value(fact["value"]), (
            f"{key} ({expected.source}): collected {classification(fact)}, "
            "which is not its documented form"
        )
    else:
        assert fact["state"] == "unknown" and fact["reason"] in expected.unknown, (
            f"{key} ({expected.source}): collected as {classification(fact)}; expected {allowed}"
        )


@pytest.fixture(scope="module")
def collection() -> dict[str, Any]:
    """The one real collection of this module: fixed local reads, at most 20 seconds."""
    return preflight.collect_preflight()


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason=HOSTED)
@pytest.mark.parametrize("key", sorted(OBSERVED))
def test_fact_is_read_or_unknown_for_a_stated_reason(collection: dict[str, Any], key: str) -> None:
    with annotated():
        check(collection, key)


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason=HOSTED)
@pytest.mark.parametrize("key", NOT_CHECKED)
def test_fact_without_a_local_source_is_not_claimed(collection: dict[str, Any], key: str) -> None:
    with annotated():
        fact = fact_of(collection, key)
        assert (fact["state"], fact["reason"], fact["value"]) == ("unknown", "not-checked", None), (
            f"{key}: collected as {classification(fact)}; the collector has no source for it"
        )


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason=HOSTED)
def test_collection_is_one_closed_evidence_document(
    collection: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    schema = json.loads((ROOT / "schemas" / "host-evidence.schema.json").read_text())
    keys = [item["key"] for item in collection["facts"]]
    # How each fact was classified, never a value: the record of this runner image.
    recorded(
        capsys,
        "local preflight collection",
        "; ".join(
            f"{item['key']}: {classification(item)}"
            for item in collection["facts"]
            if item["key"] in OBSERVED
        ),
    )
    violations = sorted(
        f"{'/'.join(str(part) for part in error.absolute_path)}: {error.validator}"
        for error in Draft202012Validator(schema).iter_errors(collection)
    )
    with annotated():
        assert not violations, f"the collection violates the evidence schema at {violations}"
        assert collection["source"] == "local-collector", "the collection names another source"
        assert sorted(keys) == sorted([*OBSERVED, *NOT_CHECKED]), (
            "another set of facts was collected"
        )
        # The loader the host commands use: the schema, value types and unique keys.
        assert len(parse_host_evidence(collection).facts) == len(keys), (
            "the loader read another number of facts"
        )


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason=HOSTED)
def test_host_command_accepts_and_reports_the_collection(
    collection: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    # The command, given the collection made above instead of making a second one.
    code = host_cli.main(
        ["preflight", "--instance", INSTANCE, "--collect-local"],
        collector=lambda instance: collection,
    )
    printed = json.loads(capsys.readouterr().out)
    with annotated():
        assert code == 0 and "error" not in printed, "the command refused the collection"
        assert printed["evidence_source"] == "local-collector", "the command names another source"
        reported = {item["key"]: item for item in printed["facts"]}
        for fact in collection["facts"]:
            view = reported[fact["key"]]
            assert (view["state"], view["reason"], view["value"]) == (
                fact["state"],
                fact["reason"],
                fact["value"],
            ), (
                f"{fact['key']}: collected as {classification(fact)}, "
                f"reported as {classification(view)}"
            )


# The expectations themselves, with synthetic collections; these run everywhere.


def synthetic(monkeypatch: pytest.MonkeyPatch, answer: Callable[[str], Result]) -> dict[str, Any]:
    monkeypatch.setattr(preflight.sys, "platform", "darwin")
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(Path, "is_file", lambda path: False)
    monkeypatch.setattr(Path, "iterdir", lambda path: iter(()))
    monkeypatch.setattr(preflight, "_file_digest", lambda path: "a" * 64)
    reverse = {argv: key for key, argv in preflight.COMMANDS.items()}
    return preflight.collect_preflight(runner=lambda argv, timeout: answer(reverse[argv]))


def test_expectations_accept_a_complete_synthetic_collection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = synthetic(monkeypatch, lambda key: Result(0, SAMPLES[key].encode(), b""))
    assert sorted(item["key"] for item in document["facts"]) == sorted([*OBSERVED, *NOT_CHECKED])
    for key in OBSERVED:
        check(document, key)
    # Every command in the collector's table is named by a fact that depends on it.
    sources = {expected.source for expected in OBSERVED.values()}
    assert {" ".join(argv) for argv in preflight.COMMANDS.values()} <= sources


def test_expectations_name_the_fact_and_reason_of_a_refused_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refused = "not what any of these tools prints"
    document = synthetic(monkeypatch, lambda key: Result(0, refused.encode(), b""))
    from_commands = [key for key in OBSERVED if OBSERVED[key].source.startswith("/")]
    assert len(from_commands) == 15
    for key in from_commands:
        assert fact_of(document, key)["reason"] == "malformed"
        with pytest.raises(AssertionError) as failure:
            check(document, key)
        message = str(failure.value)
        assert key in message and "unknown / malformed" in message and refused not in message
    # A reason is accepted only for the facts that list it.
    denied = synthetic(monkeypatch, lambda key: Result(1, b"", b"denied"))
    passing = []
    for key in from_commands:
        try:
            check(denied, key)
        except AssertionError:
            continue
        passing.append(key)
    assert passing == ["automatic_login", "internet_sharing"]

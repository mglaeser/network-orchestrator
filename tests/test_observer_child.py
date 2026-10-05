"""Mach-bootstrap and credential boundaries in pure mocks; no launchctl runs."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from netorch import observer_child as child
from netorch.codec import strict_load
from netorch.config import load_config
from netorch.pf_owner import PFError
from netorch.process import Result
from netorch.state import Snapshot

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(
    "arguments",
    [
        ["--version"],
        ["list", "--all", "--format", "json"],
        ["inspect", "example-media"],
        ["network", "inspect", "example-network"],
        [
            "exec",
            "--user",
            "0",
            "example-media",
            "/bin/cat",
            "/proc/sys/net/ipv4/ip_local_port_range",
        ],
    ],
)
def test_observer_child_permits_only_declared_read_grammar(arguments):
    assert child.read_operation(arguments)


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["start", "example-media"],
        ["system", "start"],
        ["network", "create", "example-network"],
        ["inspect", "--all"],
        ["inspect", "line\nbreak"],
        ["network", "inspect", ""],
        ["exec", "--user", "0", "example-media", "/bin/sh", "-c", "cat /proc/whatever"],
        ["exec", "--user", "0", "example-media", "/bin/cat", "/config/secrets.yaml"],
    ],
)
def test_observer_child_rejects_mutations_and_nonliteral_guest_exec(arguments):
    assert not child.read_operation(arguments)


def test_child_clears_groups_and_credentials_before_native_exec(monkeypatch):
    calls = []
    credentials = {"uid": 0, "gid": 0}
    monkeypatch.setattr(child, "sys", SimpleNamespace(platform="darwin", stderr=sys.stderr))
    monkeypatch.setattr(child.os, "geteuid", lambda: credentials["uid"])
    monkeypatch.setattr(child.os, "getuid", lambda: credentials["uid"])
    monkeypatch.setattr(child.os, "getegid", lambda: credentials["gid"])
    monkeypatch.setattr(child.os, "getgid", lambda: credentials["gid"])
    monkeypatch.setattr(child.os, "setgroups", lambda values: calls.append(("groups", values)))

    def set_gid(value):
        calls.append(("gid", value))
        credentials["gid"] = value

    def set_uid(value):
        calls.append(("uid", value))
        credentials["uid"] = value

    monkeypatch.setattr(child.os, "setgid", set_gid)
    monkeypatch.setattr(child.os, "setuid", set_uid)
    monkeypatch.setattr(child.os, "chdir", lambda value: calls.append(("cwd", value)))
    monkeypatch.setattr(child.os, "umask", lambda value: calls.append(("umask", value)))

    def executed(*values):
        calls.append(("exec", *values))
        raise RuntimeError("exec-confirmed")

    monkeypatch.setattr(child.os, "execve", executed)
    with pytest.raises(RuntimeError, match="exec-confirmed"):
        child.main(["501", "20", "/operator", "/Library/ExampleVendor/container", "--version"])
    assert calls[:5] == [("groups", []), ("gid", 20), ("uid", 501), ("cwd", "/"), ("umask", 0o077)]
    assert calls[-1] == (
        "exec",
        "/Library/ExampleVendor/container",
        ["/Library/ExampleVendor/container", "--version"],
        {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LC_ALL": "C",
            "LANG": "C.UTF-8",
            "HOME": "/operator",
        },
    )


@pytest.mark.parametrize(
    "values",
    [
        [],
        ["0", "20", "/operator", "/container", "--version"],
        ["501", "4294967295", "/operator", "/container", "--version"],
        ["501", "20", "/operator/../unsafe", "/container", "--version"],
        ["501", "20", "/operator", "relative", "--version"],
        ["501", "20", "/operator", "/container", "start", "example-media"],
    ],
)
def test_child_invalid_requests_do_not_drop_credentials_or_exec(monkeypatch, capsys, values):
    monkeypatch.setattr(child, "sys", SimpleNamespace(platform="darwin", stderr=sys.stderr))
    monkeypatch.setattr(child.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        child.os, "setgroups", lambda values: pytest.fail("invalid privilege action")
    )
    monkeypatch.setattr(child.os, "execve", lambda *args: pytest.fail("invalid exec"))
    assert child.main(values) == 69
    assert "observer-bootstrap-or-credentials-unavailable" in capsys.readouterr().err


def test_child_nonroot_or_failed_credentials_never_exec(monkeypatch):
    monkeypatch.setattr(child, "sys", SimpleNamespace(platform="darwin", stderr=sys.stderr))
    monkeypatch.setattr(child.os, "geteuid", lambda: 501)
    monkeypatch.setattr(child.os, "execve", lambda *args: pytest.fail("unsafe exec"))
    arguments = ["501", "20", "/operator", "/container", "--version"]
    assert child.main(arguments) == 69
    monkeypatch.setattr(child.os, "geteuid", lambda: 0)

    def fail_groups(values):
        raise PermissionError("denied")

    monkeypatch.setattr(child.os, "setgroups", fail_groups)
    assert child.main(arguments) == 69


def test_root_observer_adopts_bootstrap_then_routes_only_bounded_native_reads(monkeypatch):
    import netorch.apple_runtime as runtime
    import netorch.pf_owner as owner

    raw = strict_load(ROOT / "examples/runtime-settings.json")
    config = load_config(ROOT / "examples/network.json")
    monkeypatch.setattr(owner, "protected_native_code", lambda paths: None)
    calls = []

    def command(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return Result(0, b"readback", b"")

    monkeypatch.setattr(owner, "run", command)

    def observe(config, settings, runner):
        native_kwargs = {
            "run_uid": 501,
            "run_gid": 20,
            "account_home": "/operator",
            "timeout": 1.5,
        }
        assert runner([settings.executable, "--version"], **native_kwargs).stdout == b"readback"
        arguments, options = calls[-1]
        assert arguments == [
            "/bin/launchctl",
            "asuser",
            "501",
            sys.executable,
            "-I",
            "-S",
            str(Path(owner.__file__).with_name("observer_child.py")),
            "501",
            "20",
            "/operator",
            settings.executable,
            "--version",
        ]
        assert options == {"timeout": 1.5}  # launchctl still requires root credentials.
        runner(["/sbin/ifconfig", "en0"], timeout=1.0, max_output=1024)
        assert calls[-1] == (["/sbin/ifconfig", "en0"], {"timeout": 1.0, "max_output": 1024})
        with pytest.raises(PFError):
            runner([settings.executable, "start", "example-media"], **native_kwargs)
        with pytest.raises(PFError):
            runner([settings.executable, "--version"], **{**native_kwargs, "run_uid": 999})
        return Snapshot(100, "network", {}, {})

    monkeypatch.setattr(runtime, "observe_runtime", observe)
    assert owner._runtime_observer(config, raw).network_generation == "network"

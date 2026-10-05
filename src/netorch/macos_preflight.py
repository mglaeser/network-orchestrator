"""Read-only local macOS facts; no owner execution, LAN probes or consent bypass.

Native paths here are platform facts, not instance-selected executables. Raw
tool output stays in memory and is never returned, logged or used as code.
Unknown facts are retained independently rather than replaced with defaults.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import stat
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .process import OutputLimit, ProcessTimeout, Result, run

Runner = Callable[[tuple[str, ...], float], Result]
TOTAL_TIMEOUT = 20.0
COMMAND_TIMEOUT = 3.0
MAX_OUTPUT = 65_536

COMMANDS: dict[str, tuple[str, ...]] = {
    "macos_version": ("/usr/bin/sw_vers", "-productVersion"),
    "macos_build": ("/usr/bin/sw_vers", "-buildVersion"),
    "architecture": ("/usr/bin/uname", "-m"),
    "hardware_model": ("/usr/sbin/sysctl", "-n", "hw.model"),
    "filevault": ("/usr/bin/fdesetup", "status"),
    "automatic_login": (
        "/usr/bin/defaults",
        "read",
        "/Library/Preferences/com.apple.loginwindow",
        "autoLoginUser",
    ),
    "power_restart": ("/usr/bin/pmset", "-g", "custom"),
    "application_firewall": ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"),
    "network_extensions": ("/usr/bin/systemextensionsctl", "list"),
    "proxies": ("/usr/sbin/scutil", "--proxy"),
    "vpns": ("/usr/sbin/scutil", "--nc", "list"),
    "internet_sharing": (
        "/usr/bin/defaults",
        "read",
        "/Library/Preferences/SystemConfiguration/com.apple.nat",
        "NAT",
    ),
    "interfaces": ("/sbin/ifconfig", "-a"),
}
_UNOBSERVED = (
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


def _native(argv: tuple[str, ...], timeout: float) -> Result:
    return run(list(argv), timeout=timeout, max_output=MAX_OUTPUT)


def _text(result: Result) -> str:
    if len(result.stdout) + len(result.stderr) > MAX_OUTPUT:
        raise ValueError("oversized native response")
    text = result.stdout.decode("utf-8", "strict").strip()
    if "\0" in text:
        raise ValueError("malformed native response")
    return text


def _boolean(text: str, pattern: str) -> bool:
    found = re.findall(pattern, text, re.MULTILINE)
    if len(found) != 1 or found[0] not in {"0", "1"}:
        raise ValueError("incomplete boolean fact")
    return bool(found[0] == "1")


def _parse(key: str, text: str) -> Any:
    if key == "macos_version":
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", text):
            raise ValueError("malformed version")
        return text
    if key == "macos_build":
        if not re.fullmatch(r"[0-9]{2}[A-Z][0-9]+[a-z]?", text):
            raise ValueError("malformed build")
        return text
    if key == "architecture":
        if text not in {"arm64", "x86_64"}:
            raise ValueError("unknown hardware")
        return "apple-silicon" if text == "arm64" else "intel"
    if key == "hardware_model":
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]+,[0-9]+", text):
            raise ValueError("malformed model")
        return text
    if key == "filevault":
        if text not in {"FileVault is On.", "FileVault is Off."}:
            raise ValueError("unknown FileVault state")
        return "on" if text == "FileVault is On." else "off"
    if key == "automatic_login":
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", text):
            raise ValueError("unknown login preference")
        # Do not return an account name, nor infer successful unattended login.
        return True
    if key == "power_restart":
        return _boolean(text, r"^\s*autorestart\s+([01])\s*$")
    if key == "application_firewall":
        match = re.fullmatch(r"Firewall is (enabled|disabled)\. \(State = ([01])\)", text)
        if match is None or (match[1] == "enabled") != (match[2] == "1"):
            raise ValueError("unknown firewall state")
        return match[2] == "1"
    if key == "proxies":
        if not text.startswith("<dictionary> {") or not text.endswith("}"):
            raise ValueError("incomplete proxy response")
        values = re.findall(r"^\s*[A-Za-z]+Enable\s*:\s*([^\r\n]+)$", text, re.MULTILINE)
        if any(value.strip() not in {"0", "1"} for value in values):
            raise ValueError("malformed proxy state")
        return any(value.strip() == "1" for value in values)
    if key == "vpns":
        if not text.startswith("Available network connection services"):
            raise ValueError("incomplete VPN response")
        return bool(re.search(r"\((?:Connected|Connecting)\)", text))
    if key == "internet_sharing":
        return _boolean(text, r"^\s*Enabled\s*=\s*([01]);?\s*$")
    if key == "network_extensions":
        count = re.match(r"([0-9]+) extension\(s\)", text)
        if count is None:
            raise ValueError("incomplete extension inventory")
        # Retain bundle IDs, omit names and all other fields. A successful
        # truncated command must not be mistaken for no extensions.
        values = sorted(
            set(re.findall(r"\b([A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+){2,})\b", text))
        )
        if len(values) != int(count[1]):
            raise ValueError("incomplete extension inventory")
        return values
    raise ValueError("unknown native fact")


def _interface_facts(text: str, expected: str | None) -> dict[str, str]:
    blocks = re.split(r"(?m)^(?=[A-Za-z][A-Za-z0-9]*: flags=)", text)
    candidates: list[dict[str, str]] = []
    for block in blocks:
        name = re.match(r"([A-Za-z][A-Za-z0-9]*): flags=", block)
        addresses = re.findall(r"(?m)^\s*inet ([0-9.]+) netmask ", block)
        macs = re.findall(r"(?m)^\s*ether ([0-9a-f:]{17})\s*$", block)
        if name is None or len(macs) != 1:
            continue
        for address in addresses:
            value = ipaddress.IPv4Address(address)
            if value.is_loopback or value.is_link_local or value.is_unspecified:
                continue
            if expected is None or expected == address:
                candidates.append(
                    {"lan_interface": name[1], "lan_hardware_id": macs[0], "lan_ipv4": address}
                )
    if len(candidates) != 1:
        raise ValueError("LAN identity is absent or ambiguous")
    return candidates[0]


def _expected_address(instance: object) -> str | None:
    # An optional instance narrows a read-only comparison; it never selects code.
    host = instance.get("host") if isinstance(instance, dict) else getattr(instance, "host", None)
    lan = host.get("lan") if isinstance(host, dict) else getattr(host, "lan", None)
    if isinstance(lan, dict):
        value = lan.get("address", lan.get("ipv4"))
    else:
        value = getattr(lan, "address", getattr(lan, "ipv4", None))
    if isinstance(value, str):
        try:
            return str(ipaddress.IPv4Interface(value).ip)
        except ValueError:
            return None
    return None


def _file_digest(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_OUTPUT:
            raise ValueError("invalid local baseline")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_OUTPUT + 1)
        after = os.fstat(descriptor)

        def identity(item: os.stat_result) -> tuple[int, ...]:
            return (
                item.st_dev,
                item.st_ino,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        current = path.lstat()
        if (
            len(payload) > MAX_OUTPUT
            or identity(before) != identity(after)
            or identity(after) != identity(current)
        ):
            raise ValueError("baseline changed during capture")
        return hashlib.sha256(payload).hexdigest()
    finally:
        os.close(descriptor)


def collect_preflight(
    instance: object = None,
    *,
    runner: Runner = _native,
    clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Return bounded, individually aged facts. This function writes nothing."""
    if os.geteuid() == 0:
        raise PermissionError("host preflight must run as the unprivileged owner")
    facts: list[dict[str, Any]] = []
    deadline = monotonic() + TOTAL_TIMEOUT

    def emit(key: str, value: Any = None, reason: str = "complete") -> None:
        facts.append(
            {
                "key": key,
                "state": "present" if reason == "complete" else "unknown",
                "reason": reason,
                "observed_at": clock(),
                "value": value if reason == "complete" else None,
            }
        )

    for key, argv in COMMANDS.items():
        destination = "hardware_class" if key == "architecture" else key
        if sys.platform != "darwin":
            emit(destination, reason="unsupported")
            continue
        remaining = deadline - monotonic()
        if remaining <= 0:
            emit(destination, reason="timed-out")
            continue
        try:
            result = runner(argv, min(COMMAND_TIMEOUT, remaining))
            if result.returncode != 0:
                # A preference may be missing or denied; exit status alone
                # cannot establish disabled, absent or healthy.
                emit(destination, reason="inaccessible")
            elif key == "interfaces":
                for name, value in _interface_facts(
                    _text(result), _expected_address(instance)
                ).items():
                    emit(name, value)
            else:
                emit(destination, _parse(key, _text(result)))
        except ProcessTimeout:
            emit(destination, reason="timed-out")
        except (OutputLimit, UnicodeError, ValueError):
            emit(destination, reason="malformed")
        except (OSError, PermissionError):
            emit(destination, reason="inaccessible")
    # Runtime install methods are observed at fixed platform locations, never
    # executable paths supplied by an instance or an inherited PATH.
    candidates = [
        (Path("/opt/homebrew/bin/container"), "homebrew"),
        (Path("/usr/local/bin/container"), "signed-package"),
    ]
    found = [(path, method) for path, method in candidates if path.is_file()]
    if sys.platform == "darwin" and len(found) == 1 and monotonic() < deadline:
        path, method = found[0]
        try:
            result = runner((str(path), "--version"), min(COMMAND_TIMEOUT, deadline - monotonic()))
            version = re.fullmatch(
                r"container CLI version ([0-9]+\.[0-9]+\.[0-9]+)(?: \([^\r\n]*\))?", _text(result)
            )
            if result.returncode != 0 or version is None:
                raise ValueError("unknown runtime version")
            emit("runtime_version", version[1])
            # A path is only a method indicator; signature/receipt is a separate
            # installation acceptance item, not proven by directory placement.
            resolved = path.resolve()
            cellar = Path("/opt/homebrew/Cellar/container") / version[1] / "bin/container"
            if method == "homebrew" and resolved == cellar:
                emit("runtime_install_method", method)
            else:
                emit("runtime_install_method", reason="not-checked")
        except ProcessTimeout:
            emit("runtime_version", reason="timed-out")
            emit("runtime_install_method", reason="not-checked")
        except (OSError, ValueError, UnicodeError, OutputLimit):
            emit("runtime_version", reason="inaccessible")
            emit("runtime_install_method", reason="not-checked")
    else:
        for key in ("runtime_version", "runtime_install_method"):
            emit(key, reason="unsupported" if sys.platform != "darwin" else "incomplete")
    try:
        if sys.platform != "darwin":
            raise PermissionError("unsupported host")
        baseline = _file_digest(Path("/etc/pf.conf"))
        anchors = sorted(path.name for path in Path("/etc/pf.anchors").iterdir() if path.is_file())
        emit("pf_baseline_sha256", baseline)
        emit("pf_anchors", anchors)
        # Files on disk are not the evaluated kernel anchor order. A privileged
        # owner's saved kernel readback must supply that separate observation.
    except (OSError, ValueError):
        emit("pf_baseline_sha256", reason="inaccessible")
        emit("pf_anchors", reason="inaccessible")
    emit("anchor_order", reason="not-checked")
    for key in _UNOBSERVED:
        emit(key, reason="not-checked")
    present = {item["key"] for item in facts}
    interface_reason = next(
        (item["reason"] for item in facts if item["key"] == "interfaces"), "incomplete"
    )
    for key in ("lan_interface", "lan_hardware_id", "lan_ipv4"):
        if key not in present:
            emit(key, reason=interface_reason)
    # The intermediate inventory is not a fact in the closed host envelope.
    facts = [item for item in facts if item["key"] != "interfaces"]
    return {
        "schema_version": 1,
        "source": "local-collector",
        "observed_at": clock(),
        "facts": facts,
        "profiles": [],
    }

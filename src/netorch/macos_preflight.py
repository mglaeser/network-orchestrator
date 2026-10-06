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
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .legacy_import import _decode
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
        "export",
        "/Library/Preferences/SystemConfiguration/com.apple.nat",
        "-",
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

_VPN_HEADER = "Available network connection services in the current set (*=enabled):"
_VPN_ROW = re.compile(
    r"(?P<enabled>\*)?\s+\((?P<status>[A-Za-z]+)\)\s+"
    r"(?P<id>[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})\s+"
    r'[^\r\n]+\s+"[^\r\n]*"\s+\[[A-Za-z][A-Za-z0-9_.:-]*\]'
)


class IncompleteFact(ValueError):
    """A successful command did not establish a complete native observation."""


def _proxies_active(text: str) -> bool:
    """Validate the complete SCPrint dictionary/array tree before using flags.

    Nested scoped/supplemental settings are part of the same observation. Regex
    searches alone cannot distinguish missing braces, duplicate keys or a
    truncated enable field from a complete disabled configuration.
    """
    lines = text.splitlines()
    if not lines or lines[0] != "<dictionary> {":
        raise ValueError("incomplete proxy response")
    stack: list[tuple[str, set[str]]] = [("dictionary", set())]
    active = False
    for line in lines[1:]:
        if not stack or any(ord(character) < 32 for character in line):
            raise ValueError("malformed proxy structure")
        item = line.strip()
        if item == "}":
            stack.pop()
            continue
        match = re.fullmatch(r"([^\s:]+)\s*:\s*(\S.*)", item)
        if match is None:
            raise ValueError("malformed proxy entry")
        key, value = match.groups()
        kind, seen = stack[-1]
        if key in seen or (kind == "array" and key != str(len(seen))):
            raise ValueError("duplicate or incomplete proxy entries")
        seen.add(key)
        if key.endswith("Enable"):
            if value not in {"0", "1"}:
                raise ValueError("malformed proxy state")
            active |= value == "1"
        if value in {"<dictionary> {", "<array> {"}:
            if len(stack) >= 32:
                raise ValueError("proxy nesting exceeds the bound")
            stack.append(("dictionary" if value == "<dictionary> {" else "array", set()))
        elif value.startswith(("<dictionary>", "<array>")):
            raise ValueError("malformed proxy container")
    if stack:
        raise ValueError("incomplete proxy response")
    return active


def _vpn_active(text: str) -> bool:
    """Parse complete service rows, never infer absence from an unchecked header.

    Apple's scutil nc_list prints the same header and exits zero for an empty
    service array and a NULL result. Its output cannot distinguish those cases.
    A row's display/service names may contain status-looking text; only the
    dedicated status column is evidence. Unknown/invalid enabled services and
    malformed rows make the entire inventory unknown.
    """
    lines = text.splitlines()
    if not lines or lines[0] != _VPN_HEADER:
        raise ValueError("incomplete VPN response")
    if len(lines) == 1:
        raise IncompleteFact("empty VPN inventory is not independently distinguishable")
    active = False
    seen: set[str] = set()
    for line in lines[1:]:
        match = _VPN_ROW.fullmatch(line)
        if match is None or any(ord(character) < 32 for character in line):
            raise ValueError("malformed VPN inventory")
        identity = match["id"].lower()
        if identity in seen:
            raise ValueError("duplicate VPN service")
        seen.add(identity)
        status = match["status"]
        enabled = match["enabled"] is not None
        if status not in {"Disconnected", "Connecting", "Connected", "Disconnecting", "Invalid"}:
            raise IncompleteFact("unknown VPN status")
        if status == "Invalid":
            if enabled:
                raise IncompleteFact("enabled VPN status unavailable")
        elif not enabled:
            # The native producer reports Invalid for a disabled service.
            raise ValueError("contradictory VPN service status")
        else:
            active |= status != "Disconnected"
    return active


def _native(argv: tuple[str, ...], timeout: float) -> Result:
    return run(list(argv), timeout=timeout, max_output=MAX_OUTPUT)


def _text(result: Result) -> str:
    if len(result.stdout) + len(result.stderr) > MAX_OUTPUT:
        raise ValueError("oversized native response")
    text = result.stdout.decode("utf-8", "strict").strip()
    if "\0" in text:
        raise ValueError("malformed native response")
    return text


def _power_restart(text: str) -> bool:
    """Read the AC setting only after validating every printed power section."""
    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in text.splitlines():
        if line in {"AC Power:", "Battery Power:", "UPS Power:"}:
            if line in sections or (current is not None and not current):
                raise ValueError("duplicate or incomplete power section")
            current = {}
            sections[line] = current
            continue
        match = re.fullmatch(r" +([A-Za-z][A-Za-z0-9_]*) +([^\r\n]+)", line)
        if current is None or match is None or any(ord(c) < 32 for c in line):
            raise ValueError("malformed power inventory")
        key, value = match.groups()
        if key in current or (key == "autorestart" and value.strip() not in {"0", "1"}):
            raise ValueError("duplicate or malformed power setting")
        current[key] = value.strip()
    if current is None or not current or "autorestart" not in sections.get("AC Power:", {}):
        raise IncompleteFact("AC restart preference is unavailable")
    return sections["AC Power:"]["autorestart"] == "1"


def _extensions(text: str) -> list[str]:
    """Parse the complete counted native inventory rather than search for IDs."""
    lines = text.splitlines()
    count = re.fullmatch(r"([0-9]+) extension\(s\)", lines[0]) if lines else None
    if count is None:
        raise ValueError("incomplete extension inventory")
    expected = int(count[1])
    if expected == 0:
        if len(lines) != 1:
            raise ValueError("unexpected empty extension inventory content")
        return []
    values: list[str] = []
    category = False
    columns = False
    group_rows = 0
    for line in lines[1:]:
        if re.fullmatch(r"--- com\.apple\.system_extension\.[a-z_]+(?: \([^\r\n]*\))?", line):
            if category and (not columns or not group_rows):
                raise ValueError("incomplete extension category")
            category, columns, group_rows = True, False, 0
            continue
        if re.fullmatch(
            r"enabled\s+active\s+teamID\s+bundleID\s+\(version\)\s+name\s+\[state\]", line
        ):
            if not category or columns:
                raise ValueError("unexpected extension columns")
            columns = True
            continue
        row = re.fullmatch(
            r"\s*(?:\*\s+){0,2}[A-Z0-9]{10}\s+"
            r"(?P<id>[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+)\s+"
            r"\([^()\r\n]+\)\s+[^\r\n]+\s+"
            r"\[(?:activated (?:enabled|disabled|waiting for user)|"
            r"terminated waiting for uninstall on reboot)\]",
            line,
        )
        if not columns or row is None or row["id"] in values:
            raise ValueError("malformed or duplicate extension row")
        values.append(row["id"])
        group_rows += 1
    if len(values) != expected or not columns or not group_rows:
        raise ValueError("incomplete extension inventory")
    return sorted(values)


def _internet_sharing(text: str) -> bool:
    # defaults(1) export DOMAIN - emits XML. Reuse the bounded static XML decoder,
    # including duplicate-key, DTD/entity and structural checks; do not evaluate
    # the ambiguous human-readable OpenStep property-list description.
    try:
        value = _decode(text.encode("utf-8"), "plist")
    except (ValueError, UnicodeError, ET.ParseError, RecursionError) as exc:
        raise ValueError("malformed sharing preference") from exc
    if not isinstance(value, dict) or not isinstance(value.get("NAT"), dict):
        raise IncompleteFact("sharing preference unavailable")
    enabled = value["NAT"].get("Enabled")
    if type(enabled) is bool:
        return enabled
    if type(enabled) is int and enabled in {0, 1}:
        return enabled == 1
    raise IncompleteFact("sharing enable preference unavailable")


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
        return _power_restart(text)
    if key == "application_firewall":
        match = re.fullmatch(r"Firewall is (enabled|disabled)\. \(State = ([01])\)", text)
        if match is None or (match[1] == "enabled") != (match[2] == "1"):
            raise ValueError("unknown firewall state")
        return match[2] == "1"
    if key == "proxies":
        return _proxies_active(text)
    if key == "vpns":
        return _vpn_active(text)
    if key == "internet_sharing":
        return _internet_sharing(text)
    if key == "network_extensions":
        return _extensions(text)
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
        except IncompleteFact:
            emit(destination, reason="incomplete")
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

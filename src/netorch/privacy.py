"""Two-way static host literal checks; never query a host or open a socket.

Findings contain location and a value hash, not the matched private value.
Exceptions are explicit path/kind pairs with a written reason, never a blanket
permission to ignore every file or every instance value.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .legacy_import import ImportError, read_static

_KINDS = {"private-address", "interface", "home", "namespace", "name", "port"}
_IP = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?(?![\w.])")
_IF = re.compile(r"(?<![\w])(?:en[0-9]+|bridge[0-9]+|utun[0-9]+|vmenet[0-9]+)(?![\w])")
_HOME = re.compile(r"/(?:Users|home)/[A-Za-z0-9_.-]+(?:/[^\s\"'<>]*)?")
_NAMESPACE = re.compile(
    r"(?<![\w.])(?:me|com|net|org|io|dev|app)\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*(?![\w.])"
)
_SKIP = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".hypothesis",
}


class PrivacyError(ValueError):
    """A scan contract is invalid or a file could not be checked safely."""


@dataclass(frozen=True)
class HostLiteral:
    kind: str
    value: str


@dataclass(frozen=True)
class PrivacyException:
    path: str
    kind: str
    reason: str
    value_sha256: str | None = None


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    column: int
    kind: str
    value_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "kind": self.kind,
            "value_sha256": self.value_sha256,
        }


def _validate_literals(literals: Iterable[HostLiteral]) -> tuple[HostLiteral, ...]:
    values = tuple(literals)
    if len(values) > 4096 or len(set(values)) != len(values):
        raise PrivacyError("Host literal set must be bounded and distinct")
    for literal in values:
        if (
            literal.kind not in _KINDS
            or not literal.value
            or len(literal.value) > 4096
            or any(ord(c) < 32 for c in literal.value)
        ):
            raise PrivacyError("Invalid host literal")
        if literal.kind == "port" and (
            not literal.value.isdecimal() or not 1 <= int(literal.value) <= 65535
        ):
            raise PrivacyError("Invalid host port literal")
    return values


def _literal_pattern(literal: HostLiteral) -> re.Pattern[str]:
    edge = r"[A-Za-z0-9_.-]"
    return re.compile(rf"(?<!{edge}){re.escape(literal.value)}(?!{edge})")


def _generic(text: str) -> Iterable[tuple[str, re.Match[str]]]:
    for match in _IP.finditer(text):
        address = match.group().split("/")[0]
        try:
            ip = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError:
            continue
        # Documentation networks and loopback are not host-specific facts.
        if any(
            ip in ipaddress.IPv4Network(cidr)
            for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
        ):
            yield "private-address", match
    for kind, pattern in (("interface", _IF), ("home", _HOME), ("namespace", _NAMESPACE)):
        for match in pattern.finditer(text):
            if kind == "namespace" and (
                match.group() in {"com.apple", "org.python", "org.freedesktop"}
                or match.group().startswith(("com.apple.", "org.python.", "org.freedesktop."))
            ):
                continue
            yield kind, match


def scan_text(
    text: str, *, path: str, literals: Iterable[HostLiteral] = (), generic: bool = True
) -> tuple[Finding, ...]:
    if len(text.encode("utf-8")) > 1_048_576:
        raise PrivacyError("Privacy source exceeds the scan bound")
    matches = list(_generic(text)) if generic else []
    if len(matches) > 10000:
        raise PrivacyError("Privacy findings exceed the scan bound")
    for literal in _validate_literals(literals):
        matches.extend((literal.kind, match) for match in _literal_pattern(literal).finditer(text))
    if len(matches) > 10000:
        raise PrivacyError("Privacy findings exceed the scan bound")
    findings: set[Finding] = set()
    for kind, match in matches:
        start = match.start()
        findings.add(
            Finding(
                path,
                text.count("\n", 0, start) + 1,
                start - text.rfind("\n", 0, start),
                kind,
                hashlib.sha256(match.group().encode("utf-8")).hexdigest(),
            )
        )
    return tuple(sorted(findings, key=lambda f: (f.path, f.line, f.column, f.kind, f.value_sha256)))


def scan_framework(
    root: str | Path,
    *,
    files: Iterable[str] | None = None,
    literals: Iterable[HostLiteral] = (),
    exceptions: Iterable[PrivacyException] = (),
    generic: bool = True,
) -> tuple[Finding, ...]:
    """Framework CI generic guard plus instance CI exact-value guard.

    A caller should supply its VCS tracked-file list. The default bounded tree
    walk excludes only tool/build state. Symlinks, oversized or non-UTF8 inputs
    are refusal, not a successful privacy check.
    """
    directory = Path(root).resolve()
    exc = tuple(exceptions)
    allowed: set[tuple[str, str, str | None]] = set()
    for item in exc:
        p = Path(item.path)
        if (
            p.is_absolute()
            or ".." in p.parts
            or item.kind not in _KINDS
            or not item.reason.strip()
            or len(item.reason) > 2048
        ):
            raise PrivacyError("Privacy exceptions need exact relative paths, kinds and reasons")
        if item.value_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", item.value_sha256):
            raise PrivacyError("Invalid privacy exception digest")
        allowed.add((item.path, item.kind, item.value_sha256))
    validated = _validate_literals(literals)
    if files is None:
        names: list[str] = []
        for visited, (current, directories, filenames) in enumerate(
            os.walk(directory, followlinks=False), 1
        ):
            directories[:] = [name for name in directories if name not in _SKIP]
            if visited > 10000 or len(names) + len(filenames) > 10000:
                raise PrivacyError("Privacy inventory exceeds the walk bound")
            for name in directories:
                if (Path(current) / name).is_symlink():
                    raise PrivacyError("Privacy tree contains an unchecked directory symlink")
            names.extend(str((Path(current) / name).relative_to(directory)) for name in filenames)
    else:
        names = list(files)
    if len(names) > 10000 or len(set(names)) != len(names):
        raise PrivacyError("Privacy inventory must be bounded and distinct")
    findings: list[Finding] = []
    total_bytes = 0
    for name in sorted(names):
        relative = Path(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not name
            or relative.as_posix() != name
        ):
            raise PrivacyError("Privacy inventory needs exact relative paths")
        try:
            raw = read_static(directory / relative)
            total_bytes += len(raw)
            if total_bytes > 64 * 1_048_576:
                raise PrivacyError("Privacy inventory exceeds the aggregate byte bound")
            text = raw.decode("utf-8", "strict")
        except (ImportError, UnicodeError) as error:
            raise PrivacyError(f"Privacy source cannot be checked: {name}") from error
        findings.extend(
            f
            for f in scan_text(text, path=name, literals=validated, generic=generic)
            if (f.path, f.kind, None) not in allowed
            and (f.path, f.kind, f.value_sha256) not in allowed
        )
    return tuple(findings)


def instance_literals(instance: dict[str, Any]) -> tuple[HostLiteral, ...]:
    """Extract the instance's chosen literals for its pinned-framework CI guard.

    This does not replace instance schema validation. IDs, ranges and constants
    are data too; exact low-entropy numeric ports can require narrow exceptions.
    """
    values: set[HostLiteral] = set()
    host = instance.get("host", {})
    if isinstance(host, dict):
        lan = host.get("lan", {})
        account = host.get("account", {})
        runtime = host.get("runtime", {})
        for obj, keys, kind in (
            (lan, ("ipv4", "cidr"), "private-address"),
            (lan, ("hardware_id",), "interface"),
            (account, ("home",), "home"),
            (runtime, ("network",), "name"),
        ):
            if isinstance(obj, dict):
                for key in keys:
                    if isinstance(obj.get(key), str) and obj[key]:
                        values.add(HostLiteral(kind, obj[key]))
    if isinstance(instance.get("namespace"), str):
        values.add(HostLiteral("namespace", instance["namespace"]))

    def visit(node: Any, kind: str) -> None:
        if isinstance(node, str) and node:
            values.add(HostLiteral(kind, node))
        elif isinstance(node, dict):
            for item in node.values():
                visit(item, kind)
        elif isinstance(node, list):
            for item in node:
                visit(item, kind)

    visit(instance.get("names", {}), "name")
    for workload in instance.get("workloads", []):
        if isinstance(workload, dict) and isinstance(workload.get("name"), str):
            values.add(HostLiteral("name", workload["name"]))
    for port_range in instance.get("port_ranges", []):
        if isinstance(port_range, dict):
            for key in ("first", "last"):
                if type(port_range.get(key)) is int:
                    values.add(HostLiteral("port", str(port_range[key])))
    for profile in instance.get("transport", []):
        if isinstance(profile, dict):
            for selector in (profile.get("ports"), profile.get("target_ports")):
                if isinstance(selector, dict):
                    for key in ("first", "last"):
                        if type(selector.get(key)) is int:
                            values.add(HostLiteral("port", str(selector[key])))
    return _validate_literals(sorted(values, key=lambda v: (v.kind, v.value)))

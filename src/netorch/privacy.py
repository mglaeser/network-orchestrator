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

_KINDS = {
    "private-address",
    "hardware-address",
    "interface",
    "home",
    "namespace",
    "name",
    "port",
}
# A value may end a sentence. Only a dot that continues into another component
# makes it part of a longer token.
_IP = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?(?!\w)(?!\.\w)")
# Candidates only: two to seven groups that end in a colon, then a last group or
# a dotted IPv4 tail. The address parser decides what is an IPv6 literal.
_IP6 = re.compile(
    r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f]{1,4})?"
    r"(?:/[0-9]{1,3})?(?![\w:])(?!\.\w)"
)
# Six or eight octets with one separator throughout, not part of a longer run.
_MAC = re.compile(
    r"(?<![\w:.-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}"
    r"(?:(?:[0-9A-Fa-f]{2}\1){2})?[0-9A-Fa-f]{2}(?![\w:-])(?!\.\w)"
)
# The shared address space of carrier-grade NAT (RFC 6598, 100.64/10) and the
# IPv6 ranges are built from integers: as text they would be findings here.
_SITE_IPV4 = (
    *(
        ipaddress.IPv4Network(cidr)
        for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
    ),
    ipaddress.IPv4Network((100 << 24 | 64 << 16, 10)),
)
# Global unicast (2000/3), unique-local (RFC 4193, fc00/7) and the deprecated
# site-local range (fec0/10). Every other IPv6 literal is loopback, unspecified,
# link-local, multicast or lies in space that is not assigned for unicast use.
_SITE_IPV6 = tuple(
    ipaddress.IPv6Network((first << 112, prefix))
    for first, prefix in ((0x2000, 3), (0xFC00, 7), (0xFEC0, 10))
)
_DOCUMENTATION_IPV6 = ipaddress.IPv6Network("2001:db8::/32")
_IF = re.compile(r"(?<![\w])(?:en[0-9]+|bridge[0-9]+|utun[0-9]+|vmenet[0-9]+)(?![\w])")
_HOME = re.compile(r"/(?:Users|home)/[A-Za-z0-9_.-]+(?:/[^\s\"'<>]*)?")
_NAMESPACE = re.compile(
    r"(?<![\w.])(?:me|com|net|org|io|dev|app)\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*(?!\w)(?!\.\w)"
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
    inner = r"[A-Za-z0-9_-]"
    value = re.escape(literal.value)
    if literal.kind in {"name", "namespace"}:
        # A chosen name is also written in capitals and as one label of a longer
        # dotted name: a host name in its domain, a label under the namespace.
        # Further letters, digits, hyphens or underscores make it another name.
        return re.compile(rf"(?<!{inner}){value}(?!{inner})", re.IGNORECASE)
    # As above, a final dot that starts no further component does not hide the value.
    return re.compile(rf"(?<!{edge}){value}(?!{inner})(?!\.{inner})")


def _outermost(chosen: list[tuple[str, re.Match[str]]]) -> list[tuple[str, re.Match[str]]]:
    """Report a name that lies inside a longer chosen name once, as the longer one.

    An instance name is often a label of its own namespace. That occurrence is
    one finding, the namespace, not two.
    """
    named = {"name", "namespace"}
    spans = sorted(
        {match.span() for kind, match in chosen if kind in named},
        key=lambda span: (span[0], -span[1]),
    )
    inside: set[tuple[int, int]] = set()
    reach = -1
    for span in spans:
        if span[1] <= reach:
            inside.add(span)
        else:
            reach = span[1]
    return [
        (kind, match) for kind, match in chosen if kind not in named or match.span() not in inside
    ]


def _site_ipv6(address: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(address)
    except ipaddress.AddressValueError:
        return False
    if ip.ipv4_mapped is not None:
        return any(ip.ipv4_mapped in network for network in _SITE_IPV4)
    return ip not in _DOCUMENTATION_IPV6 and any(ip in network for network in _SITE_IPV6)


def _device_address(value: str) -> bool:
    """Whether six or eight octets name one device rather than a group or a fixture."""
    if "-" in value and not re.search("[A-Fa-f]", value):
        # Decimal pairs joined by hyphens are a date and time.
        return False
    octets = [int(part, 16) for part in re.split("[:-]", value)]
    # Group and locally administered addresses, the all-zero address and the
    # RFC 7042 documentation range identify no manufactured device.
    return not (
        octets[0] & 0b11
        or not any(octets)
        or (len(octets) == 6 and octets[:5] == [0x00, 0x00, 0x5E, 0x00, 0x53])
    )


def _generic(text: str) -> Iterable[tuple[str, re.Match[str]]]:
    for match in _IP.finditer(text):
        address = match.group().split("/")[0]
        try:
            ip = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError:
            continue
        # Documentation networks and loopback are not host-specific facts.
        if any(ip in network for network in _SITE_IPV4):
            yield "private-address", match
    for match in _IP6.finditer(text):
        if _site_ipv6(match.group().split("/")[0]):
            yield "private-address", match
    for match in _MAC.finditer(text):
        if _device_address(match.group()):
            yield "hardware-address", match
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
    chosen: list[tuple[str, re.Match[str]]] = []
    for literal in _validate_literals(literals):
        chosen.extend((literal.kind, match) for match in _literal_pattern(literal).finditer(text))
        if len(matches) + len(chosen) > 10000:
            raise PrivacyError("Privacy findings exceed the scan bound")
    matches.extend(_outermost(chosen))
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
        baseline = host.get("baseline", {})
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
        if isinstance(baseline, dict):
            # A declared extension identifier or proxy or VPN service name is a
            # chosen host value like the runtime network name.
            for key in ("network_extensions", "proxies", "vpns"):
                declared = baseline.get(key)
                for entry in declared if isinstance(declared, list) else ():
                    if isinstance(entry, str) and entry:
                        values.add(HostLiteral("name", entry))
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

    visit(instance.get("instance"), "name")
    visit(instance.get("names", {}), "name")
    for section in (
        "workloads",
        "port_ranges",
        "transport",
        "discovery",
        "lifecycle_tools",
        "deviations",
    ):
        for item in instance.get(section, []):
            if isinstance(item, dict):
                visit(item.get("id"), "name")
    for author in instance.get("authoring", []):
        if isinstance(author, dict):
            visit(author.get("owner"), "name")
    for workload in instance.get("workloads", []):
        if isinstance(workload, dict):
            visit(workload.get("name"), "name")
            for component in workload.get("components", []):
                if isinstance(component, dict):
                    visit(component.get("id"), "name")
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

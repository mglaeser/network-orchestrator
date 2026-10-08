"""Closed reader for the observed shape of a launchd domain's service table.

``launchctl print`` is a diagnostic interface, not a stable Apple API. This
reader accepts a complete observed envelope or refuses it; format changes,
unavailable domains and incomplete output cannot prove that a job is absent.
Only labels are retained. Environment, paths and other domain data are discarded.
"""

from __future__ import annotations

import re

_DOMAIN = re.compile(r"(?:system|(?:gui|user)/[1-9][0-9]*)\Z")
_UINT = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_ROW = re.compile(
    r"[ \t]*(0|[1-9][0-9]*)[ \t]+(-|\(pe\)|\(jt\)|-?(?:0|[1-9][0-9]*))"
    r"[ \t]+([\x21-\x7e]+)[ \t]*\Z"
)
_MAX_OUTPUT = 262_144
_MAX_SERVICES = 4096


def domain_services(report: str, domain: str) -> frozenset[str]:
    """Return every loaded label, including jobs with PID zero, or raise ValueError.

    Required identity/count fields must occur once at the top level. Exactly one
    top-level services block must contain exactly that many unique complete rows.
    Balanced, indentation-matched blocks establish that the whole print completed.
    A service-shaped row outside that block is refused, never silently skipped:
    it could be a displaced row following an injected or unexpected delimiter.
    """
    if (
        not isinstance(report, str)
        or not isinstance(domain, str)
        or _DOMAIN.fullmatch(domain) is None
        or len(report.encode("utf-8", "strict")) > _MAX_OUTPUT
        or not report.endswith("}\n")
        or any(ord(c) < 32 and c not in "\n\t" for c in report)
        or "\x7f" in report
    ):
        raise ValueError("invalid launchd domain inventory")
    lines = report.split("\n")
    if lines[0] != f"{domain} = {{" or lines[-2:] != ["}", ""]:
        raise ValueError("wrong or incomplete launchd domain envelope")
    stack = ["domain"]
    identity: dict[str, str] = {}
    labels: set[str] = set()
    service_blocks = 0
    for line in lines[1:-1]:
        if not line:
            continue
        indent = len(line) - len(line.lstrip("\t"))
        text = line[indent:]
        if text == "}":
            if indent != len(stack) - 1:
                raise ValueError("unbalanced launchd domain inventory")
            stack.pop()
            continue
        if not stack or indent < len(stack):
            raise ValueError("invalid launchd domain nesting")
        if stack == ["domain", "services"]:
            match = _ROW.fullmatch(text)
            if match is None:
                raise ValueError("unrecognized launchd service row")
            pid, status, label = match.groups()
            if (
                int(pid) > 2_147_483_647
                or (
                    status.lstrip("-").isdigit()
                    and not -2_147_483_648 <= int(status) <= 2_147_483_647
                )
                or len(label) > 1024
                or any(c in label for c in '{}"\\')
                or label in labels
                or len(labels) >= _MAX_SERVICES
            ):
                raise ValueError("invalid or repeated launchd service label")
            labels.add(label)
            continue
        # Service rows must never disappear into another/native-unknown section.
        if _ROW.fullmatch(text) is not None:
            raise ValueError("service row outside launchd services block")
        if text.endswith(" = {"):
            key = text[:-4]
            if indent != len(stack) or not key or "{" in key or "}" in key or len(stack) >= 32:
                raise ValueError("invalid launchd block")
            if key == "services":
                if stack != ["domain"] or service_blocks:
                    raise ValueError("ambiguous launchd services block")
                service_blocks += 1
            stack.append(key)
            continue
        if stack == ["domain"]:
            if " = " not in text:
                raise ValueError("invalid launchd domain field")
            key, value = text.split(" = ", 1)
            if key in {"type", "handle", "service count"}:
                if indent != 1:
                    raise ValueError("misplaced launchd domain identity")
                if key in identity:
                    raise ValueError("repeated launchd domain identity")
                identity[key] = value
            elif key == "services":
                raise ValueError("invalid launchd services block")
            # Native descriptive scalar fields can have extra tab alignment.
            # They supply no absence evidence. Identity fields and structural
            # blocks retain their exact indentation; displaced rows were refused
            # above, so alignment cannot conceal an actual service-table row.
    if stack or service_blocks != 1 or set(identity) != {"type", "handle", "service count"}:
        raise ValueError("incomplete launchd domain inventory")
    kind = domain.split("/", 1)[0]
    if (
        identity["type"] != ("login" if kind == "gui" else kind)
        or _UINT.fullmatch(identity["handle"]) is None
        or _UINT.fullmatch(identity["service count"]) is None
        or (kind == "system" and identity["handle"] != "0")
        or (kind == "user" and identity["handle"] != domain.split("/", 1)[1])
        or int(identity["service count"]) != len(labels)
    ):
        raise ValueError("launchd domain identity or count mismatch")
    return frozenset(labels)

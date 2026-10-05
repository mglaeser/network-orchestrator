"""Pure Darwin PF preview. The framework never loads rules or invokes pfctl."""

from __future__ import annotations

from collections.abc import Mapping

from .model import Config, PortRange
from .planner import plan
from .state import Admission, Intent, Snapshot


def _range(ports: PortRange) -> str:
    return str(ports.first) if ports.first == ports.last else f"{ports.first}:{ports.last}"


def render(
    config: Config,
    snapshot: Snapshot,
    admissions: Mapping[str, Admission],
    intent: Intent,
    now: float,
) -> str:
    """Render admitted candidate intent, never root authority or live acceptance.

    Root owners independently validate their exact admitted snapshot and current
    endpoint identity. Anchor/hook/state ownership is deliberately not inferred.
    """
    candidate = plan(config, snapshot, admissions, intent, now)
    lines = ["# Netorch preview only; independently verify platform hook order and admission."]
    nat: list[str] = []
    rdr: list[str] = []
    for action in candidate.actions:
        if action.operation not in {"activate", "noop"} or action.target_ipv4 is None:
            continue
        profile = config.profile(action.profile)
        scope = config.scope(profile.scope)
        label = f' label "netorch:{profile.id}"'
        if profile.kind == "publication":
            lines.append(f"# {profile.id}: native runtime publication, not a PF rule")
            continue
        source = scope.lan_cidr
        ports = _range(profile.ports)
        if profile.kind == "udp-return":
            nat.append(
                f"nat on {scope.interface} inet proto udp from {action.target_ipv4} "
                f"port {ports} to {source} -> {scope.host_ipv4} static-port{label}"
            )
            # Intentionally omit replacement target port: reverse-RDR must not
            # rewrite an unrelated outbound UDP destination into this range.
            rdr.append(
                f"rdr on {scope.interface} inet proto udp from {source} to "
                f"{scope.host_ipv4} port {ports} -> {action.target_ipv4}{label}"
            )
        else:
            target_ports = profile.target_ports or profile.ports
            rdr.append(
                f"rdr on {scope.interface} inet proto {profile.protocol} from {source} "
                f"to {scope.host_ipv4} port {ports} -> {action.target_ipv4} "
                f"port {_range(target_ports)}{label}"
            )
    return "\n".join(lines + nat + rdr) + "\n"

"""A retained state of a record is one that the record's own rules can have created.

Addresses are documentation values, ports are synthetic choices and every kernel
tool is a fake. The row forms are those the state reader accepts; which form a macOS
state table shows for a redirect or a return flow is not established here.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

import pytest

import netorch.pf_owner as owner
from netorch.config import profile_digest, to_dict, validate_config
from netorch.model import Config, PortRange
from netorch.pf_owner import PFError, ShellBackend, reconcile, withdraw
from netorch.process import Result
from netorch.state import Intent, Observation, Snapshot, intent_to_dict
from tests.test_pf_owner import STAMP, approve_all, environment, run_pass
from tests.test_pf_withdraw_order import REMAIN, LiveKernel, active, address, owned

__all__ = ["environment"]

HOST = "192.0.2.10"
CLIENT = "192.0.2.77"
PEER = "203.0.113.5"
RESOLVER = "198.51.100.10"
MEDIA = "198.51.100.12"
CAMERA = "198.51.100.13"

# A LAN client's state of a redirect, as the kernel's state model holds it:
# the target with its port (lan), the host's published port (gwy), the client (ext).
REDIRECTED = f"ALL udp {RESOLVER}:53 <- {HOST}:53 <- {CLIENT}:54321 MULTIPLE:MULTIPLE"
# A return flow of the media guest to a LAN peer through the static-port rule.
RETURNED = f"ALL udp {MEDIA}:45001 -> {HOST}:45001 -> {CLIENT}:7000 SINGLE:MULTIPLE"
# Connections a guest opens itself, through the vendor's own translation.
OWN_TCP = f"ALL tcp {RESOLVER}:51000 -> {HOST}:51000 -> {PEER}:443 ESTABLISHED:ESTABLISHED"
OWN_UDP = f"ALL udp {RESOLVER}:49211 -> {HOST}:49211 -> {PEER}:53 SINGLE:MULTIPLE"
# A state of the redirect whose peer is the host's own LAN address: the rule
# matches every source inside the LAN prefix, and that address is one of them.
FROM_HOST = f"ALL udp {RESOLVER}:53 <- {HOST}:53 <- {HOST}:54321 SINGLE:NO_TRAFFIC"


class Kernel(LiveKernel):
    """LiveKernel with state rows that are in the table whatever is invalidated."""

    def __init__(self, live_guests: Iterable[str] = (), *, lasting: Iterable[str] = ()) -> None:
        super().__init__(set(live_guests))
        self.lasting = list(lasting)

    def states(self) -> str:
        return "\n".join(row for row in (super().states(), *self.lasting) if row)


def record_of(config: Config, key: str, target: str) -> dict[str, Any]:
    """A retired record as the owner stores it for one profile and target."""
    profile = config.profile(key)
    return {
        "active": False,
        "kind": profile.kind,
        "effective_strategy": None,
        "target_ipv4": target,
        "target_generation": "instance-1",
        "network_generation": "network-1",
        "policy_digest": profile_digest(config, profile),
        "rules": "",
    }


def retained(config: Config, key: str, target: str, *rows: str) -> bool:
    return bool(
        owner.retained_states(
            config, key, target, record_of(config, key, target), owner.state_rows("\n".join(rows))
        )
    )


def published(environment: Any) -> tuple[dict[str, Any], Snapshot]:
    root, _, _, backend, snapshots = environment
    reports: list[Snapshot] = []
    result = reconcile(
        root,
        lambda config, settings: snapshots[-1],
        lambda root, settings: backend,
        now=lambda: STAMP,
        report=lambda settings, snapshot: reports.append(snapshot),
    )
    return result, reports[-1]


def moved(environment: Any, addresses: dict[str, str]) -> None:
    """A new network generation in which the named services hold other addresses."""
    config, snapshots = environment[1], environment[4]
    current = snapshots[-1]
    services = {
        key: Observation(
            "present",
            "verified",
            STAMP,
            "instance-2",
            {**value.data, "ipv4": addresses.get(key, value.data["ipv4"])},
        )
        for key, value in current.services.items()
    }
    publications = {
        key: Observation(
            value.state,
            value.reason,
            STAMP,
            "instance-2",
            {
                **value.data,
                "target_ipv4": services[config.profile(key).service].data["ipv4"],
                "target_generation": "instance-2",
                "network_generation": "network-2",
            },
        )
        for key, value in current.profiles.items()
    }
    snapshots.append(Snapshot(STAMP, "network-2", services, publications))


def acknowledge(root: Any) -> None:
    """What `acknowledge-journal` does to a failed journal."""
    journal = root.read("journal.json")
    assert journal["phase"] == "failed"
    journal["phase"] = "acknowledged"
    root.write("journal.json", journal)


# ---------------------------------------------------------------- the one reader


ROWS: dict[str, tuple[str, str, tuple[tuple[str, int | None], ...]]] = {
    "three endpoints": (REDIRECTED, "udp", ((RESOLVER, 53), (HOST, 53), (CLIENT, 54321))),
    "three endpoints, tcp": (OWN_TCP, "tcp", ((RESOLVER, 51000), (HOST, 51000), (PEER, 443))),
    "two endpoints": (
        f"all udp {CLIENT}:54321 -> {RESOLVER}:53 NO_TRAFFIC:SINGLE",
        "udp",
        ((CLIENT, 54321), (RESOLVER, 53)),
    ),
    "parenthesised endpoint": (
        f"all udp {HOST}:53 ({RESOLVER}:53) <- {CLIENT}:54321 SINGLE:MULTIPLE",
        "udp",
        ((HOST, 53), (RESOLVER, 53), (CLIENT, 54321)),
    ),
    "marked endpoint": (
        f"ALL udp {MEDIA}:45127 -> {HOST}:45127 -> ~192.0.2.82:7000 SINGLE:NO_TRAFFIC",
        "udp",
        ((MEDIA, 45127), (HOST, 45127), ("192.0.2.82", 7000)),
    ),
    "IPv4-mapped beside IPv6": (
        f"ALL udp ::ffff:{RESOLVER}[53] <- ::ffff:{HOST}[53] <- 2001:db8::7[54321] SINGLE:MULTIPLE",
        "udp",
        ((RESOLVER, 53), (HOST, 53)),
    ),
    "port zero": (
        "ALL udp ::ffff:192.0.2.1[0] -> 2001:db8::2[5353] SINGLE:NO_TRAFFIC",
        "udp",
        (("192.0.2.1", 0),),
    ),
    "no ports": (
        "ALL igmp 192.0.2.1 <- 224.0.0.1 NO_TRAFFIC:SINGLE",
        "igmp",
        (("192.0.2.1", None), ("224.0.0.1", None)),
    ),
    "one port": (
        "ALL icmp 192.0.2.1:8 <- 192.0.2.2 0:0",
        "icmp",
        (("192.0.2.1", 8), ("192.0.2.2", None)),
    ),
    "protocol number": (
        f"ALL 17 {RESOLVER}:53 <- {CLIENT}:54321 SINGLE:MULTIPLE",
        "17",
        ((RESOLVER, 53), (CLIENT, 54321)),
    ),
    "IPv6 only": (
        "ALL tcp 2001:db8::1[443] <- 2001:db8::2[50124] ESTABLISHED:ESTABLISHED",
        "tcp",
        (),
    ),
}


@pytest.mark.parametrize("row,protocol,endpoints", list(ROWS.values()), ids=list(ROWS))
def test_a_row_is_read_with_its_protocol_and_the_port_of_every_ipv4_endpoint(
    row: str, protocol: str, endpoints: tuple[tuple[str, int | None], ...]
) -> None:
    assert owner.state_rows(row) == (owner.StateRow(row, protocol, endpoints),)
    # The address view is the same parse without protocols and ports.
    assert owner.state_addresses(row) == ((row, tuple(address for address, _ in endpoints)),)


def test_the_address_view_and_the_rows_come_from_one_reader(monkeypatch: Any) -> None:
    table = f"{REDIRECTED}\n{OWN_TCP}\nALL igmp 192.0.2.1 <- 224.0.0.1 NO_TRAFFIC:SINGLE\n"
    rows = owner.state_rows(table)
    assert [row.line for row in rows] == table.splitlines()
    assert owner.state_addresses(table) == tuple(
        (row.line, tuple(address for address, _ in row.endpoints)) for row in rows
    )
    assert owner.state_rows("") == () and owner.state_rows("\n \n") == ()
    # A row one reader refuses, the other refuses: there is no second tokeniser.
    for damaged in (
        REDIRECTED.replace("<- 192.0.2.77", "-> 192.0.2.77"),
        REDIRECTED.replace(":54321", ""),
        REDIRECTED.replace(":54321", ":65536"),
        "WARNING: state inventory truncated",
    ):
        for reader in (owner.state_rows, owner.state_addresses):
            with pytest.raises(PFError):
                reader(f"{OWN_TCP}\n{damaged}")
    seen: list[str] = []

    def only_reader(raw: str) -> tuple[Any, ...]:
        seen.append(raw)
        return (owner.StateRow("row", "udp", (("192.0.2.1", 1), ("192.0.2.2", None))),)

    monkeypatch.setattr(owner, "state_rows", only_reader)
    assert owner.state_addresses("anything") == (("row", ("192.0.2.1", "192.0.2.2")),)
    assert seen == ["anything"]


# ---------------------------------------------------------------- the rule


@pytest.mark.parametrize(
    "key,target,row",
    [
        pytest.param("dns-udp", RESOLVER, REDIRECTED, id="redirect: lan, gwy, ext"),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp {CLIENT}:54321 -> {HOST}:53 -> {RESOLVER}:53 SINGLE:MULTIPLE",
            id="redirect: the target last",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"all udp {CLIENT}:54321 -> {RESOLVER}:53 NO_TRAFFIC:SINGLE",
            id="redirect: two endpoints",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"all udp {RESOLVER}:53 <- {CLIENT}:54321 SINGLE:MULTIPLE",
            id="redirect: two endpoints, target first",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"all udp {HOST}:53 ({RESOLVER}:53) <- {CLIENT}:54321 SINGLE:MULTIPLE",
            id="redirect: parenthesised display",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp {RESOLVER}:53 <- {HOST}:53 <- ~{CLIENT}:54321 SINGLE:NO_TRAFFIC",
            id="redirect: marked peer",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp ::ffff:{RESOLVER}[53] <- ::ffff:{HOST}[53] <- ::ffff:{CLIENT}[54321] "
            "SINGLE:MULTIPLE",
            id="redirect: IPv4-mapped",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL 17 {RESOLVER}:53 <- {HOST}:53 <- {CLIENT}:54321 SINGLE:MULTIPLE",
            id="redirect: protocol printed as its number",
        ),
        pytest.param(
            "dns-tcp",
            RESOLVER,
            f"ALL tcp {RESOLVER}:53 <- {HOST}:53 <- {CLIENT}:50123 ESTABLISHED:ESTABLISHED",
            id="tcp redirect",
        ),
        pytest.param("media-udp", MEDIA, RETURNED, id="return flow: outbound"),
        pytest.param(
            "media-udp",
            MEDIA,
            f"ALL udp {MEDIA}:45127 <- {HOST}:45127 <- {CLIENT}:7000 MULTIPLE:MULTIPLE",
            id="return flow: inbound, last port",
        ),
        pytest.param(
            "media-udp",
            MEDIA,
            f"ALL udp {MEDIA}:45000 -> {HOST}:45000 -> ~192.0.2.254:7000 SINGLE:NO_TRAFFIC",
            id="return flow: first port, last LAN address",
        ),
    ],
)
def test_a_state_the_rules_of_the_record_can_have_created_is_retained(
    environment: Any, key: str, target: str, row: str
) -> None:
    config = environment[1]
    assert retained(config, key, target, row)
    # Beside rows that are not such states it still is one.
    assert retained(config, key, target, OWN_TCP, row, "ALL igmp 192.0.2.1 <- 224.0.0.1 0:3")


@pytest.mark.parametrize(
    "key,target,row",
    [
        pytest.param("dns-udp", RESOLVER, OWN_TCP, id="the guest's own tcp connection"),
        pytest.param("dns-tcp", RESOLVER, OWN_TCP, id="own connection, same protocol"),
        pytest.param("dns-udp", RESOLVER, OWN_UDP, id="the guest's own query to the outside"),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp {RESOLVER}:53 -> {HOST}:53 -> {PEER}:53 SINGLE:MULTIPLE",
            id="target port, but only the host is on the LAN",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"all udp {RESOLVER}:49211 -> {CLIENT}:53 SINGLE:MULTIPLE",
            id="the peer has the port, the target has not",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp {RESOLVER}:5353 <- {HOST}:53 <- {CLIENT}:54321 SINGLE:MULTIPLE",
            id="another target port",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL tcp {RESOLVER}:53 <- {HOST}:53 <- {CLIENT}:50123 ESTABLISHED:ESTABLISHED",
            id="another protocol",
        ),
        pytest.param(
            "dns-tcp", RESOLVER, REDIRECTED.replace("ALL udp", "ALL 17"), id="another number"
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"all udp {CAMERA}:49211 -> {RESOLVER}:53 SINGLE:MULTIPLE",
            id="the peer is another guest",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"all udp 192.0.3.77:54321 -> {RESOLVER}:53 SINGLE:MULTIPLE",
            id="the peer is outside the LAN prefix",
        ),
        pytest.param("dns-udp", MEDIA, REDIRECTED, id="a state of another target"),
        pytest.param(
            "dns-udp",
            "192.0.2.50",
            f"all udp 192.0.2.50:53 -> {PEER}:53 SINGLE:MULTIPLE",
            id="the target is no peer of itself",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL igmp {RESOLVER} <- {CLIENT} NO_TRAFFIC:SINGLE",
            id="no ports at all",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            "ALL udp 2001:db8::10[53] <- 2001:db8::77[54321] SINGLE:MULTIPLE",
            id="IPv6 only",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp ::ffff:{RESOLVER}[53] <- 2001:db8::77[54321] SINGLE:MULTIPLE",
            id="no IPv4 address beside the target",
        ),
        pytest.param(
            "media-udp",
            MEDIA,
            f"ALL udp {MEDIA}:44999 -> {HOST}:44999 -> {CLIENT}:7000 SINGLE:MULTIPLE",
            id="below the published range",
        ),
        pytest.param(
            "media-udp",
            MEDIA,
            f"ALL udp {MEDIA}:45128 -> {HOST}:45128 -> {CLIENT}:7000 SINGLE:MULTIPLE",
            id="above the published range",
        ),
        pytest.param(
            "media-udp",
            MEDIA,
            f"ALL tcp {MEDIA}:45001 -> {HOST}:45001 -> {CLIENT}:445 ESTABLISHED:ESTABLISHED",
            id="tcp from a port of the range",
        ),
        pytest.param(
            "media-udp",
            MEDIA,
            f"ALL udp {MEDIA}:45001 -> {HOST}:45001 -> {PEER}:7000 SINGLE:MULTIPLE",
            id="return flow to the outside",
        ),
    ],
)
def test_a_state_the_rules_cannot_have_created_is_not_retained(
    environment: Any, key: str, target: str, row: str
) -> None:
    config = environment[1]
    assert not retained(config, key, target, row)
    # The address-only rule, which stays for a rule that is not described
    # any more, counts the row whenever it names the target.
    names_target = any(
        target == address for _, addresses in owner.state_addresses(row) for address in addresses
    )
    assert bool(owner.retained_states(None, key, target, None, owner.state_rows(row))) is (
        names_target
    )


@pytest.mark.parametrize(
    "key,target,row",
    [
        pytest.param("dns-udp", RESOLVER, FROM_HOST, id="redirect: lan, gwy, ext"),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp {HOST}:54321 -> {HOST}:53 -> {RESOLVER}:53 SINGLE:NO_TRAFFIC",
            id="redirect: the target last",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"all udp {HOST}:54321 -> {RESOLVER}:53 NO_TRAFFIC:SINGLE",
            id="redirect: two endpoints",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"all udp {RESOLVER}:53 <- {HOST}:54321 SINGLE:NO_TRAFFIC",
            id="redirect: two endpoints, target first",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"all udp {HOST}:53 ({RESOLVER}:53) <- {HOST}:54321 SINGLE:NO_TRAFFIC",
            id="redirect: parenthesised display",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp {RESOLVER}:53 <- {HOST}:53 <- ~{HOST}:54321 SINGLE:NO_TRAFFIC",
            id="redirect: marked peer",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp ::ffff:{RESOLVER}[53] <- ::ffff:{HOST}[53] <- ::ffff:{HOST}[54321] "
            "SINGLE:NO_TRAFFIC",
            id="redirect: IPv4-mapped",
        ),
        # The reader returns IPv4 addresses only: an IPv6 address beside them
        # is not an address outside the prefix.
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp ::ffff:{RESOLVER}[53] <- ::ffff:{HOST}[53] <- 2001:db8::7[54321] "
            "SINGLE:NO_TRAFFIC",
            id="redirect: IPv4-mapped, beside an IPv6 address",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL 17 {RESOLVER}:53 <- {HOST}:53 <- {HOST}:54321 SINGLE:NO_TRAFFIC",
            id="redirect: protocol printed as its number",
        ),
        pytest.param(
            "dns-tcp",
            RESOLVER,
            f"ALL tcp {RESOLVER}:53 <- {HOST}:53 <- {HOST}:50123 ESTABLISHED:ESTABLISHED",
            id="tcp redirect",
        ),
        pytest.param(
            "media-udp",
            MEDIA,
            f"ALL udp {MEDIA}:45001 <- {HOST}:45001 <- {HOST}:7000 SINGLE:NO_TRAFFIC",
            id="return profile: lan, gwy, ext",
        ),
        pytest.param(
            "media-udp",
            MEDIA,
            f"ALL udp {HOST}:7000 -> {HOST}:45127 -> {MEDIA}:45127 SINGLE:NO_TRAFFIC",
            id="return profile: the target last, last port",
        ),
        pytest.param(
            "media-udp",
            MEDIA,
            f"all udp {HOST}:7000 -> {MEDIA}:45000 NO_TRAFFIC:SINGLE",
            id="return profile: two endpoints, first port",
        ),
    ],
)
def test_a_state_whose_only_peer_is_the_hosts_own_address_is_retained(
    environment: Any, key: str, target: str, row: str
) -> None:
    config = environment[1]
    assert retained(config, key, target, row)
    # Beside the runtime's translation of the guest's own flows it still is
    # one: the rule looks at each row by itself.
    assert retained(config, key, target, OWN_TCP, OWN_UDP, row)


@pytest.mark.parametrize(
    "key,target,row",
    [
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp {PEER}:53 <- {HOST}:53 <- {RESOLVER}:53 SINGLE:MULTIPLE",
            id="a target port: the target last",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"all udp {HOST}:53 ({RESOLVER}:53) -> {PEER}:53 SINGLE:MULTIPLE",
            id="a target port: parenthesised display",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp ::ffff:{RESOLVER}[53] -> ::ffff:{HOST}[53] -> ::ffff:{PEER}[53] "
            "SINGLE:MULTIPLE",
            id="a target port: IPv4-mapped",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL 17 {RESOLVER}:53 -> {HOST}:53 -> {PEER}:53 SINGLE:MULTIPLE",
            id="a target port: protocol printed as its number",
        ),
        pytest.param(
            "dns-tcp",
            RESOLVER,
            f"ALL tcp {RESOLVER}:53 -> {HOST}:53 -> {PEER}:443 ESTABLISHED:ESTABLISHED",
            id="a target port: tcp",
        ),
        pytest.param(
            "media-udp",
            MEDIA,
            f"ALL udp {PEER}:7000 <- {HOST}:45127 <- {MEDIA}:45127 MULTIPLE:MULTIPLE",
            id="a port of the return range: the target last",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp {PEER}:53 <- {HOST}:51000 <- {RESOLVER}:51000 SINGLE:MULTIPLE",
            id="another port: the target last",
        ),
        pytest.param(
            "media-udp",
            MEDIA,
            f"ALL udp {PEER}:7000 <- {HOST}:45128 <- {MEDIA}:45128 MULTIPLE:MULTIPLE",
            id="a port above the return range: the target last",
        ),
    ],
)
def test_the_runtimes_translation_to_an_outside_peer_is_not_retained(
    environment: Any, key: str, target: str, row: str
) -> None:
    # Controls for the host's address as a peer. Each row names the guest, the
    # host's address and a peer outside the LAN prefix, so the host's address
    # is no peer in it. This held before and must go on holding.
    assert not retained(environment[1], key, target, row)


@pytest.mark.parametrize(
    "row",
    [
        pytest.param(REDIRECTED, id="beside the host's address"),
        pytest.param(
            f"all udp {HOST}:53 ({RESOLVER}:53) <- {CLIENT}:54321 ({PEER}:9) SINGLE:MULTIPLE",
            id="beside the host's address and an address outside the prefix",
        ),
        pytest.param(
            f"ALL udp {RESOLVER}:53 -> 192.0.2.9:53 -> {PEER}:53 SINGLE:MULTIPLE",
            id="beside an address outside the prefix",
        ),
    ],
)
def test_a_lan_peer_other_than_the_host_counts_whatever_else_the_row_names(
    environment: Any, row: str
) -> None:
    # Controls, as before: only the host's own address needs a row that names
    # no address outside the prefix.
    assert retained(environment[1], "dns-udp", RESOLVER, row)


def test_a_state_of_a_rule_is_retained_whichever_address_of_the_lan_prefix_is_its_peer(
    environment: Any,
) -> None:
    """Rows built from each profile's own parameters, for every address its rule matches."""
    config, snapshot = environment[1], environment[4][-1]
    checked: dict[str, int] = {}
    for profile in config.profiles:
        if profile.kind not in {"guest-direct", "udp-return"}:
            continue
        scope = config.scope(profile.scope)
        lan = ipaddress.IPv4Network(scope.lan_cidr)
        peers = [str(peer) for peer in lan]
        # The whole prefix: its first address, its last one and the host's own.
        assert len(peers) == lan.num_addresses
        assert {str(lan[0]), str(lan[-1]), scope.host_ipv4} <= set(peers)
        target = str(snapshot.services[profile.service].data["ipv4"])
        inner = profile.target_ports or profile.ports
        host = f"{scope.host_ipv4}:{profile.ports.first}"
        tail = "ESTABLISHED:ESTABLISHED" if profile.protocol == "tcp" else "SINGLE:MULTIPLE"
        rows: list[str] = []
        for port in sorted({inner.first, (inner.first + inner.last) // 2, inner.last}):
            guest = f"{target}:{port}"
            for peer in peers:
                rows += [
                    f"all {profile.protocol} {peer}:54321 -> {guest} {tail}",
                    f"all {profile.protocol} {guest} <- {peer}:54321 {tail}",
                    f"ALL {profile.protocol} {guest} <- {host} <- {peer}:54321 {tail}",
                    f"ALL {profile.protocol} {peer}:54321 -> {host} -> {guest} {tail}",
                ]
        record = record_of(config, profile.id, target)
        missed = [
            row.line
            for row in owner.state_rows("\n".join(rows))
            if not owner.retained_states(config, profile.id, target, record, (row,))
        ]
        assert missed == []
        checked[profile.id] = len(rows)

    assert checked == {"dns-udp": 1024, "dns-tcp": 1024, "media-udp": 3072}


@pytest.mark.parametrize("case", ["no-policy", "no-record", "removed", "digest", "kind"])
def test_when_the_policy_no_longer_describes_the_record_every_state_of_the_target_counts(
    environment: Any, case: str
) -> None:
    config = environment[1]
    described = record_of(config, "dns-udp", RESOLVER)
    record: dict[str, Any] | None = dict(described)
    policy: Config | None = config
    if case == "no-policy":
        policy = None
    elif case == "no-record":
        record = None
    elif case == "removed":
        policy = replace(
            config, profiles=tuple(item for item in config.profiles if item.id != "dns-udp")
        )
    elif case == "digest":
        record = {**described, "policy_digest": "0" * 64}
    else:
        record = {**described, "kind": "udp-return"}
    own = owner.state_rows(OWN_TCP)
    assert not owner.retained_states(config, "dns-udp", RESOLVER, described, own)

    assert owner.retained_states(policy, "dns-udp", RESOLVER, record, own)
    # A row that does not name the target never counts.
    other = owner.state_rows(RETURNED)
    assert not owner.retained_states(policy, "dns-udp", RESOLVER, record, other)
    assert not owner.retained_states(policy, "dns-udp", RESOLVER, record, ())


def test_two_profiles_onto_one_target_port_of_one_guest_are_not_told_apart(
    environment: Any,
) -> None:
    config = environment[1]
    second = replace(config.profile("dns-udp"), id="dns-alternate", ports=PortRange(5353, 5353))
    both = replace(config, profiles=(*config.profiles, second))
    validate_config(both)
    # A client's state of the second rule: the host endpoint has its port.
    through_second = f"ALL udp {RESOLVER}:53 <- {HOST}:5353 <- {CLIENT}:54321 SINGLE:MULTIPLE"

    assert retained(both, "dns-alternate", RESOLVER, through_second)
    # The host endpoint's port is not consulted, so it counts for the first too.
    assert retained(both, "dns-udp", RESOLVER, through_second)


@pytest.mark.parametrize(
    "key,target,row",
    [
        pytest.param(
            "media-udp",
            MEDIA,
            f"ALL udp {MEDIA}:45001 -> {HOST}:50001 -> {CLIENT}:7000 SINGLE:MULTIPLE",
            id="return profile: a flow another translation carries",
        ),
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"ALL udp {RESOLVER}:53 -> {HOST}:50002 -> {CLIENT}:5353 SINGLE:MULTIPLE",
            id="redirect: the guest sends from its published port",
        ),
    ],
)
def test_a_guests_own_flow_to_a_lan_peer_from_a_port_of_the_rule_is_not_told_apart(
    environment: Any, key: str, target: str, row: str
) -> None:
    # The rule's own states have these properties too; only the host
    # endpoint's port differs, and it is not consulted.
    assert retained(environment[1], key, target, row)


@pytest.mark.parametrize(
    "key,target,row",
    [
        pytest.param(
            "dns-udp",
            RESOLVER,
            f"all udp {RESOLVER}:53 -> {HOST}:5353 SINGLE:MULTIPLE",
            id="redirect: the guest sends from its published port",
        ),
        pytest.param(
            "media-udp",
            MEDIA,
            f"ALL udp {MEDIA}:45001 -> {HOST}:45001 -> {HOST}:7000 SINGLE:NO_TRAFFIC",
            id="return profile: a flow from the published range",
        ),
    ],
)
def test_a_guests_own_flow_to_the_hosts_address_from_a_port_of_the_rule_is_not_told_apart(
    environment: Any, key: str, target: str, row: str
) -> None:
    # A state of the rule whose peer is the host's own address names the
    # target with a port of the rule and that address, and nothing else. So
    # does this row, and the direction of a row is not read.
    assert retained(environment[1], key, target, row)


# ---------------------------------------------------------------- in a pass


def test_the_report_marks_states_of_the_rule_and_not_a_guests_own(environment: Any) -> None:
    backend = Kernel(lasting=[OWN_TCP, OWN_UDP, RETURNED])
    environment = active(environment, backend)

    result, report = published(environment)

    assert result["phase"] == "committed"
    assert report.profiles["dns-tcp"].data["states"] == ()
    assert report.profiles["dns-udp"].data["states"] == ()
    assert report.profiles["media-udp"].data["states"] == ("retained",)


def test_a_host_redirect_has_no_retained_states(environment: Any) -> None:
    # A client's state of the host redirect, and a client of the published port itself.
    through_redirect = f"ALL tcp {HOST}:8080 <- {HOST}:80 <- {CLIENT}:50000 ESTABLISHED:ESTABLISHED"
    direct = f"all tcp {CLIENT}:50001 -> {HOST}:8080 ESTABLISHED:ESTABLISHED"
    backend = Kernel(lasting=[through_redirect, direct])
    environment = active(environment, backend)
    root = environment[0]

    result, report = published(environment)

    assert result["phase"] == "committed"
    assert report.profiles["proxy-standard"].data["states"] == ()

    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    result, report = published(environment)

    # Its retirement never invalidates states of the host's own address.
    assert result["phase"] == "inhibited" and "deferred" not in result
    assert owned(backend) == [] and root.read("live.json")["records"] == {}
    assert backend.kills == [] and not any(c[0] == "drain" for c in backend.commands)
    assert report.profiles["proxy-standard"].data["states"] == ()


@pytest.mark.parametrize(
    "own",
    [
        pytest.param(None, id="untranslated"),
        pytest.param(OWN_TCP, id="translated tcp"),
        pytest.param(OWN_UDP, id="translated udp"),
        pytest.param(
            f"ALL tcp {RESOLVER}:51000 -> {HOST}:51000 -> {CLIENT}:445 ESTABLISHED:ESTABLISHED",
            id="to a LAN host",
        ),
    ],
)
def test_a_guests_own_connection_is_no_retained_state(environment: Any, own: str | None) -> None:
    resolver = address(environment, "resolver")
    assert resolver == RESOLVER
    backend = Kernel({resolver}) if own is None else Kernel(lasting=[own])
    environment = active(environment, backend)
    root = environment[0]
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))

    result, report = published(environment)

    assert result["phase"] == "inhibited" and "deferred" not in result
    assert owned(backend) == [] and root.read("live.json")["records"] == {}
    # Nothing was invalidated: the guest's connection is still there.
    assert backend.kills == [] and not any(c[0] == "drain" for c in backend.commands)
    assert all(item.data["states"] == () for item in report.profiles.values())
    assert sorted(result["changed"]) == sorted(
        f"{key}:{operation}"
        for key in ("dns-tcp", "dns-udp", "media-udp", "proxy-standard")
        for operation in ("withdraw", "drain")
    )


def test_a_client_state_of_the_retired_rule_is_invalidated_once(environment: Any) -> None:
    backend = Kernel()
    environment = active(environment, backend)
    root = environment[0]
    backend.flow_states = f"{REDIRECTED}\n{OWN_TCP}"
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))

    result, _ = published(environment)

    assert result["phase"] == "inhibited" and "deferred" not in result
    # One invalidation, for the one profile whose rule has a client state.
    assert backend.kills == [RESOLVER]
    assert backend.flow_states == "" and root.read("live.json")["records"] == {}

    assert published(environment)[0]["phase"] == "inhibited"
    assert backend.kills == [RESOLVER]


def test_a_state_whose_peer_is_the_host_is_invalidated_before_its_address_is_reused(
    environment: Any,
) -> None:
    old = address(environment, "resolver")
    backend = Kernel()
    environment = active(environment, backend)
    backend.flow_states = f"all udp {HOST}:54321 -> {old}:53 SINGLE:NO_TRAFFIC"
    # The resolver moves and another guest is given its former address.
    moved(environment, {"resolver": "198.51.100.50", "camera": old})

    result, _ = published(environment)

    assert result["phase"] == "inhibited" and "deferred" not in result
    # One invalidation of the old address, and the state is not listed any
    # more when the pass ends, before a rule for the new target is loaded.
    assert backend.kills == [old] and backend.flow_states == ""
    assert owned(backend) == []

    result, _ = published(environment)

    assert result["phase"] == "committed" and backend.kills == [old]
    assert backend.rules.count("-> 198.51.100.50 port 53") == 2


def test_a_listed_state_whose_peer_is_the_host_holds_back_the_replacement_target(
    environment: Any,
) -> None:
    old = address(environment, "resolver")
    assert old == RESOLVER
    backend = Kernel(lasting=[FROM_HOST])
    environment = active(environment, backend)
    root = environment[0]
    moved(environment, {"resolver": "198.51.100.50", "camera": old})

    result, report = published(environment)

    # The old address is invalidated, and the row is listed again at the readback.
    assert result["phase"] == "inhibited"
    assert result["deferred"] == {"dns-udp": "states-retained"}
    assert backend.kills == [old] and owned(backend) == []

    result, report = published(environment)

    # The other profiles return, the tcp one at the new address. This one
    # keeps its withdrawn record: no replacement target is activated for it.
    assert result["phase"] == "inhibited"
    assert result["deferred"] == {"dns-udp": "states-retained"}
    assert backend.kills == [old, old]
    assert owned(backend) == ["dns-tcp", "media-udp", "media-udp", "proxy-standard"]
    assert backend.rules.count("-> 198.51.100.50 port 53") == 1
    record = root.read("live.json")["records"]["dns-udp"]
    assert record["active"] is False and record["target_ipv4"] == old
    assert report.profiles["dns-udp"].data["root_ready"] is False

    backend.lasting.clear()
    result, report = published(environment)

    assert result["phase"] == "committed" and result["changed"] == ["dns-udp:activate"]
    assert backend.rules.count("-> 198.51.100.50 port 53") == 2
    assert backend.kills == [old, old]
    assert report.profiles["dns-udp"].data["root_ready"] is True


def test_an_invalidation_that_fails_ends_the_pass_failed_and_keeps_the_retired_record(
    environment: Any,
) -> None:
    approve_all(environment)
    root, _, _, backend, _ = environment
    assert run_pass(environment)["phase"] == "committed"
    backend.flow_states = REDIRECTED
    backend.undrainable = True
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))

    # The command fails. That is no drain that stays open: the pass raises.
    with pytest.raises(PFError, match="remaining states"):
        run_pass(environment)

    journal = root.read("journal.json")
    assert journal["phase"] == "failed" and "deferred" not in journal
    assert backend.rules == "" and backend.flow_states == REDIRECTED
    records = root.read("live.json")["records"]
    assert "dns-udp" in records and not any(item["active"] for item in records.values())

    # Resumed, with the command still failing: every pass ends the same way.
    root.write("operator-intent.json", intent_to_dict(Intent(2, False)))
    for _ in range(2):
        with pytest.raises(PFError, match="remaining states"):
            run_pass(environment)
        assert root.read("journal.json")["phase"] == "failed" and backend.rules == ""
        assert "dns-udp" in root.read("live.json")["records"]

    # The command works again. Without the acknowledgement the passes finish
    # the retirement, stay failed and activate nothing.
    backend.undrainable = False
    for _ in range(2):
        result = run_pass(environment)
        assert result["phase"] == "failed" and "deferred" not in result
        assert backend.rules == "" and backend.flow_states == ""
        assert root.read("live.json")["records"] == {}

    acknowledge(root)
    assert run_pass(environment)["phase"] == "committed"
    assert "# netorch:dns-udp" in backend.rules


def test_a_failing_invalidation_is_never_reported_as_states_retained(environment: Any) -> None:
    approve_all(environment)
    root, _, _, backend, snapshots = environment
    assert run_pass(environment)["phase"] == "committed"
    # A state of each of two rules is listed, and the command fails.
    backend.flow_states = f"{REDIRECTED}\n{RETURNED}"
    backend.undrainable = True
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    reports: list[Snapshot] = []

    for _ in range(3):
        with pytest.raises(PFError, match="remaining states"):
            reconcile(
                root,
                lambda config, settings: snapshots[-1],
                lambda root, settings: backend,
                now=lambda: STAMP,
                report=lambda settings, snapshot: reports.append(snapshot),
            )
        # There is no result. The journal names no deferral either, and no
        # report was written that could carry one.
        journal = root.read("journal.json")
        assert journal["phase"] == "failed" and "deferred" not in journal
        assert "states-retained" not in str(journal)
    assert reports == []


class UnreadableOnce(Kernel):
    """A state table that cannot be read at one chosen read."""

    def __init__(self, unreadable: int) -> None:
        super().__init__()
        self.unreadable = unreadable
        self.reads = 0

    def states(self) -> str:
        self.reads += 1
        if self.reads == self.unreadable:
            return "WARNING: state inventory truncated"
        return super().states()


@pytest.mark.parametrize("unreadable", [3, 4], ids=["before", "after-the-invalidation"])
def test_a_table_that_cannot_be_read_during_a_drain_ends_the_pass_failed(
    environment: Any, unreadable: int
) -> None:
    backend = UnreadableOnce(0)
    environment = active(environment, backend)
    root = environment[0]
    backend.flow_states = REDIRECTED
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    backend.reads = 0
    backend.unreadable = unreadable  # read 1: the pass starts; 2: the tcp profile

    with pytest.raises(PFError, match="unsupported PF state observation"):
        published(environment)

    journal = root.read("journal.json")
    assert journal["phase"] == "failed" and "deferred" not in journal
    assert owned(backend) == []
    records = root.read("live.json")["records"]
    assert "dns-udp" in records and not any(item["active"] for item in records.values())
    # An invalidation is issued only for a state that a read has shown.
    assert backend.kills == ([] if unreadable == 3 else [RESOLVER])

    # The table can be read again and the pause is lifted. Without the
    # acknowledgement the passes finish the retirement, stay failed and
    # activate nothing.
    root.write("operator-intent.json", intent_to_dict(Intent(2, False)))
    for _ in range(2):
        result, _ = published(environment)
        assert result["phase"] == "failed" and "deferred" not in result
        assert owned(backend) == [] and root.read("live.json")["records"] == {}
        assert backend.kills == [RESOLVER]

    acknowledge(root)
    result, _ = published(environment)
    assert result["phase"] == "committed" and "dns-udp" in owned(backend)
    assert backend.kills == [RESOLVER]


def test_a_changed_profile_waits_for_every_state_of_its_old_target(environment: Any) -> None:
    media = address(environment, "media-controller")
    backend = Kernel({media})  # the guest keeps a connection of its own
    environment = active(environment, backend)
    root, config, _, _, _ = environment
    changed = to_dict(config)
    narrowed = {"first": 45000, "last": 45063}
    next(item for item in changed["profiles"] if item["id"] == "media-udp")["ports"] = narrowed
    next(item for item in changed["services"] if item["id"] == "media-controller")[
        "automatic_ports"
    ] = narrowed
    root.write("policy.json", changed)

    # The record's rule is not the one the policy describes now, so its states
    # cannot be told from the guest's own: every state of the address counts.
    for attempt in (1, 2):
        result, report = published(environment)
        assert result["phase"] == "inhibited"
        assert result["deferred"] == {"media-udp": "states-retained"}
        assert backend.kills == [media] * attempt
        assert owned(backend) == ["dns-tcp", "dns-udp", "proxy-standard"]
        for key in ("dns-tcp", "dns-udp", "proxy-standard"):
            assert report.profiles[key].data["root_ready"] is True

    backend.live_guests.clear()
    result, _ = published(environment)
    assert "deferred" not in result and result["pending"] == ["media-udp"]
    assert "media-udp" not in root.read("live.json")["records"]


# ---------------------------------------------------------------- the administrator


def test_withdrawal_fails_closed_while_a_state_of_its_rules_remains(environment: Any) -> None:
    resolver = address(environment, "resolver")
    backend = Kernel({resolver}, lasting=[REDIRECTED])
    environment = active(environment, backend)
    root = environment[0]

    with pytest.raises(PFError, match=REMAIN):
        withdraw(root, lambda root, settings: backend)

    assert owned(backend) == [] and root.read("journal.json")["phase"] == "failed"
    assert backend.kills == [resolver]
    assert all(not item["active"] for item in root.read("live.json")["records"].values())

    # With the client's state gone the guest's own connection does not hold it up.
    backend.lasting.clear()
    result = withdraw(root, lambda root, settings: backend)

    assert result["withdrawn"] is True and result["guest_states_drained"] is True
    assert backend.kills == [resolver]
    assert root.read("live.json") == {"schema_version": 1, "records": {}}
    assert root.read("journal.json") == {
        "schema_version": 1,
        "phase": "inhibited",
        "reason": "administrator-withdrawal",
    }


def test_withdrawal_fails_closed_while_a_state_whose_peer_is_the_host_is_listed(
    environment: Any,
) -> None:
    resolver = address(environment, "resolver")
    assert resolver == RESOLVER
    backend = Kernel(lasting=[FROM_HOST])
    environment = active(environment, backend)
    root = environment[0]

    with pytest.raises(PFError, match=REMAIN):
        withdraw(root, lambda root, settings: backend)

    assert owned(backend) == [] and root.read("journal.json")["phase"] == "failed"
    assert backend.kills == [resolver]
    assert all(not item["active"] for item in root.read("live.json")["records"].values())

    backend.lasting.clear()
    result = withdraw(root, lambda root, settings: backend)

    assert result["withdrawn"] is True and result["guest_states_drained"] is True
    assert backend.kills == [resolver]
    assert root.read("live.json") == {"schema_version": 1, "records": {}}


def test_withdrawal_invalidates_a_state_whose_peer_is_the_host(environment: Any) -> None:
    resolver = address(environment, "resolver")
    backend = Kernel()
    environment = active(environment, backend)
    root = environment[0]
    backend.flow_states = f"all udp {HOST}:54321 -> {resolver}:53 SINGLE:NO_TRAFFIC"

    result = withdraw(root, lambda root, settings: backend)

    # It reports the states drained, and the state is not listed any more.
    assert result["withdrawn"] is True and result["guest_states_drained"] is True
    assert backend.kills == [resolver] and backend.flow_states == ""
    assert root.read("live.json") == {"schema_version": 1, "records": {}}


@pytest.mark.parametrize("unreadable", [2, 3], ids=["before", "after-the-invalidation"])
def test_withdrawal_fails_closed_when_the_table_cannot_be_read(
    environment: Any, unreadable: int
) -> None:
    # A control: the withdrawal never took an error in a drain for a drained state.
    backend = UnreadableOnce(0)
    environment = active(environment, backend)
    root = environment[0]
    backend.flow_states = REDIRECTED
    backend.reads = 0
    backend.unreadable = unreadable  # read 1: the tcp profile

    with pytest.raises(PFError, match="unsupported PF state observation"):
        withdraw(root, lambda root, settings: backend)

    assert owned(backend) == [] and root.read("journal.json")["phase"] == "failed"
    records = root.read("live.json")["records"]
    assert "dns-udp" in records and not any(item["active"] for item in records.values())
    assert backend.kills == ([] if unreadable == 2 else [RESOLVER])

    result = withdraw(root, lambda root, settings: backend)

    assert result["withdrawn"] is True and result["guest_states_drained"] is True
    assert backend.kills == [RESOLVER] and backend.flow_states == ""


@pytest.mark.parametrize("policy", ["missing", "damaged"])
def test_withdrawal_counts_every_state_when_it_cannot_read_the_policy(
    environment: Any, policy: str
) -> None:
    resolver = address(environment, "resolver")
    backend = Kernel({resolver})
    environment = active(environment, backend)
    root = environment[0]
    if policy == "missing":
        (root.directory / "policy.json").unlink()
    else:
        root.write("policy.json", {"schema_version": 1})

    with pytest.raises(PFError, match=REMAIN):
        withdraw(root, lambda root, settings: backend)

    assert owned(backend) == [] and backend.kills == [resolver]
    assert root.read("journal.json")["phase"] == "failed"


def test_the_backend_drain_issues_the_scoped_invalidation_and_reads_nothing(
    environment: Any, monkeypatch: Any
) -> None:
    root, _, settings, _, _ = environment
    shell = object.__new__(ShellBackend)
    shell.root = root
    shell.installation = settings
    shell.script = root.directory / "backend.sh"
    seen: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> Result:
        seen.append(argv)
        return Result(0, b"", b"")

    monkeypatch.setattr(owner, "run", run)
    shell.drain(RESOLVER)

    assert seen == [["/bin/bash", str(shell.script), "drain", settings.anchor, RESOLVER]]
    with pytest.raises(ValueError):
        shell.drain("198.51.100.10/24")
    assert len(seen) == 1

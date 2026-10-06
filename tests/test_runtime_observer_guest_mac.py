"""The runtime observer reports the guest's hardware address; the root owner checks it.

The address strings below are synthetic and follow the one form the vendor's
encoder writes. The tool outputs of the fake kernel are the same invented lines
the existing endpoint tests use; none of them is a capture.
"""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime
from netorch.codec import canonical_bytes
from netorch.config import to_dict
from netorch.model import Scope
from netorch.pf_owner import STRATEGY, Installation, ShellBackend, admit, reconcile
from netorch.state import Intent, Snapshot, intent_to_dict, snapshot_to_dict
from netorch.storage import Store
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_pf_owner import FakeBackend

__all__ = ["enrolled"]

DEFERRED = "endpoint-unverified"
GUEST_BRIDGE = 100


def attachment(items: dict[str, Any], name: str) -> Any:
    return items[name]["status"]["networks"][0]


def give_addresses(items: dict[str, Any]) -> dict[str, str]:
    """Give every running guest its own address; return guest IPv4 -> address."""
    result = {}
    for index, name in enumerate(sorted(items), start=1):
        value = f"f2:00:00:00:00:{index:02x}"
        attachment(items, name)["macAddress"] = value
        result[attachment(items, name)["ipv4Address"].split("/")[0]] = value
    return result


def observed(enrolled: Any) -> Snapshot:
    config, settings, items = enrolled
    return apple_runtime.observe_runtime(config, settings, FakeRunner(settings, items))


@pytest.mark.parametrize("version", ["1.2.0", "1.4.1", "1.5.0"])
def test_observer_reports_the_attachment_address_at_every_accepted_version(
    enrolled: Any, version: str
) -> None:
    config, settings, items = enrolled
    settings = replace(settings, accepted_version=version)
    addresses = give_addresses(items)

    snapshot = observed((config, settings, items))

    assert len(addresses) == len(snapshot.services) == 4
    for service in snapshot.services.values():
        assert (service.state, service.reason) == ("present", "verified")
        assert service.data["mac"] == addresses[service.data["ipv4"]]


def test_an_attachment_without_an_address_leaves_the_observation_without_one(
    enrolled: Any,
) -> None:
    items = enrolled[2]
    give_addresses(items)
    del attachment(items, "example-resolver")["macAddress"]

    snapshot = observed(enrolled)

    resolver = snapshot.services["resolver"]
    assert (resolver.state, resolver.reason) == ("present", "verified")
    assert "mac" not in resolver.data
    assert all("mac" in item.data for key, item in snapshot.services.items() if key != "resolver")


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "F2:00:00:00:00:0A",
        "f2-00-00-00-00-0a",
        "f2:0:0:0:0:a",
        "f2:00:00:00:00",
        "f2:00:00:00:00:0a:0b",
        "f2:00:00:00:00:0g",
        "f200.0000.000a",
        "f20000000000a",
        " f2:00:00:00:00:0a",
        "f2:00:00:00:00:0a\n",
        266_287_972_362,
        True,
        ["f2:00:00:00:00:0a"],
        {"address": "f2:00:00:00:00:0a"},
    ],
    ids=[
        "null",
        "empty",
        "upper case",
        "dashes",
        "short groups",
        "five groups",
        "seven groups",
        "not hexadecimal",
        "dotted",
        "no separators",
        "leading space",
        "trailing newline",
        "number",
        "boolean",
        "list",
        "object",
    ],
)
def test_an_address_in_any_other_form_is_not_offered_and_not_repaired(
    enrolled: Any, value: Any
) -> None:
    items = enrolled[2]
    give_addresses(items)
    attachment(items, "example-media-controller")["macAddress"] = value

    snapshot = observed(enrolled)

    media = snapshot.services["media-controller"]
    assert (media.state, media.reason) == ("present", "verified")
    assert "mac" not in media.data
    assert "mac" in snapshot.services["resolver"].data


class Kernel(FakeBackend):
    """Fake rules and states; the owner's own endpoint check over faked native tools.

    The host side answers for the LAN interface and address of the policy's
    scope; every guest is reached through one guest bridge.
    """

    def __init__(self, config: Any, neighbours: dict[str, str]) -> None:
        super().__init__()
        self.lan = config.scopes[0]
        self.bridge = f"bridge{GUEST_BRIDGE}"
        self.neighbours = neighbours
        self.offered: dict[str, str | None] = {}
        self.shell = object.__new__(ShellBackend)
        self.shell._native = self.native  # type: ignore[method-assign]

    def native(self, argv: list[str]) -> str:
        tool, target = argv[0], argv[-1]
        if tool == "/sbin/ifconfig":
            return f"{self.lan.interface}: flags=1\n inet {self.lan.host_ipv4} netmask 0xffffff00\n"
        if tool == "/usr/sbin/sysctl":
            return "1\n"
        if tool == "/sbin/route":
            return f"route to: {target}\ninterface: {self.bridge}\nflags: <UP,HOST,DONE,LLINFO>\n"
        if tool == "/usr/sbin/arp":
            # Spelled as in the existing endpoint tests: no leading zero in a group.
            entry = ":".join(
                format(int(group, 16), "x") for group in self.neighbours[target].split(":")
            )
            return f"? ({target}) at {entry} on {self.bridge} ifscope [bridge]\n"
        raise AssertionError(argv)

    def endpoint(self, scope: Scope, ipv4: str, mac: str | None, *, direct: bool) -> bool:
        if direct:
            self.offered[ipv4] = mac
        return self.shell.endpoint(scope, ipv4, mac, direct=direct)


def admitted_root(tmp_path: Path, config: Any) -> Store:
    """A protected owner store with every profile of the forwarding owner admitted."""
    settings = Installation(
        "site-forwarding",
        "com.apple/netorch.site-forwarding",
        {"schema_version": 1, "account": "example"},
        "0" * 64,
        str(tmp_path / "report.json"),
    )
    root = Store(tmp_path / "forwarding-root")
    root.write("installation.json", settings.to_dict())
    root.write("policy.json", to_dict(config))
    root.write("admissions.json", {"schema_version": 1, "strategy": STRATEGY, "profiles": {}})
    root.write("operator-intent.json", intent_to_dict(Intent()))
    for profile in config.profiles:
        if config.profile_owner(profile).id == settings.owner:
            admit(root, profile.id, acknowledge_bounded_risk=True, now=time.time() - 5)
    return root


def one_pass(enrolled: Any, root: Store, backend: Kernel) -> tuple[dict[str, Any], Snapshot]:
    """One pass of the root owner over the real observer; returns result and report."""
    _, settings, items = enrolled
    runner = FakeRunner(settings, items)
    reports: list[Snapshot] = []
    result = reconcile(
        root,
        lambda config, _: apple_runtime.observe_runtime(config, settings, runner),
        lambda root, _: backend,
        report=lambda _, snapshot: reports.append(snapshot),
    )
    return result, reports[-1]


def test_direct_guest_targets_activate_from_the_real_observation(
    enrolled: Any, tmp_path: Path
) -> None:
    config, _, items = enrolled
    addresses = give_addresses(items)
    resolver = attachment(items, "example-resolver")["ipv4Address"].split("/")[0]
    media = attachment(items, "example-media-controller")["ipv4Address"].split("/")[0]
    backend = Kernel(config, dict(addresses))

    result, report = one_pass(enrolled, admitted_root(tmp_path, config), backend)

    assert result["phase"] == "committed" and len(result["changed"]) == 4
    assert f"-> {resolver} port 53" in backend.rules
    assert f"from {media} port 45000:45127" in backend.rules and "static-port" in backend.rules
    # The root owner was offered exactly what the runtime reported for each guest.
    assert backend.offered == {resolver: addresses[resolver], media: addresses[media]}
    # The address stays inside the pass: the published report carries no service data.
    published = canonical_bytes(snapshot_to_dict(report)).decode()
    assert report.services == {} and not any(value in published for value in addresses.values())


def test_without_an_address_from_the_runtime_no_direct_target_is_accepted(
    enrolled: Any, tmp_path: Path
) -> None:
    config, _, items = enrolled
    backend = Kernel(config, {})

    result, _ = one_pass(enrolled, admitted_root(tmp_path, config), backend)

    # Each rule with a direct guest target is deferred on its own; the host
    # redirect needs no guest address and is loaded.
    assert result["phase"] == "inhibited"
    assert result["deferred"] == dict.fromkeys(("dns-tcp", "dns-udp", "media-udp"), DEFERRED)
    assert backend.offered and set(backend.offered.values()) == {None}
    guests = {attachment(items, name)["ipv4Address"].split("/")[0] for name in items}
    assert not any(guest in backend.rules for guest in guests)
    assert all("macAddress" not in attachment(items, name) for name in items)


def test_the_kernel_neighbour_must_carry_the_reported_address(
    enrolled: Any, tmp_path: Path
) -> None:
    config, _, items = enrolled
    addresses = give_addresses(items)
    media = attachment(items, "example-media-controller")["ipv4Address"].split("/")[0]
    backend = Kernel(config, {**addresses, media: "f2:00:00:00:00:ee"})

    result, _ = one_pass(enrolled, admitted_root(tmp_path, config), backend)

    assert result["deferred"] == {"media-udp": DEFERRED}
    assert backend.offered[media] == addresses[media]
    assert "static-port" not in backend.rules


def test_a_group_address_from_the_runtime_is_refused_by_the_endpoint_check(
    enrolled: Any, tmp_path: Path
) -> None:
    config, _, items = enrolled
    addresses = give_addresses(items)
    media = attachment(items, "example-media-controller")["ipv4Address"].split("/")[0]
    group = "f3:00:00:00:00:03"
    attachment(items, "example-media-controller")["macAddress"] = group
    backend = Kernel(config, {**addresses, media: group})

    result, _ = one_pass(enrolled, admitted_root(tmp_path, config), backend)

    # The observer reports what the runtime says; the root owner decides.
    assert result["deferred"] == {"media-udp": DEFERRED}
    assert backend.offered[media] == group
    assert "static-port" not in backend.rules

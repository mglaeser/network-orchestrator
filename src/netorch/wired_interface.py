"""Reuse the bounded native Ethernet selector without introducing an owner.

The installed package chooses the executable resource, never instance data.
An observation selects only a current interface: it does not assign an address,
move DHCP reservations, authorize forwarding or qualify any LAN traffic path.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from importlib import resources
from pathlib import Path
from typing import Any

from .instance import read_data, valid_wired_address
from .process import Result

RESOURCE = "platform/macos/network/wired-interface.pl"
MODE = "auto-wired"


def selector_path() -> Path:
    """Filesystem installation only; no extraction, download or writable cache."""
    installed = resources.files("netorch").joinpath(RESOURCE)
    if isinstance(installed, Path) and installed.is_file():
        return installed
    checkout = Path(__file__).resolve().parents[2] / RESOURCE
    if checkout.is_file():
        return checkout
    raise FileNotFoundError("packaged wired selector is unavailable")


def selector_digest() -> str:
    return hashlib.sha256(read_data(selector_path())).hexdigest()


def valid_proof(value: Any) -> bool:
    """Validate the closed selection observation; freshness is checked by its caller."""
    if not isinstance(value, dict) or set(value) != {
        "mode",
        "interface",
        "ipv4",
        "selector_sha256",
    }:
        return False
    if (
        value["mode"] != MODE
        or not isinstance(value["interface"], str)
        or re.fullmatch(r"en[0-9]{1,30}", value["interface"]) is None
        or not isinstance(value["selector_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["selector_sha256"]) is None
        or not isinstance(value["ipv4"], str)
    ):
        return False
    return valid_wired_address(value["ipv4"])


def observe(
    address: str,
    *,
    runner: Callable[[tuple[str, ...], float], Result],
    timeout: float,
) -> dict[str, str]:
    path = selector_path()
    before = hashlib.sha256(read_data(path)).hexdigest()
    proof = {"mode": MODE, "interface": "en0", "ipv4": address, "selector_sha256": before}
    if not valid_proof(proof):
        raise ValueError("wired selection requires one canonical unicast IPv4 address")
    result = runner(("/usr/bin/perl", str(path), address), timeout)
    if result.returncode != 0:
        raise ValueError("native wired selection did not establish unique eligible ownership")
    if result.stderr or re.fullmatch(rb"en[0-9]{1,30}\n", result.stdout) is None:
        raise ValueError("malformed wired selection result")
    if hashlib.sha256(read_data(path)).hexdigest() != before:
        raise ValueError("wired selector changed during observation")
    proof["interface"] = result.stdout.decode("ascii").rstrip("\n")
    return proof

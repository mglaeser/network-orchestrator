"""Sanitized shape of a local macOS extension replacement inventory.

Observed with the native read-only systemextensionsctl list on 2026-10-08.
Identifiers, versions and names are synthetic; this is parser evidence only.
"""

import pytest

from netorch.macos_preflight import _extensions


def inventory(retired: str = "terminated waiting to uninstall on reboot") -> str:
    return (
        "2 extension(s)\n"
        "--- com.apple.system_extension.network_extension (Go to System Settings)\n"
        "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
        f"\t\tEXAMPLTEAM\torg.example.filter (1.0/1)\tExample Filter\t[{retired}]\n"
        "*\t*\tEXAMPLTEAM\torg.example.filter (2.0/2)\tExample Filter\t[activated enabled]"
    )


def test_retired_and_active_versions_of_one_extension_are_one_baseline_identity() -> None:
    assert _extensions(inventory()) == ["org.example.filter"]


@pytest.mark.parametrize("damage", ["count", "duplicate", "team", "active", "state"])
def test_ambiguous_replacements_stay_unknown(damage: str) -> None:
    text = inventory()
    if damage == "count":
        text = text.replace("2 extension(s)", "1 extension(s)")
    elif damage == "duplicate":
        text = "\n".join([*text.splitlines()[:3], text.splitlines()[4], text.splitlines()[4]])
    elif damage == "team":
        text = text.replace("EXAMPLTEAM", "OTHERTEAM1", 1)
    elif damage == "active":
        text = text.replace("terminated waiting to uninstall on reboot", "activated enabled")
    else:
        text = text.replace("terminated waiting to uninstall on reboot", "unknown future state")
    with pytest.raises(ValueError):
        _extensions(text)

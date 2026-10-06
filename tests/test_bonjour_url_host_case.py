"""How the host name of a projected endpoint URL compares with the guest's name.

Synthetic names and RFC 5737 addresses only.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from netorch import bonjour_owner as owner
from netorch.discovery import Record

GUEST = "198.51.100.12"
TARGET = "192.0.2.10"


def projected(url: str, guest_host: str, key: str = "internal_url") -> bytes:
    source = Record(
        "Home",
        "_home-assistant._tcp",
        guest_host,
        8080,
        GUEST,
        (f"{key}={url}".encode(),),
        "bridge-test",
        1,
    )
    target = replace(source, ipv4=TARGET, port=8080)
    return owner.rewrite_endpoint_urls(source, target)[0]


@pytest.mark.parametrize(
    ("url", "guest_host"),
    [
        ("http://Guest-UI.local:8080", "Guest-UI.local."),
        ("http://guest-ui.local:8080", "Guest-UI.local."),
        ("http://GUEST-UI.LOCAL.:8080", "guest-ui.local."),
        ("http://Guest-UI.local", "guest-ui.local."),
        # Not an ASCII letter: equal only in the same spelling.
        ("http://K\u00c4MMERLEIN.local:8080", "k\u00c4mmerlein.local."),
    ],
)
def test_url_naming_the_guest_in_any_ascii_case_is_projected(url: str, guest_host: str) -> None:
    assert projected(url, guest_host) == f"internal_url=http://{TARGET}:8080".encode()


@pytest.mark.parametrize(
    ("url", "guest_host"),
    [
        # RFC 4343 compares ASCII letters only; these are two different names.
        ("http://K\u00c4MMERLEIN.local:8080", "k\u00e4mmerlein.local."),
        ("http://k\u00e4mmerlein.local:8080", "K\u00c4MMERLEIN.local."),
        ("http://other-guest.local:8080", "guest-ui.local."),
        ("http://guest-ui.local.example:8080", "guest-ui.local."),
        ("http://user:secret@Guest-UI.local:8080", "guest-ui.local."),
        ("http://[2001:db8::12]:8080", "guest-ui.local."),
        ("ftp://guest-ui.local:8080", "guest-ui.local."),
    ],
    ids=["upper-umlaut", "lower-umlaut", "other-host", "suffix", "credentials", "ipv6", "scheme"],
)
def test_url_that_does_not_name_the_guest_exactly_is_untouched(url: str, guest_host: str) -> None:
    assert projected(url, guest_host) == f"internal_url={url}".encode()


def test_url_projection_keeps_its_scheme_path_query_and_fragment() -> None:
    assert (
        projected("https://Guest-UI.local:8080/lovelace?x=1#y", "guest-ui.local.", "base_url")
        == f"base_url=https://{TARGET}:8080/lovelace?x=1#y".encode()
    )
    assert projected(f"http://{GUEST}:8080", "guest-ui.local.") == (
        f"internal_url=http://{TARGET}:8080".encode()
    )

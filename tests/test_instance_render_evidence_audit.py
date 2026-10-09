"""Cross-layer address policy regressions; synthetic data, no native operations."""

import json

import pytest

from netorch.render import render_sources
from tests.test_instance_free_text_addresses import (
    ABOVE_DOCUMENTATION,
    LINK_LOCAL,
    LOOPBACK,
    MULTICAST,
    UNIQUE_LOCAL,
)
from tests.test_render_sources import SECONDS, instance, one, reasons


@pytest.mark.parametrize("address", [UNIQUE_LOCAL, ABOVE_DOCUMENTATION])
@pytest.mark.parametrize("classification", ["constant", "unclassified", "composed", "translated"])
def test_renderer_rejects_routed_ipv6_like_instance_validation(tmp_path, address, classification):
    if classification == "constant":
        options = {"constants": ["/target"]}
        text = "http://[" + address + "]:9/"
    elif classification == "unclassified":
        options = {}
        text = address
    elif classification == "composed":
        options = {"composed": {"/target": [{"text": "[" + address + "]:"}, {"pointer": SECONDS}]}}
        text = "old"
    else:
        options = {
            "translated": {"/target": {"pointer": "/host/lan/link", "values": {"wired": address}}}
        }
        text = "old"
    captured = one(tmp_path, json.dumps({"target": text}).encode(), "json", **options)
    collected = {}
    result = render_sources(captured, instance(), collect=collected)
    selector = "/target" if classification in {"composed", "translated"} else None
    assert reasons(result) == [("live-address-in-owner-input", selector)]
    assert not collected and not result.sources


@pytest.mark.parametrize("address", ["2001:db8::1", LINK_LOCAL, LOOPBACK, MULTICAST])
def test_renderer_preserves_nonrouted_ipv6_literals_under_same_instance_rule(tmp_path, address):
    raw = json.dumps({"target": address}).encode()
    captured = one(tmp_path, raw, "json", constants=["/target"])
    collected = {}
    result = render_sources(captured, instance(), collect=collected)
    assert not result.issues
    assert result.sources[0].complete
    assert collected == {"input": raw}

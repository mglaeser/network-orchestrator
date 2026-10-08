"""The renderer's two uses of the credential guard: where it refuses, and where it relaxes.

The importer's guard reads a capital inside a word as a possible boundary, so
`replyToKen` or `passWord` name a credential. In the renderer the guard has four
callers. Two refuse a selector or a destination that holds such a key, as the
importer does, and take that guard. The other two relax: a subtree may stay
unexamined only under such a key, and a value under such a key is never
inspected. Those keep the guard as it stood before, so that the wider one does
not leave more values unexamined. Synthetic keys and documentation addresses.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest
from hypothesis import given, settings

from netorch.legacy_import import ImportError as StaticImportError
from netorch.legacy_import import _secret_key, import_sources
from netorch.render import RenderError, _named_credential, render_sources
from tests.test_importer_credential_capitals import generated_keys, refused_before
from tests.test_render_sources import instance, one, reasons

# Keys that only the wider guard names: a capital inside the listed word.
WIDER = ["replyToKen", "timeoutSecRet", "firstPassWord", "lowPassWd"]
NAME = "/names/bonjour_label"


def test_the_keys_are_named_by_the_wider_guard_only() -> None:
    assert all(_secret_key(key) and not _named_credential(key) for key in WIDER)


@pytest.mark.parametrize("key", WIDER)
def test_a_value_under_such_a_key_is_still_examined_and_cannot_be_left_unexamined(
    tmp_path: Path, key: str
) -> None:
    raw = json.dumps({"host": instance().host.lan.ipv4, key: "192.0.2.44"}).encode() + b"\n"
    mapping = {"/host": "/host/lan/ipv4"}
    # The address is inspected: an owner input that carries one is not rendered.
    result = render_sources(one(tmp_path, raw, "json", mapping), instance())
    assert reasons(result) == [("live-address-in-owner-input", None)]
    assert result.sources == ()
    # And the key does not let the manifest leave its value unexamined.
    with pytest.raises(RenderError, match="unexamined"):
        render_sources(one(tmp_path, raw, "json", mapping, unexamined=[f"/{key}"]), instance())


@pytest.mark.parametrize("key", WIDER)
def test_such_a_key_is_refused_wherever_a_credential_key_is_refused(
    tmp_path: Path, key: str
) -> None:
    raw = json.dumps({"name": "example", key: "example"}).encode() + b"\n"
    for more in (
        {"constants": [f"/{key}"]},
        {"independent": [f"/{key}"]},
        {"mapping": {f"/{key}": NAME}},
        {"mapping": {"/name": f"/workloads/example-web/{key}"}},
        {"composed": {f"/{key}": [{"pointer": NAME}]}},
        {"translated": {f"/{key}": {"pointer": NAME, "values": {"a": "b"}}}},
    ):
        with pytest.raises(RenderError, match="Credential"):
            render_sources(one(tmp_path, raw, "json", **more), instance())
    # The importer refuses the same selector and the same destination.
    for mapping in ({f"/{key}": NAME}, {"/name": f"/workloads/example-web/{key}"}):
        with pytest.raises(StaticImportError, match="Credential"):
            import_sources(one(tmp_path, raw, "json", mapping))


def test_the_relaxing_guard_answers_as_the_earlier_guard_on_every_short_key() -> None:
    # Every sequence of at most four pieces: a listed word in parts and
    # capitalisations, runs of capitals, a digit and both separators.
    pieces = ["t", "T", "oken", "OKEN", "Ken", "A", "AB", "9", "_", "-"]
    keys = [
        "".join(chosen)
        for length in range(5)
        for chosen in itertools.product(pieces, repeat=length)
    ]
    # Letters and digits before a password word, which the earlier guard reads too.
    password = ["x", "X", "9", "db2", "pass", "word", "wd", "phrase", "_"]
    keys += [
        "".join(chosen)
        for length in range(5)
        for chosen in itertools.product(password, repeat=length)
    ]
    keys += ["x9password", "db2passwd"]
    different = [key for key in keys if _named_credential(key) != refused_before(key)]
    assert different[:8] == []
    assert _named_credential("x9password") and _named_credential("db2passwd")


def test_a_constant_s_subtree_covers_a_key_only_the_wider_guard_names(tmp_path: Path) -> None:
    counted = {}
    for key in ("replyToKen", "reply_token"):
        raw = json.dumps({"name": "example", "settings": {key: "example"}}).encode() + b"\n"
        path = one(tmp_path, raw, "json", {"/name": NAME}, constants=["/settings"])
        found = render_sources(path, instance()).sources[0]
        counted[key] = (found.constants, found.unclassified, found.complete)
    # The value under the wider-only key is a constant; the other stays unclassified.
    assert counted == {"replyToKen": (1, 0, True), "reply_token": (0, 1, False)}


@settings(max_examples=1500, deadline=None, derandomize=True)
@given(generated_keys())
def test_the_relaxing_guard_answers_as_the_earlier_guard(key: str) -> None:
    assert _named_credential(key) == refused_before(key)

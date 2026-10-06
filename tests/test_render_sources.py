"""Literal owner inputs rendered from an instance: the captured file is the template.

Synthetic data only. Fixture bytes are built from the example instance's own
resolved names at run time, so that no file here states a site's namespace.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from netorch import render
from netorch.codec import canonical_bytes
from netorch.instance import (
    instance_digest,
    instance_to_dict,
    load_instance,
    parse_instance,
    resolved_names,
)
from netorch.instance_model import Instance
from netorch.legacy_import import _decode
from netorch.render import RenderError, render_sources, setting_literals, settings_view

ROOT = Path(__file__).resolve().parents[1]
PLIST_HEAD = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"'
    b' "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    b'<plist version="1.0">'
)
MARKER = "zq7"


@cache
def instance() -> Instance:
    return load_instance(ROOT / "examples" / "instance.json")


def changed(mutate: Callable[[dict[str, Any]], Any]) -> Instance:
    data = instance_to_dict(instance())
    mutate(data)
    return parse_instance(canonical_bytes(data) + b"\n")


def names() -> dict[str, str]:
    return resolved_names(instance())


def job() -> bytes:
    return (
        PLIST_HEAD + b"<dict>\n"
        b"<!-- reviewed job -->\n"
        b"<key>Label</key><string>" + names()["bonjour_label"].encode() + b"</string>\n"
        b"<key>ProgramArguments</key><array>"
        b"<string>" + names()["state_directory"].encode() + b"/bin/discover</string>"
        b"<string>serve</string></array>\n"
        b"<key>RunAtLoad</key><true/>\n"
        b"<key>ThrottleInterval</key><integer>7</integer>\n"
        b"</dict></plist>\n"
    )


def settings() -> bytes:
    return (
        b"# reviewed settings; never sourced by the importer\n"
        b"EXAMPLE_TARGET_ADDRESS=" + instance().host.lan.ipv4.encode() + b"\n"
        b'EXAMPLE_SCAN_SECONDS="20"\n'
        b"  EXAMPLE_MISS_LIMIT=3  \n"
        b"EXAMPLE_SOURCE_LINK='guest-link'\n"
    )


TYPES = b"# one type per line\nauto-tcp\n\n_example._tcp\n"
CATALOGUE = (
    b'{\n  "web": {"names": ["example-web"], "http": [27777], "note": "caf\\u00e9"},\n'
    b'  "enabled": true\n}\n'
)


def source(
    sid: str, path: str, fmt: str, mapping: dict[str, str] | None = None, **more: Any
) -> dict[str, Any]:
    return {
        "id": sid,
        "owner": "discovery",
        "path": path,
        "format": fmt,
        "sha256": None,
        "mapping": mapping or {},
        **more,
    }


def manifest(tmp_path: Path, sources: Any, **outer: Any) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "sources": sources} | outer))
    return path


def one(tmp_path: Path, raw: bytes, fmt: str, mapping: dict[str, str] | None = None, **more: Any):
    """A manifest of one source named ``input``."""
    (tmp_path / "input").write_bytes(raw)
    return manifest(tmp_path, [source("input", "input", fmt, mapping, **more)])


def complete_sources(tmp_path: Path) -> list[dict[str, Any]]:
    (tmp_path / "job.plist").write_bytes(job())
    (tmp_path / "settings.env").write_bytes(settings())
    (tmp_path / "types.list").write_bytes(TYPES)
    (tmp_path / "catalogue.json").write_bytes(CATALOGUE)
    return [
        source(
            "job",
            "job.plist",
            "plist",
            {"/Label": "/names/bonjour_label"},
            composed={
                "/ProgramArguments/0": [
                    {"pointer": "/names/state_directory"},
                    {"text": "/bin/discover"},
                ]
            },
            constants=["/ProgramArguments/1", "/RunAtLoad", "/ThrottleInterval"],
        ),
        source(
            "settings",
            "settings.env",
            "literal-env",
            {
                "/EXAMPLE_TARGET_ADDRESS": "/host/lan/ipv4",
                "/EXAMPLE_SCAN_SECONDS": "/supervision/discovery_seconds",
                "/EXAMPLE_MISS_LIMIT": "/supervision/discovery_misses",
            },
            constants=["/EXAMPLE_SOURCE_LINK"],
        ),
        source(
            "types",
            "types.list",
            "text-list",
            translated={
                "/items/0": {
                    "pointer": "/discovery/example-export/profile",
                    "values": {"published-tcp-export": "auto-tcp"},
                }
            },
            constants=["/items/1"],
        ),
        source(
            "catalogue",
            "catalogue.json",
            "json",
            {
                "/web/names/0": "/workloads/example-web/name",
                "/web/http/0": "/transport/example-publication/ports/first",
            },
            constants=["/web/note", "/enabled"],
        ),
    ]


def reasons(result: render.RenderResult) -> list[tuple[str, str | None]]:
    return [(issue.reason, issue.selector) for issue in result.issues]


# ---- rendering is the inverse of the import mapping over the captured file


def test_every_literal_format_is_reproduced_byte_for_byte(tmp_path: Path) -> None:
    collected: dict[str, bytes] = {}
    path = manifest(tmp_path, complete_sources(tmp_path))
    result = render_sources(path, instance(), collect=collected)
    assert result.issues == ()
    assert collected == {
        "job": job(),
        "settings": settings(),
        "types": TYPES,
        "catalogue": CATALOGUE,
    }
    assert all(item.identical and item.complete for item in result.sources)
    counted = {
        item.id: (item.leaves, item.mapped, item.composed, item.translated, item.constants)
        for item in result.sources
    }
    assert counted == {
        "job": (5, 1, 1, 0, 3),
        "settings": (4, 3, 0, 0, 1),
        "types": (2, 0, 0, 1, 1),
        "catalogue": (4, 2, 0, 0, 2),
    }
    assert [item.id for item in result.comparisons("discovery")] == [
        "job",
        "settings",
        "types",
        "catalogue",
    ]
    assert result.comparisons("other") == ()
    assert result.pointers("discovery") == {
        "/names/bonjour_label",
        "/names/state_directory",
        "/host/lan/ipv4",
        "/supervision/discovery_seconds",
        "/supervision/discovery_misses",
        "/discovery/example-export/profile",
        "/workloads/example-web/name",
        "/transport/example-publication/ports/first",
    }


def test_a_changed_instance_value_changes_exactly_its_literal(tmp_path: Path) -> None:
    def mutate(data: dict[str, Any]) -> None:
        data["supervision"]["discovery_seconds"] = 45
        data["names"]["bonjour_label"] = "example.site.finder"
        data["names"]["state_directory"] = "/example/State & <Data"
        data["workloads"][0]["name"] = "example-renamed"
        data["host"]["lan"].update(ipv4="198.51.100.77")

    collected: dict[str, bytes] = {}
    path = manifest(tmp_path, complete_sources(tmp_path))
    result = render_sources(path, changed(mutate), collect=collected)
    assert result.issues == ()
    assert collected["settings"] == (
        settings().replace(b'"20"', b'"45"').replace(b"198.51.100.10", b"198.51.100.77")
    )
    assert collected["job"] == (
        job()
        .replace(names()["bonjour_label"].encode(), b"example.site.finder")
        .replace(names()["state_directory"].encode(), b"/example/State &amp; &lt;Data")
    )
    assert collected["catalogue"] == CATALOGUE.replace(b"example-web", b"example-renamed")
    assert collected["types"] == TYPES
    assert [item.identical for item in result.sources] == [False, False, True, False]
    # A rendered file is read back by the importer as exactly the instance's values.
    assert _decode(collected["job"], "plist")["ProgramArguments"][0] == (
        "/example/State & <Data/bin/discover"
    )


def test_result_is_bound_to_the_manifest_and_the_instance_by_their_hashes(tmp_path: Path) -> None:
    path = manifest(tmp_path, complete_sources(tmp_path))
    result = render_sources(path, instance())
    document = result.to_dict()
    assert document["schema_version"] == 1
    assert document["manifest_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert document["instance_digest"] == instance_digest(instance())
    assert document["sources"][0]["captured_sha256"] == hashlib.sha256(job()).hexdigest()
    assert document["consumed"] == [
        {
            "owner": "discovery",
            "pointers": 8,
            "sha256": hashlib.sha256(
                canonical_bytes(sorted(result.pointers("discovery")))
            ).hexdigest(),
        }
    ]
    canonical_bytes(document)  # Plain bounded data, fit for a report.
    path.write_text(path.read_text() + "\n")
    assert render_sources(path, instance()).manifest_sha256 != result.manifest_sha256
    renamed = changed(lambda data: data["workloads"][0].update(name="example-renamed"))
    assert render_sources(path, renamed).instance_digest != result.instance_digest


def test_resolved_names_are_what_owners_are_rendered_from(tmp_path: Path) -> None:
    # A derived default is rendered like a pin.
    assert instance().names.bonjour_label is None
    assert settings_view(instance())["names"] == names()
    pinned = changed(lambda data: data["names"].update(bonjour_label="example.pinned.finder"))
    raw = b'{"label": "' + names()["bonjour_label"].encode() + b'"}\n'
    path = one(tmp_path, raw, "json", {"/label": "/names/bonjour_label"})
    assert [item.identical for item in render_sources(path, instance()).sources] == [True]
    collected: dict[str, bytes] = {}
    render_sources(path, pinned, collect=collected)
    assert collected["input"] == b'{"label": "example.pinned.finder"}\n'
    assert set(names().values()) <= set(setting_literals(instance()))


# ---- completeness: identical bytes mean something only when every leaf is accounted for


def test_every_leaf_is_mapped_or_named_a_constant(tmp_path: Path) -> None:
    sources = complete_sources(tmp_path)
    sources[1]["constants"] = []
    result = render_sources(manifest(tmp_path, sources), instance())
    found = next(item for item in result.sources if item.id == "settings")
    assert found.identical and found.unclassified == 1 and not found.complete
    assert found.to_dict()["complete"] is False


def test_unclassified_leaf_yields_no_parity_evidence_although_bytes_are_identical(
    tmp_path: Path,
) -> None:
    sources = complete_sources(tmp_path)
    sources[1]["constants"] = []
    collected: dict[str, bytes] = {}
    result = render_sources(manifest(tmp_path, sources), instance(), collect=collected)
    found = next(item for item in result.sources if item.id == "settings")
    assert (found.identical, found.unclassified, found.complete) == (True, 1, False)
    assert "settings" not in {item.id for item in result.comparisons("discovery")}
    # Only a complete source is handed out, and only it counts as consuming a value.
    assert sorted(collected) == ["catalogue", "job", "types"]
    assert "/host/lan/ipv4" not in result.pointers("discovery")


def test_source_that_maps_nothing_reproduces_itself_and_proves_nothing(tmp_path: Path) -> None:
    path = one(tmp_path, CATALOGUE, "json")
    found = render_sources(path, instance()).sources[0]
    assert (found.identical, found.leaves, found.unclassified, found.complete) == (
        True,
        4,
        4,
        False,
    )
    empty = one(tmp_path, b"{}\n", "json")
    assert [item.complete for item in render_sources(empty, instance()).sources] == [True]


def test_a_constant_that_holds_an_instance_setting_is_a_second_author(tmp_path: Path) -> None:
    sources = complete_sources(tmp_path)
    # The label and the program path stay frozen in the template instead of being rendered.
    sources[0]["mapping"], sources[0]["composed"] = {}, {}
    sources[0]["constants"] += ["/Label", "/ProgramArguments/0"]
    result = render_sources(manifest(tmp_path, sources), instance())
    found = next(item for item in result.sources if item.id == "job")
    assert found.identical and found.duplicate_constants == 2 and not found.complete
    assert "job" not in {item.id for item in result.comparisons("discovery")}


@pytest.mark.parametrize(
    "value,duplicate",
    [
        ("198.51.100.10", True),
        ("udp://198.51.100.10:5353", True),
        ("198.51.100.0/24", True),
        ("example-web", True),
        ("example-web.internal", True),
        ("x-example-web", True),
        ("example-webs", False),
        ("nexample-web", False),
        ("/example", True),
        ("/example/Library/Caches", True),
        ("data/example", False),
        ("/example2", False),
        ("example-network", True),
        ("EXAMPLE-NETWORK", False),
        ("exam", False),
    ],
)
def test_constant_repeats_a_setting_as_a_whole_value_or_as_a_delimited_token(
    tmp_path: Path, value: str, duplicate: bool
) -> None:
    path = one(tmp_path, json.dumps({"a": value}).encode(), "json", constants=["/a"])
    found = render_sources(path, instance()).sources[0]
    assert (found.duplicate_constants, found.complete) == (int(duplicate), not duplicate)


def test_setting_that_ends_in_a_delimiter_is_found_before_what_it_prefixes(tmp_path: Path) -> None:
    prefix = names()["bonjour_prefix"]
    assert prefix.endswith("-")
    path = one(tmp_path, json.dumps({"a": prefix + "web"}).encode(), "json", constants=["/a"])
    assert render_sources(path, instance()).sources[0].duplicate_constants == 1


def test_coincidence_is_waived_only_by_an_explicit_and_necessary_statement(tmp_path: Path) -> None:
    coincidence = b'{"image": "example.invalid/example-web-tools", "other": "plain"}\n'
    plain = {"constants": ["/image", "/other"]}
    blocked = render_sources(one(tmp_path, coincidence, "json", **plain), instance()).sources[0]
    assert (blocked.duplicate_constants, blocked.independent, blocked.complete) == (1, 0, False)
    stated = dict(plain, independent=["/image"])
    waived = render_sources(one(tmp_path, coincidence, "json", **stated), instance()).sources[0]
    assert (waived.duplicate_constants, waived.independent, waived.complete) == (0, 1, True)
    assert waived.constants == 2
    # A statement for a leaf that repeats nothing would hide a later real duplicate.
    needless = b'{"image": "example.invalid/other-tools", "other": "plain"}\n'
    result = render_sources(one(tmp_path, needless, "json", **stated), instance())
    assert reasons(result) == [("independent-without-duplicate", "/image")]
    assert result.sources == ()


@pytest.mark.parametrize(
    "more",
    [
        {"constants": ["/other"], "independent": ["/image"]},
        {"constants": ["/image", "/other"], "independent": ["/missing"]},
        {"constants": ["/other"], "mapping": {"/image": "/names/bonjour_label"}},
    ],
    ids=["not-a-constant", "no-such-leaf", "a-mapped-leaf"],
)
def test_independent_statement_names_exactly_one_constant_leaf(
    tmp_path: Path, more: dict[str, Any]
) -> None:
    raw = json.dumps({"image": names()["bonjour_label"], "other": "plain"}).encode()
    more = dict(more, independent=more.get("independent", ["/image"]))
    result = render_sources(one(tmp_path, raw, "json", **more), instance())
    assert ("independent-without-duplicate", more["independent"][0]) in reasons(result)
    assert result.sources == ()


def test_number_that_equals_an_instance_number_is_reported_for_review(tmp_path: Path) -> None:
    sources = complete_sources(tmp_path)
    del sources[3]["mapping"]["/web/http/0"]
    sources[3]["constants"].append("/web/http/0")
    result = render_sources(manifest(tmp_path, sources), instance())
    catalogue = next(item for item in result.sources if item.id == "catalogue")
    assert catalogue.integer_coincidences == 1 and catalogue.complete
    text = one(tmp_path, b"A=27777\nB='27778'\n", "literal-env", constants=["/A", "/B"])
    assert render_sources(text, instance()).sources[0].integer_coincidences == 1


def test_single_word_setting_is_matched_as_a_whole_literal_but_not_searched_in_programs(
    tmp_path: Path,
) -> None:
    plain = changed(lambda data: data["host"]["runtime"].update(network="default"))
    (tmp_path / "catalogue.json").write_bytes(b'{"names": ["default"], "note": "the default"}\n')
    (tmp_path / "run.sh").write_bytes(b"#!/bin/sh\n# the default program\nexec /usr/bin/true\n")
    entries = [
        source("catalogue", "catalogue.json", "json", constants=["/names", "/note"]),
        source("program", "run.sh", "source-inventory"),
    ]
    result = render_sources(manifest(tmp_path, entries), plain)
    assert [(i.constants, i.duplicate_constants) for i in result.sources] == [(2, 1)]
    assert [(i.scanned, i.embedded_literals) for i in result.inventory] == [(True, 0)]


# ---- compositions and translations


def test_composition_of_one_pointer_is_the_instance_value_itself(tmp_path: Path) -> None:
    # A second place for a value that the import takes from elsewhere.
    raw = b'{"port": 27777, "text": "27777", "api": true, "name": "example-web"}\n'
    composed = {
        "/port": [{"pointer": "/transport/example-publication/ports/first"}],
        "/api": [{"pointer": "/lifecycle_tools/example-cli/container_api_access"}],
        "/name": [{"pointer": "/workloads/example-web/name"}],
    }
    mapping = {"/text": "/transport/example-publication/ports/first"}
    path = one(tmp_path, raw, "json", mapping, composed=composed)
    found = render_sources(path, instance()).sources[0]
    assert (found.identical, found.mapped, found.composed, found.complete) == (True, 1, 3, True)

    def mutate(data: dict[str, Any]) -> None:
        data["transport"][0]["ports"].update(first=27778, last=27778)
        data["lifecycle_tools"][0]["container_api_access"] = False

    collected: dict[str, bytes] = {}
    render_sources(path, changed(mutate), collect=collected)
    assert collected["input"] == (
        b'{"port": 27778, "text": "27778", "api": false, "name": "example-web"}\n'
    )


def test_composed_leaf_joins_fixed_text_and_instance_values(tmp_path: Path) -> None:
    home = instance().host.account.home
    raw = ("SOCKET=" + home + ":27777/udp\n").encode()
    parts = [
        {"pointer": "/host/account/home"},
        {"text": ":"},
        {"pointer": "/transport/example-publication/ports/first"},
        {"text": "/udp"},
    ]
    path = one(tmp_path, raw, "literal-env", composed={"/SOCKET": parts})
    found = render_sources(path, instance()).sources[0]
    assert (found.identical, found.composed, found.complete) == (True, 1, True)
    moved = changed(lambda data: data["host"]["account"].update(home="/example/other"))
    collected: dict[str, bytes] = {}
    render_sources(path, moved, collect=collected)
    assert collected["input"] == b"SOCKET=/example/other:27777/udp\n"


def test_literal_part_of_a_composed_leaf_cannot_repeat_a_setting(tmp_path: Path) -> None:
    sources = complete_sources(tmp_path)
    tail = names()["state_directory"].removeprefix(instance().host.account.home)
    sources[0]["composed"]["/ProgramArguments/0"] = [
        {"pointer": "/host/account/home"},
        {"text": tail + "/bin/discover"},
    ]
    result = render_sources(manifest(tmp_path, sources), instance())
    assert reasons(result) == [("fixed-text-repeats-setting", "/ProgramArguments/0")]
    assert "job" not in {item.id for item in result.sources}
    # The other sources of the manifest are still rendered.
    assert len(result.sources) == 3


def test_owner_spelling_of_a_translation_cannot_repeat_a_setting(tmp_path: Path) -> None:
    table = {
        "pointer": "/host/lan/link",
        "values": {"wired": "example-web", "wifi": "radio"},
    }
    path = one(tmp_path, b"radio\n", "text-list", translated={"/items/0": table})
    assert reasons(render_sources(path, instance())) == [("fixed-text-repeats-setting", "/items/0")]


def test_translated_leaf_is_the_owners_word_for_an_instance_value(tmp_path: Path) -> None:
    raw = (
        PLIST_HEAD + b"<dict><key>Link</key><string>cable</string>"
        b"<key>Wired</key><true/><key>Rank</key><integer>1</integer></dict></plist>\n"
    )
    pointer = "/host/lan/link"
    translated = {
        "/Link": {"pointer": pointer, "values": {"wired": "cable", "wifi": "radio"}},
        "/Wired": {"pointer": pointer, "values": {"wired": "true", "wifi": "false"}},
        "/Rank": {"pointer": pointer, "values": {"wired": "1", "wifi": "2"}},
    }
    path = one(tmp_path, raw, "plist", translated=translated)
    found = render_sources(path, instance()).sources[0]
    assert (found.identical, found.translated, found.complete) == (True, 3, True)
    collected: dict[str, bytes] = {}
    render_sources(path, changed(lambda d: d["host"]["lan"].update(link="wifi")), collect=collected)
    assert collected["input"] == (
        raw.replace(b"cable", b"radio")
        .replace(b"<true/>", b"<false/>")
        .replace(b"<integer>1<", b"<integer>2<")
    )


def test_translation_spells_numbers_and_booleans_of_the_instance(tmp_path: Path) -> None:
    translated = {
        "/SCAN": {
            "pointer": "/supervision/discovery_seconds",
            "values": {"20": "fast", "45": "slow"},
        },
        "/API": {
            "pointer": "/lifecycle_tools/example-cli/container_api_access",
            "values": {"true": "yes", "false": "no"},
        },
    }
    path = one(tmp_path, b"SCAN=fast\nAPI=yes\n", "literal-env", translated=translated)
    assert [item.identical for item in render_sources(path, instance()).sources] == [True]


def test_instance_value_outside_the_translation_table_is_refused(tmp_path: Path) -> None:
    sources = complete_sources(tmp_path)
    sources[2]["translated"]["/items/0"]["values"] = {"homekit-export": "auto-tcp"}
    result = render_sources(manifest(tmp_path, sources), instance())
    assert [(i.source, i.reason) for i in result.issues] == [("types", "value-not-in-translation")]
    assert "types" not in {item.id for item in result.sources}


# ---- what the renderer refuses for one leaf


def hardware(value: str) -> Instance:
    return changed(lambda data: data["host"]["lan"].update(hardware_id=value))


NAME = "/workloads/example-web/name"
SECONDS = "/supervision/discovery_seconds"
HARDWARE = "/host/lan/hardware_id"
API = "/lifecycle_tools/example-cli/container_api_access"
LEAF_REFUSALS: list[tuple[str, bytes, str, dict[str, Any], str]] = [
    ("escaped-solidus", b'{"a": "x\\/y"}', "json", {"mapping": {"/a": NAME}}, "literal-style"),
    ("upper-hex", b'{"a": "caf\\u00E9"}', "json", {"mapping": {"/a": NAME}}, "literal-style"),
    ("negative-zero", b'{"a": -0}', "json", {"mapping": {"/a": SECONDS}}, "literal-style"),
    ("padded-number", b"A=020\n", "literal-env", {"mapping": {"/A": SECONDS}}, "literal-style"),
    ("word-number", b"A=auto\n", "literal-env", {"mapping": {"/A": SECONDS}}, "literal-style"),
    (
        "hex-integer",
        PLIST_HEAD + b"<dict><key>a</key><integer>0x14</integer></dict></plist>",
        "plist",
        {"mapping": {"/a": SECONDS}},
        "literal-style",
    ),
    (
        "entity",
        PLIST_HEAD + b"<dict><key>a</key><string>example&#45;web</string></dict></plist>",
        "plist",
        {"mapping": {"/a": NAME}},
        "literal-style",
    ),
    (
        "empty-string-element",
        PLIST_HEAD + b"<dict><key>a</key><string/></dict></plist>",
        "plist",
        {"mapping": {"/a": NAME}},
        "literal-style",
    ),
    (
        "boolean-with-end-tag",
        PLIST_HEAD + b"<dict><key>a</key><true></true></dict></plist>",
        "plist",
        {"mapping": {"/a": API}},
        "literal-style",
    ),
    (
        "boolean-with-space",
        PLIST_HEAD + b"<dict><key>a</key><true /></dict></plist>",
        "plist",
        {"mapping": {"/a": API}},
        "literal-style",
    ),
    (
        "line-break-in-text",
        PLIST_HEAD + b"<dict><key>a</key><string>two\nlines</string></dict></plist>",
        "plist",
        {"mapping": {"/a": NAME}},
        "literal-style",
    ),
    (
        "tab-in-quotes",
        b"A='two\twords'\n",
        "literal-env",
        {"mapping": {"/A": NAME}},
        "literal-style",
    ),
    ("float", b'{"a": 20.0}', "json", {"mapping": {"/a": SECONDS}}, "non-scalar"),
    ("exponent", b'{"a": 2E1}', "json", {"mapping": {"/a": SECONDS}}, "non-scalar"),
    ("null", b'{"a": null}', "json", {"mapping": {"/a": SECONDS}}, "non-scalar"),
    ("container", b'{"a": [20]}', "json", {"mapping": {"/a": SECONDS}}, "non-scalar"),
    ("empty-container", b'{"a": {}}', "json", {"mapping": {"/a": SECONDS}}, "non-scalar"),
    (
        "real",
        PLIST_HEAD + b"<dict><key>a</key><real>20</real></dict></plist>",
        "plist",
        {"mapping": {"/a": SECONDS}},
        "non-scalar",
    ),
    ("instance-container", b'{"a": "x"}', "json", {"mapping": {"/a": "/host/lan"}}, "non-scalar"),
    (
        "instance-list",
        b'{"a": "x"}',
        "json",
        {"mapping": {"/a": "/transport/example-publication/dependencies"}},
        "non-scalar",
    ),
    ("no-such-leaf", b'{"a": "x"}', "json", {"mapping": {"/b": NAME}}, "mapped-value"),
    ("no-such-index", b'{"a": ["x"]}', "json", {"mapping": {"/a/1": NAME}}, "mapped-value"),
    ("no-such-key", b"A=x\n", "literal-env", {"mapping": {"/B": NAME}}, "mapped-value"),
    ("no-such-item", b"x\n", "text-list", {"mapping": {"/items/1": NAME}}, "mapped-value"),
    ("no-such-name", b'{"a": "x"}', "json", {"mapping": {"/a": "/names/missing"}}, "instance"),
    (
        "null-in-instance",
        b'{"a": true}',
        "json",
        {"mapping": {"/a": "/host/baseline/filevault"}},
        "instance",
    ),
    ("position", b'{"a": "x"}', "json", {"mapping": {"/a": "/workloads/0/name"}}, "instance"),
    ("unknown-member", b'{"a": "x"}', "json", {"mapping": {"/a": "/workloads/z/name"}}, "instance"),
    (
        "beyond-a-list",
        b'{"a": "x"}',
        "json",
        {"mapping": {"/a": "/discovery/example-export/dependencies/1"}},
        "instance",
    ),
    (
        "below-a-scalar",
        b'{"a": "x"}',
        "json",
        {"mapping": {"/a": "/namespace/part"}},
        "instance",
    ),
    ("text-into-number", b'{"a": 20}', "json", {"mapping": {"/a": NAME}}, "type-mismatch"),
    ("text-into-boolean", b'{"a": true}', "json", {"mapping": {"/a": NAME}}, "type-mismatch"),
    ("number-into-boolean", b'{"a": true}', "json", {"mapping": {"/a": SECONDS}}, "type-mismatch"),
    ("boolean-into-text", b'{"a": "true"}', "json", {"mapping": {"/a": API}}, "type-mismatch"),
    ("boolean-into-number", b'{"a": 1}', "json", {"mapping": {"/a": API}}, "type-mismatch"),
    ("boolean-into-assignment", b"A=true\n", "literal-env", {"mapping": {"/A": API}}, "type-mis"),
    (
        "text-into-integer-element",
        PLIST_HEAD + b"<dict><key>a</key><integer>20</integer></dict></plist>",
        "plist",
        {"mapping": {"/a": NAME}},
        "type-mismatch",
    ),
    (
        "boolean-in-a-composition",
        b'{"a": "x-true"}',
        "json",
        {"composed": {"/a": [{"text": "x-"}, {"pointer": API}]}},
        "type-mismatch",
    ),
    (
        "spelling-is-no-number",
        b'{"a": 1}',
        "json",
        {"translated": {"/a": {"pointer": "/host/lan/link", "values": {"wired": "one"}}}},
        "type-mismatch",
    ),
    ("space-in-bare", b"A=x\n", "literal-env", {"mapping": {"/A": HARDWARE}}, "representable"),
    ("quote-in-double", b'A="x"\n', "literal-env", {"mapping": {"/A": HARDWARE}}, "representable"),
    ("quote-in-single", b"A='x'\n", "literal-env", {"mapping": {"/A": HARDWARE}}, "representable"),
    ("space-in-item", b"x\n", "text-list", {"mapping": {"/items/0": HARDWARE}}, "representable"),
    (
        "both-tables",
        b'{"a": "example-web"}',
        "json",
        {"mapping": {"/a": NAME}, "composed": {"/a": [{"pointer": NAME}]}},
        "duplicate-selector",
    ),
    (
        "constant-above-a-mapping",
        b'{"a": {"b": "example-web", "c": 1}}',
        "json",
        {"mapping": {"/a/b": NAME}, "constants": ["/a"]},
        "constant-overlaps",
    ),
    (
        "constant-is-the-mapping",
        b'{"a": "example-web"}',
        "json",
        {"mapping": {"/a": NAME}, "constants": ["/a"]},
        "constant-overlaps",
    ),
    ("no-such-constant", b'{"a": "x"}', "json", {"constants": ["/a", "/b"]}, "mapped-value"),
]


@pytest.mark.parametrize(
    "raw,fmt,more,reason",
    [case[1:] for case in LEAF_REFUSALS],
    ids=[case[0] for case in LEAF_REFUSALS],
)
def test_unreproducible_or_unsafe_mappings_are_refused(
    tmp_path: Path, raw: bytes, fmt: str, more: dict[str, Any], reason: str
) -> None:
    subject = hardware(f'two words "and" {MARKER}\'s')
    collected: dict[str, bytes] = {}
    result = render_sources(one(tmp_path, raw, fmt, **more), subject, collect=collected)
    assert len(result.issues) == 1 and reason in result.issues[0].reason
    assert result.issues[0].source == "input" and result.issues[0].selector is not None
    assert result.sources == () and collected == {}
    assert MARKER not in json.dumps(result.to_dict())


def test_value_is_written_only_in_the_spelling_that_reproduces_the_capture(tmp_path: Path) -> None:
    raw = b'{"plain": "x", "escaped": "caf\\u00e9", "raw": "caf\xc3\xa9"}\n'
    selectors = {"plain": "/plain", "escaped": "/escaped", "raw": "/raw"}

    def render_one(key: str, value: str) -> render.RenderResult:
        collected.clear()
        path = one(tmp_path, raw, "json", {selectors[key]: HARDWARE}, constants=other(key))
        return render_sources(path, hardware(value), collect=collected)

    def other(key: str) -> list[str]:
        return [selector for name, selector in selectors.items() if name != key]

    collected: dict[str, bytes] = {}
    assert render_one("escaped", 'naïve "x" \\ \U0001f600').issues == ()
    assert collected["input"] == raw.replace(
        b'"caf\\u00e9"', b'"na\\u00efve \\"x\\" \\\\ \\ud83d\\ude00"'
    )
    assert render_one("raw", 'naïve "x" \\').issues == ()
    assert collected["input"] == raw.replace(b'"caf\xc3\xa9"', b'"na\xc3\xafve \\"x\\" \\\\"')
    assert render_one("plain", "ascii only").issues == ()
    assert collected["input"] == raw.replace(b'"x"', b'"ascii only"')
    # The capture does not say how this file escapes; nothing is guessed.
    assert reasons(render_one("plain", "naïve")) == [("literal-style-unsupported", "/plain")]


def test_escaped_quote_and_backslash_do_not_end_a_json_string(tmp_path: Path) -> None:
    raw = b'{"a\\"b": "say \\"x\\" \\\\", "c": "example-web", "d": "\\\\"}\n'
    assert json.loads(raw) == {'a"b': 'say "x" \\', "c": "example-web", "d": "\\"}
    path = one(tmp_path, raw, "json", {"/c": NAME}, constants=['/a"b', "/d"])
    assert [item.identical for item in render_sources(path, instance()).sources] == [True]
    renamed = changed(lambda data: data["workloads"][0].update(name="example-renamed"))
    collected: dict[str, bytes] = {}
    assert render_sources(path, renamed, collect=collected).issues == ()
    assert collected["input"] == raw.replace(b"example-web", b"example-renamed")


def test_property_list_text_in_a_form_the_renderer_cannot_write_is_refused(tmp_path: Path) -> None:
    label = names()["bonjour_label"].encode()
    raw = job().replace(
        b"<string>" + label + b"</string>", b"<string><![CDATA[" + label + b"]]></string>"
    )
    path = one(tmp_path, raw, "plist", {"/Label": "/names/bonjour_label"})
    assert reasons(render_sources(path, instance())) == [("literal-style-unsupported", "/Label")]
    commented = job().replace(label, label[:3] + b"<!-- note -->" + label[3:])
    path = one(tmp_path, commented, "plist", {"/Label": "/names/bonjour_label"})
    assert reasons(render_sources(path, instance())) == [("literal-style-unsupported", "/Label")]


def test_property_list_text_escapes_what_the_capture_escapes(tmp_path: Path) -> None:
    def document(text: bytes) -> bytes:
        return PLIST_HEAD + b"<dict><key>a</key><string>" + text + b"</string></dict></plist>\n"

    def render_one(text: bytes, value: str) -> tuple[list[tuple[str, str | None]], bytes | None]:
        collected: dict[str, bytes] = {}
        path = one(tmp_path, document(text), "plist", {"/a": HARDWARE})
        result = render_sources(path, hardware(value), collect=collected)
        return reasons(result), collected.get("input")

    assert render_one(b"a &amp; b &lt; c", "x & y < z") == ([], document(b"x &amp; y &lt; z"))
    assert render_one(b"a &gt; b", "x > y & z") == ([], document(b"x &gt; y &amp; z"))
    assert render_one(b"a > b", "x > y") == ([], document(b"x > y"))
    assert render_one(b"plain", "café 'q' \"d\"") == (
        [],
        document("café 'q' \"d\"".encode()),
    )
    # Whether this file escapes ">" is not established by a capture that holds none.
    assert render_one(b"plain", "x > y")[0] == [("literal-style-unsupported", "/a")]


def test_assignment_and_list_values_keep_their_quoting(tmp_path: Path) -> None:
    raw = b"  A=bare-1  \n\tB=\"two words\"\t\nC='it is'\n"
    mapping = {"/A": "/workloads/example-web/name", "/B": HARDWARE}
    path = one(tmp_path, raw, "literal-env", mapping, composed={"/C": [{"pointer": HARDWARE}]})

    def mutate(data: dict[str, Any]) -> None:
        data["workloads"][0]["name"] = "example-renamed"
        data["host"]["lan"]["hardware_id"] = "it's é = #1"

    collected: dict[str, bytes] = {}
    result = render_sources(path, changed(mutate), collect=collected)
    # The single-quoted place cannot hold the apostrophe; nothing of the file is handed out.
    assert reasons(result) == [("value-not-representable", "/C")] and collected == {}
    path = one(tmp_path, raw, "literal-env", mapping, constants=["/C"])
    assert render_sources(path, changed(mutate), collect=collected).issues == ()
    assert collected["input"] == (
        b"  A=example-renamed  \n\tB=\"it's \xc3\xa9 = #1\"\t\nC='it is'\n"
    )


@pytest.mark.parametrize("value", ["a$b", "a`b", "a\\b"])
@pytest.mark.parametrize("quote", ['"', "'"])
def test_quoted_assignment_never_receives_an_expansion_character(
    tmp_path: Path, value: str, quote: str
) -> None:
    # The closed instance refuses "$(" and a backquote itself; a lone "$" or "\" is data there.
    raw = f"A={quote}x{quote}\n".encode()
    path = one(tmp_path, raw, "literal-env", {"/A": HARDWARE})
    try:
        subject = hardware(value)
    except ValueError:
        return
    assert reasons(render_sources(path, subject)) == [("value-not-representable", "/A")]


def test_owner_input_that_carries_a_guest_or_receiver_address_is_refused(tmp_path: Path) -> None:
    lan = instance().host.lan.ipv4.encode()
    raw = b"HOST=" + lan + b"\nLAST_TARGET=192.0.2.44\n"
    mapping = {"/HOST": "/host/lan/ipv4"}
    path = one(tmp_path, raw, "literal-env", mapping, constants=["/LAST_TARGET"])
    result = render_sources(path, instance())
    assert reasons(result) == [("live-address-in-owner-input", None)]
    assert result.sources == ()
    # Not classifying the leaf does not hide it.
    result = render_sources(one(tmp_path, raw, "literal-env", mapping), instance())
    assert reasons(result) == [("live-address-in-owner-input", None)]
    # The LAN's own address and prefix are settings: allowed here, but a second author.
    own = b"HOST=" + lan + b"\nALSO=" + lan + b":53\n"
    found = render_sources(
        one(tmp_path, own, "literal-env", mapping, constants=["/ALSO"]), instance()
    ).sources[0]
    assert (found.duplicate_constants, found.complete) == (1, False)


def test_address_rule_applies_to_what_is_rendered_not_to_a_replaced_literal(
    tmp_path: Path,
) -> None:
    lan = instance().host.lan.ipv4.encode()
    path = one(tmp_path, b"HOST=" + lan + b"\n", "literal-env", {"/HOST": "/host/lan/ipv4"})
    moved = changed(lambda data: data["host"]["lan"].update(ipv4="198.51.100.77"))
    collected: dict[str, bytes] = {}
    assert render_sources(path, moved, collect=collected).issues == ()
    assert collected["input"] == b"HOST=198.51.100.77\n"
    # Fixed manifest text is rendered too.
    for more in (
        {"composed": {"/HOST": [{"text": "192.0.2.44:"}, {"pointer": SECONDS}]}},
        {"translated": {"/HOST": {"pointer": "/host/lan/link", "values": {"wired": "192.0.2.44"}}}},
    ):
        result = render_sources(one(tmp_path, b"HOST=x\n", "literal-env", **more), instance())
        assert reasons(result) == [("live-address-in-owner-input", "/HOST")]


def test_credential_and_environment_keys_are_never_selected(tmp_path: Path) -> None:
    raw = b'{"apiToken": "x", "name": "y"}\n'
    for more in (
        {"constants": ["/apiToken"]},
        {"mapping": {"/apiToken": "/names/bonjour_label"}},
        {"mapping": {"/name": "/workloads/example-web/token"}},
        {"composed": {"/apiToken": [{"pointer": NAME}]}},
        {"composed": {"/name": [{"pointer": "/host/password"}]}},
        {"translated": {"/apiToken": {"pointer": NAME, "values": {"a": "b"}}}},
        {"translated": {"/name": {"pointer": "/host/env", "values": {"a": "b"}}}},
        {"independent": ["/apiToken"]},
    ):
        with pytest.raises(RenderError, match="Credential"):
            render_sources(one(tmp_path, raw, "json", **more), instance())


def test_environment_subtree_is_left_unexamined_only_when_the_manifest_says_so(
    tmp_path: Path,
) -> None:
    lan = instance().host.lan.ipv4.encode()
    raw = (
        PLIST_HEAD + b"<dict>\n<key>EnvironmentVariables</key><dict><key>EXAMPLE</key>"
        b"<string>" + lan + b" 192.0.2.44</string></dict>\n"
        b"<key>RunAtLoad</key><true/>\n</dict></plist>\n"
    )
    plain = {"constants": ["/RunAtLoad"]}
    silent = render_sources(one(tmp_path, raw, "plist", **plain), instance()).sources[0]
    assert (silent.unclassified, silent.unexamined, silent.complete) == (1, 0, False)
    stated = dict(plain, unexamined=["/EnvironmentVariables"])
    shown = render_sources(one(tmp_path, raw, "plist", **stated), instance()).sources[0]
    assert (shown.unclassified, shown.unexamined, shown.constants) == (0, 1, 1)
    assert shown.complete and shown.identical
    with pytest.raises(RenderError, match="unexamined"):
        render_sources(one(tmp_path, raw, "plist", unexamined=["/RunAtLoad"]), instance())
    missing = dict(plain, unexamined=["/EnvironmentVariables", "/Secret"])
    result = render_sources(one(tmp_path, raw, "plist", **missing), instance())
    assert reasons(result) == [("mapped-value-unavailable", "/Secret")]


def test_constant_subtree_never_covers_a_credential_or_environment_key(tmp_path: Path) -> None:
    raw = b'{"service": {"port": 4242, "password": "' + MARKER.encode() + b'"}}\n'
    covered = render_sources(one(tmp_path, raw, "json", constants=["/service"]), instance())
    assert [(i.constants, i.unclassified, i.complete) for i in covered.sources] == [(1, 1, False)]
    stated = {"constants": ["/service"], "unexamined": ["/service/password"]}
    shown = render_sources(one(tmp_path, raw, "json", **stated), instance()).sources[0]
    assert (shown.constants, shown.unexamined, shown.complete) == (1, 1, True)


# ---- sources that are not rendered


def test_format_without_a_renderer_is_reported_not_guessed(tmp_path: Path) -> None:
    raw = b'[dns]\ndomain = "example.internal"\n'
    for more in ({"mapping": {"/dns/domain": "/instance"}}, {"constants": ["/dns"]}):
        (tmp_path / "settings.toml").write_bytes(raw)
        entry = source("settings", "settings.toml", "toml", **more)
        result = render_sources(manifest(tmp_path, [entry]), instance())
        assert [(i.source, i.reason) for i in result.issues] == [
            ("settings", "format-not-renderable")
        ]
        assert result.sources == () and result.inventory == ()


def test_data_file_without_a_renderer_is_searched_when_it_supplies_nothing(tmp_path: Path) -> None:
    (tmp_path / "vendor.toml").write_bytes(b'[section]\nkey = "value"\n')
    path = manifest(tmp_path, [source("vendor", "vendor.toml", "toml")])
    result = render_sources(path, instance())
    assert [check.to_dict() for check in result.checks("discovery")] == [
        {
            "id": "vendor",
            "owner": "discovery",
            "sha256": hashlib.sha256(b'[section]\nkey = "value"\n').hexdigest(),
            "scanned": True,
            "embedded_literals": 0,
        }
    ]
    assert result.sources == () and result.checks("other") == ()
    (tmp_path / "vendor.toml").write_bytes(b'[section]\nkey = "example-web"\n')
    assert render_sources(path, instance()).inventory[0].embedded_literals == 1


@pytest.mark.parametrize(
    "program,scanned,found",
    [
        (b"#!/bin/sh\n# reads every setting from its literal files\nexec /usr/bin/true\n", True, 0),
        (b"#!/bin/sh\nNAME=example-web\nexec run --name example-web-2 example-webs\n", True, 2),
        (b"#!/bin/sh\nBIND=198.51.100.10:53 NET=198.51.100.0/24 OTHER=198.51.100.100\n", True, 2),
        (b"\xff\xfe\x00binary", False, 0),
        (b"text\x00example-web", False, 0),
        (b"e\x00x\x00a\x00m\x00p\x00l\x00e\x00", False, 0),
        (b"", True, 0),
    ],
    ids=["clean", "names", "addresses", "not-text", "nul", "wide-text", "empty"],
)
def test_program_is_pinned_and_searched_as_text_never_evaluated(
    tmp_path: Path, program: bytes, scanned: bool, found: int
) -> None:
    marker = tmp_path / "would-exist"
    program += f"\n# touch {marker}\n".encode() if scanned and program else b""
    (tmp_path / "program.sh").write_bytes(program)
    path = manifest(tmp_path, [source("program", "program.sh", "source-inventory")])
    result = render_sources(path, instance())
    assert result.inventory == (
        render.InventoryCheck(
            "program", "discovery", hashlib.sha256(program).hexdigest(), scanned, found
        ),
    )
    assert result.sources == () and result.issues == () and not marker.exists()


# ---- the capture, the manifest and the instance


def test_changed_capture_is_refused_by_its_pin(tmp_path: Path) -> None:
    sources = complete_sources(tmp_path)
    sources[1]["sha256"] = hashlib.sha256(settings()).hexdigest()
    path = manifest(tmp_path, sources)
    assert render_sources(path, instance()).issues == ()
    (tmp_path / "settings.env").write_bytes(settings() + b"# edited\n")
    collected: dict[str, bytes] = {}
    with pytest.raises(RenderError, match="digest changed"):
        render_sources(path, instance(), collect=collected)
    # The source before the changed one was rendered; a refused manifest hands out nothing.
    assert collected == {}


def test_instance_members_are_addressed_by_identifier_never_by_position(tmp_path: Path) -> None:
    sources = complete_sources(tmp_path)
    sources[3]["mapping"]["/web/names/0"] = "/workloads/0/name"
    result = render_sources(manifest(tmp_path, sources), instance())
    assert [(i.source, i.reason) for i in result.issues] == [
        ("catalogue", "instance-value-unavailable")
    ]

    # Inserting a member in front changes no rendered byte of an identifier-addressed leaf.
    def grow(data: dict[str, Any]) -> None:
        extra = json.loads(json.dumps(data["workloads"][0]))
        extra.update(id="example-added", name="example-added")
        data["workloads"].insert(0, extra)

    again = render_sources(manifest(tmp_path, complete_sources(tmp_path)), changed(grow))
    assert all(item.identical for item in again.sources) and not again.issues
    # A list whose members carry no identifier has only positions.
    raw = b'{"first": "example-publication"}\n'
    pointer = "/discovery/example-export/dependencies/0"
    path = one(tmp_path, raw, "json", {"/first": pointer})
    assert [item.identical for item in render_sources(path, instance()).sources] == [True]


def test_second_mapping_to_one_destination_is_refused_as_an_import_refuses_it(
    tmp_path: Path,
) -> None:
    (tmp_path / "one.json").write_bytes(b'{"name": "example-web"}\n')
    (tmp_path / "two.json").write_bytes(b'{"name": "example-web", "again": "example-web"}\n')
    entries = [
        source("one", "one.json", "json", {"/name": NAME}),
        source("two", "two.json", "json", {"/name": NAME}, constants=["/again"]),
    ]
    with pytest.raises(RenderError, match="more than one author"):
        render_sources(manifest(tmp_path, entries), instance())
    entries[1]["mapping"] = {"/name": NAME, "/again": NAME}
    del entries[0]
    with pytest.raises(RenderError, match="more than one author"):
        render_sources(manifest(tmp_path, entries), instance())
    # Further places are compositions of that one pointer.
    entries[0].pop("constants")
    entries[0].update(mapping={"/name": NAME}, composed={"/again": [{"pointer": NAME}]})
    found = render_sources(manifest(tmp_path, entries), instance()).sources[0]
    assert (found.identical, found.complete) == (True, True)


def test_assignment_keys_follow_the_importers_grammar(tmp_path: Path) -> None:
    # Whatever key the importer decodes is rendered; whatever it refuses is refused.
    raw = b"port=27777\n"
    mapping = {"/port": "/transport/example-publication/ports/first"}
    result = render_sources(one(tmp_path, raw, "literal-env", mapping), instance())
    try:
        _decode(raw, "literal-env")
    except ValueError:
        assert reasons(result) == [("unsupported-static-syntax", None)]
    else:
        assert [item.identical for item in result.sources] == [True]


UNREADABLE: list[tuple[bytes, str]] = [
    (b'{"a": ', "json"),
    (b'{"a": 1, "a": 2}', "json"),
    (b"\xff", "json"),
    (b'{"a": ' + b"[" * 34 + b"0" + b"]" * 34 + b"}", "json"),
    (b"bplist00junk", "plist"),
    (PLIST_HEAD + b"<dict><key>a</key><date>2000-01-01T00:00:00Z</date></dict></plist>", "plist"),
    (PLIST_HEAD + b"<dict><key>a</key></dict></plist>", "plist"),
    (b"A=$(hostname)\n", "literal-env"),
    (b"export A=1\n", "literal-env"),
    (b"A=1\r\n", "literal-env"),
    (b"one\none\n", "text-list"),
    (b"one two\n", "text-list"),
]


@pytest.mark.parametrize("raw,fmt", UNREADABLE)
def test_source_the_importer_cannot_read_is_not_rendered(
    tmp_path: Path, raw: bytes, fmt: str
) -> None:
    result = render_sources(one(tmp_path, raw, fmt, constants=["/a"]), instance())
    assert reasons(result) == [("unsupported-static-syntax", None)]
    assert result.sources == ()


def entry(**changes: Any) -> dict[str, Any]:
    return source("input", "input", "json", {"/a": NAME}) | changes


MALFORMED_ENTRIES: list[dict[str, Any]] = [
    {"extra": 1},
    {"id": "UPPER"},
    {"owner": None},
    {"path": ""},
    {"path": "bad\x00path"},
    {"path": 7},
    {"format": []},
    {"format": "shell"},
    {"sha256": "abcd"},
    {"sha256": 7},
    {"mapping": []},
    {"mapping": {"a": NAME}},
    {"mapping": {"/a": "/"}},
    {"mapping": {"/a": "/bad~1name"}},
    {"mapping": {"/a": "/bad//name"}},
    {"mapping": {"/a/00": NAME}},
    {"mapping": {"/a": 7}},
    {"mapping": {"/a": "/decisions/bounded"}},
    {"mapping": {"/a": "/acceptance/0/signed_by"}},
    {"mapping": {"/a": "/deviations/0/statement"}},
    {"mapping": {"/a": "/authoring/0/mode"}},
    {"mapping": {"/a": "/framework/version"}},
    {"composed": None},
    {"composed": []},
    {"composed": {"/b": None}},
    {"composed": {"/b": []}},
    {"composed": {"/b": [{"pointer": NAME}] * 17}},
    {"composed": {"/b": [{"text": "only text"}]}},
    {"composed": {"/b": [{"text": "one"}, {"text": "two"}, {"pointer": NAME}]}},
    {"composed": {"/b": [{"text": ""}, {"pointer": NAME}]}},
    {"composed": {"/b": [{"text": "line\nbreak"}, {"pointer": NAME}]}},
    {"composed": {"/b": [{"text": "x" * 4097}, {"pointer": NAME}]}},
    {"composed": {"/b": [{"text": 7}, {"pointer": NAME}]}},
    {"composed": {"/b": [{"pointer": NAME, "text": "both"}]}},
    {"composed": {"/b": [{"expression": "1 + 1"}]}},
    {"composed": {"/b": ["text"]}},
    {"composed": {"/b": [{"pointer": "/framework/version"}]}},
    {"composed": {"b": [{"pointer": NAME}]}},
    {"translated": None},
    {"translated": {"/b": None}},
    {"translated": {"/b": {"pointer": NAME}}},
    {"translated": {"/b": {"pointer": NAME, "values": {}}}},
    {"translated": {"/b": {"pointer": NAME, "values": []}}},
    {"translated": {"/b": {"pointer": NAME, "values": {"a": 1}}}},
    {"translated": {"/b": {"pointer": NAME, "values": {"a": "x", "b": "x"}}}},
    {"translated": {"/b": {"pointer": NAME, "values": {"a": "tab\there"}}}},
    {"translated": {"/b": {"pointer": NAME, "values": {"a": "x"}, "default": "y"}}},
    {"translated": {"/b": {"pointer": "/decisions/x", "values": {"a": "x"}}}},
    {
        "translated": {
            "/b": {"pointer": NAME, "values": {str(index): str(index) for index in range(65)}}
        }
    },
    {"constants": None},
    {"constants": {}},
    {"constants": ["/b", "/b"]},
    {"constants": [7]},
    {"constants": ["b"]},
    {"constants": [f"/k{index}" for index in range(1025)]},
    {"unexamined": None},
    {"unexamined": ["/b"]},
    {"unexamined": ["/token", "/token"]},
    {"unexamined": [f"/token/{index}" for index in range(65)]},
    {"independent": None},
    {"independent": ["/b", "/b"]},
    {"independent": [f"/k{index}" for index in range(17)]},
    {"format": "source-inventory"},
    {"format": "source-inventory", "mapping": {}, "constants": []},
    {"format": "source-inventory", "mapping": {}, "unexamined": []},
]


@pytest.mark.parametrize("changes", MALFORMED_ENTRIES)
def test_render_manifest_entry_is_closed(tmp_path: Path, changes: dict[str, Any]) -> None:
    (tmp_path / "input").write_bytes(b'{"a": "example-web", "b": "x"}\n')
    with pytest.raises(RenderError) as error:
        render_sources(manifest(tmp_path, [entry(**changes)]), instance())
    assert "example-web" not in str(error.value)


@pytest.mark.parametrize(
    "outer",
    [
        {"schema_version": 2},
        {"schema_version": True},
        {"extra": True},
        {"sources": []},
        {"sources": None},
        {"sources": [None]},
    ],
)
def test_render_manifest_shape_is_closed(tmp_path: Path, outer: dict[str, Any]) -> None:
    (tmp_path / "input").write_bytes(b'{"a": "example-web"}\n')
    with pytest.raises(RenderError):
        render_sources(manifest(tmp_path, outer.pop("sources", [entry()]), **outer), instance())


def test_unusable_manifest_capture_or_instance_is_one_closed_error(tmp_path: Path) -> None:
    (tmp_path / "input").write_bytes(b'{"a": "example-web"}\n')
    with pytest.raises(RenderError, match="unique"):
        render_sources(manifest(tmp_path, [entry(), entry()]), instance())
    with pytest.raises(RenderError, match="manifest"):
        render_sources(tmp_path / "absent.json", instance())
    broken = tmp_path / "broken.json"
    broken.write_text('{"schema_version": 1, "sources": [')
    with pytest.raises(RenderError, match="manifest"):
        render_sources(broken, instance())
    with pytest.raises(RenderError, match="unavailable"):
        render_sources(manifest(tmp_path, [entry(path="absent")]), instance())
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "input")
    with pytest.raises(RenderError, match="unavailable"):
        render_sources(manifest(tmp_path, [entry(path="link")]), instance())
    # A value that the closed model refuses is never written into an owner input.
    invalid = instance().__class__(
        **{
            name: getattr(instance(), name)
            for name in instance().__dataclass_fields__
            if name != "namespace"
        },
        namespace="$(hostname)",
    )
    with pytest.raises(RenderError, match="valid instance"):
        render_sources(manifest(tmp_path, [entry()]), invalid)


def test_absolute_capture_path_is_read_as_given(tmp_path: Path) -> None:
    capture = tmp_path / "elsewhere" / "input.json"
    capture.parent.mkdir()
    capture.write_bytes(b'{"a": "example-web"}\n')
    (tmp_path / "manifests").mkdir()
    path = manifest(tmp_path / "manifests", [entry(path=str(capture))])
    assert [item.identical for item in render_sources(path, instance()).sources] == [True]


# ---- the renderer is trusted only as far as the importer reads its output back


def test_rendering_that_the_importer_would_not_read_back_is_reported(tmp_path: Path) -> None:
    # Two items that become equal are no list the importer accepts.
    raw = b"example-web\nexample-media\n"
    mapping = {"/items/0": "/workloads/example-web/name"}
    path = one(tmp_path, raw, "text-list", mapping, constants=["/items/1"])
    assert [item.identical for item in render_sources(path, instance()).sources] == [True]
    renamed = changed(
        lambda data: (
            data["workloads"][0].update(name="example-media"),
            data["workloads"][1].update(name="example-other"),
        )
    )
    result = render_sources(path, renamed)
    assert reasons(result) == [("render-self-check-failed", None)] and result.sources == ()


def test_defective_span_scanner_cannot_produce_a_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = b'{"a": "example-web", "b": "example-web", "c": 1}\n'
    path = one(tmp_path, raw, "json", {"/a": NAME}, constants=["/b", "/c"])
    renamed = changed(lambda data: data["workloads"][0].update(name="example-renamed"))
    genuine = render._SPANS["json"]

    def swapped(data: bytes) -> dict[tuple[str, ...], Any]:
        spans = genuine(data)
        spans[("a",)], spans[("b",)] = spans[("b",)], spans[("a",)]
        return spans

    def lost(data: bytes) -> dict[tuple[str, ...], Any]:
        spans = genuine(data)
        del spans[("c",)]
        return spans

    def overlapping(data: bytes) -> dict[tuple[str, ...], Any]:
        spans = genuine(data)
        spans[("c",)] = spans[("b",)]
        return spans

    def failing(data: bytes) -> dict[tuple[str, ...], Any]:
        raise render.RenderError("scanner refused")

    for defect in (swapped, lost, overlapping, failing):
        monkeypatch.setitem(render._SPANS, "json", defect)
        collected: dict[str, bytes] = {}
        result = render_sources(path, renamed, collect=collected)
        assert reasons(result) == [("render-self-check-failed", None)], defect.__name__
        assert result.sources == () and collected == {}
    # The swapped spans are harmless while nothing changes, and the bytes say so.
    monkeypatch.setitem(render._SPANS, "json", swapped)
    assert [item.identical for item in render_sources(path, instance()).sources] == [True]


def test_text_in_another_declared_encoding_is_never_written_as_another_string(
    tmp_path: Path,
) -> None:
    raw = (
        b'<?xml version="1.0" encoding="ISO-8859-1"?>\n<plist version="1.0"><dict>'
        b"<key>a</key><string>plain</string><key>b</key><string>caf\xe9</string></dict></plist>\n"
    )
    assert _decode(raw, "plist") == {"a": "plain", "b": "café"}
    path = one(tmp_path, raw, "plist", {"/a": HARDWARE}, constants=["/b"])
    collected: dict[str, bytes] = {}
    assert render_sources(path, hardware("ascii"), collect=collected).issues == ()
    assert collected["input"] == raw.replace(b"plain", b"ascii")
    result = render_sources(path, hardware("café"), collect={})
    assert reasons(result) == [("render-self-check-failed", None)]
    mapped = one(tmp_path, raw, "plist", {"/b": HARDWARE}, constants=["/a"])
    assert reasons(render_sources(mapped, hardware("café"))) == [
        ("literal-style-unsupported", "/b")
    ]


# ---- diagnostics


def test_result_reports_hashes_and_counts_never_file_or_instance_values(tmp_path: Path) -> None:
    def mutate(data: dict[str, Any]) -> None:
        data["workloads"][0]["name"] = f"name-{MARKER}"
        data["names"]["state_directory"] = f"/example/state {MARKER}"
        data["host"]["lan"]["hardware_id"] = f"adapter {MARKER}"

    subject = changed(mutate)
    raw = json.dumps(
        {
            "name": f"old-{MARKER}",
            "path": f"/example/old {MARKER}/bin/tool",
            "note": f"constant {MARKER}",
            "copy": f"name-{MARKER}",
            "stray": f"unclassified {MARKER}",
            "link": f"word-{MARKER}",
            "bad": 1,
        }
    ).encode()
    more: dict[str, Any] = {
        "mapping": {"/name": NAME},
        "composed": {"/path": [{"pointer": "/names/state_directory"}, {"text": "/bin/tool"}]},
        "constants": ["/note", "/copy", "/bad"],
    }
    collected: dict[str, bytes] = {}
    result = render_sources(one(tmp_path, raw, "json", **more), subject, collect=collected)
    found = result.sources[0]
    assert (found.identical, found.duplicate_constants, found.unclassified) == (False, 1, 2)
    assert MARKER not in json.dumps(result.to_dict()) and collected == {}
    refused = dict(more, constants=["/note", "/copy", "/stray", "/link"])
    refused["mapping"] = {"/name": NAME, "/bad": HARDWARE}
    refused["translated"] = {
        "/link": {"pointer": HARDWARE, "values": {f"other {MARKER}": f"word-{MARKER}"}}
    }
    result = render_sources(one(tmp_path, raw, "json", **refused), subject)
    assert sorted(reasons(result)) == [
        ("constant-overlaps-mapping", "/link"),
        ("type-mismatch", "/bad"),
        ("value-not-in-translation", "/link"),
    ]
    assert MARKER not in json.dumps(result.to_dict())
    assert MARKER not in repr(result.issues) + repr(result.sources) + repr(result.inventory)
    smuggled = dict(more, composed={"/path": [{"pointer": NAME}, {"text": f"name-{MARKER}"}]})
    result = render_sources(one(tmp_path, raw, "json", **smuggled), subject)
    assert reasons(result) == [("fixed-text-repeats-setting", "/path")]
    assert MARKER not in json.dumps(result.to_dict())
    for broken in (
        dict(more, composed={"/path": [{"text": f"only {MARKER}"}]}),
        dict(more, translated={"/link": {"pointer": NAME, "values": {"a": f"\t{MARKER}"}}}),
        dict(more, mapping={"/name": f"/decisions/{MARKER}"}),
        dict(more, constants=[f"/{MARKER}/password"]),
        dict(more, unexamined=[f"/{MARKER}"]),
    ):
        with pytest.raises(RenderError) as error:
            render_sources(one(tmp_path, raw, "json", **broken), subject)
        assert MARKER not in str(error.value)
        # No chained error either: a parser's own message could quote its input.
        assert error.value.__cause__ is None
        assert error.value.__context__ is None or error.value.__suppress_context__


# ---- the scanners refuse what they do not recognise instead of guessing a span


@pytest.mark.parametrize(
    "raw",
    [b'{"a" 1}', b'{"a": 1', b'{"a": 1 "b": 2}', b"[1 2]", b'"abc', b'{"a": 1} x', b"{1: 2}"],
)
def test_json_scanner_refuses_text_it_cannot_walk(raw: bytes) -> None:
    with pytest.raises(RenderError):
        render._json_spans(raw)


@pytest.mark.parametrize("event", ["start", "end"])
def test_property_list_scanner_refuses_a_parser_that_reports_other_offsets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, event: str
) -> None:
    raw = PLIST_HEAD + b"<dict><key>a</key><string>example-web</string></dict></plist>\n"
    genuine = render.expat.ParserCreate

    class Shifted:
        """The real parser, reporting one kind of offset a byte late."""

        def __init__(self) -> None:
            self.parser = genuine()
            self.reporting = ""

        @property
        def CurrentByteIndex(self) -> int:
            return self.parser.CurrentByteIndex + (self.reporting == event)

        def Parse(self, data: bytes, final: bool) -> None:
            self.parser.StartElementHandler = self.on("start", self.StartElementHandler)
            self.parser.EndElementHandler = self.on("end", self.EndElementHandler)
            self.parser.CharacterDataHandler = self.CharacterDataHandler
            self.parser.Parse(data, final)

        def on(self, name: str, handler: Any) -> Any:
            def call(*arguments: Any) -> None:
                self.reporting = name
                handler(*arguments)

            return call

    assert set(render._plist_spans(raw)) == {("a",)}
    monkeypatch.setattr(render.expat, "ParserCreate", Shifted)
    with pytest.raises(RenderError, match="offset"):
        render._plist_spans(raw)
    path = one(tmp_path, raw, "plist", {"/a": NAME})
    assert reasons(render_sources(path, instance())) == [("render-self-check-failed", None)]


def test_values_outside_the_written_spellings_are_refused_before_any_byte_is_made() -> None:
    number = render._Span(0, 1, "integer", "json")
    with pytest.raises(render._Refused, match="value-not-representable"):
        render._encode(-1, 5, b"5", number)
    with pytest.raises(render._Refused, match="value-not-representable"):
        render._encode(10**10, 5, b"5", number)
    assert render._encode(7, -5, b"-5", number) == (b"7", 7)
    # No specific setting, nothing to search free text for.
    assert render._search(["word", "other"]) is None

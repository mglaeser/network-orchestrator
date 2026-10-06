"""What an import does with a manifest that a renderer reads as well.

The five keys only a renderer reads are accepted and ignored, a program
receipt alone no longer blocks a projection, and a list member is addressed
by its identifier. Nothing that was imported before is imported differently.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from netorch.instance import canonical_instance_bytes, instance_to_dict, load_instance
from netorch.legacy_import import (
    ImportError,
    ImportResult,
    Issue,
    SourceReceipt,
    generated_bytes,
    import_sources,
    project_instance,
)

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = b"#!/bin/sh\nexec /usr/bin/true\n"
RENDER_KEYS: dict[str, Any] = {
    "composed": {"/names/0": [{"pointer": "/workloads/example-web/name"}, {"text": "-one"}]},
    "translated": {"/names/1": {"pointer": "/host/lan/link", "values": {"wired": "example-two"}}},
    "constants": ["/note"],
    "unexamined": ["/environment"],
    "independent": ["/note"],
}


def base() -> Any:
    return load_instance(ROOT / "examples" / "instance.json")


def manifest(tmp_path: Path, sources: list[dict[str, Any]]) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "sources": sources}))
    return path


def entry(path: str, fmt: str, mapping: dict[str, str], **more: Any) -> dict[str, Any]:
    return {
        "id": path.split(".")[0],
        "owner": "forwarding",
        "path": path,
        "format": fmt,
        "sha256": None,
        "mapping": mapping,
        **more,
    }


def captures(tmp_path: Path) -> list[dict[str, Any]]:
    (tmp_path / "catalogue.json").write_bytes(
        b'{"lan": "198.51.100.10", "names": ["example-one", "example-two"]}\n'
    )
    (tmp_path / "settings.env").write_bytes(
        b"# literal settings\nEXAMPLE_SECONDS=20\nEXAMPLE_NAME='example-web'\n"
    )
    (tmp_path / "program.sh").write_bytes(PROGRAM)
    return [
        entry("catalogue.json", "json", {"/lan": "/host/lan/ipv4", "/names/1": "/second"}),
        entry(
            "settings.env",
            "literal-env",
            {
                "/EXAMPLE_SECONDS": "/supervision/discovery_seconds",
                "/EXAMPLE_NAME": "/workloads/0/name",
            },
        ),
        entry("program.sh", "source-inventory", {}),
    ]


def test_import_without_render_keys_is_byte_identical_to_the_previous_release(
    tmp_path: Path,
) -> None:
    # Both literals were computed with the importer of 0.3.2 (c419a62).
    result = import_sources(manifest(tmp_path, captures(tmp_path)))
    assert hashlib.sha256(generated_bytes(result)).hexdigest() == (
        "4b9d1f1db4217fbf22549cedb4f761b4ea9bd75cf9779fc39df10398dfb9ed16"
    )
    assert result.owner_digest("forwarding") == (
        "e59984e6d1ec7c2efd8dbde65bba3ca2807d2d7efae2cf114003fdbef08cb76b"
    )
    assert [(issue.source, issue.reason) for issue in result.underivable] == [
        ("program", "executable-source-not-evaluated")
    ]


def test_import_accepts_the_keys_only_a_renderer_reads_and_ignores_them(tmp_path: Path) -> None:
    plain = import_sources(manifest(tmp_path, captures(tmp_path)))
    sources = captures(tmp_path)
    sources[0].update(RENDER_KEYS)
    sources[1].update(constants=[], independent=[])
    full = import_sources(manifest(tmp_path, sources))
    assert generated_bytes(full) == generated_bytes(plain)
    assert full.owner_digest("forwarding") == plain.owner_digest("forwarding")
    assert b"example-one" not in generated_bytes(full)


@pytest.mark.parametrize("key", sorted(RENDER_KEYS))
def test_each_render_key_is_accepted_on_a_data_source_and_refused_on_a_program(
    tmp_path: Path, key: str
) -> None:
    sources = captures(tmp_path)
    sources[0][key] = RENDER_KEYS[key]
    assert import_sources(manifest(tmp_path, sources)).values["second"] == "example-two"
    sources = captures(tmp_path)
    sources[2][key] = RENDER_KEYS[key]
    with pytest.raises(ImportError, match="Executable owner sources"):
        import_sources(manifest(tmp_path, sources))


@pytest.mark.parametrize("change", [{"extra": 1}, {"template": "{{ name }}"}, {"render": True}])
def test_any_other_entry_key_is_still_refused(tmp_path: Path, change: dict[str, Any]) -> None:
    sources = captures(tmp_path)
    sources[0].update(RENDER_KEYS | change)
    with pytest.raises(ImportError, match="Unsupported static source contract"):
        import_sources(manifest(tmp_path, sources))


def test_render_keys_do_not_replace_a_required_key(tmp_path: Path) -> None:
    sources = captures(tmp_path)
    sources[0].update(RENDER_KEYS)
    del sources[0]["mapping"]
    with pytest.raises(ImportError, match="Unsupported static source contract"):
        import_sources(manifest(tmp_path, sources))


def test_program_receipt_does_not_block_projection_but_unread_data_does(tmp_path: Path) -> None:
    (tmp_path / "program.sh").write_bytes(PROGRAM)
    (tmp_path / "settings.env").write_bytes(b"EXAMPLE_INSTANCE=example\n")
    entries = [
        entry("program.sh", "source-inventory", {}),
        entry("settings.env", "literal-env", {"/EXAMPLE_INSTANCE": "/instance"}),
    ]
    template = instance_to_dict(base())
    template["instance"] = None
    result = import_sources(manifest(tmp_path, entries))
    assert [issue.reason for issue in result.underivable] == ["executable-source-not-evaluated"]
    assert project_instance(result, template) == canonical_instance_bytes(base())
    (tmp_path / "settings.env").write_bytes(b"EXAMPLE_INSTANCE=$(hostname)\n")
    broken = import_sources(manifest(tmp_path, entries))
    assert sorted(issue.reason for issue in broken.underivable) == [
        "executable-source-not-evaluated",
        "unsupported-static-syntax",
    ]
    with pytest.raises(ImportError, match="Unresolved owner inputs"):
        project_instance(broken, template)
    entries[1]["mapping"] = {"/EXAMPLE_OTHER": "/instance"}
    (tmp_path / "settings.env").write_bytes(b"EXAMPLE_INSTANCE=example\n")
    with pytest.raises(ImportError, match="Unresolved owner inputs"):
        project_instance(import_sources(manifest(tmp_path, entries)), template)


@pytest.mark.parametrize(
    "receipts,issue",
    [
        (
            (SourceReceipt("data", "site", "0" * 64, "json"),),
            Issue("data", "executable-source-not-evaluated"),
        ),
        (
            (SourceReceipt("data", "site", "0" * 64, "source-inventory"),),
            Issue("other", "executable-source-not-evaluated"),
        ),
        ((), Issue("data", "executable-source-not-evaluated")),
        (
            (SourceReceipt("data", "site", "0" * 64, "source-inventory"),),
            Issue("data", "unsupported-static-syntax"),
        ),
    ],
    ids=["a-data-source", "another-source", "no-receipt", "another-reason"],
)
def test_only_the_receipt_of_an_inventoried_program_is_no_unread_input(
    receipts: tuple[SourceReceipt, ...], issue: Issue
) -> None:
    with pytest.raises(ImportError, match="Unresolved owner inputs"):
        project_instance(ImportResult({}, receipts, (issue,)), instance_to_dict(base()))


def projected(tmp_path: Path, mapping: dict[str, str], template: dict[str, Any]) -> bytes:
    legacy = {"media": "example-media", "web": "example-web", "first": 51000}
    (tmp_path / "owner.json").write_bytes(json.dumps(legacy).encode())
    result = import_sources(manifest(tmp_path, [entry("owner.json", "json", mapping)]))
    return project_instance(result, template)


def test_projection_fills_a_list_member_by_its_identifier(tmp_path: Path) -> None:
    template = instance_to_dict(base())
    template["workloads"][1]["name"] = None
    template["port_ranges"][0]["first"] = None
    mapping = {
        "/media": "/workloads/example-media/name",
        "/first": "/port_ranges/example-range/first",
    }
    assert projected(tmp_path, mapping, template) == canonical_instance_bytes(base())
    # The same slot by its position, as before.
    by_position = {"/media": "/workloads/1/name", "/first": "/port_ranges/0/first"}
    assert projected(tmp_path, by_position, template) == canonical_instance_bytes(base())
    assert template["workloads"][1]["name"] is None


def test_identifier_names_its_member_wherever_the_member_stands(tmp_path: Path) -> None:
    template = instance_to_dict(base())
    template["workloads"].reverse()
    template["workloads"][0]["name"] = None
    expected = instance_to_dict(base())
    expected["workloads"].reverse()
    produced = projected(tmp_path, {"/media": "/workloads/example-media/name"}, template)
    assert json.loads(produced)["workloads"] == expected["workloads"]


def test_position_and_identifier_of_one_member_are_one_destination(tmp_path: Path) -> None:
    template = instance_to_dict(base())
    template["workloads"][0]["name"] = None
    mapping = {"/web": "/workloads/0/name", "/media": "/workloads/example-web/name"}
    with pytest.raises(ImportError, match="more than one author"):
        projected(tmp_path, mapping, template)


@pytest.mark.parametrize(
    "pointer,prepare",
    [
        ("/workloads/absent/name", lambda data: None),
        ("/workloads/example-web/name", lambda data: data["workloads"][1].update(id="example-web")),
        ("/workloads/example-web/name", lambda data: data["workloads"][1].pop("id")),
        ("/workloads/example-web/name", lambda data: data.update(workloads=[])),
        (
            "/host/baseline/proxies/first/name",
            lambda data: data["host"]["baseline"].update(proxies=["x"]),
        ),
        ("/transport/example-return/dependencies/first", lambda data: None),
    ],
    ids=["unknown", "ambiguous", "member-without-id", "empty-list", "list-of-text", "no-member"],
)
def test_member_that_is_not_identified_exactly_once_is_unavailable(
    tmp_path: Path, pointer: str, prepare: Any
) -> None:
    template = instance_to_dict(base())
    template["workloads"][0]["name"] = None
    prepare(template)
    with pytest.raises(ImportError, match="unavailable"):
        projected(tmp_path, {"/web": pointer}, template)

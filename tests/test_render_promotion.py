"""Literal byte parity can promote; inventory diagnostics cannot prove consumers.

Programs are pinned and searched, never executed by these tests. Synthetic data only.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from netorch.codec import canonical_bytes
from netorch.conformance import (
    ConformanceError,
    InventoryCheck,
    check_owner_flip,
    compare_bytes,
    promote_owner,
)
from netorch.instance import instance_to_dict, parse_instance
from netorch.legacy_import import (
    INVENTORY_ONLY,
    ImportResult,
    Issue,
    import_sources,
    project_instance,
)
from netorch.render import render_sources
from tests.test_render_sources import (
    CATALOGUE,
    changed,
    complete_sources,
    instance,
    manifest,
    source,
)

LITERAL = b"EXAMPLE_INTERVAL=10\n"
PROGRAM = b"#!/bin/sh\n# embeds the remaining constants of this owner\nexit 0\n"
CLEAN = b"#!/bin/sh\n# reads every setting from its literal files\nexec /usr/bin/true\n"
EMBEDDING = b"#!/bin/sh\nNAME=example-web\nexec /usr/bin/true\n"


def owner_instance(owner: str, digest: str, section: str = "discovery") -> dict[str, Any]:
    """The example instance with one generated authoring record for ``owner``."""
    data = instance_to_dict(instance())
    data["authoring"][0]["sections"].remove(section)
    data["authoring"].append(
        {
            "owner": owner,
            "sections": [section],
            "subjects": [],
            "mode": "generated",
            "source_sha256": digest,
        }
    )
    parse_instance(canonical_bytes(data) + b"\n")  # The closed model accepts this split.
    return data


def with_program(tmp_path: Path, program: bytes) -> Path:
    sources = complete_sources(tmp_path)
    (tmp_path / "discover.sh").write_bytes(program)
    sources.append(source("program", "discover.sh", "source-inventory"))
    return manifest(tmp_path, sources)


def flipped(document: dict[str, Any], owner: str) -> list[tuple[str, Any]]:
    return [
        (item["mode"], item["source_sha256"])
        for item in document["authoring"]
        if item["owner"] == owner
    ]


def test_owner_with_an_inventoried_program_is_not_promoted(tmp_path: Path) -> None:
    """The reviewer's reproducer: one literal data file and the program beside it."""
    (tmp_path / "owner.env").write_bytes(LITERAL)
    (tmp_path / "owner.sh").write_bytes(PROGRAM)
    literal = source(
        "owner-input",
        "owner.env",
        "literal-env",
        {"/EXAMPLE_INTERVAL": "/supervision/reconcile_seconds"},
    )
    program = source("owner-program", "owner.sh", "source-inventory")
    path = manifest(
        tmp_path, [literal | {"owner": "forwarding"}, program | {"owner": "forwarding"}]
    )
    imported = import_sources(path)
    rendered = render_sources(path, instance())
    before = owner_instance("forwarding", imported.owner_digest("forwarding"), "supervision")
    comparisons = rendered.comparisons("forwarding")
    assert [(item.id, item.identical) for item in comparisons] == [("owner-input", True)]
    with pytest.raises(ConformanceError, match="unresolved static inputs"):
        promote_owner(before, "forwarding", imported, comparisons, rendered.checks("forwarding"))
    # Even a byte comparison of the program with itself proves no consumer behavior.
    copied = (*comparisons, compare_bytes("owner-program", PROGRAM, PROGRAM, owner="forwarding"))
    for checks in ((), rendered.checks("forwarding")):
        with pytest.raises(ConformanceError, match="unresolved static inputs"):
            promote_owner(before, "forwarding", imported, copied, checks)


def test_owner_with_literal_inputs_and_a_clean_program_stays_generated(tmp_path: Path) -> None:
    path = with_program(tmp_path, CLEAN)
    imported = import_sources(path)
    rendered = render_sources(path, instance())
    assert [(i.id, i.scanned, i.embedded_literals) for i in rendered.inventory] == [
        ("program", True, 0)
    ]
    before = owner_instance("discovery", imported.owner_digest("discovery"))
    with pytest.raises(ConformanceError, match="unresolved static inputs"):
        promote_owner(
            before,
            "discovery",
            imported,
            rendered.comparisons("discovery"),
            rendered.checks("discovery"),
        )
    assert flipped(before, "discovery") == [("generated", imported.owner_digest("discovery"))]


def test_program_that_still_holds_a_setting_blocks_its_owner(tmp_path: Path) -> None:
    path = with_program(tmp_path, EMBEDDING)
    imported = import_sources(path)
    rendered = render_sources(path, instance())
    assert rendered.inventory[0].embedded_literals == 1
    before = owner_instance("discovery", imported.owner_digest("discovery"))
    with pytest.raises(ConformanceError, match="unresolved static inputs"):
        promote_owner(
            before,
            "discovery",
            imported,
            rendered.comparisons("discovery"),
            rendered.checks("discovery"),
        )


def test_program_that_was_not_searched_blocks_its_owner(tmp_path: Path) -> None:
    path = with_program(tmp_path, CLEAN)
    imported = import_sources(path)
    rendered = render_sources(path, instance())
    before = owner_instance("discovery", imported.owner_digest("discovery"))
    with pytest.raises(ConformanceError, match="unresolved static inputs"):
        promote_owner(before, "discovery", imported, rendered.comparisons("discovery"))
    binary = with_program(tmp_path, b"\xff\xfe\x00binary")
    imported = import_sources(binary)
    rendered = render_sources(binary, instance())
    assert rendered.inventory[0].scanned is False
    before = owner_instance("discovery", imported.owner_digest("discovery"))
    with pytest.raises(ConformanceError, match="unresolved static inputs"):
        promote_owner(
            before,
            "discovery",
            imported,
            rendered.comparisons("discovery"),
            rendered.checks("discovery"),
        )


def test_changed_program_changes_the_owner_digest(tmp_path: Path) -> None:
    path = with_program(tmp_path, CLEAN)
    first = import_sources(path)
    searched = render_sources(path, instance())
    before = owner_instance("discovery", first.owner_digest("discovery"))
    path = with_program(tmp_path, CLEAN + b"# edited\n")
    second = import_sources(path)
    assert first.owner_digest("discovery") != second.owner_digest("discovery")
    # The reviewed record no longer matches, and neither does the earlier check.
    with pytest.raises(ConformanceError, match="digest"):
        promote_owner(
            before,
            "discovery",
            second,
            searched.comparisons("discovery"),
            searched.checks("discovery"),
        )
    renewed = owner_instance("discovery", second.owner_digest("discovery"))
    with pytest.raises(ConformanceError, match="unresolved static inputs"):
        promote_owner(
            renewed,
            "discovery",
            second,
            searched.comparisons("discovery"),
            searched.checks("discovery"),
        )


def test_incomplete_or_differing_input_still_blocks_the_flip(tmp_path: Path) -> None:
    path = manifest(tmp_path, complete_sources(tmp_path))
    imported = import_sources(path)
    before = owner_instance("discovery", imported.owner_digest("discovery"))
    drifted = render_sources(
        path, changed(lambda data: data["supervision"].update(discovery_misses=4))
    )
    assert [item.identical for item in drifted.comparisons("discovery")].count(False) == 1
    with pytest.raises(ConformanceError, match="byte parity"):
        promote_owner(
            before,
            "discovery",
            imported,
            drifted.comparisons("discovery"),
            drifted.checks("discovery"),
        )
    sources = complete_sources(tmp_path)
    sources[1]["constants"] = []
    incomplete = render_sources(manifest(tmp_path, sources), instance())
    assert all(item.identical for item in incomplete.sources)
    with pytest.raises(ConformanceError, match="byte parity"):
        promote_owner(
            before,
            "discovery",
            imported,
            incomplete.comparisons("discovery"),
            incomplete.checks("discovery"),
        )


def test_unread_data_input_still_blocks_an_owner_with_a_program(tmp_path: Path) -> None:
    path = with_program(tmp_path, CLEAN)
    (tmp_path / "settings.env").write_bytes(b"EXAMPLE_TARGET_ADDRESS=$(hostname)\n")
    imported = import_sources(path)
    rendered = render_sources(path, instance())
    assert ("settings", "unsupported-static-syntax") in {
        (issue.source, issue.reason) for issue in rendered.issues
    }
    before = owner_instance("discovery", imported.owner_digest("discovery"))
    with pytest.raises(ConformanceError, match="unresolved static inputs"):
        promote_owner(
            before,
            "discovery",
            imported,
            rendered.comparisons("discovery"),
            rendered.checks("discovery"),
        )


def test_program_receipts_and_other_unresolved_inputs_block_promotion(tmp_path: Path) -> None:
    path = with_program(tmp_path, CLEAN)
    imported = import_sources(path)
    rendered = render_sources(path, instance())
    before = owner_instance("discovery", imported.owner_digest("discovery"))
    # Omitting the importer's issue cannot hide the inventory format of the receipt.
    omitted = ImportResult(imported.values, imported.receipts, ())
    with pytest.raises(ConformanceError, match="unresolved static inputs"):
        promote_owner(
            before,
            "discovery",
            omitted,
            rendered.comparisons("discovery"),
            rendered.checks("discovery"),
        )
    for issue in (Issue("job", INVENTORY_ONLY), Issue("program", "unsupported-static-syntax")):
        claimed = ImportResult(imported.values, imported.receipts, (*imported.underivable, issue))
        with pytest.raises(ConformanceError, match="unresolved static inputs"):
            promote_owner(
                before,
                "discovery",
                claimed,
                rendered.comparisons("discovery"),
                rendered.checks("discovery"),
            )


@pytest.mark.parametrize(
    "change,message",
    [
        ({"owner": "forwarding"}, "not bound to this owner"),
        ({"id": "unknown"}, "unresolved static inputs"),
        ({"id": "catalogue"}, "unresolved static inputs"),
        ({"sha256": "0" * 64}, "unresolved static inputs"),
        ({"scanned": False}, "unresolved static inputs"),
        ({"scanned": 1}, "unresolved static inputs"),
        ({"embedded_literals": 1}, "unresolved static inputs"),
        ({"embedded_literals": False}, "unresolved static inputs"),
        ({"embedded_literals": None}, "unresolved static inputs"),
    ],
)
def test_no_forged_inventory_diagnostic_can_waive_program_conformance(
    tmp_path: Path, change: dict[str, Any], message: str
) -> None:
    path = with_program(tmp_path, CLEAN)
    imported = import_sources(path)
    rendered = render_sources(path, instance())
    before = owner_instance("discovery", imported.owner_digest("discovery"))
    genuine = rendered.checks("discovery")[0]
    assert genuine == InventoryCheck(
        "program", "discovery", hashlib.sha256(CLEAN).hexdigest(), True, 0
    )
    forged = InventoryCheck(**(genuine.to_dict() | change))
    with pytest.raises(ConformanceError, match=message):
        promote_owner(before, "discovery", imported, rendered.comparisons("discovery"), (forged,))
    with pytest.raises(ConformanceError, match="unresolved static inputs"):
        promote_owner(
            before, "discovery", imported, rendered.comparisons("discovery"), (genuine, genuine)
        )


def test_evidence_made_for_another_owner_promotes_no_one(tmp_path: Path) -> None:
    sources = complete_sources(tmp_path)
    (tmp_path / "discover.sh").write_bytes(CLEAN)
    (tmp_path / "forward.sh").write_bytes(CLEAN)
    (tmp_path / "forward.env").write_bytes(LITERAL)
    sources += [
        source("program", "discover.sh", "source-inventory"),
        source("forward-program", "forward.sh", "source-inventory") | {"owner": "forwarding"},
        source(
            "forward-input",
            "forward.env",
            "literal-env",
            {"/EXAMPLE_INTERVAL": "/supervision/reconcile_seconds"},
        )
        | {"owner": "forwarding"},
    ]
    path = manifest(tmp_path, sources)
    imported = import_sources(path)
    rendered = render_sources(path, instance())
    assert [check.id for check in rendered.checks("forwarding")] == ["forward-program"]
    before = owner_instance("discovery", imported.owner_digest("discovery"))
    with pytest.raises(ConformanceError, match="Inventory checks are not bound to this owner"):
        promote_owner(
            before, "discovery", imported, rendered.comparisons("discovery"), rendered.inventory
        )
    with pytest.raises(ConformanceError, match="Byte comparisons are not bound to this owner"):
        promote_owner(
            before,
            "discovery",
            imported,
            rendered.comparisons("forwarding"),
            rendered.checks("discovery"),
        )
    with pytest.raises(ConformanceError, match="unresolved static inputs"):
        promote_owner(
            before,
            "discovery",
            imported,
            rendered.comparisons("discovery"),
            rendered.checks("discovery"),
        )


def test_unrendered_toml_search_is_diagnostic_and_cannot_replace_byte_parity(
    tmp_path: Path,
) -> None:
    vendor = b'[section]\nkey = "value"\n'
    sources = complete_sources(tmp_path)
    (tmp_path / "vendor.toml").write_bytes(vendor)
    sources.append(source("vendor", "vendor.toml", "toml"))
    path = manifest(tmp_path, sources)
    rendered = render_sources(path, instance())
    assert [(i.id, i.scanned, i.embedded_literals) for i in rendered.inventory] == [
        ("vendor", True, 0)
    ]
    imported = import_sources(path)
    before = owner_instance("discovery", imported.owner_digest("discovery"))
    comparisons = rendered.comparisons("discovery")
    with pytest.raises(ConformanceError, match="Inventory checks do not establish"):
        promote_owner(before, "discovery", imported, comparisons, rendered.checks("discovery"))
    # A site's own generator may still supply the rendered file, as before.
    own = compare_bytes("vendor", vendor, vendor, owner="discovery")
    assert promote_owner(before, "discovery", imported, (*comparisons, own))
    # Diagnostics are not accepted as promotion evidence even alongside comparisons.
    with pytest.raises(ConformanceError, match="Inventory checks do not establish"):
        promote_owner(
            before, "discovery", imported, (*comparisons, own), rendered.checks("discovery")
        )
    with pytest.raises(ConformanceError, match="byte parity"):
        promote_owner(before, "discovery", imported, comparisons)
    # A file that supplies a setting is not rendered and not searched instead.
    sources[-1]["mapping"] = {"/section/key": "/instance"}
    mapped = render_sources(manifest(tmp_path, sources), instance())
    assert ("vendor", "format-not-renderable") in {(i.source, i.reason) for i in mapped.issues}
    assert mapped.inventory == ()


def test_owner_with_nothing_rendered_is_not_promoted(tmp_path: Path) -> None:
    (tmp_path / "wrapper.sh").write_bytes(CLEAN)
    path = manifest(tmp_path, [source("wrapper", "wrapper.sh", "source-inventory")])
    imported = import_sources(path)
    rendered = render_sources(path, instance())
    assert [(i.scanned, i.embedded_literals) for i in rendered.inventory] == [(True, 0)]
    before = owner_instance("discovery", imported.owner_digest("discovery"))
    with pytest.raises(ConformanceError, match="unresolved static inputs"):
        promote_owner(before, "discovery", imported, (), rendered.checks("discovery"))


def test_import_and_render_address_the_same_member(tmp_path: Path) -> None:
    (tmp_path / "catalogue.json").write_bytes(CATALOGUE)
    entry = source(
        "catalogue",
        "catalogue.json",
        "json",
        {"/web/names/0": "/workloads/example-web/name"},
        constants=["/web/http", "/web/note", "/enabled"],
    )
    path = manifest(tmp_path, [entry])
    template = instance_to_dict(instance())
    template["workloads"][0]["name"] = None
    imported = import_sources(path)
    projected = parse_instance(project_instance(imported, template))
    assert projected.workloads[0].name == instance().workloads[0].name
    rendered = render_sources(path, projected)
    assert [(item.identical, item.complete) for item in rendered.sources] == [(True, True)]
    before = owner_instance("discovery", imported.owner_digest("discovery"))
    after = promote_owner(before, "discovery", imported, rendered.comparisons("discovery"))
    assert flipped(after, "discovery") == [("authored", None)]
    assert check_owner_flip(before, after, "discovery")


def test_clean_scan_cannot_prove_hardcoded_interval_consumes_rendered_data(tmp_path: Path) -> None:
    """No process executes: the program ignores the data file even as its value changes."""
    hardcoded = b'#!/bin/sh\nINTERVAL=10\nexec sleep "$INTERVAL"\n'
    (tmp_path / "owner.env").write_bytes(LITERAL)
    (tmp_path / "owner.sh").write_bytes(hardcoded)
    path = manifest(
        tmp_path,
        [
            source(
                "owner-input",
                "owner.env",
                "literal-env",
                {"/EXAMPLE_INTERVAL": "/supervision/reconcile_seconds"},
            )
            | {"owner": "forwarding"},
            source("owner-program", "owner.sh", "source-inventory") | {"owner": "forwarding"},
        ],
    )
    imported = import_sources(path)
    rendered = render_sources(path, instance())
    assert [(item.scanned, item.embedded_literals) for item in rendered.inventory] == [(True, 0)]
    collected: dict[str, bytes] = {}
    render_sources(
        path,
        changed(lambda data: data["supervision"].update(reconcile_seconds=20)),
        collect=collected,
    )
    assert collected["owner-input"] == b"EXAMPLE_INTERVAL=20\n"
    assert (tmp_path / "owner.sh").read_bytes() == hardcoded
    before = owner_instance("forwarding", imported.owner_digest("forwarding"), "supervision")
    with pytest.raises(ConformanceError, match="unresolved static inputs"):
        promote_owner(
            before,
            "forwarding",
            imported,
            rendered.comparisons("forwarding"),
            rendered.checks("forwarding"),
        )

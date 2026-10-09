"""Keep the manual native procedure inventory aligned with the proving registry.

This checks coverage and evidence scope, never the truth of a native measurement.
"""

import re
from pathlib import Path

from netorch.requirements import REQUIREMENTS


def test_every_native_requirement_has_a_scoped_procedure():
    document = (Path(__file__).parents[1] / "docs/native-qualification.md").read_text()
    rows = {}
    for line in document.splitlines():
        if re.match(r"\| `[A-Z][A-Z0-9-]+` \|", line):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            assert len(cells) == 7 and all(cells)
            identifier = cells[0].strip("`")
            assert identifier not in rows
            rows[identifier] = cells
    expected = {item.id: item for item in REQUIREMENTS if item.minimum_tier >= 3}
    assert rows.keys() == expected.keys()
    for identifier, item in expected.items():
        cells = rows[identifier]
        assert cells[1] == (
            " or ".join(f"`{method}`" for method in item.acceptance_methods)
            + f", tier {item.minimum_tier}"
        )
        assert cells[2] == f"`{item.applicability}`"
        if item.applicability in {"root-transport", "any-source", "bounded", "bounded-udp"}:
            assert "One record per transport profile" in cells[6]
        elif item.applicability in {"exports", "imports", "discovery", "media-audio"}:
            assert "One record per discovery selection" in cells[6]
        else:
            assert "`profile` `null`" in cells[6]
        for method, context in (
            ("heard-audio", "host-person"),
            ("local-network-consent", "user-launchagent"),
        ):
            if method in item.acceptance_methods:
                assert f"`capture_context` must be `{context}`" in cells[6]

"""Merged tree only: what an independent import binds once supervision has optional members.

The independent import and the supervision vocabulary are separate changes. Merged
as they are, the context of an independent import would carry a ``null`` for every
supervision member left out, and would not carry the target workload's own
deadlines, which a coupled selection binds through its transport dependency.
"""

from __future__ import annotations

from tests.test_discovery_independent_import import independent, resolved, selection, shipped

# Computed on the branch of the independent-import change alone.
ALONE = "fbee29b013a9e7b73e61f89383097500ed595b6ea19c199114292fedcece649b"


def test_an_independent_import_keeps_the_digest_it_has_without_the_vocabulary() -> None:
    assert resolved(independent(shipped()))["example-import"] == ALONE


def test_an_independent_import_binds_the_own_deadlines_of_its_workload() -> None:
    data = independent(shipped())
    target = selection(data)["service"]
    stated = next(item for item in data["workloads"] if item["id"] == target)

    stated["deadlines"] = {"probe_seconds": 7}
    first = resolved(data)["example-import"]
    stated["deadlines"] = {"probe_seconds": 8}
    second = resolved(data)["example-import"]

    assert len({ALONE, first, second}) == 3

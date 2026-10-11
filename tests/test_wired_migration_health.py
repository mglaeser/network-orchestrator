"""A high-port resolver success cannot qualify the physical LAN ingress path.

The scenario is derived from the adapter-replacement incident, but these
checkpoint envelopes are deliberately synthetic, not packet observations.
"""

import hashlib

import pytest

from netorch.codec import canonical_bytes
from tests.test_migration_health import check, fixture


@pytest.mark.parametrize("phase", ["pre", "post", "rollback", "soak"])
@pytest.mark.parametrize("lan_status", ["failed", "unknown", "stale-interface"])
def test_green_high_port_does_not_promote_lan_evidence(phase, lan_status):
    contract, snapshot = fixture()
    contract["services"][1]["checks"] = ["Published UDP resolution", "Published TCP resolution"]
    snapshot["contract_sha256"] = hashlib.sha256(canonical_bytes(contract)).hexdigest()
    snapshot["phase"] = phase
    resolver = snapshot["dashboard"]["services"][1]
    resolver["result"]["checks"] = [
        {"name": name, "ok": True} for name in contract["services"][1]["checks"]
    ]
    # An unreviewed metadata field cannot become native acceptance, irrespective
    # of whether it alleges failure, success or a remembered interface name.
    resolver["physicalLanDns"] = {"status": lan_status, "observer": "synthetic"}
    result = check(contract, snapshot, phase=phase)
    assert result["recorded_health_passed"] is True
    assert result["native_qualified"] is False
    assert result["mutation_available"] is False
    assert result["provenance_authenticated"] is False


def test_published_probe_cannot_replace_a_required_client_probe():
    contract, snapshot = fixture()
    contract["services"][1]["checks"] = ["Physical LAN UDP reply", "Physical LAN TCP reply"]
    snapshot["contract_sha256"] = hashlib.sha256(canonical_bytes(contract)).hexdigest()
    # An actual observer must implement these before they can be put in a live
    # catalog. Renaming or accepting the existing high-port result is forbidden.
    snapshot["dashboard"]["services"][1]["result"]["checks"] = [
        {"name": "Published UDP reply", "ok": True},
        {"name": "Published TCP reply", "ok": True},
    ]
    result = check(contract, snapshot)
    assert result["recorded_health_passed"] is False
    assert result["blockers"]
    assert result["native_qualified"] is False

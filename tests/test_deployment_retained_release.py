"""Installing a retained release again is refused before anything is written."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from netorch.deployment import install_bundle, recover_install, rollback_install
from netorch.deployment_config import DeploymentError
from netorch.state import intent_from_dict
from netorch.storage import Store
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest

__all__ = ["config", "fake_platform", "manifest"]


def release(manifest: dict[str, Any], scope: str, number: int) -> dict[str, Any]:
    value = copy.deepcopy(manifest)
    if scope == "user":
        value["jobs"][0]["interval_seconds"] = 10 + 5 * number
    elif number:
        value["jobs"][1]["log_directory"] += f"-v{number}"
    return value


@pytest.mark.parametrize("scope", ["user", "root"])
def test_reinstalling_a_retained_release_is_refused_before_hold_and_journal(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None, scope: str
) -> None:
    bundles = [
        make_bundle(tmp_path, release(manifest, scope, n), config, f"v{n}") for n in range(3)
    ]
    tools = FakeTools()
    for bundle, metadata in bundles[:2]:
        install_bundle(bundle, scope, expected_digest=metadata["bundle_digest"], runner=tools)
    state_dir = Path(manifest[scope]["state_directory"])
    rollback_install(
        state_dir, scope, expected_current_digest=bundles[1][1]["bundle_digest"], runner=tools
    )
    store = Store(state_dir)
    journal = state_dir / "installation-journal.json"
    before = journal.read_bytes()
    assert store.read("installation-journal.json")["phase"] == "rolled-back"
    intent = (state_dir / "intent.json").read_bytes() if scope == "user" else b""
    calls = len(tools.calls)
    # The second release was rolled back; its directory is retained.
    with pytest.raises(DeploymentError, match="release already exists"):
        install_bundle(
            bundles[1][0], scope, expected_digest=bundles[1][1]["bundle_digest"], runner=tools
        )
    assert journal.read_bytes() == before
    assert len(tools.calls) == calls
    if scope == "user":
        assert (state_dir / "intent.json").read_bytes() == intent
        assert not intent_from_dict(store.read("intent.json")).suspensions
    # Nothing to recover: the next reviewed release installs directly.
    result = install_bundle(
        bundles[2][0], scope, expected_digest=bundles[2][1]["bundle_digest"], runner=tools
    )
    assert result["phase"] == "committed"


def test_reinstalling_a_recovered_first_release_is_refused_the_same_way(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    digest = metadata["bundle_digest"]
    with pytest.raises(DeploymentError):
        install_bundle(bundle, "user", expected_digest=digest, runner=FakeTools("bootstrap"))
    state_dir = Path(manifest["user"]["state_directory"])
    recover_install(state_dir, "user", expected_failed_digest=digest, runner=FakeTools())
    before = {
        name: (state_dir / name).read_bytes()
        for name in ("installation-journal.json", "intent.json")
    }
    tools = FakeTools()
    with pytest.raises(DeploymentError, match="release already exists"):
        install_bundle(bundle, "user", expected_digest=digest, runner=tools)
    assert {name: (state_dir / name).read_bytes() for name in before} == before
    assert tools.calls == []

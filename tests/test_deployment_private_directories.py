"""Every directory of a bundle and of an installed release is private."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest

from netorch.deployment import install_bundle, prepare_root_bundle
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest

__all__ = ["config", "fake_platform", "manifest"]


@pytest.mark.parametrize("umask", [0o022, 0o002])
def test_every_directory_of_a_bundle_and_of_a_release_is_private(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None, umask: int
) -> None:
    # A nested destination adds an intermediate directory below `data`.
    for scope in ("user", "root"):
        source = tmp_path / f"extra-{scope}.json"
        source.write_bytes(b"{}")
        source.chmod(0o600)
        manifest["artifacts"].append(
            {
                "id": f"extra-{scope}",
                "scope": scope,
                "source": str(source),
                "destination": "data/site/tables/extra.json",
                "sha256": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            }
        )
    previous = os.umask(umask)
    try:
        bundle, metadata = make_bundle(tmp_path, manifest, config)
        prepared = tmp_path / "prepared"
        prepare_root_bundle(bundle, prepared)
        for scope in ("user", "root"):
            install_bundle(
                bundle, scope, expected_digest=metadata["bundle_digest"], runner=FakeTools()
            )
    finally:
        os.umask(previous)
    releases = [
        Path(manifest[scope]["directory"]) / "releases" / metadata["release_id"]
        for scope in ("user", "root")
    ]
    for tree in (bundle, prepared, *releases):
        directories = [tree, *(path for path in tree.rglob("*") if path.is_dir())]
        assert len(directories) >= 5
        modes = {
            str(path.relative_to(tree)): oct(stat.S_IMODE(path.lstat().st_mode))
            for path in directories
        }
        assert set(modes.values()) == {"0o700"}, modes
        files = [path for path in tree.rglob("*") if path.is_file()]
        assert {oct(stat.S_IMODE(path.lstat().st_mode)) for path in files} == {"0o600"}

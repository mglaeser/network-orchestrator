"""Package metadata and running-code identity must describe the same release."""

import tomllib
from pathlib import Path

from netorch import __version__
from netorch.cli import main


def test_distribution_and_runtime_version_agree():
    metadata = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    assert metadata["project"]["version"] == __version__


def test_version_command_reports_distribution_identity(capsys):
    import pytest

    with pytest.raises(SystemExit) as stopped:
        main(["--version"])
    assert stopped.value.code == 0
    metadata = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    assert capsys.readouterr().out.strip() == metadata["project"]["version"]

"""A bind mount names one host path and one guest path, each in one spelling."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch.workloads import Option, create_arguments
from tests.test_workloads import enrolled_input, fleet


def enrolled(tmp_path: Path, name: str = "data") -> tuple[Any, Any, Any, Path]:
    """One workload whose only enrolled persistent identity is `tmp_path/name`."""
    config, settings, _, workloads, _ = fleet(tmp_path)
    source = tmp_path / name
    source.mkdir(mode=0o700)
    return config, enrolled_input(settings, source), workloads[0], source


def rendered(tmp_path: Path, template: str, name: str = "data") -> tuple[list[str], str]:
    config, settings, workload, source = enrolled(tmp_path, name)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    value = template.format(source=source, other=other)
    options = (Option("--mount", value),)
    return create_arguments(config, settings, replace(workload, options=options)), value


@pytest.mark.parametrize(
    "template",
    [
        "type=bind,source={source},target=/config",
        "type=bind,source={source},target=/config,readonly",
        "readonly,target=/config,source={source},type=bind",
    ],
)
def test_the_reviewed_spelling_is_still_passed_through_unchanged(
    tmp_path: Path, template: str
) -> None:
    arguments, value = rendered(tmp_path, template)
    assert arguments[arguments.index("--mount") + 1] == value


@pytest.mark.parametrize(
    "template",
    [
        # The vendor reads `src` as the source and keeps the last one it saw,
        # so these mount `other` while the enrolled identity is `data`.
        "type=bind,source={source},target=/config,src={other}",
        "type=bind,source={source},src={other},target=/config",
        "type=bind,source={source},target=/config,=source={other}",
        # The same for the guest path: `dst` and `destination` mean `target`.
        "type=bind,source={source},target=/config,dst=/elsewhere",
        "type=bind,source={source},target=/config,destination=/elsewhere",
        # Not harmful in this order, but still two spellings of one setting.
        "type=bind,src={other},source={source},target=/config",
        "type=bind,source={source},dst=/elsewhere,target=/config",
    ],
)
def test_a_second_spelling_of_source_or_target_is_refused(tmp_path: Path, template: str) -> None:
    with pytest.raises(ValueError, match="unambiguous absolute bind source"):
        rendered(tmp_path, template)


@pytest.mark.parametrize(
    "template",
    [
        # Read by the vendor as read-only whatever follows the equals sign.
        "type=bind,source={source},target=/config,readonly=false",
        "type=bind,source={source},target=/config,ro=false",
        # Vendor keys that do not belong to a bind mount, and an unknown key.
        "type=bind,source={source},target=/config,size=1g",
        "type=bind,source={source},target=/config,mode=1777",
        "type=bind,source={source},target=/config,unreviewed=value",
    ],
)
def test_a_key_outside_type_source_and_target_is_refused(tmp_path: Path, template: str) -> None:
    with pytest.raises(ValueError, match="unambiguous absolute bind source"):
        rendered(tmp_path, template)


@pytest.mark.parametrize(
    "template",
    [
        "type=bind,source={source},target=/config",
        "type=bind,source={source},target=/config=",
        "type=bind,source={source},target=/config=rw",
    ],
)
def test_a_value_holding_a_further_equals_sign_is_refused(tmp_path: Path, template: str) -> None:
    # The vendor splits a piece at up to two equals signs and drops an empty
    # last part: it reads `source=/x/data=` as `/x/data`, which is a different
    # directory from the enrolled `/x/data=`. Three parts it refuses itself.
    name = "data=" if template.endswith("/config") else "data"
    if name != "data":
        (tmp_path / "data").mkdir(mode=0o700)
    with pytest.raises(ValueError, match="unambiguous absolute bind source"):
        rendered(tmp_path, template, name)


def test_the_enrolled_identity_still_decides_after_the_spelling(tmp_path: Path) -> None:
    config, settings, workload, _ = enrolled(tmp_path)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    options = (Option("--mount", f"type=bind,source={other},target=/config"),)
    with pytest.raises(ValueError, match="exactly match enrolled persistent identities"):
        create_arguments(config, settings, replace(workload, options=options))

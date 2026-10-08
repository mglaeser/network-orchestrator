"""Vendor-owned service names cannot be redirected to absent, unrelated jobs."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch.process import Result
from netorch.runtime_settings import parse_settings
from tests.test_apple_runtime import enrolled
from tests.test_runtime_fleet_start import declared, job_report
from tests.test_runtime_settings import authored

__all__ = ["enrolled"]
API = "com.apple.container.apiserver"
PREFIX = "com.apple.container."


@pytest.mark.parametrize(
    "field,value",
    [("api_label", "example.other-api"), ("runtime_label_prefix", "example.other-runtime.")],
)
def test_vendor_job_identity_is_not_an_instance_choice(field: str, value: str) -> None:
    declaration = {
        "api_label": API,
        "api_executable": "/usr/libexec/example-api",
        "runtime_label_prefix": PREFIX,
    }
    declaration[field] = value
    with pytest.raises(ValueError):
        parse_settings({**authored(), "fleet_start": declaration})


def test_wrong_prefix_cannot_turn_a_surviving_guest_into_a_stopped_guest(enrolled: Any) -> None:
    config, settings, inner = declared(enrolled)
    inner.stop_everything(jobs_too=False)
    assert settings.fleet_start is not None
    wrong = "example.other-runtime."
    settings = replace(
        settings, fleet_start=replace(settings.fleet_start, runtime_label_prefix=wrong)
    )

    def service_manager(argv: list[str], **kwargs: Any) -> Result:
        if argv[:2] == ["/bin/launchctl", "print"]:
            label = argv[2].rpartition("/")[2]
            if label.startswith(wrong):
                return Result(113, b"", b"Could not find service\n")
            if label.startswith(PREFIX) and label != API:
                return Result(0, job_report(333), b"")
        return inner(argv, **kwargs)

    result = runtime.observe_runtime(config, settings, service_manager)
    assert {value.state for value in result.services.values()} == {"unknown"}

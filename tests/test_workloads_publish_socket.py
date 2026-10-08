"""A recipe cannot name a host path that the vendor's `create` would clear."""

from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest

from netorch.apple_runtime import observe_runtime
from netorch.codec import canonical_bytes, digest
from netorch.runtime_settings import contract_digest
from netorch.workloads import Option, main, parse_workloads, plan_workloads, provision_digest
from tests.test_workloads import cli_settings, fleet, legacy_cli_conformance

__all__ = ["legacy_cli_conformance"]

PIN = "example.invalid/service@sha256:" + "1" * 64

# Every other option of the allowlist that the vendor's `create` defines.
STILL_ACCEPTED: list[tuple[str, str | None]] = [
    ("--cpus", "2"),
    ("--memory", "4G"),
    ("--env", "MODE=production"),
    ("--env-file", "/operator/site/application.env"),
    ("--gid", "1000"),
    ("--uid", "1000"),
    ("--user", "1000:1000"),
    ("--ulimit", "nofile=1024:2048"),
    ("--workdir", "/srv"),
    ("--cap-add", "CAP_NET_RAW"),
    ("--cap-drop", "ALL"),
    ("--dns", "192.0.2.53"),
    ("--dns-domain", "example.invalid"),
    ("--dns-option", "ndots:1"),
    ("--dns-search", "example.invalid"),
    ("--entrypoint", "/usr/local/bin/application"),
    ("--init-image", "example.invalid/init@sha256:" + "2" * 64),
    ("--kernel", "/operator/site/kernel"),
    ("--kernel-arg", "quiet"),
    ("--label", "role=web"),
    ("--mount", "type=bind,source=/operator/state/data,target=/data"),
    ("--volume", "/operator/state/data:/data:rw"),
    ("--init", None),
    ("--read-only", None),
    ("--rosetta", None),
    ("--ssh", None),
    ("--virtualization", None),
]


def recipe(*options: tuple[str, str | None]) -> dict[str, Any]:
    rows = [{"flag": flag, "value": value} for flag, value in options]
    return {
        "schema_version": 1,
        "workloads": [{"service": "example", "image": PIN, "options": rows, "arguments": []}],
    }


@pytest.mark.parametrize(
    "value",
    [
        "/operator/run/application.sock:/run/application.sock",
        # The vendor resolves a relative host path against its working directory.
        "run/application.sock:/run/application.sock",
        # An existing directory here is what the vendor's `create` would remove.
        "/operator/state/workloads/example:/run/application.sock",
    ],
)
def test_a_recipe_cannot_publish_a_host_socket(value: str) -> None:
    with pytest.raises(ValueError, match="unsupported workload option"):
        parse_workloads(recipe(("--publish-socket", value)))
    with pytest.raises(ValueError, match="unsupported workload option"):
        parse_workloads(recipe(("--cpus", "2"), ("--publish-socket", value), ("--init", None)))


def test_every_other_vendor_option_is_still_accepted() -> None:
    parsed = parse_workloads(recipe(*STILL_ACCEPTED))
    assert parsed[0].options == tuple(Option(flag, value) for flag, value in STILL_ACCEPTED)


@pytest.mark.usefixtures("legacy_cli_conformance")
def test_a_plan_reviewed_with_a_socket_publication_cannot_be_provisioned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module, config, settings, fake, workloads, store, recipes = cli_settings(tmp_path, monkeypatch)
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    row = Option("--publish-socket", f"{data}:/run/application.sock")
    published = (replace(workloads[0], options=(row,)), *workloads[1:])
    # The digest a review would have approved while the option was allowed: the
    # compiler and the digest are unchanged, only the recipe grammar is narrower.
    approved = provision_digest(config, settings, published)
    recipes.write_bytes(
        canonical_bytes({"schema_version": 1, "workloads": [asdict(item) for item in published]})
    )
    plan_impl, provision_impl = module.plan_workloads, module.provision_workloads
    monkeypatch.setattr(
        module,
        "plan_workloads",
        lambda config, settings, workloads, _runner=None, **kwargs: plan_impl(
            config, settings, workloads, fake, **kwargs
        ),
    )
    monkeypatch.setattr(
        module,
        "provision_workloads",
        lambda config, settings, workloads, **kwargs: provision_impl(
            config, settings, workloads, runner=fake, **kwargs
        ),
    )
    prefix = ["--settings", str(tmp_path / "private-settings.json"), "--recipes", str(recipes)]
    assert main([*prefix, "plan"]) == 69
    assert main([*prefix, "provision", "--expected-digest", approved]) == 69
    captured = capsys.readouterr()
    assert not captured.out
    assert "workload-evidence-or-authority-incomplete" in captured.err
    assert str(tmp_path) not in captured.err
    assert not fake.calls and not fake.existing
    assert not (store.directory / "workload-journal.json").exists()
    assert data.is_dir()


def test_an_existing_definition_that_publishes_a_socket_is_still_retained(tmp_path: Path) -> None:
    config, settings, fake, workloads, _ = fleet(tmp_path)
    first = settings.contracts[0]
    fake.configurations[first.name]["publishedSockets"] = [
        {"containerPath": "/run/application.sock", "hostPath": "/operator/run/application.sock"}
    ]
    enrolled = replace(first, configuration_sha256=digest(fake.configurations[first.name]))
    settings = replace(settings, contracts=(enrolled, *settings.contracts[1:]))
    config = replace(
        config,
        services=tuple(
            replace(service, contract_sha256=contract_digest(settings.contract(service.id)))
            for service in config.services
        ),
    )
    fake.config, fake.settings = config, settings
    fake.existing = {item.name: fake.snapshot(item.name) for item in settings.contracts}
    steps = plan_workloads(config, settings, workloads, fake)["steps"]
    assert {step["action"] for step in steps} == {"retain"}
    assert observe_runtime(config, settings, fake).services[first.service].state == "present"
    assert not any(argv[1:2] in (["create"], ["start"]) for argv, _ in fake.calls)

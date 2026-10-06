"""Optional job member `process_type`: two closed values, invisible at its default.

The fixed manifest, policy and source bytes below hold no site data. Every
value named `*_BEFORE` was computed with them on the tree before the member
existed, so the tests that only use those values pass there as well. They exist
to show that nothing changes for a manifest that does not ask for `standard`.
"""

from __future__ import annotations

import copy
import hashlib
import plistlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch.codec import canonical_bytes, digest
from netorch.config import parse_config
from netorch.deployment import install_bundle, render_bundle, rollback_install, validate_bundle
from netorch.deployment_config import (
    DeploymentError,
    deployment_to_dict,
    parse_deployment,
    validate_deployment,
)
from netorch.deployment_model import Job
from netorch.storage import Store
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest

__all__ = ["config", "fake_platform", "manifest"]

RELEASE = "a" * 64
DIGEST_BEFORE = "663256b755367e55e38636da1ecb78d3036bdfb528498cd26f53bcc851d6c041"
# SHA-256 of each job's plist, rendered into the release directory RELEASE.
PLISTS_BEFORE = {
    "netorch-coordinator": "07d72b72761d6fbcf7c5b63608661021877a5c814550aed52b9c20b89d3f1b8f",
    "netorch-supervisor": "8f055f75221d2ac3231356d0771d1819de3920024251a582ea983fcb6a95704d",
    "netorch-forwarding": "198fc71448cf1ccbf58f78a663bcdf367d7aa4712af3b078c1fe80ad6826fab0",
}
# The complete bundle of the fixed manifest, policy and sources.
RELEASE_ID_BEFORE = "673798478f8ea32798d70a4c0b5f67609ed7cd03238b722fbbeb2a598f7263e3"
BUNDLE_DIGEST_BEFORE = "0670f5c7108a86f5d964bbee0f3a577dfb11d4d117cdce69e832e64aa74f1640"
BUNDLE_PLISTS_BEFORE = {
    "user/launchd/netorch-coordinator.plist": (
        "97c59367d0e408340d8f3a51ccf183e794b6bb7230335dd03c3ee5336becd3ac"
    ),
    "user/launchd/netorch-supervisor.plist": (
        "1b32e48b1b05a56b1940312727b0063412d7754f71254883dfcdc1c417de7877"
    ),
    "root/launchd/netorch-forwarding.plist": (
        "94efda02ff3f1b4c1ee5b96256de4a62e5db3dbf1bf37d207ac6a18bb873434d"
    ),
}

BACKEND = b"#!/bin/sh\nexit 0\n"
SETTINGS = canonical_bytes(
    {
        "schema_version": 1,
        "owner": "site-forwarding",
        "anchor": "com.apple/netorch.site-forwarding",
        "observer": {"schema_version": 1, "account": "example"},
        "backend_sha256": hashlib.sha256(BACKEND).hexdigest(),
        "report_path": "/Library/Application Support/NetorchReports/root.json",
        "intent_path": None,
        "interval_seconds": 10,
        "allow_apple_dns_coexistence": False,
    }
)
SOURCES = {
    "/operator/site/forwarding-settings.json": SETTINGS,
    "/operator/site/backend.sh": BACKEND,
}
POLICY = {
    "schema_version": 1,
    "site": "example-site",
    "scopes": [],
    "owners": [
        {"id": "site-forwarding", "privilege": "external-root", "capabilities": ["host-redirect"]}
    ],
    "services": [],
    "profiles": [],
    "discovery": [],
}
COORDINATOR, SUPERVISOR, FORWARDING = 0, 1, 2


def fixed() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "site": "example-site",
        "user_uid": 501,
        "user": {
            "directory": "/operator/install/netorch",
            "state_directory": "/operator/state/netorch",
            "launchd_directory": "/operator/Library/LaunchAgents",
            "domain": "gui/501",
        },
        "root": {
            "directory": "/Library/Netorch/releases-owner",
            "state_directory": "/Library/Netorch/provision-state",
            "launchd_directory": "/Library/LaunchDaemons",
            "domain": "system",
        },
        "forwarding": {
            "directory": "/Library/Netorch/forwarding",
            "settings_artifact": "forwarding-settings",
            "backend_source": "/operator/site/backend.sh",
            "backend_sha256": hashlib.sha256(BACKEND).hexdigest(),
        },
        "artifacts": [
            {
                "id": "forwarding-settings",
                "scope": "root",
                "source": "/operator/site/forwarding-settings.json",
                "destination": "data/forwarding-settings.json",
                "sha256": hashlib.sha256(SETTINGS).hexdigest(),
            }
        ],
        "jobs": [
            {
                "label": "netorch-coordinator",
                "scope": "user",
                "role": "coordinator",
                "argv": [
                    "/operator/runtime/bin/python3",
                    "-m",
                    "netorch",
                    "reconcile",
                    "--state-dir",
                    "{state}",
                ],
                "interval_seconds": 10,
                "keep_alive": False,
                "working_directory": "{release}",
                "log_directory": "/operator/state/netorch/logs",
            },
            {
                "label": "netorch-supervisor",
                "scope": "user",
                "role": "monitor",
                "argv": ["/operator/tools/monit", "-I", "-c", "{release}/monit/monitrc"],
                "interval_seconds": None,
                "keep_alive": True,
                "working_directory": "{release}",
                "log_directory": "/operator/state/netorch/logs",
            },
            {
                "label": "netorch-forwarding",
                "scope": "root",
                "role": "forwarding",
                "argv": [
                    "/Library/Netorch/runtime/bin/python3",
                    "-I",
                    "-m",
                    "netorch.pf_owner",
                    "reconcile",
                    "--root-dir",
                    "/Library/Netorch/forwarding",
                ],
                "interval_seconds": 10,
                "keep_alive": False,
                "working_directory": "{release}",
                "log_directory": "/Library/Netorch/logs",
            },
        ],
        "monitors": [
            {
                "id": "workload",
                "role": "workload",
                "check_argv": ["/operator/tools/manager", "probe", "--service", "camera"],
                "recovery_argv": ["/operator/tools/manager", "start", "--service", "camera"],
                "timeout_seconds": 5,
                "cycles": 2,
                "recovery_code": 42,
            }
        ],
        "monit_interval_seconds": 10,
        "launchctl": "/bin/launchctl",
        "monit": "/operator/tools/monit",
    }


def with_class(index: int, value: Any) -> dict[str, Any]:
    changed = fixed()
    changed["jobs"][index]["process_type"] = value
    return changed


def plists(value: dict[str, Any]) -> dict[str, bytes]:
    """Each job's plist, rendered into the fixed release directory of its scope."""
    deployment = parse_deployment(canonical_bytes(value))
    rendered: dict[str, bytes] = {}
    for job in deployment.jobs:
        installation = deployment.installation(job.scope)
        rendered[job.label] = implementation._launchd(
            job, Path(installation.directory) / "releases" / RELEASE, installation.state_directory
        )
    return rendered


def bundle_of(
    value: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str = "bundle"
) -> dict[str, Any]:
    """Render the complete bundle; the two source files are served from memory."""
    read = implementation._read_file

    def captured(path: Path, **kwargs: Any) -> bytes:
        return SOURCES[str(path)] if str(path) in SOURCES else read(path, **kwargs)

    monkeypatch.setattr(implementation, "_read_file", captured)
    output = tmp_path / name
    result = render_bundle(
        parse_deployment(canonical_bytes(value)), parse_config(canonical_bytes(POLICY)), output
    )
    assert validate_bundle(output)["bundle_digest"] == result["bundle_digest"]
    return result


def bundle_plists(result: dict[str, Any]) -> dict[str, str]:
    return {
        record["path"]: record["sha256"]
        for record in result["files"]
        if "/launchd/" in record["path"]
    }


def test_manifest_without_the_member_keeps_its_canonical_form_and_digest() -> None:
    value = fixed()
    canonical = deployment_to_dict(parse_deployment(canonical_bytes(value)))
    assert canonical_bytes(canonical) == canonical_bytes(value)
    assert all("process_type" not in job for job in canonical["jobs"])
    assert digest(canonical) == DIGEST_BEFORE


def test_manifest_without_the_member_renders_the_plist_bytes_it_rendered_before() -> None:
    rendered = plists(fixed())
    assert {
        label: hashlib.sha256(payload).hexdigest() for label, payload in rendered.items()
    } == PLISTS_BEFORE
    assert plistlib.loads(rendered["netorch-supervisor"]) == {
        "Label": "netorch-supervisor",
        "ProgramArguments": [
            "/operator/tools/monit",
            "-I",
            "-c",
            f"/operator/install/netorch/releases/{RELEASE}/monit/monitrc",
        ],
        "WorkingDirectory": f"/operator/install/netorch/releases/{RELEASE}",
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "Umask": 0o077,
        "ThrottleInterval": 10,
        "StandardOutPath": "/operator/state/netorch/logs/netorch-supervisor.out.log",
        "StandardErrorPath": "/operator/state/netorch/logs/netorch-supervisor.err.log",
        "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"},
    }


def test_manifest_without_the_member_keeps_its_release_identifier_and_bundle_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = bundle_of(fixed(), tmp_path, monkeypatch)
    assert result["release_id"] == RELEASE_ID_BEFORE
    assert result["bundle_digest"] == BUNDLE_DIGEST_BEFORE
    assert bundle_plists(result) == BUNDLE_PLISTS_BEFORE
    assert all("process_type" not in job for job in result["deployment"]["jobs"])


@pytest.mark.parametrize("index", [COORDINATOR, SUPERVISOR, FORWARDING])
def test_standard_changes_one_string_in_the_plist_of_that_job_only(index: int) -> None:
    before = plists(fixed())
    rendered = plists(with_class(index, "standard"))
    label = fixed()["jobs"][index]["label"]
    old, new = b"<string>Background</string>", b"<string>Standard</string>"
    assert before[label].count(old) == 1 and new not in before[label]
    assert rendered[label] == before[label].replace(old, new)
    assert plistlib.loads(rendered[label])["ProcessType"] == "Standard"
    for other in set(before) - {label}:
        assert rendered[other] == before[other]
        assert plistlib.loads(rendered[other])["ProcessType"] == "Background"


def test_standard_is_part_of_the_canonical_form_and_of_every_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = with_class(SUPERVISOR, "standard")
    canonical = deployment_to_dict(parse_deployment(canonical_bytes(value)))
    assert canonical_bytes(canonical) == canonical_bytes(value)
    assert [job.get("process_type") for job in canonical["jobs"]] == [None, "standard", None]
    assert digest(canonical) != DIGEST_BEFORE
    other = deployment_to_dict(
        parse_deployment(canonical_bytes(with_class(COORDINATOR, "standard")))
    )
    assert digest(other) not in {digest(canonical), DIGEST_BEFORE}
    result = bundle_of(value, tmp_path, monkeypatch)
    assert result["release_id"] != RELEASE_ID_BEFORE
    assert result["bundle_digest"] != BUNDLE_DIGEST_BEFORE
    assert result["deployment"]["jobs"][SUPERVISOR]["process_type"] == "standard"
    # The release directory is part of every plist, so all three differ from the
    # default bundle's; only the supervisor's carries the other class.
    assert not set(bundle_plists(result).values()) & set(BUNDLE_PLISTS_BEFORE.values())


@pytest.mark.parametrize("indexes", [(COORDINATOR,), (FORWARDING,), (0, 1, 2)])
def test_background_written_out_is_the_same_manifest_as_leaving_it_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, indexes: tuple[int, ...]
) -> None:
    value = fixed()
    for index in indexes:
        value["jobs"][index]["process_type"] = "background"
    deployment = parse_deployment(canonical_bytes(value))
    assert deployment == parse_deployment(canonical_bytes(fixed()))
    canonical = deployment_to_dict(deployment)
    # One canonical form, so one release and one digest for the two spellings.
    assert canonical_bytes(canonical) == canonical_bytes(fixed())
    assert digest(canonical) == DIGEST_BEFORE
    assert {
        label: hashlib.sha256(payload).hexdigest() for label, payload in plists(value).items()
    } == PLISTS_BEFORE
    result = bundle_of(value, tmp_path, monkeypatch)
    assert result["release_id"] == RELEASE_ID_BEFORE
    assert result["bundle_digest"] == BUNDLE_DIGEST_BEFORE


@pytest.mark.parametrize(
    "value",
    [
        None,
        "Background",
        "Standard",
        "STANDARD",
        "interactive",
        "adaptive",
        "",
        " standard",
        "standard ",
        True,
        0,
        1,
        ["standard"],
        {"class": "standard"},
    ],
)
@pytest.mark.parametrize("index", [COORDINATOR, FORWARDING])
def test_member_takes_two_values_and_nothing_else(index: int, value: Any) -> None:
    with pytest.raises(DeploymentError, match="closed schema"):
        parse_deployment(canonical_bytes(with_class(index, value)))


def test_model_built_directly_cannot_carry_another_class() -> None:
    deployment = parse_deployment(canonical_bytes(fixed()))
    assert [job.process_type for job in deployment.jobs] == ["background"] * 3
    for accepted in ("background", "standard"):
        job: Job = replace(deployment.jobs[0], process_type=accepted)
        validate_deployment(replace(deployment, jobs=(job, *deployment.jobs[1:])))
    others: list[Any] = ["interactive", "Background", None, True]
    for refused in others:
        job = replace(deployment.jobs[0], process_type=refused)
        with pytest.raises(DeploymentError, match="closed schema"):
            validate_deployment(replace(deployment, jobs=(job, *deployment.jobs[1:])))


@pytest.mark.parametrize("scope", ["user", "root"])
def test_bundle_with_standard_installs_and_rolls_back_to_the_default(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None, scope: str
) -> None:
    index = 0 if scope == "user" else 1
    label = manifest["jobs"][index]["label"]
    installed = Path(manifest[scope]["launchd_directory"]) / f"{label}.plist"
    state = Path(manifest[scope]["state_directory"])
    tools = FakeTools()
    plain, before = make_bundle(tmp_path, manifest, config, "plain")
    install_bundle(plain, scope, expected_digest=before["bundle_digest"], runner=tools)
    assert plistlib.loads(installed.read_bytes())["ProcessType"] == "Background"
    # A receipt written without the member is the predecessor of the upgrade.
    assert "process_type" not in str(Store(state).read("installation-receipt.json"))

    chosen = copy.deepcopy(manifest)
    chosen["jobs"][index]["process_type"] = "standard"
    bundle, metadata = make_bundle(tmp_path, chosen, config, "chosen")
    assert metadata["release_id"] != before["release_id"]
    assert validate_bundle(bundle)["bundle_digest"] == metadata["bundle_digest"]
    result = install_bundle(bundle, scope, expected_digest=metadata["bundle_digest"], runner=tools)
    assert result["phase"] == "committed"
    assert plistlib.loads(installed.read_bytes())["ProcessType"] == "Standard"
    receipt = Store(state).read("installation-receipt.json")
    assert [job.get("process_type") for job in receipt["deployment"]["jobs"]] == [
        "standard" if position == index else None for position in range(2)
    ]

    rollback_install(state, scope, expected_current_digest=metadata["bundle_digest"], runner=tools)
    assert plistlib.loads(installed.read_bytes())["ProcessType"] == "Background"
    assert installed.read_bytes() == (plain / scope / "launchd" / f"{label}.plist").read_bytes()


def test_class_cannot_be_edited_into_a_bundle_whose_manifest_does_not_ask_for_it(
    tmp_path: Path, manifest: dict[str, Any], config: Any
) -> None:
    bundle, metadata = make_bundle(tmp_path, manifest, config)
    name = f"user/launchd/{manifest['jobs'][0]['label']}.plist"
    edited = (
        (bundle / name)
        .read_bytes()
        .replace(b"<string>Background</string>", b"<string>Standard</string>")
    )
    (bundle / name).write_bytes(edited)
    record = next(item for item in metadata["files"] if item["path"] == name)
    record.update(sha256=hashlib.sha256(edited).hexdigest(), bytes=len(edited))
    metadata["bundle_digest"] = digest(
        {key: item for key, item in metadata.items() if key != "bundle_digest"}
    )
    (bundle / "manifest.json").write_bytes(canonical_bytes(metadata))
    with pytest.raises(DeploymentError, match="launchd definition differs"):
        validate_bundle(bundle)

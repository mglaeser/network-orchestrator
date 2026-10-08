"""A periodic job cannot declare an interval below the throttle of its launchd job.

Every generated job is rendered with ``ThrottleInterval``, and launchd does not
start a job more often than its throttle. The manifest used to admit a job
``interval_seconds`` from 5: such a job, and a forwarding owner whose settings
must name the same interval, was told a schedule it does not get.

The first half states the bound and that nothing else moved. The second half
states what the bound means for an installation that an earlier version made
with such an interval: this version does not read such a release as one to
keep, to upgrade or to restore, and refuses before it changes anything. The one
record it still reads is that of a release whose upgrade failed over a valid
release: recovery restores the valid release and takes from the failed one's
record only the boundaries it compares.
"""

from __future__ import annotations

import ast
import contextlib
import copy
import hashlib
import plistlib
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import netorch.cli as cli
import netorch.deployment as implementation
import netorch.deployment_config as rules
from netorch.codec import canonical_bytes, digest, strict_loads
from netorch.deployment import validate_bundle
from netorch.deployment_config import (
    DeploymentError,
    deployment_to_dict,
    load_deployment,
    parse_deployment,
    validate_deployment,
)
from netorch.deployment_model import Job
from netorch.safety_contract import LAUNCHD_INTERVAL_FLOOR_SECONDS
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest
from tests.test_deployment_interrupted_install import Killed, Steps, no_flush, stepped, wipe
from tests.test_deployment_unreached_checks import Lab, write_settings

__all__ = ["config", "fake_platform", "manifest", "no_flush"]

REPOSITORY = Path(__file__).resolve().parents[1]
SCHEMA = REPOSITORY / "schemas/deployment.schema.json"
JOURNAL = "installation-journal.json"
RECEIPT = "installation-receipt.json"
BELOW = [5, 6, 7, 8, 9]
CLOSED = "violates its closed schema"
CONSTANT = "LAUNCHD_INTERVAL_FLOOR_SECONDS"
OTHER_INSTALLATION = "recovery cannot change installation boundaries"
OTHER_FORWARDING = "recovery cannot change forwarding ownership boundaries"


def with_interval(manifest: dict[str, Any], scope: str, seconds: int | None) -> dict[str, Any]:
    """The same manifest with another interval for the periodic job of one scope."""
    value = copy.deepcopy(manifest)
    value["jobs"][0 if scope == "user" else 1]["interval_seconds"] = seconds
    return value


@pytest.mark.parametrize("scope", ["user", "root"])
@pytest.mark.parametrize("seconds", BELOW)
def test_interval_below_the_throttle_is_refused_when_the_manifest_is_parsed(
    manifest: dict[str, Any], scope: str, seconds: int
) -> None:
    with pytest.raises(DeploymentError, match=CLOSED):
        parse_deployment(canonical_bytes(with_interval(manifest, scope, seconds)))
    # A model that was built in memory is held to the same bound.
    index = 0 if scope == "user" else 1
    model = parse_deployment(canonical_bytes(manifest))
    jobs = list(model.jobs)
    jobs[index] = replace(jobs[index], interval_seconds=seconds)
    with pytest.raises(DeploymentError, match=CLOSED):
        validate_deployment(replace(model, jobs=tuple(jobs)))


@pytest.mark.parametrize("seconds", [10, 11, 60, 86400, None])
def test_interval_from_the_throttle_upward_and_a_job_without_interval_still_parse(
    manifest: dict[str, Any], seconds: int | None
) -> None:
    parsed = parse_deployment(canonical_bytes(with_interval(manifest, "user", seconds)))
    assert parsed.jobs[0].interval_seconds == seconds


def test_upper_bound_of_the_interval_is_where_it_was(manifest: dict[str, Any]) -> None:
    with pytest.raises(DeploymentError, match=CLOSED):
        parse_deployment(canonical_bytes(with_interval(manifest, "user", 86401)))


def test_command_line_refuses_the_manifest_with_its_closed_diagnostic(
    tmp_path: Path, manifest: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "deployment.json"
    source.write_bytes(canonical_bytes(with_interval(manifest, "user", 9)))
    assert cli.main(["deploy", "validate", "--manifest", str(source)]) == 65
    assert strict_loads(capsys.readouterr().out)["error"] == "invalid-or-unverified"
    source.write_bytes(canonical_bytes(with_interval(manifest, "user", 10)))
    assert cli.main(["deploy", "validate", "--manifest", str(source)]) == 0
    assert strict_loads(capsys.readouterr().out)["valid"] is True


def test_schema_minimum_is_the_throttle_every_job_is_rendered_with(
    tmp_path: Path, manifest: dict[str, Any], config: Any
) -> None:
    interval = strict_loads(SCHEMA.read_bytes())["$defs"]["job"]["properties"]["interval_seconds"]
    assert interval["oneOf"][1]["minimum"] == LAUNCHD_INTERVAL_FLOOR_SECONDS
    daemon = dict(manifest["jobs"][0])
    daemon.update(
        label=daemon["label"] + "-daemon",
        role="existing-manager",
        argv=["/protected/tool", "serve"],
        interval_seconds=None,
        keep_alive=True,
    )
    manifest["jobs"].append(daemon)
    bundle, _ = make_bundle(tmp_path, manifest, config)
    rendered = [plistlib.loads(path.read_bytes()) for path in sorted(bundle.glob("*/launchd/*"))]
    assert len(rendered) == 3
    for job in rendered:
        assert job["ThrottleInterval"] == LAUNCHD_INTERVAL_FLOOR_SECONDS
        assert job.get("StartInterval", job["ThrottleInterval"]) >= job["ThrottleInterval"]


def test_refusal_and_rendering_read_one_constant_and_no_second_literal(
    manifest: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Parser and renderer import the name from the module that defines it, and
    # neither binds it a second time (syntax only, as the registry tests read).
    for module in ("deployment.py", "deployment_config.py"):
        source = REPOSITORY / "src/netorch" / module
        tree = ast.parse(source.read_bytes(), filename=str(source))
        imported = [
            (node.module, node.level, alias.asname)
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
            if alias.name == CONSTANT
        ]
        assert imported == [("safety_contract", 1, None)], module
        assert not [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and node.id == CONSTANT
            and isinstance(node.ctx, ast.Store)
        ], module
    job = parse_deployment(canonical_bytes(manifest)).jobs[0]
    slower = with_interval(manifest, "root", 15)
    # Move the constant where the schema file does not follow.
    monkeypatch.setattr(rules, CONSTANT, 15, raising=False)
    monkeypatch.setattr(implementation, CONSTANT, 15, raising=False)
    for seconds in (10, 14):
        with pytest.raises(DeploymentError, match="shorter than the throttle"):
            parse_deployment(canonical_bytes(with_interval(slower, "user", seconds)))
        # The root job is held to the same constant.
        with pytest.raises(DeploymentError, match="shorter than the throttle"):
            parse_deployment(
                canonical_bytes(with_interval(with_interval(manifest, "user", 15), "root", seconds))
            )
    assert parse_deployment(canonical_bytes(with_interval(slower, "user", 15)))
    rendered = plistlib.loads(
        implementation._launchd(job, Path("/operator/netorch/releases/reviewed"), "/operator/state")
    )
    assert rendered["ThrottleInterval"] == 15


def test_generated_job_bytes_are_those_of_the_earlier_renderer() -> None:
    label = ".".join(["org", "example", "netorch"])
    periodic = Job(
        label,
        "user",
        "coordinator",
        (
            "/protected/python",
            "-m",
            "netorch",
            "reconcile",
            "--config",
            "{release}/data/network.json",
            "--state-dir",
            "{state}",
        ),
        10,
        False,
        "{release}",
        "/operator/logs",
    )
    daemon = Job(
        label + "-daemon",
        "user",
        "existing-manager",
        ("/protected/tool", "serve"),
        None,
        True,
        "{state}",
        "/operator/logs",
    )
    # SHA-256 of what the renderer wrote for these two jobs before the bound.
    for job, size, expected in (
        (periodic, 1229, "b8062dbb11a58590efde89680d7fc7c65a90aee1f5ed2e97f1aa2acb95b2d189"),
        (daemon, 990, "110aad9b03323854ed9f4dc5e351647941c9806feefba395b57edd8366b54303"),
    ):
        payload = implementation._launchd(
            job, Path("/operator/netorch/releases/reviewed"), "/operator/state"
        )
        assert (len(payload), hashlib.sha256(payload).hexdigest()) == (size, expected)


def test_example_manifest_keeps_its_canonical_form() -> None:
    example = load_deployment(REPOSITORY / "examples/deployment.json")
    assert {job.interval_seconds for job in example.jobs} == {10, None}
    # The digest of its canonical form before the bound.
    assert (
        digest(deployment_to_dict(example))
        == "9908b141addbe7f3b1a3f7b6190b3af5caa4cb70e2e81e92bdd9b4551ef5c1bb"
    )


@pytest.mark.parametrize("seconds", BELOW)
def test_forwarding_owner_cannot_be_bound_to_an_interval_below_the_throttle(
    tmp_path: Path, manifest: dict[str, Any], config: Any, seconds: int
) -> None:
    # The owner's own settings still admit the interval; no deployment can carry it.
    write_settings(manifest, interval_seconds=seconds)
    with pytest.raises(DeploymentError, match="one authoritative polling interval"):
        make_bundle(tmp_path, manifest, config)
    with pytest.raises(DeploymentError, match=CLOSED):
        make_bundle(tmp_path, with_interval(manifest, "root", seconds), config)
    assert not (tmp_path / "bundle").exists()


# What an earlier version left behind, and what this version does with it.


@contextlib.contextmanager
def earlier_rules(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The manifest rules of the versions that admitted an interval from 5."""
    schema = strict_loads(SCHEMA.read_bytes())
    schema["$defs"]["job"]["properties"]["interval_seconds"]["oneOf"][1]["minimum"] = 5

    def shape(value: Any) -> None:
        if list(Draft202012Validator(schema).iter_errors(value)):
            raise DeploymentError("deployment manifest violates its closed schema")

    with monkeypatch.context() as patch:
        patch.setattr(rules, "_shape", shape)
        patch.setattr(rules, "LAUNCHD_INTERVAL_FLOOR_SECONDS", 5, raising=False)
        yield


def earlier_lab(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    scope: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Lab:
    """Two bundles of one scope: the older one declares 7 seconds, the newer one is valid."""
    if scope == "root":
        write_settings(manifest, interval_seconds=7)
    old = with_interval(manifest, scope, 7)
    with earlier_rules(monkeypatch):
        lab = Lab(tmp_path, old, config, scope)
    if scope == "root":
        # The valid successor names an interval launchd gives, in job and settings.
        write_settings(manifest, interval_seconds=10)
        newer = with_interval(manifest, scope, 10)
        newer["jobs"][1]["log_directory"] += "-v2"
        lab.second, lab.new = make_bundle(tmp_path, newer, config, "valid")
    return lab


@pytest.fixture(params=["user", "root"])
def earlier(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> Lab:
    return earlier_lab(tmp_path, manifest, config, request.param, monkeypatch)


def test_earlier_version_rendered_such_a_job_with_the_same_throttle(earlier: Lab) -> None:
    label = earlier.old["deployment"]["jobs"][0 if earlier.scope == "user" else 1]["label"]
    job = plistlib.loads(
        (earlier.first / earlier.scope / "launchd" / f"{label}.plist").read_bytes()
    )
    assert (job["StartInterval"], job["ThrottleInterval"]) == (7, 10)
    # Its bundle is no longer read.
    with pytest.raises(DeploymentError, match=CLOSED):
        validate_bundle(earlier.first, earlier.old["bundle_digest"])
    assert validate_bundle(earlier.second, earlier.new["bundle_digest"])


def test_installed_release_with_such_an_interval_cannot_be_upgraded_or_rolled_back(
    earlier: Lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    with earlier_rules(monkeypatch):
        earlier.install("old")
    # The current receipt is not read, so neither command changes anything.
    earlier.refused(lambda: earlier.install("new"), CLOSED)
    earlier.refused(lambda: earlier.rollback(earlier.old["bundle_digest"]), CLOSED)


def test_failed_upgrade_over_such_a_release_cannot_be_recovered(
    earlier: Lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    with earlier_rules(monkeypatch):
        earlier.install("old")
        earlier.fail_install("new")
    assert earlier.read(JOURNAL)["phase"] == "failed"
    earlier.refused(earlier.recover, CLOSED)
    # The version that accepted the interval still recovers it.
    with earlier_rules(monkeypatch):
        assert earlier.recover()["release_id"] == earlier.old["release_id"]


def test_failed_first_installation_of_such_a_release_cannot_be_recovered(
    earlier: Lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    with earlier_rules(monkeypatch):
        earlier.fail_install("old")
    earlier.refused(lambda: earlier.recover(earlier.old["bundle_digest"]), CLOSED)


def test_valid_release_installed_before_the_upgrade_is_managed_but_not_rolled_back(
    earlier: Lab, tmp_path: Path, config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The migration: with the earlier version, install a release that declares
    # 10 seconds or more. Only then does this version read the receipt.
    with earlier_rules(monkeypatch):
        earlier.install("old")
        earlier.install("new")
    receipt = earlier.read(RECEIPT)
    assert receipt["bundle_digest"] == earlier.new["bundle_digest"]
    assert receipt["previous"]["bundle_digest"] == earlier.old["bundle_digest"]
    # Its predecessor is the release this version does not read.
    earlier.refused(earlier.rollback, CLOSED)
    assert earlier.install("new") == {"phase": "unchanged", "release_id": earlier.new["release_id"]}
    third = copy.deepcopy(earlier.new["deployment"])
    third["jobs"][0 if earlier.scope == "user" else 1]["log_directory"] += "-next"
    bundle, metadata = make_bundle(tmp_path, strict_loads(canonical_bytes(third)), config, "third")
    result = implementation.install_bundle(
        bundle, earlier.scope, expected_digest=metadata["bundle_digest"], runner=earlier.tools
    )
    assert result["phase"] == "committed"
    assert earlier.read(RECEIPT)["previous"]["bundle_digest"] == earlier.new["bundle_digest"]
    # From here every release on record is one this version reads.
    assert earlier.rollback(metadata["bundle_digest"])["release_id"] == earlier.new["release_id"]


# An upgrade to such a release that failed over a valid release is recovered.


def later_lab(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    scope: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Lab:
    """Two bundles of one scope: a valid release, and a newer one that declares 7 seconds."""
    lab = Lab(tmp_path, with_interval(manifest, scope, 10), config, scope)
    if scope == "root":
        write_settings(manifest, interval_seconds=7)
    with earlier_rules(monkeypatch):
        lab.second, lab.new = make_bundle(
            tmp_path, with_interval(manifest, scope, 7), config, "seven"
        )
    return lab


@pytest.fixture(params=["user", "root"])
def later(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> Lab:
    return later_lab(tmp_path, manifest, config, request.param, monkeypatch)


def apart_from_the_journal(lab: Lab) -> dict[str, Any]:
    """The receipt and the job files as bytes, the loaded jobs, and what durable intent says."""
    records = lab.records()
    records["state"].pop(JOURNAL, None)
    if "intent.json" in records["state"]:
        # Every change of the record counts its revision; what it says is compared.
        intent = strict_loads(records["state"].pop("intent.json"))
        records["intent"] = {key: value for key, value in intent.items() if key != "revision"}
    return records


def test_failed_upgrade_to_such_a_release_is_recovered_to_the_valid_release_under_it(
    later: Lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    later.install("old")
    before = apart_from_the_journal(later)
    with earlier_rules(monkeypatch):
        later.fail_install("new")
    journal = later.read(JOURNAL)
    assert (journal["phase"], journal["failed_phase"]) == ("failed", "starting-jobs")
    index = 0 if later.scope == "user" else 1
    assert journal["deployment"]["jobs"][index]["interval_seconds"] == 7
    assert apart_from_the_journal(later) != before
    # This version does not read the failed release as a release ...
    with pytest.raises(DeploymentError, match=CLOSED):
        validate_bundle(later.second, later.new["bundle_digest"])
    # ... and restores the valid one under it, byte for byte.
    result = later.recover()
    assert (result["phase"], result["release_id"]) == ("rolled-back", later.old["release_id"])
    assert result["retained_failed_release"] == later.new["release_id"]
    assert apart_from_the_journal(later) == before
    assert later.read(JOURNAL)["phase"] == "rolled-back"


@pytest.mark.parametrize("scope", ["user", "root"])
def test_upgrade_to_such_a_release_stopped_at_any_step_is_recovered_to_the_valid_release(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
    no_flush: None,
    scope: str,
) -> None:
    lab = later_lab(tmp_path, manifest, config, scope, monkeypatch)
    sources = {entry.name for entry in tmp_path.iterdir()}

    def attempt(steps: Steps) -> None:
        with (
            earlier_rules(monkeypatch),
            stepped(monkeypatch, steps, lab.state_dir, lab.tools) as counted,
        ):
            lab.install("new", counted)

    def prepare() -> None:
        wipe(tmp_path, sources)
        lab.tools = FakeTools()
        lab.install("old")

    prepare()
    counter = Steps()
    attempt(counter)
    assert counter.count > 15
    phases: set[str] = set()
    for step in range(counter.count):
        prepare()
        before, closed = apart_from_the_journal(lab), lab.read(JOURNAL)
        with pytest.raises(Killed):
            attempt(Steps(step))
        journal = lab.read(JOURNAL)
        if journal != closed:
            phases.add(journal["phase"])
            assert lab.recover()["release_id"] == lab.old["release_id"], step
            assert lab.read(JOURNAL)["phase"] == "rolled-back", step
        elif apart_from_the_journal(lab) != before:
            # Only the user suspension was written.
            assert lab.recover()["phase"] == "hold-released", step
        assert apart_from_the_journal(lab) == before, step
    # Both records recovery reads the failed release from were met: the
    # journal's own while the release was staged, the retained manifest after.
    assert {"staging", "starting-jobs"} <= phases


def stopped_while_staging(lab: Lab, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stop the upgrade after its first release file; recovery then reads the journal's record."""
    lab.install("old")
    with (
        earlier_rules(monkeypatch),
        stepped(monkeypatch, Steps(3), lab.state_dir, lab.tools) as counted,
        pytest.raises(Killed),
    ):
        lab.install("new", counted)
    journal: dict[str, Any] = lab.read(JOURNAL)
    assert journal["phase"] == "staging"
    return journal


def other_directory(record: dict[str, Any], scope: str) -> None:
    record[scope]["launchd_directory"] += "-other"


def extra_member(record: dict[str, Any], scope: str) -> None:
    record[scope]["extra"] = record[scope]["domain"]


def missing_member(record: dict[str, Any], scope: str) -> None:
    del record[scope]["domain"]


def not_an_object(record: dict[str, Any], scope: str) -> None:
    record[scope] = record[scope]["directory"]


@pytest.mark.parametrize(
    "change", [other_directory, extra_member, missing_member, not_an_object, None]
)
def test_recovery_still_requires_the_failed_record_to_show_the_same_installation(
    later: Lab, monkeypatch: pytest.MonkeyPatch, no_flush: None, change: Any
) -> None:
    journal = stopped_while_staging(later, monkeypatch)
    damaged = copy.deepcopy(journal)
    if change is None:
        damaged["deployment"] = None
    else:
        change(damaged["deployment"], later.scope)
    later.write(JOURNAL, damaged)
    later.refused(later.recover, OTHER_INSTALLATION)
    # With the record as the installer wrote it the same command recovers.
    later.write(JOURNAL, journal)
    assert later.recover()["release_id"] == later.old["release_id"]


@pytest.mark.parametrize("change", ["other-directory", "not-an-object", "absent"])
def test_recovery_still_requires_the_failed_record_to_show_the_same_forwarding_directory(
    later: Lab, monkeypatch: pytest.MonkeyPatch, no_flush: None, change: str
) -> None:
    journal = stopped_while_staging(later, monkeypatch)
    damaged = copy.deepcopy(journal)
    if change == "other-directory":
        damaged["deployment"]["forwarding"]["directory"] += "-other"
    elif change == "not-an-object":
        damaged["deployment"]["forwarding"] = damaged["deployment"]["forwarding"]["directory"]
    else:
        del damaged["deployment"]["forwarding"]
    later.write(JOURNAL, damaged)
    if later.scope == "root":
        later.refused(later.recover, OTHER_FORWARDING)
        later.write(JOURNAL, journal)
    # The user scope does not own that directory and never compared it.
    assert later.recover()["release_id"] == later.old["release_id"]

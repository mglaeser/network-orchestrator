"""Rollback refuses before any effect what an installation refuses for a new job.

A job that only the predecessor has is new to the current installation. An
installation checks a new job twice before it stops anything: a file of its
name in the launchd directory is not an owned artifact, and a label of its
name that launchd does not report absent is not an owned job. Rollback restored
such a job without either check, and without a receipt it ended in
``FileNotFoundError``.

Every refusal here is required to leave the journal, the receipt, durable
intent, the job files and the loaded jobs as they were. The file refusals call
no tool at all; the label refusal calls ``launchctl print`` for that label and
nothing else.
"""

from __future__ import annotations

import copy
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch.deployment import rollback_install
from netorch.deployment_config import DeploymentError
from netorch.process import ProcessTimeout, Result
from netorch.state import Intent, intent_to_dict
from tests.test_deployment import config, fake_platform, make_bundle, manifest
from tests.test_deployment_bootout_wait import Launchd as LingeringLaunchd
from tests.test_deployment_unreached_checks import Lab, failing

__all__ = ["config", "fake_platform", "manifest"]

JOURNAL = "installation-journal.json"
RECEIPT = "installation-receipt.json"
NO_RECEIPT = "rollback requires an installation receipt"
# The two refusals of an installation, word for word.
NOT_OWNED = "existing launchd file is not an unchanged owned artifact"
NOT_ABSENT = "launchd label is present or unknown without owned installation evidence"
Runner = Callable[[tuple[str, ...]], Result]


def older(manifest: dict[str, Any], scope: str) -> dict[str, Any]:
    """The predecessor. In user scope it has a second job that the current release lacks."""
    value = copy.deepcopy(manifest)
    if scope == "user":
        extra = copy.deepcopy(value["jobs"][0])
        extra.update(
            label=extra["label"] + "-before",
            role="existing-manager",
            argv=["/protected/tool", "serve"],
            interval_seconds=None,
            keep_alive=True,
        )
        value["jobs"].append(extra)
    return value


def current(manifest: dict[str, Any], scope: str) -> dict[str, Any]:
    """The current release. In root scope its one job has another label than before."""
    value = copy.deepcopy(manifest)
    if scope == "user":
        value["jobs"][0]["interval_seconds"] = 15
    else:
        value["jobs"][1]["label"] += "-next"
        value["jobs"][1]["log_directory"] += "-next"
    return value


def lab_of(tmp_path: Path, manifest: dict[str, Any], config: Any, scope: str) -> Lab:
    lab = Lab(tmp_path, older(manifest, scope), config, scope)
    lab.second, lab.new = make_bundle(tmp_path, current(manifest, scope), config, "current")
    return lab


@pytest.fixture(params=["user", "root"])
def lab(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
) -> Lab:
    return lab_of(tmp_path, manifest, config, request.param)


def only_before(lab: Lab) -> str:
    """The label of the job that the predecessor has and the current release lacks."""
    now = {job["label"] for job in lab.new["deployment"]["jobs"] if job["scope"] == lab.scope}
    (label,) = [
        job["label"]
        for job in lab.old["deployment"]["jobs"]
        if job["scope"] == lab.scope and job["label"] not in now
    ]
    return str(label)


def read_of(lab: Lab, label: str) -> tuple[str, ...]:
    return (lab.manifest["launchctl"], "print", f"{lab.manifest[lab.scope]['domain']}/{label}")


def reviewed(lab: Lab, label: str) -> bytes:
    """The predecessor's own bytes for this job, from its retained release."""
    return (lab.release(lab.old) / "launchd" / f"{label}.plist").read_bytes()


def rollback(lab: Lab, runner: Runner) -> dict[str, Any]:
    return rollback_install(
        lab.state_dir, lab.scope, expected_current_digest=lab.new["bundle_digest"], runner=runner
    )


def refused_after_reading(lab: Lab, call: Callable[[], Any], message: str, label: str) -> None:
    """Refused with this message; the one tool call read this label; nothing changed."""
    before = lab.records()
    lab.tools.calls.clear()
    with pytest.raises(DeploymentError, match=message):
        call()
    assert lab.tools.calls == [read_of(lab, label)]
    assert lab.records() == before


def failing_for(lab: Lab, label: str, verb: str) -> Runner:
    """Fail the `bootstrap` of this label, or the read that follows its `bootstrap`."""
    loaded: list[str] = []

    def runner(argv: tuple[str, ...]) -> Result:
        if argv[1] == "bootstrap" and Path(argv[-1]).stem == label:
            if verb == "bootstrap":
                lab.tools.calls.append(argv)
                return Result(1, b"", b"")
            loaded.append(label)
        elif verb == "print" and argv == read_of(lab, label) and loaded:
            lab.tools.calls.append(argv)
            return Result(1, b"", b"")
        return lab.tools(argv)

    return runner


# Without a receipt there is nothing to roll back.


@pytest.mark.parametrize(
    "left", ["recovered-first-installation", "receipt-removed", "failed-rollback"]
)
def test_rollback_without_a_receipt_is_a_closed_refusal_before_any_effect(
    lab: Lab, left: str
) -> None:
    if left == "recovered-first-installation":
        lab.fail_install("old")
        lab.recover(lab.old["bundle_digest"])
        assert lab.read(JOURNAL)["phase"] == "rolled-back"
        expected = lab.old["bundle_digest"]
    else:
        lab.install("old")
        lab.install("new")
        if left == "failed-rollback":
            with pytest.raises(DeploymentError, match="managed tool operation failed"):
                rollback(lab, failing(lab.tools, "bootstrap"))
            assert lab.read(JOURNAL)["failed_phase"] == "rolling-back"
        (lab.state_dir / RECEIPT).unlink()
        expected = lab.new["bundle_digest"]
    assert not (lab.state_dir / RECEIPT).exists()
    lab.refused(lambda: lab.rollback(expected), NO_RECEIPT)


def test_open_installation_journal_is_refused_first_as_before(lab: Lab) -> None:
    lab.fail_install("old")
    assert not (lab.state_dir / RECEIPT).exists()
    lab.refused(
        lambda: lab.rollback(lab.old["bundle_digest"]),
        "unfinished installation needs phase-aware recovery",
    )


# A file at the name of a job that only the predecessor has.


@pytest.mark.parametrize("kind", ["foreign-bytes", "predecessor-bytes", "symbolic-link"])
def test_file_at_the_name_of_a_job_only_the_predecessor_has_refuses_the_rollback(
    lab: Lab, tmp_path: Path, kind: str
) -> None:
    lab.install("old")
    lab.install("new")
    label = only_before(lab)
    path = lab.jobs / f"{label}.plist"
    assert not path.exists() and label not in lab.tools.loaded
    if kind == "symbolic-link":
        elsewhere = tmp_path / "elsewhere.plist"
        elsewhere.write_bytes(b"another owner's job")
        path.symlink_to(elsewhere)
    else:
        # Under a committed release even the predecessor's bytes were not put
        # there by this installation: its upgrade removed that file.
        path.write_bytes(
            b"another owner's job" if kind == "foreign-bytes" else reviewed(lab, label)
        )
        path.chmod(0o600)
    lab.refused(lab.rollback, NOT_OWNED)
    assert path.is_symlink() is (kind == "symbolic-link")
    # Without the file the same command restores the predecessor.
    path.unlink()
    assert lab.rollback()["release_id"] == lab.old["release_id"]
    assert path.read_bytes() == reviewed(lab, label) and label in lab.tools.loaded


def test_link_that_leads_nowhere_at_that_name_refuses_the_rollback_too(
    lab: Lab, tmp_path: Path
) -> None:
    lab.install("old")
    lab.install("new")
    label = only_before(lab)
    path = lab.jobs / f"{label}.plist"
    nowhere = tmp_path / "nowhere.plist"
    path.symlink_to(nowhere)
    # Nothing can be read through this link: it exists only as a link.
    assert path.is_symlink() and not path.exists()
    before = {
        entry.name: entry.read_bytes()
        for entry in sorted(lab.state_dir.iterdir())
        if entry.name != "owner.lock"
    }
    loaded = set(lab.tools.loaded)
    lab.tools.calls.clear()
    with pytest.raises(DeploymentError, match=NOT_OWNED):
        lab.rollback()
    # Refused as a file is: launchd was not asked, and nothing was written.
    assert lab.tools.calls == [] and lab.tools.loaded == loaded
    assert before == {
        entry.name: entry.read_bytes()
        for entry in sorted(lab.state_dir.iterdir())
        if entry.name != "owner.lock"
    }
    assert os.readlink(path) == str(nowhere) and not nowhere.exists()
    path.unlink()
    assert lab.rollback()["release_id"] == lab.old["release_id"]
    assert path.read_bytes() == reviewed(lab, label) and not path.is_symlink()


# A label of that name that launchd does not report absent.


@pytest.mark.parametrize("status", [0, 1, 36])
def test_label_that_launchd_does_not_report_absent_refuses_the_rollback(
    lab: Lab, status: int
) -> None:
    lab.install("old")
    lab.install("new")
    label = only_before(lab)

    def answering(argv: tuple[str, ...]) -> Result:
        if argv == read_of(lab, label):
            lab.tools.calls.append(argv)
            return Result(status, b"", b"")
        return lab.tools(argv)

    refused_after_reading(lab, lambda: rollback(lab, answering), NOT_ABSENT, label)
    assert not (lab.jobs / f"{label}.plist").exists()


def test_job_of_another_owner_under_that_label_is_neither_stopped_nor_replaced(lab: Lab) -> None:
    lab.install("old")
    lab.install("new")
    label = only_before(lab)
    # Somebody else's job with this label is loaded from another place.
    lab.tools.loaded.add(label)
    refused_after_reading(lab, lab.rollback, NOT_ABSENT, label)
    assert label in lab.tools.loaded
    # Once it is gone the same command restores the predecessor.
    lab.tools.loaded.discard(label)
    assert lab.rollback()["release_id"] == lab.old["release_id"]
    assert (lab.jobs / f"{label}.plist").read_bytes() == reviewed(lab, label)


def test_label_read_that_cannot_complete_changes_nothing(lab: Lab) -> None:
    lab.install("old")
    lab.install("new")
    label = only_before(lab)

    def silent(argv: tuple[str, ...]) -> Result:
        if argv == read_of(lab, label):
            raise ProcessTimeout("bounded command timed out")
        return lab.tools(argv)

    before = lab.records()
    lab.tools.calls.clear()
    with pytest.raises(ProcessTimeout):
        rollback(lab, silent)
    assert lab.tools.calls == [] and lab.records() == before


def test_absent_file_and_absent_label_cost_one_read_before_anything_is_stopped(lab: Lab) -> None:
    lab.install("old")
    lab.install("new")
    label = only_before(lab)
    lab.tools.calls.clear()
    assert lab.rollback()["release_id"] == lab.old["release_id"]
    calls = lab.tools.calls
    assert calls[0] == read_of(lab, label) and calls[1][1] == "bootout"
    # The only other read of this label is the readback after it was loaded.
    assert calls.count(read_of(lab, label)) == 2
    assert calls[calls.index(read_of(lab, label), 1) - 1][1] == "bootstrap"
    assert label in lab.tools.loaded


@pytest.mark.parametrize("status", [3, 113])
def test_either_status_that_launchctl_gives_for_an_absent_label_lets_the_rollback_go_on(
    lab: Lab, status: int
) -> None:
    lab.install("old")
    lab.install("new")
    label = only_before(lab)
    asked: list[tuple[str, ...]] = []

    def answering(argv: tuple[str, ...]) -> Result:
        # The read before anything is stopped; the read-back after loading stays the fake's.
        if argv == read_of(lab, label) and not asked:
            asked.append(argv)
            return Result(status, b"", b"")
        return lab.tools(argv)

    assert rollback(lab, answering)["release_id"] == lab.old["release_id"]
    assert asked == [read_of(lab, label)] and label in lab.tools.loaded


def test_label_is_read_with_the_launchctl_of_the_release_that_is_restored(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    earlier = older(manifest, "user")
    # The predecessor names another launchctl than the current release.
    earlier["launchctl"] = "/protected/earlier/launchctl"
    lab = Lab(tmp_path, earlier, config, "user")
    lab.second, lab.new = make_bundle(tmp_path, current(manifest, "user"), config, "current")
    assert lab.new["deployment"]["launchctl"] == manifest["launchctl"] != earlier["launchctl"]
    lab.install("old")
    lab.install("new")
    label = only_before(lab)
    target = f"{manifest['user']['domain']}/{label}"
    lab.tools.calls.clear()
    assert lab.rollback()["release_id"] == lab.old["release_id"]
    # The tool that loads the restored job and reads it back also answers before.
    assert lab.tools.calls[0] == (earlier["launchctl"], "print", target)
    assert [call[0] for call in lab.tools.calls if call[1] == "bootstrap"] == [
        earlier["launchctl"]
    ] * 2
    # The current release's job is stopped with the current release's tool.
    assert lab.tools.calls[1][:2] == (manifest["launchctl"], "bootout")


def test_every_job_that_only_the_predecessor_has_gets_both_checks(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    earlier = older(manifest, "user")
    another = copy.deepcopy(earlier["jobs"][-1])
    another["label"] += "-too"
    earlier["jobs"].append(another)
    lab = Lab(tmp_path, earlier, config, "user")
    lab.second, lab.new = make_bundle(tmp_path, current(manifest, "user"), config, "current")
    lab.install("old")
    lab.install("new")
    first, last = (str(job["label"]) for job in earlier["jobs"][-2:])
    assert not {first, last} & {job["label"] for job in lab.new["deployment"]["jobs"]}
    # Somebody else's job under the last of the two labels: both are read, in
    # the order of the predecessor's inventory, and the second read refuses.
    lab.tools.loaded.add(last)
    before = lab.records()
    lab.tools.calls.clear()
    with pytest.raises(DeploymentError, match=NOT_ABSENT):
        lab.rollback()
    assert lab.tools.calls == [read_of(lab, first), read_of(lab, last)]
    assert lab.records() == before
    lab.tools.loaded.discard(last)
    # A file at the last label's name refuses before launchd is asked about either.
    path = lab.jobs / f"{last}.plist"
    path.write_bytes(b"another owner's job")
    path.chmod(0o600)
    lab.refused(lab.rollback, NOT_OWNED)
    path.unlink()
    assert lab.rollback()["release_id"] == lab.old["release_id"]
    assert {first, last} <= lab.tools.loaded


def test_refusal_that_needs_no_tool_comes_before_the_label_is_read(
    tmp_path: Path, manifest: dict[str, Any], config: Any, fake_platform: None
) -> None:
    lab = lab_of(tmp_path, manifest, config, "user")
    lab.install("old")
    lab.install("new")
    label = only_before(lab)
    lab.tools.loaded.add(label)
    intent = lab.read("intent.json")
    # Another holder has the installation suspension.
    lab.write("intent.json", intent_to_dict(Intent().pause().suspend("installation", "holder-a")))
    before = lab.records()
    lab.tools.calls.clear()
    with pytest.raises(ValueError, match="owned by another holder"):
        lab.rollback()
    assert lab.tools.calls == [] and lab.records() == before
    lab.write("intent.json", {"schema_version": 999})
    lab.refused(lab.rollback, "readable durable intent")
    lab.write("intent.json", intent)
    # A file that is not owned is refused without asking launchd about the label.
    (lab.jobs / f"{label}.plist").write_bytes(b"another owner's job")
    (lab.jobs / f"{label}.plist").chmod(0o600)
    lab.refused(lab.rollback, NOT_OWNED)


# A repeated rollback (its journal says that this rollback failed) may find its own work.


@pytest.mark.parametrize("stopped_at", ["bootstrap", "print"])
def test_repeated_rollback_accepts_the_file_and_the_job_its_first_attempt_left(
    lab: Lab, stopped_at: str
) -> None:
    lab.install("old")
    lab.install("new")
    label = only_before(lab)
    with pytest.raises(DeploymentError, match="managed tool operation failed"):
        rollback(lab, failing_for(lab, label, stopped_at))
    assert lab.read(JOURNAL)["failed_phase"] == "rolling-back"
    assert (lab.jobs / f"{label}.plist").read_bytes() == reviewed(lab, label)
    # The first attempt wrote the file; with `print` it also loaded the job.
    assert (label in lab.tools.loaded) is (stopped_at == "print")
    lab.tools.calls.clear()
    assert lab.rollback()["release_id"] == lab.old["release_id"]
    # Its own file is the evidence: launchd is not asked about the label first.
    assert lab.tools.calls[0][1] == "bootout"
    assert lab.read(JOURNAL)["phase"] == "rolled-back" and label in lab.tools.loaded


def test_repeated_rollback_without_its_own_file_still_refuses_a_loaded_label(lab: Lab) -> None:
    lab.install("old")
    lab.install("new")
    label = only_before(lab)
    with pytest.raises(DeploymentError, match="managed tool operation failed"):
        rollback(lab, failing(lab.tools, "bootout"))
    assert lab.read(JOURNAL)["failed_phase"] == "rolling-back"
    assert not (lab.jobs / f"{label}.plist").exists()
    # The first attempt never wrote the file, so it never loaded this label.
    lab.tools.loaded.add(label)
    refused_after_reading(lab, lab.rollback, NOT_ABSENT, label)
    assert label in lab.tools.loaded
    lab.tools.loaded.discard(label)
    assert lab.rollback()["release_id"] == lab.old["release_id"]


@pytest.mark.parametrize("found", ["foreign-bytes", "symbolic-link"])
@pytest.mark.parametrize("first_attempt", ["wrote-nothing", "wrote-the-file"])
def test_repeated_rollback_refuses_a_file_that_is_not_the_predecessors(
    lab: Lab, tmp_path: Path, first_attempt: str, found: str
) -> None:
    lab.install("old")
    lab.install("new")
    label = only_before(lab)
    path = lab.jobs / f"{label}.plist"
    broken = (
        failing(lab.tools, "bootout")
        if first_attempt == "wrote-nothing"
        else failing_for(lab, label, "bootstrap")
    )
    with pytest.raises(DeploymentError, match="managed tool operation failed"):
        rollback(lab, broken)
    assert path.exists() is (first_attempt == "wrote-the-file")
    path.unlink(missing_ok=True)
    if found == "symbolic-link":
        # Even one that leads to the predecessor's own bytes.
        elsewhere = tmp_path / "elsewhere.plist"
        elsewhere.write_bytes(reviewed(lab, label))
        elsewhere.chmod(0o600)
        path.symlink_to(elsewhere)
    else:
        path.write_bytes(b"another owner's job")
        path.chmod(0o600)
    lab.refused(lab.rollback, NOT_OWNED)
    assert lab.read(JOURNAL)["failed_phase"] == "rolling-back"
    path.unlink()
    assert lab.rollback()["release_id"] == lab.old["release_id"]
    assert path.read_bytes() == reviewed(lab, label)


# The wait after a `bootout`: a job the upgrade dropped is stopped and not waited for.


def test_job_the_upgrade_just_stopped_refuses_the_rollback_until_launchd_reports_it_gone(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(implementation, "BOOTOUT_POLL_SECONDS", 0.0)
    lab = lab_of(tmp_path, manifest, config, "user")
    launchd = LingeringLaunchd()
    lab.tools = launchd
    label = only_before(lab)
    lab.install("old")
    # From here a stopped job is still reported by the next two reads of it.
    launchd.linger = 2
    lab.install("new")
    # The upgrade does not load this job again, so it did not wait for it.
    assert launchd.leaving == {label: 2} and label not in launchd.loaded
    for _attempt in range(2):
        refused_after_reading(lab, lab.rollback, NOT_ABSENT, label)
        assert lab.read(JOURNAL)["phase"] == "committed"
    assert lab.rollback()["release_id"] == lab.old["release_id"]
    assert (lab.jobs / f"{label}.plist").read_bytes() == reviewed(lab, label)
    assert label in launchd.loaded and not launchd.leaving

"""Recovery of a failed upgrade writes the receipt back as the attempt found it.

Releases of one scope in the disposable lab of ``tests/test_deployment.py``.
The first two are installed, so the receipt names the second and, as its one
predecessor, the first. The upgrade to the third fails or is stopped, and
``recover`` is run with its digest. The receipt must then be, byte for byte,
the one the attempt found, and ``rollback`` of the second release must restore
the first.

The installation journal carries the replaced receipt. Everything else in it,
and every journal of an installation that replaces a receipt without a
predecessor, is what earlier releases wrote; a journal of an earlier release
is recovered as before.

The journal now holds one record more than before. An installation whose
journal the state store would not write is refused before anything is written.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import netorch.deployment as implementation
from netorch.codec import MAX_JSON_BYTES, canonical_bytes, strict_loads
from netorch.deployment import install_bundle, recover_install, rollback_install
from netorch.deployment_config import DeploymentError
from netorch.process import Result
from netorch.state import intent_from_dict
from netorch.storage import Store, UnsafeState
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest
from tests.test_deployment_interrupted_install import Killed, Steps, no_flush, stepped, wipe
from tests.test_deployment_rollback_reentrant import launchd
from tests.test_full_deployment import IntegratedTools, setup_forwarding

__all__ = ["config", "fake_platform", "manifest", "no_flush"]

JOURNAL = "installation-journal.json"
RECEIPT = "installation-receipt.json"
SCOPES = ["user", "root"]
TOO_LARGE = "installation journal would exceed its size bound"
Runner = Callable[[tuple[str, ...]], Result]
# Every phase an upgrade of the scope journals before it commits.
PHASES = {
    "user": {"staging", "preflight-jobs", "stopping-jobs", "installing-jobs", "starting-jobs"},
    "root": {
        "staging",
        "preflight-jobs",
        "quiescing-forwarding-owner",
        "installing-forwarding-owner",
        "stopping-jobs",
        "installing-jobs",
        "starting-jobs",
    },
}


def release(manifest: dict[str, Any], scope: str, number: int) -> dict[str, Any]:
    """One of four releases; in user scope every one but the second has a job of its own."""
    value = copy.deepcopy(manifest)
    if scope == "root":
        value["jobs"][1]["log_directory"] += f"-v{number}"
        return value
    value["jobs"][0]["interval_seconds"] = 10 + 5 * number
    if number != 1:
        extra = copy.deepcopy(value["jobs"][0])
        extra.update(
            label=f"{extra['label']}-v{number}",
            role="existing-manager",
            argv=["/protected/tool", "serve"],
            interval_seconds=None,
            keep_alive=True,
        )
        value["jobs"].append(extra)
    return value


def padded(manifest: dict[str, Any], scope: str, number: int, size: int) -> dict[str, Any]:
    """The same release with user jobs whose arguments add about this many bytes to its record."""
    value = release(manifest, scope, number)
    index = 0
    while size > 0:
        count = min(63, max(1, size // 4096))
        extra = copy.deepcopy(manifest["jobs"][0])
        extra.update(
            label=f"{extra['label']}-pad{index}",
            role="existing-manager",
            argv=["/protected/tool", *["x" * 4096] * count],
            interval_seconds=None,
            keep_alive=True,
        )
        value["jobs"].append(extra)
        size -= count * 4096
        index += 1
    return value


class Failing(Steps):
    """One step fails once; the installer's own handler sees it and records the phase."""

    def __call__(self) -> None:
        if not self.dead and self.count == self.stop_before:
            self.dead = True
            raise DeploymentError("this step failed")
        self.count += 1


class Lab:
    """Four reviewed releases of one scope and one installation that is wiped on request."""

    def __init__(
        self,
        tmp_path: Path,
        manifest: dict[str, Any],
        config: Any,
        scope: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        if scope == "root":
            setup_forwarding(manifest, monkeypatch)
        self.tmp_path = tmp_path
        self.scope = scope
        self.state_dir = Path(manifest[scope]["state_directory"])
        self.jobs = Path(manifest[scope]["launchd_directory"])
        self.owner = Path(manifest["forwarding"]["directory"])
        self.bundles = [
            make_bundle(tmp_path, release(manifest, scope, number), config, f"v{number}")
            for number in range(4)
        ]
        self.digests = [metadata["bundle_digest"] for _, metadata in self.bundles]
        self.sources = {entry.name for entry in tmp_path.iterdir()}
        self.tools: FakeTools = FakeTools()
        self.runner: Runner = self.tools

    def prepare(self, installed: int = 2) -> None:
        """An empty installation, then this many releases installed one after the other."""
        wipe(self.tmp_path, self.sources)
        self.tools = IntegratedTools() if self.scope == "root" else FakeTools()
        # launchd refuses to load a label that is still loaded.
        self.runner = launchd(self.tools)
        for number in range(installed):
            assert self.install(number)["phase"] == "committed"

    def install(self, number: int, runner: Runner | None = None) -> dict[str, Any]:
        bundle, metadata = self.bundles[number]
        return install_bundle(
            bundle,
            self.scope,
            expected_digest=metadata["bundle_digest"],
            runner=self.runner if runner is None else runner,
        )

    def broken(self, argv: tuple[str, ...]) -> Result:
        """The same tools, except that launchd loads nothing."""
        return Result(1, b"", b"") if "bootstrap" in argv else self.runner(argv)

    def fail_install(self, number: int) -> None:
        with pytest.raises(DeploymentError, match="managed tool operation failed"):
            self.install(number, self.broken)

    def attempt(self, monkeypatch: pytest.MonkeyPatch, steps: Steps, number: int = 2) -> int:
        """Install with every journal, receipt or intent write, file and tool call counted."""
        with stepped(monkeypatch, steps, self.state_dir, self.runner) as counted:
            self.install(number, counted)
        return steps.count

    def recover(self, number: int = 2, runner: Runner | None = None) -> dict[str, Any]:
        return recover_install(
            self.state_dir,
            self.scope,
            expected_failed_digest=self.digests[number],
            runner=self.runner if runner is None else runner,
        )

    def rollback(self, number: int = 1, runner: Runner | None = None) -> dict[str, Any]:
        return rollback_install(
            self.state_dir,
            self.scope,
            expected_current_digest=self.digests[number],
            runner=self.runner if runner is None else runner,
        )

    def raw(self, name: str) -> bytes:
        return (self.state_dir / name).read_bytes()

    def read(self, name: str) -> Any:
        return Store(self.state_dir).read(name)

    def holds(self) -> dict[str, str]:
        directory, name = (
            (self.state_dir, "intent.json")
            if self.scope == "user"
            else (self.owner, "operator-intent.json")
        )
        if not (directory / name).exists():
            return {}
        return dict(intent_from_dict(Store(directory).read(name)).suspensions)

    def installed(self, number: int) -> None:
        """Exactly this release's jobs are installed and loaded, with its reviewed bytes."""
        reviewed = self.bundles[number][0] / self.scope / "launchd"
        expected = {path.name: path.read_bytes() for path in sorted(reviewed.iterdir())}
        assert {path.name: path.read_bytes() for path in sorted(self.jobs.iterdir())} == expected
        assert self.tools.loaded == {Path(name).stem for name in expected}

    def rollback_restores_the_first_release(self) -> None:
        """The second release is current, and its predecessor can still be restored."""
        predecessor = self.read(RECEIPT)["previous"]
        assert predecessor["bundle_digest"] == self.digests[0]
        self.installed(1)
        assert self.rollback()["release_id"] == self.bundles[0][1]["release_id"]
        assert self.read(RECEIPT) == predecessor
        assert self.read(JOURNAL)["phase"] == "rolled-back"
        assert "installation" not in self.holds()
        self.installed(0)

    def enlarge(self, manifest: dict[str, Any], config: Any, size: int) -> list[int]:
        """Replace the first three releases by padded ones; the size of each one's record."""
        self.bundles = [
            make_bundle(self.tmp_path, padded(manifest, self.scope, number, size), config, name)
            for number, name in enumerate(("large0", "large1", "large2"))
        ]
        self.digests = [metadata["bundle_digest"] for _, metadata in self.bundles]
        self.sources = {entry.name for entry in self.tmp_path.iterdir()}
        return [len(canonical_bytes(metadata["deployment"])) for _, metadata in self.bundles]

    def everything(self) -> dict[str, Any]:
        """Every record, job file and release directory of the scope, and what is loaded."""
        releases = Path(self.bundles[0][1]["deployment"][self.scope]["directory"]) / "releases"
        return {
            "records": {
                str(path): path.read_bytes()
                for directory in (self.state_dir, self.owner, self.jobs)
                if directory.is_dir()
                for path in sorted(directory.iterdir())
                if path.is_file() and path.name != "owner.lock"
            },
            "releases": sorted(path.name for path in releases.iterdir()),
            "loaded": set(self.tools.loaded),
            "calls": len(self.tools.calls),
        }

    def earlier_journal(self, number: int, found: dict[str, Any] | None, phase: str) -> Any:
        """What earlier releases journalled for an installation that failed over this receipt."""
        _, metadata = self.bundles[number]
        return strict_loads(
            canonical_bytes(
                {
                    "schema_version": 1,
                    "phase": "failed",
                    "failed_phase": phase,
                    "scope": self.scope,
                    "release_id": metadata["release_id"],
                    "bundle_digest": metadata["bundle_digest"],
                    "previous": None if found is None else {**found, "previous": None},
                    "deployment": metadata["deployment"],
                }
            )
        )


@pytest.fixture(params=SCOPES)
def lab(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> Lab:
    return Lab(tmp_path, manifest, config, request.param, monkeypatch)


def test_recovered_upgrade_keeps_the_predecessor_of_the_release_it_restores(lab: Lab) -> None:
    lab.prepare()
    before = lab.raw(RECEIPT)
    found = strict_loads(before)
    assert found["bundle_digest"] == lab.digests[1]
    assert found["previous"]["bundle_digest"] == lab.digests[0]
    lab.fail_install(2)
    assert lab.read(JOURNAL)["failed_phase"] == "starting-jobs"
    assert lab.recover()["release_id"] == found["release_id"]
    assert lab.raw(RECEIPT) == before
    lab.rollback_restores_the_first_release()


@pytest.mark.parametrize("stop", [Killed, DeploymentError], ids=["stopped", "failed"])
def test_upgrade_stopped_or_failed_at_any_step_is_recovered_to_the_receipt_it_found(
    lab: Lab, monkeypatch: pytest.MonkeyPatch, no_flush: None, stop: type[BaseException]
) -> None:
    lab.prepare()
    total = lab.attempt(monkeypatch, Steps())
    assert total > 15
    phases: set[str] = set()
    replaced = 0
    for step in range(total):
        lab.prepare()
        before, closed = lab.raw(RECEIPT), lab.raw(JOURNAL)
        with pytest.raises(stop):
            lab.attempt(monkeypatch, Steps(step) if stop is Killed else Failing(step))
        journal = lab.read(JOURNAL)
        opened = lab.raw(JOURNAL) != closed
        if opened:
            # A stop leaves the phase it reached; a failure is recorded with its phase.
            phases.add(journal.get("failed_phase", journal["phase"]))
        replaced += lab.raw(RECEIPT) != before
        if opened or "installation" in lab.holds():
            lab.recover()
        else:
            # Nothing was written: there is nothing to recover and nothing was lost.
            with pytest.raises(DeploymentError, match="does not match a failed installation"):
                lab.recover()
        assert lab.raw(RECEIPT) == before, step
        lab.rollback_restores_the_first_release()
    assert phases >= PHASES[lab.scope]
    # The last steps come after the new receipt was written: then only the
    # journal still has the one it replaced.
    assert replaced >= 1


def test_repeated_failed_upgrades_and_a_failed_recovery_change_nothing_in_the_receipt(
    lab: Lab,
) -> None:
    lab.prepare()
    before = lab.raw(RECEIPT)
    found = strict_loads(before)
    for number in (2, 3):
        lab.fail_install(number)
        # The recovery fails once, at the job it restores, and is repeated.
        with pytest.raises(DeploymentError, match="managed tool operation failed"):
            lab.recover(number, lab.broken)
        # Every attempt journals the same single receipt, not a history.
        assert lab.read(JOURNAL)["previous"] == found
        assert lab.recover(number)["release_id"] == found["release_id"]
        assert lab.raw(RECEIPT) == before
    lab.rollback_restores_the_first_release()


def test_rollback_of_a_recovered_release_that_fails_is_repeated_to_the_first_release(
    lab: Lab,
) -> None:
    lab.prepare()
    lab.fail_install(2)
    lab.recover()
    with pytest.raises(DeploymentError, match="managed tool operation failed"):
        lab.rollback(1, lab.broken)
    journal = lab.read(JOURNAL)
    assert (journal["phase"], journal["failed_phase"]) == ("failed", "rolling-back")
    assert journal["to_bundle_digest"] == lab.digests[0]
    assert lab.rollback()["phase"] == "rolled-back"
    assert lab.read(RECEIPT)["bundle_digest"] == lab.digests[0]
    assert "installation" not in lab.holds()
    lab.installed(0)


def test_journal_of_an_upgrade_holds_the_replaced_receipt_with_its_one_predecessor(
    lab: Lab,
) -> None:
    lab.prepare()
    found = lab.read(RECEIPT)
    lab.fail_install(2)
    journal = lab.read(JOURNAL)
    assert journal["previous"] == found
    # One more level than earlier releases journalled, never a chain.
    assert journal["previous"]["previous"]["previous"] is None
    journal["previous"] = {**journal["previous"], "previous": None}
    assert journal == lab.earlier_journal(2, found, "starting-jobs")


def test_committed_upgrade_still_names_one_predecessor_and_no_history(lab: Lab) -> None:
    lab.prepare()
    second = lab.read(RECEIPT)
    assert second["previous"]["previous"] is None
    # A failed attempt and its recovery in between do not add a level either.
    lab.fail_install(2)
    lab.recover(2)
    assert lab.install(3)["phase"] == "committed"
    receipt = lab.read(RECEIPT)
    assert receipt["bundle_digest"] == lab.digests[3]
    assert receipt["previous"] == {**second, "previous": None}
    lab.installed(3)


def test_journal_of_an_earlier_release_is_recovered_as_before(lab: Lab) -> None:
    lab.prepare()
    found = lab.read(RECEIPT)
    lab.fail_install(2)
    journal = lab.read(JOURNAL)
    # Earlier releases journalled the replaced receipt without its predecessor,
    # and nothing else differs.
    earlier = lab.earlier_journal(2, found, "starting-jobs")
    assert {**journal, "previous": {**journal["previous"], "previous": None}} == earlier
    Store(lab.state_dir).write(JOURNAL, earlier)
    assert lab.recover()["release_id"] == found["release_id"]
    assert lab.read(RECEIPT) == {**found, "previous": None}
    assert lab.read(JOURNAL) == {**earlier, "phase": "rolled-back"}
    assert "installation" not in lab.holds()
    lab.installed(1)
    with pytest.raises(DeploymentError, match="first installation has no prior release"):
        lab.rollback()


@pytest.mark.parametrize("installed", [0, 1], ids=["first-installation", "first-upgrade"])
def test_installation_over_a_receipt_without_predecessor_journals_what_it_always_did(
    lab: Lab, installed: int
) -> None:
    lab.prepare(installed)
    before = lab.raw(RECEIPT) if installed else None
    found = None if before is None else strict_loads(before)
    lab.fail_install(installed)
    earlier = lab.earlier_journal(installed, found, "starting-jobs")
    assert lab.raw(JOURNAL) == canonical_bytes(earlier) + b"\n"
    lab.recover(installed)
    if before is None:
        assert not (lab.state_dir / RECEIPT).exists()
        assert not list(lab.jobs.iterdir()) and not lab.tools.loaded
    else:
        assert lab.raw(RECEIPT) == before
        lab.installed(0)


# The journal holds one record more than before: it must still fit the state store.


@pytest.mark.parametrize(
    ("lab", "size"),
    [("user", 345), ("user", 400), ("user", 480), ("root", 345)],
    indirect=["lab"],
    ids=lambda value: value if isinstance(value, str) else f"{value}KiB",
)
def test_upgrade_whose_journal_would_not_fit_is_refused_before_anything_is_written(
    lab: Lab, manifest: dict[str, Any], config: Any, size: int
) -> None:
    records = lab.enlarge(manifest, config, size * 1024)
    # Two such records fit the bound, as a receipt and as the journal of the
    # first upgrade. The journal of the second upgrade would hold three.
    assert all(2 * record < MAX_JSON_BYTES < 3 * record for record in records)
    lab.prepare()
    before = lab.everything()
    for _attempt in range(2):
        with pytest.raises(DeploymentError, match=TOO_LARGE):
            lab.install(2)
        # No suspension, no journal, no release directory and no tool call.
        assert lab.everything() == before
    assert "installation" not in lab.holds()
    with pytest.raises(DeploymentError, match="does not match a failed installation"):
        lab.recover()
    # After a rollback the receipt names no predecessor, and the journal of the
    # same upgrade holds two records again.
    assert lab.rollback()["phase"] == "rolled-back"
    assert lab.install(2)["phase"] == "committed"
    assert lab.read(RECEIPT)["previous"]["bundle_digest"] == lab.digests[0]
    lab.installed(2)


def test_three_records_that_fit_the_bound_together_are_still_upgraded(
    lab: Lab, manifest: dict[str, Any], config: Any
) -> None:
    records = lab.enlarge(manifest, config, 300 * 1024)
    assert all(record > 300_000 and 3 * record < MAX_JSON_BYTES for record in records)
    lab.prepare()
    found = lab.read(RECEIPT)
    assert lab.install(2)["phase"] == "committed"
    assert lab.read(JOURNAL)["previous"] == found
    lab.installed(2)


def test_journal_is_refused_exactly_where_the_state_store_would_refuse_one_of_its_forms(
    tmp_path: Path, no_flush: None
) -> None:
    def journal(characters: int) -> dict[str, Any]:
        """A first installation's journal whose deployment record has this much text."""
        text = ["x" * 65_536] * (characters // 65_536) + ["x" * (characters % 65_536)]
        return {
            "schema_version": 1,
            "phase": "staging",
            "scope": "user",
            "release_id": "0" * 64,
            "bundle_digest": "0" * 64,
            "previous": None,
            "deployment": {"text": text},
        }

    # Every form the installer and recovery write: an open phase or the closing
    # one alone, and after a failure or a stop the phase reached beside the
    # phase of the recovery.
    reached = [*sorted(implementation._OPEN_INSTALL_PHASES), "committed"]
    forms = [{"phase": phase} for phase in reached] + [
        {"phase": phase, "failed_phase": failed}
        for phase in ("failed", "recovering", "rolled-back")
        for failed in reached
    ]
    low, high = 900_000, MAX_JSON_BYTES
    assert implementation._journal_fits(journal(low))
    assert not implementation._journal_fits(journal(high))
    while high - low > 1:
        middle = (low + high) // 2
        if implementation._journal_fits(journal(middle)):
            low = middle
        else:
            high = middle
    store = Store(tmp_path / "state")
    # The largest journal that is accepted can be written in every form.
    for form in forms:
        store.write(JOURNAL, {**journal(low), **form})
        assert store.read(JOURNAL)["phase"] == form["phase"]
    # One more character, and the store refuses the widest of them.
    refused = 0
    for form in forms:
        try:
            store.write(JOURNAL, {**journal(high), **form})
        except (UnsafeState, ValueError):
            refused += 1
    assert refused >= 1

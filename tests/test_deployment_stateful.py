"""Stateful search over the real user-scope installer, and its findings kept readable.

One Hypothesis state machine drives ``install_bundle``, ``recover_install`` and
``rollback_install`` over a real ``Store`` in the disposable lab of
``tests/test_deployment.py``. launchctl and Monit are one fake: any single call
of a command can fail, and it remembers the bytes launchd was given. Between
commands an operator pauses and resumes, two holders take and release three
operation names (one of them the installer's own), and a retained release or
an installed job file is overwritten.

After every step the machine compares the durable records with what the
provisioning guide states:

* the operator's pause is exactly what the operator last chose;
* a suspension is released only by the holder that took it;
* the installer's own suspension exists exactly while its journal is open;
* a journal that is not closed is changed only by the command that owns it,
  and that command either completes or leaves the journal as it found it;
* launchd is only ever given job bytes of a release whose installed files are
  the reviewed ones;
* a closed journal leaves exactly the receipt's jobs installed and loaded.

The search uses one fixed seed: the same sequences run everywhere and after
every edit of this file, so a failure is a regression and not a lottery. The
functions after the machine replay the shortest sequences behind each property.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, seed, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)

from netorch.codec import canonical_bytes, digest, strict_loads
from netorch.deployment import install_bundle, recover_install, rollback_install
from netorch.process import Result
from netorch.state import Intent, intent_from_dict, intent_to_dict
from netorch.storage import Store
from tests.test_deployment import FakeTools, config, fake_platform, make_bundle, manifest

__all__ = ["config", "fake_platform", "manifest"]

# What the command line reports as a closed refusal (exit 65).
REFUSAL = (ValueError, OSError)
CLOSED = {"committed", "rolled-back"}
OPERATIONS = ("installation", "backup", "maintenance")
HOLDERS = ("holder-a", "holder-b")
JOURNAL = "installation-journal.json"
RECEIPT = "installation-receipt.json"
SEED = 8
SEARCH = settings(
    max_examples=60,
    stateful_step_count=20,
    deadline=None,
    database=None,
    suppress_health_check=list(HealthCheck),
)


def variants(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Five releases: the shared job differs in every one, three have a second job."""
    result = []
    for index, suffix in enumerate(("a", "b", None, None, "a")):
        value = strict_loads(canonical_bytes(manifest))
        value["jobs"][0]["interval_seconds"] = 10 + 5 * index
        if suffix is not None:
            extra = dict(value["jobs"][0])
            extra.update(
                label=f"{extra['label']}-{suffix}",
                role="existing-manager",
                argv=["/protected/tool", "serve"],
                interval_seconds=None,
                keep_alive=True,
            )
            value["jobs"].append(extra)
        result.append(value)
    return result


def tree(directory: Path) -> dict[str, bytes]:
    if not directory.is_dir():
        return {}
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


class Release:
    """One reviewed bundle and the bytes its user scope installs."""

    def __init__(self, bundle: Path, metadata: dict[str, Any]) -> None:
        self.bundle = bundle
        self.digest: str = metadata["bundle_digest"]
        self.release_id: str = metadata["release_id"]
        self.files = {
            record["path"].removeprefix("user/"): (bundle / record["path"]).read_bytes()
            for record in metadata["files"]
            if record["path"].startswith("user/")
        }
        self.files["bundle-manifest.json"] = canonical_bytes(metadata) + b"\n"
        self.jobs = {
            Path(name).stem: payload
            for name, payload in self.files.items()
            if name.startswith("launchd/")
        }


class Lab:
    """Five rendered bundles and one user installation that is wiped between sequences."""

    def __init__(self, tmp_path: Path, manifest: dict[str, Any], config: Any) -> None:
        self.namespace = tmp_path
        self.state_dir = Path(manifest["user"]["state_directory"])
        self.agents = Path(manifest["user"]["launchd_directory"])
        self.release_root = Path(manifest["user"]["directory"]) / "releases"
        self.releases = [
            Release(*make_bundle(tmp_path, value, config, f"bundle-{index}"))
            for index, value in enumerate(variants(manifest))
        ]
        self.by_digest = {release.digest: release for release in self.releases}
        self.sources = {entry.name for entry in tmp_path.iterdir()}

    def reset(self) -> None:
        for entry in self.namespace.iterdir():
            if entry.name not in self.sources:
                shutil.rmtree(entry)

    def directory(self, release: Release) -> Path:
        return self.release_root / release.release_id

    def require_reviewed(self, label: str, payload: bytes) -> None:
        """What launchd loads is a reviewed job of a release that is installed intact."""
        owners = [release for release in self.releases if release.jobs.get(label) == payload]
        assert owners, f"launchd was given bytes of no reviewed release for {label}"
        assert tree(self.directory(owners[0])) == owners[0].files, (
            f"{label} was loaded from a release whose files are not the reviewed ones"
        )


class Launchd:
    """launchctl and Monit for one domain; one chosen call of a command fails."""

    def __init__(self, lab: Lab) -> None:
        self.lab = lab
        self.loaded: dict[str, bytes] = {}
        self.calls: list[tuple[str, ...]] = []
        self.fail: int | str | None = None
        self.failed = False

    def arm(self, fail: int | str | None = None) -> Launchd:
        """Fail the call with this index, or the first call of this verb; it has no effect."""
        self.calls = []
        self.fail = fail
        self.failed = False
        return self

    def __call__(self, argv: tuple[str, ...]) -> Result:
        index = len(self.calls)
        self.calls.append(argv)
        if not self.failed and self.fail in {index, argv[1]}:
            self.failed = True
            return Result(1, b"", b"")
        if argv[1] == "bootstrap":
            path = Path(argv[-1])
            if path.stem in self.loaded:
                # A label that is loaded cannot be loaded a second time.
                return Result(5, b"", b"")
            payload = path.read_bytes()
            self.lab.require_reviewed(path.stem, payload)
            self.loaded[path.stem] = payload
        elif argv[1] == "bootout":
            if self.loaded.pop(argv[-1].rsplit("/", 1)[-1], None) is None:
                return Result(3, b"", b"")
        elif argv[1] == "print" and argv[-1].rsplit("/", 1)[-1] not in self.loaded:
            return Result(113, b"", b"")
        return Result(0, b"", b"")


def run_command(
    lab: Lab,
    kind: str,
    release: Release,
    runner: Callable[[tuple[str, ...]], Result],
    scope: str = "user",
) -> dict[str, Any] | None:
    """One installer command; a refusal is ``None``."""
    try:
        if kind == "install":
            return install_bundle(
                release.bundle, scope, expected_digest=release.digest, runner=runner
            )
        if kind == "recover":
            return recover_install(
                lab.state_dir, scope, expected_failed_digest=release.digest, runner=runner
            )
        return rollback_install(
            lab.state_dir, scope, expected_current_digest=release.digest, runner=runner
        )
    except REFUSAL:
        return None


def edit_intent(lab: Lab, change: Callable[[Intent], Intent]) -> bool:
    """What ``netorch pause``, ``resume``, ``suspend`` and ``release`` do to the record."""
    store = Store(lab.state_dir)
    with store.lock():
        intent = intent_from_dict(store.read("intent.json"))
        try:
            changed = change(intent)
        except ValueError:
            return False
        store.write("intent.json", intent_to_dict(changed))
    return True


def overwrite_policy(lab: Lab, release: Release, *, consistent: bool) -> None:
    """Change one installed release file; optionally make its own manifest agree."""
    directory = lab.directory(release)
    payload = (directory / "data/network.json").read_bytes() + b"\n"
    (directory / "data/network.json").write_bytes(payload)
    if consistent:
        metadata = strict_loads((directory / "bundle-manifest.json").read_bytes())
        record = next(
            item for item in metadata["files"] if item["path"] == "user/data/network.json"
        )
        record.update(sha256=hashlib.sha256(payload).hexdigest(), bytes=len(payload))
        metadata["bundle_digest"] = digest(
            {key: value for key, value in metadata.items() if key != "bundle_digest"}
        )
        (directory / "bundle-manifest.json").write_bytes(canonical_bytes(metadata) + b"\n")


INDEX = st.integers(0, 4)
# No call fails, or the first call of one verb, or the call with one index.
FAILURE = st.one_of(
    st.none(),
    st.sampled_from(("-t", "bootout", "bootstrap", "print")),
    st.integers(0, 9),
)


class Installer(RuleBasedStateMachine):
    def __init__(self, lab: Lab) -> None:
        super().__init__()
        lab.reset()
        self.lab = lab
        self.launchd = Launchd(lab)
        # What the operator last chose; None until an installation created the record.
        self.pause: bool | None = None
        # Suspensions taken by someone other than the installer.
        self.holds: dict[str, str] = {}
        # The command kind and digest that own a journal which is not closed.
        self.open: tuple[str, str] | None = None
        # A release or an installed job was overwritten; nothing has to succeed any more.
        self.dirty = False
        self.commands = 0

    def record(self, name: str) -> bytes | None:
        path = self.lab.state_dir / name
        return path.read_bytes() if path.exists() else None

    def snapshot(self) -> dict[str, Any]:
        return {
            "journal": self.record(JOURNAL),
            "receipt": self.record(RECEIPT),
            "intent": self.record("intent.json"),
            "jobs": tree(self.lab.agents),
            "releases": tree(self.lab.release_root),
            "loaded": dict(self.launchd.loaded),
        }

    def command(
        self, kind: str, index: int, fail_at: int | str | None, scope: str = "user"
    ) -> None:
        lab = self.lab
        release = lab.releases[index]
        self.commands += 1
        before = self.snapshot()
        staged = lab.directory(release).exists()
        receipt = None if before["receipt"] is None else strict_loads(before["receipt"])
        current = None if receipt is None else receipt["bundle_digest"]
        owner = self.open
        owned = {"recover": "install", "rollback": "rollback"}.get(kind)
        result = run_command(lab, kind, release, self.launchd.arm(fail_at), scope)
        after = self.snapshot()
        working = not self.launchd.failed
        phase = None if after["journal"] is None else strict_loads(after["journal"])["phase"]
        if before["intent"] is None and after["intent"] is not None:
            self.pause = True
        if scope != "user" or (owner is not None and owner != (owned, release.digest)):
            # The other scope's command, or one that does not own the open journal:
            # refused before anything is written or any tool is called.
            assert result is None
            assert after == before
            assert self.launchd.calls == []
            return
        if owner is not None:
            if result is None:
                # Refused or failed again: the journal is as its owner found it.
                assert after["journal"] == before["journal"]
                # Recovery of an untouched failed installation completes when no tool fails.
                assert kind != "recover" or self.dirty or not working
            else:
                assert phase == "rolled-back"
                self.open = None
            return
        if result is None:
            if after["journal"] != before["journal"]:
                # Only an installation or a rollback opens a journal, and then owns it.
                assert kind in {"install", "rollback"}
                self.open = (kind, release.digest)
            else:
                assert after["receipt"] == before["receipt"]
                assert after["intent"] == before["intent"]
        elif result["phase"] == "unchanged":
            assert after == before
        else:
            assert kind != "recover" and phase == result["phase"]
        if not working or self.dirty:
            return
        # With working tools and reviewed bytes everywhere the outcome is known.
        contested = "installation" in self.holds
        if kind == "recover":
            assert result is None and after == before and self.launchd.calls == []
        elif kind == "rollback":
            possible = current == release.digest and receipt["previous"] is not None
            assert (result is not None) is (possible and not contested)
        elif current == release.digest:
            assert result == {"phase": "unchanged", "release_id": release.release_id}
        elif staged:
            # A retained release is never overwritten.
            assert result is None and tree(lab.directory(release)) == release.files
        else:
            assert (result is not None) is not contested

    @precondition(lambda self: self.open is None and self.fresh())
    @rule(pick=INDEX, fail_at=FAILURE)
    def install_of_a_release_not_seen_before(self, pick: int, fail_at: int | str | None) -> None:
        fresh = self.fresh()
        self.command("install", fresh[pick % len(fresh)], fail_at)

    @precondition(lambda self: self.open is None and self.restorable())
    @rule(fail_at=FAILURE)
    def rollback_of_the_current_release(self, fail_at: int | str | None) -> None:
        current = strict_loads(self.record(RECEIPT) or b"")["bundle_digest"]
        self.command("rollback", self.lab.releases.index(self.lab.by_digest[current]), fail_at)

    @precondition(lambda self: self.open is not None)
    @rule(fail_at=FAILURE)
    def owner_repeats(self, fail_at: int | str | None) -> None:
        assert self.open is not None
        kind, holder = self.open
        index = self.lab.releases.index(self.lab.by_digest[holder])
        self.command("recover" if kind == "install" else "rollback", index, fail_at)

    @precondition(lambda self: self.record(JOURNAL) is not None)
    @rule(
        kind=st.sampled_from(("install", "recover", "rollback")),
        index=INDEX,
        other_scope=st.booleans(),
    )
    def any_command_with_any_digest(self, kind: str, index: int, other_scope: bool) -> None:
        self.command(kind, index, None, "root" if other_scope and kind != "install" else "user")

    @precondition(lambda self: self.pause is not None)
    @rule(paused=st.booleans())
    def operator_chooses(self, paused: bool) -> None:
        assert edit_intent(self.lab, lambda intent: intent.pause() if paused else intent.resume())
        self.pause = paused

    @precondition(lambda self: self.pause is not None)
    @rule(
        operation=st.sampled_from(OPERATIONS), holder=st.sampled_from(HOLDERS), take=st.booleans()
    )
    def holder_takes_or_releases(self, operation: str, holder: str, take: bool) -> None:
        held = self.holds.get(operation)
        if operation == "installation" and self.open is not None:
            held = self.open[1]
        if take:
            taken = edit_intent(self.lab, lambda intent: intent.suspend(operation, holder))
            assert taken is (held in {None, holder})
            if taken:
                self.holds[operation] = holder
        else:
            released = edit_intent(self.lab, lambda intent: intent.release(operation, holder))
            assert released is (self.holds.get(operation) == holder)
            if released:
                del self.holds[operation]

    @precondition(lambda self: self.commands >= 4 and self.restore_target() is not None)
    @rule(what=st.sampled_from(("release", "release and manifest", "job")))
    def what_a_restore_would_use_is_overwritten(self, what: str) -> None:
        release = self.restore_target()
        assert release is not None
        present = sorted(self.lab.agents.glob("*.plist")) if self.lab.agents.is_dir() else []
        if what == "job" and present:
            present[0].write_bytes(b"not a reviewed job")
            self.dirty = True
        elif what != "job" and tree(self.lab.directory(release)) == release.files:
            overwrite_policy(self.lab, release, consistent=what != "release")
            self.dirty = True

    def restore_target(self) -> Release | None:
        """The release a rollback or a recovery would restore now."""
        name = JOURNAL if self.open is not None and self.open[0] == "install" else RECEIPT
        raw = self.record(name)
        previous = None if raw is None else strict_loads(raw)["previous"]
        return None if previous is None else self.lab.by_digest[previous["bundle_digest"]]

    def fresh(self) -> list[int]:
        return [
            index
            for index, release in enumerate(self.lab.releases)
            if not self.lab.directory(release).exists()
        ]

    def restorable(self) -> bool:
        raw = self.record(RECEIPT)
        return raw is not None and strict_loads(raw)["previous"] is not None

    @invariant()
    def intent_is_what_operator_and_holders_left(self) -> None:
        raw = self.record("intent.json")
        if raw is None:
            assert self.pause is None and self.open is None
            return
        intent = intent_from_dict(strict_loads(raw))
        assert not intent.damaged
        assert intent.operator_paused is self.pause
        expected = dict(self.holds)
        if self.open is not None:
            expected["installation"] = self.open[1]
        assert dict(intent.suspensions) == expected

    @invariant()
    def journal_is_closed_or_owned(self) -> None:
        raw = self.record(JOURNAL)
        if self.open is None:
            assert raw is None or strict_loads(raw)["phase"] in CLOSED
            return
        journal = strict_loads(raw or b"")
        assert journal["phase"] == "failed"
        if self.open[0] == "install":
            assert (journal["scope"], journal["bundle_digest"]) == ("user", self.open[1])

    @invariant()
    def closed_journal_leaves_one_release_installed(self) -> None:
        if self.open is not None or self.dirty:
            return
        raw = self.record(RECEIPT)
        jobs = {} if raw is None else self.lab.by_digest[strict_loads(raw)["bundle_digest"]].jobs
        assert tree(self.lab.agents) == {f"{label}.plist": jobs[label] for label in jobs}
        assert self.launchd.loaded == jobs


@pytest.fixture
def lab(
    tmp_path: Path,
    manifest: dict[str, Any],
    config: Any,
    fake_platform: None,
    monkeypatch: pytest.MonkeyPatch,
) -> Lab:
    # These tests are about which steps happened, not about durability.
    monkeypatch.setattr(os, "fsync", lambda descriptor: None)
    return Lab(tmp_path, manifest, config)


def test_installer_keeps_its_documented_invariants_in_any_order(lab: Lab) -> None:
    run_state_machine_as_test(seed(SEED)(lambda: Installer(lab)), settings=SEARCH)


def intent_of(lab: Lab) -> Intent:
    return intent_from_dict(Store(lab.state_dir).read("intent.json"))


def records(lab: Lab, launchd: Launchd) -> dict[str, Any]:
    """Everything a command of this scope may change."""
    return {
        **{name: path.read_bytes() for name, path in sorted(tree_paths(lab.state_dir).items())},
        "jobs": tree(lab.agents),
        "releases": tree(lab.release_root),
        "loaded": dict(launchd.loaded),
    }


def tree_paths(directory: Path) -> dict[str, Path]:
    return {
        path.name: path
        for path in directory.iterdir()
        if path.name in {JOURNAL, RECEIPT, "intent.json"}
    }


def installed(lab: Lab, launchd: Launchd, release: Release | None) -> None:
    """Exactly this release's jobs are installed and loaded, with its reviewed bytes."""
    jobs = {} if release is None else release.jobs
    assert tree(lab.agents) == {f"{label}.plist": jobs[label] for label in jobs}
    assert launchd.loaded == jobs


@pytest.mark.parametrize("first", [True, False], ids=["first", "upgrade"])
def test_failed_installation_and_its_recovery_change_only_the_installers_own_hold(
    lab: Lab, first: bool
) -> None:
    launchd = Launchd(lab)
    old, new, *_ = lab.releases
    if not first:
        assert run_command(lab, "install", old, launchd.arm()) is not None
    # An operator who resumed, and two holders with an operation each.
    chosen = Intent().suspend("backup", "holder-a").suspend("maintenance", "holder-b")
    Store(lab.state_dir).write("intent.json", intent_to_dict(chosen))
    assert run_command(lab, "install", new, launchd.arm("bootstrap")) is None
    held = intent_of(lab)
    assert held.operator_paused is False
    assert held.suspensions == {**chosen.suspensions, "installation": new.digest}
    assert run_command(lab, "recover", new, launchd.arm()) is not None
    after = intent_of(lab)
    assert after.operator_paused is False
    assert after.suspensions == chosen.suspensions
    installed(lab, launchd, None if first else old)


def test_installer_never_takes_over_or_releases_a_foreign_hold_of_its_own_operation(
    lab: Lab,
) -> None:
    launchd = Launchd(lab)
    old, new, *_ = lab.releases
    assert run_command(lab, "install", old, launchd.arm()) is not None
    assert edit_intent(lab, lambda intent: intent.suspend("installation", "holder-a"))
    before = records(lab, launchd)
    # Neither a new installation nor a rollback proceeds under another holder's name.
    assert run_command(lab, "install", new, launchd.arm()) is None
    assert records(lab, launchd) == before and launchd.calls == []
    assert intent_of(lab).suspensions == {"installation": "holder-a"}
    assert edit_intent(lab, lambda intent: intent.release("installation", "holder-a"))
    assert run_command(lab, "install", new, launchd.arm("bootstrap")) is None
    # While the installer holds the name, nobody else can take or release it.
    assert not edit_intent(lab, lambda intent: intent.suspend("installation", "holder-a"))
    assert not edit_intent(lab, lambda intent: intent.release("installation", "holder-a"))
    assert intent_of(lab).suspensions == {"installation": new.digest}


@pytest.mark.parametrize("first", [True, False], ids=["first", "upgrade"])
def test_recovery_that_fails_leaves_the_journal_for_its_next_attempt(lab: Lab, first: bool) -> None:
    launchd = Launchd(lab)
    old, new, *_ = lab.releases
    if not first:
        assert run_command(lab, "install", old, launchd.arm()) is not None
    assert run_command(lab, "install", new, launchd.arm("bootstrap")) is None
    journal = (lab.state_dir / JOURNAL).read_bytes()
    assert strict_loads(journal)["phase"] == "failed"
    for verb in ("bootout",) if first else ("bootout", "bootstrap", "print"):
        assert run_command(lab, "recover", new, launchd.arm(verb)) is None
        assert launchd.failed
        assert (lab.state_dir / JOURNAL).read_bytes() == journal
        assert intent_of(lab).suspensions == {"installation": new.digest}
    result = run_command(lab, "recover", new, launchd.arm())
    assert result is not None and result["phase"] == "rolled-back"
    assert strict_loads((lab.state_dir / JOURNAL).read_bytes())["phase"] == "rolled-back"
    assert not intent_of(lab).suspensions
    installed(lab, launchd, None if first else old)


def test_jobs_only_the_other_release_has_are_removed_by_upgrade_rollback_and_recovery(
    lab: Lab,
) -> None:
    with_a, with_b, plain, *_ = lab.releases
    launchd = Launchd(lab)
    assert run_command(lab, "install", with_b, launchd.arm()) is not None
    assert run_command(lab, "install", plain, launchd.arm()) is not None
    installed(lab, launchd, plain)
    lab.reset()
    launchd = Launchd(lab)
    assert run_command(lab, "install", plain, launchd.arm()) is not None
    assert run_command(lab, "install", with_a, launchd.arm()) is not None
    installed(lab, launchd, with_a)
    assert run_command(lab, "rollback", with_a, launchd.arm()) is not None
    installed(lab, launchd, plain)
    assert run_command(lab, "install", with_b, launchd.arm("bootstrap")) is None
    assert set(tree(lab.agents)) == {f"{label}.plist" for label in with_b.jobs}
    assert run_command(lab, "recover", with_b, launchd.arm()) is not None
    installed(lab, launchd, plain)


@pytest.mark.parametrize("command", ["rollback", "recover"])
@pytest.mark.parametrize("consistent", [False, True], ids=["file", "file-and-manifest"])
def test_rewritten_predecessor_is_never_restored_or_loaded(
    lab: Lab, command: str, consistent: bool
) -> None:
    launchd = Launchd(lab)
    old, new, *_ = lab.releases
    assert run_command(lab, "install", old, launchd.arm()) is not None
    failure = None if command == "rollback" else "bootstrap"
    assert (run_command(lab, "install", new, launchd.arm(failure)) is None) is bool(failure)
    # Someone who can write the release tree changes the predecessor, and, in the
    # second case, its own manifest to match. Only the receipt's digest can tell.
    overwrite_policy(lab, old, consistent=consistent)
    before = records(lab, launchd)
    assert run_command(lab, command, new, launchd.arm()) is None
    assert records(lab, launchd) == before
    assert launchd.calls == []


def test_command_of_the_other_scope_or_another_digest_leaves_an_open_journal_alone(
    lab: Lab,
) -> None:
    launchd = Launchd(lab)
    failed, other, *_ = lab.releases
    # Both scopes are installed on one host: the root scope's directories exist.
    assert install_bundle(failed.bundle, "root", expected_digest=failed.digest, runner=FakeTools())
    assert run_command(lab, "install", failed, launchd.arm(0)) is None
    before = records(lab, launchd)
    assert strict_loads(before[JOURNAL])["failed_phase"] == "preflight-jobs"
    for kind, release, scope in (
        ("recover", failed, "root"),
        ("rollback", failed, "root"),
        ("recover", other, "user"),
        ("rollback", failed, "user"),
        ("rollback", other, "user"),
        ("install", other, "user"),
        ("install", failed, "user"),
    ):
        assert run_command(lab, kind, release, launchd.arm(), scope) is None, (kind, scope)
        assert records(lab, launchd) == before, (kind, scope)
        assert launchd.calls == [], (kind, scope)
    assert run_command(lab, "recover", failed, launchd.arm()) is not None
    assert not intent_of(lab).suspensions

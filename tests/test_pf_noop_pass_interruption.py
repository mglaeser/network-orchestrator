"""A pass that stopped before it journalled a candidate wrote nothing.

A killed process runs no handler, so nothing here raises inside a pass. Each
test photographs everything that outlives a process (the protected store and the
fake kernel) around every step of a complete pass, then starts the next pass
from each photograph: that is the pass a restarted scheduler would run.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from netorch.pf_owner import STRATEGY, PFError, compose_rules, reconcile
from netorch.state import Intent, intent_to_dict
from netorch.storage import Store
from tests.test_pf_owner import STAMP, FakeBackend, approve_all, environment, run_pass

__all__ = ["environment"]

CLIENT = "192.0.2.77"


@dataclass(frozen=True)
class Photo:
    """What a process leaves behind when it dies at one point of a pass."""

    files: dict[str, Any]
    rules: str
    states: str

    @property
    def journal(self) -> Any:
        return self.files.get("journal.json")

    @property
    def unfinished_without_candidate(self) -> bool:
        journal = self.journal
        return (
            journal is not None
            and journal["phase"] == "applying"
            and "candidate_records" not in journal
        )


class Watched:
    """Hands every call to the fake kernel on and photographs before and after it."""

    def __init__(self, backend: FakeBackend, shoot: Callable[[], None]) -> None:
        self._backend = backend
        self._shoot = shoot

    def __getattr__(self, name: str) -> Any:
        call = getattr(self._backend, name)

        def around(*arguments: Any, **options: Any) -> Any:
            self._shoot()
            try:
                return call(*arguments, **options)
            finally:
                self._shoot()

        return around


def photographed_pass(environment: Any) -> tuple[dict[str, Any], list[Photo]]:
    """Run one complete pass; return its result and every durable state it went through.

    Photographs are taken around each kernel call, at each runtime observation,
    after each store write and at the report. Equal neighbours are kept once:
    the next pass depends on nothing else, so they cannot behave differently.
    """
    root, _, _, backend, snapshots = environment
    photos: list[Photo] = []

    def shoot() -> None:
        photo = Photo(
            {path.name: root.read(path.name) for path in sorted(root.directory.glob("*.json"))},
            backend.rules,
            backend.flow_states,
        )
        if not photos or photos[-1] != photo:
            photos.append(photo)

    def observe(config: Any, settings: Any) -> Any:
        shoot()
        return snapshots[-1]

    write = root.write

    def recording_write(name: str, value: Any) -> None:
        write(name, value)
        shoot()

    root.write = recording_write  # type: ignore[method-assign]
    try:
        result = reconcile(
            root,
            observe,
            lambda root, settings: Watched(backend, shoot),
            now=lambda: STAMP,
            report=lambda settings, snapshot: shoot(),
        )
    finally:
        del root.write
    return result, photos


def die_at(environment: Any, photo: Photo) -> None:
    """Put the store and the kernel back to what a killed process left behind."""
    root, _, _, backend, _ = environment
    for path in sorted(root.directory.glob("*.json")):
        if path.name not in photo.files:
            path.unlink()
    for name, value in photo.files.items():
        root.write(name, value)
    backend.rules = photo.rules
    backend.flow_states = photo.states


def acknowledge(root: Store) -> None:
    """What the administrator's `acknowledge-journal` command does to the journal."""
    journal = root.read("journal.json")
    assert journal["phase"] == "failed"
    journal["phase"] = "acknowledged"
    root.write("journal.json", journal)


def phases(photos: list[Photo]) -> list[str | None]:
    return [None if photo.journal is None else photo.journal["phase"] for photo in photos]


def test_a_healthy_pass_that_dies_at_any_point_needs_no_acknowledgement(environment: Any) -> None:
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    backend = environment[3]
    loaded = backend.rules
    assert loaded

    result, photos = photographed_pass(environment)

    assert result == {"schema_version": 1, "phase": "committed", "changed": [], "pending": []}
    # A pass that changes nothing still leaves an unfinished journal for a while.
    assert phases(photos) == ["committed", "applying", "committed"]
    assert photos[1].unfinished_without_candidate
    for photo in photos:
        die_at(environment, photo)
        mark = len(backend.commands)
        assert run_pass(environment) == result, photo.journal["phase"]
        assert backend.rules == loaded
        assert ("replace",) not in backend.commands[mark:]


def test_a_paused_pass_that_dies_does_not_block_the_later_resume(environment: Any) -> None:
    approve_all(environment)
    root, _, _, backend, _ = environment
    root.write("operator-intent.json", intent_to_dict(Intent().pause()))
    assert run_pass(environment)["phase"] == "inhibited"

    result, photos = photographed_pass(environment)

    assert result["phase"] == "inhibited" and result["changed"] == []
    assert phases(photos) == ["inhibited", "applying", "inhibited"]
    for photo in photos:
        die_at(environment, photo)
        assert run_pass(environment)["phase"] == "inhibited", photo.journal["phase"]
        assert backend.rules == ""
        root.write("operator-intent.json", intent_to_dict(Intent().resume()))
        assert run_pass(environment)["phase"] == "committed"
        assert backend.rules


def test_a_death_before_the_first_candidate_of_a_writing_pass_needs_none(
    environment: Any,
) -> None:
    approve_all(environment)
    backend = environment[3]

    result, photos = photographed_pass(environment)

    assert result["phase"] == "committed" and len(result["changed"]) == 4
    loaded = backend.rules
    early = [
        photo for photo in photos if photo.journal is None or photo.unfinished_without_candidate
    ]
    assert phases(early) == [None, "applying"]
    for photo in early:
        # Nothing had been written to the anchor at that point.
        assert photo.rules == "" and "live.json" not in photo.files
        die_at(environment, photo)
        assert run_pass(environment)["phase"] == "committed"
        assert backend.rules == loaded


def test_a_death_after_a_candidate_was_journalled_still_needs_the_acknowledgement(
    environment: Any,
) -> None:
    approve_all(environment)
    root, _, _, backend, _ = environment

    result, photos = photographed_pass(environment)

    assert result["phase"] == "committed" and len(result["changed"]) == 4
    journalled = [
        photo
        for photo in photos
        if photo.journal is not None and "candidate_records" in photo.journal
    ]
    # For each of the four activations: candidate journalled, rules loaded, record stored.
    assert len(journalled) == 12
    assert {photo.journal["phase"] for photo in journalled} == {"applying"}
    for photo in journalled:
        die_at(environment, photo)
        for _ in range(2):
            assert run_pass(environment)["phase"] == "failed"
            assert backend.rules == ""
        acknowledge(root)
        assert run_pass(environment)["phase"] == "committed"


def test_an_unacknowledged_failure_survives_a_death_in_every_later_pass(
    environment: Any,
) -> None:
    approve_all(environment)
    root, _, _, backend, _ = environment
    backend.fail_after_replace = True
    with pytest.raises(PFError):
        run_pass(environment)
    assert root.read("journal.json")["phase"] == "failed"
    assert backend.rules

    photos: list[Photo] = []
    # The pass that retires the partial write, then one with nothing left to do.
    for _ in range(2):
        result, taken = photographed_pass(environment)
        assert result["phase"] == "failed"
        photos += taken
    assert backend.rules == ""

    for photo in photos:
        die_at(environment, photo)
        assert run_pass(environment)["phase"] == "failed", photo.journal
        assert backend.rules == ""
    acknowledge(root)
    assert run_pass(environment)["phase"] == "committed"


def test_a_damaged_admission_record_is_not_forgotten_by_a_death(environment: Any) -> None:
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    root, _, _, backend, _ = environment
    admitted = root.read("admissions.json")
    root.write("admissions.json", {"schema_version": 1, "strategy": STRATEGY, "profiles": []})

    result, photos = photographed_pass(environment)

    assert result["phase"] == "failed" and backend.rules == ""
    recorded = [photo for photo in photos if photo.journal != photos[0].journal]
    assert recorded
    for photo in recorded:
        die_at(environment, photo)
        # Repaired by hand in the meantime, but nothing was acknowledged.
        root.write("admissions.json", admitted)
        assert run_pass(environment)["phase"] == "failed", photo.journal["phase"]
        assert backend.rules == ""


@pytest.mark.parametrize(
    "added,removed",
    [
        ({"candidate_records": {}}, ()),
        ({"candidate_records": None}, ()),
        ({"reason": "administrator-withdrawal"}, ()),
        ({}, ("actions",)),
        ({}, ("started_at",)),
    ],
    ids=["empty candidate", "null candidate", "another field", "no actions", "no start time"],
)
def test_only_the_exact_first_record_of_a_pass_is_exempt(
    environment: Any, added: dict[str, Any], removed: tuple[str, ...]
) -> None:
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    root, _, _, backend, _ = environment
    _, photos = photographed_pass(environment)
    first = next(photo.journal for photo in photos if photo.unfinished_without_candidate)

    root.write(
        "journal.json",
        {**{key: value for key, value in first.items() if key not in removed}, **added},
    )

    assert run_pass(environment)["phase"] == "failed"
    assert backend.rules == ""


def test_a_death_while_only_states_are_invalidated_is_repeated_from_fresh_evidence(
    environment: Any,
) -> None:
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    root, _, _, backend, snapshots = environment
    loaded = backend.rules
    guest = str(snapshots[-1].services["resolver"].data["ipv4"])
    # One profile is recorded as retired while a state for its target remains:
    # the pass has no rule to write, only states to invalidate.
    live = root.read("live.json")
    live["records"]["dns-udp"].update(active=False, rules="")
    root.write("live.json", live)
    backend.rules = compose_rules(live["records"])
    backend.flow_states = f"all udp {CLIENT}:54321 -> {guest}:53 NO_TRAFFIC:SINGLE"

    result, photos = photographed_pass(environment)

    assert result["changed"] == ["dns-udp:drain"]
    # The states are killed before the candidate of that step is journalled.
    early = [photo for photo in photos if photo.unfinished_without_candidate]
    assert [bool(photo.states) for photo in early] == [True, False]
    for photo in early:
        die_at(environment, photo)
        mark = len(backend.commands)
        outcomes = [run_pass(environment)["phase"] for _ in range(2)]
        assert "failed" not in outcomes and outcomes[-1] == "committed", outcomes
        assert backend.flow_states == ""
        assert sorted(backend.rules.splitlines()) == sorted(loaded.splitlines())
        if photo.states:
            assert ("drain", guest) in backend.commands[mark:]

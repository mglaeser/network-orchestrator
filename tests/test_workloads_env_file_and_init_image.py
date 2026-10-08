"""A recipe's environment file holds literals only, and its init image is in the cache.

The vendor's `create` gives a line of an environment file that has no `=` the
value that name has in the environment of the calling process, and it fetches a
custom init image exactly as it fetches the workload image. The plan therefore
reads an environment file through its hashed receipt and refuses every line
that is not blank, a comment or `NAME=value`, and it looks a custom init image
up in the native cache with the call the workload image gets. No vendor command
is run here.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest

import netorch.workloads as module
from netorch.apple_runtime import RuntimeReadError
from netorch.codec import canonical_bytes, strict_loads
from netorch.process import Result
from netorch.runtime_settings import FileIdentity
from netorch.workloads import (
    Option,
    main,
    plan_workloads,
    provision_digest,
    provision_workloads,
)
from tests.test_workloads import cli_settings, enrolled_input, fleet

REDACTED = '{"error":"workload-evidence-or-authority-incomplete"}\n'
INIT = "example.invalid/init@sha256:" + "2" * 64

# What the vendor's parser takes as literal data, line by line.
LITERAL = (
    "# Settings of the example application\n"
    "\n"
    "   \t\n"
    "TZ=Etc/UTC\r\n"
    "  \tINDENTED=value\n"
    "EMPTY=\n"
    "EQUATION=a=b=c\n"
    "SPACED= kept as it is # no comment here\n"
    'QUOTED="kept with its quotes"\n'
    "lower.case-and_1.digits=yes\n"
    # No real names: a letter outside ASCII inside a value, and as its first character.
    "WORD=Flürbaz\n"
    "NAME=Ölvex\n"
    "SAMPLE=例文\n"
    "PRICE=€5\n"
    "#über: a comment may continue with any letter\n"
    "#\n"
    "LAST=without a final line end"
)

# One refused line each. The vendor reads the first group as bare names, whose
# values it takes from the environment of the caller.
BARE_NAMES = {
    "bare-name": "HOME",
    "bare-name-among-literals": "A=1\nHOME\nB=2",
    "bare-name-indented": "A=1\n  \tPATH\n",
    "bare-name-after-carriage-return": "A=1\rHOME",
    "value-cut-by-a-form-feed": "A=one\x0ctwo",
    "value-cut-by-a-line-tabulation": "A=one\x0btwo",
    "value-cut-by-a-next-line": "A=one\x85two",
    "value-cut-by-a-line-separator": "A=one\u2028two",
    "value-cut-by-a-paragraph-separator": "A=one\u2029two",
    # `=` and a combining character are one character for the vendor: no `=` is found.
    "equals-with-a-combining-solidus": "HOME=\u0338x",
    "equals-with-a-combining-accent": "A=\u0301",
    "equals-with-a-joiner": "A=\u200dx",
    "equals-with-a-variation-selector": "A=\ufe0f",
    "equals-with-an-enclosing-keycap": "A=\u20e3",
    "equals-with-a-spacing-vowel": "A=\u0e33",
    # The second of the two letters that extend: the list of exceptions names both.
    "equals-with-the-lao-spacing-vowel": "A=\u0eb3",
    # A spacing mark of the category the rule must not take as standing alone.
    "equals-with-a-spacing-mark": "A=\u0903",
    "equals-with-a-halfwidth-sound-mark": "A=\uff9e",
    "equals-with-an-emoji-modifier": "A=\U0001f3fb",
    "equals-with-an-unassigned-character": "A=\u0378",
    "comment-sign-with-a-combining-accent": "#\u0301 not a comment",
}
# The vendor refuses these when it creates the workload, or reads them in a way
# this check does not state.
NOT_STATED = {
    "no-name": "=value",
    "space-in-name": "NAME =value",
    "tab-in-name": "NA\tME=value",
    "exported": "export NAME=value",
    "name-outside-ascii": "\u00c4PFEL=1",
    "control-character-in-name": "A\x01B=1",
    "no-break-space-before-the-name": "\u00a0A=1",
    "ideographic-space-before-the-name": "\u3000A=1",
    "byte-order-mark": "\ufeffA=1",
    "null-character": "A=1\x00",
}
REFUSED = {
    **{key: value.encode() for key, value in {**BARE_NAMES, **NOT_STATED}.items()},
    "not-utf-8": b"A=\xff",
    "surrogate-bytes": b"A=\xed\xa0\x80",
}


def with_environment(tmp_path: Path, content: bytes) -> tuple[Any, Any, Any, Any, Any, Path]:
    """The seven-workload fleet whose first recipe names an enrolled environment file."""
    config, settings, fake, workloads, store = fleet(tmp_path)
    source = tmp_path / "application.env"
    source.write_bytes(content)
    source.chmod(0o600)
    settings = enrolled_input(settings, source, receipt=True)
    first = replace(workloads[0], options=(Option("--env-file", str(source)),))
    return config, settings, fake, (first, *workloads[1:]), store, source


def writes(fake: Any) -> list[list[str]]:
    return [argv for argv, _ in fake.calls if argv[1:2] in (["create"], ["start"])]


def test_an_environment_file_of_literals_plans_and_provisions(tmp_path: Path) -> None:
    config, settings, fake, workloads, _store, source = with_environment(tmp_path, LITERAL.encode())
    planned = plan_workloads(config, settings, workloads, fake)
    assert {step["action"] for step in planned["steps"]} == {"create-stopped"}
    result = provision_workloads(
        config, settings, workloads, expected_digest=planned["provision_digest"], runner=fake
    )
    assert result["provisioned"] and len(fake.existing) == 7
    created = next(argv for argv in writes(fake) if argv[1] == "create")
    assert created[created.index("--env-file") + 1] == str(source)


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_a_line_that_is_no_literal_refuses_the_plan(tmp_path: Path, case: str) -> None:
    config, settings, fake, workloads, store, _source = with_environment(tmp_path, REFUSED[case])
    with pytest.raises(ValueError) as refused:
        plan_workloads(config, settings, workloads, fake)
    # One fixed sentence: neither the line, the name nor its position.
    assert str(refused.value) == (
        "environment file lines must be blank, comments or literal NAME=value"
    )
    assert refused.value.__cause__ is None and refused.value.__context__ is None
    with pytest.raises(ValueError):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=provision_digest(config, settings, workloads),
            runner=fake,
        )
    assert not writes(fake) and not fake.existing
    assert not (store.directory / "workload-journal.json").exists()


@pytest.mark.parametrize("excess", [0, 1])
def test_an_environment_file_is_read_up_to_one_mebibyte(tmp_path: Path, excess: int) -> None:
    content = b"A=" + b"x" * (1_048_576 - 2 + excess)
    config, settings, fake, workloads, _store, _source = with_environment(tmp_path, content)
    if excess:
        with pytest.raises(RuntimeReadError) as refused:
            plan_workloads(config, settings, workloads, fake)
        assert refused.value.reason == "identity-mismatch"
    else:
        assert len(plan_workloads(config, settings, workloads, fake)["steps"]) == 7


def test_what_is_judged_is_the_content_the_receipt_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file replaced after its identity check is not the enrolled file, whatever it holds."""
    config, settings, fake, workloads, _store, source = with_environment(tmp_path, b"A=1\n")
    assert len(plan_workloads(config, settings, workloads, fake)["steps"]) == 7
    seen: list[str] = []

    def replaced(path: Any, **_keywords: Any) -> bytes:
        seen.append(str(path))
        return b"B=2\n"

    monkeypatch.setattr(module, "read_bounded_file", replaced, raising=False)
    with pytest.raises(RuntimeReadError) as refused:
        plan_workloads(config, settings, workloads, fake)
    assert refused.value.reason == "identity-mismatch" and seen == [str(source)]


def test_the_plan_command_echoes_nothing_of_a_refused_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _module, _config, settings, fake, workloads, _store, recipes = cli_settings(
        tmp_path, monkeypatch
    )
    source = tmp_path / "application.env"
    source.write_bytes(b"API_TOKEN=correct-horse-battery\nINHERITED_SECRET_NAME\n")
    source.chmod(0o600)
    settings = enrolled_input(settings, source, receipt=True)
    first = replace(workloads[0], options=(Option("--env-file", str(source)),))
    recipes.write_bytes(
        canonical_bytes(
            {"schema_version": 1, "workloads": [asdict(w) for w in (first, *workloads[1:])]}
        )
    )
    plan = module.plan_workloads
    monkeypatch.setattr(module, "load_settings", lambda _path: settings)
    monkeypatch.setattr(
        module,
        "plan_workloads",
        lambda config, actual, rows, _runner=None, **keywords: plan(
            config, actual, rows, fake, **keywords
        ),
    )
    prefix = ["--settings", str(tmp_path / "private-settings.json"), "--recipes", str(recipes)]
    assert main([*prefix, "plan"]) == 69
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", REDACTED)
    # The same file with the bare name removed plans, and still shows no value.
    source.write_bytes(b"API_TOKEN=correct-horse-battery\n")
    settings = enrolled_input(settings, source, receipt=True)
    assert main([*prefix, "plan"]) == 0
    captured = capsys.readouterr()
    assert len(strict_loads(captured.out)["steps"]) == 7 and not captured.err
    assert "correct-horse" not in captured.out and "API_TOKEN" not in captured.out


def image_lookups(fake: Any) -> list[str]:
    return [argv[3] for argv, _ in fake.calls if argv[1:3] == ["image", "inspect"]]


def with_init_image(tmp_path: Path) -> tuple[Any, Any, Any, Any, Any]:
    config, settings, fake, workloads, store = fleet(tmp_path)
    first = replace(workloads[0], options=(Option("--init-image", INIT),))
    return config, settings, fake, (first, *workloads[1:]), store


def test_a_custom_init_image_is_looked_up_like_the_workload_image(tmp_path: Path) -> None:
    config, settings, fake, workloads, _store = with_init_image(tmp_path)
    planned = plan_workloads(config, settings, workloads, fake)
    assert len(planned["steps"]) == 7
    # One lookup per workload image, and one more for the one custom init image.
    assert image_lookups(fake) == [workloads[0].image, INIT, *(w.image for w in workloads[1:])]
    lookups = [(argv, kwargs) for argv, kwargs in fake.calls if argv[1:3] == ["image", "inspect"]]
    (first, first_bounds), (second, second_bounds) = lookups[:2]
    assert first[:3] == second[:3] == [settings.executable, "image", "inspect"]
    assert set(first_bounds) == set(second_bounds) and 0 < second_bounds["timeout"] <= 4
    assert not writes(fake)


def test_a_recipe_without_a_custom_init_image_is_looked_up_as_before(tmp_path: Path) -> None:
    config, settings, fake, workloads, _store = fleet(tmp_path)
    plan_workloads(config, settings, workloads, fake)
    assert image_lookups(fake) == [workload.image for workload in workloads]


# What the lookup of the init image answers, and the reason the plan then carries.
# An empty list is also what the vendor prints for the init image its own
# configuration names: it leaves that image out of the listing.
NOT_CACHED = {
    "not-found": (Result(1, b"", b"Error: image not found\n"), "unavailable"),
    "found-with-a-warning": (Result(0, b'[{"reference":"x"}]', b"warning\n"), "unavailable"),
    "empty-list": (Result(0, b"[]", b""), "incomplete"),
    "two-rows": (Result(0, b"[{},{}]", b""), "incomplete"),
    "not-a-list": (Result(0, b"{}", b""), "incomplete"),
    "row-is-not-an-object": (Result(0, b"[null]", b""), "incomplete"),
}


@pytest.mark.parametrize("answer", sorted(NOT_CACHED))
def test_a_custom_init_image_that_is_not_cached_refuses_before_any_write(
    tmp_path: Path, answer: str
) -> None:
    config, settings, fake, workloads, store = with_init_image(tmp_path)
    result, reason = NOT_CACHED[answer]

    def runner(argv: list[str], **kwargs: Any) -> Result:
        if argv[1:] == ["image", "inspect", INIT]:
            fake.calls.append((argv, kwargs))
            return result
        return fake(argv, **kwargs)

    with pytest.raises(RuntimeReadError) as refused:
        plan_workloads(config, settings, workloads, runner)
    assert refused.value.reason == reason
    with pytest.raises(RuntimeReadError):
        provision_workloads(
            config,
            settings,
            workloads,
            expected_digest=provision_digest(config, settings, workloads),
            runner=runner,
        )
    assert INIT in image_lookups(fake)
    assert not writes(fake) and not fake.existing
    assert not (store.directory / "workload-journal.json").exists()


def test_the_checks_change_no_digest_of_a_recipe_that_plans(tmp_path: Path) -> None:
    """Neither check enters the approval: it binds the receipt's hash and the argv as before."""
    config, settings, fake, workloads, _store, source = with_environment(tmp_path, b"A=1\n")
    workloads = (
        replace(workloads[0], options=(*workloads[0].options, Option("--init-image", INIT))),
        *workloads[1:],
    )
    before = provision_digest(config, settings, workloads)
    planned = plan_workloads(config, settings, workloads, fake)
    assert planned["provision_digest"] == before == provision_digest(config, settings, workloads)
    receipt = settings.contracts[0].receipts[0]
    assert receipt.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()


# What the plan does with a row, by the state the vendor's inventory gives it;
# `None` is a row the inventory does not list. Both checks judge the recipe of
# every row, like the validation of its arguments, whatever the plan then does.
ACTIONS = {
    None: "create-stopped",
    "running": "retain",
    "stopped": "start-existing",
    "stopping": "blocked",
    "unknown": "blocked",
}
SECOND_INIT = "example.invalid/init@sha256:" + "3" * 64


def listed(fake: Any, settings: Any, state: str | None) -> None:
    """Every row of the fleet already exists in this state, or none does."""
    if state is not None:
        for contract in settings.contracts:
            fake.existing[contract.name] = fake.snapshot(contract.name, state)


def hashed(source: Path) -> FileIdentity:
    meta = source.stat()
    return FileIdentity(
        str(source),
        "file",
        meta.st_uid,
        meta.st_dev,
        meta.st_ino,
        hashlib.sha256(source.read_bytes()).hexdigest(),
    )


@pytest.mark.parametrize("state", list(ACTIONS), ids=lambda state: state or "not-listed")
def test_the_environment_file_is_judged_whatever_the_plan_does_with_the_row(
    tmp_path: Path, state: str | None
) -> None:
    config, settings, fake, workloads, _store, source = with_environment(tmp_path, b"A=1\n")
    listed(fake, settings, state)
    planned = plan_workloads(config, settings, workloads, fake)
    assert {step["action"] for step in planned["steps"]} == {ACTIONS[state]}
    # The same fleet in the same state, and a bare name in the enrolled file.
    source.write_bytes(b"A=1\nHOME\n")
    settings = enrolled_input(settings, source, receipt=True)
    with pytest.raises(ValueError, match="environment file lines must be"):
        plan_workloads(config, settings, workloads, fake)
    assert not writes(fake)


@pytest.mark.parametrize("state", list(ACTIONS), ids=lambda state: state or "not-listed")
def test_a_custom_init_image_is_looked_up_whatever_the_plan_does_with_the_row(
    tmp_path: Path, state: str | None
) -> None:
    config, settings, fake, workloads, _store = with_init_image(tmp_path)
    listed(fake, settings, state)
    planned = plan_workloads(config, settings, workloads, fake)
    assert {step["action"] for step in planned["steps"]} == {ACTIONS[state]}
    assert image_lookups(fake) == [workloads[0].image, INIT, *(w.image for w in workloads[1:])]

    def runner(argv: list[str], **kwargs: Any) -> Result:
        if argv[1:] == ["image", "inspect", INIT]:
            return Result(1, b"", b"Error: image not found\n")
        return fake(argv, **kwargs)

    with pytest.raises(RuntimeReadError) as refused:
        plan_workloads(config, settings, workloads, runner)
    assert refused.value.reason == "unavailable" and not writes(fake)


@pytest.mark.parametrize(
    "place", ["after-another-option", "first-of-two-files", "second-of-two-files"]
)
def test_every_environment_file_a_recipe_names_is_judged(tmp_path: Path, place: str) -> None:
    config, settings, fake, workloads, _store = fleet(tmp_path)
    literal, bare = tmp_path / "literal.env", tmp_path / "bare.env"
    literal.write_bytes(b"A=1\n")
    bare.write_bytes(b"HOME\n")
    for source in (literal, bare):
        source.chmod(0o600)
    first = replace(settings.contracts[0], receipts=(hashed(literal), hashed(bare)))
    settings = replace(settings, contracts=(first, *settings.contracts[1:]))

    def rows(judged: Path) -> tuple[Any, ...]:
        here, other = Option("--env-file", str(judged)), Option("--env-file", str(literal))
        options = {
            "after-another-option": (Option("--cpus", "2"), here),
            "first-of-two-files": (here, other),
            "second-of-two-files": (other, here),
        }[place]
        return (replace(workloads[0], options=options), *workloads[1:])

    # With a file of literals in that place the recipe plans; with the bare name it does not.
    assert len(plan_workloads(config, settings, rows(literal), fake)["steps"]) == 7
    with pytest.raises(ValueError, match="environment file lines must be"):
        plan_workloads(config, settings, rows(bare), fake)
    assert not writes(fake)


def test_every_custom_init_image_a_recipe_names_is_looked_up(tmp_path: Path) -> None:
    """Each one is an argument of `create`: the plan looks up every one, in order."""
    config, settings, fake, workloads, _store = fleet(tmp_path)
    options = (Option("--init-image", INIT), Option("--init-image", SECOND_INIT))
    rows = (replace(workloads[0], options=options), *workloads[1:])
    assert len(plan_workloads(config, settings, rows, fake)["steps"]) == 7
    assert image_lookups(fake)[:3] == [workloads[0].image, INIT, SECOND_INIT]

    def runner(argv: list[str], **kwargs: Any) -> Result:
        if argv[1:] == ["image", "inspect", SECOND_INIT]:
            return Result(0, b"[]", b"")
        return fake(argv, **kwargs)

    with pytest.raises(RuntimeReadError) as refused:
        plan_workloads(config, settings, rows, runner)
    assert refused.value.reason == "incomplete" and not writes(fake)

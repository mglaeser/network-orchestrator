"""The supervisor's start of the vendor runtime changes no configuration and reads exactly.

The vendor's start command copies the account's own configuration file over the
copy below the application root before it does anything else (apple/container
`ConfigurationLoader.copyConfigurationToReadOnly`, the same at tags 1.2.0, 1.4.1
and 1.5.0). A start by the supervisor is therefore permitted only where that
copy would change nothing. A printed job is compared exactly: only the printer's
indentation is removed. The remaining tests pin single conditions of the start
that the neighbouring module states and did not prove one by one.

Everything native is faked, with the helpers of the neighbouring module; its
fake vendor command makes the same copy as the vendor's.
"""

from __future__ import annotations

import os
import pwd
import sys
import time
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch import process, runtime_settings
from netorch.process import ProcessTimeout, Result
from netorch.runtime_settings import parse_settings
from tests.test_apple_runtime import enrolled
from tests.test_runtime_settings import authored
from tests.test_runtime_start_vendor_runtime import (
    APP,
    FLEET_ONLY,
    IDLE,
    INSTALL,
    LABEL,
    ROOTS,
    World,
    between_the_reads,
    command,
    lock_is_held,
    printed,
    refuses_to_start,
    start,
    state,
)

__all__ = ["enrolled"]

# The bound of one configuration file, stated here once more: a change of it is a decision.
BOUND = 1_048_576
SETTING = b"[example]\nsetting = 1\n"
OTHER = b"[example]\nsetting = 2\n"
FULL = b"#" * BOUND
# Python's documented table of the characters at which `str.splitlines` ends a line.
LINE_BOUNDARIES = "\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"
# The reader of the user database as the module defines it; the fixture below replaces it.
LISTED_HOME = getattr(runtime, "_listed_home", None)


@pytest.fixture(autouse=True)
def only_the_enrolled_home(monkeypatch: Any) -> None:
    """The user database of the machine that runs the tests is no part of them."""
    monkeypatch.setattr(runtime, "_listed_home", lambda _uid: None, raising=False)


def own_file(world: World) -> Path:
    """The account's own configuration, where the vendor's command looks for it."""
    return Path(world.settings.account.home) / ".config/container/config.toml"


def copy_file(world: World) -> Path:
    """The copy below the application root, which the vendor's command replaces."""
    return world.app / "config/config.toml"


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def link_to(path: Path, data: bytes) -> None:
    real = path.with_name("real.toml")
    write(real, data)
    path.symlink_to(real)


def pipe(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(path)


def directory(path: Path) -> None:
    path.mkdir(parents=True)


def check_configuration(world: World) -> None:
    runtime.check_configuration(world.settings, world.settings.fleet_start.runtime_start)


def configuration(world: World) -> dict[str, bytes | None]:
    return {
        str(path): path.read_bytes() if path.is_file() else None
        for path in (own_file(world), copy_file(world))
    }


# The start leaves the configuration of the vendor runtime as it is.

UNCHANGED: dict[str, Callable[[World], Any]] = {
    "no-file-of-the-account-and-no-copy": lambda w: None,
    "no-file-of-the-account-beside-a-copy": lambda w: write(copy_file(w), SETTING),
    "equal": lambda w: (write(own_file(w), SETTING), write(copy_file(w), SETTING)),
    "both-empty": lambda w: (write(own_file(w), b""), write(copy_file(w), b"")),
    "equal-at-the-bound": lambda w: (write(own_file(w), FULL), write(copy_file(w), FULL)),
}


@pytest.mark.parametrize("case", sorted(UNCHANGED))
def test_a_start_that_would_change_no_configuration_is_permitted(
    enrolled: Any, tmp_path: Path, case: str
) -> None:
    world = World(enrolled, tmp_path)
    UNCHANGED[case](world)
    before = configuration(world)
    check_configuration(world)
    assert state(world) == "absent"
    assert start(world) == "started"
    # The fake command made the vendor's copy; nothing is different afterwards.
    assert configuration(world) == before
    assert runtime._CONFIGURATION_BYTES == BOUND


CHANGED: dict[str, Callable[[World], Any]] = {
    "different": lambda w: (write(own_file(w), OTHER), write(copy_file(w), SETTING)),
    "different-in-the-last-byte": lambda w: (
        write(own_file(w), SETTING),
        write(copy_file(w), SETTING[:-1]),
    ),
    "a-longer-copy": lambda w: (write(own_file(w), SETTING), write(copy_file(w), SETTING + b"#")),
    "no-copy": lambda w: write(own_file(w), SETTING),
    "no-copy-of-an-empty-file": lambda w: write(own_file(w), b""),
    "the-account-s-file-is-a-link": lambda w: (
        link_to(own_file(w), SETTING),
        write(copy_file(w), SETTING),
    ),
    "the-account-s-file-is-a-link-to-nothing": lambda w: (
        own_file(w).parent.mkdir(parents=True),
        own_file(w).symlink_to("missing.toml"),
        write(copy_file(w), SETTING),
    ),
    "the-copy-is-a-link": lambda w: (write(own_file(w), SETTING), link_to(copy_file(w), SETTING)),
    "the-account-s-file-is-a-directory": lambda w: (
        directory(own_file(w)),
        write(copy_file(w), SETTING),
    ),
    "the-copy-is-a-directory": lambda w: (write(own_file(w), SETTING), directory(copy_file(w))),
    "the-account-s-file-is-a-pipe": lambda w: (pipe(own_file(w)), write(copy_file(w), b"")),
    "the-copy-is-a-pipe": lambda w: (write(own_file(w), b""), pipe(copy_file(w))),
    "one-byte-beyond-the-bound": lambda w: (
        write(own_file(w), FULL + b"#"),
        write(copy_file(w), FULL + b"#"),
    ),
}


@pytest.mark.parametrize("case", sorted(CHANGED))
def test_a_start_that_would_change_the_configuration_is_refused(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, case: str
) -> None:
    world = World(enrolled, tmp_path)
    assert state(world) == "absent"
    CHANGED[case](world)
    before = configuration(world)
    with pytest.raises(runtime.RuntimeReadError) as refused:
        check_configuration(world)
    # The closed outcome of a launch file that differs.
    assert refused.value.reason == "identity-mismatch"
    refuses_to_start(monkeypatch, world)
    # The same files stop the activation of an idle job.
    world.runner.load(**IDLE)
    refuses_to_start(monkeypatch, world)
    assert configuration(world) == before


def test_without_the_rule_the_command_would_replace_the_copy(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    write(own_file(world), OTHER)
    write(copy_file(world), SETTING)
    with pytest.raises(runtime.RuntimeReadError):
        start(world)
    assert world.vendor_calls() == [] and copy_file(world).read_bytes() == SETTING
    # What the rule prevents, shown with the same fake command and the rule taken away.
    monkeypatch.setattr(runtime, "check_configuration", lambda _settings, _start: None)
    assert start(world) == "started"
    assert copy_file(world).read_bytes() == OTHER


def test_a_running_declared_job_is_running_whatever_the_configuration(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    world.runner.load()
    write(own_file(world), OTHER)
    # Like the launch file: nothing would be started, so nothing is compared.
    assert state(world) == "running"
    assert command(monkeypatch, world, "runtime-probe") == 0


def test_a_configuration_that_changes_between_the_reads_starts_nothing(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    write(own_file(world), SETTING)
    write(copy_file(world), SETTING)
    between_the_reads(monkeypatch, lambda: write(own_file(world), OTHER))
    with pytest.raises(runtime.RuntimeReadError):
        start(world)
    assert world.vendor_calls() == []


def test_the_home_of_the_user_database_is_read_as_well(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    listed = tmp_path / "listed-home"
    asked: list[int] = []

    def database(uid: int) -> str:
        asked.append(uid)
        return str(listed)

    monkeypatch.setattr(runtime, "_listed_home", database)
    # No file below either home.
    assert state(world) == "absent"
    assert set(asked) == {world.settings.account.uid}
    # The command looks below the listed home first: a file there must equal the copy.
    write(listed / ".config/container/config.toml", OTHER)
    refuses_to_start(monkeypatch, world)
    write(copy_file(world), SETTING)
    refuses_to_start(monkeypatch, world)
    write(copy_file(world), OTHER)
    assert state(world) == "absent"
    # Without an entry it looks below `HOME`, the enrolled home: neither may differ.
    write(own_file(world), SETTING)
    refuses_to_start(monkeypatch, world)
    write(own_file(world), OTHER)
    assert start(world) == "started"


def test_the_listed_home_is_the_entry_of_the_user_database(monkeypatch: Any) -> None:
    assert LISTED_HOME is not None
    entries: dict[int, Any] = {
        1001: SimpleNamespace(pw_dir="/operator"),
        1002: SimpleNamespace(pw_dir=""),
    }
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: entries[uid])
    assert LISTED_HOME(1001) == "/operator"
    # An entry without a directory and a missing entry name no home.
    assert LISTED_HOME(1002) is None
    assert LISTED_HOME(1003) is None


def test_nothing_of_either_file_reaches_an_output(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    world = World(enrolled, tmp_path)
    mark = "marker-7c1e9d"
    write(own_file(world), f"own = '{mark}'\n".encode())
    write(copy_file(world), f"copy = '{mark}'\n".encode())
    with pytest.raises(runtime.RuntimeReadError) as refused:
        check_configuration(world)
    said = [str(refused.value), repr(refused.value), repr(refused.value.args)]
    said += [repr(refused.value.__cause__), repr(refused.value.__context__)]
    capsys.readouterr()
    assert command(monkeypatch, world, "runtime-probe") == runtime.UNKNOWN
    assert command(monkeypatch, world, "runtime-start") == runtime.UNKNOWN
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == '{"error":"runtime-evidence-or-authority-incomplete"}\n' * 2
    said += [output.out, output.err]
    said += [repr(call) for call in world.runner.calls]
    assert all(mark not in text for text in said)
    # A link is refused by the system; that error names a path and nothing else.
    own_file(world).unlink()
    link_to(own_file(world), f"own = '{mark}'\n".encode())
    with pytest.raises(runtime.RuntimeReadError) as linked:
        check_configuration(world)
    assert isinstance(linked.value.__cause__, OSError)
    assert mark not in repr(linked.value.__cause__) + str(linked.value)


# A printed job is compared exactly: only the printer's indentation is removed.


def padded(old: str, new: str) -> Callable[[bytes], bytes]:
    return lambda text: text.replace(old.encode(), new.encode())


EXACT_FAULTS: dict[str, Callable[[World], Callable[[bytes], bytes]]] = {
    "app-root-with-a-final-space": lambda w: padded(f"{APP} => {w.app}\n", f"{APP} => {w.app} \n"),
    "app-root-with-a-final-tab": lambda w: padded(f"{APP} => {w.app}\n", f"{APP} => {w.app}\t\n"),
    "app-root-with-a-leading-space": lambda w: padded(
        f"{APP} => {w.app}\n", f"{APP} =>  {w.app}\n"
    ),
    "app-root-before-a-line-separator": lambda w: padded(
        f"{APP} => {w.app}\n", f"{APP} => {w.app}\u2028\n"
    ),
    "app-root-before-a-form-feed": lambda w: padded(
        f"{APP} => {w.app}\n", f"{APP} => {w.app}\x0c\n"
    ),
    "app-root-before-a-carriage-return": lambda w: padded(
        f"{APP} => {w.app}\n", f"{APP} => {w.app}\r\n"
    ),
    "install-root-with-a-final-space": lambda w: padded(
        f"{INSTALL} => {w.install}\n", f"{INSTALL} => {w.install} \n"
    ),
    "launch-file-with-a-final-space": lambda w: padded(
        f"path = {w.launch}\n", f"path = {w.launch} \n"
    ),
    "launch-file-with-a-leading-space": lambda w: padded(
        f"path = {w.launch}\n", f"path =  {w.launch}\n"
    ),
    "program-with-a-final-space": lambda w: padded(
        f"program = {w.program}\n", f"program = {w.program} \n"
    ),
    "first-argument-with-a-final-space": lambda w: padded(
        f"\t\t{w.program}\n\t\tstart\n", f"\t\t{w.program} \n\t\tstart\n"
    ),
    "second-argument-with-a-final-space": lambda w: padded("\t\tstart\n", "\t\tstart \n"),
    "second-argument-with-a-leading-space": lambda w: padded("\t\tstart\n", "\t\t start\n"),
    "second-argument-indented-with-spaces": lambda w: padded("\t\tstart\n", "\t        start\n"),
    "arguments-opened-with-a-final-space": lambda w: padded(
        "\targuments = {\n", "\targuments = { \n"
    ),
    "environment-closed-with-a-final-space": lambda w: padded(
        f"XPC_SERVICE_NAME => {LABEL}\n\t}}\n", f"XPC_SERVICE_NAME => {LABEL}\n\t}} \n"
    ),
}


@pytest.mark.parametrize("fault", sorted(EXACT_FAULTS))
@pytest.mark.parametrize("job", ["running", "idle"])
def test_a_job_that_differs_by_white_space_is_not_the_declared_job(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, fault: str, job: str
) -> None:
    world = World(enrolled, tmp_path)
    loaded: dict[str, Any] = {} if job == "running" else dict(IDLE)
    world.runner.load(**loaded)
    assert state(world) == job
    exact = printed(world, **loaded)
    changed = EXACT_FAULTS[fault](world)(exact)
    assert changed != exact
    world.runner.job_answer = Result(0, changed, b"")
    with pytest.raises(runtime.RuntimeReadError) as refused:
        state(world)
    assert refused.value.reason == "identity-mismatch"
    refuses_to_start(monkeypatch, world)


def test_an_idle_state_with_white_space_at_its_end_is_not_the_idle_state(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    world.runner.load(**IDLE)
    changed = printed(world, **IDLE).replace(b"state = not running\n", b"state = not running \n")
    world.runner.job_answer = Result(0, changed, b"")
    refuses_to_start(monkeypatch, world)


def test_a_block_is_read_with_its_own_indentation_only() -> None:
    block = runtime._job_block
    text = "x = {\n\targuments = {\n\t\t/a b \n\t\t start\n\t\t\n\t}\n\tother = {\n\t}\n}\n"
    # A member keeps its own white space; an empty member is a member.
    assert block(text, "arguments") == ["/a b ", " start", ""]
    assert block(text, "other") == []
    assert block(text, "missing") is None
    assert block(text.replace("\t\t start\n", "\t start\n"), "arguments") is None
    assert block(text.replace("\t}\n\tother", "\t} \n\tother"), "arguments") is None
    assert block(text.replace("arguments = {\n", "arguments = { \n"), "arguments") is None
    # A line that is not exactly the opening opens nothing, so it is no second block either.
    twin = text.replace("\tother = {\n\t}\n", "\targuments = { \n\t}\n")
    assert twin != text and block(twin, "arguments") == ["/a b ", " start", ""]
    # A line ends at a line feed and nowhere else.
    assert block(text.replace("/a b \n", "/a\u2028b\x0c\n"), "arguments")[0] == "/a\u2028b\x0c"
    # Deeper in the print the same rule holds with the deeper indentation.
    deeper = text.replace("\n\t", "\n  \t")
    assert block(deeper, "arguments") == ["/a b ", " start", ""]


def test_a_block_that_is_not_closed_is_no_block(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    world.runner.load(**IDLE)
    # The print ends with the last variable: every line so far is a member.
    cut = printed(world, **IDLE).partition(b"\n\t}\n\n\tdomain = ")[0]
    assert cut.endswith(f"XPC_SERVICE_NAME => {LABEL}".encode())
    assert runtime._job_block(cut.decode(), "arguments") == [str(world.program), "start"]
    assert runtime._job_block(cut.decode(), "environment") is None
    world.runner.job_answer = Result(0, cut, b"")
    refuses_to_start(monkeypatch, world)


# Every `program =` line is the declared one, and there is exactly one.

PROGRAM_FAULTS: dict[str, Callable[[World], Callable[[bytes], bytes]]] = {
    "a-second-line-names-another-program": lambda w: padded(
        "\truns = 1\n", "\truns = 1\n\tprogram = /usr/libexec/another\n"
    ),
    "a-second-line-names-the-same-program": lambda w: padded(
        "\truns = 1\n", f"\truns = 1\n\tprogram = {w.program}\n"
    ),
    "a-first-line-names-another-program": lambda w: padded(
        "\ttype = LaunchAgent\n", "\ttype = LaunchAgent\n\tprogram = /usr/libexec/another\n"
    ),
    "no-line-names-a-program": lambda w: padded(f"\tprogram = {w.program}\n", ""),
}


@pytest.mark.parametrize("fault", sorted(PROGRAM_FAULTS))
@pytest.mark.parametrize("job", ["running", "idle"])
def test_exactly_one_program_line_names_the_declared_program(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, fault: str, job: str
) -> None:
    world = World(enrolled, tmp_path)
    loaded: dict[str, Any] = {} if job == "running" else dict(IDLE)
    world.runner.load(**loaded)
    exact = printed(world, **loaded)
    changed = PROGRAM_FAULTS[fault](world)(exact)
    assert changed != exact
    world.runner.job_answer = Result(0, changed, b"")
    refuses_to_start(monkeypatch, world)


# A declared path holds no character at which a line ends.


def test_the_line_boundaries_are_the_ones_python_documents() -> None:
    found = [
        chr(point)
        for point in range(sys.maxunicode + 1)
        if len(f"a{chr(point)}b".splitlines()) != 1
    ]
    assert sorted(found) == sorted(LINE_BOUNDARIES) and len(set(LINE_BOUNDARIES)) == 10
    assert sorted(runtime_settings._LINE_BOUNDARIES) == sorted(LINE_BOUNDARIES)


# The delete character is no line boundary; it is refused as a control character.
@pytest.mark.parametrize("character", [*LINE_BOUNDARIES, "\x7f"], ids=lambda c: f"U+{ord(c):04X}")
@pytest.mark.parametrize("member", ["app_root", "install_root", "api_executable"])
def test_a_path_with_a_line_boundary_is_refused(character: str, member: str) -> None:
    declared: dict[str, Any] = {**FLEET_ONLY, "runtime_start": dict(ROOTS)}
    target = declared if member == "api_executable" else declared["runtime_start"]
    assert parse_settings({**authored(), "fleet_start": declared}).fleet_start is not None
    target[member] = f"/opt/example/a{character}b"
    with pytest.raises(ValueError, match="one spelling"):
        parse_settings({**authored(), "fleet_start": declared})


# Single conditions of the start, each with the smallest test.

AFTER_STATUS: dict[str, Callable[[World], Any]] = {
    "the-launch-file-differs": lambda w: w.write(w.changed(KeepAlive=True)),
    "the-launch-file-is-gone": lambda w: w.launch.unlink(),
    "the-inventory-is-unreadable": lambda w: setattr(w.runner, "failure", "duplicate"),
}


@pytest.mark.parametrize("fault", sorted(AFTER_STATUS))
def test_an_activation_whose_readback_does_not_hold_is_unknown(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, fault: str
) -> None:
    world = World(enrolled, tmp_path)
    world.runner.load(**IDLE)
    real = world.runner.system

    def then(argv: list[str], kwargs: dict[str, Any]) -> Result:
        answer = real(argv, kwargs)
        AFTER_STATUS[fault](world)
        return answer

    monkeypatch.setattr(world.runner, "system", then)
    assert command(monkeypatch, world, "runtime-start") == runtime.UNKNOWN
    # The request woke the job; what was read afterwards did not hold.
    assert world.vendor_calls() == [["system", "status"]]
    assert world.runner.job is not None and world.runner.job["state"] == "running"
    assert world.runner.lock_held == [True] and not lock_is_held(world.settings)


@pytest.mark.parametrize("declared,bound", [({}, 20), ({"timeout_seconds": 45}, 45)])
def test_the_status_request_has_the_bound_of_the_start(
    enrolled: Any, tmp_path: Path, declared: dict[str, int], bound: int
) -> None:
    world = World(enrolled, tmp_path, **declared)
    world.runner.load(**IDLE)
    assert start(world) == "activated"
    (kwargs,) = [kwargs for argv, kwargs in world.runner.calls if argv[1:2] == ["system"]]
    assert kwargs["timeout"] == bound


@pytest.mark.parametrize("job", ["absent", "idle"])
def test_the_readback_is_made_under_the_operation_lock(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, job: str
) -> None:
    world = World(enrolled, tmp_path)
    if job == "idle":
        world.runner.load(**IDLE)
    held: dict[str, bool] = {}
    checks: list[bool] = []
    real_check = runtime.check_launch_file

    def recording(argv: list[str], **kwargs: Any) -> Result:
        if world.vendor_calls():
            # Every call after the vendor's own belongs to the readback.
            held[" ".join(argv[:2])] = lock_is_held(world.settings)
        return world.runner(argv, **kwargs)

    def checking(*arguments: Any) -> None:
        checks.append(lock_is_held(world.settings))
        real_check(*arguments)

    monkeypatch.setattr(runtime, "check_launch_file", checking)
    assert runtime.start_runtime(world.settings, recording) in {"started", "activated"}
    # Two reads and the readback compare the launch file; the job and the inventory follow.
    assert checks == [True, True, True]
    assert held == {
        "/bin/launchctl print": True,
        "/bin/ps -p": True,
        f"{world.settings.executable} list": True,
    }
    assert not lock_is_held(world.settings)


def exchanged_after_the_identity_check(patch: Any, exchange: Callable[[], Any]) -> None:
    real = runtime.check_identity

    def then(identity: Any, **kwargs: Any) -> None:
        real(identity, **kwargs)
        exchange()

    patch.setattr(runtime, "check_identity", then)


def test_another_file_at_the_name_after_the_identity_check_is_not_read(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)

    def exchange() -> None:
        # The same bytes, mode and single link in a file whose identity nobody checked.
        fresh = world.launch.with_name("fresh.plist")
        fresh.write_bytes(world.launch.read_bytes())
        fresh.chmod(0o644)
        os.replace(fresh, world.launch)

    with monkeypatch.context() as patch:
        exchanged_after_the_identity_check(patch, exchange)
        with pytest.raises(runtime.RuntimeReadError) as refused:
            world.check_launch_file()
    assert refused.value.reason == "identity-mismatch"
    # Checked from the beginning, the new file is the expected one.
    world.check_launch_file()


@pytest.mark.parametrize("kind", ["a-pipe", "a-directory"])
def test_another_kind_of_object_at_the_name_after_the_identity_check_is_not_read(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, kind: str
) -> None:
    world = World(enrolled, tmp_path)

    def exchange() -> None:
        world.launch.unlink()
        if kind == "a-pipe":
            os.mkfifo(world.launch, 0o644)
        else:
            world.launch.mkdir(mode=0o755)

    with monkeypatch.context() as patch:
        exchanged_after_the_identity_check(patch, exchange)
        with pytest.raises(runtime.RuntimeReadError) as refused:
            world.check_launch_file()
    assert refused.value.reason == "identity-mismatch"


def test_a_link_at_the_name_is_not_followed_even_to_the_checked_file(
    enrolled: Any, tmp_path: Path, monkeypatch: Any
) -> None:
    world = World(enrolled, tmp_path)
    directory_of_file = world.launch.parent
    kept = directory_of_file.with_name("kept")
    real_open = os.open

    def exchange() -> None:
        # The checked file stays untouched in its directory, which is moved aside;
        # the name now holds a link to it.
        directory_of_file.rename(kept)
        directory_of_file.mkdir(mode=0o755)
        world.launch.symlink_to(kept / world.launch.name)

    def restore() -> None:
        world.launch.unlink()
        directory_of_file.rmdir()
        kept.rename(directory_of_file)

    def opening(path: Any, flags: int, *arguments: Any, **options: Any) -> int:
        descriptor = real_open(path, flags, *arguments, **options)
        if Path(path) == world.launch:
            # Opened through the link: put everything back before the final comparison.
            restore()
        return descriptor

    with monkeypatch.context() as patch:
        exchanged_after_the_identity_check(patch, exchange)
        patch.setattr(runtime.os, "open", opening)
        with pytest.raises(runtime.RuntimeReadError) as refused:
            world.check_launch_file()
    assert refused.value.reason == "identity-mismatch"
    # The open itself refused the link, so nothing was put back by it.
    assert world.launch.is_symlink()
    restore()
    world.check_launch_file()


@pytest.mark.parametrize("mode", [0o400, 0o444, 0o604, 0o700, 0o744])
def test_only_the_two_modes_of_the_vendor_s_write_are_accepted(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, mode: int
) -> None:
    world = World(enrolled, tmp_path)
    world.launch.chmod(mode)
    with pytest.raises(runtime.RuntimeReadError):
        world.check_launch_file()
    refuses_to_start(monkeypatch, world)
    for accepted in (0o600, 0o644):
        world.launch.chmod(accepted)
        world.check_launch_file()


def test_the_launch_file_check_ends_with_the_pass(enrolled: Any, tmp_path: Path) -> None:
    world = World(enrolled, tmp_path)
    fleet = world.settings.fleet_start
    reader = world.reader()
    runtime.check_launch_file(world.settings, fleet, fleet.runtime_start, reader)
    # A pass whose time is used up reads no further identity.
    reader.deadline = time.monotonic() - 1
    with pytest.raises(ProcessTimeout):
        runtime.check_launch_file(world.settings, fleet, fleet.runtime_start, reader)


@pytest.mark.parametrize("pid", [0, "none", "-"])
def test_a_job_without_a_process_prints_no_process_line_at_all(
    enrolled: Any, tmp_path: Path, monkeypatch: Any, pid: Any
) -> None:
    world = World(enrolled, tmp_path)
    world.runner.load(**IDLE)
    assert state(world) == "idle"
    # `state = not running` beside any `pid = ` line is neither idle nor running.
    world.runner.load(state="not running", pid=pid)
    assert f"\tpid = {pid}\n".encode() in printed(world, state="not running", pid=pid)
    refuses_to_start(monkeypatch, world)


def test_the_runner_takes_eight_additions_with_names_of_sixty_four_characters() -> None:
    script = "import os; print(sorted(name for name in os.environ if name[0] in 'AV'))"
    eight = {f"V{index}": "x" for index in range(8)}
    result = process.run([sys.executable, "-c", script], environment=eight)
    assert result.stdout.decode().strip() == repr(sorted(eight))
    longest = "A" * 64
    result = process.run([sys.executable, "-c", script], environment={longest: "x"})
    assert result.stdout.decode().strip() == repr([longest])
    for refused in ({**eight, "V8": "x"}, {longest + "A": "x"}):
        with pytest.raises(ValueError, match="invalid bounded command"):
            process.run([sys.executable, "-c", "pass"], environment=refused)

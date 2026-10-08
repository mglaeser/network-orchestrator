"""A peer's mount in guest memory is not a second writer of a host path.

The reader refuses a workload while another inventoried definition has a
writable mount of the same, a nested or an aliased host path. A mount of the
vendor's memory-backed type names no host path: its source is a label that the
runtime hands to the guest. The vendor's builder definition is created with
such a mount and an empty source. Compared like a host path, an empty source is
the prefix of every absolute path, and that one definition would make every
workload unknown.

Mount rows are written as the vendor's encoder writes them at tags 1.2.0, 1.4.1
and 1.5.0 of apple/container (`Sources/ContainerResource/Container/Filesystem.swift`,
one file at the three tags; the builder's mounts are set in
`Sources/ContainerCommands/Builder/BuilderStart.swift`). What the type means is
read from the vendor's Linux runtime, so a mount is passed over only in a
definition that names that runtime as its handler, as the vendor writes it
(`runtimeHandler`, `Sources/ContainerResource/Container/ContainerConfiguration.swift`
line 48, one file at the three tags). No vendor command is run. Synthetic data
only.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch import pf_owner as owner
from netorch.codec import canonical_bytes, digest
from netorch.config import load_config, to_dict
from netorch.pf_owner import STRATEGY, Installation, admit, reconcile
from netorch.process import Result
from netorch.runtime_settings import (
    FileIdentity,
    contract_digest,
    load_settings,
    settings_to_dict,
)
from netorch.state import Intent, intent_to_dict
from netorch.storage import Store
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_pf_owner import FakeBackend
from tests.test_runtime_fleet_start import declared
from tests.test_runtime_tolerated_stopped_peer import tolerating

__all__ = ["enrolled"]

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
VERSIONS = ("1.2.0", "1.4.1", "1.5.0")
STATES = ("stopped", "running", "stopping", "unknown")
SERVICES = ("resolver", "web-proxy", "media-controller", "camera")
PEER = "example-builder"
# The handler every accepted version writes for a definition of the vendor's own
# Linux runtime, the builder's included: the default of `runtimeHandler`.
LINUX_RUNTIME = "container-runtime-linux"
VERIFIED = ("present", "verified")
REFUSED = ("unknown", "identity-mismatch")
MALFORMED = ("unknown", "malformed")


def guest_memory(source: str = "", options: tuple[str, ...] = ()) -> dict[str, Any]:
    """A mount of the memory-backed type; with the defaults, the builder's own."""
    return {
        "type": {"tmpfs": {}},
        "source": source,
        "destination": "/run",
        "options": list(options),
    }


def host_directory(source: Path | str, options: tuple[str, ...] = ()) -> dict[str, Any]:
    """A shared host directory, writable unless its options say `ro`."""
    return {
        "type": {"virtiofs": {}},
        "source": str(source),
        "destination": "/data",
        "options": list(options),
    }


def builder(tmp_path: Path) -> list[dict[str, Any]]:
    """The builder's two mounts as `BuilderStart.swift` sets them: guest memory at
    `/run` with an empty source, then its own writable export directory."""
    directory = tmp_path / "application-support" / "builder"
    directory.mkdir(parents=True, exist_ok=True)
    shared = host_directory(directory)
    return [guest_memory(), {**shared, "destination": "/var/lib/container-builder-shim/exports"}]


def define(
    runner: FakeRunner,
    mounts: list[Any],
    *,
    name: str = PEER,
    state: str = "stopped",
    handler: Any = LINUX_RUNTIME,
) -> None:
    """Put a definition that no settings enroll into the vendor's inventory.

    It names the vendor's Linux runtime as its handler unless another value is
    given; an ellipsis leaves the member out.
    """
    status: dict[str, Any] = {"state": state, "networks": []}
    if state == "running":
        status["startedDate"] = "2026-01-01T00:00:05Z"
    configuration: dict[str, Any] = {"id": name, "mounts": mounts}
    if handler is not ...:
        configuration["runtimeHandler"] = handler
    runner.items[name] = {"id": name, "configuration": configuration, "status": status}


def read(config: Any, settings: Any, runner: FakeRunner) -> dict[str, tuple[str, str]]:
    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    return {name: (item.state, item.reason) for name, item in observed.services.items()}


def every(outcome: tuple[str, str]) -> dict[str, tuple[str, str]]:
    return dict.fromkeys(SERVICES, outcome)


def only(service: str, outcome: tuple[str, str]) -> dict[str, tuple[str, str]]:
    """The named workload has the outcome; every other one is verified."""
    return {**every(VERIFIED), service: outcome}


def data_directory(settings: Any, service: str) -> Path:
    return Path(settings.contract(service).mounts[0].path)


def accepting(settings: Any, version: str) -> Any:
    return replace(settings, accepted_version=version, legacy_risk_acknowledged=version == "1.2.0")


# The defect and its correction -------------------------------------------------


@pytest.mark.parametrize("state", STATES)
@pytest.mark.parametrize("version", VERSIONS)
def test_a_builder_definition_no_longer_makes_every_workload_unknown(
    enrolled: Any, tmp_path: Path, version: str, state: str
) -> None:
    config, settings, items = enrolled
    settings = accepting(settings, version)
    runner = FakeRunner(settings, items)
    assert read(config, settings, runner) == every(VERIFIED)
    define(runner, builder(tmp_path), state=state)
    observed = runtime.observe_runtime(config, settings, runner, clock=lambda: 1000)
    assert {name: (item.state, item.reason) for name, item in observed.services.items()} == every(
        VERIFIED
    )
    assert {name: item.state for name, item in observed.profiles.items()} == {
        "proxy-high": "present",
        "camera-web": "present",
    }
    assert observed.network_generation is not None


# What the accepted versions record for a mount in guest memory. The builder's
# is the same row at the three tags. `--tmpfs` goes through `Filesystem.tmpfs`,
# which sets the source `tmpfs`, and takes mount options from 1.4.1 on.
# `--mount type=tmpfs` keeps the empty source of `Filesystem()` at 1.2.0 and is
# given the source `tmpfs` from 1.4.1 on (`Parser.swift` of each tag).
RECORDED = [
    ("1.2.0", "builder", "", ()),
    ("1.4.1", "builder", "", ()),
    ("1.5.0", "builder", "", ()),
    ("1.2.0", "--tmpfs", "tmpfs", ()),
    ("1.4.1", "--tmpfs", "tmpfs", ("noexec", "size=1m")),
    ("1.5.0", "--tmpfs", "tmpfs", ("noexec", "size=1m")),
    ("1.2.0", "--mount", "", ("mode=1777",)),
    ("1.4.1", "--mount", "tmpfs", ("mode=1777",)),
    ("1.5.0", "--mount", "tmpfs", ("mode=1777",)),
]


@pytest.mark.parametrize("state", ["stopped", "running"])
@pytest.mark.parametrize(
    ("version", "origin", "source", "options"),
    RECORDED,
    ids=[f"{version}:{origin}" for version, origin, _, _ in RECORDED],
)
def test_guest_memory_is_passed_over_as_each_version_records_it(
    enrolled: Any, version: str, origin: str, source: str, options: tuple[str, ...], state: str
) -> None:
    config, settings, items = enrolled
    settings = accepting(settings, version)
    runner = FakeRunner(settings, items)
    define(runner, [guest_memory(source, options)], state=state)
    assert read(config, settings, runner) == every(VERIFIED)


def test_the_label_of_guest_memory_is_not_looked_up_as_a_path(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    # The reader's working directory holds an entry named like the label, and
    # that entry is the camera's own data directory under another name.
    work = tmp_path / "work"
    work.mkdir()
    (work / "tmpfs").symlink_to(data_directory(settings, "camera"))
    monkeypatch.chdir(work)
    define(runner, [guest_memory("tmpfs")])
    assert read(config, settings, runner) == every(VERIFIED)
    # On a mount of another type the same text is a source and is compared.
    define(runner, [{**guest_memory("tmpfs"), "type": {"virtiofs": {}}}])
    assert read(config, settings, runner) == only("camera", REFUSED)


def test_the_type_decides_and_not_the_source(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    camera = data_directory(settings, "camera")
    # The runtime gives the guest this text as the label of a memory mount and
    # opens nothing on the host for it, so it is no writer of that directory.
    define(runner, [guest_memory(str(camera)), guest_memory(str(camera.parent))])
    assert read(config, settings, runner) == every(VERIFIED)


def test_only_the_peer_reading_passes_over_and_only_that_type() -> None:
    rows = [
        guest_memory(),
        host_directory("/srv/example/first"),
        guest_memory("tmpfs", ("ro",)),
        {"source": "", "options": []},
        {"type": "tmpfs", "source": "/srv/example/second", "options": ["ro"]},
    ]
    assert runtime._mounts({"mounts": rows}) == [
        ("", True),
        ("/srv/example/first", True),
        ("tmpfs", False),
        ("", True),
        ("/srv/example/second", False),
    ]
    assert runtime._mounts({"mounts": rows}, without_guest_memory=True) == [
        ("/srv/example/first", True),
        ("", True),
        ("/srv/example/second", False),
    ]


# What is still refused ---------------------------------------------------------


def overlap(settings: Any, tmp_path: Path, how: str) -> Path:
    camera = data_directory(settings, "camera")
    if how == "the same directory":
        return camera
    if how == "a directory below it":
        return camera / "inner"
    if how == "a directory above it":
        return camera.parent
    alias = tmp_path / "another-name"
    alias.symlink_to(camera)
    return alias


@pytest.mark.parametrize("state", ["stopped", "running"])
@pytest.mark.parametrize("memory_first", [True, False], ids=["memory-first", "host-path-first"])
@pytest.mark.parametrize(
    "how",
    ["the same directory", "a directory below it", "a directory above it", "another name of it"],
)
def test_a_host_path_beside_guest_memory_is_still_a_second_writer(
    enrolled: Any, tmp_path: Path, how: str, memory_first: bool, state: str
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    mounts = [guest_memory(), host_directory(overlap(settings, tmp_path, how))]
    define(runner, mounts if memory_first else mounts[::-1], state=state)
    # The directory above the camera's holds every workload's directory.
    expected = every(REFUSED) if how == "a directory above it" else only("camera", REFUSED)
    assert read(config, settings, runner) == expected


def test_a_later_peer_is_still_compared_after_one_with_guest_memory_only(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    define(runner, [guest_memory(), guest_memory("tmpfs")], name="example-first")
    define(runner, [host_directory(data_directory(settings, "resolver"))], name="example-second")
    define(runner, [guest_memory()], name="example-third")
    assert read(config, settings, runner) == only("resolver", REFUSED)


def test_two_host_paths_conflict_as_before(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    camera = data_directory(settings, "camera")
    define(runner, [host_directory(camera)])
    assert read(config, settings, runner) == only("camera", REFUSED)
    # Read-only sharing of a host path is allowed.
    define(runner, [host_directory(camera, ("ro",))])
    assert read(config, settings, runner) == every(VERIFIED)


def test_a_read_only_host_path_beside_guest_memory_is_no_writer(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    camera = data_directory(settings, "camera")
    define(runner, [guest_memory(), host_directory(camera, ("ro",)), guest_memory("tmpfs")])
    assert read(config, settings, runner) == every(VERIFIED)


BLOCK = {"format": "ext4", "cache": {"on": {}}, "sync": {"fsync": {}}}
# Members of a mount row with an empty source that is not of the memory-backed
# type as the vendor writes it. Each such row is compared as before.
NEAR_MISSES: dict[str, dict[str, Any]] = {
    "no type member": {},
    "the member under another name": {"Type": {"tmpfs": {}}},
    "the case name as text": {"type": "tmpfs"},
    "the type as its JSON text": {"type": '{"tmpfs":{}}'},
    "the type as printed text": {"type": "{'tmpfs': {}}"},
    "null": {"type": None},
    "true": {"type": True},
    "a number": {"type": 1},
    "an empty object": {"type": {}},
    "an empty list": {"type": []},
    "a list holding the case name": {"type": ["tmpfs"]},
    "a list holding the type": {"type": [{"tmpfs": {}}]},
    "null as the value": {"type": {"tmpfs": None}},
    "a list as the value": {"type": {"tmpfs": []}},
    "text as the value": {"type": {"tmpfs": ""}},
    "false as the value": {"type": {"tmpfs": False}},
    "zero as the value": {"type": {"tmpfs": 0}},
    "a value with a member": {"type": {"tmpfs": {"size": 0}}},
    "a value holding the type": {"type": {"tmpfs": {"tmpfs": {}}}},
    "a second case beside it": {"type": {"tmpfs": {}, "virtiofs": {}}},
    "a capital letter": {"type": {"Tmpfs": {}}},
    "capital letters": {"type": {"TMPFS": {}}},
    "a blank after the name": {"type": {"tmpfs ": {}}},
    "a blank before the name": {"type": {" tmpfs": {}}},
    "a line feed after the name": {"type": {"tmpfs\n": {}}},
    "a look-alike letter": {"type": {"tmpf\u0455": {}}},
    "a full-width letter": {"type": {"\uff54mpfs": {}}},
    "full-width letters": {"type": {"\uff54\uff4d\uff50\uff46\uff53": {}}},
    "a zero-width space after the name": {"type": {"tmpfs\u200b": {}}},
    "a NUL after the name": {"type": {"tmpfs\x00": {}}},
    "a byte-order mark before the name": {"type": {"\ufefftmpfs": {}}},
    "another memory file system": {"type": {"ramfs": {}}},
    "a shorter name": {"type": {"tmp": {}}},
    "the type one level down": {"type": {"type": {"tmpfs": {}}}},
    "a shared directory": {"type": {"virtiofs": {}}},
    "a named volume": {"type": {"volume": {"name": "example-volume", **BLOCK}}},
    "a block image": {"type": {"block": BLOCK}},
}


@pytest.mark.parametrize("state", ["stopped", "running"])
@pytest.mark.parametrize("members", NEAR_MISSES.values(), ids=NEAR_MISSES.keys())
def test_a_type_that_only_resembles_guest_memory_is_compared_as_before(
    enrolled: Any, members: dict[str, Any], state: str
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    row = {"source": "", "destination": "/run", "options": [], **members}
    define(runner, [row], state=state)
    assert read(config, settings, runner) == every(REFUSED)
    # With the vendor's own spelling of the type the same row is passed over.
    define(runner, [{**row, "type": {"tmpfs": {}}}], state=state)
    assert read(config, settings, runner) == every(VERIFIED)


@pytest.mark.parametrize("members", NEAR_MISSES.values(), ids=NEAR_MISSES.keys())
def test_a_near_miss_on_a_workloads_directory_is_still_a_second_writer(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, members: dict[str, Any]
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    camera = data_directory(settings, "camera")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    # The row in question stands behind one that is compared and one that is
    # passed over, and it names a host path instead of nothing.
    ahead = [host_directory(elsewhere), guest_memory()]
    # In the reader's working directory the label is another name of the
    # camera's directory, so both sources below name that directory.
    work = tmp_path / "work"
    work.mkdir()
    (work / "tmpfs").symlink_to(camera)
    monkeypatch.chdir(work)
    for source in (str(camera), "tmpfs"):
        row = {"source": source, "destination": "/data", "options": [], **members}
        define(runner, [*ahead, row])
        assert read(config, settings, runner) == only("camera", REFUSED)
        # With the vendor's own spelling of the type the same row is passed over.
        define(runner, [*ahead, {**row, "type": {"tmpfs": {}}}])
        assert read(config, settings, runner) == every(VERIFIED)


# What a row of the memory-backed type says beside its type is not consulted.
OTHER_MEMBERS: dict[str, dict[str, Any]] = {
    "no destination": {"destination": ...},
    "the root directory as the label": {"source": "/"},
    "mount options of another kind": {"options": ["rbind", "rw"]},
}


@pytest.mark.parametrize("change", OTHER_MEMBERS.values(), ids=OTHER_MEMBERS.keys())
def test_the_rest_of_a_guest_memory_row_does_not_decide(
    enrolled: Any, change: dict[str, Any]
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    # An ellipsis stands for a member that the row does not have.
    row = {key: value for key, value in {**guest_memory(), **change}.items() if value is not ...}
    # As a shared directory the row is compared: its source is above every path.
    define(runner, [{**row, "type": {"virtiofs": {}}}])
    assert read(config, settings, runner) == every(REFUSED)
    define(runner, [row])
    assert read(config, settings, runner) == every(VERIFIED)


# The runtime that gives the type its meaning -------------------------------------

# A `runtimeHandler` member that is not the vendor's Linux runtime as the vendor
# writes it. An ellipsis stands for a definition without the member.
OTHER_HANDLERS: dict[str, Any] = {
    "another runtime": "example-runtime",
    "no member": ...,
    "null": None,
    "true": True,
    "a number": 1,
    "an empty text": "",
    "a list holding the name": [LINUX_RUNTIME],
    "an object holding the name": {LINUX_RUNTIME: {}},
    "an object naming it": {"name": LINUX_RUNTIME},
    "a capital letter": "Container-runtime-linux",
    "capital letters": LINUX_RUNTIME.upper(),
    "a blank after the name": LINUX_RUNTIME + " ",
    "a blank before the name": " " + LINUX_RUNTIME,
    "a line feed after the name": LINUX_RUNTIME + "\n",
    "a NUL after the name": LINUX_RUNTIME + "\x00",
    "a zero-width space after the name": LINUX_RUNTIME + chr(0x200B),
    "a full-width letter": chr(0xFF43) + LINUX_RUNTIME[1:],
    "a look-alike letter": LINUX_RUNTIME.replace("x", chr(0x445)),
    "underscores": LINUX_RUNTIME.replace("-", "_"),
    "a longer name": LINUX_RUNTIME + "-2",
    "a shorter name": "container-runtime",
    "the name behind a directory": "plugins/" + LINUX_RUNTIME,
}


@pytest.mark.parametrize("state", ["stopped", "running"])
@pytest.mark.parametrize("handler", OTHER_HANDLERS.values(), ids=OTHER_HANDLERS.keys())
def test_guest_memory_is_passed_over_only_under_the_vendors_linux_runtime(
    enrolled: Any, tmp_path: Path, handler: Any, state: str
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    # The builder's own two mounts in a definition of another handler: nothing
    # establishes what the type means there, so its empty source is compared.
    define(runner, builder(tmp_path), state=state, handler=handler)
    assert read(config, settings, runner) == every(REFUSED)
    # The same definition as the vendor writes it.
    define(runner, builder(tmp_path), state=state)
    assert read(config, settings, runner) == every(VERIFIED)


@pytest.mark.parametrize(
    "member", ["RuntimeHandler", "runtimehandler", "runtime_handler", "runtime", "handler"]
)
def test_the_handler_under_another_name_is_no_handler(
    enrolled: Any, tmp_path: Path, member: str
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    define(runner, builder(tmp_path), handler=...)
    runner.items[PEER]["configuration"][member] = LINUX_RUNTIME
    assert read(config, settings, runner) == every(REFUSED)
    runner.items[PEER]["configuration"]["runtimeHandler"] = LINUX_RUNTIME
    assert read(config, settings, runner) == every(VERIFIED)


def test_a_host_path_as_the_label_under_another_runtime_is_a_second_writer(enrolled: Any) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    camera = data_directory(settings, "camera")
    row = {"type": {"tmpfs": {}}, "source": str(camera), "destination": "/data", "options": []}
    # A running definition of another runtime: what it does with that source is
    # not known, so the camera's directory may have a second writer.
    define(runner, [row], state="running", handler="example-runtime")
    assert read(config, settings, runner) == only("camera", REFUSED)
    # Under the vendor's Linux runtime the same text is a label for the guest.
    define(runner, [row], state="running")
    assert read(config, settings, runner) == every(VERIFIED)


def test_the_handler_decides_for_guest_memory_only(enrolled: Any, tmp_path: Path) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    camera = data_directory(settings, "camera")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    for handler in (LINUX_RUNTIME, "example-runtime", ...):
        # A host path is compared under every handler.
        define(runner, [host_directory(camera)], handler=handler)
        assert read(config, settings, runner) == only("camera", REFUSED)
        # And a definition whose mounts conflict with nothing refuses nothing.
        define(
            runner, [host_directory(elsewhere), host_directory(camera, ("ro",))], handler=handler
        )
        assert read(config, settings, runner) == every(VERIFIED)


OTHER_SHAPES: dict[str, dict[str, Any]] = {
    "no source": {"source": ...},
    "null as source": {"source": None},
    "a number as source": {"source": 7},
    "a list as source": {"source": ["tmpfs"]},
    "an object as source": {"source": {}},
    "no options": {"options": ...},
    "null as options": {"options": None},
    "text as options": {"options": "ro"},
    "an object as options": {"options": {}},
}


@pytest.mark.parametrize("change", OTHER_SHAPES.values(), ids=OTHER_SHAPES.keys())
def test_a_guest_memory_row_of_another_shape_is_still_malformed(
    enrolled: Any, change: dict[str, Any]
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    # An ellipsis stands for a member that the row does not have.
    row = {key: value for key, value in {**guest_memory(), **change}.items() if value is not ...}
    define(runner, [row])
    assert read(config, settings, runner) == every(MALFORMED)
    # Also behind a well-formed row that is passed over.
    define(runner, [guest_memory(), row])
    assert read(config, settings, runner) == every(MALFORMED)


# The tolerance setting ---------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "tolerated", "expected"),
    [
        ("stopped", False, REFUSED),
        ("running", False, REFUSED),
        ("stopped", True, VERIFIED),
        ("running", True, REFUSED),
        ("stopping", True, REFUSED),
        ("unknown", True, REFUSED),
    ],
)
def test_the_tolerance_setting_is_still_what_accepts_a_stopped_second_writer(
    enrolled: Any, state: str, tolerated: bool, expected: tuple[str, str]
) -> None:
    config, settings, runner = declared(enrolled)
    # A definition that really names the camera's host directory, and has guest
    # memory as well. Only the camera's contract can tolerate it.
    define(
        runner, [guest_memory(), host_directory(data_directory(settings, "camera"))], state=state
    )
    if tolerated:
        config, settings = tolerating(config, settings, "camera", PEER)
    assert read(config, settings, runner) == only("camera", expected)


# What follows from the reading ---------------------------------------------------


@pytest.mark.parametrize("state", ["stopped", "running"])
def test_probe_and_recovery_act_on_a_stopped_workload_beside_a_builder(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    define(runner, builder(tmp_path), state=state)
    runner.items["example-camera"]["status"]["state"] = "stopped"
    assert read(config, settings, runner) == only("camera", ("absent", "confirmed-absent"))
    observe = runtime.observe_runtime
    monkeypatch.setattr(runtime, "load_settings", lambda _path: settings)
    monkeypatch.setattr(runtime, "observe_runtime", lambda *args: observe(*args[:2], runner))
    probe = ["--settings", "/unused", "probe", "--service"]
    assert runtime.main([*probe, "camera"]) == runtime.STOPPED
    assert runtime.main([*probe, "resolver"]) == 0
    recovered = runtime.recover_service(config, settings, "camera", runner)
    assert recovered.services["camera"].state == "present"
    starts = [argv for argv, _ in runner.calls if argv[1:2] == ["start"]]
    assert starts == [[settings.executable, "start", "example-camera"]]
    assert runner.items[PEER]["status"]["state"] == state


def test_a_builder_counts_in_the_all_stopped_guard_like_any_other_definition(
    enrolled: Any, tmp_path: Path
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    for item in runner.items.values():
        item["status"] = {"state": "stopped", "networks": []}
    guarded = every(("unknown", "incomplete"))
    stopped = every(("absent", "confirmed-absent"))
    assert read(config, settings, runner) == guarded
    # One definition that is not stopped has always ended that guard, and the
    # guard is not changed here. What changed is the reading once it has ended.
    define(runner, [], name="example-plain", state="running")
    assert read(config, settings, runner) == stopped
    del runner.items["example-plain"]
    # A stopped builder leaves every definition stopped: still unknown.
    define(runner, builder(tmp_path), state="stopped")
    assert read(config, settings, runner) == guarded
    # A builder in any other state is now read like the definition without
    # mounts; before, the guard had ended as well and the workloads were refused
    # for the builder's empty source.
    for state in ("running", "stopping", "unknown"):
        define(runner, builder(tmp_path), state=state)
        assert read(config, settings, runner) == stopped


def test_the_root_owner_keeps_its_rules_beside_a_builder(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    monkeypatch.setattr(owner, "protected_native_code", lambda paths: None)

    def routed(arguments: list[str], **kwargs: Any) -> Result:
        if arguments[:2] == ["/bin/launchctl", "asuser"]:
            # The fixed wrapper that runs the vendor CLI as the enrolled account.
            account = settings.account
            return runner(
                arguments[10:],
                run_uid=account.uid,
                run_gid=account.gid,
                account_home=account.home,
                **kwargs,
            )
        return runner(arguments, **kwargs)

    monkeypatch.setattr(owner, "run", routed)
    installation = Installation(
        "site-forwarding",
        "com.apple/netorch.site-forwarding",
        settings_to_dict(settings),
        hashlib.sha256(b"backend").hexdigest(),
        str(tmp_path / "report.json"),
    )
    root = Store(tmp_path / "root")
    root.write("installation.json", installation.to_dict())
    root.write("policy.json", to_dict(config))
    root.write("admissions.json", {"schema_version": 1, "strategy": STRATEGY, "profiles": {}})
    root.write("operator-intent.json", intent_to_dict(Intent()))
    for profile in config.profiles:
        if config.profile_owner(profile).id == installation.owner:
            admit(root, profile.id, acknowledge_bounded_risk=True, now=time.time() - 1)
    backend = FakeBackend()

    def root_pass() -> dict[str, Any]:
        # The owner's own observer, as its scheduled command passes it.
        return reconcile(
            root,
            owner._runtime_observer,
            lambda store, record: backend,
            report=lambda record, snapshot: None,
        )

    assert sorted(root_pass()["changed"]) == [
        "dns-tcp:activate",
        "dns-udp:activate",
        "media-udp:activate",
        "proxy-standard:activate",
    ]
    rules = backend.rules
    assert rules.count("# netorch:") == 5
    for state in ("running", "stopped"):
        define(runner, builder(tmp_path), state=state)
        passed = root_pass()
        assert passed["changed"] == [] and passed["phase"] == "committed"
        assert backend.rules == rules
    # The same definition over the resolver's host directory is a second writer:
    # the root owner retires the rules of that workload, and of no other.
    define(runner, [guest_memory(), host_directory(data_directory(settings, "resolver"))])
    assert sorted(root_pass()["changed"]) == [
        "dns-tcp:drain",
        "dns-tcp:withdraw",
        "dns-udp:drain",
        "dns-udp:withdraw",
    ]
    assert "# netorch:dns-" not in backend.rules
    assert backend.rules.count("# netorch:") == 3


# The workload's own side is not changed ------------------------------------------


def with_own_guest_memory(
    config: Any,
    settings: Any,
    runner: FakeRunner,
    source: str,
    *enrolled_too: FileIdentity,
    handler: Any = LINUX_RUNTIME,
) -> tuple[Any, Any]:
    """Give the camera's definition guest memory and enroll its new fingerprint.

    The definition names the vendor's Linux runtime as its handler unless
    another value is given; an ellipsis leaves the member out.
    """
    configuration = runner.items["example-camera"]["configuration"]
    configuration["mounts"].append(guest_memory(source))
    if handler is not ...:
        configuration["runtimeHandler"] = handler
    contract = settings.contract("camera")
    contract = replace(
        contract,
        configuration_sha256=digest(configuration),
        mounts=(*contract.mounts, *enrolled_too),
    )
    settings = replace(
        settings,
        contracts=tuple(contract if c.service == "camera" else c for c in settings.contracts),
    )
    return runtime.derive_policy(config, settings), settings


@pytest.mark.parametrize("source", ["", "tmpfs"])
def test_a_workload_with_guest_memory_of_its_own_stays_unknown_itself(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    monkeypatch.chdir(tmp_path)
    config, settings = with_own_guest_memory(config, settings, runner, source)
    observed = read(config, settings, runner)
    # Its mounts are compared with the enrolled paths, and the settings loader
    # takes no path that is empty or relative: the workload stays unknown.
    assert observed["camera"] == REFUSED
    # To the other workloads it is a peer like the builder.
    assert observed == only("camera", REFUSED)


@pytest.mark.parametrize("handler", ["example-runtime", ...], ids=["another runtime", "no member"])
def test_a_workload_of_another_runtime_is_a_peer_whose_guest_memory_is_compared(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, handler: Any
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    monkeypatch.chdir(tmp_path)
    config, settings = with_own_guest_memory(config, settings, runner, "", handler=handler)
    # As before: to the other three its empty source is above every path.
    assert read(config, settings, runner) == every(REFUSED)


def test_the_comparison_from_the_workloads_own_side_is_unchanged(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    # Settings built here, which no file can hold: the empty source is enrolled
    # as the working directory it resolves to. From the workload's own side the
    # empty source is still the prefix of every peer's path.
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    monkeypatch.chdir(work)
    meta = work.lstat()
    own = FileIdentity("", "directory", os.geteuid(), meta.st_dev, meta.st_ino)
    config, settings = with_own_guest_memory(config, settings, runner, "", own)
    observed = read(config, settings, runner)
    assert observed["camera"] == REFUSED
    assert observed == only("camera", REFUSED)
    # It is the comparison that refuses, not the enrolled working directory:
    # once no peer writes anywhere, the same workload is verified.
    for name in ("example-resolver", "example-web-proxy", "example-media-controller"):
        runner.items[name]["configuration"]["mounts"][0]["options"] = ["ro"]
    assert read(config, settings, runner)["camera"] == VERIFIED


def captured_mounts(settings: Any, runner: FakeRunner) -> list[str] | None:
    """The paths a capture stores for the camera, or nothing when it is refused."""
    try:
        captured = runtime.capture_enrollment(settings, runner)
    except (OSError, runtime.RuntimeReadError):
        return None
    return [identity.path for identity in captured.contract("camera").mounts]


@pytest.mark.parametrize("source", ["", "tmpfs"])
def test_enrollment_does_not_pass_over_a_workloads_own_guest_memory(
    enrolled: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    config, settings, items = enrolled
    runner = FakeRunner(settings, items)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    monkeypatch.chdir(work)
    camera = str(data_directory(settings, "camera"))
    assert captured_mounts(settings, runner) == [camera]
    _, settings = with_own_guest_memory(config, settings, runner, source)
    # The capture is refused, or it stores the label as a path, which the
    # settings loader does not read. Which of the two happens is not this
    # change's subject: it never returns an enrollment that leaves the mount out.
    assert captured_mounts(settings, runner) in (None, [camera, source])


# No document, digest or stored form moves ----------------------------------------


def test_the_shipped_examples_keep_every_digest() -> None:
    """Every literal below was computed with the tree this change is based on."""
    shipped = load_settings(EXAMPLES / "runtime-settings.json")
    assert {item.service: contract_digest(item) for item in shipped.contracts} == {
        "resolver": "738717b976875cab43dc7235150aebbaa3b894a4904c86334dcd9d63250ee153",
        "web-proxy": "afcfdc49c1a7fd7b435a54f1cb75b32fb48fb3ea1865f3e31b4b854081bb5508",
        "media-controller": "0067741a703af180b7fac6e0be8d1880699e1db21517ff09d047cfa83d479d19",
        "camera": "07b9fec3b2403f238c5b4689d80815a7bdb0913a1e887c5fb4228a7fc8cc3f45",
    }
    assert (
        hashlib.sha256(canonical_bytes(settings_to_dict(shipped))).hexdigest()
        == "d1307ffc7cb45fb28b71c4cd190e57a4f8548b76b28a66fad9c4eec52cc28ab8"
    )
    derived = runtime.derive_policy(load_config(EXAMPLES / "network.json"), shipped)
    assert (
        hashlib.sha256(canonical_bytes(to_dict(derived))).hexdigest()
        == "431d44362de0cda22ceb0fc2d289c40e38fe3d856a47c860b0a2736750a0e497"
    )

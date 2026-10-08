"""What waits for one read of the fleet, and what a stated bound means for it.

Three things wait for a read. The supervisor waits for the probe: where a
bundle carries the probe's own settings and these state `read_timeout_seconds`,
the bundle is rendered only if the check's timeout leaves the margin above that
bound. The owner endpoint's clients wait ten seconds, so the endpoint keeps
eight and a fleet that needs longer stays unknown to them. And whoever wants a
lock waits for the reads made under it.

A bundle whose settings do not state the member renders the bytes it rendered
before, whatever its timeouts are. Fake runner and injected clocks only.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

import pytest

from netorch import apple_runtime as runtime
from netorch import bonjour_owner, owners
from netorch import deployment as implementation
from netorch import pf_owner as owner
from netorch import runtime_settings as loader
from netorch.codec import canonical_bytes, strict_loads
from netorch.config import load_config
from netorch.deployment import render_bundle
from netorch.deployment_config import DeploymentError, parse_deployment
from netorch.discovery_plan import plan_discovery
from netorch.mock import mock_admissions
from netorch.pf_owner import Installation, admit, reconcile
from netorch.planner import plan
from netorch.process import ProcessTimeout, Result
from netorch.runtime_settings import settings_to_dict
from netorch.state import Intent, Snapshot
from netorch.storage import Busy, Store
from tests.test_apple_runtime import FakeRunner, enrolled
from tests.test_owner_lock_busy import Clock
from tests.test_pf_owner import FakeBackend
from tests.test_runtime_read_deadline import (
    START,
    Paced,
    _installed,
    _probe,
    _routed,
    states,
    with_bound,
)

__all__ = ["enrolled"]

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
BACKEND = b"#!/bin/sh\nexit 0\n"
# What waits for one read waits this much longer than the read may take.
MARGIN = 2
REFUSAL = "probe check timeout leaves no margin above the read bound of its settings"
# The shipped probe, part by part.
PYTHON = "/operator/runtime/bin/python3"
MODULE = "netorch.apple_runtime"
FILE = "{release}/data/runtime-settings.json"
TAIL = ["probe", "--service", "media-controller"]
SHIPPED = [PYTHON, "-m", MODULE, "--settings", FILE, *TAIL]


def digest_of(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class Site:
    """The shipped example deployment, rendered from payloads served for its own source paths.

    No path of the test's own directory enters the manifest, so the rendered
    bytes are the same on every machine and can be compared with literals.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch, output: Path) -> None:
        self.monkeypatch, self.output = monkeypatch, output
        self.manifest: dict[str, Any] = strict_loads((EXAMPLES / "deployment.json").read_bytes())
        forwarding = strict_loads((EXAMPLES / "forwarding-settings.json").read_bytes())
        forwarding["backend_sha256"] = digest_of(BACKEND)
        self.manifest["forwarding"]["backend_sha256"] = digest_of(BACKEND)
        self.payloads = {
            "runtime-settings": (EXAMPLES / "runtime-settings.json").read_bytes(),
            "bonjour-settings": b"{}",
            "bindings": (EXAMPLES / "owner-bindings.json").read_bytes(),
            "forwarding-settings": canonical_bytes(forwarding),
        }
        self.probe: dict[str, Any] = next(
            item for item in self.manifest["monitors"] if item["role"] == "workload"
        )
        assert self.probe["check_argv"] == SHIPPED and self.probe["timeout_seconds"] == 10
        self._read = implementation._read_file

    def state(self, bound: Any, **changes: Any) -> None:
        """The probe's settings artifact: the shipped document with the member stated."""
        document = strict_loads((EXAMPLES / "runtime-settings.json").read_bytes())
        self.payloads["runtime-settings"] = canonical_bytes(
            {**document, "read_timeout_seconds": bound, **changes}
        )

    def render(self, name: str = "bundle") -> dict[str, Any]:
        served = {self.manifest["forwarding"]["backend_source"]: BACKEND}
        for artifact in self.manifest["artifacts"]:
            served[artifact["source"]] = self.payloads[artifact["id"]]
            artifact["sha256"] = digest_of(self.payloads[artifact["id"]])

        def read(path: Path, **kwargs: Any) -> bytes:
            return served[str(path)] if str(path) in served else self._read(path, **kwargs)

        self.monkeypatch.setattr(implementation, "_read_file", read)
        result: dict[str, Any] = render_bundle(
            parse_deployment(canonical_bytes(self.manifest)),
            load_config(EXAMPLES / "network.json"),
            self.output / name,
        )
        return result

    def refused(self, name: str = "bundle") -> bool:
        """Whether rendering is refused for the probe's timeout, with nothing written."""
        try:
            self.render(name)
        except DeploymentError as exc:
            assert str(exc) == REFUSAL and not (self.output / name).exists()
            return True
        assert (self.output / name / "manifest.json").is_file()
        return False

    def on_disk(self, name: str = "bundle") -> str:
        """One digest over the name and the bytes of every file of a rendered bundle."""
        files = sorted(path for path in (self.output / name).rglob("*") if path.is_file())
        return digest_of(
            b"".join(
                str(path.relative_to(self.output / name)).encode() + b"\0" + path.read_bytes()
                for path in files
            )
        )


@pytest.fixture
def site(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Site:
    return Site(monkeypatch, tmp_path)


# --- Without the member a bundle is the bundle it was ---------------------------


@pytest.mark.parametrize(
    "timeout,bundle_digest,files",
    [
        # The shipped example, and the same with every check timeout at one second.
        # All four literals were computed with the tree this change is based on.
        (
            None,
            "026b0dc01b415abe060abd74c66fec7a4f7bd32a322e39740ab55f68c877ce38",
            "7703cd106364816171d71b57caa0fc1fdbaf4cd0d11c2667badc437ef2332b0c",
        ),
        (
            1,
            "4da55cc78e2e992a18320d20b83e4aaa453dfc6dbc5f0f537498d114eda50792",
            "a3956934d7448a1a180df4a805bcf4f7348214f0fabc1b82a8e417ce88edc15c",
        ),
    ],
)
def test_a_bundle_without_the_member_renders_the_bytes_it_rendered(
    site: Site, timeout: int | None, bundle_digest: str, files: str
) -> None:
    if timeout is not None:
        for monitor in site.manifest["monitors"]:
            monitor["timeout_seconds"] = timeout
    result = site.render()
    assert b"read_timeout_seconds" not in site.payloads["runtime-settings"]
    assert result["bundle_digest"] == bundle_digest
    assert site.on_disk() == files
    monitrc = (site.output / "bundle/user/monit/monitrc").read_text()
    assert monitrc.count(f"  timeout {10 if timeout is None else timeout} seconds\n") == 2


# --- The probe's check leaves the margin above a stated bound -------------------


@pytest.mark.parametrize(
    "bound,timeout,rendered",
    [
        # One second below the margin, and the margin itself, at each end and between.
        (8, 9, False),
        (8, 10, True),
        (9, 10, False),
        (9, 11, True),
        (20, 21, False),
        (20, 22, True),
        (118, 119, False),
        (118, 120, True),
        # Far from the edge on either side.
        (20, 1, False),
        (118, 10, False),
        (20, 120, True),
    ],
)
def test_a_probe_s_check_leaves_the_margin_above_the_bound_its_settings_state(
    site: Site, bound: int, timeout: int, rendered: bool
) -> None:
    site.state(bound)
    site.probe["timeout_seconds"] = timeout
    assert site.refused() is not rendered
    assert rendered is (timeout >= bound + MARGIN)
    if rendered:
        bundle = site.output / "bundle"
        assert f"  timeout {timeout} seconds\n" in (bundle / "user/monit/monitrc").read_text()
        stored = strict_loads((bundle / "user/data/runtime-settings.json").read_bytes())
        assert stored["read_timeout_seconds"] == bound


def test_the_same_timeouts_render_while_the_member_is_unset(site: Site) -> None:
    """The comparison exists for a stated bound only: unset is not read as eight."""
    site.probe["timeout_seconds"] = 9
    assert not site.refused("unset")
    site.state(8)
    assert site.refused("stated")


PROBES: dict[str, list[str]] = {
    "as shipped": SHIPPED,
    "value joined to the option": [PYTHON, "-m", MODULE, f"--settings={FILE}", *TAIL],
    "option shortened": [PYTHON, "-m", MODULE, "--setting", FILE, *TAIL],
    "option of one letter with its value": [PYTHON, "-m", MODULE, f"--s={FILE}", *TAIL],
    "given twice, the bundle's file last": [
        PYTHON,
        "-m",
        MODULE,
        "--settings",
        "/operator/site/other.json",
        "--settings",
        FILE,
        *TAIL,
    ],
    "service option shortened": [
        PYTHON,
        "-m",
        MODULE,
        "--settings",
        FILE,
        "probe",
        "--se",
        "media-controller",
    ],
    "interpreter option before": [PYTHON, "-I", "-m", MODULE, "--settings", FILE, *TAIL],
    "interpreter options in one group": [PYTHON, "-ISm", MODULE, "--settings", FILE, *TAIL],
    "module joined to the option": [PYTHON, "-m" + MODULE, "--settings", FILE, *TAIL],
    "group and module joined": [PYTHON, "-Im" + MODULE, "--settings", FILE, *TAIL],
    "interpreter option with a value": [
        PYTHON,
        "-X",
        "utf8",
        "-m",
        MODULE,
        "--settings",
        FILE,
        *TAIL,
    ],
    "through a launcher": ["/usr/bin/env", PYTHON, "-m", MODULE, "--settings", FILE, *TAIL],
    "a dot in the path": [
        PYTHON,
        "-m",
        MODULE,
        "--settings",
        "{release}/./data/runtime-settings.json",
        *TAIL,
    ],
    "a doubled slash": [
        PYTHON,
        "-m",
        MODULE,
        "--settings",
        "{release}//data/runtime-settings.json",
        *TAIL,
    ],
    "up and down again": [
        PYTHON,
        "-m",
        MODULE,
        "--settings",
        "{release}/data/../data/runtime-settings.json",
        *TAIL,
    ],
    "two leading slashes": [PYTHON, "-m", MODULE, "--settings", "/" + FILE, *TAIL],
    "a trailing slash": [PYTHON, "-m", MODULE, "--settings", FILE + "/", *TAIL],
    "other case of letters": [
        PYTHON,
        "-m",
        MODULE,
        "--settings",
        "{release}/Data/Runtime-Settings.json",
        *TAIL,
    ],
}


def module_arguments(argv: list[str], release: str) -> list[str]:
    """What the interpreter hands to the module, found here by the module's name alone."""
    resolved = [item.replace("{release}", release) for item in argv]
    index = next(i for i, item in enumerate(resolved) if item.endswith(MODULE))
    return resolved[index + 1 :]


@pytest.mark.parametrize("argv", PROBES.values(), ids=PROBES.keys())
def test_every_spelling_of_the_probe_is_compared(
    site: Site, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    # The probe itself reads these arguments as a probe of one settings file.
    release = "/operator/install/netorch/releases/" + "0" * 64
    loaded: list[str] = []

    def load(path: Path) -> Any:
        loaded.append(str(path))
        raise ValueError("nothing is read here")

    with monkeypatch.context() as patch:
        patch.setattr(runtime, "load_settings", load)
        assert runtime.main(module_arguments(argv, release)) == runtime.UNKNOWN
    capsys.readouterr()
    assert runtime.probe_settings(module_arguments(argv, release)) == loaded[0]
    # That file is the bundle's artifact, in whatever spelling the system resolves alike.
    resolved = Path(loaded[0]).resolve()
    assert str(resolved).casefold() == f"{release}/data/runtime-settings.json"
    # So the bundle is rendered with the margin and refused one second below it.
    site.state(20)
    site.probe["check_argv"] = argv
    site.probe["timeout_seconds"] = 20 + MARGIN - 1
    assert site.refused("below")
    site.probe["timeout_seconds"] = 20 + MARGIN
    assert not site.refused("at")
    assert capsys.readouterr() == ("", "")


OTHER_CHECKS: dict[str, list[str]] = {
    "another command of the module": [PYTHON, "-m", MODULE, "--settings", FILE, "observe"],
    "the owner endpoint": [PYTHON, "-m", MODULE, "--settings", FILE, "request"],
    "arguments the probe refuses": [PYTHON, "-m", MODULE, "--settings", FILE, "probe"],
    "the settings after the command": [PYTHON, "-m", MODULE, *TAIL, "--settings", FILE],
    "an option the probe does not have": [
        PYTHON,
        "-m",
        MODULE,
        "--settings",
        FILE,
        "--deadline",
        "5",
        *TAIL,
    ],
    "the probe's help": [PYTHON, "-m", MODULE, "--settings", FILE, "probe", "--help"],
    "no arguments at all": [PYTHON, "-m", MODULE],
    "another module": [PYTHON, "-m", "netorch.bonjour_owner", "--settings", FILE, *TAIL],
    "a longer module name": [PYTHON, "-m", "site." + MODULE, "--settings", FILE, *TAIL],
    "a longer joined module name": [PYTHON, "-msite." + MODULE, "--settings", FILE, *TAIL],
    "the name without the interpreter's option": [
        "/operator/tools/site-check",
        MODULE,
        "--settings",
        FILE,
        *TAIL,
    ],
    "the name after another option": [PYTHON, "-c", MODULE, "--settings", FILE, *TAIL],
    "a group that ends in another letter": [PYTHON, "-mI", MODULE, "--settings", FILE, *TAIL],
    "a group with an option that takes a value": [
        PYTHON,
        "-Xm",
        MODULE,
        "--settings",
        FILE,
        *TAIL,
    ],
    "the option as the last argument": [PYTHON, "--settings", FILE, *TAIL, "-m"],
    "the name as an argument of another module": [
        PYTHON,
        "-m",
        "site.check",
        MODULE,
        "--settings",
        FILE,
        *TAIL,
    ],
}


@pytest.mark.parametrize("argv", OTHER_CHECKS.values(), ids=OTHER_CHECKS.keys())
def test_a_check_that_is_not_the_probe_is_not_compared(
    site: Site, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    site.state(118)
    site.probe["check_argv"] = argv
    site.probe["timeout_seconds"] = 1
    assert not site.refused()
    # Reading such a command line prints nothing and ends nothing.
    assert capsys.readouterr() == ("", "")


def test_the_other_owner_s_check_is_not_compared(site: Site) -> None:
    """The discovery owner's health check has its own timeout, whatever the bound is."""
    site.state(118)
    site.probe["timeout_seconds"] = 120
    other = next(item for item in site.manifest["monitors"] if item["role"] == "discovery")
    other["timeout_seconds"] = 1
    assert not site.refused()


def runtime_monitor(timeout: int) -> dict[str, Any]:
    """A monitor of the vendor runtime whose check is the runtime probe of these settings."""
    return {
        "id": "runtime",
        "role": "runtime",
        "check_argv": [PYTHON, "-m", MODULE, "--settings", FILE, "runtime-probe"],
        "recovery_argv": [PYTHON, "-m", MODULE, "--settings", FILE, "runtime-start"],
        "timeout_seconds": timeout,
        "cycles": 2,
        "recovery_code": 42,
    }


def test_the_runtime_probe_s_check_leaves_the_margin_as_the_probe_s_does(site: Site) -> None:
    """The runtime probe reads through the same reader and takes the bound its settings state."""
    site.state(20)
    site.probe["timeout_seconds"] = 20 + MARGIN
    site.manifest["monitors"].append(runtime_monitor(20 + MARGIN - 1))
    assert site.refused("below")
    site.manifest["monitors"][-1] = runtime_monitor(20 + MARGIN)
    assert not site.refused("at")


ELSEWHERE: dict[str, list[str]] = {
    "a file outside the release": ["--settings", "/operator/site/runtime-settings.json"],
    "a file of the state directory": ["--settings", "{state}/runtime-settings.json"],
    "a link the site maintains": [
        "--settings",
        "/operator/install/netorch/current/data/runtime-settings.json",
    ],
    "no artifact of that name": ["--settings", "{release}/data/other-settings.json"],
    "a longer name": ["--settings", FILE + ".old"],
    "a path that leaves the release": ["--settings", "{release}/../data/runtime-settings.json"],
    "a release of a longer name": ["--settings", "{release}-old/data/runtime-settings.json"],
    "a name that continues the release's": ["--settings", "{release}-data/runtime-settings.json"],
    "the release inside another path": ["--settings", "/backup" + FILE],
    "a relative path": ["--settings", "data/runtime-settings.json"],
    "given twice, another file last": [
        "--settings",
        FILE,
        "--settings",
        "/operator/site/other.json",
    ],
}


@pytest.mark.parametrize("settings", ELSEWHERE.values(), ids=ELSEWHERE.keys())
def test_settings_that_are_no_file_of_the_bundle_are_not_compared(
    site: Site, settings: list[str]
) -> None:
    site.state(118)
    site.probe["check_argv"] = [PYTHON, "-m", MODULE, *settings, *TAIL]
    site.probe["timeout_seconds"] = 1
    assert not site.refused()


def test_an_artifact_of_the_root_scope_is_no_file_of_the_probe_s_release(site: Site) -> None:
    site.state(118)
    site.probe["timeout_seconds"] = 1
    assert site.refused("user")
    artifact = next(item for item in site.manifest["artifacts"] if item["id"] == "runtime-settings")
    artifact["scope"] = "root"
    assert not site.refused("root")


@pytest.mark.parametrize(
    "payload",
    [
        # The member with a value its loader refuses: the probe reads nothing and
        # answers unknown at once, so there is no read for a timeout to cut short.
        {"read_timeout_seconds": 119},
        {"read_timeout_seconds": 7},
        {"read_timeout_seconds": "20"},
        {"read_timeout_seconds": None},
        {"read_timeout_seconds": True},
        # An accepted value in a document that is refused for another member.
        {"read_timeout_seconds": 118, "accepted_version": "9.9.9"},
        # Not a settings document at all.
        [],
        "settings",
    ],
    ids=repr,
)
def test_settings_that_their_loader_refuses_are_not_compared(site: Site, payload: Any) -> None:
    document = strict_loads((EXAMPLES / "runtime-settings.json").read_bytes())
    stored = {**document, **payload} if isinstance(payload, dict) else payload
    site.payloads["runtime-settings"] = canonical_bytes(stored)
    with pytest.raises(ValueError):
        loader.parse_settings(stored)
    site.probe["timeout_seconds"] = 1
    assert not site.refused()


def test_each_check_is_compared_with_its_own_settings(site: Site) -> None:
    site.state(20)
    site.probe["timeout_seconds"] = 20 + MARGIN
    document = strict_loads((EXAMPLES / "runtime-settings.json").read_bytes())
    site.payloads["second-settings"] = canonical_bytes({**document, "read_timeout_seconds": 30})
    site.manifest["artifacts"].append(
        {
            "id": "second-settings",
            "scope": "user",
            "source": "/operator/site/second-settings.json",
            "destination": "data/second-settings.json",
            "sha256": "0" * 64,
        }
    )
    # A second check, of the other owner's role, that runs the probe with those.
    other = next(item for item in site.manifest["monitors"] if item["role"] == "discovery")
    other["check_argv"] = [
        PYTHON,
        "-m",
        MODULE,
        "--settings",
        "{release}/data/second-settings.json",
        *TAIL,
    ]
    other["timeout_seconds"] = 30 + MARGIN - 1
    assert site.refused("second-below")
    other["timeout_seconds"] = 30 + MARGIN
    assert not site.refused("both-at")
    # The first check is still held to its own bound, not to the smaller timeout's.
    site.probe["timeout_seconds"] = 20 + MARGIN - 1
    assert site.refused("first-below")


@pytest.mark.parametrize(
    "first",
    [
        OTHER_CHECKS["another command of the module"],
        OTHER_CHECKS["another module"],
        [PYTHON, "-m", MODULE, *ELSEWHERE["a file outside the release"], *TAIL],
        [PYTHON, "-m", MODULE, *ELSEWHERE["no artifact of that name"], *TAIL],
    ],
    ids=["another command", "another module", "settings elsewhere", "no such artifact"],
)
def test_a_check_that_is_not_compared_does_not_end_the_comparison(
    site: Site, first: list[str]
) -> None:
    """Every monitor is looked at, whatever the one before it was."""
    site.state(20)
    assert site.manifest["monitors"][0] is site.probe
    site.probe["check_argv"] = first
    site.probe["timeout_seconds"] = 1
    second = site.manifest["monitors"][1]
    second["check_argv"] = SHIPPED
    second["timeout_seconds"] = 20 + MARGIN - 1
    assert site.refused("below")
    second["timeout_seconds"] = 20 + MARGIN
    assert not site.refused("at")


def test_the_renderer_compares_with_the_margin_under_its_one_name(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The figure is not written a second time where the bundle is rendered."""
    assert implementation.READ_TIMEOUT_MARGIN is loader.READ_TIMEOUT_MARGIN
    monkeypatch.setattr(implementation, "READ_TIMEOUT_MARGIN", 5)
    site.state(20)
    site.probe["timeout_seconds"] = 24
    assert site.refused("below")
    site.probe["timeout_seconds"] = 25
    assert not site.refused("at")


# --- The probe's command line is read with the probe's own parser ----------------


@pytest.mark.parametrize(
    "arguments,settings",
    [
        (["--settings", "/a/b.json", "probe", "--service", "camera"], "/a/b.json"),
        (["--settings=/a/b.json", "probe", "--service=camera"], "/a/b.json"),
        (["--s", "/a/b.json", "probe", "--s", "camera"], "/a/b.json"),
        (
            ["--settings", "/x.json", "--settings", "/a/b.json", "probe", "--service", "c"],
            "/a/b.json",
        ),
        (["--settings", "/a//./b.json/", "probe", "--service", "camera"], "/a/b.json"),
        (["--settings", "relative.json", "probe", "--service", "camera"], "relative.json"),
        # The runtime probe reads through the same reader with the same bound.
        (["--settings", "/a/b.json", "runtime-probe"], "/a/b.json"),
        (["--settings=/a//./b.json", "runtime-probe"], "/a/b.json"),
    ],
)
def test_probe_settings_names_the_file_that_the_probe_itself_loads(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    settings: str,
) -> None:
    assert runtime.probe_settings(arguments) == settings
    assert runtime.probe_settings(tuple(arguments)) == settings
    # Asking is silent.
    assert capsys.readouterr() == ("", "")
    # The module, given the same arguments, loads that file and no other.
    loaded: list[str] = []

    def load(path: Path) -> Any:
        loaded.append(str(path))
        raise ValueError("nothing is read here")

    monkeypatch.setattr(runtime, "load_settings", load)
    assert runtime.main(arguments) == runtime.UNKNOWN
    assert loaded == [settings]
    capsys.readouterr()


@pytest.mark.parametrize(
    "arguments",
    [
        ["--settings", "/a/b.json", "observe"],
        ["--settings", "/a/b.json", "request"],
        ["--settings", "/a/b.json", "start", "--service", "camera"],
        ["--settings", "/a/b.json", "runtime-start"],
        ["--settings", "/a/b.json", "enroll", "--output", "/o.json"],
        ["--settings", "/a/b.json", "derive-policy", "--source", "/s", "--output", "/o"],
    ],
    ids=lambda arguments: arguments[2],
)
def test_probe_settings_names_nothing_for_another_command(
    capsys: pytest.CaptureFixture[str], arguments: list[str]
) -> None:
    assert runtime.probe_settings(arguments) is None
    assert capsys.readouterr() == ("", "")
    # The same arguments with the probe in that command's place are a probe.
    probe = [*arguments[:2], "probe", "--service", "camera"]
    assert runtime.probe_settings(probe) == "/a/b.json"


@pytest.mark.parametrize(
    "arguments,status",
    [
        (["--settings", "/a/b.json", "probe"], 2),
        (["--settings", "/a/b.json", "probe", "--service"], 2),
        (["--settings", "/a/b.json", "probe", "--service", "camera", "more"], 2),
        (["--settings", "/a/b.json", "probe", "--service", "camera", "--settings", "/c"], 2),
        (["--settings", "/a/b.json", "--deadline", "5", "probe", "--service", "camera"], 2),
        (["probe", "--service", "camera"], 2),
        (["--settings", "probe", "--service", "camera"], 2),
        (["--settings", "/a/b.json", "inspect"], 2),
        (["--settings", "/a/b.json"], 2),
        ([], 2),
        # Its help is an answer of its own and runs no command.
        (["--settings", "/a/b.json", "probe", "--service", "camera", "--help"], 0),
        (["--help"], 0),
        (["-h"], 0),
    ],
)
def test_probe_settings_names_nothing_where_the_module_runs_no_command(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    status: int,
) -> None:
    assert runtime.probe_settings(arguments) is None
    # Asking prints nothing and ends nothing.
    assert capsys.readouterr() == ("", "")
    # The module itself refuses these arguments, or prints its help, and loads nothing.
    loaded: list[Path] = []
    monkeypatch.setattr(runtime, "load_settings", loaded.append)
    with pytest.raises(SystemExit) as stopped:
        runtime.main(arguments)
    assert stopped.value.code == status and not loaded
    capsys.readouterr()


def test_the_module_still_answers_its_own_command_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reading a command line for someone else changed nothing for the module itself."""
    with pytest.raises(SystemExit) as refused:
        runtime.main(["--settings", "/a/b.json", "probe"])
    assert refused.value.code == 2
    assert "--service" in capsys.readouterr().err
    with pytest.raises(SystemExit) as helped:
        runtime.main(["--help"])
    assert helped.value.code == 0
    text = capsys.readouterr().out
    assert all(word in text for word in ("--settings", "probe", "start", "enroll", "request"))


def test_the_greatest_bound_is_the_longest_check_less_the_margin() -> None:
    assert loader.READ_TIMEOUT_MARGIN == MARGIN == 2
    schema = strict_loads((ROOT / "schemas/deployment.schema.json").read_bytes())
    longest = schema["$defs"]["monitor"]["properties"]["timeout_seconds"]["maximum"]
    assert loader.READ_TIMEOUT_MAXIMUM == longest - loader.READ_TIMEOUT_MARGIN == 118
    # The greatest bound is therefore one that a check can still be given the margin above.
    assert longest == loader.READ_TIMEOUT_MAXIMUM + loader.READ_TIMEOUT_MARGIN


# --- The owner endpoint's clients: a fleet that needs twelve seconds --------------


class Report(owners.RootReportOwner):
    """The root owner's published report, as the user side reads it."""

    def __init__(self, config: Any, name: str, report: Snapshot) -> None:
        super().__init__(config, name, Path("/unused"))
        self.report = report

    def observe(self) -> Snapshot:
        return self.report


def endpoint(
    monkeypatch: pytest.MonkeyPatch, config: Any, settings: Any, items: Any, step: float
) -> tuple[list[float], list[Paced]]:
    """`owners.ProcessOwner` with the real endpoint behind it instead of a process."""
    waited: list[float] = []
    reads: list[Paced] = []

    def run(argv: list[str], *, input_data: bytes, timeout: float) -> Result:
        waited.append(timeout)
        paced = Paced(monkeypatch, FakeRunner(settings, items), step=step)
        reads.append(paced)
        answer = runtime.handle_request(config, settings, strict_loads(input_data), paced)
        if paced.elapsed >= timeout:
            raise ProcessTimeout("cut off by its client")
        return Result(0, canonical_bytes(answer), b"")

    monkeypatch.setattr(owners, "run", run)
    return waited, reads


@pytest.mark.parametrize("step,known", [(0.25, True), (0.75, False)])
def test_a_fleet_that_needs_twelve_seconds_stays_unknown_to_the_endpoint_s_clients(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, step: float, known: bool
) -> None:
    """With the bound stated on both sides: who reads the fleet, and who still cannot.

    Sixteen calls of 0.75 seconds are a read of twelve seconds. The probe and the
    root owner take the stated bound of twenty. The endpoint keeps eight, because
    its clients end it after ten, and so the coordinator and the discovery owner
    see nothing of that fleet. A read of four seconds is the control.
    """
    config, plain, items = enrolled
    settings = with_bound(plain, 20)
    # The probe.
    paced = Paced(monkeypatch, FakeRunner(settings, items), step=step)
    assert _probe(monkeypatch, config, settings, paced) == 0
    assert paced.elapsed == 16 * step
    # The root owner, whose own document states the same bound: a pass over the
    # slow fleet keeps the rules that a pass over a fast one loaded.
    root, installation = _installed(tmp_path, config, settings)
    backend, reports = FakeBackend(), []
    monkeypatch.setattr(owner, "protected_native_code", lambda paths: None)

    def root_pass(pace: float) -> tuple[dict[str, Any], float]:
        paced = Paced(monkeypatch, FakeRunner(settings, items), step=pace)
        monkeypatch.setattr(owner, "run", _routed(settings, paced))
        result = reconcile(
            root,
            owner._runtime_observer,
            lambda store, record: backend,
            report=lambda record, snapshot: reports.append(snapshot),
        )
        return result, paced.elapsed

    assert len(root_pass(0.0)[0]["changed"]) == 4 and backend.rules
    result, lasted = root_pass(step)
    assert result["changed"] == [] and result["phase"] == "committed" and backend.rules
    # Two reads under the owner's lock.
    assert lasted == 2 * 16 * step
    owned = {key for key, item in reports[-1].profiles.items() if item.data["root_ready"]}
    assert len(owned) == 4 and all(
        item.state == "present" for item in reports[-1].profiles.values()
    )
    # The endpoint, reached as the coordinator and the discovery owner reach it.
    waited, reads = endpoint(monkeypatch, config, settings, items, step)
    clients: dict[str, Any] = {
        settings.owner: owners.ProcessOwner(config, settings.owner, ["/usr/bin/example-endpoint"]),
        installation.owner: Report(config, installation.owner, reports[-1]),
    }
    merged = owners.observe(config, clients)
    now = time.time()
    assert waited == [loader.READ_TIMEOUT_DEFAULT + MARGIN] == [10]
    admissions = owners.effective_admissions(config, clients, merged, mock_admissions(config), now)
    transport = plan(config, merged, admissions, Intent(), now)
    discovery = plan_discovery(config, merged, transport, Intent(), now)
    ready = [
        bonjour_owner.dependencies_ready(
            config, policy, merged, Intent(), transport.ready_profiles, now
        )
        for policy in config.discovery
    ]
    assert len(config.discovery) == 2
    if known:
        assert reads[0].elapsed == 4.0 and len(reads[0].calls) == 16
        assert states(merged) == {("present", "verified")}
        assert merged.network_generation is not None
        assert owned <= set(admissions)
        assert transport.ready_profiles == {profile.id for profile in config.profiles}
        assert ready == [True, True]
        return
    # It answered by itself, inside its eight seconds, and knows nothing.
    assert reads[0].elapsed == 8.0 and len(reads[0].calls) == 11
    assert states(merged) == {("unknown", "timed-out")}
    assert merged.network_generation is None
    # No rule of the root owner counts as ready for the user side, although the
    # root owner reports all four as loaded and ready.
    assert not owned & set(admissions)
    assert transport.ready_profiles == frozenset()
    # Nothing is published: the coordinator plans both declarations inactive and
    # the discovery owner's own check of its dependencies fails.
    assert [(action.active, action.reason) for action in discovery] == [
        (False, "network-unknown"),
        (False, "network-unknown"),
    ]
    assert ready == [False, False]


# --- The locks: who waits while a read is made under one -------------------------


def test_while_one_recovery_reads_another_ends_busy_and_so_does_an_operator_command(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A recovery holds the state lock for three reads; nobody else gets it meanwhile."""
    config, plain, items = enrolled
    settings = with_bound(plain, 20)
    inner = FakeRunner(settings, items)
    for name in ("example-camera", "example-resolver"):
        inner.items[name]["status"]["state"] = "stopped"
    paced = Paced(monkeypatch, inner, step=0.75)
    waited: list[float] = []
    busy: list[float] = []

    def during(argv: list[str], **kwargs: Any) -> Result:
        if not waited:
            # The first call of the first read: the lock is held from here on.
            clock = Clock()
            with pytest.raises(Busy):
                runtime.recover_service(
                    config, settings, "resolver", paced, clock=clock, sleep=clock.sleep
                )
            waited.append(sum(clock.slept))
        if len(paced.calls) in {0, 20, 40, 58}:
            # What `pause` and the coordinator's pass do first: at the start of
            # the first two reads, at the start call and at the last call of all.
            with pytest.raises(Busy), Store(Path(settings.state_dir)).lock():
                raise AssertionError("the state lock was free")
            busy.append(paced.elapsed)
        result: Result = paced(argv, **kwargs)
        return result

    result = runtime.recover_service(config, settings, "camera", during)
    assert result.services["camera"].state == "present"
    # The other workload's recovery gave up after its five seconds and read nothing.
    assert waited == [runtime.START_LOCK_WAIT_SECONDS] == [5.0]
    assert len(paced.calls) == 2 * 20 + 18 + 1 and paced.bounds("vendor start") == [4]
    # Both stopped peers require job reads; the final pass has one stopped peer.
    assert busy == [0.0, 15.0, 30.0, 43.5]
    assert paced.elapsed == (2 * 20 + 18 + 1) * 0.75
    with Store(Path(settings.state_dir)).lock():
        pass


# --- The root owner's own document: a value its loader refuses ---------------------


@pytest.mark.parametrize("value", [119, 7, "20", None])
def test_a_bound_the_loader_refuses_in_the_root_owner_s_document_retires_every_rule(
    enrolled: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: Any
) -> None:
    """As any malformed observer does: it is stored and admitted, and read only by a pass."""
    config, plain, items = enrolled
    root, _installation = _installed(tmp_path, config, plain)
    backend = FakeBackend()
    paced = Paced(monkeypatch, FakeRunner(plain, items))
    monkeypatch.setattr(owner, "protected_native_code", lambda paths: None)
    monkeypatch.setattr(owner, "run", _routed(plain, paced))

    def root_pass() -> dict[str, Any]:
        return reconcile(
            root,
            owner._runtime_observer,
            lambda store, record: backend,
            report=lambda record, snapshot: None,
        )

    loaded = root_pass()["changed"]
    assert len(loaded) == 4 and backend.rules
    # The administrator stores the document with the refused value and admits
    # every profile again; neither step parses the observer.
    record = root.read("installation.json")
    stored = Installation.from_dict(
        {**record, "observer": {**settings_to_dict(plain), "read_timeout_seconds": value}}
    )
    root.write("installation.json", stored.to_dict())
    for profile in config.profiles:
        if config.profile_owner(profile).id == stored.owner:
            admit(root, profile.id, acknowledge_bounded_risk=True, now=START - 1)
    calls = len(paced.calls)
    retired = root_pass()["changed"]
    assert {item for item in retired if item.endswith(":withdraw")} == {
        item.replace(":activate", ":withdraw") for item in loaded
    }
    assert not backend.rules
    # Nothing of the runtime was read for that decision.
    assert len(paced.calls) == calls

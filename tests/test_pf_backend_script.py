"""The Bash backend executed against a fake pfctl: guards, file checks, reads, exits.

`/bin/bash` runs a private copy of the shipped script in which only the root
check and the paths of three tools are replaced. That is bash 5 on a Linux
machine and the system's bash 3.2 on macOS. `NETORCH_TEST_BASH` names another
shell binary to run the same tests under, for example a bash 3.2 built from
Apple's published source. The fake tools model control flow only: none of
their output is Darwin PF grammar, and no real pfctl is called.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from netorch.config import load_config
from netorch.pf_owner import render_profile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "platform/macos/pf/backend.sh"
BASH = Path(os.environ.get("NETORCH_TEST_BASH", "/bin/bash"))
ANCHOR = "com.apple/netorch.site-forwarding"
GUEST = "198.51.100.12"
NOTICES = "No ALTQ support in kernel\nALTQ related functions disabled\n"
HOOKS = 'nat-anchor "com.apple/*" all\nrdr-anchor "com.apple/*" all\n'

pytestmark = pytest.mark.skipif(not BASH.exists(), reason="the backend needs bash")

FAKE_PFCTL = r"""
import json, os, sys
state = os.environ["NETORCH_FAKE_PF"]
arguments = sys.argv[1:]
with open(os.path.join(state, "calls"), "a") as log:
    log.write(" ".join(arguments) + "\n")
def stored(name, default=""):
    try:
        with open(os.path.join(state, name)) as stream:
            return stream.read()
    except FileNotFoundError:
        return default
def canonical(path):
    with open(path) as stream:
        lines = [" ".join(line.split("#", 1)[0].split()) for line in stream]
    return "".join(line + "\n" for line in lines if line)
anchored = arguments[:1] == ["-a"]
rest = arguments[2:] if anchored else arguments
if rest[:1] == ["-s"] and len(rest) == 2:
    name = ("anchor-" if anchored else "") + rest[1]
elif rest[:3] == ["-n", "-v", "-f"] and len(rest) == 4:
    name = "parse"
elif rest[:1] == ["-f"] and len(rest) == 2:
    name = "load"
elif rest[:1] == ["-k"]:
    name = "kill"
elif rest == ["-E"]:
    name = "enable"
else:
    sys.stderr.write("unexpected call\n")
    sys.exit(99)
count = int(stored("count-" + name, "0")) + 1
with open(os.path.join(state, "count-" + name), "w") as stream:
    stream.write(str(count))
fault = json.loads(stored("faults", "{}")).get(name, {})
if "calls" in fault and count not in fault["calls"]:
    fault = {}
if "-n" not in rest:
    sys.stderr.write("No ALTQ support in kernel\nALTQ related functions disabled\n")
sys.stderr.write(fault.get("stderr", ""))
if "stdout" in fault:
    sys.stdout.write(fault["stdout"])
elif name == "anchor-nat":
    sys.stdout.write(stored("live"))
elif name == "nat":
    sys.stdout.write(stored("main-nat"))
elif name in ("anchor-rules", "anchor-Anchors", "anchor-Tables", "states", "info", "References"):
    sys.stdout.write(stored(name))
elif name == "parse":
    text = canonical(rest[3])
    if text.startswith("bad"):
        sys.stderr.write("syntax error\n")
        sys.exit(1)
    sys.stdout.write(text)
elif name == "load" and "skip" not in fault:
    with open(os.path.join(state, "live"), "w") as stream:
        stream.write(fault.get("loads", canonical(rest[1])))
elif name == "enable":
    sys.stdout.write("pf enabled\nToken : 18446744073709551615\n")
sys.exit(fault.get("exit", 0))
"""

FAKE_STAT = r"""
import os, stat, sys
state = os.environ["NETORCH_FAKE_PF"]
def claimed(name):
    try:
        with open(os.path.join(state, name)) as stream:
            return stream.read().strip()
    except FileNotFoundError:
        return "0"
assert sys.argv[1] == "-f" and len(sys.argv) == 4, sys.argv
info = os.lstat(sys.argv[3])
print(
    sys.argv[2]
    .replace("%u", claimed("uid"))
    .replace("%g", claimed("gid"))
    .replace("%Lp", format(stat.S_IMODE(info.st_mode), "o"))
    .replace("%l", str(info.st_nlink))
)
"""

FAKE_UNAME = "print('Darwin')\n"


class Sandbox:
    """A private copy of the script, its fake tools and the fake kernel's files."""

    def __init__(self, directory: Path, *, broken_filter: bool = False) -> None:
        self.state = directory / "kernel"
        self.files = directory / "protected"
        tools = directory / "tools"
        for item in (self.state, self.files, tools):
            item.mkdir(mode=0o700)
        for name, body in (("pfctl", FAKE_PFCTL), ("stat", FAKE_STAT), ("uname", FAKE_UNAME)):
            tool = tools / name
            tool.write_text(f"#!{sys.executable} -IS\n{body}")
            tool.chmod(0o700)
        replaced = [
            ('"$EUID"', "0"),
            ("/usr/bin/uname", shlex.quote(str(tools / "uname"))),
            ("/sbin/pfctl", shlex.quote(str(tools / "pfctl"))),
            ("/usr/bin/stat", shlex.quote(str(tools / "stat"))),
        ]
        if broken_filter:
            # The one grep that drops the two notices fails instead of filtering.
            failing = tools / "failing"
            failing.write_text(f"#!{sys.executable} -IS\nraise SystemExit(2)\n")
            failing.chmod(0o700)
            replaced.append(("/usr/bin/grep -Fxv", shlex.quote(str(failing))))
        text = SCRIPT.read_text()
        for original, replacement in replaced:
            assert text.count(original) == 1, original
            text = text.replace(original, replacement)
        self.script = directory / "backend.sh"
        self.script.write_text(text)
        self.kernel("main-nat", HOOKS)
        self.kernel("info", "Status: Enabled for 0 days 00:01:00\n")

    def kernel(self, name: str, text: str) -> None:
        (self.state / name).write_text(text)

    def faults(self, **faults: dict[str, Any]) -> None:
        self.kernel(
            "faults", json.dumps({key.replace("_", "-"): value for key, value in faults.items()})
        )

    def rules(self, name: str, text: str, mode: int = 0o600) -> str:
        path = self.files / name
        path.write_text(text)
        path.chmod(mode)
        return str(path)

    def run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(BASH), str(self.script), *arguments],
            env={"NETORCH_FAKE_PF": str(self.state), "PATH": "/usr/bin:/bin"},
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    @property
    def calls(self) -> list[str]:
        path = self.state / "calls"
        return path.read_text().splitlines() if path.exists() else []

    @property
    def loads(self) -> list[str]:
        return [call for call in self.calls if call.startswith(f"-a {ANCHOR} -f ")]

    @property
    def live(self) -> str:
        path = self.state / "live"
        return path.read_text() if path.exists() else ""


@pytest.fixture
def sandbox(tmp_path: Path) -> Sandbox:
    return Sandbox(tmp_path)


@pytest.fixture(scope="module")
def rule() -> str:
    """One rule exactly as the owner renders it; its comment names the profile."""
    config = load_config(ROOT / "examples/network.json")
    return render_profile(config, config.profile("proxy-standard"), "192.0.2.10")


def bare(rule: str) -> str:
    """What the fake parser prints for a rendered rule: no comment, single spaces."""
    return " ".join(rule.split("#", 1)[0].split()) + "\n"


def code_lines() -> list[str]:
    return [line for line in SCRIPT.read_text().splitlines() if not line.lstrip().startswith("#")]


def test_the_shipped_script_refuses_to_run_unprivileged() -> None:
    result = subprocess.run(
        [str(BASH), str(SCRIPT), "inspect", ANCHOR],
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert (result.returncode, result.stdout) == (77, "")


def test_no_check_is_a_bare_conditional_statement() -> None:
    """Under bash 3.2 a failing `[[ ]]` statement does not end a `set -e` script."""
    checked = [line for line in code_lines() if "[[ " in line]
    assert len(checked) > 10
    for line in checked:
        assert re.fullmatch(
            r"\s*(?:if \[\[ .+ \]\]; then (?:exit|return) [0-9]+; fi"
            r"|\[\[ .+ \]\] \|\| (?:exit|return) [0-9]+)",
            line,
        ), line


def test_no_pipeline_feeds_a_grep_that_leaves_at_its_first_match() -> None:
    """Such a writer can die of SIGPIPE, which `pipefail` reports as a failed check."""
    quiet = [line for line in code_lines() if re.search(r"grep -[A-Za-z]*q", line)]
    assert len(quiet) == 3
    for line in quiet:
        assert "|" not in line.split("grep", 1)[0] and "<<<" in line, line


def test_script_avoids_constructs_newer_than_bash_3_2() -> None:
    newer = (
        r"\b(?:declare|local|typeset) -[A-Za-z]*[An]",
        r"\$\{[^}]*(?:,,|\^\^|@[A-Za-z])",
        r"\b(?:mapfile|readarray|coproc)\b",
        r"&>>|\|&|;;&|;&",
        r"\[\[ -v ",
        r"\bshopt\b",
        r"\bwait -n\b",
    )
    for line in code_lines():
        for pattern in newer:
            assert re.search(pattern, line) is None, line


@pytest.mark.parametrize(
    "arguments",
    [
        ("inspect", "extra"),
        ("normalize",),
        ("normalize", "one", "two"),
        ("replace", "one"),
        ("replace", "one", "two", "three"),
        ("states", "extra"),
        ("drain",),
        ("drain", GUEST, GUEST),
        ("enable", "extra"),
        ("enabled", "extra"),
        ("references", "extra"),
    ],
    ids=" ".join,
)
def test_a_wrong_argument_count_is_refused_before_any_pfctl_call(
    sandbox: Sandbox, arguments: tuple[str, ...]
) -> None:
    result = sandbox.run(arguments[0], ANCHOR, *arguments[1:])

    assert (result.returncode, result.stdout) == (64, "")
    assert sandbox.calls == []


@pytest.mark.parametrize(
    "target",
    [
        "0.0.0.0/0",
        f"{GUEST}/32",
        "198.51.100",
        "any",
        "all",
        "",
        "-F",
        f"{GUEST} -k 0.0.0.0/0",
        f"{GUEST}\n0.0.0.0/0",
        "2001:db8::1",
    ],
    ids=[
        "everything",
        "prefix",
        "three parts",
        "any",
        "all",
        "empty",
        "flag",
        "two",
        "lines",
        "v6",
    ],
)
def test_drain_kills_nothing_unless_its_target_is_one_dotted_address(
    sandbox: Sandbox, target: str
) -> None:
    result = sandbox.run("drain", ANCHOR, target)

    assert result.returncode == 64
    assert sandbox.calls == []


def test_drain_kills_states_from_and_to_exactly_that_address(sandbox: Sandbox) -> None:
    result = sandbox.run("drain", ANCHOR, GUEST)

    assert (result.returncode, result.stdout) == (0, "")
    assert sandbox.calls == [f"-k {GUEST}", f"-k 0.0.0.0/0 -k {GUEST}"]


def test_a_failed_state_kill_is_reported(sandbox: Sandbox) -> None:
    sandbox.faults(kill={"exit": 1})

    assert sandbox.run("drain", ANCHOR, GUEST).returncode == 1


@pytest.mark.parametrize("token", ["42", "18446744073709551615", "any"])
def test_releasing_a_reference_is_not_an_operation(sandbox: Sandbox, token: str) -> None:
    result = sandbox.run("release", ANCHOR, token)

    assert result.returncode == 64
    assert sandbox.calls == []


@pytest.mark.parametrize(
    "operation,anchor",
    [
        ("flush", ANCHOR),
        ("inspect", "com.apple/Other"),
        ("inspect", "netorch.site-forwarding"),
        ("inspect", ANCHOR + "\n"),
        ("inspect", ANCHOR + "/child"),
        ("inspect", "com.apple/netorch." + "n" * 64),
    ],
    ids=["unknown operation", "foreign", "no prefix", "newline", "child", "too long"],
)
def test_unknown_operations_and_foreign_anchors_are_refused(
    sandbox: Sandbox, operation: str, anchor: str
) -> None:
    result = sandbox.run(operation, anchor)

    assert result.returncode == 64
    assert sandbox.calls == []


def test_a_rule_file_of_another_group_is_read_when_owner_mode_and_links_hold(
    sandbox: Sandbox, rule: str
) -> None:
    sandbox.kernel("gid", "80")

    result = sandbox.run("normalize", ANCHOR, sandbox.rules("parse.rules", rule))

    assert (result.returncode, result.stdout) == (0, bare(rule))


@pytest.mark.parametrize(
    "fault", ["owner", "group readable", "world readable", "hard link", "symlink", "directory"]
)
def test_a_rule_file_that_is_not_private_to_root_is_not_read(
    sandbox: Sandbox, rule: str, fault: str
) -> None:
    path = sandbox.rules("parse.rules", rule)
    if fault == "owner":
        sandbox.kernel("uid", "501")
    elif fault == "group readable":
        os.chmod(path, 0o640)
    elif fault == "world readable":
        os.chmod(path, 0o644)
    elif fault == "hard link":
        os.link(path, sandbox.files / "second-name")
    elif fault == "symlink":
        os.symlink(path, sandbox.files / "link")
        path = str(sandbox.files / "link")
    else:
        path = str(sandbox.files)

    result = sandbox.run("normalize", ANCHOR, path)

    assert (result.returncode, result.stdout) == (1, "")
    assert sandbox.calls == []


def test_a_missing_rule_file_is_not_read(sandbox: Sandbox) -> None:
    result = sandbox.run("normalize", ANCHOR, str(sandbox.files / "absent.rules"))

    assert (result.returncode, result.stdout) == (1, "")
    assert sandbox.calls == []


def test_the_notices_pfctl_writes_on_every_call_do_not_fail_a_listing(sandbox: Sandbox) -> None:
    rows = "all udp 192.0.2.77:54321 -> 198.51.100.12:53 NO_TRAFFIC:SINGLE\n"
    sandbox.kernel("states", rows)
    sandbox.kernel("References", "11 pfctl 18446744073709551615 0 days 00:00:01\n")

    states = sandbox.run("states", ANCHOR)
    references = sandbox.run("references", ANCHOR)

    assert (states.returncode, states.stdout) == (0, rows)
    assert (references.returncode, references.stdout.split()[2]) == (0, "18446744073709551615")
    assert sandbox.run("enabled", ANCHOR).returncode == 0
    assert sandbox.run("inspect", ANCHOR).returncode == 0


@pytest.mark.parametrize(
    "operation,listing",
    [("states", "states"), ("references", "References"), ("enabled", "info"), ("inspect", "nat")],
)
@pytest.mark.parametrize(
    "fault",
    [
        {"stderr": "pfctl: listing failed\n", "stdout": ""},
        {"stderr": "pfctl: listing failed\n"},
        {"stderr": NOTICES + "pfctl: listing failed\n"},
        {"exit": 1},
    ],
    ids=["warning and nothing", "warning beside output", "warning after notices", "exit status"],
)
def test_a_listing_that_warns_or_fails_is_not_taken_for_an_answer(
    sandbox: Sandbox, operation: str, listing: str, fault: dict[str, Any]
) -> None:
    sandbox.kernel("states", "all udp 192.0.2.77:54321 -> 198.51.100.12:53 NO_TRAFFIC:SINGLE\n")
    sandbox.faults(**{listing: fault})

    result = sandbox.run(operation, ANCHOR)

    # Refused either way. A listing that failed ends with status 1; one that ended
    # with status 0 and an unexpected line ends with the script's own status for it.
    assert result.returncode == (1 if "exit" in fault else 76)
    # Nothing was loaded, killed or enabled on the strength of that read.
    assert not any(call.split()[0] in {"-k", "-E", "-X"} for call in sandbox.calls)
    assert sandbox.loads == []


@pytest.mark.parametrize("operation", ["states", "references", "enabled", "inspect"])
def test_a_listing_is_not_an_answer_when_its_warnings_could_not_be_examined(
    tmp_path: Path, operation: str
) -> None:
    sandbox = Sandbox(tmp_path, broken_filter=True)

    assert sandbox.run(operation, ANCHOR).returncode == 1


def test_status_must_say_enabled(sandbox: Sandbox) -> None:
    sandbox.kernel("info", "Status: Disabled for 0 days 00:01:00\n")

    assert sandbox.run("enabled", ANCHOR).returncode == 1


def test_an_owned_anchor_that_does_not_exist_yet_reads_as_empty(sandbox: Sandbox) -> None:
    """The kernel refuses these listings for a missing anchor; pfctl exits 0."""
    refused = {"stderr": "pfctl: the anchor does not exist\n", "stdout": ""}
    sandbox.faults(anchor_nat=refused, anchor_rules=refused, anchor_Anchors=refused)

    result = sandbox.run("inspect", ANCHOR)

    assert (result.returncode, result.stdout) == (0, "")


@pytest.mark.parametrize(
    "name,text",
    [
        ("main-nat", 'rdr-anchor "com.apple/*" all\n'),
        ("main-nat", 'nat-anchor "com.apple/*" all\n'),
        ("main-nat", ""),
        ("anchor-rules", "pass all\n"),
        ("anchor-Anchors", f"  {ANCHOR}/child\n"),
        ("anchor-Tables", "blocked\n"),
    ],
    ids=["no nat hook", "no rdr hook", "no hooks", "filter rule", "child anchor", "table"],
)
def test_inspect_requires_both_hooks_and_an_anchor_with_translations_only(
    sandbox: Sandbox, rule: str, name: str, text: str
) -> None:
    sandbox.kernel("live", bare(rule))
    assert sandbox.run("inspect", ANCHOR).stdout == bare(rule)
    sandbox.kernel(name, text)

    result = sandbox.run("inspect", ANCHOR)

    assert (result.returncode, result.stdout) == (1, "")


def test_an_owned_anchor_read_that_exits_nonzero_fails_inspect(sandbox: Sandbox) -> None:
    sandbox.faults(anchor_nat={"exit": 1})

    assert sandbox.run("inspect", ANCHOR).returncode == 1


def test_replace_loads_the_candidate_once_and_prints_its_readback(
    sandbox: Sandbox, rule: str
) -> None:
    old, new = sandbox.rules("expected.rules", ""), sandbox.rules("candidate.rules", rule)

    result = sandbox.run("replace", ANCHOR, old, new)

    assert (result.returncode, result.stdout) == (0, bare(rule))
    assert sandbox.live == bare(rule)
    assert sandbox.loads == [f"-a {ANCHOR} -f {new}"]

    # And back to an empty anchor, expecting exactly what is loaded.
    result = sandbox.run("replace", ANCHOR, new, old)

    assert (result.returncode, result.stdout) == (0, "\n")
    assert sandbox.live == ""
    assert sandbox.loads == [f"-a {ANCHOR} -f {new}", f"-a {ANCHOR} -f {old}"]


def test_replace_does_not_load_over_rules_it_did_not_expect(sandbox: Sandbox, rule: str) -> None:
    sandbox.kernel("live", "rdr on lan inet proto tcp from any to any port 12 -> 192.0.2.20\n")
    old, new = sandbox.rules("expected.rules", ""), sandbox.rules("candidate.rules", rule)

    result = sandbox.run("replace", ANCHOR, old, new)

    assert (result.returncode, result.stdout) == (73, "")
    assert sandbox.loads == []


def test_replace_does_not_load_when_the_reread_before_loading_fails(
    sandbox: Sandbox, rule: str
) -> None:
    """A failed second read of an empty anchor must not pass for "still empty"."""
    old, new = sandbox.rules("expected.rules", ""), sandbox.rules("candidate.rules", rule)
    sandbox.faults(anchor_nat={"exit": 1, "calls": [2]})

    result = sandbox.run("replace", ANCHOR, old, new)

    assert (result.returncode, result.stdout) == (1, "")
    assert sandbox.loads == []
    assert sandbox.live == ""


def test_replace_does_not_load_when_the_anchor_changed_before_loading(
    sandbox: Sandbox, rule: str
) -> None:
    old, new = sandbox.rules("expected.rules", ""), sandbox.rules("candidate.rules", rule)
    sandbox.faults(
        anchor_nat={"stdout": "rdr on lan from any to any -> 192.0.2.20\n", "calls": [2]}
    )

    result = sandbox.run("replace", ANCHOR, old, new)

    assert (result.returncode, result.stdout) == (73, "")
    assert sandbox.loads == []


def test_replace_does_not_load_a_candidate_that_does_not_parse(sandbox: Sandbox) -> None:
    old, new = sandbox.rules("expected.rules", ""), sandbox.rules("candidate.rules", "bad rule\n")

    result = sandbox.run("replace", ANCHOR, old, new)

    assert (result.returncode, result.stdout) == (1, "")
    assert sandbox.loads == []


@pytest.mark.parametrize(
    "fault,status",
    [
        ({"exit": 1, "skip": True}, 74),
        ({"loads": "rdr on lan from any to any -> 192.0.2.20\n"}, 74),
        ({"exit": 1}, 0),
    ],
    ids=["failed and unchanged", "other rules read back", "failed but candidate read back"],
)
def test_the_readback_after_a_load_decides_not_the_exit_status_of_the_load(
    sandbox: Sandbox, rule: str, fault: dict[str, Any], status: int
) -> None:
    old, new = sandbox.rules("expected.rules", ""), sandbox.rules("candidate.rules", rule)
    sandbox.faults(load=fault)

    result = sandbox.run("replace", ANCHOR, old, new)

    assert result.returncode == status
    assert result.stdout == (bare(rule) if status == 0 else "")
    assert len(sandbox.loads) == 1


def test_enable_passes_the_token_line_on(sandbox: Sandbox) -> None:
    result = sandbox.run("enable", ANCHOR)

    assert result.returncode == 0
    assert "Token : 18446744073709551615" in result.stdout.splitlines()
    assert "-E" in sandbox.calls

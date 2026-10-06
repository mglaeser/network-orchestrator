"""The root owner's anchor: the product form for its own owner, or one pinned component.

Two retained places check the name, the installation record and the argument check
of the Bash backend. One table goes through both. The backend runs as a private copy
of the shipped script in which only the root check and the paths of three tools are
replaced; the fake tools model control flow only and no real pfctl is called.
`NETORCH_TEST_BASH` names another shell binary to run the same tests under, for
example a bash 3.2 built from Apple's published source.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import netorch.pf_owner as module
from netorch.codec import canonical_bytes, strict_loads
from netorch.config import to_dict
from netorch.instance import load_instance, resolved_names
from netorch.pf_owner import (
    Installation,
    PFError,
    admit,
    admitted_digest,
    install,
    reconcile,
    withdraw,
)
from netorch.process import Result
from netorch.state import Intent, Snapshot, intent_to_dict, snapshot_to_dict
from netorch.storage import Store
from tests.test_deployment import config, make_bundle, manifest
from tests.test_pf_owner import STAMP, approve_all, environment, run_pass, shell_backend

__all__ = ["config", "environment", "manifest"]

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "platform/macos/pf/backend.sh"
BASH = Path(os.environ.get("NETORCH_TEST_BASH", "/bin/bash"))
needs_bash = pytest.mark.skipif(not BASH.exists(), reason="the backend needs bash")

OWNER = "site-forwarding"
PREFIX = "com.apple/"
PRODUCT = PREFIX + "netorch." + OWNER
# A site's own reverse-DNS style name, assembled so that no literal of it exists here.
PINNED = PREFIX + ".".join(["org", "example", "site", "forwarding"])
OTHER_PIN = PREFIX + "example-site"
FOREIGN_RULE = "rdr on lo0 inet proto tcp from any to 192.0.2.10 port 80 -> 192.0.2.10 port 8080\n"

# anchor, owner, the installation record accepts it, the backend's argument check accepts it
TABLE: list[tuple[str, str, bool, bool]] = [
    # the product form: unchanged, and still tied to this installation's owner
    (PRODUCT, OWNER, True, True),
    (PREFIX + "netorch." + "o" * 63, "o" * 63, True, True),
    (PREFIX + "netorch.a", "a", True, True),
    # the backend does not know the owner; the record refuses another owner's form
    (PREFIX + "netorch.other", OWNER, False, True),
    (PREFIX + "netorch." + OWNER + "x", OWNER, False, True),
    (PREFIX + "netorch.site.forwarding", OWNER, False, True),
    (PREFIX + "netorch.", OWNER, False, True),
    (PREFIX + "netorch." + "o" * 64, "o" * 63, False, False),
    # one pinned component of at most 63 characters
    (PINNED, OWNER, True, True),
    (OTHER_PIN, OWNER, True, True),
    (PREFIX + "netorch", OWNER, True, True),
    (PREFIX + "a", OWNER, True, True),
    (PREFIX + "a" * 63, OWNER, True, True),
    (PREFIX + "a" + ".0-" * 20 + "z9", OWNER, True, True),
    (PREFIX + "a" * 64, OWNER, False, False),
    (PREFIX + "a" * 140, OWNER, False, False),
    # nested anchors stay refused
    (PREFIX + "example/nested", OWNER, False, False),
    (PREFIX + "netorch." + OWNER + "/child", OWNER, False, False),
    (PINNED + "/", OWNER, False, False),
    (PREFIX + "/example", OWNER, False, False),
    # a pinned component begins with a lower-case letter and has no other characters
    (PREFIX + "250.example", OWNER, False, False),
    (PREFIX + "-example", OWNER, False, False),
    (PREFIX + ".example", OWNER, False, False),
    (PREFIX + "Example", OWNER, False, False),
    (PREFIX + "example_site", OWNER, False, False),
    (PREFIX + "example site", OWNER, False, False),
    (PREFIX + "example;id", OWNER, False, False),
    (PREFIX + "example$(id)", OWNER, False, False),
    (PREFIX + "example*", OWNER, False, False),
    (PREFIX + "exampl\u00e9", OWNER, False, False),
    (PREFIX + "example\n", OWNER, False, False),
    (PRODUCT + "\n", OWNER, False, False),
    (PREFIX, OWNER, False, False),
    ("com.apple", OWNER, False, False),
    ("", OWNER, False, False),
    # only directly below the platform namespace
    ("comXapple/example", OWNER, False, False),
    ("com.apple.example", OWNER, False, False),
    (".".join(["org", "example"]) + "/forwarding", OWNER, False, False),
    ("x" + PINNED, OWNER, False, False),
    ("/" + PINNED, OWNER, False, False),
]
ROWS = [f"{index:02d}-{row[0][:36]!r}" for index, row in enumerate(TABLE)]

FAKE_PFCTL = r"""
import os, sys
state = os.environ["NETORCH_FAKE_PF"]
arguments = sys.argv[1:]
with open(os.path.join(state, "calls"), "a") as log:
    log.write("\t".join(arguments) + "\n")
def stored(name):
    try:
        with open(os.path.join(state, name)) as stream:
            return stream.read()
    except FileNotFoundError:
        return ""
anchored = arguments[:1] == ["-a"]
rest = arguments[2:] if anchored else arguments
if rest == ["-s", "nat"]:
    sys.stdout.write(stored("live") if anchored else stored("hooks"))
elif rest == ["-s", "states"]:
    sys.stdout.write("reached\n")
elif anchored and rest[:3] == ["-n", "-v", "-f"]:
    with open(rest[3]) as stream:
        sys.stdout.write(stream.read())
elif anchored and rest[:1] == ["-f"]:
    with open(rest[1]) as source, open(os.path.join(state, "live"), "w") as live:
        live.write(source.read())
# `-s rules`, `-s Anchors`, `-s Tables`: an anchor of the owned shape prints nothing.
"""

# Answers whatever format the script asks for, as a root-owned file would.
FAKE_STAT = r"""
import os, stat, sys
assert sys.argv[1] == "-f" and len(sys.argv) == 4, sys.argv
info = os.lstat(sys.argv[3])
print(
    sys.argv[2]
    .replace("%u", "0")
    .replace("%g", "0")
    .replace("%Lp", format(stat.S_IMODE(info.st_mode), "o"))
    .replace("%l", str(info.st_nlink))
)
"""


class Sandbox:
    """A private copy of the script, its fake tools and the fake kernel's files."""

    def __init__(self, directory: Path) -> None:
        self.state = directory / "kernel"
        self.files = directory / "protected"
        tools = directory / "tools"
        for item in (directory, self.state, self.files, tools):
            item.mkdir(mode=0o700)
        bodies = {"pfctl": FAKE_PFCTL, "stat": FAKE_STAT, "uname": "print('Darwin')\n"}
        for name, body in bodies.items():
            tool = tools / name
            tool.write_text(f"#!{sys.executable} -IS\n{body}")
            tool.chmod(0o700)
        text = SCRIPT.read_text()
        for original, replacement in (
            ('"$EUID"', "0"),
            ("/usr/bin/uname", shlex.quote(str(tools / "uname"))),
            ("/sbin/pfctl", shlex.quote(str(tools / "pfctl"))),
            ("/usr/bin/stat", shlex.quote(str(tools / "stat"))),
        ):
            assert text.count(original) == 1, original
            text = text.replace(original, replacement)
        self.script = directory / "backend.sh"
        self.script.write_text(text)
        self.kernel("hooks", 'nat-anchor "com.apple/*" all\nrdr-anchor "com.apple/*" all\n')

    def kernel(self, name: str, text: str) -> None:
        (self.state / name).write_text(text)

    def rules(self, name: str, text: str) -> str:
        path = self.files / name
        path.write_text(text)
        path.chmod(0o600)
        return str(path)

    def run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(BASH), str(self.script), *arguments],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env={"NETORCH_FAKE_PF": str(self.state), "PATH": "/usr/bin:/bin"},
        )

    def calls(self) -> list[list[str]]:
        log = self.state / "calls"
        return [line.split("\t") for line in log.read_text().splitlines()] if log.exists() else []


@pytest.fixture
def sandbox(tmp_path: Path) -> Sandbox:
    return Sandbox(tmp_path / "backend")


def record(anchor: str, owner: str = OWNER) -> Installation:
    return Installation(owner, anchor, {"schema_version": 1}, "0" * 64, "/protected/report.json")


def record_accepts(anchor: str, owner: str = OWNER) -> bool:
    try:
        record(anchor, owner)
    except PFError as error:
        assert str(error) == "invalid independent PF owner identity"
        return False
    return True


def pin(environment: Any, anchor: str = PINNED) -> Installation:
    """Make the fixture's installation one that was installed with a pinned anchor."""
    root, _, settings, _, _ = environment
    pinned = Installation.from_dict({**settings.to_dict(), "anchor": anchor})
    root.write("installation.json", pinned.to_dict())
    return pinned


def staged(tmp_path: Path, environment: Any, settings: Installation) -> tuple[Path, Path]:
    policy, setup = tmp_path / "policy.json", tmp_path / "settings.json"
    policy.write_bytes(canonical_bytes(to_dict(environment[1])))
    setup.write_bytes(canonical_bytes(settings.to_dict()))
    return policy, setup


# ---- the installation record


def test_installation_accepts_the_product_form_only_for_its_own_owner() -> None:
    assert record(PRODUCT).anchor == PRODUCT
    assert record_accepts(PREFIX + "netorch." + "o" * 63, "o" * 63)
    for owner in ("other", OWNER + "x", "site"):
        assert not record_accepts(PRODUCT, owner)
        assert not record_accepts(PREFIX + "netorch." + owner)
    # The owner identifier itself is as closed as before.
    for owner in ("", "Site", "site.forwarding", "o" * 64, "9site"):
        assert not record_accepts(PREFIX + "netorch." + owner, owner)
        assert not record_accepts(PINNED, owner)


def test_installation_accepts_one_pinned_component_and_refuses_nested_or_long_ones() -> None:
    assert record(PINNED).anchor == PINNED
    assert record_accepts(OTHER_PIN)
    assert record_accepts(PREFIX + "a" * 63) and not record_accepts(PREFIX + "a" * 64)
    assert not record_accepts(PREFIX + "example/nested")
    assert not record_accepts(PINNED + "/child")
    for anchor in (PREFIX, PREFIX + "250.example", PREFIX + "Example", PINNED + "\n", PINNED[1:]):
        assert not record_accepts(anchor)
    wrong_types: tuple[Any, ...] = (None, 5, PINNED.encode(), [PINNED])
    for wrong in wrong_types:
        assert not record_accepts(wrong)
    # The record round-trips unchanged: same schema, same members.
    assert Installation.from_dict(record(PINNED).to_dict()) == record(PINNED)
    assert set(record(PINNED).to_dict()) == set(record(PRODUCT).to_dict())


def test_pinned_anchor_cannot_claim_the_product_form_of_another_owner() -> None:
    for anchor in (
        PREFIX + "netorch.other",
        PREFIX + "netorch." + OWNER + "-2",
        PREFIX + "netorch.site.forwarding",  # would be a legal pin without the product prefix
        PREFIX + "netorch.",
    ):
        assert not record_accepts(anchor)
    # A component that is not the product prefix is an ordinary pin.
    assert record_accepts(PREFIX + "netorch") and record_accepts(PREFIX + "netorchx.other")


@pytest.mark.parametrize("anchor,owner,accepted,_backend", TABLE, ids=ROWS)
def test_installation_grammar_table(
    anchor: str, owner: str, accepted: bool, _backend: bool
) -> None:
    assert record_accepts(anchor, owner) is accepted
    if not anchor.startswith(PREFIX + "netorch."):
        assert _backend is accepted  # the two places differ only for the product form


def derived_anchor(name: str) -> str:
    instance = load_instance(ROOT / "examples" / name)
    assert instance.names.pf_anchor is None
    derived = resolved_names(instance)["pf_anchor"]
    assert derived == PREFIX + instance.namespace + ".forwarding"
    return derived


@pytest.mark.parametrize("name", ["instance.json", "instance-structural.json"])
def test_instance_default_anchor_is_accepted_by_the_owner(name: str) -> None:
    derived = derived_anchor(name)
    assert record(derived).anchor == derived


# ---- the backend's argument check, executed


@needs_bash
@pytest.mark.parametrize("anchor,_owner,_record,accepted", TABLE, ids=ROWS)
def test_backend_argument_check_matches_the_installation_grammar(
    sandbox: Sandbox, anchor: str, _owner: str, _record: bool, accepted: bool
) -> None:
    result = sandbox.run("states", anchor)
    if accepted:
        assert (result.returncode, result.stdout) == (0, "reached\n")
        assert sandbox.calls() == [["-s", "states"]]
    else:
        assert (result.returncode, result.stdout) == (64, "")
        assert sandbox.calls() == []


@needs_bash
@pytest.mark.parametrize("name", ["instance.json", "instance-structural.json"])
def test_instance_default_anchor_passes_the_backend_argument_check(
    sandbox: Sandbox, name: str
) -> None:
    result = sandbox.run("states", derived_anchor(name))
    assert (result.returncode, result.stdout) == (0, "reached\n")


@needs_bash
def test_backend_expression_and_installation_agree_on_generated_names() -> None:
    """Every component of up to three characters from a small alphabet, in one shell."""
    line = next(text for text in SCRIPT.read_text().splitlines() if "=~ ^com" in text)
    matched = re.fullmatch(r'\[\[ \$# -ge 2 && "\$2" =~ (\S+) \]\] \|\| exit 64', line)
    assert matched is not None, line
    alphabet = ["a", "z", "0", ".", "-", "/", "A", "_"]
    components = [""]
    for _ in range(3):
        components += [head + tail for head in components for tail in alphabet]
    candidates = sorted({PREFIX + component for component in components})
    candidates += [PREFIX + "b" * length for length in (62, 63, 64, 65)]
    script = (
        "export LC_ALL=C\n"
        'while IFS= read -r candidate; do if [[ "$candidate" =~ '
        + matched[1]
        + " ]]; then echo 1; else echo 0; fi; done\n"
    )
    result = subprocess.run(
        [str(BASH), "-c", script],
        input="".join(candidate + "\n" for candidate in candidates),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    answers = [answer == "1" for answer in result.stdout.split()]
    assert len(answers) == len(candidates) > 500
    assert answers == [record_accepts(candidate) for candidate in candidates]
    assert 0 < sum(answers) < len(answers)


@needs_bash
def test_backend_operates_on_exactly_the_pinned_anchor(sandbox: Sandbox) -> None:
    sandbox.kernel("live", "")
    result = sandbox.run("inspect", PINNED)
    assert (result.returncode, result.stdout) == (0, "")
    anchored = [call for call in sandbox.calls() if call[0] == "-a"]
    assert [call[2:] for call in anchored] == [
        ["-s", "rules"],
        ["-s", "Anchors"],
        ["-s", "Tables"],
        ["-s", "nat"],
    ]
    assert {call[1] for call in anchored} == {PINNED}


@needs_bash
@pytest.mark.parametrize("anchor", [PINNED, PRODUCT])
def test_backend_does_not_replace_rules_it_was_not_told_to_expect(
    sandbox: Sandbox, anchor: str
) -> None:
    """A pin onto an anchor another manager still fills is refused, not taken over."""
    sandbox.kernel("live", FOREIGN_RULE)
    expected = sandbox.rules("expected.rules", "")
    candidate = sandbox.rules("candidate.rules", "rdr own\n")
    result = sandbox.run("replace", anchor, expected, candidate)
    assert result.returncode == 73 and result.stdout == ""
    assert (sandbox.state / "live").read_text() == FOREIGN_RULE
    assert not any(call[2:3] == ["-f"] for call in sandbox.calls())
    # The hand-over: the previous manager empties the anchor, then the load is exact.
    sandbox.kernel("live", "")
    result = sandbox.run("replace", anchor, expected, candidate)
    assert (result.returncode, result.stdout) == (0, "rdr own\n")
    assert [call for call in sandbox.calls() if call[2:3] == ["-f"]] == [
        ["-a", anchor, "-f", candidate]
    ]


# ---- the owner with a pinned anchor, fake native tools only


def test_owner_with_a_pinned_anchor_converges_and_hands_the_name_to_its_backend(
    environment: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _, backend, snapshots = environment
    pinned = pin(environment)
    approve_all(environment)
    seen: list[str] = []

    def factory(_root: Store, installation: Installation) -> Any:
        seen.append(installation.anchor)
        return backend

    result = reconcile(
        root,
        lambda config, settings: snapshots[-1],
        factory,
        now=lambda: STAMP,
        report=lambda settings, snapshot: None,
    )
    assert result["phase"] == "committed" and seen == [PINNED]
    assert "static-port" in backend.rules
    # The real backend passes the installed name as the script's anchor argument.
    shell = shell_backend(environment, monkeypatch)
    shell.installation = pinned
    commands: list[list[str]] = []

    def fake(argv: list[str], **kwargs: Any) -> Result:
        commands.append(argv)
        return Result(0, b"", b"")

    monkeypatch.setattr(module, "run", fake)
    shell.inspect()
    shell.states()
    assert [command[:4] for command in commands] == [
        ["/bin/bash", str(shell.script), "inspect", PINNED],
        ["/bin/bash", str(shell.script), "states", PINNED],
    ]


@pytest.mark.parametrize("admitted", [False, True])
def test_pinned_anchor_that_already_holds_foreign_rules_stops_the_pass(
    environment: Any, admitted: bool
) -> None:
    root, _, _, backend, _ = environment
    pin(environment)
    if admitted:
        approve_all(environment)
    backend.rules = FOREIGN_RULE
    for _ in range(2):
        with pytest.raises(PFError, match="owned PF rules drifted; no overwrite or activation"):
            run_pass(environment)
    assert backend.rules == FOREIGN_RULE
    assert not any(command[0] in {"replace", "drain"} for command in backend.commands)
    assert not (root.directory / "live.json").exists()
    # The administrator's withdrawal does not empty somebody else's anchor either.
    with pytest.raises(PFError):
        withdraw(root, lambda root, settings: backend)
    assert backend.rules == FOREIGN_RULE
    # After the previous manager has emptied the anchor the next pass proceeds.
    backend.rules = ""
    root.write("operator-intent.json", intent_to_dict(Intent()))  # the withdrawal paused
    result = run_pass(environment)
    assert (result["phase"] == "committed") is admitted
    assert bool(backend.rules) is admitted


def test_admitted_digest_binds_the_pinned_anchor(environment: Any) -> None:
    root, config, settings, backend, _ = environment
    product, pinned = settings, Installation.from_dict({**settings.to_dict(), "anchor": PINNED})
    other = Installation.from_dict({**settings.to_dict(), "anchor": OTHER_PIN})
    for profile in config.profiles:
        digests = {admitted_digest(config, profile, item) for item in (product, pinned, other)}
        assert len(digests) == 3
    # An approval given under one anchor is not an approval under another: the
    # record of the installation is all that changes, and the pass retires everything.
    approve_all(environment)
    assert run_pass(environment)["phase"] == "committed"
    assert backend.rules
    pin(environment)
    result = run_pass(environment)
    assert result["phase"] == "inhibited" and len(result["pending"]) == 4
    assert backend.rules == ""
    admit(root, "proxy-standard", acknowledge_bounded_risk=False, now=STAMP - 1)
    assert "proxy-standard:activate" in run_pass(environment)["changed"]


@pytest.mark.parametrize(
    "installed,requested",
    [(PRODUCT, PINNED), (PINNED, PRODUCT), (PINNED, OTHER_PIN)],
    ids=["product-to-pin", "pin-to-product", "pin-to-pin"],
)
def test_installed_anchor_is_never_migrated_silently(
    monkeypatch: pytest.MonkeyPatch,
    environment: Any,
    tmp_path: Path,
    installed: str,
    requested: str,
) -> None:
    monkeypatch.setattr(module, "protected_ancestors", lambda *a, **kw: None)
    root, _, settings, _, _ = environment
    before = pin(environment, installed)
    wanted = Installation.from_dict({**settings.to_dict(), "anchor": requested})
    policy, setup = staged(tmp_path, environment, wanted)
    with pytest.raises(PFError, match="cannot be silently migrated"):
        install(root.directory, policy, setup, SCRIPT)
    assert root.read("installation.json") == before.to_dict()
    # Installing the same name again is not a migration.
    policy, setup = staged(tmp_path, environment, before)
    assert install(root.directory, policy, setup, SCRIPT)["installed"]
    assert root.read("installation.json")["anchor"] == installed


def test_new_installation_with_a_pinned_anchor_starts_paused_and_unadmitted(
    monkeypatch: pytest.MonkeyPatch, environment: Any, tmp_path: Path
) -> None:
    monkeypatch.setattr(module, "protected_ancestors", lambda *a, **kw: None)
    settings = Installation.from_dict({**environment[2].to_dict(), "anchor": PINNED})
    policy, setup = staged(tmp_path, environment, settings)
    result = install(tmp_path / "new-root", policy, setup, SCRIPT)
    store = Store(tmp_path / "new-root")
    assert result["installed"] and len(result["pending"]) == 4
    assert store.read("installation.json")["anchor"] == PINNED
    assert store.read("operator-intent.json")["operator_paused"]
    assert store.read("admissions.json")["profiles"] == {}
    # A name neither place accepts is refused before anything is written.
    settings_raw = {**environment[2].to_dict(), "anchor": PINNED + "/child"}
    setup.write_bytes(canonical_bytes(settings_raw))
    with pytest.raises(PFError, match="invalid independent PF owner identity"):
        install(tmp_path / "second-root", policy, setup, SCRIPT)
    assert not (tmp_path / "second-root").exists()


def test_deployment_bundle_carries_a_pinned_anchor_to_the_root_owner(
    tmp_path: Path, manifest: dict[str, Any], config: Any
) -> None:
    """The retained provisioning reads the same record: a pin reaches root unchanged."""
    source = Path(manifest["artifacts"][0]["source"])

    def settings_with(anchor: str) -> None:
        source.write_bytes(canonical_bytes({**strict_loads(source.read_bytes()), "anchor": anchor}))
        manifest["artifacts"][0]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()

    settings_with(PINNED)
    bundle, _ = make_bundle(tmp_path, manifest, config)
    rendered = bundle / "root" / manifest["artifacts"][0]["destination"]
    assert rendered.read_bytes() == source.read_bytes()
    assert Installation.from_dict(strict_loads(rendered.read_bytes())).anchor == PINNED
    settings_with(PINNED + "/child")
    with pytest.raises(PFError, match="invalid independent PF owner identity"):
        make_bundle(tmp_path, manifest, config, "nested")
    assert not (tmp_path / "nested").exists()


def test_published_report_does_not_name_the_pinned_anchor(environment: Any) -> None:
    """A site's own name stays in the protected record, out of the public report."""
    root, _, _, backend, snapshots = environment
    pin(environment)
    approve_all(environment)
    reports: list[Snapshot] = []
    reconcile(
        root,
        lambda config, settings: snapshots[-1],
        lambda root, settings: backend,
        now=lambda: STAMP,
        report=lambda settings, snapshot: reports.append(snapshot),
    )
    published = canonical_bytes(snapshot_to_dict(reports[-1])).decode()
    assert PINNED not in published and PINNED.removeprefix(PREFIX) not in published
    assert root.read("installation.json")["anchor"] == PINNED

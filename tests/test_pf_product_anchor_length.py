"""An anchor is a name that the tool and the kernel can both take: 63 bytes in all.

The complete name is what is passed to `pfctl` as one argument, `com.apple/`
included. The kernel does not create a component of 64 bytes or more; the nearest
published source of the tool stops at an argument of 64 bytes or more, and
Apple's own is not published. So the installation record holds the complete name
to 63 bytes in both of its forms: the product form `com.apple/netorch.<owner>`
exists for an owner identifier of at most 45 characters, a pinned component has
at most 53, and an owner with a longer identifier pins its anchor. The record
refuses a longer name where it is read. The backend script's argument check is
not changed; three tests state how its expression and the record's rule belong
together. An instance's derived anchor is held to the same bound. Fake native
tools only, except one hosted test: the script runs as the private copy that the
pinned-anchor tests build, and `NETORCH_TEST_BASH` selects the shell as it does
there.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import netorch.pf_owner as module
from netorch.codec import canonical_bytes, strict_loads
from netorch.config import load_config, parse_config, to_dict
from netorch.instance import (
    InstanceError,
    canonical_instance_bytes,
    instance_contract_digest,
    instance_digest,
    parse_instance,
    resolved_names,
)
from netorch.model import Config
from netorch.pf_owner import (
    Installation,
    PFError,
    admit,
    admitted_digest,
    install,
    reconcile,
    withdraw,
)
from netorch.state import Snapshot
from netorch.storage import Store
from tests.test_deployment import make_bundle, manifest
from tests.test_instance_any_source import BASE as SHIPPED_INSTANCES
from tests.test_pf_owner import ROOT, STAMP, approve_all, environment, run_pass
from tests.test_pf_pinned_anchor import BASH, PINNED, PREFIX, SCRIPT, Sandbox, needs_bash, sandbox
from tests.test_pf_profile_id_length import renamed

__all__ = ["environment", "manifest", "sandbox"]

OWNER = "site-forwarding"
NAME = "netorch."
# The record's bound: the bytes of the complete name, and of one component.
BOUND = 63
# What the bound leaves for a pinned component, and for the identifier of the product form.
PIN = BOUND - len(PREFIX)
LONGEST = PIN - len(NAME)
IDENTITY = "invalid independent PF owner identity"
NEEDS_PIN = "an owner identifier of more than 45 characters needs a pinned anchor"
DERIVED = "namespace-derived names exceed native name bounds; pin explicit names"


def owner(length: int) -> str:
    return "o" * length


def product(identifier: str) -> str:
    return PREFIX + NAME + identifier


def pinned(length: int) -> str:
    """A pinned anchor whose one component has this many characters."""
    return PREFIX + "a" * length


def raw(identifier: Any, anchor: Any, **decisions: str) -> dict[str, Any]:
    """An installation record as it is stored, with every member spelled out."""
    return {
        "schema_version": 1,
        "owner": identifier,
        "anchor": anchor,
        "observer": {"schema_version": 1, "account": "example"},
        "backend_sha256": "0" * 64,
        "report_path": "/protected/report.json",
        "intent_path": None,
        "interval_seconds": 10,
        "allow_apple_dns_coexistence": False,
        **decisions,
    }


def refusal(identifier: Any, anchor: Any) -> str | None:
    """The message with which both ways of making a record refuse it, or None."""
    messages = []
    for make in (
        lambda: Installation(identifier, anchor, {"schema_version": 1}, "0" * 64, "/report.json"),
        lambda: Installation.from_dict(raw(identifier, anchor)),
    ):
        try:
            make()
        except PFError as error:
            messages.append(str(error))
        else:
            messages.append(None)
    assert messages[0] == messages[1]
    return messages[0]


def policy_of(identifier: str) -> Config:
    """The example policy with its root owner renamed."""
    return parse_config(json.dumps(renamed("owner", OWNER, identifier)))


# ---- the installation record


def test_the_bound_is_one_constant_and_leaves_53_and_45_characters() -> None:
    from netorch import platform_contract

    assert platform_contract.PF_ANCHOR_BYTES == BOUND
    assert module.PF_ANCHOR_BYTES is platform_contract.PF_ANCHOR_BYTES
    assert (PIN, LONGEST) == (53, 45)
    assert len(pinned(PIN)) == len(product(owner(LONGEST))) == BOUND
    # The message takes its number from the same constant and the prefix.
    assert module._NEEDS_PIN == NEEDS_PIN and f" {LONGEST} " in NEEDS_PIN
    # One rule for both forms: the expression of a component, and the complete name.
    for anchor in (pinned(PIN), product(owner(LONGEST))):
        assert module._anchor_accepted(anchor)
        assert not module._anchor_accepted(anchor + "a")
        assert module._ANCHOR.fullmatch(anchor + "a")
    assert not module._anchor_accepted(pinned(PIN)[:-1] + "A")


@pytest.mark.parametrize("length", [1, 2, 44, 45])
def test_product_anchor_is_accepted_up_to_45_characters(length: int) -> None:
    assert refusal(owner(length), product(owner(length))) is None
    assert Installation.from_dict(raw(owner(length), product(owner(length)))).anchor == product(
        owner(length)
    )


@pytest.mark.parametrize("length", [46, 47, 55, 56, 62, 63])
def test_product_anchor_of_a_longer_identifier_is_refused_with_a_closed_message(
    length: int,
) -> None:
    message = refusal(owner(length), product(owner(length)))
    assert message == NEEDS_PIN
    # Closed: the message is one constant and repeats nothing of the input.
    assert owner(length) not in NEEDS_PIN and "com.apple" not in NEEDS_PIN


def test_every_identifier_length_has_exactly_this_answer() -> None:
    for length in range(1, 64):
        expected = None if length <= LONGEST else NEEDS_PIN
        assert refusal(owner(length), product(owner(length))) == expected, length
        # The identifier itself keeps its own bound of 63: it only needs a pin.
        assert refusal(owner(length), PINNED) is None, length
    assert refusal(owner(64), product(owner(64))) == IDENTITY
    assert refusal(owner(64), PINNED) == IDENTITY


@pytest.mark.parametrize("length", [46, 56, 63])
def test_a_longer_identifier_is_installed_with_a_pinned_anchor(length: int) -> None:
    for anchor in (PINNED, pinned(PIN), PREFIX + "netorch", PREFIX + "netorchx.other"):
        record = Installation.from_dict(raw(owner(length), anchor))
        assert (record.owner, record.anchor) == (owner(length), anchor)
        assert record.to_dict() == raw(owner(length), anchor)


def test_a_pinned_anchor_is_held_to_the_same_bound() -> None:
    """Every length of a pin has one answer, whatever the identifier beside it."""
    for identifier in (OWNER, owner(LONGEST), owner(63)):
        for length in range(1, 71):
            expected = None if length <= PIN else IDENTITY
            assert refusal(identifier, pinned(length)) == expected, (identifier, length)
        # Every character a pin may have, in the longest name and in one more.
        assert refusal(identifier, PREFIX + "a" + ".0-" * 16 + "z9z9") is None
        assert refusal(identifier, PREFIX + "a" + ".0-" * 17 + "z9") == IDENTITY
    assert len("a" + ".0-" * 16 + "z9z9") == PIN and len("a" + ".0-" * 17 + "z9") == PIN + 1


def test_other_refusals_keep_their_message() -> None:
    """Only this installation's own product form gets the answer of its own."""
    for identifier, anchor in (
        # another owner's product form, short and longer than the bound
        (OWNER, product("other")),
        (OWNER, product(owner(46))),
        (owner(46), product(owner(47))),
        (owner(63), product(owner(46))),
        (owner(63), product(owner(64))),
        # nested, and not below the platform namespace
        (owner(46), product(owner(46)) + "/child"),
        (owner(46), product(owner(46))[1:]),
        (owner(46), product(owner(46)) + "\n"),
        # a pin whose complete name is one byte too long, and one with a longer component
        (OWNER, pinned(PIN + 1)),
        (owner(46), pinned(63)),
        (owner(63), pinned(64)),
    ):
        assert refusal(identifier, anchor) == IDENTITY, (identifier, anchor)


@pytest.mark.parametrize(
    "wrong", [None, 5, 5.5, True, b"site-forwarding", ["site-forwarding"], {"owner": OWNER}]
)
def test_owner_and_anchor_are_text_before_anything_else_is_asked(wrong: Any) -> None:
    """A value of another type is refused with the closed message, never with a type error."""
    assert refusal(wrong, PINNED) == IDENTITY
    assert refusal(OWNER, wrong) == IDENTITY
    assert refusal(wrong, wrong) == IDENTITY
    # Also where the other member is one that would be refused for its length.
    assert refusal(wrong, pinned(PIN + 1)) == IDENTITY
    assert refusal(owner(LONGEST + 1), wrong) == IDENTITY


# ---- what is stored stays as it was

# name: (record, SHA-256 of its stored canonical bytes, admission digest of the
# example's `proxy-standard` under an implementation fingerprint of 64 times "f").
# The literals were computed on the tree this change is based on.
STORED: dict[str, tuple[dict[str, Any], str, str]] = {
    "product form, 45 characters": (
        raw(owner(45), product(owner(45))),
        "277c260dc5a65220e69df5a7e658ae3a427569f754369dbd1d681b564d9f81d9",
        "a0703812795fe520e145c213c660637db6b6a3a07cdb50da12ee77211240f302",
    ),
    "product form with both decisions": (
        raw(OWNER, product(OWNER), enable_reference="reacquire", cold_start="self-heal"),
        "a71f056fb4ac675caa67c55d1682fe16cba2069c8b1629144bae6f16c48cb673",
        "dcf3885921da40dd8cb2e472c0737ff4e87e00635c183efdb03d2541285eeac1",
    ),
    "pin of 53 characters, identifier of 63": (
        raw(owner(63), pinned(53)),
        "8a43c48d5d74b3c3813590dc454fc756619c788f0877c0d4a95796f71a49e65e",
        "aa3136b2b62fc8197a54e0a8e1342a6b2af295b79e75af9bab1be04a631753aa",
    ),
    "pin, identifier of 46": (
        raw(owner(46), PINNED),
        "7c37c687253bea48ef9fd552ca65e48a1455b50c6a31821cc0d3432f77434e8d",
        "352e2d16b8f679745d6d863d2a30059bf4cc3c2f8f9eebc5f9650ca4c321102c",
    ),
}
EXAMPLE = (
    "95be49e017ee4b685b88ddedfb087b1322e250254a618ab3b2aecea599190288",
    "b6e227a7522567875e2243ad15eac79eb1970f0b35a2910cf391acf6ce9a351b",
)


def stored_and_admitted(record: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    monkeypatch.setattr(module, "implementation_digest", lambda: "f" * 64)
    config = load_config(ROOT / "examples/network.json")
    installation = Installation.from_dict(record)
    stored = canonical_bytes(installation.to_dict())
    # Reading and writing a record changes nothing in it.
    assert stored == canonical_bytes(record)
    return (
        hashlib.sha256(stored).hexdigest(),
        admitted_digest(config, config.profile("proxy-standard"), installation),
    )


@pytest.mark.parametrize("name", sorted(STORED))
def test_stored_bytes_and_admission_digests_of_valid_records_are_unchanged(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    record, stored, admitted = STORED[name]
    assert stored_and_admitted(record, monkeypatch) == (stored, admitted)


def test_shipped_settings_example_is_stored_and_admitted_as_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = strict_loads((ROOT / "examples/forwarding-settings.json").read_bytes())
    assert record["anchor"] == product(record["owner"]) and len(record["anchor"]) <= BOUND
    assert stored_and_admitted(record, monkeypatch) == EXAMPLE


# ---- refused where the record is read, before the backend is called

# A record that an earlier state of the code accepted: (identifier, anchor, the refusal).
REFUSED = {
    "product form of 46": (owner(46), product(owner(46)), NEEDS_PIN),
    "product form of 63": (owner(63), product(owner(63)), NEEDS_PIN),
    "pin of 54": (OWNER, pinned(54), IDENTITY),
    "pin of 63": (OWNER, pinned(63), IDENTITY),
}


def staged_inputs(tmp_path: Path, record: dict[str, Any]) -> tuple[Path, Path]:
    policy, setup = tmp_path / "policy.json", tmp_path / "settings.json"
    policy.write_bytes(canonical_bytes(renamed("owner", OWNER, record["owner"])))
    setup.write_bytes(canonical_bytes(record))
    return policy, setup


@pytest.mark.parametrize("length", [45, 46, 63])
def test_installer_stores_the_product_form_up_to_45_characters_and_nothing_beyond(
    monkeypatch: pytest.MonkeyPatch, environment: Any, tmp_path: Path, length: int
) -> None:
    monkeypatch.setattr(module, "protected_ancestors", lambda *args, **kwargs: None)
    identifier = owner(length)
    record = {**environment[2].to_dict(), "owner": identifier, "anchor": product(identifier)}
    policy, setup = staged_inputs(tmp_path, record)
    destination = tmp_path / "new-root"
    if length > LONGEST:
        with pytest.raises(PFError) as refused:
            install(destination, policy, setup, SCRIPT)
        assert str(refused.value) == NEEDS_PIN
        assert not destination.exists()
        # The same owner is installed under a pinned anchor.
        record["anchor"] = PINNED
        setup.write_bytes(canonical_bytes(record))
    assert install(destination, policy, setup, SCRIPT)["installed"]
    assert (destination / "installation.json").read_bytes() == canonical_bytes(record) + b"\n"
    assert Store(destination).read("operator-intent.json")["operator_paused"]


@pytest.mark.parametrize("length", [53, 54, 63])
def test_installer_stores_a_pin_up_to_53_characters_and_nothing_beyond(
    monkeypatch: pytest.MonkeyPatch, environment: Any, tmp_path: Path, length: int
) -> None:
    monkeypatch.setattr(module, "protected_ancestors", lambda *args, **kwargs: None)
    record = {**environment[2].to_dict(), "anchor": pinned(length)}
    policy, setup = staged_inputs(tmp_path, record)
    destination = tmp_path / "new-root"
    if length > PIN:
        with pytest.raises(PFError) as refused:
            install(destination, policy, setup, SCRIPT)
        assert str(refused.value) == IDENTITY
        assert not destination.exists()
        # The longest name that fits is installed.
        record["anchor"] = pinned(PIN)
        setup.write_bytes(canonical_bytes(record))
    assert install(destination, policy, setup, SCRIPT)["installed"]
    assert (destination / "installation.json").read_bytes() == canonical_bytes(record) + b"\n"


def stored_by_an_earlier_state(environment: Any, identifier: str, anchor: str) -> Config:
    """Put the record and its policy into the store as code without the rule did."""
    root, _, settings, _, _ = environment
    config = policy_of(identifier)
    root.write("policy.json", to_dict(config))
    root.write("installation.json", {**settings.to_dict(), "owner": identifier, "anchor": anchor})
    return config


@pytest.mark.parametrize("name", sorted(REFUSED))
def test_stored_record_is_refused_before_the_backend_is_made_or_anything_is_written(
    environment: Any, name: str
) -> None:
    root, _, _, backend, snapshots = environment
    identifier, anchor, message = REFUSED[name]
    stored_by_an_earlier_state(environment, identifier, anchor)

    def files() -> dict[str, bytes]:
        return {path.name: path.read_bytes() for path in sorted(root.directory.glob("*.json"))}

    before = files()
    made: list[str] = []
    observed: list[str] = []

    def factory(_root: Store, installation: Installation) -> Any:
        made.append(installation.anchor)
        return backend

    def observer(config: Config, settings: Any) -> Snapshot:
        observed.append(config.site)
        return snapshots[-1]

    operations: dict[str, Callable[[], Any]] = {
        "pass": lambda: reconcile(
            root, observer, factory, now=lambda: STAMP, report=lambda settings, snapshot: None
        ),
        "withdraw": lambda: withdraw(root, factory),
        "admit": lambda: admit(root, "proxy-standard", acknowledge_bounded_risk=False, now=1.0),
    }
    for operation_name, operation in operations.items():
        with pytest.raises(PFError) as refused:
            operation()
        assert str(refused.value) == message, operation_name
    # No backend, hence no pfctl; no observation; no journal, record or pause.
    assert made == [] and observed == [] and backend.commands == []
    assert files() == before
    assert not (root.directory / "journal.json").exists()
    assert not (root.directory / "live.json").exists()
    assert root.read("operator-intent.json")["operator_paused"] is False


@pytest.mark.parametrize("form", ["product", "pin"])
def test_owner_with_the_longest_anchor_is_admitted_and_converges(
    environment: Any, form: str
) -> None:
    root, _, settings, backend, snapshots = environment
    identifier, anchor = (
        (owner(LONGEST), product(owner(LONGEST))) if form == "product" else (OWNER, pinned(PIN))
    )
    config = stored_by_an_earlier_state(environment, identifier, anchor)
    longest = Installation.from_dict(root.read("installation.json"))
    assert len(longest.anchor) == BOUND
    renamed_environment = (root, config, longest, backend, snapshots)
    approve_all(renamed_environment)
    assert run_pass(renamed_environment)["phase"] == "committed"
    assert backend.rules and root.read("live.json")["records"]
    assert settings.anchor != longest.anchor


@pytest.mark.parametrize("length", [45, 46])
def test_deployment_bundle_is_held_to_the_same_record(
    tmp_path: Path, manifest: dict[str, Any], length: int
) -> None:
    identifier = owner(length)
    source = Path(manifest["artifacts"][0]["source"])
    record = {
        **strict_loads(source.read_bytes()),
        "owner": identifier,
        "anchor": product(identifier),
    }
    source.write_bytes(canonical_bytes(record))
    manifest["artifacts"][0]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    if length > LONGEST:
        with pytest.raises(PFError) as refused:
            make_bundle(tmp_path, manifest, policy_of(identifier))
        assert str(refused.value) == NEEDS_PIN
        assert not (tmp_path / "bundle").exists()
    else:
        bundle, _ = make_bundle(tmp_path, manifest, policy_of(identifier))
        rendered = bundle / "root" / manifest["artifacts"][0]["destination"]
        assert rendered.read_bytes() == source.read_bytes()


# ---- the script's expression and the record's rule: two texts, pinned together

# What the script's expression takes: one component of the kernel's bound, whatever
# the complete name; and the product form of every identifier the record knows.
COMPONENT = 63


def script_expression() -> str:
    """The anchor expression of the shipped script, wherever the script states it."""
    found = set(re.findall(r"\^com\\\.apple/[^\s'\"]+\$", SCRIPT.read_text()))
    assert len(found) == 1, found
    return found.pop()


def test_script_expression_is_the_product_form_or_the_record_expression() -> None:
    """Two hand-written texts in two languages: a change of either fails here.

    The script lets through the product form of every identifier, or one component.
    The record's expression is that component; its rule also bounds the complete name.
    """
    identifier = module._ID.pattern.removesuffix(r"\Z")
    assert identifier == "[a-z][a-z0-9-]{0,62}"
    assert module._ANCHOR.pattern.startswith(r"com\.apple/")
    component = module._ANCHOR.pattern.removeprefix(r"com\.apple/").removesuffix(r"\Z")
    assert component == "[a-z][a-z0-9.-]{0,62}"
    assert module._ANCHOR.pattern == r"com\.apple/" + component + r"\Z"
    assert script_expression() == (
        r"^com\.apple/(" + re.escape(NAME) + identifier + "|" + component + ")$"
    )
    # The expression holds a component to the kernel's bound, for a pin and the product.
    assert module._ANCHOR.fullmatch(pinned(COMPONENT))
    assert not module._ANCHOR.fullmatch(pinned(COMPONENT + 1))
    assert module._ANCHOR.fullmatch(product(owner(COMPONENT - len(NAME))))
    assert not module._ANCHOR.fullmatch(product(owner(COMPONENT - len(NAME) + 1)))


@needs_bash
def test_script_and_record_differ_only_where_the_complete_name_is_too_long() -> None:
    """The script's own expression, in one shell, for every identifier and pin length."""
    owners = [owner(length) for length in range(1, 66)]
    pins = [pinned(length) for length in range(1, 66)]
    candidates = [product(identifier) for identifier in owners] + pins
    loop = (
        "export LC_ALL=C\n"
        'while IFS= read -r candidate; do if [[ "$candidate" =~ '
        + script_expression()
        + " ]]; then echo 1; else echo 0; fi; done\n"
    )
    result = subprocess.run(
        [str(BASH), "-c", loop],
        input="".join(candidate + "\n" for candidate in candidates),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    script = [answer == "1" for answer in result.stdout.split()]
    assert len(script) == len(candidates)
    # The script: the product form of every valid identifier, and a pin of one component.
    assert script == [len(identifier) <= 63 for identifier in owners] + [
        len(pin) - len(PREFIX) <= COMPONENT for pin in pins
    ]
    record = [refusal(identifier, product(identifier)) is None for identifier in owners] + [
        refusal(OWNER, pin) is None for pin in pins
    ]
    # The record: what the script lets through, where the complete name has 63 bytes at most.
    assert record == [
        accepted and len(candidate) <= BOUND
        for accepted, candidate in zip(script, candidates, strict=True)
    ]
    # Identifiers of 46 to 63 characters, and pins of 54 to 63.
    assert sum(script) - sum(record) == (63 - LONGEST) + (COMPONENT - PIN) == 18 + 10


@needs_bash
@pytest.mark.parametrize(
    "anchor,by_record,by_script",
    [
        (product(owner(45)), True, True),
        (product(owner(46)), False, True),
        (product(owner(63)), False, True),
        (product(owner(64)), False, False),
        (pinned(53), True, True),
        (pinned(54), False, True),
        (pinned(63), False, True),
        (pinned(64), False, False),
    ],
    ids=[
        "product-45",
        "product-46",
        "product-63",
        "product-64",
        "pin-53",
        "pin-54",
        "pin-63",
        "pin-64",
    ],
)
def test_shipped_script_still_passes_a_longer_name_on_and_the_record_does_not(
    sandbox: Sandbox, anchor: str, by_record: bool, by_script: bool
) -> None:
    """The real argument check, executed: it is not changed and bounds no complete name."""
    result = sandbox.run("states", anchor)
    if by_script:
        assert (result.returncode, result.stdout) == (0, "reached\n")
        assert sandbox.calls() == [["-s", "states"]]
    else:
        assert (result.returncode, result.stdout) == (64, "")
        assert sandbox.calls() == []
    identifier = anchor.removeprefix(PREFIX + NAME) if anchor.startswith(PREFIX + NAME) else OWNER
    assert (refusal(identifier, anchor) is None) is by_record


# ---- hosted macOS: what the platform's own tool takes as an anchor argument (nothing is loaded)

# The complete argument: three lengths around the bound, and one whose single
# component has the kernel's 63 bytes while the argument has 73.
ARGUMENTS = [pinned(52), pinned(53), pinned(54), pinned(63)]


def translation_rule() -> str:
    """One harmless redirect, of the kind the hosted parser test of the redirect uses.

    Interface and address are those of the shipped example policy, as they are there.
    """
    config = load_config(ROOT / "examples/network.json")
    scope = config.scope(config.profile("proxy-standard").scope)
    return (
        f"rdr on {scope.interface} inet proto tcp from any to {scope.host_ipv4} "
        f"port 80 -> {scope.host_ipv4} port 8080\n"
    )


def test_hosted_dry_runs_ask_what_the_record_decides() -> None:
    """Runs everywhere: the arguments and the rule that the hosted test hands to the tool."""
    assert [len(argument) for argument in ARGUMENTS] == [62, 63, 64, 73]
    assert [len(argument) - len(PREFIX) for argument in ARGUMENTS] == [52, 53, 54, COMPONENT]
    # The record takes the first two and refuses the other two.
    assert [refusal(OWNER, argument) for argument in ARGUMENTS] == [None, None, IDENTITY, IDENTITY]
    rule = translation_rule()
    assert re.fullmatch(
        r"rdr on \S+ inet proto tcp from any to (\S+) port 80 -> \1 port 8080\n", rule
    )


def recorded(capsys: Any, title: str, seen: str) -> None:
    """On the hosted runner, keep what the platform tool answered as a notice of the job."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        text = seen.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        # Capture is lifted for one line of its own: the runner reads commands at line starts.
        with capsys.disabled():
            print(f"\n::notice title={title}::{text}")


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
def test_platform_tool_takes_an_anchor_argument_of_63_bytes(tmp_path: Path, capsys: Any) -> None:
    """`pfctl -a <anchor> -n -f` only parses a file; run unprivileged it can load nothing.

    Four dry runs with one harmless translation rule, for arguments of 62, 63, 64
    and 73 bytes. Every answer is recorded first. Only what the record relies on
    is asserted: the argument of 63 bytes is accepted. What the tool answers for
    64 and for 73 bytes is not decided here; the notices are the evidence, for one
    hosted runner image only. Each call also writes its notice about `-f` to
    standard error, so that stream is recorded and never compared.
    """
    rules = tmp_path / "anchor.pf"
    rules.write_text(translation_rule())
    answers = {}
    for argument in ARGUMENTS:
        result = subprocess.run(
            ["/sbin/pfctl", "-a", argument, "-n", "-f", str(rules)],
            capture_output=True,
            timeout=10,
            check=False,
        )
        answers[len(argument)] = result
        recorded(
            capsys,
            f"pfctl dry run with an anchor argument of {len(argument)} bytes",
            f"status {result.returncode}, out {result.stdout[:300]!r}, err {result.stderr[:500]!r}",
        )
    assert answers[BOUND].returncode == 0, answers[BOUND].stderr.decode("utf-8", "replace")


# ---- the instance: a derived anchor is held to the same bound, a pinned one is not judged


def instance_of(length: int, **names: str) -> dict[str, Any]:
    """The structural example with a namespace of this length and the given names pinned."""
    data: dict[str, Any] = json.loads((ROOT / "examples/instance-structural.json").read_bytes())
    stem = ".".join(["org", "example"]) + "."
    data["namespace"] = stem + "n" * (length - len(stem))
    assert len(data["namespace"]) == length
    data["names"].update(names)
    return data


def derived_anchor(data: dict[str, Any]) -> str:
    return PREFIX + data["namespace"] + ".forwarding"


def parse(data: dict[str, Any]) -> Any:
    return parse_instance(canonical_bytes(data) + b"\n")


@pytest.mark.parametrize("length", [22, 41, 42])
def test_instance_whose_derived_anchor_fits_is_accepted_and_installable(length: int) -> None:
    data = instance_of(length)
    instance = parse(data)
    derived = resolved_names(instance)["pf_anchor"]
    assert instance.names.pf_anchor is None and derived == derived_anchor(data)
    assert len(derived) == length + 21 <= BOUND
    # The owner's record takes the name the instance derives.
    assert refusal(OWNER, derived) is None


@pytest.mark.parametrize("length", [43, 44, 52])
def test_instance_whose_derived_anchor_is_too_long_is_refused_where_the_owner_refuses(
    length: int,
) -> None:
    data = instance_of(length)
    assert len(derived_anchor(data)) == length + 21 > BOUND
    with pytest.raises(InstanceError) as refused:
        parse(data)
    assert str(refused.value) == DERIVED
    assert refusal(OWNER, derived_anchor(data)) == IDENTITY
    # With a pinned name that fits, the same namespace is an instance again.
    assert resolved_names(parse(instance_of(length, pf_anchor=PINNED)))["pf_anchor"] == PINNED


def test_longer_namespace_with_pinned_prefixes_is_held_to_the_bound_as_well() -> None:
    """Pinned discovery prefixes were the one way to a derived component of 64 and more."""
    prefixes = {"bonjour_prefix": "example-container-", "import_prefix": "example-lan-"}
    for length, accepted in ((42, True), (43, False), (53, False), (60, False)):
        data = instance_of(length, **prefixes)
        if accepted:
            assert resolved_names(parse(data))["pf_anchor"] == derived_anchor(data)
        else:
            with pytest.raises(InstanceError) as refused:
                parse(data)
            assert str(refused.value) == DERIVED


def test_pinned_anchor_of_an_instance_is_not_judged_by_this_rule() -> None:
    """The schema lets a site state the name it uses; the retained owner may not take it."""
    data = instance_of(52)
    for stated in (derived_anchor(data), PREFIX + "example/nested", pinned(100)):
        instance = parse(instance_of(52, pf_anchor=stated))
        assert resolved_names(instance)["pf_anchor"] == stated
        assert refusal(OWNER, stated) == IDENTITY


@pytest.mark.parametrize("name", sorted(SHIPPED_INSTANCES))
def test_shipped_instances_keep_their_bytes_and_digests(name: str) -> None:
    """Literals of the tree this change is based on, kept in the neighbouring module."""
    expected = SHIPPED_INSTANCES[name]
    stored = (ROOT / "examples" / name).read_bytes()
    instance = parse_instance(stored)
    assert hashlib.sha256(stored).hexdigest() == expected["file_sha256"]
    assert canonical_instance_bytes(instance) == stored
    assert instance_digest(instance) == expected["instance_digest"]
    assert instance_contract_digest(instance) == expected["contract_digest"]
    derived = resolved_names(instance)["pf_anchor"]
    assert instance.names.pf_anchor is None and len(derived) <= BOUND
    assert refusal(OWNER, derived) is None

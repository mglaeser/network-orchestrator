"""Closed domain inventories: parser proof plus read-only macOS grammar checks."""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable

import pytest

from netorch.launchd_inventory import domain_services
from netorch.process import run
from tests.test_apple_runtime import domain_report

DOMAIN = "user/501"
LABEL = "com.apple.container.example-runtime.example-camera"


@pytest.mark.parametrize("domain", ["system", "user/501", "gui/501"])
@pytest.mark.parametrize("labels", [(), (LABEL,), (LABEL, "example.unrelated")])
def test_complete_domains_include_loaded_jobs_even_without_a_pid(domain, labels):
    assert domain_services(domain_report(domain, labels).decode(), domain) == frozenset(labels)


@pytest.mark.parametrize("pid", ["0", "1", "2147483647"])
@pytest.mark.parametrize("status", ["-", "0", "-15", "127", "(pe)", "(jt)"])
def test_known_loaded_row_forms(pid, status):
    text = domain_report(DOMAIN, (LABEL,)).decode().replace("0 - ", f"{pid} {status} ")
    assert domain_services(text, DOMAIN) == {LABEL}


@pytest.mark.parametrize(
    "change",
    [
        lambda s: "",
        lambda s: s[:-2],
        lambda s: s + "trailing junk\n",
        lambda s: s.replace("user/501 =", "user/502 ="),
        lambda s: s.replace("\ttype = user", "\ttype = login"),
        lambda s: s.replace("\thandle = 501", "\thandle = 502"),
        lambda s: s.replace("service count = 1", "service count = 0"),
        lambda s: s.replace("service count = 1", "service count = 2"),
        lambda s: s.replace("service count = 1", "service count = -1"),
        lambda s: s.replace("\tservice count = 1\n", ""),
        lambda s: s.replace("\tservices = {\n", "\tservices = {\n\t\tgarbage\n"),
        lambda s: s.replace("\tservices = {\n", "\tservices = {\n\t\t0 - other label\n"),
        lambda s: s.replace("\tservices = {\n", "\tservices = {\n\t\t0 - nested {\n"),
        lambda s: s.replace("\tservices = {", "\tservices = {}\n\tservices = {"),
        lambda s: s.replace("\tservices = {", "\tservices = {\n\t}\n\tservices = {"),
        lambda s: s.replace("\tservice count = 1", "\tservice count = 1\n\tservice count = 1"),
        lambda s: s.replace("\ttype = user", "\ttype = user\n\ttype = user"),
        lambda s: s.replace("0 - ", "-1 - "),
        lambda s: s.replace("0 - ", "x - "),
        lambda s: s.replace("0 - ", "0 (unknown) "),
        lambda s: s.replace(LABEL, LABEL + "\x00"),
        lambda s: s.replace("service count = 1", "service count = 2").replace(
            "\t}\n", f"\t\t0 - {LABEL}\n\t}}\n"
        ),
        lambda s: s.replace("\tservices = {", "\tother = {\n\tservices = {").replace(
            "\t}\n", "\t}\n\t}\n"
        ),
    ],
)
def test_invalid_or_ambiguous_inventory_never_proves_absence(change: Callable[[str], str]):
    text = domain_report(DOMAIN, (LABEL,)).decode()
    with pytest.raises(ValueError):
        domain_services(change(text), DOMAIN)


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s.replace("\t}\n", "\t\t}\n"),
        lambda s: s.replace("\tservices = {", "\t0 - example.displaced\n\tservices = {"),
        lambda s: s.replace("\tservices = {", "\tinvalid { = {\n\t}\n\tservices = {"),
        lambda s: s.replace("\ttype = user", "\ttype user"),
    ],
)
def test_displaced_rows_and_invalid_block_boundaries_are_not_ignored(change):
    with pytest.raises(ValueError):
        domain_services(change(domain_report(DOMAIN, (LABEL,)).decode()), DOMAIN)


def test_domain_print_size_bound_applies_even_when_services_block_is_small():
    text = (
        domain_report(DOMAIN)
        .decode()
        .replace("\tservices = {", "\textra = " + "x" * 262144 + "\n\tservices = {")
    )
    with pytest.raises(ValueError):
        domain_services(text, DOMAIN)


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="read-only macOS userspace grammar")
@pytest.mark.parametrize("kind", ["system", "user", "gui"])
def test_actual_service_domain_grammar_without_loading_or_starting_jobs(kind):
    domain = "system" if kind == "system" else f"{kind}/{os.getuid()}"
    result = run(["/bin/launchctl", "print", domain], timeout=3, max_output=262144)
    # A headless host can have no GUI session. CI has one and must prove its grammar.
    if kind == "gui" and result.returncode and os.environ.get("GITHUB_ACTIONS") != "true":
        pytest.skip("no GUI session; this is not an empty service-domain proof")
    assert result.returncode == 0 and not result.stderr
    # Keep a failed native parse from printing host paths or unrelated labels in
    # pytest's argument/traceback display. Evidence is the shape/count, not data.
    labels = None
    diagnostic = {}
    try:
        labels = domain_services(result.stdout.decode("utf-8", "strict"), domain)
    except ValueError as exc:
        # Exception messages are fixed parser categories. Reveal structure/counts
        # only, never native paths, environment values or unrelated job labels.
        trace = exc.__traceback__
        while trace is not None and trace.tb_next is not None:
            trace = trace.tb_next
        state = {} if trace is None else trace.tb_frame.f_locals
        line = state.get("line", "")
        identity = state.get("identity", {})
        count = identity.get("service count", "")
        diagnostic = {
            "category": str(exc),
            "line_shape": re.sub(r"[^ \t{}=]", "x", line),
            "labels_parsed": len(state.get("labels", ())),
            "declared_count": int(count) if count.isascii() and count.isdecimal() else None,
        }
    assert labels is not None, diagnostic
    assert labels, "native contract fixture needs a nonempty domain"

"""The hard-bounds row after the unrestricted source, and the packet from outside.

`ROOT-HARD-BOUNDS` is worded so that it is true with and without `source_scope: any`.
A profile that declares the setting also makes `ANY-SOURCE-INGRESS` applicable, and
only a record of the method `external-first-packet` for that profile verifies it. No
signature stands in for that record: the row keeps its proving gate, like every other
native acceptance.
Nothing but the registry's own text moves in a report: the literal hashes below were
taken from the tree before this change, whose registry had neither the row nor the
sentence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from netorch import host_report
from netorch.codec import canonical_bytes
from netorch.host_report import MANDATORY_PROVING_GATES, build_report, empty_evidence
from netorch.instance import (
    InstanceError,
    canonical_instance_bytes,
    instance_contract_digest,
    instance_digest,
    resolved_profile_digest,
)
from netorch.profile_library import STRATEGIES, strategy
from netorch.requirements import REQUIREMENTS, Requirement, requirement
from tests.test_check_positive_path import attest as prove
from tests.test_check_positive_path import (
    host,
    list_platform,
    observations,
    open_rows,
    retract,
    triple,
)
from tests.test_check_positive_path import report as host_report_of
from tests.test_instance_any_source import PUBLICATION, REDIRECT, with_redirect
from tests.test_report_guards import (
    EXAMPLES,
    NOW,
    attest,
    checked_in_test_files,
    evidence,
    parsed,
    platform,
    report,
    status,
)
from tests.test_report_truthfulness import deviation, row

__all__ = ["host"]

BOUNDS = "ROOT-HARD-BOUNDS"
OUTSIDE = "ANY-SOURCE-INGRESS"
METHOD = "external-first-packet"
RETURN = "example-return"
SECOND = "example-redirect-second"

FORMER_STATEMENT = "No profile widens interface, IPv4 scope or admitted rule shape."
FORMER_TESTS = ("test_unknown_strategy_or_version_is_rejected",)
# What the reworded sentence rests on, part by part: the instance parser, root's own
# acknowledgement at admission, the rule bytes of a policy without the setting (its
# interface, prefix and shape), the renderer's refusal for a guest target or a return
# pair, and the acknowledgement that every pass asks of the admission record.
BOUNDS_TESTS = (
    *FORMER_TESTS,
    "test_admission_of_an_unrestricted_source_needs_its_own_acknowledgement",
    "test_existing_rules_keep_their_bytes",
    "test_renderer_itself_never_emits_any_for_a_guest_target_or_a_return_pair",
    "test_record_without_the_acknowledgement_never_activates_an_unrestricted_source",
)
OUTSIDE_TESTS = (
    "test_any_source_host_redirect_renders_from_any_to_the_host_address",
    "test_a_lan_first_packet_record_does_not_prove_the_outside_packet",
)
# The one form of source the registry has: a concern of this review.
REVIEW = "review-2026-10-05"
NOT_APPLICABLE = ("not-applicable", "No corresponding declared capability.")
UNPROVEN = (
    "unverified",
    "Declared capability requires its proving test at the recorded host tier.",
)
VERIFIED = (
    "fulfilled-verified",
    "Current content-bound owner acceptance and retained evidence hash verified.",
)
GATED = (
    "not-fulfilled",
    "An owner-accepted deviation cannot replace this mandatory proving gate.",
)

# SHA-256 of the complete report without evidence, as the tree before this change printed it.
BASE_REPORT_SHA256 = {
    "shipped": "2f3dc929c382af3f88318115f20ce470f85dee6b418d57247b39e370d6e941b3",
    "shipped-structural": "9d678e1e170bc6911e4216d0b4981e837a38a716a447c5a1bd30477d74a2c597",
    "lan-redirect": "bccaecf52c17ae0f0d1d6ca4fd940c5cdc92c8f63d7967a1c0b0d863bcfea556",
    "any-redirect": "7adf3590bedb1f5fd28e5434a08e5e5490bfbcda98cede9ba27375894e49f78f",
}
# Bytes and digests of the example with a redirect, from the tree before this change.
BASE_REDIRECT = {
    "lan-redirect": {
        "file_sha256": "159a48f1af4cd0fd6f6f02a2635ee4301aaf648d023af7d41e7ee5c2a806d972",
        "instance_digest": "26c170fb7de280199e7ae7b4950e1f679fc594d29d7613d81df230a63d1e2822",
        "contract_digest": "1eef151a27fab98d288f35aac4eaf4f69e33255d768b51d0fdd42f3d7171628d",
        "redirect": "b97fcaab5a53d81c9aa1b6519032cb3a41be5c7268959777f7f0b8838f7466f8",
    },
    "any-redirect": {
        "file_sha256": "0eb2fe43635db06176abe27d908ae31d44e9c8d286a0f9af5b63a21e43bfde16",
        "instance_digest": "b99dafe972f6a0f749ac3beea879be4e601310e306b6f0b63ac55a4fca4248ce",
        "contract_digest": "e16cbe92349908e5271e63608d21cfb1a9335f71c3f130336f12b06a373abc7b",
        "redirect": "605f7844bcb18b4be55334c1d40ee110917e74c135b043454e02da9294c32d26",
    },
}
# The acceptance methods both schemas listed before this change, in their order.
BASE_METHODS = [
    "schema-tests",
    "fixture-parity",
    "darwin-cli",
    "native-publication",
    "rule-readback",
    "first-packet",
    "state-drain",
    "application-connect",
    "cold-application-scan",
    "receiver-change",
    "heard-audio",
    "dns-client-identity",
    "unattended-reboot",
    "restore-rehearsal",
    "process-inventory",
    "local-network-consent",
    "root-runtime-observer",
    "port-budget",
]
# Every row a signed deviation could not stand in for before this change.
BASE_GATES = frozenset(
    {
        "BOUNDED-IDENTITY",
        "PLATFORM-SUPPORT",
        "SOURCE-AUTHORSHIP",
        "OWNER-CONFORMANCE",
        "ROOT-ADMISSION",
        "ROOT-HARD-BOUNDS",
        "ROOT-INDEPENDENCE",
        "PAUSE-PRESERVED",
        "UNKNOWN-NO-RECOVERY",
        "RESTORE-REHEARSAL",
        "NO-LOCAL-NETWORK",
        "CURRENT-OBSERVATIONS",
        "DISCOVERY-PUBLICATION",
        "DISCOVERY-IMPORT",
        "DISCOVERY-LEASES",
        "CONSENT-IDENTITY",
        "UDP-FIRST-PACKET",
        "DNS-CLIENT-IDENTITY",
        "HEARD-AUDIO",
        "MULTI-RECEIVER",
        "BOOT-RECOVERY",
        "OWNER-ROLLBACK",
        "PORT-BUDGET",
    }
)


def document(case: str) -> dict[str, Any]:
    if case == "lan-redirect":
        return with_redirect()
    if case == "any-redirect":
        return with_redirect(source_scope="any")
    name = "instance.json" if case == "shipped" else "instance-structural.json"
    data: dict[str, Any] = json.loads((EXAMPLES / name).read_bytes())
    return data


def wide() -> dict[str, Any]:
    """The example with an unrestricted-source redirect in front of its publication."""
    return document("any-redirect")


def plain(data: dict[str, Any]) -> dict[str, Any]:
    """The report without any evidence, as the pinned hashes were taken."""
    return build_report(parsed(data), empty_evidence(NOW), now=NOW, data_directory=EXAMPLES)


def outcome(result: dict[str, Any], identifier: str) -> tuple[str, str]:
    found = row(result, identifier)
    return found["status"], found["reason"]


def proven(data: dict[str, Any], records: Path) -> dict[str, Any]:
    return report(data, platform(), evidence_directory=records)


def former_registry() -> tuple[Requirement, ...]:
    """The registry as it was: neither the new row nor the new sentence."""
    return tuple(
        replace(item, statement=FORMER_STATEMENT, proving_tests=FORMER_TESTS)
        if item.id == BOUNDS
        else item
        for item in REQUIREMENTS
        if item.id != OUTSIDE
    )


# ---- the reworded row


def test_hard_bounds_statement_names_the_three_bounds_and_both_acts() -> None:
    statement = requirement(BOUNDS).statement
    assert statement == (
        "No profile widens interface, IPv4 scope or admitted rule shape beyond what "
        "its policy declares and root admitted for it."
    )
    # The former sentence is how it begins; the rest says what a profile is measured against.
    assert statement.startswith(FORMER_STATEMENT.removesuffix("."))
    for part in ("interface", "IPv4 scope", "admitted rule shape", "its policy declares"):
        assert part in statement
    assert statement.endswith("and root admitted for it.")
    assert row(plain(document("shipped")), BOUNDS)["statement"] == statement


def test_hard_bounds_keeps_its_method_tier_applicability_and_gate() -> None:
    bounds = requirement(BOUNDS)
    assert bounds.acceptance_methods == ("first-packet",)
    assert (bounds.minimum_tier, bounds.applicability) == (3, "root-transport")
    assert bounds.source == "review-2026-10-05:Rule2"
    assert bounds.proving_tests[0] == "test_unknown_strategy_or_version_is_rejected"
    assert BOUNDS in MANDATORY_PROVING_GATES


def test_hard_bounds_names_the_refusal_without_the_separate_acknowledgement() -> None:
    named = requirement(BOUNDS).proving_tests
    assert named == BOUNDS_TESTS
    assert named[1] == "test_admission_of_an_unrestricted_source_needs_its_own_acknowledgement"


@pytest.mark.parametrize("name", BOUNDS_TESTS[2:])
def test_hard_bounds_names_the_tests_of_the_rendered_rule_and_of_every_pass(name: str) -> None:
    # The refusal at admission shows neither that a rule without the declaration keeps
    # its interface, prefix and shape, nor that a record without the acknowledgement
    # loads nothing on a later pass. The row names the tests that do.
    assert name in requirement(BOUNDS).proving_tests
    assert checked_in_test_files()[name] == {"test_any_source.py"}


def test_both_rows_name_tests_in_the_files_that_exercise_them() -> None:
    files = checked_in_test_files()

    def named(identifier: str) -> set[str]:
        return {file for name in requirement(identifier).proving_tests for file in files[name]}

    assert named(BOUNDS) == {"test_instance.py", "test_any_source.py"}
    assert named(OUTSIDE) == {"test_any_source.py", Path(__file__).name}


# ---- the new row


def test_the_outside_packet_has_a_row_of_its_own_below_hard_bounds() -> None:
    outside = requirement(OUTSIDE)
    assert outside.statement == (
        "A first packet from outside the LAN prefix is answered through each redirect "
        "with an unrestricted source; a LAN client proves nothing about that setting."
    )
    assert outside.acceptance_methods == (METHOD,)
    assert (outside.minimum_tier, outside.applicability) == (3, "any-source")
    assert outside.source == requirement(BOUNDS).source
    order = [item.id for item in REQUIREMENTS]
    assert order.index(OUTSIDE) == order.index(BOUNDS) + 1


def test_the_outside_packet_names_exactly_its_two_proving_tests() -> None:
    # The rule that matches every source, and the report that refuses a LAN record.
    assert requirement(OUTSIDE).proving_tests == OUTSIDE_TESTS


def test_both_rows_trace_to_the_rule_whose_bound_they_concern() -> None:
    # A source names the concern of the review that a row serves, never who added the row.
    assert {item.source.partition(":")[0] for item in REQUIREMENTS} == {REVIEW}
    assert requirement(BOUNDS).source == requirement(OUTSIDE).source == REVIEW + ":Rule2"
    # The label exists where the repository explains that review's rules.
    table = (EXAMPLES.parent / "docs" / "review-traceability.md").read_text(encoding="utf-8")
    assert "\n| Rule 2: content admission |" in table
    # It is the rule of what root admits: the admission, its bound, and the evidence
    # for the one declared exception to that bound.
    admitted = [item.id for item in REQUIREMENTS if item.source == REVIEW + ":Rule2"]
    assert admitted == ["ROOT-ADMISSION", BOUNDS, OUTSIDE]


def test_the_method_belongs_to_the_one_requirement_and_to_no_strategy() -> None:
    assert [item.id for item in REQUIREMENTS if METHOD in item.acceptance_methods] == [OUTSIDE]
    # A strategy's list is the same for every profile that uses it, so it cannot ask
    # for something only a declared setting needs.
    assert not any(METHOD in item.proving_tests for item in STRATEGIES)
    assert strategy("host-port-redirect", 1).proving_tests == ("rule-readback", "first-packet")


@pytest.mark.parametrize("case", ["shipped", "shipped-structural", "lan-redirect"])
def test_the_row_does_not_apply_without_the_setting(case: str) -> None:
    result = plain(document(case))
    assert outcome(result, OUTSIDE) == NOT_APPLICABLE
    assert row(result, OUTSIDE)["required_methods"] == [METHOD]


def test_the_row_applies_where_the_setting_is_declared() -> None:
    lan, declared = plain(document("lan-redirect")), plain(wide())
    assert outcome(declared, OUTSIDE) == UNPROVEN
    asked = row(declared, OUTSIDE)
    assert (asked["required_methods"], asked["minimum_tier"]) == ([METHOD], 3)
    before = {item["id"]: item["status"] for item in lan["requirements"]}
    after = {item["id"]: item["status"] for item in declared["requirements"]}
    assert {key for key in before if before[key] != after[key]} == {OUTSIDE}
    assert not declared["fully_served"]


def test_any_scope_but_the_default_asks_for_the_outside_packet(tmp_path: Path) -> None:
    # Validation refuses this value; the report still fails closed on a model built by hand.
    data = document("lan-redirect")

    def forged() -> Any:
        instance = parsed(data)
        return replace(
            instance,
            transport=tuple(
                replace(item, source_scope="everything") if item.id == REDIRECT else item
                for item in instance.transport
            ),
        )

    result = build_report(forged(), empty_evidence(NOW), now=NOW, data_directory=EXAMPLES)
    assert outcome(result, OUTSIDE) == UNPROVEN
    # The same profile is the one a record has to name: none without a profile stands in.
    whole = instance_contract_digest(forged())
    attest(data, tmp_path, OUTSIDE, METHOD, 3, contract_sha256=whole)
    assert not host_report._acceptance(
        forged(), requirement(OUTSIDE), evidence(platform()), NOW, tmp_path
    )


def test_a_host_redirect_without_the_setting_needs_nothing_new(tmp_path: Path) -> None:
    data = document("lan-redirect")
    for profile in (REDIRECT, RETURN):
        attest(data, tmp_path, BOUNDS, "first-packet", 3, profile)
    result = proven(data, tmp_path)
    assert outcome(result, BOUNDS) == VERIFIED
    assert outcome(result, OUTSIDE) == NOT_APPLICABLE
    listed = [item for item in result["retirement"] if item["name"] == "host-port-redirect"]
    assert [list(item["proving_tests"]) for item in listed] == [["rule-readback", "first-packet"]]


# ---- what must stay: bytes, digests, and every other byte of a report


@pytest.mark.parametrize("case", sorted(BASE_REDIRECT))
def test_digests_of_an_instance_with_a_redirect_are_those_of_the_base(case: str) -> None:
    instance = parsed(document(case))
    expected = BASE_REDIRECT[case]
    raw = canonical_instance_bytes(instance)
    assert hashlib.sha256(raw).hexdigest() == expected["file_sha256"]
    assert instance_digest(instance) == expected["instance_digest"]
    assert instance_contract_digest(instance) == expected["contract_digest"]
    redirect = instance.transport_profile(REDIRECT)
    assert resolved_profile_digest(instance, redirect) == expected["redirect"]


@pytest.mark.parametrize("case", sorted(BASE_REPORT_SHA256))
def test_the_former_registry_prints_the_report_of_the_base(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    monkeypatch.setattr(host_report, "REQUIREMENTS", former_registry())
    former = plain(document(case))
    assert hashlib.sha256(canonical_bytes(former)).hexdigest() == BASE_REPORT_SHA256[case]
    assert former["schema_version"] == 2


@pytest.mark.parametrize("case", sorted(BASE_REPORT_SHA256))
def test_a_report_differs_from_the_base_only_in_the_two_registry_rows(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    current = plain(document(case))
    monkeypatch.setattr(host_report, "REQUIREMENTS", former_registry())
    former = plain(document(case))
    assert hashlib.sha256(canonical_bytes(former)).hexdigest() == BASE_REPORT_SHA256[case]
    assert {key for key in current if current[key] != former[key]} == {"requirements"}
    rows = {item["id"]: item for item in current["requirements"]}
    kept = [key for key in rows if key != OUTSIDE]
    assert kept == [item["id"] for item in former["requirements"]]
    for before in former["requirements"]:
        after = rows[before["id"]]
        changed = {key for key in before if before[key] != after[key]}
        assert changed == ({"statement", "proving_tests"} if before["id"] == BOUNDS else set())
    assert set(rows[OUTSIDE]) == set(rows[BOUNDS])
    expected = UNPROVEN if case == "any-redirect" else NOT_APPLICABLE
    assert outcome(current, OUTSIDE) == expected


# ---- evidence for the new row


def test_without_a_record_the_outside_packet_is_unverified(tmp_path: Path) -> None:
    data = wide()
    for result in (plain(data), report(data), proven(data, tmp_path)):
        assert outcome(result, OUTSIDE) == UNPROVEN
        assert not result["fully_served"]


def test_a_lan_first_packet_record_does_not_prove_the_outside_packet(tmp_path: Path) -> None:
    data = wide()
    attest(data, tmp_path, OUTSIDE, "first-packet", 3, REDIRECT)
    for profile in (REDIRECT, RETURN):
        attest(data, tmp_path, BOUNDS, "first-packet", 3, profile)
    result = proven(data, tmp_path)
    # The first packet of the same profile proves its bound and nothing about the outside.
    assert outcome(result, BOUNDS) == VERIFIED
    assert outcome(result, OUTSIDE) == UNPROVEN
    attest(data, tmp_path, OUTSIDE, METHOD, 3, REDIRECT)
    result = proven(data, tmp_path)
    assert outcome(result, BOUNDS) == outcome(result, OUTSIDE) == VERIFIED


@pytest.mark.parametrize("tier", [3, 4, 5])
def test_an_outside_record_of_the_profile_verifies_the_row(tmp_path: Path, tier: int) -> None:
    data = wide()
    retained = attest(data, tmp_path, OUTSIDE, METHOD, tier, REDIRECT)
    entry = data["acceptance"][-1]
    assert entry["contract_sha256"] == BASE_REDIRECT["any-redirect"]["redirect"]
    record = json.loads(retained.read_bytes())
    assert (record["method"], record["profile"], record["tier"]) == (METHOD, REDIRECT, tier)
    schema = host_report._validator("acceptance-evidence.schema.json")
    assert not list(schema.iter_errors(record))
    assert outcome(proven(data, tmp_path), OUTSIDE) == VERIFIED
    # The ledger entry alone, without the retained record, is nothing.
    assert outcome(report(data, platform()), OUTSIDE) == UNPROVEN
    retained.unlink()
    assert outcome(proven(data, tmp_path), OUTSIDE) == UNPROVEN


@pytest.mark.parametrize(
    "problem",
    ["lower-tier", "publication", "return-profile", "instance-wide", "lan-digest", "fixture"],
)
def test_a_record_that_is_not_this_profiles_outside_packet_proves_nothing(
    tmp_path: Path, problem: str
) -> None:
    data = wide()
    if problem == "lower-tier":
        attest(data, tmp_path, OUTSIDE, METHOD, 2, REDIRECT)
    elif problem == "publication":
        attest(data, tmp_path, OUTSIDE, METHOD, 3, PUBLICATION)
    elif problem == "return-profile":
        attest(data, tmp_path, OUTSIDE, METHOD, 3, RETURN)
    elif problem == "instance-wide":
        attest(data, tmp_path, OUTSIDE, METHOD, 3)
    elif problem == "lan-digest":
        # Captured while the redirect was LAN-scoped: the digest binds the scope.
        attest(
            data,
            tmp_path,
            OUTSIDE,
            METHOD,
            3,
            REDIRECT,
            contract_sha256=BASE_REDIRECT["lan-redirect"]["redirect"],
        )
    else:
        attest(data, tmp_path, OUTSIDE, METHOD, 3, REDIRECT, context="offline-fixture")
    assert len(data["acceptance"]) == 1
    assert outcome(proven(data, tmp_path), OUTSIDE) == UNPROVEN


def test_a_record_made_before_the_widening_does_not_follow_the_profile(tmp_path: Path) -> None:
    data = document("lan-redirect")
    attest(data, tmp_path, OUTSIDE, METHOD, 3, REDIRECT)
    assert outcome(proven(data, tmp_path), OUTSIDE) == NOT_APPLICABLE
    data["transport"][-1]["source_scope"] = "any"
    assert outcome(proven(data, tmp_path), OUTSIDE) == UNPROVEN


def test_each_unrestricted_profile_needs_its_own_record(tmp_path: Path) -> None:
    data = wide()
    data["transport"].append(
        {**data["transport"][-1], "id": SECOND, "ports": {"first": 443, "last": 443}}
    )
    attest(data, tmp_path, OUTSIDE, METHOD, 3, REDIRECT)
    assert outcome(proven(data, tmp_path), OUTSIDE) == UNPROVEN
    attest(data, tmp_path, OUTSIDE, METHOD, 3, SECOND)
    assert outcome(proven(data, tmp_path), OUTSIDE) == VERIFIED


def test_the_method_counts_only_for_its_own_requirement(tmp_path: Path) -> None:
    data = wide()
    for profile in (REDIRECT, RETURN):
        attest(data, tmp_path, BOUNDS, METHOD, 3, profile)
    result = proven(data, tmp_path)
    # The parser accepts the rows; the report counts a method for its requirement only.
    assert outcome(result, BOUNDS) == UNPROVEN
    assert outcome(result, OUTSIDE) == UNPROVEN


# ---- a signed deviation


def test_mandatory_gates_gain_the_outside_packet_and_nothing_else() -> None:
    gates = set(MANDATORY_PROVING_GATES)
    assert gates == BASE_GATES | {OUTSIDE}


def test_every_native_acceptance_keeps_its_proving_gate() -> None:
    native = {item.id for item in REQUIREMENTS if item.minimum_tier >= 3}
    assert OUTSIDE in native and native <= MANDATORY_PROVING_GATES


def test_a_signed_deviation_cannot_stand_in_for_the_outside_packet(tmp_path: Path) -> None:
    data = wide()
    data["deviations"].append(deviation(OUTSIDE, accepted_by=None, accepted_at=None))
    assert status(report(data), OUTSIDE) == "not-fulfilled"  # recorded, not accepted
    data["deviations"][0] = deviation(OUTSIDE)
    assert outcome(report(data), OUTSIDE) == GATED
    # The deviation stays recorded and keeps the row open, also beside a record.
    attest(data, tmp_path, OUTSIDE, METHOD, 3, REDIRECT)
    assert outcome(proven(data, tmp_path), OUTSIDE) == GATED
    del data["deviations"][0]
    assert outcome(proven(data, tmp_path), OUTSIDE) == VERIFIED


def test_one_signature_serves_no_unrestricted_profile_now_or_later(tmp_path: Path) -> None:
    # A deviation is bound to no profile, digest or release; a record is bound to all
    # three. So the signature serves neither the profile it was written for nor one
    # that is added afterwards, and after a new release pin only a new record counts.
    data = wide()
    data["deviations"].append(deviation(OUTSIDE))
    assert outcome(proven(data, tmp_path), OUTSIDE) == GATED
    data["transport"].append(
        {**data["transport"][-1], "id": SECOND, "ports": {"first": 443, "last": 443}}
    )
    assert outcome(proven(data, tmp_path), OUTSIDE) == GATED
    data["deviations"].clear()
    for profile in (REDIRECT, SECOND):
        attest(data, tmp_path, OUTSIDE, METHOD, 3, profile)
    assert outcome(proven(data, tmp_path), OUTSIDE) == VERIFIED
    data["framework"]["artifact_sha256"] = "1" * 64
    assert outcome(proven(data, tmp_path), OUTSIDE) == UNPROVEN
    data["deviations"].append(deviation(OUTSIDE))
    assert outcome(proven(data, tmp_path), OUTSIDE) == GATED


@pytest.mark.parametrize("case", ["lan-redirect", "any-redirect"])
def test_hard_bounds_still_cannot_be_waived(case: str) -> None:
    data = document(case)
    assert outcome(report(data), BOUNDS) == UNPROVEN
    data["deviations"].append(deviation(BOUNDS))
    assert outcome(report(data), BOUNDS) == GATED


@pytest.mark.parametrize("case", ["shipped", "lan-redirect"])
def test_a_deviation_changes_nothing_where_the_row_does_not_apply(case: str) -> None:
    data = document(case)
    before = report(data)["requirements"]
    data["deviations"].append(deviation(OUTSIDE, accepted_by=None, accepted_at=None))
    after = report(data)
    assert outcome(after, OUTSIDE) == NOT_APPLICABLE
    assert after["requirements"] == before


def widened(proven_host: SimpleNamespace) -> list[str]:
    """Put an unrestricted-source redirect in front of the proven host's publication.

    Returns the rows that are open afterwards, with nothing attested for the new instance.
    """
    data = proven_host.data
    publication = data["transport"][0]
    data["transport"].append(
        {
            "dependencies": [publication["id"]],
            "fallback_publication": None,
            "id": REDIRECT,
            "ports": {"first": 80, "last": 80},
            "protocol": "tcp",
            "service": publication["service"],
            "source_scope": "any",
            "strategy": "host-port-redirect",
            "target_ports": dict(publication["ports"]),
            "version": 1,
        }
    )
    data["acceptance"] = []
    proven_host.document = observations(data)
    return open_rows(host_report_of(proven_host))


def test_fully_served_needs_the_outside_packet_itself(
    host: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    list_platform(monkeypatch, triple(host.data))
    still_open = widened(host)
    assert OUTSIDE in still_open and BOUNDS in still_open
    instance = parsed(host.data)
    profiles = {
        "transport": [item.id for item in instance.transport],
        "root-transport": [REDIRECT],
        "any-source": [REDIRECT],
        "discovery": [item.id for item in instance.discovery],
        "exports": [item.id for item in instance.discovery],
    }
    for identifier in still_open:
        if identifier != OUTSIDE:
            for profile in profiles.get(requirement(identifier).applicability, [None]):
                prove(host.data, host.records, identifier, profile, instance=instance)
    result = host_report_of(host)
    assert open_rows(result) == [OUTSIDE] and outcome(result, OUTSIDE) == UNPROVEN
    assert result["current_ready"] and not result["fully_served"]

    # A signature that the packet from outside was not captured serves nothing.
    host.data["deviations"].append(deviation(OUTSIDE))
    result = host_report_of(host)
    assert outcome(result, OUTSIDE) == GATED
    assert open_rows(result) == [OUTSIDE] and not result["fully_served"]

    # Only the record does.
    host.data["deviations"].clear()
    prove(host.data, host.records, OUTSIDE, REDIRECT, instance=instance)
    result = host_report_of(host)
    assert outcome(result, OUTSIDE) == VERIFIED
    assert open_rows(result) == [] and result["fully_served"]

    # Nor is the bound itself served by a signature.
    retract(host.data, BOUNDS)
    host.data["deviations"].append(deviation(BOUNDS))
    result = host_report_of(host)
    assert outcome(result, BOUNDS) == GATED
    assert open_rows(result) == [BOUNDS] and not result["fully_served"]


# ---- the two enumerations


@pytest.mark.parametrize(
    ("name", "path"),
    [
        ("instance.schema.json", ("properties", "acceptance", "items", "properties", "method")),
        ("acceptance-evidence.schema.json", ("properties", "method")),
    ],
)
def test_both_enumerations_only_gain_the_method_as_their_last_value(
    name: str, path: tuple[str, ...]
) -> None:
    node: Any = json.loads((EXAMPLES.parent / "schemas" / name).read_bytes())
    for key in path:
        node = node[key]
    assert node == {"enum": [*BASE_METHODS, METHOD]}


def test_an_instance_acceptance_row_may_name_the_method(tmp_path: Path) -> None:
    data = wide()
    attest(data, tmp_path, OUTSIDE, METHOD, 3, REDIRECT)
    assert parsed(data).acceptance[0].method == METHOD
    # The ledger is outside the contract digest, as before.
    expected = BASE_REDIRECT["any-redirect"]["contract_digest"]
    assert instance_contract_digest(parsed(data)) == expected
    data["acceptance"][0]["method"] = "outside-first-packet"
    with pytest.raises(InstanceError, match="closed versioned schema"):
        parsed(data)

# Discovery readiness record, 9 October 2026

This record covers the discovery findings R-D1 to R-D13 of the readiness check
of release 0.4.2 (`main` at `de4cbb5`) against what an existing site does, and
two findings, R-D14 and R-D15, that came up while checking R-D6 and R-D10. It
was checked by reading the discovery owner (`bonjour_owner.py`,
`bonjour_process.py`, `discovery.py`, `discovery_plan.py`), the owner's guides
and review records, and by running the owner's own functions against the fake
native clients of the existing Bonjour tests. Fixtures use invented names and
RFC 5737 addresses. All evidence is mock tier: nothing ran on a host, and what
an existing site does is stated in general words only.

[`tests/test_readiness_discovery.py`](../../tests/test_readiness_discovery.py)
holds a test for each flagged finding that the code can express, two for R-D15
(one for an activation, one for a cleanup). Each asserts the behaviour proposed
below and is marked `xfail(strict=True, raises=AssertionError)`: it fails today
with an AssertionError whose message states what the owner does now, the suite
stays green, and the test fails the suite once the proposal is implemented, so
that this record is followed up. Run
`pytest tests/test_readiness_discovery.py --runxfail` to see the failures. A
test's set-up checks call `pytest.fail`, so a fixture that stops holding fails
the suite instead of passing as expected. In a throwaway copy of the tree, a
minimal implementation of each proposal turned its test into `XPASS(strict)`;
those implementations are not part of this change.

The tests prove what the repository's code does with these inputs. They do not
prove native behaviour (the vendor client, the daemon, timing on a host), what
an existing site does, or anything an application sees. The closing acceptance
of each entry names the requirement row of `src/netorch/requirements.py` and
what a host measurement would have to show.

Two rules of the coordinator recur. A publisher that reads a policy as `unknown`
makes the coordinator's next run plan a cleanup (`discovery_plan.plan_discovery`,
reason `publisher-unknown`), and only the run after that can activate the
policy again: R-D9, R-D10 and R-D14. And a discovery readback that is not the
expected one within the endpoint's seven seconds, after an activation or after
a cleanup, leaves a failed journal that blocks every later run until an
administrator acknowledges it: R-D15, which R-D9 and R-D10 reach too. The owner
protocol states both ([owner protocol](../owner-protocol.md), "Discovery
owner": "Unknown, stale, generation-changed or unconfirmed evidence requests
cleanup and inhibits activation until a later complete observation." and
"Returned unknown or mismatched readback stops subsequent writes and records a
failed journal."). The proposals of R-D14 and R-D15 are exceptions to these two
sentences, so the protocol text changes with them. The coordinator's interval is
at least 10 seconds (`safety_contract.LAUNCHD_INTERVAL_FLOOR_SECONDS`, the
example deployment's value).

## R-D1: an export whose address answer is an alias first

On `main` an export whose guest answers the address query with another of its
addresses first (an alias) is dropped without a count (`skipped` stays 0),
against the guide's sentence that "its record is then read by the guest
address". Fixed in a separate pull request of this round, "Read an exported
guest by its address when an alias answers first", which reads the address a
second time only where every address of the first answer lies outside the guest
network, so an alias inside the guest network is read as before; no test here.

## R-D2: a failed registration is tried again at once

On `main` a registration that fails (a rename on a name conflict, a denial)
withdraws its policy, and the publisher's next turn registers every record again
without a hold-off: 16 clients for one record in 20 seconds with a fake client
that renames after one second. Fixed in a separate pull request of this round,
"Hold a record back after its registration client fails"; no test here.

## R-D3: instances that never answer withdraw the whole import

**What an existing site does.** Its import leaves out instances that do not
answer and keeps importing the others.

**What this repository does.** `bonjour_process.scan` leaves out at most
`MAX_LEFT_OUT` (4) instances of one scan, one type on one interface, and fails
the scan with `incomplete` at the fifth. It counts an instance whose resolve
printed no reply line (`unanswered`) like one whose answers cannot be used.
`bonjour_owner.scan_policy` then fails the whole policy. Where another scan of
the pass read an instance, `_only_unfinished` does not mark the failure as a
read that did not complete, so `counts_as_miss` is false and the policy is
withdrawn even under `failed_pass: "miss"`. The import's eligible receivers go
with it, although the instances that failed the scan never answered and could
not have been imported. The guide states the bound
([Bonjour owner](../bonjour-owner.md), "One instance and the scan as a whole"):
"A fifth unusable instance fails the scan with `incomplete`, and the names
after it are not asked about", and "so does a scan at its fifth instance left
out where another scan of the pass read one".
`test_scan_at_its_fifth_unanswered_instance_beside_one_that_read_keeps_failing`
pins it. The ledger's limits for #72 ("wholly unproved scans still fail") and
#107 do not name this case: here the pass read a usable instance of the policy.

**Evidence.** `test_r_d3_instances_that_never_answer_leave_the_import_of_another_type`,
for five and six instances of `_companion-link._tcp` that print no reply beside
one eligible `_airplay._tcp` instance, through the real reader, a real scanner
pass and a publisher turn:
`pytest tests/test_readiness_discovery.py -k r_d3 --runxfail`. Today the pass
writes the reason `incomplete`, no records and no count, and the publisher reads
`unknown / unobserved`. A set-up check requires that five instances whose
answers cannot be used (a reply with a port that cannot be published) still
fail their scan, so raising `MAX_LEFT_OUT` alone fails the test instead of
satisfying it; only a bound of their own for instances that never answered
does.

**Proposed change.** In `bonjour_process.scan`, count an instance that was left
out because its resolve printed no reply line apart from one whose answers
cannot be used. Keep `MAX_LEFT_OUT` for the second kind. Give the first a bound
of its own, for example the policy's `max_records`, which the browse already
enforces for the names it lists. The scan's own 45 seconds stay the outer bound:
each such instance costs `scan_seconds`, and a scan that runs out of time still
fails with `timed-out`. Both kinds go into the candidate's `skipped`, and
`lease_records` takes the new bound (`max_records` for each type instead of
`min(MAX_LEFT_OUT, max_records)`). Nothing else changes: a pass leaves nothing
out unless it read an instance of the policy, and every command that cannot
prove itself, every reply for another interface and every diagnostic still
fails the scan. The guide binds these reading rules to discovery digest
version 4, so as a default the change needs digest version 6 with version-5
requests, candidates and readbacks refused; as an opt-in it is an owner setting
whose absence keeps today's bound. The test above asserts the default; an
opt-in needs the test to state the setting, and the existing test named above
changes with it.

**Decision needed.** Which bound for instances that never answered; a default
with a new digest version, or a setting; and whether the longer wait of such a
scan (up to its 45 seconds instead of five times `scan_seconds`) is acceptable,
since that time ages the candidate of every policy of the pass.

**Closing acceptance.** `DISCOVERY-IMPORT`, methods `cold-application-scan` and
`receiver-change`, tier 5. On a host with one eligible media receiver and at
least five devices that announce a related type of the import without answering
its resolve, the media application's own scanner finds the receiver after a
cold start and after a receiver change. It passes when the receiver is found
both times, the observation's `skipped_count` shows the silent devices, and the
receiver is never withdrawn because of them.

## R-D4: no automatic export of announced TCP services (reference)

Recorded by the owner: [site-requirements review](2026-10-08-site-requirements-review.md),
item 3; [closure record](2026-10-08-closure-and-qualification.md), "Discovery
selection and names"; [migration readiness](../migration-readiness.md), "Known
extraction gaps"; `test_discovery_service_types.py` proves the refusal of the
automatic form. What the text leaves out: an explicit list has a cost of its own.
Each batch of up to eight types of a policy adds 45 seconds to the scanner's
pass budget (`bonjour_owner.pass_budget`), and with it 90 seconds to the lease
that a miss tolerance needs (R-D7).

## R-D5: an export rests on the publication row alone

**What an existing site does.** Before it publishes a guest service on the LAN,
it checks that a socket listens on the LAN address and port.

**What this repository does.** `discovery.project_export` publishes a record
only where exactly one verified publication of the same service, generation,
scope and protocol maps the record's port to the LAN endpoint. That publication
is the runtime owner's report (`apple_runtime._publication`), which reads the
vendor's configured `publishedPorts` row and nothing else. The guide rules a
listener out as a reason to export ("A coincident numeric listener or another
container's publication does not qualify."), and nothing requires one either:
no reader checks that something listens there. The only socket reader on `main`
is the root forwarding owner's `socket_inventory`
(`netstat -anlv -W -p <protocol>`). It serves two other purposes: `ports_clear`
at the activation of each of that owner's rules (the rule's host ports must be
free of other listeners), and, for #104, `_judged` and `_listening`, which keep
a loaded host path whose runtime read timed out only where a listener is on
every port. Neither result reaches the discovery owner, which reads the owners'
reports (`independent_snapshot`) and holds no listener evidence. The ledger
records for #104: "Listener alone is residual availability policy, not identity
proof."

**Evidence.** No test. A strict expected failure would need an input that tells
the discovery owner that nothing listens. There is none: the `Publication` that
`project_export` matches carries no listener, and the owner runs no socket read.
A test would have to invent the interface of the change before the owner has
chosen it. That an export rests on the row alone is visible in
`tests/test_discovery.py` (`test_export_preserves_identity_and_binary_txt`,
`test_exact_publication_tuple_must_be_unique`): the projection's only inputs are
the record, the service's observation and the publications.

**Proposed change.** An availability check beside the publication, never in its
place. Once per pass and protocol, the scanner reads the listening sockets
before it projects an export (`bonjour_owner.scan_policy`). A record whose LAN
endpoint has no listener on the scope's host address or the wildcard is left
out and counted in `skipped`, as `pf_owner._listening` decides for #104 (for
UDP, a bound socket). Two places can provide the read: an unprivileged
`netstat -an -p <protocol>` in the discovery owner, or a listener fact in the
root forwarding owner's report, which already reads the inventory as root.
Whether the platform lists every user's sockets to an unprivileged reader is not
captured; the vendor's port forwarder may run under another identity. A read
that fails or times out is a read that did not complete: it withdraws the export
as a failed pass does, and counts as a miss only under `failed_pass: "miss"`.
Default: an owner setting (for example `listener_check`), absent unless given,
because it changes what is published for an unchanged input.

**Decision needed.** Whether the discovery owner may read sockets at all, which
reader, and what an unreadable inventory does.

**Closing acceptance.** `DISCOVERY-PUBLICATION` and `DISCOVERY-LEASES`, method
`application-connect`, tier 5. An accessory controller on the LAN connects to an
exported endpoint. Then the guest's listener stops while its container runs and
its publication row stays. It passes when, with the setting, the record leaves
the LAN within one pass and one publisher poll, returns with the listener, and
the controller reconnects. If the read is a connection from the discovery
owner's own job, `CONSENT-IDENTITY` (`local-network-consent`, tier 3) applies to
that job.

## R-D6: a record leaves the network at each renewal (reference)

Recorded by the owner: [Bonjour owner](../bonjour-owner.md), "Supervision,
leases and recovery" ("Without the setting the record is not registered between
the two clients: it leaves the network and returns at least every two
minutes."), and the paragraphs on `renewal_overlap_seconds`;
[site-requirements review](2026-10-08-site-requirements-review.md), item 4.
What the text leaves out is what the gap does to the coordinator: a run that
falls into it withdraws the whole policy. That is recorded as R-D14.

## R-D7: the lease that a miss tolerance needs (guidance)

**What an existing site does.** It keeps an outward record that its scans miss
for several passes; the ledger describes the existing loss policy for #62 as
"outward (three passes) and inward (immediate)".

**What this repository does.** A missed record is carried only while its lease
outlasts the next candidate: `MissedSources.__call__` keeps it while
`seen_at + max_age_seconds > now + carry_horizon`, `now` being the start of the
pass that misses it. `load_settings` refuses a tolerance above 1 unless a lease
exceeds `pass_interval + carry_horizon`. `carry_horizon` is the rest and two
pass budgets, and `pass_budget` is 10 seconds for each other owner's report, 4
for each scope, 45 for each batch of up to eight types of each owned policy, and
5. The guide states the rule and the example's numbers (119 and 243 seconds),
and that the lease, not the tolerance, ends a kept record.

For a policy of three owners, one scope and four owned policies (three exports
of one type each, one import of four types), `pass_budget` is 209 seconds. With
the default rest of 5 seconds or `pass_seconds` 30:

| | Rest 5 s (`poll_seconds`, the default) | Rest 30 s (`pass_seconds` 30) |
|---|---|---|
| `carry_horizon` | 423 s | 448 s |
| Smallest lease that loads, tolerance 1 | 1 s (no condition) | 60 s (twice `pass_seconds`) |
| Smallest lease that loads, tolerance 2 or 3 (owner's setting or a policy's `misses`) | 429 s | 479 s |
| Lease that keeps a record through one miss (tolerance 2), passes of 0 s / 10 s / the whole budget | 429 / 439 / 638 s | 479 / 489 / 688 s |
| Lease that keeps a record through two misses (tolerance 3), passes of 0 s / 10 s / the whole budget | 434 / 454 / 852 s | 509 / 529 / 927 s |

A tolerance of k keeps a record through k − 1 missed passes only where
`max_age_seconds > (k − 1) × P + carry_horizon`, P being the time from the start
of one pass to the start of the next: the rest and the pass itself. The
smallest lease that loads assumes a pass that takes no time. At that lease a
tolerance of 2 or 3 keeps a record through one miss only if the pass that read
it took less than a second, and through none if it took 10 seconds. Every pass
takes at least one browse of `scan_seconds` (1 to 5, default 2) for each policy
it scans, because a browse runs until its `-t` timer. On a host that lease
therefore keeps nothing, which the guide's sentence "Settings are refused where
a tolerance above 1 could never keep anything" does not reflect.

The numbers were computed on `main` with the owner's functions, for synthetic
files of that shape:

```python
from netorch import bonjour_owner as owner
from netorch.config import load_config

settings = owner.load_settings(settings_path)  # ValueError where no lease has room
config = load_config(settings.config)
owner.pass_budget(config, settings)  # 209
owner.carry_horizon(config, settings)  # 423 at a rest of 5 s, 448 at 30 s
# The smallest lease that loads: the least max_age_seconds that load_settings accepts.
# The kept-through columns: owner.MissMemory(k).begin(policy, fence, now + horizon),
# called for the pass that reads the record and for each pass that misses it.
```

**Evidence.** No test, as no code change is proposed. The rule itself is proved
by `test_record_is_carried_only_while_its_lease_outlasts_the_next_candidate` and
`test_lease_ends_a_carried_record_whatever_the_tolerance`.

**Proposed change.** Guidance only. In the guide, after "The example's
120-second leases do not have it.", state the formula above, that P is at least
the rest and one browse of `scan_seconds` for each policy a pass scans, and that
the smallest lease that loads keeps nothing on a host.

**Decision needed.** Whether the settings check should count the least length of
a pass and scale with the tolerance, so that a lease which cannot keep a record
is refused as the guide says. That would refuse settings that load today (the
owner's `test_tolerance_is_refused_where_no_owned_lease_could_ever_carry` loads
`least + 1`), so this record does not propose it without his decision.

**Closing acceptance.** `DISCOVERY-LEASES`, method `application-connect`,
tier 5. With the chosen lease and tolerance, an accessory controller stays
connected while the guest's advertisement is missed by up to k − 1 consecutive
passes, and the record leaves the network once the guest stops advertising, no
later than its lease. It passes when both hold and the measured pass period is
within the P that the lease was chosen for.

## R-D8: an endpoint URL that names another guest-network address

**What an existing site does.** Section 3 records no behaviour of an existing
site for this case. What matters here is that an address of the guest network
cannot be reached from the LAN.

**What this repository does.** `project_records` passes every exported record
through `bonjour_owner.rewrite_endpoint_urls`, which returns the TXT of every
type other than `_home-assistant._tcp` unchanged. For that type it rewrites
`internal_url` and `base_url` to the LAN endpoint where the URL's host is the
guest's current address or its host name (in ASCII DNS case, #56). Every other
URL is published unchanged, also one that names another address of the guest
network: an earlier address of this guest, or another guest's. The guide: "For
`_home-assistant._tcp` only, `internal_url` and `base_url` values that point
exactly to the resolved guest hostname/address are projected to the reachable
LAN address and mapped port." The ledger for #56: "External and
credentials-bearing URLs remain unchanged."

**Evidence.** `test_r_d8_url_naming_another_guest_network_address_is_not_published`,
for an `internal_url` and a `base_url` naming `198.51.100.20` while the guest
holds `198.51.100.13`, through the real reader and a real scanner pass:
`pytest tests/test_readiness_discovery.py -k r_d8 --runxfail`. Today the
exported record's TXT holds the URL as the guest announced it.

**Proposed change.** In `rewrite_endpoint_urls`, with the scope's guest network
passed from `project_records`: an `internal_url` or `base_url` that is an http
or https URL without credentials, whose host is an IPv4 address inside the
scope's `guest_cidr` other than the guest's current address, is (A) left out of
the published TXT; or (B) rewritten to the LAN endpoint like the current
address, which is right only where the address is an earlier one of this guest,
and the repository cannot know that (another guest's address would send clients
to the wrong service); or (C) published as today, with a sentence in the guide.
External URLs, credentials-bearing URLs, host names other than the guest's own
and opaque TXT stay untouched in every option. We propose A. It changes the
published TXT for an unchanged input, so as a default it needs discovery digest
version 6 with version-5 authority refused; as an opt-in it is an owner setting
absent unless given. The test asserts the default and accepts A or B; under C it
is removed.

**Decision needed.** A, B or C, and default or setting.

**Closing acceptance.** `DISCOVERY-PUBLICATION`, method `application-connect`,
tier 5. A LAN application that reads the endpoint URL from the record (the
companion app of the announcing service) connects through the published record
while the guest's configured URL names an earlier guest-network address. It
passes when the application reaches the LAN endpoint and the TXT leads it
nowhere into the guest network, or, under C, when the operator has accepted the
URL as it is.

## R-D9: a guest interface absent for one pass

**What an existing site does.** It keeps the records and waits for the guest
interface to return.

**What this repository does.** `scan_pass` checks both interfaces of every scope
before any policy (`_interfaces`, through `bonjour_process.interface_index`:
`ifconfig` and the interface index). An interface that does not exist fails the
whole pass with `unavailable`. `serve` then writes a candidate without policies
and clears the miss memory. Neither `miss_tolerance` nor `failed_pass: "miss"`
applies: they cover a completed pass that misses a record and a read that did
not complete. The publisher collects its own proof every `poll_seconds`
(`collect_proof`, the same check); a collection that fails leaves it without
proof, and `publisher_tick` withdraws every owned registration
(`unknown / unobserved`, interface unconfirmed). That includes an export, whose
registrations use the LAN interface. The owner states the limit: the
[Bonjour guide](../bonjour-owner.md) ("A stalled scan, stale owner evidence,
failed interface check, ... withdraws owned registrations." and "a pass that
fails as a whole (an owner report or an interface check) ... forget as before")
and the [configuration guide](../configuration.md) ("An absent or unconfirmed
interface is cleanup-only, never a wildcard interface fallback."). What it
leaves out: a coordinator run while the publisher has no proof plans cleanups
(`publisher-unknown`) whose readback stays `unknown` for the endpoint's seven
seconds. The executor then records a failed journal, and every later run, also
after the interface has returned, is refused until an administrator
acknowledges it (R-D15).

**Evidence.** `test_r_d9_guest_interface_absent_for_one_pass_keeps_the_export`:
an export with leases of 600 seconds, a tolerance of three passes and
`failed_pass: "miss"`, through the real scanner process (`serve`), the real
interface check against a fake `ifconfig`, and the publisher's own proof
collection: `pytest tests/test_readiness_discovery.py -k r_d9 --runxfail`. After
one pass without the guest interface, the pass writes the reason `unavailable`
and no export records, and the publisher reads `unknown / unobserved` and has
closed the registration.

**Proposed change.** Under `failed_pass: "miss"` or a key of its own (absent:
today's behaviour). (1) Scanner: `_interfaces` reports, per scope, a guest
interface that does not exist (`ifconfig`'s status and message for a missing
interface; an interface with another address stays `identity-mismatch`) instead
of failing the pass. `scan_pass` counts that pass as a failed pass for the
scope's export policies (`carried_through`, with a `tolerated_failure` value
such as `unavailable` that `lease_records` then accepts), and scans the scope's
import policies as usual, since their source is the LAN interface. (2)
Publisher: `collect_proof` keeps such a scope with its LAN index alone;
`publisher_tick` keeps the scope's export registrations, which use the LAN
interface, for as long as the candidate lists them, and withdraws its import
registrations, which cannot exist without the guest interface, until it
returns. The tolerance and the lease bound how long anything stays: at most
k − 1 passes, never past `max_age_seconds`, and a new network generation forgets
at once. A coordinator run while the interface is absent still meets the
import's `unknown` readback, which needs R-D15's proposal (b).

**Decision needed.** Whether an absent guest interface may count as a miss at
all, since it may also mean that the guest network is gone for good (its
runtime stopped, the network removed). With the change, the records of a network
that does not return stay for at most k − 1 passes and never past their lease.
And under which key.

**Closing acceptance.** `DISCOVERY-PUBLICATION` and `DISCOVERY-LEASES`, method
`application-connect`, tier 5; tier 3 lists interface absence among its native
cases ([testing](../testing.md)). Remove the guest network's interface for less
than one pass interval while an accessory controller is connected to an exported
service. It passes when the record stays on the LAN and the controller keeps or
regains its connection without a new coordinator request, and when a guest
network that does not return is withdrawn within the tolerance and the lease.

## R-D10: after a guest restart the records wait for the coordinator

**What an existing site does.** After a guest restart it publishes the guest's
records again by itself once it reads them.

**What this repository does.** The coordinator's request names the service
generation it was planned for, and `lease_records` refuses a request or a
candidate for another generation than the publisher's fresh proof. A guest
restart changes that generation (`apple_runtime` digests the start time with
the configuration, network and address). The publisher withdraws at its next
proof (it collects one every `poll_seconds`) and reads `unknown / unobserved`,
although the scanner reads the guest again under the new generation at its next
pass. What follows depends on which comes first, the publisher's next proof or
the coordinator's next run, a race that only a host decides:

- Where the publisher has seen the restart, the coordinator's next run plans a
  cleanup (`publisher-unknown`), the publisher confirms it under the new
  generation, and only the run after that plans `ready` and requests the new
  generation. The owner protocol states the rule (quoted in the introduction),
  and `test_retired_publisher_generation_requires_cleanup_before_reactivation`
  pins the two cycles. It does not state what this costs after a restart: the
  records return with the second run, that is, with runs 10 seconds apart, 10 to
  20 seconds after the restart, plus up to 7 seconds of the endpoint's wait in
  each run, and not before the scanner's first pass under the new generation
  (a rest of 5 seconds and the pass, whose budget is 119 seconds for the example
  policy). An import also waits until the root forwarding owner reports its UDP
  return verified for the new generation.
- Where the coordinator reads the restart before the publisher's next proof, it
  plans the cleanup from `publisher-generation-changed`, and the publisher
  confirms the absence under the older generation. The endpoint returns that at
  once, since it compares no generation for an inactive request, and the
  executor, which compares the service generation for inactive decisions too,
  raises "publisher failed complete scoped lease readback". The journal is
  `failed`, and every later run is refused until an administrator acknowledges
  it (R-D15).

The activation that the second run of the first branch requests also fails the
journal when the scanner has not yet written a candidate for the new generation
(R-D15). A change that lets the coordinator activate sooner must therefore not
activate before that candidate exists.

**Evidence.** `test_r_d10_guest_restart_is_activated_by_the_next_coordinator_run`:
the export is published, the guest restarts at the same address, the scanner
reads it under the new generation, and the publisher makes one turn. The
coordinator's decision is then computed with `planner.plan` and `plan_discovery`:
`pytest tests/test_readiness_discovery.py -k r_d10 --runxfail`. Today the
publisher reads `unknown / unobserved` with no records, and the coordinator
plans `publisher-unknown`, a cleanup. A set-up check shows that every other gate
is verified for the new generation: with the publisher's confirmed absence the
same decision would be `ready`.

**Proposed change.** (1) Publisher: where the only fence a policy fails is that
its active request names an earlier service generation than the publisher's own
proof, and the scanner's candidate already names the proof's generation,
withdraw and read `absent / confirmed-absent` with the proof's generation
instead of `unknown / unobserved`. That is the "later complete observation" of
the protocol's rule, so the coordinator's next run plans `ready`. (2) Optional:
`plan_discovery` plans `ready` instead of a cleanup where the publisher still
reads the older service generation. Alternative: an active request survives a
change of the service generation alone (`lease_records` keeps comparing the
policy digest and the network generation, and takes the service generation from
the candidate and the proof), so the publisher leases the scanner's next
candidate without any coordinator run. In every variant the request stays bound
to its policy, digest and network generation. Each variant changes what the
owner reports or leases for an unchanged input, so it is the owner's decision
whether it becomes the default or an owner setting (absent: today's
behaviour); the test asserts the default and accepts (1) or the alternative.
None of them closes the second branch: there the cleanup confirmed under the
older generation fails the journal, and with (2) the activation does instead,
since the publisher's older proof answers it `unknown`. That needs R-D15's
proposal (b).

**Decision needed.** Whether the coordinator's approval stays bound to one
service generation (1, with or without 2) or to the policy and network
generation (the alternative), and default or setting.

**Closing acceptance.** `DISCOVERY-PUBLICATION` and `DISCOVERY-LEASES`, method
`application-connect`, tier 5; a guest restart is also a tier 4 lifecycle case.
Restart the guest that announces an exported service while an accessory
controller is connected, and measure the time from the guest's start to the
record's return on the LAN and to the controller's reconnection. Since the
branch is a race, force each order once (a coordinator run before and after the
publisher's next proof) or repeat the restart a number of times stated in
advance. It passes when the record returns within the bound the owner sets
(with the change, one coordinator run or the scanner's next pass) and the
coordinator's journal stays committed every time.

## R-D11: an import independent of the return path (reference)

Recorded by the owner: [configuration](../configuration.md), "Discovery
strategies" (`return_path`); the [Bonjour guide](../bonjour-owner.md) ("A
verified UDP-return dependency is required by the canonical import policy,
unless its entry says `"return_path": "independent"`"); [migration
readiness](../migration-readiness.md), "Known extraction gaps"; the ledger for
#64. What the text leaves out: nothing about the mechanism. It follows that while
another packet-filter owner keeps the return path, nothing in this repository
observes that path, and an independent import keeps publishing receivers while
the path is down.

## R-D12: projected host names (reference)

Recorded by the owner: [site-requirements review](2026-10-08-site-requirements-review.md),
item 3; the ledger for #73 ("Does not preserve exact legacy hostname suffix
algorithm/length; exact-name conformance remains unresolved."); the closure
record, "Discovery selection and names". What the text leaves out is what the
suffix is computed from (`bonjour_owner.project_records`): the first 16
hexadecimal digits of a digest of the policy id, instance name and type for an
export, and of the source host, address, instance name and type for an import.
An extraction has to compare exactly that with the predecessor's algorithm. An
import's projected name changes with the receiver's address, and an export's
with the policy id.

## R-D13: a runtime read longer than eight seconds (reference)

Recorded by the owner: [Apple runtime](../apple-runtime.md), the paragraph that
begins "The owner endpoint (`request`) does not take the bound" and ends
"Closing that needs the owner protocol's ten seconds to become a setting of
their own, which this setting is not." What the text leaves out: it describes a
fleet whose reads are always slow. One read above eight seconds has the same
effect for one pass of the discovery owner. Its scanner skips the dependent
policies and forgets their miss memory (the Bonjour guide states that for "a
pass skipped because its dependencies were not ready"), and its publisher
withdraws their records, whatever the tolerance. If the owner protocol's ten
seconds become a setting, as that paragraph says closing needs, `pass_budget`
has to follow: it counts those ten seconds (`_OWNER_READ_LIMIT`) for each other
owner's report, and the lease of R-D7 grows by twice each added second for each
other owner.

## R-D14: a coordinator run in a renewal gap withdraws the whole policy

**What an existing site does.** Section 3 records nothing for this case; the
finding came up while checking R-D6. We do not know how an existing site's
discovery renews its registrations.

**What this repository does.** Without `renewal_overlap_seconds`, a record is
not registered between its client's end on its own timer and its replacement's
confirmation, at least every two minutes (R-D6), for at most the five-second
confirmation limit. During that gap the policy reads `unknown / unobserved`
([Bonjour guide](../bonjour-owner.md): "During an unconfirmed replacement the
policy reads `unknown / unobserved`, even if siblings are still registered.";
`test_no_current_registration_is_not_verified_during_renewal`). A coordinator
run that reads the policy in that gap plans a cleanup (`plan_discovery`,
`publisher-unknown`). The executor sends the inactive request, the publisher
withdraws every record of the policy, siblings included, and only the next run,
at least 10 seconds later, plans `ready` and requests them again. For each
renewal, a run falls into a gap of g seconds with a chance of about g divided by
the coordinator's interval; how long the gap lasts on a host is not measured.

**Evidence.** `test_r_d14_coordinator_run_in_a_renewal_gap_keeps_the_sibling_record`:
two confirmed records of the import; one client ends on its own timer and the
publisher starts its replacement; a coordinator run (the real planner and
executor, the discovery owner's real endpoint, the publisher turning while the
endpoint waits) falls into that turn:
`pytest tests/test_readiness_discovery.py -k r_d14 --runxfail`. Today the run
plans `publisher-unknown` (inactive), ends `inhibited`, and the sibling record's
client is closed. A set-up check requires that the policy reads `unknown` during
the gap, as the owner's amendment of #43 requires.

**Proposed change.** The publisher names the gap without claiming the record.
Its observation during an unconfirmed replacement stays `unknown / unobserved`
and carries a member such as `renewing`, the number of records between two
clients, left out while there is none (as `tolerated_failure` is). Where the
readback names a renewal and its digest, interface and generations are current,
`plan_discovery` plans no cleanup: preferably a decision of its own (a new
reason in the closed `DISCOVERY_REASONS`, active) for which the executor sends
nothing, since the owner already holds the active request. Planning `ready`
instead would send that request again and wait for `present`, and a replacement
that fails then runs into R-D15. This is an exception to the owner protocol's
sentence that unknown evidence requests cleanup (quoted in the introduction), so
that sentence changes with it. We do not propose reporting `present` during an
unconfirmed renewal: the owner rejected that in his amendment of #43 (ledger:
"reject the proposal to claim present/verified while every current registration
is unconfirmed"). The remedy that needs no change is `renewal_overlap_seconds`:
a replacement that confirms before its predecessor ends leaves no gap. The guide
keeps the overlap's native effect (no goodbye when the first client ends) a
capture still to make. Minimal implementations of both variants, the decision of
its own and `ready`, turned the test into `XPASS(strict)` in a throwaway copy.

**Decision needed.** Whether the coordinator may skip the cleanup for a renewal
gap that the publisher names (a readback member and a planner rule, so a
behaviour change for an unchanged input: default or setting), or whether
`renewal_overlap_seconds` becomes the recommended setting, or both.

**Closing acceptance.** `DISCOVERY-LEASES`, method `application-connect`,
tier 5. Over a period of many renewals, an accessory controller stays connected
to an exported service. It passes when no coordinator run withdraws a policy
during a renewal (none of the coordinator's journals shows a cleanup of a
policy that was present before) and the controller never loses the accessory.
With the overlap setting, the capture that the guide names applies too.

## R-D15: an unexpected discovery readback leaves a failed journal

**What an existing site does.** Section 3 records nothing for this case; the
finding came up while checking R-D10.

**What this repository does.** The executor compares each discovery readback
that the endpoint returns within its seven seconds with the decision
(`executor.execute`): the state it asked for, the policy digest, a confirmed
interface for an activation, and the service and network generation, for a
cleanup too. Any difference raises "publisher failed complete scoped lease
readback" and records the journal `failed`; every later run then raises
"unfinished journal needs explicit phase-aware operator recovery" until an
administrator runs `acknowledge-journal`. Three sources give such a readback
although no write is in doubt:

1. An activation that the coordinator plans before the scanner has written a
   candidate for the current generation, after a cold start or after R-D10's
   cleanup. The publisher reads the policy `absent / confirmed-absent` whether
   or not such a candidate exists, and answers the active request with
   `unknown / unobserved` (`lease_records` refuses the missing or older
   candidate). Nothing was registered; once the candidate exists, the publisher
   registers the record for the request it holds while the journal reads
   `failed`, as the first test below shows.
2. A cleanup while the publisher has no proof: after a boot until its first
   proof collection ends, and while a collection fails, as for R-D9's absent
   interface. The publisher reads every policy `unknown`, also after the
   inactive request; it has withdrawn whatever it held.
3. A cleanup that the coordinator plans from a guest restart which the
   publisher's proof has not yet seen (R-D10). The publisher confirms the
   absence under the older service generation, and the endpoint returns that at
   once: its wait (`bonjour_owner.endpoint`) compares no generation for an
   inactive request, while the executor compares the service generation for
   every decision. No test in this file expresses this source.

Whether a coordinator run falls into one of these windows depends on the order
in which the jobs start, on the guest's start, on the root owner's report and on
the length of a pass: it is a race that only a host shows, and the tests fix the
order by construction. The owner protocol states the journal rule (quoted in the
introduction), and `test_lying_discovery_readback_preserves_failed_journal` pins
it for an `unknown` readback; neither names these sources.

**Evidence.** Two tests run the real planner and executor against the discovery
owner's real endpoint, with the publisher turning on the fake clock while the
endpoint waits, so the seven seconds pass on that clock and no test sleeps:
`pytest tests/test_readiness_discovery.py -k r_d15 --runxfail`.

- `test_r_d15_activation_before_the_first_candidate_does_not_block_the_coordinator`
  (source 1): a cold start with the guest's record on the guest network, then
  two coordinator runs with the scanner's first pass between them. Today "the
  first run ends 'raised: publisher failed complete scoped lease readback' with
  the journal 'failed'; after the scanner's pass the publisher reads present /
  verified; the next run ends 'raised: unfinished journal needs explicit
  phase-aware operator recovery'".
- `test_r_d15_cleanup_while_the_publisher_has_no_proof_does_not_block_the_coordinator`
  (source 2): the export is published and a run commits; then a run while the
  publisher turns without proof, and a run after the proof has returned. Today
  "the run without proof ends 'raised: publisher failed complete scoped lease
  readback' with the journal 'failed'; the run after the proof returned ends
  'raised: unfinished journal needs explicit phase-aware operator recovery'".

**Proposed change.** (b) The executor records a discovery decision whose
readback is `unknown`, or names another service or network generation than the
decision, as pending (`waiting-external-owner`), never as a write in doubt; the
next run plans again from fresh evidence. The owner protocol gives the reason
itself: "Every long-lived publisher must independently enforce lease age and
dependency validity between coordinator calls". A discovery registration in
doubt therefore ends by itself within its lease, unlike a root packet rule,
which stays loaded until it is withdrawn. A readback that is stale or from the
future is read as `unknown` (`Observation.at`) and is pending too; another
digest, an unconfirmed interface after an activation and a state other than the
requested one, with current generations, still fail the journal. This is an
exception to the owner protocol's sentence "Returned unknown or mismatched
readback stops subsequent writes and records a failed journal.", so that
sentence changes with it, and so do five cases of
`test_lying_discovery_readback_preserves_failed_journal` (`unknown`, `stale`,
`future`, `service-generation`, `network-generation`); its other three keep
failing. (a), a narrower alternative for source 1 only: the planner plans an
activation only where the publisher shows a current candidate. Its
confirmed-absence readback says so, for example with a member
`candidate_current` that is left out while it holds one, and the planner
otherwise plans an inactive decision of its own that the executor finds
complete. (a) does not close sources 2 and 3: under (a) alone the second test
stays an expected failure. A variant of (a) in which the publisher reads a
policy without a current candidate as `unknown / unobserved` does not close
even source 1, because the cleanup that `unknown` plans is itself checked for
`absent` and fails the journal the same way. In a throwaway copy a minimal (b)
turned both tests into `XPASS(strict)` and a minimal (a) the first only. Both
keep fail closed: the publisher registers nothing without a current candidate
and fresh proof.

**Decision needed.** (b), with or without (a) for source 1. We count this as a
defect, since the coordinator stops although no write is in doubt, so the change
would be the default; the owner decides whether he agrees.

**Closing acceptance.** `BOOT-RECOVERY`, method `unattended-reboot`, tier 4.
One clean reboot does not show it, because the order is a race. Either force the
order (start the discovery job only after the coordinator's first run, which
puts that run before the publisher's first proof and the scanner's first pass),
or repeat the unattended reboot a number of times stated in advance, for example
ten. After
each reboot, read the coordinator's journal after every run until every
discovery policy reads `present`. It passes when no journal ends `failed` and
discovery returns without an administrator's acknowledgement every time. Sources
2 and 3 have the same criterion for a guest interface that goes away for less
than a pass (tier 3) and for a guest restart (tier 4), each with a coordinator
run forced into the window.

# Readiness record: the UDP return path (R-U1 to R-U7)

Checked on 9 October 2026 against `main` at `de4cbb5` (release 0.4.2). A readiness check
compared the root PF owner's UDP return pair, and the state handling around it, with how an
existing site runs the same path. This record states the seven findings of that area. It
changes no production code, no schema and no guide.

Where a finding can be expressed against the code,
[`tests/test_readiness_udp_return.py`](../../tests/test_readiness_udp_return.py) holds one test
marked `xfail(strict=True, raises=AssertionError)` that asserts the proposed behaviour. Run
with `--runxfail`, its assertion message shows what the code does today. Once the change is
implemented the test passes, the strict marker reports that as a failure, and the change
removes the marker. Only an assertion about the finding raises `AssertionError`: a set-up step
that does not hold, and a consistency check inside a fake, fail the test through `pytest.fail`,
so that neither can count as the expected failure. Where a proposal is an installation
decision, the test writes the decision under the name proposed here. The installation of
`de4cbb5` refuses a key it does not know as an unsupported schema; the test then measures the
default installation, which is the behaviour the finding names. Any other refusal fails the
test.

The tests prove what the owner's code does, with the existing suites' fakes, for the inputs
they name: the plan, the backend calls, the records, the journal and the report. They do not
prove what a macOS state table prints, which states `pfctl -k` ends, which host ports the
vendor's translation uses, or anything about packets or audio. Each such statement below is
marked as a capture or as native acceptance. Addresses are documentation values; the port
range is the one of `examples/network.json`.

| ID | Kind | Test |
|---|---|---|
| R-U1 | flag, decision | `test_r_u1_a_read_that_timed_out_withdraws_the_pair_and_invalidates_no_state` |
| R-U2 | flag | `test_r_u2_a_failed_invalidation_of_the_pair_leaves_the_other_services_loaded` |
| R-U3 | flag | `test_r_u3_a_loaded_pair_is_not_ready_once_a_check_of_its_activation_fails` (two cases) |
| R-U4 | flag | `test_r_u4_the_pair_follows_its_guest_while_another_guest_holds_the_old_address` |
| R-U5 | flag, capture | none |
| R-U6 | reference, acceptance | none |
| R-U7 | flag, capture | `test_r_u7_a_zoned_link_local_row_is_foreign_and_the_rest_of_the_table_is_read` |

## R-U1: a retirement on missing evidence invalidates by address

**What an existing site does.** It invalidates states only for a planned stop.

**What this repository does.** On the first pass whose read of a service runs out of time, the
planner retires that service's rules (`src/netorch/planner.py`, `_profile_plan`, reason
`endpoint-unknown`; `snapshot-stale` and `network-unknown` behave alike), and `_retire` plans a
withdrawal and a drain. `reconcile` withdraws the rules, then carries out the drain through
`_own_states_gone`: when `retained_states` finds one state of the record, it issues
`backend.drain(target)`, which is the backend script's `drain`, `pfctl -k <target>` and
`pfctl -k 0.0.0.0/0 -k <target>`. That ends the states from and to the guest's address, the
guest's own connections among them, not only the states of the withdrawn rule. The owner guide
states it ("While a retained state of a withdrawn rule exists, invalidate states from and to the
exact old guest address and read back that none is left", "Reconciliation and failure
semantics", step 7), and so does `docs/safety-contract.md` ("unknown retires immediately",
"states from and to the old address are invalidated", row "Bounded guest identity"). The reason
is given under "Host paths while runtime evidence is unknown": "For a rule that names a guest
address this is the point: the address may belong to another guest by now." The decision
`"runtime_unknown": "keep-host-paths"` keeps only rules that end at the host's own address. The
guide's sentence under "Retained states" that a retirement does not reset a guest's own
connections holds only while no state of the rule is listed; its correction is a separate
change.

**Evidence.** `test_r_u1_a_read_that_timed_out_withdraws_the_pair_and_invalidates_no_state`;
`pytest tests/test_readiness_udp_return.py -k r_u1 --runxfail`. The test gives the pair an
`unknown_limit` (K) of 2, which the owner does not read today, so that the bound proposed below
can be seen. The pair is loaded, and the state table lists one state of the pair and two TCP
connections of the media guest through the vendor's translation. The guest's read times out
once (`unknown`, `timed-out`), so the plan's only reason is `endpoint-unknown`. Today: "one
runtime read that timed out retired the pair and invalidated the states from and to the guest's
address: changed ['media-udp:withdraw', 'media-udp:drain'], addresses invalidated
['198.51.100.12'], states left []". The fake ends every row that names the address; which rows a
real kernel ends is native evidence. The test then requires that the pair returns without an
invalidation when the same guest is observed again, and that of two passes in a row without
evidence the second invalidates, so that a change without the bound does not pass.

**Proposed change.** An installation decision `"drain_on_unknown": "defer"` in
`installation.json`, written and bound like the four existing decisions: the only value that
can be written, left out of the stored form while absent so that stored installations keep their
bytes, part of `admitted_digest` so that choosing it or taking it back voids every admission of
the owner, and shown by `review-admission` and `admit`. Absent, nothing changes. With it:

1. In `reconcile`, where the host-path candidates are settled (before the first action, from the
   plan and its snapshot; nothing is read), a profile whose rules name a guest address
   (`udp-return`, and `guest-direct` in its direct form) and whose withdrawal the plan has only
   because evidence is missing is withdrawn as today. Its planned drain is not carried out,
   unless this is the K-th pass in a row without evidence, K being the profile's admitted
   `unknown_limit`: that pass invalidates as today. The condition on the withdrawal is the
   predicate `_evidence_missing` that the host-path decision already uses: the read of the
   service ran out of time, or present evidence is merely too old. With `unknown_limit: 1`, the
   minimum and the value of every profile in `examples/network.json`, nothing waits.
2. Its record stays, withdrawn, with one new member, `"drain_deferred"`: the number of passes in
   a row that kept its states, left out while there is none, so that every stored record keeps
   its bytes. The profile is reported deferred with a new reason, `states-kept`, in the journal,
   the result and the report.
3. The planner (`_profile_plan`, the branch for an absent record) activates such a record's own
   target again, without an invalidation, on the first pass whose fresh evidence names the same
   target address, target generation, network generation and strategy. Everything else
   invalidates as today: another generation or address, evidence that states a fact
   (`unavailable`, `inaccessible`, a mismatch), a pause, a suspension, a hold, a removed or
   changed profile.

The rules are still withdrawn at the first unknown; only the invalidation waits, for at most
K - 1 passes. The price: while it waits, the states that the withdrawn rules made go on
translating their flows to the old address. If the guest is in fact gone and its address is
dealt to another guest (the repository's model of the vendor's allocator reuses a released
address after the rest of the pool, and re-deals it at once when a new helper rebuilds the
pool; `docs/safety-contract.md`, "Versioned synthetic allocator contract"), the packets of those
flows reach that guest until evidence returns or the K-th pass invalidates them. That is the
address-reuse residual that every bounded profile states, extended from the observation race of
one pass to K passes: in the conditional window of `docs/safety-contract.md` ("T, K and the
withdrawal window"), the effective K of a guest's states becomes the admitted `unknown_limit`
instead of 1, while its rules keep an effective K of 1.

Texts and tests that change with it: the guide's deferral table and
`tests/test_pf_deferral.py::test_deferral_reasons_are_one_closed_vocabulary` (the new reason);
in `docs/safety-contract.md`, the row "Bounded guest identity" ("unknown retires immediately";
"states from and to the old address are invalidated and the profile stays retired until a
readback shows none") and the section "T, K and the withdrawal window" ("The report exposes both
values; it does not add a delayed-withdrawal algorithm."); in the owner guide, the sentence
"For a rule that names a guest address this is the point: the address may belong to another
guest by now."; and the two definitions of `unknown_limit`: "`unknown_limit` is an existing
reader's maximum bounded retry contract, not a permission to keep a stale target."
(`docs/configuration.md`) and "`unknown_limit` is the maximum retry tolerance permitted to an
independent owner, rather than a promise that this planner retains an exposure for that many
passes." (`docs/state-machine.md`).

**Decision needed.** Availability against that residual: whether an installation may keep the
states of a guest whose identity is merely unknown, for at most K - 1 passes; for `udp-return`
only, or for `guest-direct` as well; and whether a bounded profile's risk statement, which its
admission binds, must then say so (the statements of `examples/network.json` answer stale
identity with rule withdrawal and state invalidation).

**Closing acceptance.** `BOUNDED-IDENTITY`, method `state-drain` (tier 3), on a real host with
the decision admitted for a profile with an `unknown_limit` of at least 2, the pair loaded, a
guest flow through it, and one connection of the guest to a host outside the LAN. Make the read
of the runtime run out of time for one pass, and later for K passes in a row (how to cause that
without another effect is part of the acceptance plan). Capture the state table
(`pfctl -s states`) before and after each pass, and packets on the LAN interface and on the
guest's interface. Passes when the pair's rules are gone after the first such pass, the guest's
state rows are unchanged by every pass before the K-th, the guest's own connection carries
traffic until then, the pass with evidence loads the pair again without an invalidation, and the
K-th pass in a row without evidence leaves no state of the old address. Then `UDP-FIRST-PACKET`,
method `first-packet` (tier 3), for the reloaded pair: a first outbound request and its reply
keep the source port inside the range.

## R-U2: one failed invalidation withdraws every service until acknowledged

**What an existing site does.** It withdraws only the workload concerned.

**What this repository does.** An invalidation that fails, or a state table that cannot be read
before or after it, raises in `_own_states_gone`; `reconcile` records its journal `failed` and
raises. Every later pass finds `failed`, owes an acknowledgement and marks its intent damaged
(`intent = replace(intent, damaged=True)`), so the planner retires every profile of the owner
(reason `intent-damaged`) and nothing is activated until `acknowledge-journal`. The guide states
the failure and the acknowledgement: under "Retained states", "An invalidation that fails and a
table that cannot be read, before or after it, are errors and not an open drain: they end the
pass `failed`"; under "Deferral and writes in doubt", "The acknowledgement exists for one
situation: the kernel may hold something other than what the owner's records say", with "an
invalidation of the states of a withdrawn rule that fails" among the cases; and, for the
host-path judgement, "the next pass owes an acknowledgement and retires every rule". It does not
say that one address's failed invalidation takes every other service off the network, DNS and
the web redirect included, although their rules were read back exactly and their states are not
in doubt. In this release `acknowledge-journal`, like `reconcile`, exits 78 at the mutation gate
before it reads anything (`docs/safety-contract.md`: acknowledging an interrupted activation
journal is "Blocked"); both pass `require_mutation_qualified("privileged-owner-mutation")`, so a
release that qualifies one qualifies both.

**Evidence.** `test_r_u2_a_failed_invalidation_of_the_pair_leaves_the_other_services_loaded`;
`pytest tests/test_readiness_udp_return.py -k r_u2 --runxfail`. All four profiles are loaded; the
media guest restarts at another address while a state of the pair is listed; the invalidation of
the old address fails once; then every read and the invalidation work. Today: "one failed
invalidation of the pair's old address (journal failed), then three passes whose reads all work,
(phase, rules loaded): [('failed', []), ('failed', []), ('failed', [])]". The test looks at three
passes, so that a change that keeps the owed profiles in one journal record only, and loses them
with the next, does not pass.

**Proposed change.** An installation decision `"failed_invalidation": "hold-address"`, written
and bound like the others. With it, an exception from `_own_states_gone` no longer damages the
intent of later passes. The pass names the profiles whose records name the address of that
invalidation (`"owed": [...]`) and ends `failed` as today; every journal record of the passes
that follow names them again, until `acknowledge-journal` ends the record as it does today. A
pass that finds such a record plans every other profile as usual. The named profiles are retired
and their old address is invalidated again on each pass, and nothing is activated for them until
the acknowledgement. Every other write in doubt keeps the acknowledgement for the whole owner,
because there the kernel's rules may differ from the records: a load or readback that differs, a
candidate or record that cannot be written, a reference that cannot be identified, a table that
cannot be read when a pass starts.

**Decision needed.** Whether an acknowledgement may be owed for one address, and whether that is
an installation decision as proposed or the default. The guide's own statement of what the
acknowledgement is for would support the default: only the states of that address are in
doubt.

**Closing acceptance.** `BOUNDED-IDENTITY`, method `state-drain` (tier 3). A failed invalidation
cannot be caused on a real host without injecting a fault into the tool; the test above is the
evidence for the owner's logic. The native acceptance remains the successful invalidation that
the registry already requires: both directions, read back, and no state left for a reallocated
non-target guest.

## R-U3: the host-socket and route/ARP checks run only at activation

**What an existing site does.** It re-checks every ten seconds.

**What this repository does.** `reconcile` calls `backend.endpoint(..., direct=True)` (the
interface and its prefix, forwarding, the route to the guest over a bridge, and the neighbour
entry against the observed hardware address) and `backend.ports_clear(...)` (the host's own
socket inventory over the profile's ports) for an `activate` action only. A loaded pair is a
`noop` on later passes, and neither check runs for it again; `root_ready` requires the approval,
an unblocked intent, a verified plan, the enable reference, and no deferral or withholding. The
guide: "Immediately before each activation, reread durable gates, desired content, approvals and
fresh runtime evidence. Verify current LAN interface/address, forwarding, route/ARP for direct
guest targets and host socket coexistence." ("Reconciliation and failure semantics", step 5),
and "Host port conflicts are blocked from complete numeric Darwin socket inventory." ("DNS
coexistence"). Neither says that a loaded rule is not checked again.

What a healthy pass already reads on `de4cbb5`, counted with the fakes for the example policy:
the owned anchor twice (`inspect`), the state table twice, the boot session once, the enable
reference once (`references`, `enabled`) and the runtime twice. The route and neighbour check
runs on every pass only for a `guest-direct` profile with a fallback publication, where it
decides `direct_available`: once for each such profile in each snapshot the pass takes (four
calls in a healthy pass with the two DNS profiles of `tests/test_pf_owner.py`'s fallback
fixture). A pair has no fallback, so for a pair it never runs again.

**Evidence.** `test_r_u3_a_loaded_pair_is_not_ready_once_a_check_of_its_activation_fails`, cases
`host-socket` and `route-arp`; `pytest tests/test_readiness_udp_return.py -k r_u3 --runxfail`.
The test first requires that the pair is loaded for its guest and ready; then the fake's socket
check reports a host socket in the range, or the fake's route and neighbour check stops verifying
the guest's address, while a state of the pair is listed. Today, for both: "the pass ended
committed, the pair is loaded for 198.51.100.12 and root_ready is True (withheld None, deferred
None)".

**Proposed change.** An installation decision `"loaded_checks": "every-pass"`, written and bound
like the others. With it, every pass that leaves a rule loaded whose target is a guest
(`udp-return`, and `guest-direct` in its direct form) repeats both checks before its first
action, beside the reads of the host-path judgement: `ports_clear` for the profile (one socket
inventory per protocol and pass, shared by all such rules) and `endpoint(..., direct=True)` for
the record's target with the hardware address of the pass's observation. The two outcomes
differ:

- A host socket in the range, or a socket inventory that cannot be read, withholds the rule: it
  stays loaded and unchanged with its states, it is not `root_ready`, its published data carries
  `withheld: ports-unverified` (the withholding vocabulary gains this word, which is a deferral
  reason already), and the pass ends `inhibited`. The first pass whose check passes reports it
  ready again. A host socket in the range is a coexistence fault; it does not send a guest's
  packets to another host.
- A route or neighbour check that does not pass, or cannot be read, retires the rule in that
  pass: it is withdrawn with the planned withdrawals and its states are invalidated, as at a
  retirement, and the profile is reported deferred with `endpoint-unverified`, as its activation
  is while the check fails. The check also fails when the neighbour entry names another hardware
  address than the one observed, a sign that the guest's address now leads to another host;
  withholding would leave the pair delivering to it.

Cost per pass: one `netstat -anlv -W -p udp` (two-second bound) and, per target, `ifconfig`, the
`sysctl` read of IP forwarding, `route -n get -inet` and `arp -n` (two seconds each). Texts and
tests that change with it: the guide's deferral table, whose reasons describe what a pass found
before it wrote anything for the profile, and the two tests that pin the withholding
vocabulary, `tests/test_pf_translation_order.py::test_withholding_reasons_are_a_second_closed_vocabulary`
and `tests/test_pf_host_paths_on_unknown_runtime.py::test_the_reasons_that_keep_are_two_closed_lists`.

**Decision needed.** Whether to re-check at all, and on every pass or on every Nth pass.

**Closing acceptance.** `COEXISTENCE`, method `rule-readback` (tier 2), for the host socket, on a
real host with the decision admitted and the pair loaded: in an authorized session, bind a UDP
socket on the host to one port inside the range, read the next report, remove the socket and
read the report after it. Passes when, within one pass interval, the pair is not `root_ready`
and carries `withheld: ports-unverified`, the rules and the state table are unchanged by that
pass, and readiness returns one pass after the socket is gone. A neighbour entry that names
another hardware address cannot be made on a real host without changing the guest network; the
test is the evidence for the owner's logic, and the invalidation that follows is the one that
`BOUNDED-IDENTITY` (`state-drain`) accepts.

## R-U4: the pair does not follow its guest while another guest uses the old address

**What an existing site does.** It invalidates states only for a planned stop (R-U1), so an
address change does not end another guest's states there.

**What this repository does.** After the guest's address changes, the plan withdraws the pair
and drains the old address. `retained_states` counts a row as a state of the pair when the row
has the profile's protocol, names the old address with a port inside the range, and names a LAN
peer; the host endpoint's port is not consulted. A flow of whichever guest now holds the old
address, from a port inside the range to a LAN host through the vendor's translation, meets all
three. Listed again after each invalidation, it defers the profile with `states-retained`; the
withdrawn record stays, the plan holds it at "drain only" and never activates the new address,
and every pass invalidates the states from and to the old address, which are now the other
guest's. The guide records the limit for the guest's own flows: "Nor can it tell a state of the
rule from a flow that the guest itself opens to a LAN peer from a port of the rule: for a UDP
return profile that is every flow from the published range to the LAN, also one that the
runtime's own translation carries after the rule is withdrawn", and "In these cases the
retirement stays `states-retained`, with an invalidation on each pass, for as long as such a
state is listed again when the table is read back" ("Retained states"); and "no replacement
target is activated for it while the state remains" ("Deferral and writes in doubt"). It leaves
out that the flow can be another guest's on the old address, that the pair then does not follow
its guest to the new address for as long as that flow lasts, and that every pass ends that
other guest's connections.

**Evidence.** `test_r_u4_the_pair_follows_its_guest_while_another_guest_holds_the_old_address`;
`pytest tests/test_readiness_udp_return.py -k r_u4 --runxfail`. The media guest restarts at
another address while a state of the pair is listed; another guest's flow on the old address is
listed again after every invalidation. Today: "the guest moved and another guest keeps a flow on
the old address: passes (phase, media deferral, pair target) [('inhibited', 'states-retained',
None), ('inhibited', 'states-retained', None), ('inhibited', 'states-retained', None)]; old
address invalidated 3 times". The test then moves the guest again while a row that the pair
itself can make (the same flow, with the same port on the guest and on the host) is listed
again at the address it left; there the pair must not follow, so that a change that follows the
guest whatever is still listed does not pass.

**Proposed change.** In `retained_states`, for a `udp-return` record only: a row that names the
scope's host address, never with a port with which it names the target, and that names a third
address, is a state of another translation and does not count. The rendered pair cannot make
such a row: its outbound translation keeps the source port (`static-port`) and its inbound
redirection names no target port, so that the destination port is kept; every state of the pair
therefore names the host with the guest's port. A row without the host's address, and a row
whose only other address is the host's, count as today; redirects, and records that the policy
no longer describes, keep today's rule. The old address is then invalidated once, while a state
of the pair is listed, and the pair is activated at the new address on the next pass. The change
rests on how a real table prints the pair's states (see the acceptance below); until that is
captured, it is a proposal and not a default. Two existing tests state today's rule and change
with it: in `tests/test_pf_own_states.py`, the case "return profile: a flow another translation
carries" of `test_a_guests_own_flow_to_a_lan_peer_from_a_port_of_the_rule_is_not_told_apart` (it
is inverted), and `test_a_state_of_a_rule_is_retained_whichever_address_of_the_lan_prefix_is_its_peer`,
whose media rows put the first port of the range on the host for every guest port, a row that
the pair's rules never make. The guide's paragraph "Two limits are known" changes with them.

**Decision needed.** Whether the rule may rest on the pair's port mapping once captured. And
what may hold back the activation at a new address: today, any row that counts, for as long as
it is listed. A bound in passes, after which the pair is activated at the new address and the
old states are left to expire, is not proposed: it would load the pair while states that may be
its own still translate to the old address.

**Closing acceptance.** `BOUNDED-IDENTITY`, method `state-drain` (tier 3), and
`UDP-FIRST-PACKET`, method `first-packet` (tier 3). On a real host with the pair loaded, capture
the state table while a guest sends through the pair and a receiver answers: passes when every
row of the pair names the host with the guest's port, in both directions. With the pair
withdrawn, capture the row of a flow that the guest opens from a port of the range through the
vendor's translation, and record the host port it names. Then, in an authorized session, give
the guest another address while another guest holds the old one: passes when the old address is
invalidated at most once and the first packet from the new address keeps its source port.

## R-U5: fixed AirPlay 2 ports outside the range are not covered

**What an existing site does.** Its pair covers the guest's automatic range only; it does not
forward fixed ports outside that range either.

**What this repository does.** A `udp-return` profile must equal its service's automatic port
range (`src/netorch/config.py`, `_check_profiles`: "UDP return must equal the guest automatic
port range"), and `render_profile` renders that range only. The guide: "The range must exactly
match the service's automatic socket range. Never widen it to mask capacity problems."
("Structural versus bounded profiles"). Nothing renders or checks a fixed port outside the
range. A public reference implementation shows that AirPlay 2 timing uses such ports: nqptp,
the timing companion of the open-source AirPlay 2 receiver Shairport Sync, monitors PTP
"clocks it sees on ports 319 and 320", "provides timing information for AirPlay 2 operation",
and asks a host with a firewall to "ensure that ports 319 and 320 are open for UDP traffic in
both directions" ([README at tag 1.2.6](https://github.com/mikebrady/nqptp/blob/1.2.6/README.md)).
That implementation is a receiver; what a sender needs is not stated there.

**Evidence.** No test: whether a sender in a guest needs such ports across the translation is a
property of the protocol and of the receivers, not of this code, and it is not captured.

**Proposed change.** First the capture, read-only, on a real host: during playback from a sender
in a guest to one receiver and to several, capture UDP on the LAN interface and on the guest's
interface (`tcpdump -n -i <interface> udp`), and record every UDP port outside the range that
the sender and the receivers use towards each other; in particular whether packets for ports 319
and 320 are sent to the guest's address or to the host's, and whether they arrive. If none is
needed across the translation, this entry closes. If some are, a pair for fixed ports cannot be
declared today. It would need a reviewed profile form for fixed UDP ports with its own admission,
the port-collision checks against the host's own sockets (the host may use such ports itself),
and the statement that a fixed host port maps to one guest only.

**Decision needed.** Whether the capture is made before the pair's acceptance.

**Closing acceptance.** `UDP-FIRST-PACKET`, method `first-packet` (tier 3); `PORT-BUDGET`, method
`port-budget` (tier 3); `MULTI-RECEIVER`, method `port-budget` (tier 5); `HEARD-AUDIO`, method
`heard-audio` (tier 5): the capture above, then audible playback to one receiver and to several.
A profile for fixed ports, if one is introduced, also needs `ROOT-HARD-BOUNDS`, method
`first-packet` (tier 3): a first packet through it, and none through a port it does not name.

## R-U6: the rendered pair and audible playback (reference)

The owner records it: [site-requirements review](2026-10-08-site-requirements-review.md),
"Remaining reference-installation conformance work", item 8: "first packet and reply" and
"video/audio" "remain separate acceptance gates. Historical audio confirmation does not accept a
new policy/release." What it leaves out: the split pair that `render_profile` writes (outbound
translation with `static-port`, inbound redirection without a target port;
`test_rule_renderer_static_port_and_targetless_rdr` and
`test_admitted_preview_splits_udp_static_nat_from_targetless_rdr`) has the form of an existing
site's own pair, and audible playback through that pair has not been confirmed at the existing
site either. There is no historical confirmation to compare with: `HEARD-AUDIO` (method
`heard-audio`, tier 5) needs a first confirmation for the exact policy and runtime, on both
sides.

## R-U7: a zoned IPv6 address makes the whole state table unknown

**What an existing site does.** Not established by this review. Whether the platform prints such
a row at all is the open question.

**What this repository does.** `_state_endpoint` refuses an address that carries a zone
(`"%" in address`: "unsupported PF endpoint address"), so `state_rows` refuses the whole table.
`reconcile` then takes its path for an unknown table: every owned rule is withdrawn, the journal
ends `failed` with the reason `kernel-state-unknown`, and an acknowledgement is owed. While such a
row is listed, every pass ends that way, and after it is gone every pass stays `failed` until an
administrator acknowledges. The guide: "An unrecognized row makes the whole inventory unknown. It
never supplies an empty owned-state result or permits a successful drain report." The owner
handles IPv4 only (`IPV4-SCOPE`: "IPv6 is outside the custom policy, not asserted blocked"), and
it reads every other IPv6 endpoint that is not IPv4-mapped as foreign.

**Evidence.** `test_r_u7_a_zoned_link_local_row_is_foreign_and_the_rest_of_the_table_is_read`;
`pytest tests/test_readiness_udp_return.py -k r_u7 --runxfail`. Beside a state of the pair, which
the reader reads by itself, the table lists one link-local row whose addresses carry a zone.
Today: "the reader answered PFError: unsupported PF endpoint address; the pass ended failed with
reason kernel-state-unknown, changed ['dns-tcp:withdraw', 'dns-udp:withdraw',
'media-udp:withdraw', 'proxy-standard:withdraw'], rules loaded []".

**Proposed change.** In `_state_endpoint`: an address with a zone is read only where the address
before the `%` is an IPv6 link-local unicast address (`fe80::/10`) or a multicast address of
interface-local or link-local scope, and the zone has the form of an interface name (a letter,
then at most 15 letters, digits, `_`, `.` or `-`). The endpoint is then foreign, like every IPv6
endpoint that is not IPv4-mapped. Every other zoned form stays refused, a global or an IPv4-mapped
address among them, so that a zone can never hide an IPv4 address. The rest of the row is checked
as today, and the rest of the table is read. The capture decides whether to make the change: on a
real host with PF enabled and a state for a link-local IPv6 flow, read the table as root
(`pfctl -s states`) and record whether a row prints a zone, and in which form. A form with the
zone embedded in the address, such as `fe80:4::1`, has no `%` and is already read as foreign. If
no zone is ever printed, the test is deleted and the refusal stays. One existing case states
today's refusal and changes with it, in
`tests/test_pf_owner.py::test_partial_or_malformed_pf_row_never_proves_absence`, the row
`all udp fe80::1%example[80] -> 2001:db8::2[80] SINGLE:SINGLE`. The refused endpoint
`2001:db8::1%lo0[443]` of `tests/test_pf_state_row_forms.py` stays refused.

**Decision needed.** Whether a row outside the owner's IPv4 scope may cost every rule and an
acknowledgement.

**Closing acceptance.** `BOUNDED-IDENTITY`, method `state-drain` (tier 3): the state tables of
that acceptance, before and after, are read by the owner without a refused row; a captured zoned
row, sanitized, becomes a fixture of the reader.

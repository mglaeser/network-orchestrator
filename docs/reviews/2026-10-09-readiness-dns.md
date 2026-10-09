# Readiness of the name-service path, 9 October 2026

This record covers the findings R-N1 to R-N8 of a readiness check of the
combined state against an existing site: the path on which LAN clients reach the
resolver on port 53. It was made on `main` at `de4cbb5` (release 0.4.2) and read
`src/netorch/pf_owner.py` (the direct redirect to the resolver guest, its native
fallback to a host port, how a pass chooses between them, the decision to keep
host paths of #104, the state-table read, the host-socket check, pause and
holds), `src/netorch/planner.py`, `src/netorch/apple_runtime.py` (what the probe
and recovery check for a resolver workload), the guides `docs/pf-owner.md`,
`docs/apple-runtime.md`, `docs/state-machine.md`, `docs/migration-readiness.md`
and `docs/migration-health.md`, and the owner's records of 8 October.

In the example policy the name service has two profiles, `dns-tcp` and
`dns-udp`, of kind `guest-direct`: a redirect of the host's port 53 to port 53
of the resolver guest. A profile that names a `fallback_publication` has a
second form, which redirects port 53 to the host's own address and the port of
a native publication of the same service (1053 in the tests), and which the
owner records as a host redirect with `effective_strategy: degraded-fallback`.
A pass runs every `interval_seconds`, ten seconds unless the installation
states another value from 1 to 60.

Five findings are flags that a test can state: R-N1, R-N2, R-N3, R-N4 and R-N8.
Each has a strict expected failure in `tests/test_readiness_dns.py` that asserts
the proposed behaviour and fails on this release with an assertion whose
message says what the owner does today; `pytest tests/test_readiness_dns.py
--runxfail` prints them. One more test there is an ordinary one that passes: it
holds a safety property that the change proposed for R-N4 must keep. The tests
prove what the passes of the PF owner do with the port-53 rules for the given
evidence, with the fake kernel, the example policy and the fallback helper of
the existing PF tests. Nothing ran against a host. They prove nothing about
packets, real tool output or timings, and not that a proposed change is safe:
each entry names what a real host has to show. The tests were also run against
prototypes of the proposed changes, and of forms that this record rejects; the
prototypes are not part of this change. R-N5 and R-N6 are recorded in the
owner's own documents. R-N7 is a flag that no test can state without inventing
an interface.

The closing acceptance uses four rows of the requirements registry, with the
method and minimum tier it gives them: `DNS-CLIENT-IDENTITY`
(`dns-client-identity`, tier 5), `RUNTIME-DNS` (`darwin-cli`, tier 2),
`BOOT-RECOVERY` (`unattended-reboot`, tier 4) and `COEXISTENCE`
(`rule-readback`, tier 2). The common measurement is a client on the LAN that
asks the host's address a fixed question at a fixed rate, over UDP and over TCP,
through each switch, restart and reboot, and records every unanswered query and
the longest gap; the resolver's log gives the client address it saw.

## R-N1: a switch between the direct and the fallback form takes two passes

**What an existing site does.** It swaps its port-53 rule between the direct and
the fallback target in one load.

**What this repository does.** The planner retires a loaded rule whose recorded
strategy is not the one the pass selects (`planner.py:243-249`, reason
`target-replaced`) and never activates a replacement in the same plan
(`planner.py:123-131`). The owner withdraws the two port-53 rules, one anchor
load each, drains, and ends the pass `inhibited`; the next pass activates the
other form. The guide states the order (`docs/pf-owner.md`, "Explicit DNS
availability fallback"): "If direct access becomes unverifiable, root withdraws
its guest rules and drains old guest states first; only a later fresh pass
exposes the fixed native host socket. [...] Returning to the direct path also
retires the old strategy before a later activation." Step 7 of "Reconciliation
and failure semantics" says: "Activate a replacement only in a later pass with
fresh identity evidence." The guide does not state the cost: at every switch, in
either direction, no rule is loaded on port 53 for at least one pass interval,
and LAN clients have no name service for that time.

**Evidence.**
`test_r_n1_a_switch_of_the_name_service_path_never_leaves_port_53_without_a_rule`,
in both directions: `pytest tests/test_readiness_dns.py -k test_r_n1 --runxfail`.
It asserts that of the anchor loads of the switching pass exactly one changes
port 53, for both profiles together, from the old form to the new. Today,
switching to the fallback: "the anchor loads of the switching pass leave port 53
with [{'dns-udp': '198.51.100.10:53'}, {}] (inhibited, ['dns-tcp:withdraw',
'dns-udp:withdraw', 'dns-tcp:drain', 'dns-udp:drain']); the next pass changes
['dns-tcp:activate', 'dns-udp:activate']"; switching back, the same with the
fallback target `192.0.2.10:1053`.

**Proposed change.** In `reconcile`, the profiles whose loaded record differs
from the plan of the pass only in its strategy (same policy digest, same service
generation, same network generation) are switched together:

1. Before anything is written, the pass checks every precondition of an
   activation of each new form, as an activation does today
   (`pf_owner.py:2401-2477`: gates, admission, fresh observation and plan, the
   interface, route and neighbour check for the new form, the host-socket
   check). For a switch to the direct form it also reads the state table and
   requires that no row is a retained state of the direct record for that
   guest address.
2. One anchor load replaces the rules of every profile whose loaded form names
   the guest that the switch leaves, here both port-53 profiles; a switch back
   replaces both fallback forms in the same way. The candidate is journalled
   like every write, loaded with one `replace`, which hands the whole anchor to
   one `pfctl -f`, and read back exactly. One load per profile is not enough:
   if the invalidation after the first load fails, the pass ends `failed` with
   the other profile still translating to a guest whose direct path no longer
   verifies (measured with a prototype that loads each profile by itself).
3. After that load the pass invalidates the states of the guest address that
   the switch left and reads the table back, against the old records. An
   invalidation that fails, or a table that cannot be read, ends the pass
   `failed` as today, and no rule names that guest any more. If a state of an
   old record is still listed, the pass withdraws the new forms as well, in one
   more load, and keeps the retired direct records: the profiles are then where
   they are today, `states-retained` with a drain on every pass.
4. If a precondition of step 1 does not hold, a switch to the fallback goes as
   today: the direct forms are retired and the fallback waits for the next
   pass. A switch back to the direct form leaves the fallback forms loaded, not
   reported ready on that pass, because they name no guest.

Whether a client can see the anchor between the old and the new rules depends
on the tool and the kernel. In the published `pfctl` lineage one `pfctl -f` of
an anchor is one transaction for its NAT, BINAT and RDR rulesets (FreeBSD 8.4
`contrib/pf/pfctl/pfctl.c`: `pfctl_rules` opens it at line 1423 through
`pfctl_ruleset_trans`, lines 1188-1216, and commits it once at lines 1469-1474).
The macOS kernel commits a transaction under its locks and swaps whole
rulesets (xnu, tag `xnu-12377.121.6`, `bsd/net/pf_ioctl.c`: `pfioctl` takes
`pf_perim_lock`, exclusively for a call that writes, and `pf_lock` at lines
1606-1612 and releases them at lines 2006-2007; `DIOCXCOMMIT`, lines 4280-4374,
checks every ruleset of the transaction before it commits any, line 4292, and
then commits each one with `pf_commit_rules`, lines 1109-1191, which swaps the
whole active rule list with the inactive one, "Swap rules, keep the old." at
line 1140; the packet path takes the same locks in `pf_af_hook`, lines
4631-4635, and `pf_test` in `bsd/net/pf.c` asserts `pf_lock` at line 9731).
Apple does not publish its `pfctl`, so that the macOS tool loads an anchor's
translation rules in one transaction is not established; it is a native
acceptance item.

The planner has to hand the owner the new forms together with the
retirement, either as activations that follow the retirement in the same plan,
for this case only, or as an operation of its own. Both change the plan output
and need an output-version decision. A readback that differs from the
candidate stays a write in doubt. Default: the switch is what every profile
with a declared fallback does, without a setting. A declared fallback is
already an admission of both forms (the digest binds both strategies and the
publication), and the switch uses exactly the evidence that an activation
uses. The test states it so.

The change reverses: the planner's rule that a replacement is never activated
in the plan that retires (`planner.py:123-131`); step 7 of the guide and the
sentences of "Explicit DNS availability fallback" quoted above; the docstring of
`reconcile`, "Replacement targets require a later fresh pass after previous
rules and states have been read back absent" (`pf_owner.py:2106-2108`); and, in
step 4, a fallback form stays loaded without #104's listener and reference
conditions and without a check of its publication. The owner's test
`test_dns_mode_changes_retire_guest_states_then_later_restore_direct`
(`tests/test_pf_owner.py:1412`) changes: it asserts that each switching pass
withdraws and does not activate.

**Decision needed.**

1. Whether a strategy switch may activate in the pass that retires, against the
   planner's rule, step 7 and the docstring above, and whether that is a
   correction of the default (proposed) or an installation decision; in the
   second case the test names that decision.
2. The plan vocabulary of the switch and its output version.
3. What happens to a state of the old guest address that survives its
   invalidation (proposed: back to today's sequence for those profiles).
4. Step 4: keep the fallback forms loaded when the checks of the direct form
   fail, without #104's conditions and without a check of the publication, or
   retire them as today.

**Closing acceptance.** `DNS-CLIENT-IDENTITY` (`dns-client-identity`) and
`COEXISTENCE` (`rule-readback`). On a real host the LAN client asks at a fixed
rate (for example ten UDP and one TCP question a second) while the direct path
is made unverifiable and verifiable again; the means used is recorded. Measured:
unanswered queries and the longest gap at each switch, the client address the
resolver logs, and the owned anchor's listing before and after each switch.
Passes when no query is left unanswered at either switch, the resolver logs the
client's own address on the direct form and the host's on the fallback form,
which the report states as `degraded-fallback`, and the two listings differ in
the port-53 rules only.

## R-N2: a timed-out runtime read withdraws a loaded direct rule and loads nothing

**What an existing site does.** It uses its fallback on any failure.

**What this repository does.** A read of the resolver that ran out of time makes
the plan retire the loaded rule for missing evidence (`planner.py:180-181`,
`endpoint-unknown`) before the fallback is ever selected (`planner.py:205-211`).
With #104's decision a pass keeps a loaded rule only where its record ends at
the host (`_host_path`, `pf_owner.py:1872-1905`); the direct form names the
guest, so it is withdrawn and drained with or without the decision, and nothing
is loaded on port 53 until the reads answer again. The guide states it
(`docs/pf-owner.md`, "Explicit DNS availability fallback"): "Only the independent
PF owner's current kernel route/ARP checks select the fallback. [...] Unknown
runtime identity is insufficient to select or to activate either strategy. A
fallback rule that is already loaded outlasts it only where the installation
chose to keep host paths"; and of that decision: "The decision keeps and never
activates. It cannot bring a rule into existence". It does not say that with the
direct form loaded, which is the normal state, no installation can keep the
name service while the reads run out of time.

**Evidence.** `test_r_n2_a_timed_out_read_moves_direct_dns_to_its_listening_fallback`:
`pytest tests/test_readiness_dns.py -k test_r_n2 --runxfail`. The test writes
the decision proposed below, beside `keep-host-paths`, through a helper that
keeps the default installation only when the release refuses exactly that key
as unknown and ends the test on any other refusal. The fallback is declared,
admitted and verified by the earlier passes, and a listener holds its port.
Today: "with the default installation (this release refuses {'direct_unknown'}
as unknown) and a fallback that is declared, admitted and listening, a read of
the resolver that ran out of time leaves port 53 with {} (inhibited,
['dns-tcp:withdraw', 'dns-udp:withdraw', 'dns-tcp:drain', 'dns-udp:drain'],
withheld {})". With `keep-host-paths` alone the outcome is the same.

**Proposed change.** An installation decision of its own,
`"direct_unknown": "fallback"` in `installation.json`; the name is the owner's
to choose, and while it is absent nothing changes. It needs
`runtime_unknown: "keep-host-paths"` beside it, because from the pass after the
switch the fallback form is a host path that only that decision keeps. Like the
other decisions it is left out of the stored form while absent, and choosing it
changes the digest of every admission of the owner. With it, a loaded direct
form whose profile declares a fallback, and whose plan retires it only for
missing evidence by the two closed lists of #104 (`_evidence_missing`), is
replaced by its fallback form in one load, for every profile that names that
guest (R-N1, step 2), instead of being withdrawn, if on this pass:

- root's socket inventory lists a listener of the profile's protocol on every
  port that the fallback form translates to, on the host's address or the
  wildcard (the fourth condition of #104);
- the owner's enable reference is held (the fifth condition); the switch never
  takes it;
- the host-socket check of port 53 and the interface check of the host address
  pass, as at an activation of the fallback form.

The states of the guest address are handled after the load as the retirement
handles them (today they are invalidated; R-U1 proposes to keep them when the
only cause is unknown evidence). The fallback form is then withheld with
`runtime-unknown` and is not `root_ready`; from the next pass on, #104's
keeping applies to it, and when the reads answer again R-N1's switch returns to
the direct form. Nothing changes for any other reason of an unknown
observation, for an authority that changed, or without the decision.

For an installation that makes it, the decision reverses the limit that the
owner accepted with #104, "no new activation/reference" in the proposal ledger,
and the guide sentences quoted above: "The decision keeps and never activates",
"It cannot bring a rule into existence", "Only the independent PF owner's
current kernel route/ARP checks select the fallback" and "Unknown runtime
identity is insufficient to select or to activate either strategy". It is
therefore not part of `keep-host-paths`: with the switch put under that
decision, the owner's seeded tests
`test_seeded_passes_never_report_a_kept_rule_ready_keep_a_guest_rule_or_activate`
(seed 22) and `test_one_long_seeded_sequence_reaches_every_outcome` fail; with a
decision of its own both host-path test files pass (measured with prototypes of
both forms). The new decision needs a seeded property test of its own.

**Decision needed.**

1. Fallback on unknown evidence. The listener check establishes that something
   listens, not whose socket it is: the price that #104 records for keeping a
   loaded host path is paid here for a rule that is brought into existence.
   While the fallback is in effect the resolver sees the host's address, not
   the client's. Keeping the direct form instead is not proposed: it names a
   guest address that may belong to another guest by then, the address-reuse
   risk that the bounded safety model of the direct profiles names.
2. The name of the decision, and whether it rests on `keep-host-paths`
   (proposed) or keeps the fallback form by itself.
3. Whether a listener is enough, or the owner must also have verified the
   fallback publication in the pass that last verified the direct form; that
   needs one fact more in the owner's record of the direct form.

**Closing acceptance.** `DNS-CLIENT-IDENTITY` (`dns-client-identity`). On a real
host the LAN client asks at a fixed rate while the reads of the resolver's
container run out of time; the means used is recorded. Measured: unanswered
queries from the first such pass on, the longest gap, the client address the
resolver logs, and the report. Passes when no query is left unanswered across
the switch, the resolver logs the host's address while the fallback is in
effect and the report shows both profiles withheld with `runtime-unknown`, and
when the reads answer again the direct form returns and the client's own
address is logged.

## R-N3: a restart on the same address costs one pass without a port-53 rule

**What an existing site does.** The readiness check records nothing for this
case; we do not know whether an existing site loses time on a restart beyond
the resolver's own start.

**What this repository does.** The runtime observer derives a guest's generation
from its configuration, its current start time, the network generation and its
address (`apple_runtime.py:1070-1077`; `docs/apple-runtime.md`, step 6: "Derive
guest generations from configuration, current start time, current network
generation and current address."). A restart therefore gives a new generation
although nothing else changed, and the planner retires both rules
(`planner.py:243-249`, `target-replaced`); the next pass activates them again.
The guide states the retirement and the later activation (`docs/pf-owner.md`,
step 7) but not that every restart of the resolver costs at least one pass
interval without a rule on port 53.

**Evidence.** `test_r_n3_a_resolver_restart_on_the_same_address_keeps_port_53_served`:
`pytest tests/test_readiness_dns.py -k test_r_n3 --runxfail`. The restarted
observation has the same address, link address, contract and network
generation. Today: "leaves port 53 with {} (inhibited, ['dns-tcp:withdraw',
'dns-udp:withdraw', 'dns-tcp:drain', 'dns-udp:drain']); the next pass changes
['dns-tcp:activate', 'dns-udp:activate']".

**Proposed change.** Two variants; the test accepts either.

- **A, reload within the pass (proposed default).** The pass withdraws the rules
  and drains the old instance's states as today. When the state readback shows
  none left, it activates the rules for the new generation within the same
  pass, with the evidence an activation reads anyway: a fresh observation and
  plan, the route and neighbour check against the observation's link address,
  the host-socket check. The order "drain, read back, then expose" stays; only
  the wait for the next pass goes, and the gap is the drain and one runtime
  read instead of a pass interval.
- **B, keep (an installation decision).** When the new observation names the
  same address, the same link address and the same contract and configuration
  in the same network generation, and the neighbour entry carries that link
  address, the plan keeps the rule and the owner writes the new generation into
  the record without a load. There is no gap; the states of the old instance
  survive, and a datagram of such a state reaches the new instance on the same
  address.

**Decision needed.** Whether variant A is a correction of the default or an
option. For variant B, what proves that the same address belongs to the same
service: the observation alone, or also the link address in the neighbour
entry. Whether the vendor keeps a guest's link address across a restart is not
known.

**Closing acceptance.** `DNS-CLIENT-IDENTITY` (`dns-client-identity`). On a real
host the LAN client asks at a fixed rate while the resolver's container is
stopped and started again. Measured: the time from the resolver's first answer,
asked from the host on its guest address, to the first answer through the
redirect; the unanswered queries; the guest's address and link address before
and after, read with the vendor's inspection. Passes when the redirect answers
within one query interval of the resolver (variant B) or within the drain and
one runtime read (variant A), and the resolver logs the client's own address.

## R-N4: a state table that cannot be read withdraws every owned rule

**What an existing site does.** Its name-service path reads no state table.

**What this repository does.** Every pass reads the whole state table first
(`pf_owner.py:1604`), through the backend's four-second bound
(`pf_owner.py:999-1004`) and the runner's output bound of 1 MiB
(`process.py:74`). A read that fails, for whatever reason, retires every record,
host redirects included, in one load, and journals `failed` with the reason
`kernel-state-unknown` (`pf_owner.py:2212-2267`). Every later pass then owes the
administrator's acknowledgement and plans with damaged intent, which retires
every rule (`pf_owner.py:2182-2195`). A final readback whose table read fails
raises out of the pass and ends in the same place (`pf_owner.py:2614`,
`2826-2834`). The guide states it: "a final state table that cannot be read [...]
Each ends the pass `failed`, as does a state table that cannot be read when the
pass starts" ("Deferral and writes in doubt"), and "The state table cannot be
read [...] every rule is retired" ("Host paths while runtime evidence is
unknown"). It does not say that the plan of a loaded host redirect, the web
redirect or the fallback form of the name service, needs nothing from that
table: `_snapshot` gives a host-redirect record no states
(`pf_owner.py:1619-1624`). An activation of the fallback form does need it: it
waits while the retired direct record's states are listed
(`planner.py:234-239`). The table holds every state of the host, the vendor's
own translations of the guests' connections included; at about 100 bytes a
row, 1 MiB is about ten thousand rows (arithmetic, not a measurement).

**Evidence.** `test_r_n4_a_listing_over_its_bound_leaves_host_redirects_to_their_own_plan`,
for a listing slower than its time limit and one larger than its output bound,
at the first and at the final read of a pass: `pytest tests/test_readiness_dns.py
-k test_r_n4 --runxfail`. The name service is loaded in its fallback form beside
the web redirect and the UDP return pair. After the pass whose listing runs over
its bound, the web service is held, and the listing of the next pass runs over
the same bound when the pass starts; a third pass reads the table. The test
asserts that the fallback form stays loaded through both passes, that the held
web redirect is withdrawn although the table cannot be read, and that the name
service is ready on the third pass. Today, first read: "ends failed (reason
kernel-state-unknown) with port 53 at {}; with the web service held, the next
pass, whose listing runs over the same bound when it starts, ends failed
(reason kernel-state-unknown) with port 53 at {} and the web redirect withdrawn;
the pass after it, with a readable table, ends failed, owing the
acknowledgement, with port 53 at {} and [] ready"; at the final read the first
pass raises with the rules still loaded and the next pass withdraws them.

`test_r_n4_a_pause_withdraws_every_rule_also_while_the_state_table_cannot_be_read`
is a guard and passes today: under an operator pause, a pass whose listing runs
over its bound withdraws every rule, host redirects included. With a prototype
that left every host redirect loaded and unchanged, the form of the first
version of this record, the guard fails and the expected failure above does not
turn into a pass: the held web redirect stays loaded, and under a pause every
host redirect stays loaded for as long as the listing runs over its bound. With
a prototype of the change below, the four cases pass and the guard holds.

**Proposed change.** Only a listing that runs over the runner's time limit or
its output bound (`ProcessTimeout`, `OutputLimit`) qualifies. A listing that
failed, a listing refused for a notice, and a malformed or changed listing stay
as today. For a listing over its bound:

- Host redirects are planned from a snapshot that needs no state table, which
  is the snapshot `_snapshot` already builds for them, with the intent and the
  admissions of the pass, and are retired wherever that plan retires them: a
  pause, a suspension, a hold, a damaged intent, an admission that lapsed, a
  policy that changed or was removed, evidence that says so. A host redirect
  that the plan verifies stays loaded; a retired one needs no drain.
- Every record that is not a host redirect is retired as today, with its drain
  in doubt. The acknowledgement covers those records only (R-U2 asks the same
  scope for a drain that fails), so that the next pass does not retire the host
  redirects on damaged intent.
- The final readback follows the same rule.

This reverses the position stated at `pf_owner.py:2215-2217`, "Unknown state
metadata must not retain known active exposure", for host redirects and these
two failures. It changes the guide sentences quoted above from "Deferral and
writes in doubt" and "Host paths while runtime evidence is unknown". The
owner's tests that pin the retirement of every rule for a table that cannot be
read, `test_a_state_table_that_cannot_be_read_retires_every_rule_as_before`,
`test_unknown_kernel_states_withdraws_known_rules_without_claiming_drained` and
`test_unknown_numeric_state_row_withdraws_without_claiming_drain`, feed a
malformed listing, which this proposal keeps as today: with a prototype of it
they pass, as do the other tests of the PF owner; with the earlier form, which
treated every failed read alike, all three fail. The name of the first speaks of
any table that cannot be read and needs the narrower wording, and the bound
cases come beside them. Default: a correction, without a setting.

**Decision needed.** Correction of the default (proposed) or an option. The
scope of the acknowledgement, shared with R-U2. Whether a loaded and verified
direct form, whose plan does not consult its states either, may stay as well:
not proposed, because its retirement needs the drain that the table proves.

**Closing acceptance.** No row measures this directly; `COEXISTENCE`
(`rule-readback`) is the closest, because the table is shared with every other
user of PF on the host. Measured on a real host: the size and the duration of
the backend's `states` listing as root, at a fixed interval over a
representative day, read-only. Passes when the largest listing stays well
inside both bounds; we propose half of each, two seconds and 512 KiB.

## R-N5 (ref): port 53 is accepted from LAN sources only

An existing site accepts any source on the LAN interface. Recorded by the owner:
the site-requirements review, "Remaining reference-installation conformance
work", item 2, and the closure's row "DNS source scope", which names
`test_any_source.py` for the enforcement. What it leaves out: in words, that the
refusal covers the profile's fallback form too, which ends at the host's own
address as a structural host redirect does
(`test_any_source_is_refused_for_a_fallback_capable_direct_profile` shows it), so
that neither form serves a client outside the LAN prefix; such a client's query
to the host's port 53 is not redirected at all.

## R-N6 (ref): a pause withdraws every owned rule, the name service included

An existing site's name-service path is not paused by another owner's pause.
Recorded by the owner: `docs/state-machine.md`, "Pause is independent of
operation ownership" ("The first three stop every service; a hold stops one and
never narrows the other three."), and `docs/pf-owner.md`, "Holding one service"
("A hold on one service [...] retires that service's profiles and leaves the
others loaded."). Executable proof exists:
`test_pause_retires_every_rule_although_one_state_readback_fails`
(`tests/test_pf_withdraw_order.py`) and
`test_root_owner_retires_only_the_held_service_and_external_gate_only_adds`
(`tests/test_service_holds_root.py`). What it leaves out: that where one PF
owner carries all forwarding of a site, as in the examples, its pause, and the
installer's suspension during an upgrade or a rollback, takes name resolution
away from the LAN; and that the way to stop every other forwarding and keep the
name service is then a hold on each other service. A policy can also give the
name-service profiles an `external-root` owner of their own, with its own
installation, anchor and pause; this record has not examined that form, in
which the translation-order check that an installation can choose does not pass
while the other owner's anchor beside its own holds translation rules.

## R-N7: nothing asks the resolver a question

**What an existing site does.** Its supervisor queries the resolver over UDP
and TCP and restarts it on failure.

**What this repository does.** The probe returns 0 for a running enrolled
container on its network and address, 42 for a proven stopped one and 69 for
anything unknown or held (`apple_runtime.py:1015-1091`, `1917-1926`); recovery
starts a twice-proven stopped guest and requires running readback
(`apple_runtime.py:1547-1597`). Neither sends a DNS query, and the PF owner's
readiness rests on the same container evidence. The health checkpoint evaluates
a saved dashboard recording; "It makes no request" (`docs/migration-health.md`).
The owner records parts: "This is not proof of application health: a runtime
forwarder can be alive while its application is unhealthy"
(`docs/apple-runtime.md`); "DNS answers over required transports from the client
side" is a health layer of the readiness dossier (`docs/migration-readiness.md`);
the closure's row "Supervisor behavior" records no separate in-guest component
repair; and an instance can declare such a check only as a component whose
health stays with the existing owner (`health: "existing-owner"`). What none
says: a resolver that stops answering inside a running guest is reported running
by the probe, nothing restarts it, and the PF owner keeps the port-53 rules
ready.

**Evidence.** No test. A test would have to choose who asks (the probe, a
command of its own, the root owner), over which path (the guest's address, the
host's port), which question, with which bound and which result vocabulary; that
choice is the proposed change, not an interface of this release. The probe's
code above shows that it asks nothing.

**Proposed change.** A check of the resolver as a component of its workload
(`COMPONENT-HEALTH`), never a reason to restart the container:

- Where: a read-only command of the user runtime owner beside `probe`, for one
  declared component of a workload. For a running, verified guest it asks a
  fixed question that the resolver answers itself (a name of the site's own
  zone, declared with the component, so that the answer does not depend on
  upstream servers), once over UDP and once over TCP, on the guest's verified
  address and port 53. Its result is component evidence of the host report
  (`components` rows of `schemas/host-evidence.schema.json`). The PF owner does
  not use it: the fallback reaches the same resolver.
- Bound: two seconds for each question, both within the read bound of the
  probe, so that the check timeout that a bundle enforces for `probe` (the
  bound plus two seconds) covers it; that bundle check has to know the new
  command.
- On timeout: a question that is not answered within its bound makes the
  component's observation `unknown` with `timed-out`, and the command exits as
  the probe does for unknown (69). It authorizes nothing (`UNKNOWN-NO-RECOVERY`),
  but the component is not current, so the host report's current readiness is
  false. An answer with an error is a failed check; it restarts no guest either.
  A repair stays with the component's owner (`recovery: "component-owner"`),
  which at an existing site is its supervisor; a status that asks a supervisor
  to start the component needs the in-guest ensure that the closure records as
  missing, and is not proposed.

**Decision needed.** Whether this repository should ask the resolver at all
before the existing supervisor is extracted (the closure says to keep that
supervisor until its behaviour is extracted, and the query is part of it).
Whether an unanswered question, which this check exists to notice, may ever be
a finding rather than an unknown observation. The question asked, the number of
failed checks before the component counts as failed, and whether the platform's
local-network permission applies to the vendor's bridge for the job that asks
(not known).

**Closing acceptance.** `BOOT-RECOVERY` (`unattended-reboot`) and
`DNS-CLIENT-IDENTITY` (`dns-client-identity`). On a real host the LAN client
asks over UDP and TCP at a fixed rate while the resolver's process inside the
running guest is stopped, and through an unattended reboot. Measured: unanswered
queries, the time until the component check reports the failure, whether the
container is restarted, the earliest valid answer after the boot, and the
client address the resolver logs. Passes when the component is reported not
current within the declared number of checks, the container is not restarted,
answers return after the component owner's repair with the client's own
address, and the first valid answer after the boot falls within the limit the
instance chose.

## R-N8: the coexistence check runs at activation only

**What an existing site does.** The readiness check records nothing for this
case; we do not know whether an existing site checks its port-53 listener again.

**What this repository does.** The host-socket check (`ShellBackend.ports_clear`,
`pf_owner.py:1245-1270`), which lets the platform's own DNS listener through
where the installation admitted its exception, runs only immediately before an
activation (`pf_owner.py:2451-2459`). A pass that leaves a rule loaded does not
run it, and `root_ready` (`pf_owner.py:2755-2762`) does not depend on it. The
guide says when it runs (`docs/pf-owner.md`, step 5: "Immediately before each
activation, [...] Verify [...] host socket coexistence") and what the exception
admits ("DNS coexistence"). It does not say that a listener appearing on port 53
later is not noticed and the rules stay ready.

**Evidence.** `test_r_n8_a_listener_that_appears_on_port_53_ends_the_readiness_of_the_dns_rules`:
`pytest tests/test_readiness_dns.py -k test_r_n8 --runxfail`. The test uses the
owner's own check over a fake socket inventory, without the exception. Today:
"the pass after a listener appeared on the host's port 53 ends committed,
reports ['dns-tcp', 'dns-udp', 'media-udp', 'proxy-standard'] ready and runs
the host-socket check 0 times".

**Proposed change.** After the actions of a pass, where the translation-order
check of a loaded pair runs (`pf_owner.py:2661-2685`), the pass runs the
host-socket check for every active record, with one inventory read per protocol
and pass. A profile whose check does not pass is withheld with a reason of its
own (for example `ports-unverified`, added to the withholding vocabulary): its
rules stay loaded, it is not `root_ready`, and the pass ends `inhibited`; the
first pass whose check passes reports it ready again. Cost: one inventory read
per protocol, a bounded call of two seconds each, on every pass that leaves a
rule loaded, and where the exception is admitted and a port-53 socket of the
platform's listener is listed, the reads that verify its identity. Today a pass
reads the inventory only at an activation and, with #104's decision, for a host
path that it judges; it does read route and neighbour on every pass for each
profile with a fallback. Default: a correction, because the change reports less
readiness and withdraws nothing.

**Decision needed.** Withhold (proposed) or withdraw: a loaded redirect takes
the LAN's port-53 traffic before any host listener sees it, so withdrawing would
hand LAN clients to the platform's listener. Every pass or a bounded interval;
R-U3 asks the same for the host-socket check of the UDP return pair.

**Closing acceptance.** `COEXISTENCE` (`rule-readback`) and `RUNTIME-DNS`
(`darwin-cli`). On a real host, with the rules loaded and ready, the platform's
own DNS listener starts on port 53; the means used is recorded. Measured: root's
socket inventory, the report of the next pass, the owned anchor's listing before
and after, and, with the native tools, which process holds port 53 on which
address and the vendor runtime's DNS settings. Passes when the next pass reports
both port-53 profiles not ready with the reason, the anchor listing is unchanged,
the listener is untouched, and the runtime's DNS settings are what they were.

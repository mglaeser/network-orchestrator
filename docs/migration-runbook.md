# One-owner-at-a-time migration runbook

This is a preparation document for a future qualified release and separately
authorized native window. It runs nothing. The current public activation gate
stays in force; do not call retained internal execution functions to bypass it.
Complete the [readiness gates](migration-readiness.md) first. This procedure
extracts the existing owners instead of replacing them with a new orchestrator.

## Scope and invariant

One transaction changes one owner or one workload definition. The instance pins
its input and release pair; the installed owner remains the sole writer until
handoff, and the successor is the sole writer afterwards. The predecessor stays
available as inert rollback material until retirement evidence permits deletion.
There are never two active publishers, PF writers or competing recovery loops.

Preserve existing names, paths, application data, pairing, root grants, interface
scope, source semantics, publication mappings and pause/holder records. Any
intentional difference is a separate declared change with its own evidence.
Runtime upgrades, kernel changes, application upgrades, new helpers/automations
and new receiver pairing are not bundled into an extraction transaction.

## Phase A: prepare without changing production

1. Read the current source and installed-owner contracts. Pin exact versions and
   hashes, inventory each authority and record all unresolved differences.
   Preserve unrelated working-tree and application changes.
2. Freeze the private instance, generated view, conformance captures and
   complete reviewed dashboard roster. Re-import the generated view, validate the closed
   data and run the existing report/check plus `supervision-gaps`. Retain the
   resulting blockers; an empty GitHub queue is not an empty gate report.
3. For each proposed owner commit, identify the exact embedded settings removed,
   new single author, generated files and unchanged installed names. Compare
   every rendered byte, including headers and line endings. Prove behavior with
   meaningful refusal, race, partial-write and rollback tests. Run the required
   final macOS CI and both privacy guards on the pinned release.
4. Prepare off-host recovery material, exact predecessor code/input hashes and
   the rehearsed recovery procedure before an operation that could require them.
   Record ongoing file, volume, kernel and journal references. Preparation does
   not delete historical material simply because a new release exists.
5. Define the step dependency graph, full health checkpoints, finite retry/time
   limits, rollback branches and sunset criteria. The graph records ordering;
   it is not an executable command language or an apply coordinator.
6. Review the [privilege-session design](migration-privilege-session.md). Stage
   all code and fixed data that the authorized transaction and its declared
   recovery branches will need. No later download or editable command request
   may acquire the session's privilege.

A blocked owner can remain installed while independent preparation continues.
Do not begin a different migration merely to hide the block, or expand scope
until the blocker disappears.

## Phase B: close the prerequisites and announce the window

The readiness record names which evidence is already valid and which native
qualification must be performed in its own bounded window. Recovery rehearsal,
platform/runtime decisions, launch-context consent and native testing remain
separate actions; this document does not imply that they happened. Keep the
platform fixed once its baseline is accepted for extraction.

Immediately before the first native action, notify the operator with:

> Starting the reviewed migration window for the fixed owner sequence and pinned
> changes listed in the private plan. Each transition changes one owner; the
> affected services, interruptions and per-transition/whole-window bounds are
> recorded. Each predecessor and its scoped rollback are ready. The complete
> dashboard roster and applicable independent pre-checks passed. One initial local
> administrator authentication covers this finite preapproved sequence and its
> declared retries/recovery. No owner, new candidate or application change may
> be added during the window; a failed checkpoint stops the remaining sequence.

The actual notice names the concrete owner order, affected services and bounds.
A one-owner window uses the same rule. The sequence does not implicitly authorize
any owner: every transition and recovery branch must already have its specific
authorization and evidence. Do
not send a start notice during preparation and then quietly begin later with
stale health evidence. It is a notification under the authorization already
recorded for the window, not a request to invent missing acceptance.

Authentication happens locally; no password is read, stored, copied into a file
or passed through chat. The finite session should avoid further prompts for
already reviewed same-input retries. It is not an indefinite credential cache,
new sudoers grant or unattended privileged endpoint. Its precise boundary and
failure behavior are specified in the privilege-session document. Session loss,
reboot or a changed code/input envelope cannot be promised automatic privileged
continuation. Preserve holds and report the partial state instead of prompting
repeatedly or bypassing authentication.

## Phase C: migrate in dependency order

The order below is the default extraction order. Actual profile dependencies
can add prerequisites but cannot justify parallel writers. The existing root
owner remains available for planned-stop withdrawal while other owners move;
its own input migration is last.

| Order | Transaction | Required preserved behavior and exit evidence |
|---|---|---|
| 1 | Existing Bonjour owner's inputs and embedded data | Exact dynamic/explicit type selection, projected names/TXT, interface and genuine source identity, per-direction miss/expiry behavior and actual dependencies. Prove old registration withdrawal before a successor publishes; retain one publisher and its consent context. Full health post-check plus applicable native discovery acceptance. |
| 2 | Existing recovery adapter and Monit configuration | Same launcher/process type/throttle, one startup/recovery owner, reserved statuses, component-only repair and complete-action bounds. Unknown, timeout and historical job uncertainty must start nothing. Preserve operator pause and every other holder. Full health post-check and safe no-op/rollback evidence. |
| 3 | Workload inputs, one workload per transaction | Exact image/init/kernel/resources/mounts/arguments/publications, immutable persistent identities and application state. Start with the least critical eligible workload and leave the resolver until last. Prefer an input-only no-op when recreation is unnecessary; a required recreation is explicitly planned and uses the existing withdrawal gate. |
| 4 | Existing root owner's inputs | Data-only parsing, identical admitted rule meaning, anchor/order/reference/lock identity, protected paths and exact content-bound admission. No root rewrite, new planner call, broad pass rule, global flush or stale-state replay. Real readback must establish the owned result while unrelated state is unchanged. |
| 5 | Final lifecycle acceptance and retirement | Full service and external-client health, repeated provisioning no-op, applicable cold/reboot/restore evidence and a clean reference inventory for each predecessor. Retire only the owner whose individual criteria have passed. |

When an existing owner needs functionality the retained framework cannot yet
express, its transaction stays blocked. Examples include dynamic discovery,
exact legacy name construction, named-volume/socket/memory-backed mount handling,
control-state ACL parity and unmatched supervisor behavior. Do not choose a
convenient approximation and label it conformance.

## The transaction sequence for every owner

1. **Revalidate.** Recheck the pinned release/input identities, prerequisite
   evidence, owner/job identities, foreign coexistence baseline and a fresh
   complete [health checkpoint](migration-health.md). Changed evidence means
   stop before taking authority or changing files.
2. **Take only this operation's hold.** Keep the operator's pause and unrelated
   holds untouched. Record holder and phase durably outside the release tree.
   Unknown or damaged control state inhibits the change.
3. **Withdraw when required.** Use the existing owner's established procedure.
   For a bounded guest or runtime-wide stop, withdraw only owned rules, drain
   their old-address states in both directions and verify current kernel
   retirement before stopping the guest/runtime. Withdrawing rule text alone
   does not retire established flows.
4. **Handoff without a second writer.** Recheck the source and target bytes and
   retire the predecessor's active authority before enabling the successor.
   Keep current state locations and names. Install only the owner input/code
   already within the reviewed transaction. Do not edit application storage.
5. **Observe the actual result.** Obtain fresh runtime/network generations and
   independent owner readback. Preserve currently admitted content; changed
   content stays pending the separate administrative admission. Discovery uses
   its actual declared dependencies, never an invented readiness shortcut.
6. **Return through the owner's established gates.** Release only this
   operation's holder when withdrawal/apply/recovery readback is proven. Never
   clear operator pause, another transaction's hold or an acknowledgement owed
   for an uncertain write. If one legitimately keeps the service unavailable,
   the migration cannot report an all-healthy post-check.
7. **Check the entire roster.** Use the existing dashboard's supported refresh/read
   mechanism for the complete reviewed roster, with new timestamps and the
   current step/generation. Pass the offline coverage/freshness evaluation of
   the actual API recording, and separately verify every applicable independent
   external/client or native checkpoint. The evaluator cannot authenticate a
   recording or prove those additional conditions. Record failure, retry and
   rollback checkpoints as well as success. An intended intermediate outage
   does not count as a completed step.
8. **Close narrowly.** Verify repeat provisioning is a no-op, preserve the
   receipt/journal and classify this owner as migrated but retained for rollback
   until its sunset conditions are met. Start no dependent step before this
   step's required health and readback evidence is complete.

## Failure, retries and rollback

Unknown evidence, unexpected differences, a failed health check, unverified
withdrawal, loss of the single-writer boundary or changed authority stops the
next mutation. A finite retry is allowed only for the explicitly classified
transient condition, within the same reviewed bytes, owner and deadline, after
fresh prerequisite checks. Busy locks are never removed or replaced to force
progress. Authentication success is not evidence that a retry is safe.

Rollback is owner-scoped to the pinned predecessor release and its instance
input. Use the same verified withdrawal sequence, restore only owned code and
desired inputs, and obtain fresh readback. Preserve current pause and holder
state instead of restoring an old unpaused snapshot. Never run predecessor and
successor together or restore application data automatically as part of a
networking rollback.

After rollback, recheck every vital service and external sentinel. If the
predecessor cannot be verified, required recovery material is unavailable or a
write remains uncertain, retain the protective hold and exact failed phase.
Report what is still running, what is withdrawn and the evidence required to
continue. Do not chase green dashboard tiles with unrelated restarts, extra
audio tests, broader rules or guessed application fixes.

## Phase D: sunset each predecessor explicitly

An artifact progresses from active to inactive-but-retained to deletion-eligible.
The private retirement ledger records its hash, former owner, replacement,
retention reason, reference checks and final disposition. No time-based expiry
or directory-name match makes it eligible automatically.

Before deleting an old owner file or temporary diagnostic artifact, establish:

- No loaded launchd/Monit job, process argument, helper binding, generated input,
  start/recovery path or privileged entrypoint still names it.
- No current container definition, volume/mount, image/init/kernel reference,
  open file or running service depends on it. Do not infer absence from a
  partial API inventory or an unprivileged failed lookup.
- No pending operation, rollback receipt, durable pause/hold, required journal,
  lock inode, retained PF reference or accepted recovery copy needs it.
- The successor's per-owner acceptance and full health checkpoints are complete;
  its second provision is a no-op; the predecessor's rollback retention need has
  ended according to the reviewed policy.

Remove only the exact proven-unreferenced set. Do not delete a shared state tree,
kernel directory, backups, locks or journals wholesale. Keep migration evidence
and off-host recovery material for the declared retention period; cleanup must
not recreate the earlier absence of recovery material. Re-run the full health
checkpoint after each cleanup transaction and record the result.

## Completion

Report each owner separately: prepared, blocked, migrated with predecessor
retained, retired, or rolled back. Include pinned revisions, evidence tiers,
health checkpoints, unresolved requirements and any retained holds. These are
human workflow descriptions, not new runtime authority states.

The whole installation is served only when every applicable requirement has
appropriate verified evidence, an allowed explicitly accepted residual, or a
genuine non-applicability result; no required native gate remains unverified.
All names/state paths remain preserved, the complete vital roster is healthy,
and the required application, DNS, unattended-reboot and restore results exist.
An idle PR queue, successful installer exit, matching render or green CI alone
cannot establish that outcome.

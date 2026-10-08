# Repository review closure and deployment qualification

This document separates completion of the repository review from completion of
an installation. Read it with the [proposal ledger](2026-10-08-proposal-ledger.json),
[site-requirements review](2026-10-08-site-requirements-review.md), and
[migration gates](../site-migration.md). It records no new native acceptance.

The public release remains an extraction and review framework. It cannot yet
replace every existing networking, workload and supervision input merely by
being given a private instance. Closing all reviewed PRs means their proposals
have dispositions and their accepted changes have passed repository checks.
It does not mean the reference installation is migrated or fully served.

## What can be closed independently

| Claim | Evidence needed | What it does not establish |
|---|---|---|
| Repository correction complete | Reproduced defect, enforcing regression, reviewed final diff and required CI on the final revision | Native behavior or installed-source parity |
| Owner extraction complete | Complete frozen inputs, one author per setting, identical rendered inputs and preserved names; declared differences separately reviewed | Packets, application recovery or cold-boot behavior |
| Installation qualified | Exact platform/release/profile evidence at each applicable native, lifecycle and application tier | Qualification of another host or a later release |

Historical descriptions of “complete deployment bundles” refer to the bundle
transaction and its user/root domains. They do not promise support for every
workload mount, publication, discovery policy or supervisor behavior. Likewise,
a contract capable of describing a native definition is not necessarily a
recipe capable of creating it.

The public mutation gate in `workflow_gate.py` still refuses activation before
reading mutation inputs, creating state or calling native tools. No instance
flag, environment variable, root invocation or green CI run overrides it.
Observation and explicitly negative requests remain subject to their existing
ownership and envelope checks. Tests in `test_workflow_gate.py` exercise this
boundary; they do not bypass it for deployment.

## Remaining parity work and current safe behavior

These are declared limits, not additional demonstrated unsafe behavior. Keep
the existing owner responsible for each unmatched capability until extraction
and qualification are complete. Do not silently narrow or broaden its behavior
to make the new model appear compatible.

| Area | Actual retained capability and limit | Concrete work before an owner can replace its predecessor |
|---|---|---|
| Source and installed-input parity | Static literals can be imported and rendered. An inventoried executable is not proof that all embedded values were extracted. Protected active policy is not inferred from readable source. | Freeze the actual installed sources and inputs, reconcile tracked-source drift, account for embedded constants, and prove byte parity for the individual owner. `test_conformance.py`, `test_conformance_capture_identity.py` and `test_render_promotion.py` prove refusal and identity boundaries, not full site extraction. |
| DNS source scope | Unrestricted sources are permitted only for structural host redirects. A direct-to-guest profile remains LAN-scoped. | Decide explicitly between preserving the existing broader behavior through a separately reviewed strategy and accepting a narrower behavior. Neither is a transparent refactor. `test_any_source.py` covers the current enforcement; real client identity and source-scope packets remain required. |
| Discovery selection and names | Retained owner policies take explicit service types. The instance vocabulary can describe `auto-tcp`, but that token is refused by retained policy. Configurable prefixes retain the current suffix algorithm, not an arbitrary predecessor's algorithm. | Extract dynamic type enumeration and exact projected-name construction from the predecessor before claiming parity. Preserve independent direction-specific miss policy and import dependencies. `test_discovery_service_types.py` explicitly proves the automatic-form refusal; `test_discovery_name_prefixes.py` and `test_bonjour_cross_proposal_boundaries.py` cover names, loss, renewal and rejected-source boundaries. |
| Workload provisioning | Recipes support enrolled absolute bind mounts. Named volumes may be described in contracts but cannot be created through the retained recipe path. Socket publication and own-workload memory-backed mount recipes are unsupported. | Capture exact current create arguments and persistent identities, then extract one workload at a time. Socket-path ownership and vendor replacement effects need an explicit model before enabling the option; named volumes need their own recovery handling. `test_contract_definition_facts.py`, `test_workloads.py`, `test_workloads_publish_socket.py` and `test_workloads_vendor_options.py` distinguish descriptive support from refusal at provisioning. |
| Supervisor behavior | The renderer uses a fixed launchd throttle. It has one reserved recovery status and no separate in-guest component repair. Start-call timeouts do not cover the complete action. | Preserve the existing supervisor until its actual launcher, status and component-repair behavior are extracted. Any whole-action guarantee must include lock acquisition, all reads, the vendor call and final verification. `test_instance_supervision_gaps_command.py` reports unsupported declarations; `test_supervision_whole_action_deadline.py` demonstrates the difference from a call timeout; `test_deployment_interval_throttle.py` covers the actual scheduler floor. |
| User control-state trust | The store enforces leaf/directory owner, mode, type, link and descriptor identity. Its contract requires callers to provision protected ancestors; it does not establish complete ACL and ancestor parity merely from POSIX modes. | Compare the predecessor's full trust checks, provision the protected tree and add any missing bounded ACL/ancestor verification before migration. `test_storage.py` and `test_runtime_protected_inputs.py` prove their stated narrower checks. `test_runtime_intent_store_binding.py` proves that an alternate intent file cannot bypass the authoritative pause; it is not an ACL acceptance test. |

## Final correctness corrections (0.4.1)

The historical-handler concern in [#111](https://github.com/mglaeser/network-orchestrator/issues/111)
was reproduced independently against 0.4.0. Six counterexamples put a surviving
historical job in each of the three service domains after re-enrollment or
retained-peer recreation. The previous current-label checks missed all six.
Two further counterexamples established that vendor-runtime startup omitted an
API job in the system domain, including an unreadable system-domain lookup.

The correction supplements current-label checks with complete, bounded domain
inventories and a fresh final absence fence. It rejects any vendor runtime label
that could name the watched guest under a historical handler; dotted-name
ambiguity is refused conservatively. Plugin installation lists and a newly
accepted configuration hash do not prove teardown. Runtime startup now refuses
a loaded or unreadable system-domain API job too.

Executable evidence:

- `test_runtime_historical_jobs.py`: 41 mock cases cover the eight failures above,
  all three domains, late arrivals, retained peers, ordinary successful recovery,
  changed enrollment, denied/empty/malformed/truncated/over-limit responses and
  exhausted observation budgets. The eight core counterexamples failed before
  the correction and pass after it.
- `test_launchd_inventory.py`: closed envelope, count, row, duplicate and boundary
  checks plus actual read-only macOS userspace grammar. The combined 99 tests pass
  locally; the parser has complete statement and branch coverage in that group.
- The existing runtime and PF observation group passes 639 tests (three hosted
  topology checks skipped locally). Deadline scenarios explicitly account for
  the six added inventory reads; no production deadline is increased.

Required macOS CI on the final PR revision remains the merge condition. These
proofs resolve the modeled false-absence defects. They do not demonstrate a
surviving custom-runtime lifecycle on hardware, add support for arbitrary runtime
transitions or authorize native recovery. The same production gates remain in
force after issue closure.

## Repository release closure checklist

1. Record a disposition for every reviewed proposal. For amendments, identify
   the disproved claim and the regression that prevents it returning. Close
   superseded proposal PRs with a link to the tested consolidation; do not count
   their old individual CI as verification of the combined revision.
2. Fix confirmed repository defects, including interacting changes. Run affected
   counterexamples and required final macOS CI on the exact revision to merge:
   supported Python matrix, formatting/lint/types, dependency audit, privacy,
   installed-wheel smoke checks and the existing grammar-only PF checks.
3. Keep release, schema/digest and dependency references consistent. A change of
   transport or discovery meaning must invalidate old authority at the actual
   enforcing boundary; documentation alone is insufficient.
4. Retain source provenance and distinguish synthetic fixtures, mock native
   effects, native parser observations and actual packet/application evidence.
   Refresh the private report without copying private identifiers into the
   public release.
5. Confirm the final merge and release references. An empty PR queue is a
   repository bookkeeping result. Preserve the limitations above and the empty
   qualified platform matrix rather than declaring deployment complete.

## Subsequent installation qualification checklist

The following is a separate operation, not part of repository review or CI:

1. Finish the private source/input freeze, protected-state inventory and
   complete instance. Re-import unchanged legacy input byte-for-byte. Keep
   secrets and current guest/receiver addresses out of desired data.
2. Rehearse recovery from retained material and pin the platform. A runtime
   upgrade or container recreation has its own effects and acceptance; it is
   not concealed in an owner refactor.
3. Extract one owner at a time, retaining its installed names, paths, current
   negative intent and sole-writer ownership. Prove unchanged rendered inputs
   or record each intended difference. Inspect kernel readback where applicable;
   a matching source file does not replace it.
4. Prove withdrawal and state draining, first outbound UDP packet and first
   reply, translation order, range boundaries and DNS client identity. Keep
   foreign PF state, unrelated listeners and vendor NAT outside the owner.
5. Prove discovery in the application's real execution context from cold or
   independently refreshed evidence. A warm reload alone cannot qualify a
   shared scanner. Prove multiple-device selection, record expiry and
   reconnection without treating player state as audible delivery.
6. Complete the applicable heard-audio/visible-video and unattended-reboot
   acceptance, including DNS availability and preserved operator pause. Record
   exact release/platform/profile identity, evidence tier and remaining residuals.
7. Add qualified support only when the required evidence exists. Every applicable
   requirement must be verified, an explicitly accepted residual, or genuinely
   not applicable. An `unverified` row remains unfinished installation work even
   when every repository check is green.

No new implementation language, multicast stack, privilege path or owner rewrite
is required merely to close the review. Future implementation work follows a
specific demonstrated extraction gap and the original one-owner-at-a-time
strategy; native acceptance remains an evidence requirement.

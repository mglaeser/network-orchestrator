# Migration readiness and evidence gates

This is preparation for a future owner migration. It does not approve or perform
one. The current release retains its empty native-qualified platform matrix and
its activation gate. Root privileges, a passing health checkpoint or a complete
plan cannot bypass that gate. Existing networking owners remain installed.

The [migration runbook](migration-runbook.md) describes the sequence. The
[release closure record](reviews/2026-10-08-closure-and-qualification.md) identifies
the remaining implementation/parity limits. The [requirements registry](../src/netorch/requirements.py),
[acceptance schema](../schemas/acceptance-evidence.schema.json) and
[`netorch-host` report/check](instances.md#seven-commands) remain the source of
qualification rules. There is no second acceptance system in this document.

## Three distinct conclusions

| Conclusion | Meaning | Does not mean |
|---|---|---|
| Preparation complete | The bounded change, evidence still needed, health contract, rollback and retirement plan are reviewable | Native work may start |
| Health checkpoint accepted | Every required service/check has matching, fresh evidence for this checkpoint | Root admission, full parity, or physical application acceptance |
| Owner qualified | The applicable existing requirements have evidence at their prescribed tier and method, and the specific migration is authorized | Other owners, hosts, releases or later behavior changes are qualified |

Missing or negative evidence stays visible. `unverified` is unfinished work;
`not-fulfilled` cannot be improved by allowing evidence to grow stale. An owner
attestation is a record with provenance, not an independently replayed native
measurement or an administrative grant. A generic signed exception cannot waive
the mandatory native, lifecycle or application acceptance ladder.

## The private preparation dossier

Keep the following together in the private instance repository or private host
evidence store, as appropriate. Public examples contain only synthetic data.

- Pin the framework artifact, source revision, dependency lock, instance commit,
  contract digests and exact proposed owner change. Record the installed release
  separately; a source checkout or version string is not its identity.
- Inventory every source, generated input, loaded job, publisher, lifecycle
  writer, state file and recovery reference involved. Record source and installed
  hashes independently. Application secrets and pairing material stay outside
  the dossier; evidence contains redacted metadata and content references.
- Include the existing `netorch-host` report/check result, its bound acceptance
  records and the exact unresolved requirements. Do not replace them with a
  hand-authored `qualified: true` assertion.
- Freeze the complete reviewed dashboard roster and its functional checks.
  Keep independent external/client acceptance checks alongside that contract,
  with a baseline, the required pre/post checkpoints for every step, finite
  deadlines and the reaction to failure.
- Name one owner per transaction, dependencies, preserved names/paths, existing
  suspension procedure, predecessor release/input pair, rollback conditions and
  old files eligible for eventual retirement. The plan is inert data, not shell
  commands or a new planner-to-root request channel.
- Link the finite [privilege-session plan](migration-privilege-session.md), the
  notification that will precede native work and the recovery material needed
  if the session ends unexpectedly.

Unmigrated inputs remain authoritative. Their instance sections are generated
views and must re-import byte-for-byte. At the individual owner flip, authority
moves once: the section becomes authored data and the old inputs become generated
output. Never maintain two hand-edited copies while waiting for the next step.

## Concrete gates, using the existing registry

The table groups existing requirements for review; its row labels are not new
acceptance methods. Apply each requirement to every relevant owner/profile, not
just to the first successful example. Required tier and method come from the
registry, not from the migration plan.

| Gate | Existing requirements and evidence | Blocks progress when |
|---|---|---|
| Release and platform | `FRAMEWORK-PIN`, `PLATFORM-SUPPORT`, `HOST-CAPABILITIES`, `LAN-IDENTITY`; exact artifact/lock verification, qualified build/runtime context, `darwin-cli` and `root-runtime-observer` evidence where required | Installed identity differs, support is only parser compatibility, a capability is unknown, or required qualification is absent |
| Single author and names | `SOURCE-AUTHORSHIP`, `OWNER-CONFORMANCE`, `NAMES-PRESERVED`, `RENDER-INDEPENDENCE`; `fixture-parity` against actual installed inputs and the synthetic instance | Source drift is unresolved, a value is underivable, a program search is treated as semantic proof, or a name/path/order changes without a declared change |
| Private data and closed inputs | `HOST-DATA`, `DATA-ONLY`, `IPV4-SCOPE`; canonical closed parsing and both public/private literal guards | Credentials, live guest/receiver addresses or executable configuration appear in desired data; the private guard has only unacknowledged partial coverage |
| Workload preservation | `WORKLOAD-CONTRACTS`, `APPLICATION-PRESERVED`, `COMPONENT-HEALTH`; exact image/init/kernel, mount, resource, network and process-contract comparison | A descriptive fact cannot be provisioned identically, persistent identities differ, or component failure would restart its parent workload |
| Authority and control state | `ROOT-INDEPENDENCE`, `ROOT-ADMISSION`, `PAUSE-PRESERVED`, `UNKNOWN-NO-RECOVERY`; independent root readback, content-bound admission and negative-intent tests | An unprivileged path grants root authority, a changed digest reuses approval, unknown starts recovery, or ACL/ancestor/lock/intent protection parity is missing |
| Supervisor and other writers | `LIFECYCLE-WRITERS`, `CURRENT-OBSERVATIONS`, `NO-EXTRA-WORKLOAD`; `process-inventory`, exact launcher/monitor bytes and `supervision-gaps` | There are two starters, an untracked API client, unmatched throttle/status/whole-action deadline, or an unsupported component-repair path |
| Discovery parity | `DISCOVERY-PUBLICATION`, `DISCOVERY-IMPORT`, `DISCOVERY-LEASES`, `IMPORT-VISIBILITY`, `CONSENT-IDENTITY`; source parity plus the prescribed `application-connect`, `cold-application-scan`/`receiver-change` and `local-network-consent` evidence | Automatic type enumeration or projected names differ, records lack provenance, expiry depends on scan completion, the actual job identity lacks consent proof, or a warm cache is the only application evidence |
| Packet and address ownership | `ROOT-HARD-BOUNDS`, `BOUNDED-IDENTITY`, `UDP-FIRST-PACKET`, `ANY-SOURCE-INGRESS` where applicable; `first-packet`, `state-drain` and `external-first-packet` | Rule/state withdrawal is unproved, address generation changed, source scope differs, or a parser result is offered as packet evidence |
| Port and coexistence limits | `PORT-RANGES`, `PORT-COLLISIONS`, `PORT-BUDGET`, `COEXISTENCE`, `RUNTIME-DNS`; declared/live range equality, `port-budget`, `rule-readback` and appropriate `darwin-cli` evidence | A range widens, a publication/listener collides, native DNS assumptions change, or foreign rules/listeners are affected |
| Recovery and application results | `RESTORE-REHEARSAL`, `OWNER-ROLLBACK`, `BOOT-RECOVERY`, `DNS-CLIENT-IDENTITY`, `HEARD-AUDIO`, `MULTI-RECEIVER` as applicable | Recoverable material or a rehearsed restore is missing; DNS loses client identity; unattended recovery, actual sound or representative receiver capacity is unverified |
| Health and retirement procedure | Full [health contract](migration-health.md), `CURRENT-OBSERVATIONS`, `EXIT-STRATEGIES` and the runbook's reference checks | Any vital check is missing/stale/unknown/degraded, rollback cannot be completed within its declared envelope, or an old artifact still has a live/durable reference |

Readiness is not improved by deleting an applicable requirement, removing an
unhealthy service from the roster or replacing an unavailable observation with a
saved green value. The original baseline and all unsuccessful attempts remain
part of the private evidence history.

## Known extraction gaps must close before their owner moves

The retained implementation is narrower than the existing-instance vocabulary
in several areas. The release closure record is authoritative for the current
list; these are concrete preparation tasks, not permission to work around it:

- Reconcile installed/tracked source differences and protected active state.
  Neither a filename nor matching text from an obsolete tracked copy is enough.
- Resolve direct DNS source-scope differences explicitly while preserving client
  identity. Do not substitute a host-port fallback as an unnoticed redesign.
- Extract dynamic `auto-tcp` selection and exact projected-name construction
  before replacing an owner that needs them. Preserve distinct import/export
  loss policies and the actual existing dependencies. Inward discovery must not
  acquire an audio-return dependency solely because an example has one.
- Preserve named volumes, socket publications and memory-backed mounts without
  guessing unsupported create options. A contract that describes them does not
  create the required ownership, deletion-safety or recovery handling.
- Preserve the existing launcher throttle, reserved statuses, component repair
  and complete-action timing contract. A vendor subprocess timeout cannot stand
  in for a complete transaction deadline.
- Establish full control-state ACL and ancestor trust rather than inferring it
  from private leaf modes. Verify the predecessor's protection in context.

The smallest justified implementation change is extraction of the affected
existing owner, with its inputs unchanged. A new root implementation, native
Bonjour adapter, daemon, language, broad reflector or general privilege channel
does not close these gaps by itself.

## Health coverage before and after every step

Freeze the complete reviewed dashboard roster before migration, including all
vital services and the reviewed device/webpage sentinels. Keep the dashboard
itself and its existing health backend covered. Do not introduce a second
collector. Independently compare the roster with the actual catalog: a contract
cannot detect a service omitted from both it and its recording. Add separate
acceptance records for user-visible paths and required components that the
dashboard cannot prove. Marking a tile green is not a replacement for the check
contract beneath it.

The following table covers the overall readiness dossier, not just the dashboard
contract's JSON fields. Native and application records remain in the existing
acceptance ledger and are evaluated by their prescribed methods.

| Health layer | Minimum readiness/acceptance evidence alongside the dashboard contract |
|---|---|
| Runtime and workload | Current complete observation, correct enrolled definition and generation, required process/component availability |
| Service function | The service's established authenticated health/API response where applicable; intended listener/publication identity; bounded current response |
| DNS and ingress | DNS answers over required transports from the client side; ingress route/certificate/application response through the intended path, not only a host listener |
| Discovery and automation | Real application entities/connections and required discovery records, distinguished from cached state; component availability separate from parent-container state |
| Media and external clients | Passive availability at routine checkpoints; separately coordinated audible/visible evidence only for the acceptance that actually requires it |
| Management access | Dashboard plus independent administration path and existing native services remain reachable through their own established checks |

The [offline checkpoint evaluator](migration-health.md) reads a saved actual
dashboard API response inside a closed recording envelope. It does not run
these probes, repair a service, collect credentials, play audio or qualify a
host. The snapshot binds the contract (which binds the private plan), step,
phase, generation and observation times. Dashboard coverage must match that
pinned contract; individual values cannot be silently filled from an older
snapshot. A passing result does not authenticate the recording or verify the
independent native/application records. Those are additional checkpoint gates,
not claims made by the evaluator.

Every executed migration transaction needs a fresh pre-check and a fresh full
post-check, including after a failed attempt, retry or rollback. An intended
temporary outage inside a transaction is logged as such; it is not a successful
post-check. A step is complete only after the required services return healthy
within their declared bounds. Existing degraded vital services block the start;
they are not grandfathered in as successful baseline evidence.

## Evidence that must remain native

CI provides pure, mock/process and named userspace-parser evidence. The following
must be recorded separately for the specific release, platform and profile:

- Actual root-owned rule/readback and state invalidation, including both state
  directions and no leakage to a reallocated non-target guest after invalidation.
- An outbound UDP first request/reply with unchanged destination and preserved
  source port, plus both admitted-range ends and just-outside probes. Use a
  responder path that does not accidentally exercise the DNS redirect instead.
- Genuine cold/refreshed shared-scanner discovery, receiver change or a new
  receiver, exact launch-context consent, expiry and reconnection. A standalone
  discovery library run and a warm integration reload do not establish this.
- Client-preserving DNS, application behavior and coordinated heard/visible
  media where required. A completed service call or playing state is weaker.
- Unattended reboot, earliest valid DNS response, restored workload ownership and
  preserved pause, plus a rehearsed restore from the retained recovery copy.

Unchanged rendered PF bytes on an unchanged accepted platform need not trigger
redundant packet tests merely to compare renderers. A changed policy, owner
meaning, platform or unresolved native gate needs its appropriate acceptance.
Evidence is never manufactured to satisfy a checklist.

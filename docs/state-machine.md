# State, admission, and transition contract

Netorch coordinates existing owners. The planner is pure and the executor is an
unprivileged client. A plan cannot grant privilege. The packet implementation,
live identity read, protected admission and retained-state cleanup remain the
platform owner's responsibilities.

## Evidence has three states

| State | Reason | Meaning |
| --- | --- | --- |
| `present` | `verified` | A complete read verified the described resource. |
| `absent` | `confirmed-absent` | A complete read verified absence; retained packet states are separately reported. |
| `unknown` | A closed uncertainty code | The reader cannot establish present or absent. |

Unknown reasons are `incomplete`, `malformed`, `inaccessible`, `timed-out`, `busy`,
`stale`, `future`, `local-network-denied`, `identity-mismatch`,
`generation-mismatch`, `unobserved`, and `unavailable`. Adding a reason requires a
model/version change; it never silently adds a recovery branch.

Every observation includes an epoch timestamp, an instance-generation identifier
when established, and JSON data. Data is deeply copied and frozen. A snapshot
binds the individual observations and the guest-network generation. The canonical
snapshot digest includes all evidence and timestamps.

Age greater than a profile's maximum makes evidence unknown. A timestamp in the
future is also unknown. Missing observations are unknown. A successful command
with truncated, unsupported or unproven empty output cannot establish absence.
Readers and platform adapters must enforce that last requirement.

Unknown never initiates activation or workload recovery. This planner chooses
the conservative option of retiring a known exposure at the first unknown
identity. `unknown_limit` is the maximum retry tolerance permitted to an
independent owner, rather than a promise that this planner retains an exposure
for that many passes.

## Admission binds content

Admission is `{profile, digest, approved_by, approved_at, risk_acknowledged}`. The
digest covers the resolved profile, scope, service contract and owner, plus the
schema and digest versions. Changing a port, interface, address, capability,
contract, protocol or safety statement invalidates admission. Identifiers alone
never constitute admission. Future approval timestamps inhibit activation.

Direct guest targets require a bounded safety declaration and an explicit risk
acknowledgement. They do not claim that periodic observation can eliminate the
address-reuse race. A host redirect uses a structural host socket target, while
still requiring its service identity to be verified. A host redirect declared
with an unrestricted source is planned only while its admission also carries
the acknowledgement; without it the profile stays `risk-unacknowledged`.

An external-root owner must obtain its own protected admission and observe its
own target. Copying this user-space admission document into a root job is not a
privileged installer. The built-in executor introduces no `sudo`, `pfctl`, or
privileged reconciliation RPC path. An explicitly bound user adapter is trusted
operator-selected code and must independently stay within its declared user
privilege; a declaration alone cannot prove arbitrary code is unprivileged.

## Pause is independent of operation ownership

`Intent` has a monotonically increasing revision, an operator pause, an
operation-to-holder suspension map, and a damaged flag. It is stored outside the
installed release directory.

| Operation | Effect | Preserves |
| --- | --- | --- |
| `pause` | Sets the operator pause; increments revision on change. | Every owned suspension. |
| `resume` | Clears only the operator pause; increments revision on change. | Every owned suspension. |
| `suspend(operation, holder)` | Adds the named suspension; another holder cannot replace it. | Operator pause and other suspensions. |
| `release(operation, holder)` | Removes only that holder's matching suspension. | Operator pause and other suspensions. |
| Reopen/reinstall | Reads the durable state without resetting it. | All intent. |
| Unreadable/old-format/unknown-version state | Effective pause with `damaged=true`. | A requirement for explicit owner repair. |

The effective inhibit is the union of operator pause, any suspension, and damage.
Nothing expires by elapsed time. A process crash cannot clear a suspension.
Determining that a dead holder can be removed is a platform/operator decision;
there is no age-based automatic release.

## Pure profile decisions

The planner considers current policy, exact admission, intent and current
evidence. It emits ordered `Action` values containing profile, owner, operation,
reason, and any established target address/generation. Root actions are data for
an independent owner, never an invitation to escalate.

Service observation ownership and profile mutation ownership are distinct. A
profile may select its owner explicitly; otherwise it uses the service's owner.
This lets a user manager own a native publication and a separate protected owner
own the redirect without letting either fabricate the other's readback.

| Condition | Decision |
| --- | --- |
| New profile, complete absence and no exact admission | `pending`; no activation. |
| Operator paused, suspended or damaged | Inhibit activation; retire any established exposure. |
| Service absent or unknown, stale/future snapshot, missing network generation, changed contract or invalid endpoint | Inhibit activation; retire any established exposure. |
| Profile readback unknown or incomplete | No activation and no verified readiness. |
| Structural host redirect's corresponding publication is missing, gated or unverified | Inhibit the redirect until the actual same-service publication verifies readiness. |
| Verified profile absent but retained states remain | `drain` only. |
| Existing profile policy/target/service generation/network generation changed | `withdraw`, then `drain`; no replacement activation in that plan. |
| Exact admitted profile, verified current service, complete rule absence and verified empty states | `activate`. |
| Exact profile and target verified by current readback | `noop`; this is the only discovery-ready result. |

If a readback is unknown and no verified owned target was retained, the framework
cannot invent an address to drain. It remains blocked. The independent platform
owner must implement fail-closed withdrawal of its own rules under this condition
and establish ownership before touching retained states.

Retirement retains the old observed target and generation. A second fresh read
must show the old rule absent and its retained states empty before a replacement
can activate. Merely removing a rule or changing a receipt does not establish
that packet states are gone. Which states are retained states of a profile is
the owner's definition: for the [PF owner](pf-owner.md), those that the
withdrawn rule itself can have created.

Discovery dependencies require `Plan.ready_profiles`, which contains only
verified `noop` profiles. Planning or completing a write does not by itself
authorize advertising its endpoint. The owner must publish new readback first.

## Discovery coordination

`plan_discovery` emits `DiscoveryAction` values for the independent user discovery
owner. Each action carries its scoped policy identity, active/inactive intent,
closed reason, a resolved policy digest, the service generation and the network
generation. The digest binds the discovery policy, scope, service and owners,
plus every resolved transport dependency. Runtime generations are carried
separately; a static policy digest cannot prove that today's guest is the same.

Activation requires current service identity/contract, fresh snapshot evidence,
verified transport `noop` dependencies, and a complete publisher observation
with `interface_confirmed=true`. Both absent and present publisher observations
must describe the current service and network generations. A stale or missing
generation is inactive cleanup intent. Missing, timed-out or otherwise unknown
publisher evidence is likewise inactive; the owner cleans up its scoped leases
and reports complete absence before a later fresh cycle can enable publishing.

An existing publication whose digest or runtime generation changed is withdrawn
first. The executor does discovery work before transport mutations so forwarding
cannot be torn down while its publication remains deliberately enabled. New
transport policy cannot enable a publication in the same cycle: another complete
readback must verify that transport first.

The executor validates the publication state, exact discovery digest and exact
runtime generations after reconciliation; active readback also requires the
confirmed interface. A failed readback leaves a failed journal and prevents
later transport writes. Successful-empty output and a status exit code cannot
substitute for this record. No discovery action confers root authority or
performs pairing, playback, application configuration or workload recreation.

## Execution journal

Execution has one operation lock and durable writes. A busy lock inhibits work;
it is not removed, stolen or treated as a workload failure. The state store uses
private owner files, rejects final-component symlinks and hardlinks, writes a
temporary file with `fsync`, atomically renames it, and `fsync`s the directory.
Its ancestor tree is an explicit operator provisioning responsibility.

The journal's finite phases describe coordination, not the workload's lifecycle:

| Phase | Meaning | Allowed next step |
| --- | --- | --- |
| `planned` | A reviewed, fenced plan is durably recorded before its first owner call. | Apply a permitted user action or hand off an external action. |
| `applying` | An action is recorded before the owner is invoked. | Record verified completion; otherwise stop with incomplete evidence. |
| `failed` | An exception, failed readback or interrupted action prevents further writes. | Explicit phase-aware inspection and recovery. |
| `waiting-external-owner` | An independent owner must perform an action; no privileged call was made. | Obtain fresh owner readback and construct a new plan. |
| `inhibited` | Admission, evidence or intent gates leave the plan unresolved. | Resolve the gate and construct a new plan; no completion receipt is written. |
| `committed` | The executed actions and their owner readbacks completed. | Observe again for actual status; a receipt is not live truth. |

There is no speculative automatic rollback. A journal in `planned`, `applying` or `failed`
blocks a subsequent execution until the operator examines the actual owner state
and records a recovery decision. A crash after a mutation but before completion
is therefore visible. Reapplying old policy against a reused address is not a
safe generic rollback.

The journal records the full reviewed plan, the initial evidence and the durable
intent. It retains old target addresses and generations across a later source
change. Unsupported versions and phases inhibit execution. Before writes, the
executor compares durable intent under its lock and re-derives the operations
from current admissions and evidence. A changed action list invalidates the
reviewed plan. A live owner must supply fresh observation; stale caller evidence
is sufficient only for an explicitly simulated run.

Receipts identify completed policy/plan hashes and whether the clients were
simulations. They never prove that today's kernel state, listener or discovery
registration is healthy. In particular, a simulation receipt cannot certify a
platform deployment.

## Platform handoff and acceptance gates

A real adapter must independently validate scoped ownership, endpoint identity,
current network generation, exact admitted content and retained states. Its
transport must not expand privilege or let configuration select executable
commands. A result must establish full target/policy readback, not merely return
an exit status or a `present` label.

Public CI exercises models, bounded readers, local process fixtures, mock
owners, failure injection and state interleavings. It does not certify Darwin
packet semantics, network privacy consent, address allocation, audible playback,
simultaneous receivers or unattended reboot recovery. Those remain separately
authorized platform acceptance with a rehearsed recovery path.

The implementation's tests include exact admission mutation, independent pause
ownership, damaged intent, random pause/suspend/reopen interleavings, missing and
stale evidence, old generation retirement, retained-state drainage, and the
external-root no-call boundary. They deliberately test decision behavior rather
than claiming that a mock implements a real operating system.

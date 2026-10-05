# Review requirements and evidence

The design implements the independent architecture review without distributing its
private site facts, addresses, ownership statements, credentials or captures. The
concern IDs below preserve review traceability. They describe framework contracts,
not a claim that a particular production installation has passed acceptance.

## Benchmark goals

| Goal | Evaluation | Blocking failures |
|---|---|---|
| Highly robust | Identity-fenced readback, bounded uncertainty, lease expiry, interrupted-operation recovery | Wrong target, unbounded stale exposure, lost negative intent |
| Easy to maintain | One author per setting, explicit module/owner boundaries, standard deployment artifacts | Duplicate authority, hidden dependencies, implicit privilege escalation |
| Well tested and optimized | Pure/property/process tests, injected failures, measured native behavior and no-op passes | Mocks presented as packets, unbounded subprocesses, unnecessary rule reloads |
| One coherent setup | Shared policy/status and generated launchd/Monit deployment | One all-powerful daemon replacing independent authority |

Correctness and admission are gates, not a weighted score. Simpler code or a lower
process count does not compensate for any blocking failure.

## October 2026 review: D1–D8 and rules 1–9

The later review reduces this release to read-only extraction. No host is declared
fully served, and no owner is parameterized on production. The source/installed
contract and right-tier native acceptance must exist before that next stage.

| Review rule | Implemented boundary | Regression evidence / remaining gate |
|---|---|---|
| D1: no host data | Public generic guard plus each private instance's own-value guard; diagnostics omit values | `test_privacy`; only exact file/kind/reason exceptions, never private trees |
| D2: data only | Canonical closed instance and contract schemas, fixed names/versions | `test_instance`; no scripts, paths-as-code, PF text, expressions or live endpoint fields |
| D3: one-way pin/root | Artifact/revision/lock pins, independent root semantics; host verbs never call owners | `test_host_cli`, `test_pf_owner`, `test_workflow_gate`; native root install deferred |
| D4: pinned names/order | Namespace derivation or explicit current names; order is observed, not presumed | `test_instance`, `test_macos_preflight`; actual kernel order still requires native evidence |
| D5: observed capabilities | Fixed bounded local collector, per-fact state/reason/time; inaccessible remains unknown | `test_macos_preflight`, `test_host_cli`; no sudo, LAN/Bonjour calls or credentials |
| D6: qualified support | Candidate build/runtime separate from empty accepted matrix; public mutation refused before effects | `test_workflow_gate`, `test_requirements`; a real host's acceptance is still absent |
| D7: requirements | Stable registry/applicability/proving tests and context-bound retained evidence | `test_requirements`, `test_host_cli`; owner attestations are not replayed native tests or root approval |
| D8: narrow scope | One IPv4 LAN, named constants, no multi-host/plugin/generalized OS support | `test_instance`; synthetic second host is validation evidence only |
| Rule 1: single author | Static import, canonical generated view, complete source/byte conformance, provenance-only flip | `test_legacy_import`, `test_conformance`, `test_instance`; underivable inputs block migration |
| Rule 2: content admission | Existing root resolved-content/code binding retained; new public admission unavailable | `test_pf_owner` single-field/range/input-swap regressions; actual installed contract remains host evidence |
| Rule 3: no root call | Host read-only command has no owner/executor path; existing independent pull retained | `test_host_cli`, `test_cli`, `test_pf_owner`; no new sudoers/RPC interface |
| Rule 4: bounded risk | Explicit T/K/residual; conservative withdrawal-bound report and model allocator | `test_safety_contract`, `test_pf_owner`; scheduler/read/apply bounds and native re-deal remain unverified |
| Rule 5: negative intent | Independent durable operator pause and holder records, fail-closed reads, no TTL | Existing state/property/install tests; real crash/reboot/restore remains a host gate |
| Rule 6: unknown | Three aged states and closed reasons, no unknown recovery, reserved status 42 | Reader/process/supervisor tests; no physical recovery qualification |
| Rule 7: no new LAN tool | Six host verbs read local data only; collector fixed commands | `test_host_cli`, `test_macos_preflight`; new consent identity/adapter deferred |
| Rule 8: genuine Bonjour | Retained publication/record/interface/callback/lease fencing | `test_discovery`, `test_bonjour_owner`, process fixtures; genuine cold shared-scanner acceptance unrun |
| Rule 9: measured range | One named range referenced by workload/PF selection; no automatic widening | `test_instance`, `test_pf_owner`; occupancy, exhaustion, collision and first replies require native measurement |

The review cited an older containerization tag; the platform contract records the
actual dependency of Container 1.5.0 as 0.47.0 and links its manifest and allocator.
The FIFO test is source-model evidence, not a run of the allocator on hardware.
No old-version fixture or parser success qualifies a runtime upgrade.

## Earlier C1–C10 implementation map

| Review ID and concern | Implemented response | Portable evidence | Native/site gate still required |
|---|---|---|---|
| **C1: addresses versus service identity** | Definition/persistent-mount enrollment, helper/boot/instance generations, independent root observation; retire old rules and guest states before later replacement; explicit bounded-risk declaration | Reader races/timeouts/drift, retained-state and interrupted-write fake backend tests | Shared-pool reuse, helper/runtime restart, real state invalidation; absolute exclusivity requires a separately reviewed structural network |
| **C2: desired data becoming root authority** | No coordinator→root execution; fixed root pull job; protected descriptor capture; independent admission binds resolved policy plus observer/backend/implementation semantics | Single-field mutation, input swap, changed code/contract pending, user-root action rejection, protected-report tests | Administrator-owned interpreter/code/ancestors and installed owner acceptance |
| **C3: pre-login DNS/runtime outage** | Login/session availability remains explicit; generated start/monitoring chain reports unknown and cannot invent pre-login runtime availability | Job generation and guarded proven-stopped recovery tests | Site chooses login/resolver architecture; separately approved unattended reboot measures first valid DNS answer and client identity |
| **C4: runtime security and stale reader fixtures** | Explicit accepted version and versioned JSON shape contracts; unsupported shape/version fails closed; no automatic upgrade/recreation | Synthetic nested and flat CLI fixtures, definition/enrollment drift and changed-schema tests | Operator reviews current upstream advisories and performs separate runtime/Socktainer/kernel upgrade and application reacceptance |
| **C5: pause versus operation suspension** | Durable operator pause outside releases; holder-owned independent suspensions; effective union; no TTL; rollback preserves current intent | Stateful pause/release/crash tests, failed upgrade/rollback and journal recovery tests | Real job/owner crash and restoration rehearsal |
| **C6: unknown is not absence or recovery** | Three aged observation states and closed reasons; no unknown start; Monit recovery only on reserved proven-stopped status 42; discovery requires verified transport | Empty/truncated/denied/timeout/busy reader tests, wrong argument fixtures, Monit generation and runtime probes | Actual Monit termination/timeout behavior and service-owner readback |
| **C7: catalog adds a second source** | Literal-only derivation, cross-owner lint, immutable captured settings; per-owner authority flip with old input generated | Derive byte equivalence, duplicate-key/schema/invariant tests, deterministic bundle/render validation | Site inventories sources and removes dual editing during promotion; arbitrary scripts are not sourced |
| **C8: user Local Network privacy** | Native CLI strategy, explicit user job identity, distinct denial reason; no root consent workaround or new compiled adapter | Denial/interface/parser/process fixtures, generated LaunchAgent contract | Actual user LaunchAgent, SSH and Monit launch contexts; cold login/rebuild consent |
| **C9: listener, exit status and completed pass are weak evidence** | Exact announcing-service publication provenance; owned address and nonzero interface; exact service+A callbacks; binary TXT; independent monotonic lease watchdog and child/parent exit cleanup | Numeric collision/ambiguity, unknown-interface exit-zero, binary/empty TXT, multi-device projection, frozen scanner/backward clock, child failure isolation | Native browse/resolve/register parity, interface replacement, lease withdrawal and application reconnect |
| **C10: bounded UDP range and capacity** | Live guest allocator range equals admitted range; static-port outbound NAT plus target-less inbound RDR; no automatic widening; receiver-independent LAN scope | Range equality, out-of-range rule rejection, full split rule fixtures, allocator read contracts | Actual first request/reply, port exhaustion/collision and measured simultaneous-receiver socket use |

C10 is deliberately not marked completely proven by static checks. The framework
checks the declared/live range and prevents authority expansion; real socket
occupancy and collision behavior require the declared native test. Similarly,
versioned fixture coverage does not establish current runtime security or promise
forward compatibility with future releases.

## Evidence tiers

1. **Pure/model:** canonical policy, admissions, state transitions, derivation,
   projection and invariants.
2. **Mock/process:** real owner/installer control flow against fake tool effects,
   exact reader formats, subprocess lifecycle and protected temporary files.
3. **Native packets/discovery:** actual OS/version tools, interface identity, PF
   hooks, first/reply packets, state draining and user consent.
4. **Lifecycle:** approved crash, recreation, runtime change, reboot and restore.
5. **Application/person:** discover/reconnect and an explicitly coordinated audible
   or visible result.

Public CI establishes tiers 1–2. It does not establish production Bonjour parity,
physical routing, client identity, Home Assistant connection or audible playback.
Record each site result with versions, exact policy/release digests, evidence tier
and unrun gates. See [testing](testing.md).

## Selected and deferred tools

The reviewed path retains native Apple Container, PF, DNS-SD and launchd plus
maintained Monit. Typed Python provides strict closed data, deterministic planning,
bounded CLI readers, independent owner control flow and standard packaging. A
small Bash backend confines fixed native PF mutation. These are executable
components, not empty adapter interfaces.

A compiled Swift, Go or Rust rewrite is deferred: it would add toolchain,
review/maintenance and potentially signing/consent obligations without removing
native semantics or privilege boundaries. A second mDNS stack, general reflector
or VM helper is not required by the selected-record contract. No third-party tool
is accepted merely because it has overlapping features.

Reassess retirement at every accepted runtime upgrade. A supported physical-LAN
mode could replace return forwarding and discovery projection; exclusive address
allocation could remove identity chasing; reliable events could replace polling;
supported pre-login startup could remove a DNS availability workaround. Accept
an alternative only if it covers the full contract and passes the matching tiers.

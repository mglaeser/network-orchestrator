# Integrated readiness review, 9 October 2026

Baseline: `de4cbb520a960266360f00722b3a89e2426c00d3` (0.4.2).
This review inventories all 119 PRs then present, reviews the seven new heads
#121–127 and the later #77/#78 interaction comments, and checks their combined
behavior against the repository's existing-instance requirements. Previous PRs
retain their recorded dispositions; the complete regression suite checks their
current combined implementation. This is not a claim to have re-proved every
historical patch independently. Exact heads and individual dispositions are in
[the ledger](2026-10-09-readiness-ledger.json).

## Goals and decision rule

Robust identity and privilege boundaries come before uninterrupted availability.
Maintainability means retaining existing independent owners and using existing
intent, journal and settings contracts. Tests must exercise real boundary code
and counterexamples, with native evidence distinguished from mocks. Instance
values stay private; public examples remain synthetic. Repository closure is
not native qualification or permission to migrate an existing installation.

An expected-failure test proves that its asserted alternative is not implemented;
it does not prove that the alternative is safe or required. The readiness PRs
contain useful reproductions but also proposed policy choices. They are resolved
individually below, rather than shipping 25 expected failures as an accepted
future specification. Unsafe alternatives are declined; real parity and native
gaps stay explicitly blocking in the existing readiness documents.

## Integrated changes

| PR | Disposition and independent evidence |
|---|---|
| #121 | Adapt and incorporate the bounded export alias reread. [Apple's client](https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-2881.120.11/Clients/dns-sd.c) can exit at its first answer with no MoreComing flag; an alias-only answer loses the inspected guest under the old reader. The new suite exercises address permutations, malformed output, interface identity, unrelated publications and deadline exhaustion. No native alias timing is claimed. |
| #122 | Adapt and incorporate per-record failure backoff. Also repair real OS exceptions missed by its mock: four Popen failure classes caused 20 attempts in five seconds instead of three bounded attempts. Normalize setup/read OS errors to the existing failure class, reap partially constructed children and retain sibling/backoff state. |
| #123 | Partially implement R-U3 loaded endpoint/socket rechecks; retain documented safety contracts and native blockers for the other flags. Do not defer address invalidation on an unknown owner, or silently weaken address-wide cleanup. |
| #124 | Implement R-N8 loaded coexistence rechecks. Keep fresh-pass DNS transition fences, conservative unknown handling and complete state-read requirements. Resolver functional health remains separately unqualified. |
| #125 | Implement an optional, independent durable runtime-start attempt budget, document trusted native executable prerequisites, and adopt scoped native procedures. Do not promote residuals into verified safety or add executable manager commands to instance data. |
| #126 | Retain the useful discovery limits and qualification blockers; decline unsupported relaxation of interface, generation and journal barriers. Record exact decisions below. |
| #127 | Incorporate accurate drain, late-hold and workload-budget documentation with passing characterization tests. Extend the runtime-budget wording to distinguish the new explicit optional budget. This also addresses the later #78/#77 interaction comment. |

Discovery behavior now uses digest version **6**. Older candidate leases,
requests, endpoint actions and readback are rejected, including version 5.
Without that correction, #121/#122 would reuse approvals for changed semantics.
PF admissions already bind all implementation modules; the new loaded checks
therefore invalidate an old implementation approval. No setting or root grant
is widened. Existing settings without `start_budget` retain their bytes and
meaning; no default budget is invented for a host.

Loaded PF endpoint checks are deduplicated within a bounded batch and re-run on
every pass. An early failed direct endpoint uses the existing withdraw-then-drain
journal; a failure first observed at final readback withholds readiness until the
next pass. A socket conflict withholds readiness rather than surrendering the
UDP first-packet path. Backend reads remain individually bounded; this does not
close the separate whole-action deadline qualification gap.

## Discovery findings

| Flag | Verified fact and final disposition |
|---|---|
| R-D1 | Confirmed alias-first export loss. Fixed through #121 plus digest 6. |
| R-D2 | Confirmed rapid registration retry. Fixed through #122 plus real OS failure handling and digest 6. |
| R-D3 | Confirmed fifth unusable instance fails its type scan. Retain the bounded default; broadening tolerated unanswered input is a measured deployment choice, not justified by a synthetic busy network alone. Discovery parity remains required. |
| R-D4 | Automatic announced-TCP enumeration is missing. Existing extraction/parity blocker remains; a fixed allowlist is not declared equivalent. |
| R-D5 | Publication ownership is proved, independent listener health is not. A listener alone cannot establish identity or application health. Preserve exact own-publication selection and require application-connect qualification; no new probing authority is inferred. |
| R-D6 | Renewal can have a gap; optional overlap already exists. Native registration continuity and consent are unverified. |
| R-D7 | A syntactically valid lease need not retain records for the requested number of slow passes. Document the lease/pass/carry relationship; qualify real timing instead of widening leases implicitly. |
| R-D8 | Only the announcing guest's URL endpoint is rewritten. A URL naming a different guest remains as announced. Blind rewriting would invent identity; repair/declare the source or prove a profile-specific rewrite before migration. |
| R-D9 | Guest-interface absence withdraws projections. Retain current interface/address proof; do not preserve exports on uncertain topology. |
| R-D10 | A new guest generation requires fresh coordinator intent after cleanup. Retain the fence; an old generation request is not authority for the replacement. |
| R-D11 | Independent import is already explicit. Its visibility/health does not prove an audio return path. |
| R-D12 | Projected-name derivation can differ from the predecessor. Exact name parity remains blocking; do not rename existing accessories as a side effect. |
| R-D13 | The scanner's runtime read remains bounded at eight seconds. Actual timing/conformance must be measured; a slower former owner does not authorize unbounded reads. |
| R-D14 | A renewal with no currently confirmed client can cause coordinator cleanup. Retain truthful unknown status and existing protocol. Qualified overlap may address availability, but unknown cannot become present. |
| R-D15 | Unconfirmed or wrong-generation discovery readback leaves a failed journal. Confirmed behavior, but blanket pending treatment is rejected: it would silently relax the owner protocol. Any narrower deferred-state design must separately prove expiry, cancellation, fresh generations and recovery after every write phase. |

## Packet, DNS and lifecycle findings

| Flag | Verified fact and final disposition |
|---|---|
| R-U1 | Unknown-driven retirement may invalidate all states of the guest address. Retain cleanup of both directions; delaying it without a reviewed bounded identity decision can retain traffic to a reused address. |
| R-U2 | A failed invalidation blocks this owner's other profiles. Retain conservative journal isolation. Per-address partial commits need a separately proven recovery design; not a small retry change. |
| R-U3 | Loaded pairs previously skipped endpoint/socket rechecks. Fixed with bounded rechecks and negative readiness; no native packet claim. |
| R-U4 | A reused old address can keep a pair retired and can incur address-wide state invalidation. Retain the conservative gate; safe selective state identity is not established. This availability/foreign-flow residual must be accepted or the architecture changed before migration. |
| R-U5 | Fixed media ports outside the configured range are not covered, but the cited receiver timing service does not prove this sender needs them. Applicability is unverified; capture the actual path before any range change. |
| R-U6 | Rendered rules and successful calls do not prove audible output. Historical audible confirmations exist and must not be denied; they do not qualify this exact candidate. Current release still needs first-packet and heard-audio evidence. |
| R-U7 | An unfamiliar zoned IPv6 state row can make the complete listing unknown. No trustworthy native fixture supplied. Retain strict parsing; qualify observed grammar before extending it. IPv6 is outside custom policy, not asserted blocked. |
| R-N1 | Direct/fallback switching has a rule-free pass. Retain drain plus later fresh identity; same-pass substitution is not proven safe. |
| R-N2 | A timed-out runtime read does not newly activate a DNS fallback. Retain unknown-no-activation; keep-host-paths only retains eligible already loaded host paths. |
| R-N3 | Same-address restart still changes generation and requires a fresh pass. Retain the fence; address equality is not instance identity. |
| R-N4 | An incomplete/oversized/timed-out state listing withdraws all owned rules. Retain conservative unknown handling. Partial owner availability requires a separate journal/state attribution design. |
| R-N5 | LAN-only DNS source scope is a known parity difference where the predecessor accepts other sources. Resolve explicitly per profile; no silent widening. |
| R-N6 | Pause withdraws owned DNS as well as other rules. Preserve negative intent; use existing scoped holds only where their contract fits. |
| R-N7 | Runtime health does not ask a functional DNS question. Preserve separate component health and require client-side DNS/dashboard checks before each migration step. Do not infer permission to restart a resolver from packet health alone. |
| R-N8 | Loaded host rules previously skipped listener/coexistence rechecks. Fixed, including DNS coexistence at final readiness. |
| R-O1 | Native mutation remains gated and qualified platforms empty. Retain; source completeness and green CI do not open the gate. |
| R-O2 | Candidate platform/version is not observed installed backend identity. Exact runtime/Socktainer alignment and native qualification remain separate migration prerequisites. |
| R-O3 | Root observation refuses user-replaceable CLI/helper executables and ancestors. Intentional security boundary. Document trusted installation and caller reconciliation as a separate runtime change, not an automatic chmod or reinstall. |
| R-O4 | Native procedures lacked per-requirement coverage. Adopt the corrected procedure inventory with a registry coverage check. No procedures were executed. Bounded identity, import visibility and API writer residuals never become absolute verified safety. |
| R-O5 | Values embedded in consuming programs still need extraction/conformance. Static literal inventory alone is not proof. Existing parity gate retained. |
| R-O6 | Component repair inside a guest is not implemented. Existing component-health/repair parity gate retained; do not restart the parent or introduce arbitrary commands. |
| R-O7 | Manager-specific workload-start hooks lack vocabulary/parity. Do not introduce executable hooks into data. Migration of an affected owner remains blocked pending a narrowly extracted existing contract. |
| R-O8 | Workload restart budgets did not bound vendor-runtime attempts. Add explicit `runtime_start.start_budget`, a separate durable counter and existing-format supervisor suspension. Record attempts before effects and reject damaged state; no new privileged path. |

## Proof, limitations and release

The original combined proposal branch was green partly because 25 proposed
alternative expectations were marked xfail. Independent execution with
`--runxfail` reproduced the documented assertion failures; those are evidence of
current behavior, not approval of each proposed alternative. The narrow U3/N8
counterexamples pass after repair. New passing regressions cover OS registration
errors, partial child cleanup, runtime budget/clock/storage/intent failures,
loaded PF preconditions and old discovery approvals. The full suite retains
existing unknown, pause, privilege, packet-rendering and recovery proofs.

No dependencies or Actions changed. Final exact-revision macOS CI, build and
release results are recorded in the integration PR and release. Privacy checks
use synthetic public data and a separately classified private known-value subset;
a partial private inventory is never called complete. Existing private source,
dashboard template and backend pins were compared locally without authentication
or native changes. The private dossier carries those results.

The migration-health evaluator and preparation remain reasonable offline tools:
closed roster/time/generation checks cannot authenticate a saved dashboard result.
No privileged migration runner was added. The first authenticated window must
still bind exact reviewed operations and recovery; it cannot promise reusable
privilege after session death, reboot or changed root code.

Remaining parity, native packet/discovery/application, all-service health,
recovery/restore and unattended-boot gates remain in
[migration readiness](../migration-readiness.md), the
[closure record](2026-10-08-closure-and-qualification.md) and the
[native procedure inventory](../native-qualification.md).
Closing these PR discussions records decisions, not completion of those gates.
No installed owner was replaced, no container restarted, and no audio played.

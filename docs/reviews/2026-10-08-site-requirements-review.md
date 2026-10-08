# Site-requirements review, 8 October 2026

This review starts at `c419a62` and examines the exact heads of proposals
#24–109 together, including their integration resolutions at `b067431`.
All 109 existing PRs were enumerated with pagination. The 23 older PRs remain
merged or closed with their earlier evidence and dispositions in the two
6 October review records; none was reopened. The 86 new proposals were open,
not drafts. Commits, comments, review threads, exact diffs, CI and dependency
changes were inspected. No review thread was awaiting resolution.

The [proposal ledger](2026-10-08-proposal-ledger.json) records every reviewed
head and its disposition. Acceptance here means repository integration with
stated amendments and limits. It does not qualify an installation, approve a
new native owner, or enable an optional behavior on an existing host.

## Goals assessed

| Goal | Evidence and outcome |
|---|---|
| Robustness | Independent counterexamples exposed false stop/readiness evidence, stale rollback completion and lost-pause paths despite green proposal suites. Corrections retain fail-closed behavior. |
| Maintainability | Reused Python models and existing native owner boundaries. No VM, daemon, UI, new language, package dependency or action upgrade. Kept data-only inputs and explicit unsupported cases. |
| Meaningful tests | Compared selected cases with baseline, inspected mocks, joined real producer/consumer functions, and used fake-clock recovery and system Bash with a fake PF executable. Native parser evidence is distinguished from packet proof. |
| One author per setting | Literal sources can be rendered with lexical preservation and strict decoder round-trip. A searched program cannot prove that it consumes the rendered values and cannot authorize promotion. |
| Scope and privilege | Exact admissions, negative intent and single-writer contracts remain distinct. Optional source scope and runtime recovery are explicit, digest-bound choices, not silently selected migration defaults. |
| Actual installation fit | Compared private requirements with readable installed source and tracked administration declarations. Differences below remain blockers instead of being represented by invented settings or acceptance. |
| Reproducibility and honesty | macOS-only CI, pinned locks, schema/output versions, old-approval rejection and explicit unverified requirements remain enforced. A matching release file is not proof of executing that file. |

## Independent counterexamples and amendments

| Finding | Demonstrated failure | Correction / executable proof |
|---|---|---|
| Runtime vendor identity | A configurable nonexistent guest-job prefix allowed stopped evidence while the real vendor job could remain loaded. | Vendor-owned labels are fixed platform facts; reject invalid settings at parsing and observation boundaries. Runtime adversarial regressions. |
| Partial fleet | With `fleet_start` omitted, one running API row bypassed the all-stopped guard; another API-stopped guest could be restarted while its real vendor job remained loaded. | Require independent fixed-vendor job absence for every stopped guest. Six failing-before cases plus an absence control in `test_runtime_partial_fleet_stop.py`. Five further cross-domain/denied-read counterexamples require absence in system, GUI and user domains independently of the current helper. |
| Stopped peer | API-only stopped state skipped a tolerated peer during persistent-path writer checks, including when stronger service-manager evidence was selected. | Require the stopped-job proof for that exception; loaded peer jobs cannot be ignored. Runtime adversarial regressions. |
| Durable pause | Recovery could lock one state directory while reading a different intent file, missing the operator's pause in the locked store. | Bind recovery intent to that store and keep invalid control paths unknown; redact unsafe-store failures. Runtime adversarial regressions. |
| Interrupted rollback | A retry after the predecessor receipt was written released the installation hold despite removed jobs or changed installed/retained bytes. | Revalidate files and loaded jobs before releasing the hold. Six failing-before cases in `test_deployment_rollback_completion_readback.py`. |
| Renewal readiness | A historical confirmation made a renewal report verified with no currently confirmed registration. | Require current confirmation; a real confirmed overlap can preserve continuity but history cannot. `test_bonjour_cross_proposal_boundaries.py`. |
| Rejected-record resurrection | Per-record isolation plus miss memory restored an explicitly unusable record, including beside an unfinished scan. | Remove rejected identities from carry-forward memory while preserving healthy siblings. Same cross-proposal suite. |
| Registration readback | An extra foreign-interface line and trailing removal after child exit escaped validation. | Require matching interface evidence and complete bounded pipe draining before clean completion. Same cross-proposal suite. |
| False conformance | A program hardcoded interval 10 while rendered input changed to 20; lexical inventory reported zero matches and promotion succeeded. | Inventory-only programs and search-only TOML cannot satisfy automatic promotion. Literal rendering and static projection remain available. `test_render_promotion.py`. |
| False whole-action limit | `recover_service` completed after 42.5/122.5 seconds with a compliant 40/120-second vendor-call timeout. | Report whole-action deadlines as unsupported; do not equate call timeout with observation/lock/action duration. `test_supervision_whole_action_deadline.py`. |
| Native extension replacement | Real read-only macOS output included retired and active versions of one bundle plus the native “waiting to uninstall” state; parsing failed. | Count distinct native rows, retain one baseline identity, reject conflicting teams/active duplicates/unknown states. Sanitized shape in `test_preflight_extension_replacement.py`. |
| Hosted assumptions | No-instance collection on a container host has several addressed interfaces; the new hosted topology test treated correct uncertainty as a defect. | Keep strict topology expectations on hosted CI; retain schema and command round-trip checks on every Mac. No guessed LAN selection. |

The discovery contract advances to version 5. Older digests are rejected at
candidate, request, cached readback and owner endpoint boundaries. Output
vocabulary changes use report/plan/check schema version 2; validate/preflight
remain at version 1. Optional settings remain omitted when absent to preserve
unchanged canonical inputs. Exact owner source changes still require reviewed
release and admission transitions before native use.

## Claims accepted, rejected or limited

- Lowercase literal assignment names are valid inert data; refusing all of them
  was an extraction limitation. This does not authorize evaluating executable
  sources. Text-to-integer conversion is restricted to explicitly mapped values
  from untyped formats and an unambiguous closed integer schema slot.
- A source scan without findings is a tripwire, not semantic conformance. The
  attempted automatic promotion based on that scan is rejected.
- A broader credential refusing guard must not broaden “unexamined” allowances.
  The integrated separate relaxation guard is retained and regression-tested.
- A host redirect with explicitly admitted unrestricted sources is not the same
  as unrestricted direct-to-guest forwarding. The latter is not silently added.
- Process state, API records, file mode, code hashes and signatures each establish
  a limited fact. They do not substitute for current native acceptance.
- A platform can become accepted only through the shipped matrix and appropriate
  evidence. The positive-path test patches its matrix locally; the actual
  qualified matrix remains empty and native mutation remains unavailable.
- Existing PF state examples are sanitized fixture/printer lineage, not claimed
  raw kernel captures. Documentation and test provenance are corrected.
- The protected file path containment check is a read-only layout gate, not an
  atomic defense against concurrent parent-directory replacement. Content hashes
  remain independently required.
- Generic privacy scanning does not detect every locally administered hardware
  address or arbitrarily mislabeled secret. A complete private own-values pass
  and finite reviewed exceptions remain required.

## Remaining reference-installation conformance work

These are explicit limits, not successful migration outcomes. No installed
service, networking setting, container, application data or audio changed.

1. Installed forwarding, endpoint and Bonjour sources differ from tracked
   administration implementations. Source capabilities are not current kernel
   readback. Protected active policy/admissions/gates remain unverified.
2. Existing direct DNS accepts sources more broadly than the bounded candidate.
   Preserving or deliberately narrowing that behavior needs an independently
   reviewed strategy decision and client-identity/packet acceptance.
3. Dynamic `auto-tcp` discovery has no retained implementation. Explicit lists
   cannot be claimed equivalent. Prefix selection also does not preserve the
   existing hostname suffix algorithms; exact name parity remains required.
4. Outbound and inbound discovery have different miss policies, and existing
   inward discovery is independent of UDP forwarding. Per-selection settings
   can describe this; optional failed-read tolerance and overlap are not enabled
   by a repository review, and native cache continuity is unverified.
5. Workload contracts can describe named volumes, image/kernel/init metadata and
   other native facts, but the retained provisioner still has narrower mount and
   publication support. Description is not whole-fleet reproducibility.
6. The existing supervisor's launcher throttle, separate component repair,
   recovery statuses and whole-action deadlines need exact input and behavior
   conformance. A configurable process type or call timeout alone is insufficient.
7. Retained user control readers do not yet establish the complete legacy ACL
   and ancestor protection contract. Do not qualify a native cutover on POSIX
   mode checks alone. Runtime writer/recovery alternatives require one-owner
   migration, never a parallel starter.
8. Off-host recovery and restore rehearsal, native platform/launch identity,
   planned-stop state drain, first packet and reply, DNS client identity, receiver
   rediscovery, video/audio and unattended reboot remain separate acceptance
   gates. Historical audio confirmation does not accept a new policy/release.

The existing partial import was regenerated byte-for-byte, and all 22 captured
source pins still matched during this review. That evidence covers the partial
view only. It is not a complete instance or installed-output parity. Private
requirements and exact installed identifiers stay in the private repository.

## Verification and merge evidence

The audit keeps individual proposal checks separate from final combined checks.
Before additional fixes, the runtime proposal group passed 1,679 tests, the PF /
deployment group passed 2,453 and the Bonjour group passed 1,167. Those green
results did not prevent the independent counterexamples above. Baseline failures
also include missing new APIs and deliberately changed vocabulary; they are not
counted as that many independent bugs.

Combined CI also exposed a release-verification test that implicitly relied on
the frozen examples naming the current package, and two test fault selectors
that matched the vendor API job before the intended guest. The verification
fixture now names the running version explicitly and tests a wrong version too.
The examples retain their historical bytes for compatibility proofs; their
placeholder pins are documented as unusable installation pins. The selectors
target the exact guest job and
assert that every unaffected service remains present. Production PF behavior
for the API-wide timeout was correct and was not relaxed.

Required final verification is the unchanged three-Python macOS matrix (3.12,
3.13, 3.14), format/lint/strict types, dependency audit, public privacy guard,
installed-wheel smoke checks and grammar-only PF compilation. The test-job
limit becomes 45 minutes because the combined proposal suite demonstrably
exceeded 15 minutes on all three hosted Python versions. Coverage requirements
and test scope are not reduced to fit the clock.

The consolidation PR records final results and exact revision. Its merge is
permitted only after all four required checks pass on that revision. No mock,
hosted runner or this document can establish hardware tiers 3–5, and no test
result here removes the production qualification gates.

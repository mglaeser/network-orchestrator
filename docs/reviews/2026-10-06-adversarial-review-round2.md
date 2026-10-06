# Repeated adversarial repository review — 6 October 2026

## Scope and method

Baseline: `e91c081f8edc5681d8fc43ec2bebb1e95d5c3276` (0.3.1).
This is the requested second review, after the earlier delayed review. It covers
the current main tree, all PR history and the fifteen subsequent proposed fixes.
The [first report](2026-10-06-adversarial-review.md) remains a historical record;
this report does not retrospectively turn its passing tests into proof that it
found every defect.

Four reviewers divided source/import/conformance, reports/model/evidence,
native-owner contracts, and integration/privacy/CI. Reviewers reproduced proposed
failures against the baseline, inspected the assertions and mocks, tested the
combined fixes, and cross-reviewed supplemental changes. Real temporary files,
filesystem aliases and controlled child processes supplement pure and mock tests.
Native-owner tests use fake kernel/runtime boundaries. No production networking,
service, container or application was changed and no audio was played.

REST pagination enumerated all PR states. Per-PR GraphQL queries exhausted
commits, comments, reviews and review threads; no submitted review or inline
thread existed on PRs #7–#21 at the inventory checkpoint. Each proposed head had
four green CI checks, but that was treated only as evidence about its existing
tests. The reviewed changes are consolidated for a fresh combined macOS matrix;
the source PRs are closed as incorporated, not represented as individually merged.

## Goal benchmark

| Goal | Result and limits |
|---|---|
| Robustness | Corrected clock ordering, malformed-input handling, stale proof reuse and withdrawal ordering. Negative or missing evidence cannot improve a requirement. Native return traffic and recovery still need their separate proving tests. |
| Maintainability | Retained Python, typed models and existing independent owners. Shared guards and bounded readers were extended; no daemon, language rewrite, adapter or dependency was added. |
| Logic versus settings | Kept generic code separate from private instance data. Imports cannot author signatures, decisions, provenance or release pins. Per-profile evidence now binds the actual target and supervision settings. |
| Testing quality | Reproduced every proposed bug before accepting its fix. Added cases missed by the proposed suites, including file-identity races, malformed XML topology and evidence downgrades. Coverage is a floor, not a completeness claim. |
| Ownership and privilege | Read-only extraction remains the available stage. All retiring PF scopes are withdrawn before any state-drain failure can interrupt progress. Monitor commands receive the same direct escalation checks as jobs. |
| Privacy | Sentence punctuation cannot hide recognized private literals. Public PF status carries a state-existence marker instead of raw peer rows. No private values, credentials or native captures are committed. |
| Reproducibility and compatibility | Hashed dependency locks and SHA-pinned actions are unchanged. Schema and digest migration decisions are explicit below. Final combined CI and published asset hashes identify the tested result. |

## PR-by-PR disposition

The failure counts are independently observed proposed regression failures on
the baseline, not counts of independent security vulnerabilities. Passing
control cases were retained. Exact proposed revisions are recorded to make the
review reproducible.

| PR | Proposed head | Disposition / evidence |
|---|---|---|
| [#1](https://github.com/mglaeser/network-orchestrator/pull/1) | Historical closed dependency PR | Exact setup-python SHA remains in main; no omitted upgrade. Previous disposition stands. |
| [#2](https://github.com/mglaeser/network-orchestrator/pull/2) | Historical closed dependency PR | Exact upload-artifact SHA remains in main; no omitted upgrade. |
| [#3](https://github.com/mglaeser/network-orchestrator/pull/3) | Historical closed dependency PR | Exact checkout SHA remains in main; no omitted upgrade. |
| [#4](https://github.com/mglaeser/network-orchestrator/pull/4) | Previously merged | Retained owners are reviewed through the current tree. New latent defects are corrected by #16, #18–#21 and supplements below; qualification gates stay closed. |
| [#5](https://github.com/mglaeser/network-orchestrator/pull/5) | Previously merged | Extraction architecture is preserved. New model, import and reporting counterexamples are corrected below. |
| [#6](https://github.com/mglaeser/network-orchestrator/pull/6) | Previously merged | Earlier corrections remain; new failures disprove any completeness inference from its green CI. |
| [#7](https://github.com/mglaeser/network-orchestrator/pull/7) | `8e28f5c0a8d86f9cc5475bd1575a0f5925d6c6be` | Accept: read the clock after collection. Four failing-before cases prove fresh collected observations were classified as future-dated; an explicit injected clock remains authoritative. |
| [#8](https://github.com/mglaeser/network-orchestrator/pull/8) | `7e1c5232a49eb03e93850e473a85f8f154d3f0c0` | Accept: valid two-component macOS versions are representable. Seven failing-before cases; this does not broaden the qualified platform matrix. |
| [#9](https://github.com/mglaeser/network-orchestrator/pull/9) | `bac2b771c9e30a4551d8580eb8b33d5d931d603b` | Accept with supplement: refuse aliased inputs and bind comparisons to an owner. Twelve proposed failures plus two descriptor/cross-entry counterexamples. |
| [#10](https://github.com/mglaeser/network-orchestrator/pull/10) | `bb3f33dd5e780c2820fd9ec2e29335c47744ad7b` | Accept with supplement: literal import must preserve meaning or report underivable. Fifty-two proposed failures plus thirteen malformed XML topology cases. |
| [#11](https://github.com/mglaeser/network-orchestrator/pull/11) | `92249525d1a54f53ad9cbceb02c9263d32d0d0f5` | Accept with narrower waiver semantics: stale/negative facts, unaccepted deviations and unscoped evidence must not improve reports. Thirty-six proposed failures; additional report counterexamples below. |
| [#12](https://github.com/mglaeser/network-orchestrator/pull/12) | `0c2bfad2ab858db26e84a928f1b104433e71f8a7` | Accept: strict number/text types, distinct names, registered requirements and assessable decisions. Seventy-four proposed failures; add target/supervision digest binding. |
| [#13](https://github.com/mglaeser/network-orchestrator/pull/13) | `77560d05a89b36055b1050924d7caf0a367e7a64` | Accept: twelve failing-before proving-test reference checks, plus report guard coverage. Three representative guard mutations were independently detected; the original full 24-mutation aggregate was not replayed. References are source/test coverage, not hardware acceptance. |
| [#14](https://github.com/mglaeser/network-orchestrator/pull/14) | `bad386ca8061a10ab5f6397a625488588553e40e` | Accept: punctuation-aware private literal boundaries. Nineteen proposed failures; longer distinct tokens remain controls. Finite generic framework exceptions were inspected. |
| [#15](https://github.com/mglaeser/network-orchestrator/pull/15) | `b0e6d8d0b031f3ea856929b7a820e7ef9e5c601e` | Accept: ten cases prove static import could fill human-authored authority/provenance/release sections. All are refused. |
| [#16](https://github.com/mglaeser/network-orchestrator/pull/16) | `c9ee3fd223279982b4d412792d37866c5731c356` | Accept with parser/version supplement: four failures reproduce rejection of the native timestamped STARTING banner. Exact native row identity must also be preserved. |
| [#17](https://github.com/mglaeser/network-orchestrator/pull/17) | `21c49201363a2a5e355aaee098600cdb6e37fd74` | Accept: fifteen failures prove duplicate source/target aliases in a bind mount evaded the contract. Apple parser source at 1.2.0, 1.4.1 and 1.5.0 independently confirms alias normalization and last-spelling behavior. |
| [#18](https://github.com/mglaeser/network-orchestrator/pull/18) | `583b5b83c1affbf87916678843d47a7e26c41109` | Accept: seventeen failures prove monitor check/recovery argv bypassed the direct privilege-escalation guard applied to jobs. Executable provenance remains a separate trusted-code boundary. |
| [#19](https://github.com/mglaeser/network-orchestrator/pull/19) | `ba2ea30f83fe2d551ead050f74a726b76f11c728` | Accept: two failures demonstrate starter bindings called a nonexistent owner subcommand. Exercise the actual CLI parser at the binding boundary. |
| [#20](https://github.com/mglaeser/network-orchestrator/pull/20) | `299cca205ddf69be49b3cae54b3fca1484683ef1` | Accept with interruption regressions: five failures demonstrate an early drain error prevented withdrawal of later scopes. Stable partition withdraws every scope first. |
| [#21](https://github.com/mglaeser/network-orchestrator/pull/21) | `bf8b285474bad5096300f914d0277a4eefab53bf` | Accept: two failures demonstrate raw peer state rows leaked into public status. A retained-state marker preserves the consumer's safety decision without payloads. |

## Supplemental counterexamples

Primary source checks used Apple's
[mount parser at 1.2.0](https://github.com/apple/container/blob/1.2.0/Sources/Services/ContainerAPIService/Client/Parser.swift#L366-L396),
[1.4.1](https://github.com/apple/container/blob/1.4.1/Sources/Services/ContainerAPIService/Client/Parser.swift#L386-L416)
and [1.5.0](https://github.com/apple/container/blob/1.5.0/Sources/Services/ContainerAPIService/Client/Parser.swift#L387-L417),
plus mDNSResponder's exact
[browse callback](https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-2881.120.11/Clients/dns-sd.c#L755-L768),
[STARTING output](https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-2881.120.11/Clients/dns-sd.c#L2396-L2398)
and [timer exit path](https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-2881.120.11/Clients/dns-sd.c#L1317-L1320).
These are source evidence, not execution of a vendor runtime on a production host.

- **File identity after capture:** a parent symlink replaced after a bounded read
  could make a later pathname comparison examine a different file. Captures now
  retain the descriptor's device/inode identity. Captured and rendered roles must
  also be disjoint across the whole manifest, preventing cross-entry swaps.
- **XML structure:** empty roots, scalar child elements and non-layout text in
  containers/Booleans were silently discarded or raised uncaught parser errors.
  Complete supported topology is validated before decoding; malformed input is
  underivable and its contents are not emitted.
- **Report truthfulness:** whitespace-only attestations, residual promotion,
  omitted negative framework privacy observations and wrong-typed prerequisite
  facts had additional failure paths. A matched artifact cannot promote an
  accepted lifecycle residual to verified behavior. Generic deviations cannot
  waive categorical safety/provenance gates or the required native, lifecycle
  and application acceptance ladder. A signed deviation remains recorded;
  it cannot substitute for a required audible or reboot result.
  Final cross-review also reproduced malformed or blank consent identities
  verifying consent and blank deviation statements becoming accepted residuals.
  Seven additional failing-before cases now require meaningful typed identities
  and nonblank statements.
- **Per-profile evidence context:** renaming a target container or changing
  reconcile/discovery interval, miss limit or read timeout could reuse old verified
  transport/discovery evidence and readiness. Cross-review also demonstrated
  account and runtime-network omissions, plus stale readiness after platform or
  runtime-version changes. Both resolved envelopes now bind target name,
  supervision, account, platform and runtime context and use version 2. Old
  version 1 proofs are rejected.
- **Bonjour identity:** whitespace-separated parsing merged distinct labels with
  leading spaces; Unicode string line splitting rejected valid name characters.
  Parse the native fixed-width columns and split bytes before decoding, preserving
  exact labels. Malformed native columns still fail closed.
- **Command data:** named shell wrappers with `-c`, combined flags or `--command`
  accepted executable text in jobs and monitor bindings. Reject those forms while
  retaining trusted script-path bindings. This is a data-contract guard, not a
  sandbox for arbitrary or renamed executables.
- **Retiring PF scopes:** phase-injection tests interrupt before kernel replace,
  after kernel replace and after live-record write at each of four withdrawals.
  The next pass retires remaining scopes even with persistent drain failure. A
  later successful drain cannot acknowledge a failed generation-change journal
  or reactivate the profile.

## Compatibility and intentionally bounded claims

The canonical instance schema stays version 1: two-component macOS text is a
grammar correction, while number, control-character and name checks enforce
the existing closed data contract. An older framework can reject newly valid
two-component version declarations; use the explicit framework release pin.
Neither version syntax nor a candidate declaration qualifies native support.
Apple publishes two- and three-component macOS releases in its
[Tahoe update record](https://support.apple.com/en-us/122868).

Resolved transport and discovery evidence envelopes are version 2. The retained
Bonjour owner's discovery digest is version 3; prior candidates, requests,
readback and endpoint approvals need renewal. The PF owner continues to bind
its implementation fingerprint, so changed implementation bytes invalidate old
admission. Whole-instance contract digest version 2 from 0.3.1 is unchanged.

- A timer-bounded `dns-sd` process exiting zero is not by itself a parser failure:
  the native program intentionally does so on its timer path. The supported
  STARTING banner is grounded in Apple's source, not made-up observed packets.
  A registration child exiting still loses its registrations; its policy is
  withdrawn and retried from fresh evidence. Native renewal and cache continuity
  remain unverified. One malformed record currently withholds the complete
  policy conservatively; this review does not relax that authority boundary.
- A same-byte comparison does not authenticate renderer execution; ordinary
  copies remain indistinguishable. Owner labels prevent mix-ups, not forgery.
- Disjoint authoring records for one owner are accepted by the general instance
  schema, while the migration helper requires one record that may list multiple
  sections. The helper fails closed; this is a documented subset, not false
  promotion or a reason to redesign provenance during this review.
- Literal imports deliberately do not evaluate lowercase shell assignments,
  substitutions or numeric-string conversions. Unsupported forms stay underivable.
- Privacy matching detects documented classes and supplied exact private values.
  It is not a universal secret detector; public generic exceptions cannot waive
  per-instance matches.
- Green mock CI, signed statements and file hashes do not prove native packets,
  local-network consent, unattended reboot, restore, application effects or sound.

## Final verification and remaining gates

The combined corrected source passed **2,645 local tests** with **94.30% combined
line/branch coverage**. All four required checks passed on PR head
`0d9d863762e59775191857a001b6bd6dc541bad9` in
[CI run 37425669614](https://github.com/mglaeser/network-orchestrator/actions/runs/37425669614).
Each macOS 26 / Python 3.12, 3.13 and 3.14 job passed 2,644 tests with one optional
Monit grammar skip and the same coverage. Ruff, formatting, strict typing,
hash-locked dependency audit, public privacy, synthetic examples, PF grammar-only
compilation, package builds and installed-wheel smoke checks passed. Repeated
local builds produced identical wheel and source bytes. Merge `c61964a7f6ec5773c3eb9faf11e290c3f560973d`
has the exact tested tree. Subsequent documentation-only clarification and final
release evidence are linked from [PR #22](https://github.com/mglaeser/network-orchestrator/pull/22)
and the release; no weaker check is substituted for final required CI.

The qualified native platform matrix remains empty. Installed/source conformance,
protected input and explicit owner flips, valid recovery material and rehearsal,
native UDP first packets/state drain, Bonjour consent and renewal, runtime
compatibility, reboot and application/person acceptance remain separate gates.
The private installation inventory is incomplete; no fabricated observation,
signature or matching hash fills those gaps. This review creates no monitoring
schedule and activates no production owner.

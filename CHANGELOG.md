# Changelog

## 0.4.2 — migration preparation and health checkpoints

- Document parity and native qualification gates, one-owner migration and
  predecessor retirement, scoped rollback, and a bounded administrator-session
  concept for a future preapproved window. No privileged runner is implemented.
- Add offline validation of the complete reviewed dashboard roster after each
  step, rollback and soak. Reject stale, partial, failed, duplicated or mismatched
  recordings without collecting data, changing services or authenticating claims.
- Add adversarial checkpoint tests and preserve all native activation gates.
  No production owner, application or networking setting is changed.

## 0.4.1 — historical runtime job proof

- Refuse stopped-workload and retained-peer readiness when any loaded Apple
  runtime job still names the container, including a historical runtime handler.
- Bound and validate complete service-domain inventories; recheck absence at the
  end of the observation. Missing domains and unknown output cannot authorize
  recovery. Keep current-label checks as independent evidence.
- Refuse a vendor-runtime start if its API job remains loaded in the system
  domain, or that cross-domain read is unavailable.
- Add adversarial history, lifecycle, parser and native userspace grammar tests.
  Preserve the closed native qualification gate and existing production owners.
- Record repository closure separately from remaining production parity and
  hardware acceptance in the [closure record](docs/reviews/2026-10-08-closure-and-qualification.md).

## 0.4.0 — reviewed extraction and retained owner contracts

- Review and integrate the 86 proposals #24–109 with exact-head dispositions,
  combined interaction tests and additional independent counterexamples.
- Extend static literal import/rendering, supervisor and workload vocabulary,
  service-scoped holds, restart budgets, optional vendor recovery, native
  definitions, PF scope/lifetime controls and per-policy discovery settings.
- Keep one-author promotion conservative: lexical program inventory is not
  consuming-program conformance and cannot authorize an owner flip.
- Correct stale Bonjour renewal and rejected-record resurrection, strengthen
  registration readback, and advance the discovery contract to version 5.
- Revalidate retained and installed jobs before finishing interrupted rollback.
  Constrain vendor job identities and preserve pause through runtime recovery.
- Parse native extension replacement inventories without hiding malformed rows.
  Distinguish hosted runner topology assumptions from general macOS tests.
- Rename unproven fulfilment to `unverified` in report/plan/check schema version 2;
  add reusable preflight evidence and the read-only `supervision-gaps` command.
- Keep whole-action deadline gaps explicit; a vendor call timeout does not bound
  the surrounding observation, locking and validation work.
- Extend meaningful mock, property, process and macOS userspace coverage. Keep
  the three required macOS Python jobs and their coverage gate; allow 45 minutes.
- No dependency or action pin changes. Native mutation remains gated, the
  qualified platform matrix remains empty, and no existing owner is replaced.

## 0.3.2 — repeated adversarial review

- Integrate all fifteen reviewed follow-up PRs with independent counterexamples
  and supplemental corrections. The [second review](docs/reviews/2026-10-06-adversarial-review-round2.md)
  records every PR disposition, source evidence and remaining qualification gates.
- Fresh local facts use the post-collection clock. Negative facts, blank signatures,
  residuals and deviations cannot falsely improve requirement reports or replace
  required safety, native, lifecycle or application proof.
- Resolved profile/discovery evidence envelopes become version 2, binding target
  name, supervision, account, platform and runtime context. Old evidence is invalid.
- Correct macOS version grammar and enforce closed number/text/name contracts.
  Static imports preserve literal meaning, validate complete XML structure and
  cannot author decisions, signatures, provenance or framework pins.
- Conformance comparisons bind their owner and captured descriptor identities,
  rejecting aliases and capture/render reuse across entries.
- Privacy guards recognize sentence-ending values. PF status exposes only state
  existence, preventing peer disclosure and unbounded snapshot growth.
- Parse native Bonjour STARTING output and fixed-width browse labels without
  changing device identity. Discovery digest version 3 rejects older approvals.
  Starter discovery bindings call the actual endpoint command.
- Withdraw every retiring PF rule before draining states; interruption tests
  cover each write boundary. Direct privilege escalation and explicit shell
  command strings are refused consistently for jobs and monitor bindings.
- Reject duplicate mount source/target aliases according to the vendor parser.

No dependencies or platform qualification were added. Instance schema version 1
is retained with corrected grammar and validation; see the review's migration
decision. Native owners remain gated and production installations are unchanged.

## 0.3.1 — adversarial review corrections

- Current discovery readiness now requires the owner's desired configuration to
  match admission and applied state. Whole-instance evidence binds authoring
  provenance using contract digest version 2; older attestations need renewal.
- Instance privacy checks cover chosen host, workload and component identifiers.
  Static import rejects common camelCase credential keys as well as separated keys.
- TCP export dependencies must be TCP publications. Imported-record visibility
  has its own explicit owner-attested residual requirement.
- Native preflight parsers refuse ambiguous or truncated inventories instead of
  declaring inactive settings. Header-only VPN output remains unknown.
- Nonregular file inputs cannot block validation, status or negative-intent reads
  while waiting for a FIFO writer; protected metadata checks remain enforced.
- Bonjour reports retain the service generation expected by their consumer;
  registration callbacks wait for complete lines across asynchronous pipe reads.
  Both selectors use ASCII DNS hostname equivalence plus address and exclude own
  projections regardless of ASCII case. Discovery digest version 2 rejects older
  requests, candidates and readback after this semantic change.
- PF state readback rejects incomplete endpoint rows before claiming withdrawal.
  Root endpoint validation bounds declared LAN scope to the observed interface prefix.
- Added failing-before regression cases and a PR-by-PR review record in
  [the adversarial audit](docs/reviews/2026-10-06-adversarial-review.md).

The native qualification matrix remains empty. These fixes do not activate any
owner, migrate a production host or certify packets, reboot, recovery or audio.

## 0.3.0 — read-only host-independent extraction

- Closed canonical instance and workload-contract schemas; separate public code,
  private host data and local mutable state. Named strategy/profile and platform
  libraries replace host-specific configuration in new tools.
- Six unprivileged read-only host verbs, bounded local preflight, five-state
  profile views, context-bound retained evidence and truthful requirements reports.
- Literal-only legacy importer, exact byte/source conformance checks and both
  public and per-instance privacy guards. Underivable/protected inputs remain unknown.
- Explicit native mutation gate: no accepted hardware support matrix, no activation,
  admission, recovery or installation bypass. Existing installed owners are retained.
- macOS-only Python 3.12–3.14 CI, expanded strict/model/mock/fault tests and packaged
  schema smoke checks. No production networking or application setting is changed.

Candidate platform compatibility does not qualify a host. Owner flips, runtime
upgrades, physical packets/discovery, restore, reboot and audible acceptance remain
separate gates. This release cannot claim a host fully served without that evidence.

## 0.2.0 — executable macOS owners and provisioning

- Typed native Apple Container observation, full-definition enrollment and
  fixed native publication/lifecycle endpoints; unknown never permits recovery.
  Root observation adopts the enrolled user's Mach bootstrap context, then drops
  credentials before closed native read operations.
- Explicit digest-bound initial workload creation/start without replacing an
  existing definition or changing application configuration, plus explicit
  inspected-failure acknowledgement preserving pause and unrelated holds.
- Independent protected PF pull owner, code/observer-bound root admissions,
  scoped kernel readback/state draining and independently gated DNS fallback.
- Genuine selected-record Bonjour import/export with binary TXT preservation,
  exact service/publication dependencies and an independent expiry watchdog.
- Deterministic launchd/Monit deployment, separate user/root installers,
  failed-install recovery and rollback retaining current negative intent.
  Privileged paths and artifacts reject unsafe ACLs; release and job bytes are
  verified again before execution, including rollback and recovery.
- Read-only root readiness proof, user admission CLI and bounded status reporting.
- Expanded process, property, mock-kernel, multi-workload provisioning and
  partial-failure tests. CI also checks Darwin PF grammar without loading rules
  and smoke-tests every installed owner entry point outside the checkout.

This release has not been deployed to a production host. Native packets, Bonjour
consent/renewal, runtime upgrades, boot/login behavior, restore and application
acceptance remain explicit installation gates. CI does not play audio.

## 0.1.0 — initial alpha

- Portable, closed policy schema and frozen typed model; private site settings
  remain outside the package.
- Strict JSON/literal-source derivation, semantic lint and exact-content admission.
- Generation-fenced transport planning, independently gated discovery coordination
  and explicit external-root owner boundary.
- Durable operator pause, holder-owned suspensions, non-stealable locking and
  phase-aware partial-operation journals.
- Bounded user-owner subprocess protocol, read-only external owner snapshots,
  lossless record selection/projection and pure PF preview.
- Unit/property/fault/mock/process tests, public CI, type/lint checks,
  hashed dependency locks and installed-wheel verification.
- Architecture, configuration, owner integration, migration, recovery and
  hardware acceptance documentation.

This release has not been promoted to a production host. Native packet behavior,
owner integration, discovery consent and real application acceptance remain
installation-specific gates. No root service or packet stack is bundled.

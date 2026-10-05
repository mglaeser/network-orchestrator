# Changelog

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
- Unit/property/fault/mock/process tests, Linux/macOS public CI, type/lint checks,
  hashed dependency locks and installed-wheel verification.
- Architecture, configuration, owner integration, migration, recovery and
  hardware acceptance documentation.

This release has not been promoted to a production host. Native packet behavior,
owner integration, discovery consent and real application acceptance remain
installation-specific gates. No root service or packet stack is bundled.

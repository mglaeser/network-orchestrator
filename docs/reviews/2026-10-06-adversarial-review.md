# Adversarial repository review — 6 October 2026

## Scope and method

Baseline: `4a8e3df726272f80648722e9fad946012092ea39` (release 0.3.0).
This review evaluates the repository's stated goals and the October extraction
review recorded in [review traceability](../review-traceability.md). It is an
independent source, fixture, subprocess and mock review; it is not a production
installation or hardware acceptance report.

Four parallel review areas covered PR history/dependencies/preflight,
instance/evidence/privacy, privileged owners/lifecycle, and Bonjour/consumer
contracts. Reviewers inspected each other's corrections. Confirmed issues were
reproduced against the baseline before correction; regressions assert observable
behavior, including real temporary FIFOs and fragmented subprocess output.
No production networking, runtime, containers, service state or audio changed.

## Goals assessed

| Goal | Assessment and consequence |
|---|---|
| Robustness and truthful state | Found false readiness, stale evidence, ambiguous native parser results and blocking input paths. Corrected and regression-tested. Unknown remains distinct from healthy, absent and restart permission. |
| Maintainability | Kept the current language and owner boundaries. Shared bounded file reading replaces repeated unsafe general reads. No new adapter, daemon, VM or root call path. |
| Settings separate from logic | Closed instance model and exact source conformance retained. Authoring provenance now participates in the evidence digest; TCP exports require usable publication types. |
| Privacy and data-only migration | Added omitted chosen identifiers to the instance guard and common credential-key spellings to the static importer. These are explicit guards, not a promise to recognize arbitrary mislabeled secrets. |
| Meaningful testing | Added tests that join actual owner reports to their consumer, and tests with real process/file behavior. Unit success remains separate from native packet, recovery and application proof. |
| Coherent workflow and authority | Six read-only host operations remain unchanged. Native qualification/activation gates remain enforced. The audit does not promote the framework to production-ready. |

## Every existing PR

REST pagination covered every open and closed PR. GraphQL pagination flags were
checked for commits, comments, reviews and review threads. There were five PRs
at the start of this review and none was created during the requested delay.
All five had no submitted review or review thread. The three dependency PRs had
only bot status/closure comments, with no human finding awaiting resolution.

| PR | Observed state | Independently verified disposition |
|---|---|---|
| [#1](https://github.com/mglaeser/network-orchestrator/pull/1), setup-python 7.0.0 | Closed, unmerged | The exact proposed action SHA is already included by `ed25cf6` and retained in main. The removed optional install input is not used. No missing upgrade to merge. |
| [#2](https://github.com/mglaeser/network-orchestrator/pull/2), upload-artifact 7.0.1 | Closed, unmerged | The exact proposed SHA is already included by `ed25cf6`. The workflow uploads the multi-file report archive using the supported default. No missing upgrade. |
| [#3](https://github.com/mglaeser/network-orchestrator/pull/3), checkout 7.0.1 | Closed, unmerged | The exact proposed SHA is already included by `ed25cf6`; the hosted macOS workflow supports the action runtime. No missing upgrade. |
| [#4](https://github.com/mglaeser/network-orchestrator/pull/4), retained owners and provisioning | Merged | Reviewed its six commits and final changes. Found owner/report, stream parsing, file-bound and state-readback gaps listed below. Native execution remains gated by #5. |
| [#5](https://github.com/mglaeser/network-orchestrator/pull/5), read-only extraction | Merged | Reviewed both commits and final changes. Found evidence, privacy, dependency validation and preflight gaps listed below. Corrected without relaxing its stage boundary. |

Action tags and each `action.yml` were checked against their upstream
repositories. Baseline macOS CI also passed on the actual merged tree:
[run 37377749011](https://github.com/mglaeser/network-orchestrator/actions/runs/37377749011).
That successful baseline did not reveal the defects below, demonstrating why
CI status alone was insufficient.

## Confirmed findings and corrections

All findings below are P2 correctness, availability or privacy-boundary defects.
Latent native-owner effects are identified separately from currently available
read-only entrypoints; this review does not claim production exploitation.

| ID | Proven counterexample | Correction and regression evidence |
|---|---|---|
| A01 | Discovery's owner desired digest could differ from the canonical policy while current readiness stayed true. | Require desired, admitted and applied equality for discovery as well as transport. `test_discovery_current_readiness_requires_owner_desired_digest`. |
| A02 | A whole-instance conformance/source proof remained verified after its authoring owner, source hash or migration mode changed. | Instance contract digest version 2 binds authoring. Six retained-proof mutation cases in `test_authoring_changes_invalidate_retained_conformance`. Historical version 1 attestations require renewal. |
| A03 | The per-instance literal guard missed chosen instance names and workload/component/profile identifiers. | Inventory those local identifiers explicitly. `test_instance_guard_includes_host_and_local_identifiers` scans a synthetic leak and requires findings. |
| A04 | All-TCP discovery export profiles validated with only a same-workload UDP publication. | Require a TCP publication for each supported export selection. `test_tcp_discovery_export_rejects_udp_only_publication` covers each export profile. |
| A05 | An import-visibility decision was stored but never evaluated by the requirements report. | Add applicable `IMPORT-VISIBILITY`; require explicit acceptance and a nonblank, nonfuture owner attestation. It remains an accepted residual, never authenticated authority or verified behavior. |
| A06 | Common camelCase credential selectors could pass the static import key guard. | Reject equivalent credential words across ordinary casing conventions at selectors and nested projections, with synthetic non-emission regressions. Arbitrarily mislabeled secrets remain outside the detector's claim. |
| A07 | Ambiguous or malformed native inventories could be reported as inactive settings. | Parse complete supported native structures and classify incomplete/malformed input as unknown. Native VPN header-only output cannot distinguish an empty list from a failed copy and therefore remains unknown. Synthetic positive and negative fixtures cover proxy, VPN, extension, power and sharing readers. |
| A08 | A named pipe without a writer blocked validation or state reads before file-type checks ran. | Open nonblocking before descriptor validation and reject nonregular data. Real subprocess/FIFO tests cover public validators, state read/write and protected owner readers, including replacement between checks. |
| A09 | Actual Bonjour readback omitted the service-generation field its planner required; both complete absence and confirmed registrations were rejected as generation changes. | Include that field. `test_real_owner_readback_preserves_generation_for_discovery_planner` joins publisher, serialized endpoint response and actual planner. |
| A10 | A valid registration callback split across two pipe reads was treated as a conflicting identity. | Parse only newline-complete callbacks, retaining existing deadlines, size limits and identity checks. `test_registration_waits_for_complete_callback_line` uses an actual fragmented child process. |
| A11 | The retained pure import selector included an unrelated hostname sharing an eligible address and could reimport its own projected name. Both selectors also treated DNS hostname case as identity and allowed mixed-case projection prefixes. | Match hostname plus address with ASCII-only DNS case equivalence, preserving record spelling; exclude both projection prefixes in names and hostnames in either direction. [RFC 4343 section 3](https://www.rfc-editor.org/rfc/rfc4343.html#section-3) defines the comparison; Unicode casefold is deliberately excluded. Discovery digest v2 invalidates old approvals. Pure/native-selector regressions and actual owner boundary tests reject v1 candidates, requests, cached readbacks and endpoint calls. |
| A12 | PF readback accepted truncated endpoint rows as complete with no relevant addresses, potentially misreporting withdrawal. | Require complete numerical endpoint and state grammar before using any row; malformed output remains unknown. Positive translation/IPv6 and malformed-row regressions cover the retained parser. Native activation remains unavailable. |
| A13 | The retained root endpoint guard verified the host address but ignored the interface netmask, allowing a declared LAN scope wider than the observed interface prefix. | Derive the actual interface network from its unique address/netmask row and require the declared scope to be a subnet. Missing, malformed, ambiguous and wider-scope cases fail closed. Native activation remains unavailable. |

## Claims rejected or bounded

- **Closed dependency PRs meant missing upgrades:** disproven by comparing their
  exact diffs/SHAs with main. Reopening or remerging them would add no correction.
- **Read-only PF status creates missing root state:** disproven by control flow;
  protected ancestor/leaf validation fails before the state constructor runs.
- **Prior all-green CI proved the repository correct:** disproven by the new
  failing-before cases, including a producer/consumer mismatch hidden by mock
  reports that manually inserted the missing field.
- **An owner signature or matching file hash proves operational acceptance:**
  rejected. It establishes an attestation/content relationship, not observation
  truth or authenticated root authorization.
- **macOS-only CI proves production Apple Container networking:** rejected.
  Current jobs run on macOS only; PF grammar compilation does not load rules or
  establish return traffic, client identity, multicast projection or audio.

## Verification and remaining gates

Regression, property, process and mock tests, lint, formatting, strict typing,
public privacy scanning, dependency audit and installed-wheel checks are run on
the correction branch. The PR and subsequent main CI provide the exact revision
and results; no test result from this document can stand in for those runs.

Final local macOS/Python 3.12.14 verification: **2,075 tests passed**, with
**93.89% combined line/branch coverage**. Ruff, formatting, strict mypy,
dependency consistency/audit, public privacy guard, both synthetic instance
validators and Bash syntax checks passed. Wheel/source builds succeeded; an
isolated installed-wheel smoke check covered all six packaged schemas, owner
entrypoints, examples and the read-only report. Hosted CI separately repeats
the supported Python 3.12/3.13/3.14 matrix, PF grammar-only compilation and wheel
checks. Its optional Monit grammar test may skip when Monit is unavailable.

Candidate platform qualification remains empty. Production migration still
requires source/installed byte conformance, independently admitted scope,
retained recovery material and a rehearsed restore, the accepted platform and
launch identity, native first-packet/state-drain/Bonjour tests, unattended reboot,
and application/person acceptance where applicable. None is marked satisfied by
this audit. The one-time review does not introduce ongoing monitoring.

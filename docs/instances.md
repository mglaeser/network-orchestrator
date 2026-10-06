# Private instances and the read-only host entrypoint

Version 0.3 adds a canonical, bounded **data model and read-only reporting stage**. It does not activate a new instance, parameterize existing owners, install services, admit PF rules, recover a workload, or qualify a native host. The independently gated 0.2 owner utilities remain compatibility components; they are not an automatic apply path from this model.

The public repository contains the schemas, named strategy and application profiles, source-backed platform facts, requirements registry, tests and synthetic examples. A private instance repository contains chosen host values, names, content references, decisions and acceptance records. Local runtime state contains observations, admissions, journals, pause/suspensions, immutable receipts and preflight results. Application secrets and configuration stay with their applications. None of that runtime state becomes instance desired state.

## Instance contract

`schemas/instance.schema.json` closes every object. `instance.json` must use sorted keys, compact UTF-8 JSON, and exactly one final newline. Duplicate keys, non-finite values, extra fields, expressions, templates, executable paths, shell snippets, raw PF text and live guest/receiver addresses are rejected. All arrays and reads are bounded. Exactly one chosen IPv4 LAN is allowed. IPv6 is outside this custom policy; it is not declared blocked.

An instance pins the framework version, exact release-artifact SHA-256, source revision, dependency-lock SHA-256 and schema version. Content verification is not publisher authentication: acquire the release and reviewed digests through your trusted release process. Synthetic example pins are deliberately zero placeholders and cannot verify a real release.

Workloads reference canonical private contract files by relative data path and SHA-256. A contract contains an immutable image reference, resources, mount data, kernel-argument hash, network name/MTU and data-recovery class. It cannot contain credentials, environment values, executable commands or raw runtime inspection output. Checking a contract file proves its content matches the reference; installed definition parity requires separate evidence. Component health/recovery is separate from workload recovery: a failed component never grants workload restart authority.

Automatic UDP socket ranges have one named definition. The workload and its return-forwarding profile refer to that same definition; an independently copied range is invalid. Strategy/profile versions and cross-owner dependencies are explicit. Resolved digests include names, framework pins, workload contract, LAN identity, relevant policy and transitive publication/fallback contracts. Changing them invalidates older matching evidence.

Installed names and state paths can be pinned. Null names are deterministically derived from the private namespace; the PF namespace stays under the platform-defined `com.apple/` anchor namespace. Changing names is a reviewed owner migration, not an automatic rename.

## One source of settings during migration

The initial view of an existing installation is generated from literal, static legacy data using the [no-evaluation importer](legacy-import.md). Import provenance and source hashes are private evidence. Executable logic is inventoried and marked underivable, never evaluated to invent missing settings. A partial inventory is not a complete instance and is not deployable.

`authoring` records select an owner, closed sections, optional subject IDs and either `generated` or `authored`. Generated sections require their aggregate source hash; authored sections cannot retain a generated-source hash. Overlapping ownership is rejected. Missing section/subject coverage is reported as not fulfilled. Promoting one owner requires its frozen byte conformance and explicit owner flip; the host CLI does neither. Do not maintain a manually edited duplicate alongside a generated authoritative view.

The complete instance contract digest (version 2) binds these authoring records,
including owner, source hash and migration mode. A source or ownership change
invalidates earlier whole-instance attestations even if rendered behavior has
not changed. Only the acceptance ledger itself and informational deviations are
excluded from that digest; version 1 receipts require renewed evidence.

## Six commands

Install the reviewed wheel in a normal unprivileged Python environment. Commands read local files and print JSON to stdout. They do not create state; redirect reports into an existing private host-state directory if desired.

```sh
netorch-host validate --instance /private/instance/instance.json
netorch-host preflight --instance /private/instance/instance.json
netorch-host status --instance /private/instance/instance.json --evidence /private/host-state/preflight.json
netorch-host plan --instance /private/instance/instance.json --evidence /private/host-state/observations.json
netorch-host check --instance /private/instance/instance.json
netorch-host report --instance /private/instance/instance.json
```

`validate` checks schema, canonical bytes, references, collisions and referenced contract contents. `preflight` reports declared versus observed prerequisites. `status` reports profiles and requirements. `plan` compares desired and owner-reported digests and emits **no actions**. `check` exits 1 until all applicable requirements, current evidence and qualified support are established. `report` produces the complete report. Root execution is refused (77); invalid/unavailable local data returns 65, with redacted errors.

Optional `--framework-artifact /private/release/package.whl --dependency-lock /private/release/dependency-lock.json` checks exact artifact/lock bytes and the installed package version. `--data-dir` selects the existing private directory containing contract references. `--evidence-dir` selects retained content-addressed acceptance files. No path in these data files is executed.

Only `preflight`, `status` and `report` permit explicit `--collect-local`. This invokes a fixed, bounded local macOS collector, never a LAN/Bonjour probe, owner endpoint, privilege escalation or service action. It checks OS/vendor state readable without administrator rights. Unavailable, malformed, denied or unexamined facts remain unknown. Terminal consent is not LaunchAgent consent; read-only collection cannot establish the latter.

## Truth and confidence

Every profile reports five distinct state layers: desired, admitted, observed, applied and receipt. Admission/application digests supplied in an owner snapshot are explicitly unverified owner reports, not root authorization or kernel readback. Observations keep independent timestamps, reasons and generation IDs. Receipts are historical and never establish current readiness. Transport, discovery, probe, application and heard-audio observations remain separate. A transport success with unknown discovery is not a healthy application. The optional `workloads` and `components` evidence rows describe their own observations. Current readiness also requires every declared workload and component to be freshly present. Required layers/dependencies for one workload must carry the same shared workload-identity generation token; a projection from an old generation cannot be combined with a newly running workload. These are consistency checks on owner-reported evidence, not independent observation or restart authorization.

Transport and discovery readiness both require the owner's desired digest to
match the canonical, admitted and applied digests. An absent or different owner
desired digest remains unready even when other observations are positive.

The instance-to-framework privacy guard checks the instance name, workload and
component IDs, profile/range/tool IDs and authoring owners as well as addresses,
ports and pinned native names. Generic pattern checks alone cannot recognize
these locally chosen names.

The static importer rejects known credential and environment keys in selectors,
targets and nested projections, including camelCase and acronym spellings such
as `apiToken`, `clientSecret` and `APIKey`. This is a key-name guard, not a detector
for arbitrary secret values; mappings still require review before committing.

Discovery selections have their own rows and resolved digests, with dependency states. Warm-cache reload does not establish inward Apple-media discovery. The pinned Home Assistant shared-scanner cold-start/receiver-change proof remains a named **unverified** acceptance requirement; offline synthetic coverage does not claim it happened.

Every current export profile requires a TCP publication for its own workload;
a UDP socket at the same port cannot substantiate a TCP DNS-SD announcement.
Instances with imports also report `IMPORT-VISIBILITY`: visibility must be
explicitly accepted with a nonblank owner name and a nonfuture signing time.
That remains an owner-recorded accepted residual, not authenticated authority,
even if a matching acceptance artifact exists. Export-only instances do not
need an import-visibility decision.

Requirement statuses are `fulfilled-verified`, `fulfilled-unverified`, `accepted-residual`, `not-applicable` or `not-fulfilled`. Software invariants can be verified by deterministic tests. Native/application requirements need their exact recorded tier and method. Retained evidence must match schema, host build/runtime, framework artifact and resolved profile or complete instance contract. A single profile receipt cannot cover a second applicable profile, and a record without a profile never stands in for a per-profile requirement. Synthetic sources/proofs and offline fixture contexts never establish native acceptance. Heard audio requires a person's record; root observer and LaunchAgent consent require their named execution contexts. These records are owner attestations with content hashes, not independently replayed measurements or cryptographic authority.

Missing, stale or negative knowledge never improves a row. A reported `absent` or false `recovery_material`, `owner_conformance`, `names_preserved` or `instance_literal_check` fact keeps its requirement `not-fulfilled` until a positive observation replaces it; growing stale does not clear it and an acceptance record does not override it. A reported installed framework hash other than the pinned artifact does the same for the release pin. A recorded deviation names a requirement that is not met: without a current owner acceptance its row is `not-fulfilled`, with one it is `accepted-residual` and never better. An accepted deviation does not lift a row that is `not-fulfilled` for another reason.

A compatible parser is not a supported production host. The candidate contract is macOS 27.0.1 build 26A434, Apple silicon, container 1.5.0 (containerization 0.47.0). The framework ships an **empty native-qualified matrix**; private ledger entries cannot override it. Installed legacy versions, including 1.2.0, remain read-only and unqualified. There is no qualification writer or automatic runtime upgrade in this stage.

Bounded direct guest and UDP return profiles require an explicit current T/K/residual signature. The current owner effectively withdraws on the first unknown (K=1); configured K is displayed separately. No whole-pass scheduling/read/apply upper bound is guessed. Without actual finite aggregate bounds and native proof, the withdrawal guarantee remains unverified and zero misdelivery is never asserted. A native LAN alias uses ordinary vendor networking and is not treated as a PF rule to a recyclable guest address.

Unattended recovery requires a separately accepted DNS-ready limit and boot/restore evidence. FileVault requiring a person does not fulfil that goal through automatic login: a reported `on` blocks at any age, only a current observation counts as `off`, and without one the declared baseline decides. A FileVault state that is neither currently observed off nor declared off is `not-fulfilled`. Lifecycle/API writers and residual authority are explicit; a signature is an owner decision, not authentication against a hostile writer. The read-only stage never changes power, login, startup chains or recovery behavior.

## Proof before activation

Run schema/property/fault/fixture/conformance tests in CI. Keep native parser/packet/consent/startup/application/heard-audio acceptance separate and bind it to the exact version/host/profile. Before any owner is activated: inspect the generated private view, fill only genuinely known missing values, pin existing names, prove byte parity for that owner, review its exact resolved parameters and rollback, and complete the separately approved native acceptance. No report command performs those actions.

The two checked-in examples exercise different synthetic host/account/LAN/network/workload choices: `examples/instance.json` includes bounded UDP plus Apple-media import; `examples/instance-structural.json` has only native publication/export and no bounded transport. Both are valid data, not accepted installations.

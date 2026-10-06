# Private instances and the read-only host entrypoint

Version 0.3 adds a canonical, bounded **data model and read-only reporting stage**. It does not activate a new instance, parameterize existing owners, install services, admit PF rules, recover a workload, or qualify a native host. The independently gated 0.2 owner utilities remain compatibility components; they are not an automatic apply path from this model.

The public repository contains the schemas, named strategy and application profiles, source-backed platform facts, requirements registry, tests and synthetic examples. A private instance repository contains chosen host values, names, content references, decisions and acceptance records. Local runtime state contains observations, admissions, journals, pause/suspensions, immutable receipts and preflight results. Application secrets and configuration stay with their applications. None of that runtime state becomes instance desired state.

## Instance contract

`schemas/instance.schema.json` closes every object. `instance.json` must use sorted keys, compact UTF-8 JSON, and exactly one final newline. Duplicate keys, non-finite values, extra fields, expressions, templates, executable paths, shell snippets, raw PF text and live guest/receiver addresses are rejected. Every number must be written as a JSON integer (`1.0` is refused), and no string may contain a control character or a line or paragraph separator, so a trailing newline is refused too. The same two rules apply to workload contract files, evidence documents and retained acceptance files; only evidence times may be fractional. Acceptance and deviation entries must name a registered requirement. A bounded decision must be one the safety assessment can evaluate: a blank residual statement or one longer than 2000 characters, a blank signer, or a signature dated before 1970 is refused when the instance is parsed. All arrays and reads are bounded. Exactly one chosen IPv4 LAN is allowed. IPv6 is outside this custom policy; it is not declared blocked.

An instance pins the framework version, exact release-artifact SHA-256, source revision, dependency-lock SHA-256 and schema version. Content verification is not publisher authentication: acquire the release and reviewed digests through your trusted release process. Synthetic example pins are deliberately zero placeholders and cannot verify a real release. [The release pin](#the-release-pin) says where each value comes from and what checking it establishes.

Workloads reference canonical private contract files by relative data path and SHA-256. A contract contains an immutable image reference, resources, mount data, kernel-argument hash, network name/MTU and data-recovery class. It cannot contain credentials, environment values, executable commands or raw runtime inspection output. Checking a contract file proves its content matches the reference; installed definition parity requires separate evidence. Component health/recovery is separate from workload recovery: a failed component never grants workload restart authority.

Automatic UDP socket ranges have one named definition. The workload and its return-forwarding profile refer to that same definition; an independently copied range is invalid. Strategy/profile versions and cross-owner dependencies are explicit. Resolved digests include names, framework pins, workload contract, LAN identity, relevant policy and transitive publication/fallback contracts. Changing them invalidates older matching evidence.

Resolved transport and discovery digest envelopes are version 2. They now bind the target workload's container name, owning account, runtime/platform context and supervision settings, including observation/read bounds and discovery timing, through each required transport dependency. Version 1 profile acceptance and owner-state digests require renewed evidence; renaming a target or changing its account, runtime, platform or supervision cannot reuse a previous profile's receipt or readiness.

Installed names and state paths can be pinned. Null names are deterministically derived from the private namespace; the PF namespace stays under the platform-defined `com.apple/` anchor namespace. Pinned or derived, the five launchd labels must be distinct, the export prefix must differ from the import prefix, and the user state directory must differ from the root state directory; two workloads cannot share a container name. Changing names is a reviewed owner migration, not an automatic rename.

## One source of settings during migration

The initial view of an existing installation is generated from literal, static legacy data using the [no-evaluation importer](legacy-import.md). Import provenance and source hashes are private evidence. Executable logic is inventoried and marked underivable, never evaluated to invent missing settings. A partial inventory is not a complete instance and is not deployable.

`authoring` records select an owner, closed sections, optional subject IDs and either `generated` or `authored`. Generated sections require their aggregate source hash; authored sections cannot retain a generated-source hash. Overlapping ownership is rejected. Missing section/subject coverage is reported as not fulfilled. Promoting one owner requires its frozen byte conformance and explicit owner flip; the host CLI does neither. Do not maintain a manually edited duplicate alongside a generated authoritative view.

The complete instance contract digest (version 2) binds these authoring records,
including owner, source hash and migration mode. A source or ownership change
invalidates earlier whole-instance attestations even if rendered behavior has
not changed. Only the acceptance ledger itself and informational deviations are
excluded from that digest; version 1 receipts require renewed evidence.

## The release pin

`framework` names one release. Its values are copied in by the author of the instance; no command fetches or derives them. `schema_version` is the version of the instance schema. The other four come from the release:

- `version` is the release's version: the tag without its `v`, `0.3.2` for the tag `v0.3.2`.
- `artifact_sha256` is the SHA-256 of that release's wheel, `netorch-0.3.2-py3-none-any.whl`. The release page of the tag in the public repository lists the wheel, the source archive and a file `SHA256SUMS`; the wheel's line in that file is the published digest.
- `revision` is the full commit the tag names, which `git rev-parse 'v0.3.2^{commit}'` prints in a clone of the public repository.
- `dependency_lock_sha256` is the SHA-256 of `requirements-lock.txt` as that commit has it. That file is the runtime lock: the wheel's dependencies are installed from it with `pip install --require-hashes -r requirements-lock.txt`. It is not `requirements-dev-lock.txt`, which locks the development and build tools, and it is not inside the wheel. Take it from the source archive or from an export of the tag and hash it yourself.

A published digest says what was uploaded, not what the commit builds. To check the wheel against the commit, export the tag into a new directory and build it with the hash-locked build tools, the way CI builds it:

```sh
# In a clone of the public repository. /private/build/source must be new and empty.
version=0.3.2
git rev-parse "v$version^{commit}"
mkdir -p /private/build/source
git archive --format=tar "v$version" | tar -x -C /private/build/source
python3 -m venv /private/build/venv
/private/build/venv/bin/python -m pip install --require-hashes -r /private/build/source/requirements-dev-lock.txt
(cd /private/build/source && /private/build/venv/bin/python -m build --no-isolation)
shasum -a 256 "/private/build/source/dist/netorch-$version-py3-none-any.whl" /private/build/source/requirements-lock.txt
```

The first output is the `revision`; the last command prints the artifact digest and the lock digest. The artifact digest must equal the wheel's line in `SHA256SUMS`. When this section was written, release 0.3.2 was rebuilt this way on Linux with Python 3.12 and with Python 3.13: the wheel and the source archive had the published digests, also when the exported files had other permissions and timestamps. A rebuild on macOS has not been compared. If your wheel differs, pin neither digest until you know why.

`--framework-artifact` and `--dependency-lock` compare two files on disk with the pin. `release_verified` in the output of `validate` is true exactly when the artifact file has the pinned `artifact_sha256`, the lock file has the pinned `dependency_lock_sha256`, and the pinned `version` equals the version of the package that runs the command. Both options are needed; with one of them alone the result is false. Both must name ordinary single-link files of at most 1 MiB, as every other local input must; a symbolic link or a larger file ends the command with status 65. With that result the `FRAMEWORK-PIN` requirement is `fulfilled-verified`, unless host evidence reports another installed artifact or a deviation is recorded for it; without that result `check` cannot pass.

That result means "the pinned files on disk match the pin". It does not mean "this is the code that is running". The command does not look inside the wheel, does not compare the installed package with it, and does not check that the dependencies were installed from the lock; a source checkout or any other installation with the same version string gets the same result. `revision` is recorded, and it is part of the whole-instance contract digest and of every resolved transport digest, so changing it invalidates earlier evidence bound to those; but no command compares it with anything, and the wheel does not carry its commit. Installing exactly the pinned wheel from exactly the pinned lock, and keeping the installation that way, remains the operator's procedure.

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

Optional `--framework-artifact /private/release/package.whl --dependency-lock /private/release/requirements-lock.txt` checks exact artifact/lock bytes and the version of the package that runs the command; [the release pin](#the-release-pin) says what that result does and does not establish. `--data-dir` selects the existing private directory containing contract references. `--evidence-dir` selects retained content-addressed acceptance files. No path in these data files is executed.

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

Missing, stale or negative knowledge never improves a row. A reported `absent` or false `recovery_material`, `owner_conformance`, `names_preserved`, `framework_literal_check` or `instance_literal_check` fact keeps its requirement `not-fulfilled` until a positive observation replaces it; growing stale does not clear it and an acceptance record does not override it. These prerequisite values must be booleans when supplied, so numeric zero and the string `"false"` cannot hide a negative result. A reported installed framework hash other than the pinned artifact does the same for the release pin. A recorded deviation names a requirement that is not met: without a current owner acceptance its row is `not-fulfilled`, with one it is `accepted-residual` and never better. An accepted deviation does not lift a row that is `not-fulfilled` for another reason. Generic deviations cannot replace mandatory platform/identity/provenance proof, root authority boundaries, pause preservation, unknown-state guards or the read-only stage. Every requirement whose registry tier calls for native, lifecycle or application acceptance (tiers 3–5) also keeps its proving gate, including heard audio, DNS client identity and unattended boot. Deviations from these requirements remain recorded but `not-fulfilled` until resolved and the required proof established; their signatures cannot waive the acceptance ladder.

Every acceptance record needs a nonblank owner name. A supplied Local Network identity must be nonblank text, and a deviation needs a nonblank statement before its signature can count. Lifecycle authority residuals also require a nonblank statement and signer, and remain `accepted-residual` even with a matching process-inventory record: inventory does not remove another API writer's authority.

A compatible parser is not a supported production host. The candidate contract is macOS 27.0.1 build 26A434, Apple silicon, container 1.5.0 (containerization 0.47.0). The framework ships an **empty native-qualified matrix**; private ledger entries cannot override it. Installed legacy versions, including 1.2.0, remain read-only and unqualified. There is no qualification writer or automatic runtime upgrade in this stage.

Bounded direct guest and UDP return profiles require an explicit current T/K/residual signature. The current owner effectively withdraws on the first unknown (K=1); configured K is displayed separately. No whole-pass scheduling/read/apply upper bound is guessed. Without actual finite aggregate bounds and native proof, the withdrawal guarantee remains unverified and zero misdelivery is never asserted. A native LAN alias uses ordinary vendor networking and is not treated as a PF rule to a recyclable guest address.

Unattended recovery requires a separately accepted DNS-ready limit and boot/restore evidence. FileVault requiring a person does not fulfil that goal through automatic login: a reported `on` blocks at any age, only a current observation counts as `off`, and without one the declared baseline decides. A FileVault state that is neither currently observed off nor declared off is `not-fulfilled`. Lifecycle/API writers and residual authority are explicit; a signature is an owner decision, not authentication against a hostile writer. The read-only stage never changes power, login, startup chains or recovery behavior.

## Proof before activation

Run schema/property/fault/fixture/conformance tests in CI. Keep native parser/packet/consent/startup/application/heard-audio acceptance separate and bind it to the exact version/host/profile. Before any owner is activated: inspect the generated private view, fill only genuinely known missing values, pin existing names, prove byte parity for that owner, review its exact resolved parameters and rollback, and complete the separately approved native acceptance. No report command performs those actions.

The two checked-in examples exercise different synthetic host/account/LAN/network/workload choices: `examples/instance.json` includes bounded UDP plus Apple-media import; `examples/instance-structural.json` has only native publication/export and no bounded transport. Both are valid data, not accepted installations.

# Private instances and the read-only host entrypoint

Version 0.3 adds a canonical, bounded **data model and read-only reporting stage**. It does not activate a new instance, parameterize existing owners, install services, admit PF rules, recover a workload, or qualify a native host. The independently gated 0.2 owner utilities remain compatibility components; they are not an automatic apply path from this model.

The public repository contains the schemas, named strategy and application profiles, source-backed platform facts, requirements registry, tests and synthetic examples. A private instance repository contains chosen host values, names, content references, decisions and acceptance records. Local runtime state contains observations, admissions, journals, pause/suspensions, immutable receipts and preflight results. Application secrets and configuration stay with their applications. None of that runtime state becomes instance desired state.

## Instance contract

`schemas/instance.schema.json` closes every object. `instance.json` must use sorted keys, compact UTF-8 JSON, and exactly one final newline. Duplicate keys, non-finite values and extra fields are rejected. So is a string value that carries an expression or template marker (`$(`, `${`, a backquote, `{{` or `}}`), that is an absolute path through a `bin` or `sbin` directory or ending in `.sh`, `.py`, `.rb`, `.pl` or `.command`, or that begins with a packet-filter rule opening (`nat on`, `rdr on`, `pass in`, `pass out`, `block in`, `block out`, `load anchor`). Live guest and receiver addresses are rejected in every string value, also when a full stop ends the sentence after them: any IPv4 address or prefix other than the declared LAN address and LAN prefix, and any IPv6 unique-local or global unicast address outside the documentation range `2001:db8::/32`. A dotted number that continues into a longer token, such as a five-part version or a file name, is not read as an address. These checks keep code and live addresses out of instance values; they do not judge prose that merely describes a command or a rule, because nothing in an instance is executed. Every number must be written as a JSON integer (`1.0` is refused), and no string may contain a control character or a line or paragraph separator, so a trailing newline is refused too. The same two rules apply to workload contract files, evidence documents and retained acceptance files; only evidence times may be fractional. Acceptance and deviation entries must name a registered requirement. A bounded decision must be one the safety assessment can evaluate: a blank residual statement or one longer than 2000 characters, a blank signer, or a signature dated before 1970 is refused when the instance is parsed. All arrays and reads are bounded. Exactly one chosen IPv4 LAN is allowed. IPv6 is outside this custom policy; it is not declared blocked.

An instance pins the framework version, exact release-artifact SHA-256, source revision, dependency-lock SHA-256 and schema version. Content verification is not publisher authentication: acquire the release and reviewed digests through your trusted release process. Synthetic example pins are deliberately zero placeholders and cannot verify a real release.

Workloads reference canonical private contract files by relative data path and SHA-256. A contract contains an immutable image reference, resources, mount data, kernel-argument hash, network name/MTU and data-recovery class. It cannot contain credentials, environment values, executable commands or raw runtime inspection output. Checking a contract file proves its content matches the reference; installed definition parity requires separate evidence. Component health/recovery is separate from workload recovery: a failed component never grants workload restart authority.

A contract can state six further facts of a definition. An optional member is left out when it does not apply, and `null` is refused for it. `capabilities` has `add`, `drop` or both; each is an ascending list of distinct names in the runtime's own normalised spelling, upper case with the `CAP_` prefix (`CAP_NET_RAW`), or `ALL` alone. The runtime applies both lists as sets, so their order and a repeated name in a definition carry no meaning. Absent means that the definition adds and drops no capability. `kernel_sha256` is the SHA-256 of the kernel file given to the runtime; absent means the runtime's default kernel. `image_alternates` lists one to three further exact images, ascending and never `image_lock`, that a definition may carry and still be within the contract while one image is being replaced by another or rolled back; absent means that only `image_lock` is admitted. A mount is either a bind mount (`source`, an absolute path) or a named volume (`volume`, the volume's name as the runtime accepts it), never both, and a volume mount requires `recovery_class: named-volume`. The options of a volume belong to the volume, which outlives the definition, and stay outside the contract. `network.mtu` stays required and is an integer or `null`; `null` is the one spelling for a definition that carries no MTU, for which the runtime applies its own default. `init_process_sha256` pins the executable and arguments of the definition's resolved first process. It is the one member whose absence states nothing about the definition: a definition stores its resolved first process whether or not it overrides the image's default, so absent can only mean that the contract does not pin it. Absent `capabilities`, `kernel_sha256` and `image_alternates`, in contrast, are statements. A site whose definition adds or drops a capability, uses its own kernel or may carry a second image states the member; that changes the contract's hash and renews the evidence bound to that workload.

The two argument hashes have a defined input: the package's canonical JSON, which is UTF-8 with sorted keys, no white space between tokens and non-ASCII characters written as themselves. `kernel_arguments_sha256` is the SHA-256 of the array of the kernel arguments the definition was created with (each `--kernel-arg` value, in the order given), and of `[]` when it was created with none. The runtime appends them to its own default command line, so on a host they are part of the stored list, not the whole of it. `init_process_sha256` is the SHA-256 of the object with the members `arguments` and `executable` of the resolved first process, as the definition's stored configuration has them under `initProcess`; its environment is not part of the input. `netorch.workload_contract.kernel_arguments_digest` and `init_process_digest` compute them. Validation treats both hashes as opaque values, so an existing contract stays valid; a site that derived `kernel_arguments_sha256` in another way recomputes it, which changes that contract's hash. Each example below is a member, its hash input, and the value on the next line:

```text
kernel_arguments_sha256  []
4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945

kernel_arguments_sha256  ["panic=1","quiet"]
f8455b62342711136db2149d0e414ea8972e98873c52adfd209b95c2671e6527

init_process_sha256  {"arguments":["--serve"],"executable":"/bin/example"}
1080df65789a07fb9c79c12f872d10b6671c733f53cdcb9db5a838b4071299dd
```

Environment values stay outside the contract, also as a hash: they are where credentials live, and a hash of a short value can be confirmed by guessing. They are not unbound. The retained runtime reader fingerprints a definition's complete native configuration, environment and first process included, when the definition is enrolled and compares it on every read. That fingerprint is local state of the retained owner, not part of the instance. Describing a definition in a contract does not make it creatable: the retained provisioner creates bind mounts only and has no named-volume mount.

Automatic UDP socket ranges have one named definition. The workload and its return-forwarding profile refer to that same definition; an independently copied range is invalid. Strategy/profile versions and cross-owner dependencies are explicit. Resolved digests include names, framework pins, workload contract, LAN identity, relevant policy and transitive publication/fallback contracts. Changing them invalidates older matching evidence.

A discovery selection takes its DNS-SD service types from its named profile.
Optional `service_types` states them where they differ: 1 to 16 distinct TCP
types. For the generic export `published-tcp-export` it lists the types to
export, in ascending order. Without it that profile keeps its automatic form,
which stands for whatever TCP services the workload announces. For a profile
with a list of its own it names a proper subset in the profile's order, and an
import keeps `_airplay._tcp`, the type its eligibility is decided from. The
whole list is said by leaving the member out. No retained owner implements the
automatic form, and its token `auto-tcp` is not a service type of the retained
policy. Whatever turns an instance into retained discovery policy therefore
refuses a selection in the automatic form (`instance.selection_types` returns
`None` for it) and never guesses its types; a listed selection is that
policy's `types` exactly. A report's discovery row carries `service_types`
only where the selection declares them.

A transport row may declare `"source_scope": "any"`. It is the only value: a row without the member is LAN-scoped, and an explicit `"lan"` or `null` is refused, so each row has exactly one byte form and an instance written before the member existed keeps its bytes and digests. `any` is accepted only for a `host-port-redirect`, whose translation target is the host's own address behind its exact publication dependency; every other strategy is LAN-scoped. The resolved profile digest binds the member where it is declared, inside the unchanged version 2 envelope, and the report shows `source_scope` on that profile row only. First-packet evidence for such a profile is valid only when captured from a source outside the LAN prefix; a LAN client proves nothing about this setting.

Resolved transport and discovery digest envelopes are version 2. They now bind the target workload's container name, owning account, runtime/platform context and supervision settings, including observation/read bounds and discovery timing, through each required transport dependency. Version 1 profile acceptance and owner-state digests require renewed evidence; renaming a target or changing its account, runtime, platform or supervision cannot reuse a previous profile's receipt or readiness.

`supervision.discovery_seconds` and `supervision.discovery_misses` record how
often the site's discovery owner makes a pass and after how many consecutive
passes that miss a record it withdraws that record. A selection whose
tolerance differs says so with `misses`, 1 to 8. The instance-wide value is
said by leaving the member out; repeating it on a selection is refused.
`misses` is part of the selection and therefore of its resolved digest. These
values describe the site's own discovery owner. No retained owner reads them:
the bundled discovery owner takes its timing from its own settings.

`supervision` describes the supervisor of the site, which need not be the retained one. `failure_exit_code` is required: the probe status, 1 to 125, on which that supervisor starts a workload whose `recovery` is `proven-stopped`. Zero is success, and a shell uses 126 and above for a program it could not run and for one that a signal ended. The other members of this vocabulary are optional. Each is left out when the site does not state it, `null` is refused, and a document without them keeps its bytes and every digest. `component_exit_code` (1 to 125, different from `failure_exit_code`) is a second status on which the supervisor asks a running guest to start one component without restarting the guest; it is stated exactly when at least one component has `recovery: supervisor-ensure`. `restart_budget` (`starts` 1 to 10 and `window_seconds` 60 to 86400, both required) says that after that many start actions for one workload within the period the supervisor stops acting on that workload until an operator intervenes; it is stated in seconds because the instance does not carry the supervisor's cycle length. `action_timeout_seconds` (1 to 300) is the site's deadline for one whole start action. A workload's `deadlines` object states `probe_seconds`, `action_seconds` or both (1 to 300) where that workload differs from the site defaults `read_timeout_seconds` and `action_timeout_seconds`. A lifecycle tool of kind `supervisor` declares the supervisor itself as a container-API writer. Resolved profile digests bind what is stated: the supervision block as a whole, and a workload's `deadlines` in every profile that targets it.

These members describe a site; they do not change the retained supervisor. It starts on status 42 only, has no second status, no in-guest ensure and no restart budget, takes a check timeout of at most 120 seconds per monitor, and has no setting for the deadline of a start action. `netorch.instance.retained_supervision_gaps` names, as JSON pointers into the instance, every stated member the retained supervisor cannot honour. A renderer for the retained supervisor must refuse an instance for which that list is not empty.

Installed names and state paths can be pinned. Null names are deterministically derived from the private namespace; the PF namespace stays under the platform-defined `com.apple/` anchor namespace. The retained PF owner accepts a pinned or derived anchor that is one component of at most 63 characters below that namespace; a nested or longer name, which this schema still accepts, cannot be installed. `names.helper_label` has no counterpart in the retained owners, because their only root job is the forwarding owner, which reads the runtime inside its own pass (the `helper_label` of the runtime settings is the vendor's network helper, a different thing); the name stays in the instance for a site that still runs such a job until it is retired, so that its label cannot collide with the other four. Pinned or derived, the five launchd labels must be distinct, the export prefix must differ from the import prefix, and the user state directory must differ from the root state directory; two workloads cannot share a container name. Changing names is a reviewed owner migration, not an automatic rename.

## One source of settings during migration

The initial view of an existing installation is generated from literal, static legacy data using the [no-evaluation importer](legacy-import.md). Import provenance and source hashes are private evidence. Executable logic is inventoried and marked underivable, never evaluated to invent missing settings. An inventoried program supplies no value; its receipt alone does not make a projection incomplete, while data that could not be read does. A partial inventory is not a complete instance and is not deployable.

`authoring` records select an owner, closed sections, optional subject IDs and either `generated` or `authored`. Generated sections require their aggregate source hash; authored sections cannot retain a generated-source hash. Overlapping ownership is rejected. Missing section/subject coverage is reported as not fulfilled. Promoting one owner requires its frozen byte conformance and explicit owner flip; the host CLI does neither. The rendered side of that comparison can come from the library function [`netorch.render.render_sources`](legacy-import.md#render-literal-inputs-from-the-instance): it uses each captured literal file as its own template, replaces exactly the values a manifest maps to instance settings and keeps every other byte. A file yields a comparison only when every one of its values is classified as rendered or as the owner's own constant, and no constant repeats an instance setting unless the owner states `independent` for exactly that value. `independent` is a bounded, explicit waiver of the one-author rule and is refused where it is unnecessary. A program of the owner is never rendered: it stays pinned by its hash and its text is searched for the instance's specific string settings. That search is a tripwire, not a proof. The renderer writes no file and installs nothing. Do not maintain a manually edited duplicate alongside a generated authoritative view.

The complete instance contract digest (version 2) binds these authoring records,
including owner, source hash and migration mode. A source or ownership change
invalidates earlier whole-instance attestations even if rendered behavior has
not changed. Only the acceptance ledger itself and informational deviations are
excluded from that digest; version 1 receipts require renewed evidence.

## Six commands

Install the reviewed wheel in a normal unprivileged Python environment. Commands read local files and print JSON to stdout. They do not create state; redirect reports into an existing private host-state directory if desired.

```sh
netorch-host validate --instance /private/instance/instance.json
netorch-host preflight --instance /private/instance/instance.json --collect-local --emit-evidence > /private/host-state/host-evidence.json
netorch-host status --instance /private/instance/instance.json --evidence /private/host-state/host-evidence.json
netorch-host plan --instance /private/instance/instance.json --evidence /private/host-state/host-evidence.json
netorch-host check --instance /private/instance/instance.json
netorch-host report --instance /private/instance/instance.json
```

`validate` checks schema, canonical bytes, references, collisions and referenced contract contents. `preflight` reports the observed prerequisites (each fact with its state, reason, age and value), the resolved names and the platform flags; it does not compare them with the declared `host.baseline`. `status` and `report` print the same complete report: profiles, requirements, facts, workloads and the rest. `plan` compares desired and owner-reported digests and emits **no actions**. `check` exits 1 until all applicable requirements, current evidence and qualified support are established. Root execution is refused (77); invalid/unavailable local data returns 65, with redacted errors.

Optional `--framework-artifact /private/release/package.whl --dependency-lock /private/release/dependency-lock.json` checks exact artifact/lock bytes and the installed package version. `--data-dir` selects the existing private directory containing contract references. `--evidence-dir` selects retained content-addressed acceptance files. No path in these data files is executed.

Only `preflight`, `status` and `report` permit explicit `--collect-local`. This invokes a fixed, bounded local macOS collector, never a LAN/Bonjour probe, owner endpoint, privilege escalation or service action. It checks OS/vendor state readable without administrator rights. Unavailable, malformed, denied or unexamined facts remain unknown. Terminal consent is not LaunchAgent consent; read-only collection cannot establish the latter.

`--evidence` reads one document of `schemas/host-evidence.schema.json`. The ordinary output of every verb, `preflight` included, is a report and not such a document; it is refused there with 65. `preflight --collect-local --emit-evidence` prints the collected document itself as canonical JSON instead of the report view, and is the only command that produces one. The flag is a usage error for every other verb and without `--collect-local`, and it writes no file: redirect standard output into an existing private host-state directory, as in the second command above. Each fact keeps the time it was observed, and a report judges that age against its own clock: a fact older than 300 seconds is `stale` and therefore unknown, so collect again instead of reusing an old document. The collector's document has no profile, workload or component rows. Those belong to an owner snapshot, the same schema with source `owner-snapshot`; nothing in this release writes one, so with the collector's document `plan` shows every profile as pending.

## Truth and confidence

Every profile reports five distinct state layers: desired, admitted, observed, applied and receipt. Admission/application digests supplied in an owner snapshot are explicitly unverified owner reports, not root authorization or kernel readback. Observations keep independent timestamps, reasons and generation IDs. Receipts are historical and never establish current readiness. Transport, discovery, probe, application and heard-audio observations remain separate. A transport success with unknown discovery is not a healthy application. The optional `workloads` and `components` evidence rows describe their own observations. Current readiness also requires every declared workload and component to be freshly present. Required layers/dependencies for one workload must carry the same shared workload-identity generation token; a projection from an old generation cannot be combined with a newly running workload. These are consistency checks on owner-reported evidence, not independent observation or restart authorization.

Transport and discovery readiness both require the owner's desired digest to
match the canonical, admitted and applied digests. An absent or different owner
desired digest remains unready even when other observations are positive.

The instance-to-framework privacy guard checks the instance name, workload and
component IDs, profile/range/tool IDs, authoring owners and the declared baseline
extension, proxy and VPN names as well as addresses,
ports and pinned native names. Generic pattern checks alone cannot recognize
these locally chosen names. Names and the namespace are matched in any letter
case and as a label of a longer dotted name, so a host name with its domain and
a label derived from the namespace are findings too.

The static importer rejects known credential and environment keys in selectors,
targets and nested projections, including camelCase and acronym spellings such
as `apiToken`, `clientSecret` and `APIKey`, `passphrase`, and compound password
names such as `PGPASSWORD`. This is a key-name guard, not a detector
for arbitrary secret values; mappings still require review before committing.

Discovery selections have their own rows and resolved digests, with dependency states. Warm-cache reload does not establish inward Apple-media discovery. The pinned Home Assistant shared-scanner cold-start/receiver-change proof remains a named **unverified** acceptance requirement; offline synthetic coverage does not claim it happened.

An import selection lists a UDP return profile of its own workload. A site that
imports receivers for discovery only, or that admits the return path as a
separate decision, says so with `"return_path": "independent"` on that
selection. It then lists no return profile, and its dependency list may be
empty; its report row then reads `dependencies-none`. The default has no
spelling: `"required"` is refused, and so is the member on an export. A
selection otherwise binds the target workload's container name, the release
pin, the supervision settings and the account, runtime and platform context
through its required dependency; an independent import carries them in its own
resolved digest. `HEARD-AUDIO` and `MULTI-RECEIVER` are asked where an
importing workload also declares a UDP return profile, whether a selection
lists it or not. Every instance that was valid before the setting existed
reports them as before.

Every current export profile requires a TCP publication for its own workload;
a UDP socket at the same port cannot substantiate a TCP DNS-SD announcement.
Instances with imports also report `IMPORT-VISIBILITY`: visibility must be
explicitly accepted with a nonblank owner name and a nonfuture signing time.
That remains an owner-recorded accepted residual, not authenticated authority,
even if a matching acceptance artifact exists. Export-only instances do not
need an import-visibility decision.

Requirement statuses are `fulfilled-verified`, `unverified`, `accepted-residual`, `not-applicable` or `not-fulfilled`. `unverified` means that the requirement applies, that nothing negative is known and that no proof exists at the required tier and method; it does not say the requirement is met and it never counts as served. Version 1 of the outputs prefixed this status with `fulfilled-`. Because the word changed, every output that carries a status has `schema_version` 2: `status`, `check` and `report` with their requirement rows, and `plan` with the safety assessment of each bounded profile. `validate` and `preflight` carry no status and stay at 1. Software invariants can be verified by deterministic tests. Native/application requirements need their exact recorded tier and method. Retained evidence must match schema, host build/runtime, framework artifact and resolved profile or complete instance contract. A single profile receipt cannot cover a second applicable profile, and a record without a profile never stands in for a per-profile requirement. Synthetic sources/proofs and offline fixture contexts never establish native acceptance. Heard audio requires a person's record; root observer and LaunchAgent consent require their named execution contexts. These records are owner attestations with content hashes, not independently replayed measurements or cryptographic authority.

Missing, stale or negative knowledge never improves a row. A reported `absent` or false `recovery_material`, `owner_conformance`, `names_preserved`, `framework_literal_check` or `instance_literal_check` fact keeps its requirement `not-fulfilled` until a positive observation replaces it; growing stale does not clear it and an acceptance record does not override it. These prerequisite values must be booleans when supplied, so numeric zero and the string `"false"` cannot hide a negative result. A reported installed framework hash other than the pinned artifact does the same for the release pin. A recorded deviation names a requirement that is not met: without a current owner acceptance its row is `not-fulfilled`, with one it is `accepted-residual` and never better. An accepted deviation does not lift a row that is `not-fulfilled` for another reason. Generic deviations cannot replace mandatory platform/identity/provenance proof, root authority boundaries, pause preservation, unknown-state guards or the read-only stage. Every requirement whose registry tier calls for native, lifecycle or application acceptance (tiers 3–5) also keeps its proving gate, including heard audio, DNS client identity and unattended boot. Deviations from these requirements remain recorded but `not-fulfilled` until resolved and the required proof established; their signatures cannot waive the acceptance ladder.

`UNKNOWN-NO-RECOVERY` is verified from the model only while every declared start status, `failure_exit_code` and a stated `component_exit_code`, lies in 32 to 63 or 79 to 125. A status in 1 to 31 is also how a supervisor can report a probe that a signal ended, and includes the generic failures 1 and 2; 64 to 78 holds the statuses the framework's own tools return for unknown and for errors. A supervisor that starts on such a status can start a workload on an observation that never completed, so the row is then `not-fulfilled`, and like every row that is not fulfilled it is lifted neither by an acceptance record nor by a deviation. Status 42 stays verified.

Every acceptance record needs a nonblank owner name. A supplied Local Network identity must be nonblank text, and a deviation needs a nonblank statement before its signature can count. Lifecycle authority residuals also require a nonblank statement and signer, and remain `accepted-residual` even with a matching process-inventory record: inventory does not remove another API writer's authority.

A compatible parser is not a supported production host. The candidate contract is macOS 27.0.1 build 26A434, Apple silicon, container 1.5.0 (containerization 0.47.0). The framework ships an **empty native-qualified matrix**; private ledger entries cannot override it. Installed legacy versions, including 1.2.0, remain read-only and unqualified. There is no qualification writer or automatic runtime upgrade in this stage. `PLATFORM-SUPPORT` is the row that matrix governs: a retained record for it (the root runtime observer in its LaunchDaemon context, tier 2) counts only when the matrix lists the instance's declared macOS version, build and runtime version. With the empty matrix the row is never verified, no host is reported as accepted and `check` cannot pass. A listed platform would still leave `mutation_qualified` false.

Bounded direct guest and UDP return profiles require an explicit current T/K/residual signature. The current owner effectively withdraws on the first unknown (K=1); configured K is displayed separately. No whole-pass scheduling/read/apply upper bound is guessed. Without actual finite aggregate bounds and native proof, the withdrawal guarantee remains unverified and zero misdelivery is never asserted. A native LAN alias uses ordinary vendor networking and is not treated as a PF rule to a recyclable guest address. It is a bare declaration without an address or ports, because the one LAN address is the only address an instance names; a workload therefore declares it at most once, and a second alias row for the same workload is refused.

Unattended recovery requires a separately accepted DNS-ready limit and boot/restore evidence. FileVault requiring a person does not fulfil that goal through automatic login: a reported `on` blocks at any age, only a current observation counts as `off`, and without one the declared baseline decides. A FileVault state that is neither currently observed off nor declared off is `not-fulfilled`. Lifecycle/API writers and residual authority are explicit; a signature is an owner decision, not authentication against a hostile writer. The read-only stage never changes power, login, startup chains or recovery behavior.

An instance that accepts unattended recovery also names who starts what after
a boot. `lifecycle_tools[].kind` has the value `supervisor` for the site's
supervisor, and at most one tool has that kind. That tool may carry
`starts_fleet: true`: it is the one starter of the workloads. The member is
written only as `true`, only on the supervisor tool and only together with
`container_api_access: true`; it is left out otherwise, so an instance without
it keeps its bytes and both digests. `BOOT-RECOVERY` is `not-fulfilled` for an
accepted unattended recovery unless exactly one tool carries `starts_fleet: true`
and at least one tool carries `starts_runtime: true`, because without a declared
starter of the workloads and of the runtime nothing restores them after a boot.
Both declarations describe the site; they start nothing. An instance that
accepted unattended recovery before this rule names the tool that starts its
workloads and the tool that starts the runtime. That changes its contract
digest, so a retained instance-wide acceptance record is renewed.

## Proof before activation

Run schema/property/fault/fixture/conformance tests in CI. Keep native parser/packet/consent/startup/application/heard-audio acceptance separate and bind it to the exact version/host/profile. Before any owner is activated: inspect the generated private view, fill only genuinely known missing values, pin existing names, prove byte parity for that owner, review its exact resolved parameters and rollback, and complete the separately approved native acceptance. No report command performs those actions.

The two checked-in examples exercise different synthetic host/account/LAN/network/workload choices: `examples/instance.json` includes bounded UDP plus Apple-media import; `examples/instance-structural.json` has only native publication/export and no bounded transport. Both are valid data, not accepted installations.

# Deployment and owner integration

> **0.3 stage boundary:** this guide describes retained owner mechanisms and mock
> contracts. Native authority expansion is unavailable while the accepted support
> matrix is empty. Existing installed owners stay in place; see
> [read-only workflow](getting-started.md) and [migration gates](site-migration.md).

Version 0.2 supplies complete user/root deployment bundles, an Apple Container
reader and lifecycle adapter, a native Bonjour owner and an independent PF owner.
The same external tables can describe an entire site's custom container-networking
setup. Installation is explicit, domain-separated and journalled; a successful
public build does not change a production host.

Use [getting started](getting-started.md) for the end-to-end command sequence,
[provisioning](provisioning.md) for the bundle transaction, and the
[runtime](apple-runtime.md), [workload](workloads.md),
[Bonjour](bonjour-owner.md) and [PF](pf-owner.md) guides for owner contracts.

## External inputs and durable state

Keep site-specific names, addresses, MACs, paths, ports, recipes and credentials
outside the public checkout. The following are conceptual records; use the
versioned schemas and actual owner formats.

```text
site/
  network.json             policy or generated owner catalog
  runtime-settings.json    accepted runtime identity and enrolled definitions
  workloads.json           optional explicit initial-create recipes
  bonjour-settings.json    interface bindings and scanner settings
  bindings.json            trusted user provider endpoints
  forwarding-settings.json independent administrator-owned observer settings
  deployment.json          domains, jobs, monitors, paths and artifact hashes
user-state/
  admissions.json          user profile approvals
  intent.json              durable operator pause and holder suspensions
  journal.json             reconciliation phases
  installation-journal.json installation phases
  installation-receipt.json retained reviewed release identity
root-state/
  policy.json              protected installed desired snapshot
  admissions.json          independent expanded root approvals
  operator-intent.json     independent negative authority
  live.json and journal.json known exposure and interrupted phase evidence
```

All owner inputs are bounded, strictly parsed, protected single-link regular
files. Settings and mutable private state use mode 0600 and private directories.
Root code, policy, admissions and ancestors must be administrator-owned and
protected against user replacement. A separately protected read-only root report
contains typed networking observations, not credentials or raw inspect output.
Mutable intent, admissions and journals are never release artifacts.

The framework does not install Python, Monit, Apple Container or an application.
Install reviewed managed tool artifacts first. Root must use a root-owned installed
Python/package in isolated mode, never a user's checkout or virtual environment.
No `sudo`, privileged RPC or automatic runtime upgrade is embedded in the user
coordinator. The manifest refuses `sudo`, `su` and `doas` in every job, monitor
check and monitor recovery command line. Known shell invocations with `-c`
(including combined flags such as `-lc`) or `--command` are also refused, so an
explicit wrapper cannot turn manifest data into a shell command string.
These are narrow guards, not executable sandboxing: renamed helpers, interpreter
code and reviewed script files remain trusted operator bindings. Their behavior
and privileges require review; a valid manifest cannot prove arbitrary programs
safe.

## 1. Inventory and choose authority

Identify every native, third-party and custom owner and its current source. Record
accepted OS/runtime/tool versions, executable/job identity, publication contracts,
persistent mounts, helper generation, boot/login constraints and missing gates.
Use bounded read-only observation and enrolled definition capture before writes.
An inspection timeout, Local Network denial or contradictory stopped listing is
unknown, not proof that a workload needs recovery.

While a legacy owner remains authoritative, statically derive its literal facts
and fail a regeneration check if the catalog drifts. Never source configuration
as code. Flip ownership only in the same change that makes the previous input
generated, with rendered equivalence. Each setting has one author at every step.

Select exactly one writer per anchor, publication, service lifecycle and Bonjour
role. Disable a competing schedule through its own guarded owner procedure before
promotion. The installer does not guess which unrelated Login Item or LaunchAgent
is obsolete.

## 2. Validate and preview without network changes

The synthetic examples are documentation shapes, not deployable defaults. Copy
and fill private inputs outside the checkout, then validate them and observe the
reviewed user bindings:

```sh
netorch validate --config /operator/site/network.json
netorch init-state --state-dir /operator/state/netorch
netorch observe --config /operator/site/network.json \
  --bindings /operator/site/bindings.json
netorch reconcile --config /operator/site/network.json \
  --bindings /operator/site/bindings.json \
  --admissions /operator/state/netorch/admissions.json \
  --state-dir /operator/state/netorch
```

Initial intent is paused. Reconciliation is a plan until
`--execute-user-owners` is explicitly supplied; it cannot execute external-root
actions. Provider paths are trusted local bindings, not network-policy commands.
Real fixed owner endpoints independently validate requests and current evidence.

Optional initial workload provisioning is a separate operator maintenance command.
It plans exact pinned create arguments, requires the reviewed digest and creates
only missing declared workloads. It preserves existing definitions and does not
stop, delete, replace or recreate a container. See [workloads](workloads.md).
Enrollment alone reads a definition and records its protected identity; it does
not configure the application.

## 3. Build a deterministic installation bundle

```sh
netorch deploy validate --manifest /operator/site/deployment.json
netorch deploy build --manifest /operator/site/deployment.json \
  --config /operator/site/network.json --output /operator/staging/bundle
netorch deploy verify --bundle /operator/staging/bundle
netorch deploy plan --bundle /operator/staging/bundle --scope user
netorch deploy plan --bundle /operator/staging/bundle --scope root
```

The renderer captures protected sources once through descriptors, checks declared
SHA-256 hashes, parses JSON strictly and generates immutable policy copies,
launchd plists, Monit configuration and the captured PF backend. The release ID
binds deployment and policy; the bundle digest binds every captured/generated byte
and closed inventory. Validation rerenders managed job bytes and rejects extra
files or changed content. Settings artifacts are copied byte-exact; only command
arguments and working directories support fixed `{release}`/`{state}` placeholders.

Review plans, exact hashes and existing ownership before installation. Artifact
hashes in examples are deliberately all zero; they cannot approve actual files.
The source package and executable paths require their own reviewed installation.
The bundle is not permission to run a privileged user-supplied binary.

## 4. Install user scope

```sh
netorch deploy install-user --bundle /operator/staging/bundle \
  --expected-digest REVIEWED_BUNDLE_SHA256
```

Run directly as the manifest's user on macOS. The transaction creates durable
intent paused on first install, preserves existing operator pause, takes its own
holder suspension, stages immutable files, checks Monit syntax and owned job
hashes, stops only managed jobs, installs/loads them and reads launchd back.
Only complete success releases that transaction's suspension. It does not resume
the operator or grant admission.

The generated coordinator, Bonjour service and Monit jobs run in the declared
user domain. Bonjour's separate publisher/watchdog owns its registration children
and checks independent dependency evidence; the endpoint cannot supply fabricated
records. Heartbeat failure cannot restart a healthy container. Only the workload
probe's reserved status 42 can permit a separately guarded proven-stopped start.
Signals, timeouts, denial and unknown results do not meet that condition.

Monit runs the recovery command once when that rule first matches. If the attempt
starts nothing, Monit does not run it again while the probe keeps returning 42.
A workload monitor may therefore set the optional integer
`recovery_repeat_cycles` (1 to 360). Its rule is then rendered with
`repeat every N cycles`, and Monit runs the command again every N cycles for as
long as the probe returns 42. There is no attempt budget and no Monit restart
action: every attempt is the same guarded start of a workload that two fresh
observations prove stopped. A monitor without a recovery command cannot set it.
Without the setting the generated file is byte-identical to what earlier
versions rendered, and a manifest that does not use it keeps its digests.

Local Network consent must be accepted in the actual LaunchAgent identity and
launch context. Terminal/SSH success does not prove this context. Record consent
and test after code identity changes; root is not the workaround.

## 5. Independently install and admit root scope

```sh
netorch deploy prepare-root --bundle /operator/staging/bundle \
  --output /operator/staging/root-reviewed-bundle
```

This only prepares reviewed bytes. An administrator separately invokes the
root-owned installed package to install root scope:

```sh
/Library/Netorch/runtime/bin/python3 -I -m netorch deploy install-root \
  --bundle /operator/staging/root-reviewed-bundle \
  --expected-digest REVIEWED_BUNDLE_SHA256
```

Use paths from the actual manifest. Root installation verifies protected code
ancestry and exact bundle identity, takes its own durable suspension and installs
the independent PF pull job. It does not inherit authority from a user admission.
New or changed profiles remain pending. Administrator review/admit/resume uses
[the PF owner's fixed commands](pf-owner.md).

Root admission binds complete resolved policy, observer settings, strategy and
installed implementation/backend semantics. Changed ports, interface, service
contract, settings or code must not silently preserve old authority. The root job
independently observes runtime/kernel state, rereads gates before activation,
withdraws stale targets and invalidates their retained guest states. It mutates
only its owned anchor and holds only its own PF enable reference.

Native host publication remains Apple Container's user-owned capability. Root can
redirect to an independently verified same-service publication, but cannot claim
its ownership. A coincident listener belonging to another service is insufficient.

## Shared guest identity and UDP acceptance

An IP in a PF rule names an address, not a service. A shared pool can reassign
addresses and retained states can outlive rules. Direct guest/UDP-return profiles
therefore require explicit bounded-risk acceptance with independent observation
age, withdrawal and retained-state readback. This cannot certify a zero-duration
misdelivery race after every crash. A requirement for absolute exclusivity needs
a separately reviewed structural network design.

The guest automatic socket range and admitted return range must agree exactly.
Outbound NAT preserves source ports; inbound RDR has no replacement target port.
The scope is the reviewed LAN, supporting changing addresses and multiple media
receivers. Do not widen ranges to mask leaks, capacity or discovery faults.

The optional direct-DNS fallback retires/drains the old direct path before a later
fresh pass uses the same service's admitted native publication. It reports a
changed effective strategy because client identity differs. Unknown runtime
identity cannot activate either path.

## Native acceptance and boot availability

Installation readback proves managed jobs are registered; it does not prove
packets, application discovery or audible output. Promote only with evidence at
the relevant [testing tier](testing.md):

- First request and reply, both range boundaries and probes outside the range.
- Actual hook order, anchor readback, original client identity and retained-state
  invalidation after generation change.
- Genuine import/export parity, exact service/publication provenance, real user
  consent, expired/hung scanner withdrawal and child exit cleanup.
- Application discovery/reconnect for changing/multiple devices.
- Explicitly approved container/runtime restart, reboot and restore rehearsal.
- Human confirmation for requirements such as audible playback.

If the runtime requires a user session, a root forwarding job cannot make its
workloads available before login. A sole LAN resolver in that runtime has a
separate unattended-reboot availability decision. Document chosen login/resolver
architecture, privacy readiness and measured time to first valid answer. The
framework does not enable automatic login, change FileVault, power settings or
router DNS. These remain explicit native/application-owner decisions.

Runtime upgrades and container recreation require separate maintenance and
reacceptance. Versioned reader fixtures cover declared shapes, not future unknown
schemas. Preserve image pins, persistent mounts, kernel arguments and application
configuration. Networking installation never implies recreation.

## Failure, rollback and cleanup

Every reconciliation and installation records its finite phase and stops after an
unexpected partial failure. Do not replay an old plan, remove a live lock, flush
global PF state or invent rollback commands. Inspect fresh readback and the saved
phase, then choose the explicit operation:

```sh
netorch deploy recover --state-dir /operator/state/netorch --scope user \
  --expected-digest FAILED_BUNDLE_SHA256
netorch deploy rollback --state-dir /operator/state/netorch --scope user \
  --expected-digest CURRENT_BUNDLE_SHA256
```

Use root-owned execution and the manifest's root state directory for root scope.
Recovery fences an interrupted installation and its verified predecessor;
rollback fences a committed current release and refuses while an installation or
recovery is unfinished. A rollback that failed is repeated with the same command
and digest. They restore only verified owned job
bytes, preserve current negative intent/admissions and do not replay stored guest
addresses. Root replacement first suspends and withdraws through its independently
owned boundary. Damaged intent, changed release/job bytes, unknown journals or
unavailable predecessor inhibit recovery.

Operator pause and holder suspension are separate and never expire. A transaction
releases only its own hold. `acknowledge-journal` acknowledges an exact inspected
reconciliation journal; it does not repair, approve or resume. Receipts are history,
not kernel truth. A kernel lock reporting busy is a retry condition, not permission
to delete its inode.

Retain required recovery material outside immutable releases. Clean up only after
checking installed jobs, settings, release receipts and rollback references. Never
delete durable intent, admissions, a live owner lock, a referenced executable,
application data or the verified predecessor merely because it looks temporary.
The framework does not set a site's backup retention policy or silently delete
service backups.

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

Use [getting started](getting-started.md) for the read-only workflow of this
release, [provisioning](provisioning.md) for the bundle transaction, and the
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
  intent.json              durable operator pause, holder suspensions and service holds
  recovery-starts.json     starts issued by recovery; only with a restart budget
  journal.json             reconciliation phases
  installation-journal.json installation phases
  installation-receipt.json retained reviewed release identity
root-state/
  policy.json              protected installed desired snapshot
  admissions.json          independent expanded root approvals
  operator-intent.json     independent negative authority
  live.json and journal.json known exposure and interrupted phase evidence
```

All owner inputs are bounded and strictly parsed. How far a reader also protects
the file depends on the input:

- The state store opens the records of a state directory (intent, journals,
  receipts and the root owner's records) without following a final symbolic
  link. They must be single-link regular files of mode 0600 owned by the calling
  user, in a private mode 0700 directory of that user. The provider bindings and
  the Bonjour settings, with the admissions and intent they name, are held to
  the same file rule.
- Bundle sources and bundle files are also opened without following a final
  symbolic link and must be single-link regular files that group and others
  cannot write. The PF owner's `install` reads its policy, settings and backend
  inputs once, in the same way, as single-link regular files that must not
  change while they are read; it does not check their mode.
- `netorch` reads `--config`, `--admissions`, `--snapshot` and `--intent` as
  general data through the bounded reader, which requires a regular file,
  follows a final symbolic link and checks neither owner, mode nor link count.
  The same reader serves a deployment `--manifest`, the `intent.json` of a
  reconciliation preview, a `snapshot-file` binding, the policy path named in
  Bonjour or runtime settings, and the Apple runtime and workload commands for
  their settings file, the intent and admissions paths named in it and a recipe
  file.

Keep settings and mutable private state in mode 0600 files and private
directories whichever reader applies.
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
netorch observe --config /operator/site/network.json \
  --bindings /operator/site/bindings.json
netorch reconcile --config /operator/site/network.json \
  --bindings /operator/site/bindings.json \
  --admissions /operator/state/netorch/admissions.json \
  --state-dir /operator/state/netorch
```

`netorch init-state --state-dir /operator/state/netorch` creates the state
directory with a paused initial intent. This release refuses it with status 78
(`stage-not-qualified`) before anything is created, so it writes no initial
intent; a state directory left by an earlier installation is read as it is. The
preview never initializes state: an absent or unreadable `intent.json` is
planned as damaged intent, which inhibits activation, and an unreadable
`--admissions` file ends the command with status 65. Reconciliation is a plan until
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

A job may carry the optional member `process_type`. It has two values:
`"background"` renders the launchd key `ProcessType` as `Background`, and
`"standard"` renders it as `Standard`. Any other value, including `null`, is
refused. A job without the member is rendered as `Background`, which is what
every job was rendered as before the member existed. Writing `"background"` out
is the same manifest as leaving the member out: it has the same canonical form,
release identifier and bundle digest. A manifest that does not use `"standard"`
therefore keeps its digests and its plist bytes, while one that uses it is a
different release, which earlier versions refuse as a violation of the closed
schema. Which class a job needs on a given host is the site's decision; the
manifest only selects what is rendered.

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
long as the probe returns 42. The rule has no attempt budget and no Monit restart
action: every attempt is the same guarded start of a workload that two fresh
observations prove stopped. A monitor without a recovery command cannot set it.
Without the setting the generated file is byte-identical to what earlier
versions rendered, and a manifest that does not use it keeps its digests.

A budget of starts, where one is wanted, is a setting of that guarded start and
not of the rule ([`restart_budget`](apple-runtime.md#restart-budget) of the
runtime settings): once it is spent the start holds the service instead, the
probe no longer returns 42 and the rule stops matching until an operator
releases the hold.

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

What the root forwarding owner does after a reboot is such a decision as well:
the optional `cold_start` member of its settings, described under
[After a reboot](pf-owner.md#after-a-reboot). Without it the owner leaves its
remembered rules to an administrator, and forwarding stays withdrawn after a
reboot until `withdraw` and `resume`.

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
An installation stopped by an interrupt, a kill or lost power is recovered with
the same command; [provisioning](provisioning.md) lists what it accepts.
Recovery fences an interrupted installation and its verified predecessor;
rollback fences a committed current release and refuses while an installation or
recovery is unfinished. A rollback that failed is repeated with the same command
and digest. They restore only verified owned job
bytes, preserve current negative intent/admissions and do not replay stored guest
addresses. Root replacement first suspends and withdraws through its independently
owned boundary. Damaged intent, changed release/job bytes, unknown journals or
unavailable predecessor inhibit recovery.

Installation, recovery and rollback keep every hold on a single service
([state contract](state-machine.md)), as they keep the pause. A release from
before holds reads an intent file that contains one as damaged: its installer
refuses to install, and after a rollback to such a release every owner of it
stays inhibited until the holds are released by a release that knows them.
Release holds before rolling back that far where possible, and place the first
hold only after every scope runs a release that knows holds.

Operator pause, holder suspensions and holds on single services are separate and
never expire. A transaction releases only its own suspension.
`acknowledge-journal` acknowledges an exact inspected
reconciliation journal; it does not repair, approve or resume. Receipts are history,
not kernel truth. A kernel lock reporting busy is a retry condition, not permission
to delete its inode. Root installation, rollback and recovery apply that to the
forwarding owner: an owner command that exits 75 has done nothing and is repeated
every 0.5 seconds for at most 5 seconds, because the scheduled pass, and the job
an installation has just loaded, hold the owner's lock while they run. An owner
that is still busy after that fails the operation in its recorded phase, as any
other status does at once. Status 75 from `launchctl` or Monit is never repeated.

Retain required recovery material outside immutable releases. Clean up only after
checking installed jobs, settings, release receipts and rollback references. Never
delete durable intent, admissions, a live owner lock, a referenced executable,
application data or the verified predecessor merely because it looks temporary.
The framework does not set a site's backup retention policy or silently delete
service backups.

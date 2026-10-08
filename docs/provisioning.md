# Complete deployment bundles and independent installation domains

> **0.3 stage boundary:** this guide describes retained owner mechanisms and mock
> contracts. Native authority expansion is unavailable while the accepted support
> matrix is empty. Existing installed owners stay in place; see
> [read-only workflow](getting-started.md) and [migration gates](site-migration.md).

Deployment settings are external, explicitly trusted operator data, distinct
from network policy and runtime observations. `schemas/deployment.schema.json`
is closed and versioned. The portable renderer, installer, explicit rollback and
failed-upgrade recovery are implemented in `deployment.py`; launchd and Monit
remain the maintained scheduling tools. No privileged coordination daemon or
new multicast stack is introduced.

## Inputs and one author per setting

`network.json` contains scopes, services, transport and discovery policy.
Runtime settings bind enrolled existing container definitions and persistent
identities. Bonjour settings identify the one selected-record publisher.
Provider bindings identify trusted user adapters. Root forwarding settings bind
its independent observer, backend digest, root state and report location.
`deployment.json` specifies installation paths, job labels, account/domain,
command argument arrays, monitors and SHA-256 hashes of each captured input.

Use the synthetic `examples/deployment.json` as a table shape. Its documentation
paths, UID and all-zero hashes are deliberately unusable production defaults.
Replace them outside the checkout, bind actual files and record reviewed hashes.
The managed Python/package and Monit executable must already be installed from
reviewed artifacts. Production interpreters, package source and privileged
backend code must never refer to a mutable user checkout.

Copied JSON artifacts remain byte-exact: no recursive interpolation, shell
evaluation, environment expansion or speculative rewriting is performed.
Paths inside private settings can refer to stable protected private data and
installed executables. Only command arguments and working directories support
the two fixed placeholders `{release}` and `{state}`. Each artifact has exactly
one author. Intent, admissions, journals and receipts cannot be release artifacts.

Before promotion, review existing single-owner enrollment and disable a competing
schedule in its own guarded owner mechanism. Netorch never guesses which legacy
Login Item, helper or unrelated LaunchAgent is obsolete.

## Render, inspect and validate

```sh
netorch deploy validate --manifest /operator/site/deployment.json
netorch deploy render --manifest /operator/site/deployment.json \
  --config /operator/site/network.json --output /operator/staging/bundle
netorch deploy plan --bundle /operator/staging/bundle --scope user
netorch deploy plan --bundle /operator/staging/bundle --scope root
```

The renderer captures each source through `O_NOFOLLOW`, requires a regular
single-link protected file, checks its expected content hash, and parses JSON
strictly. It generates immutable user/root policy copies, plists, Monit config
and a captured PF backend. A release ID binds deployment and complete policy;
a bundle digest binds every generated/captured byte and the closed inventory.
Files are mode 0600 in mode 0700 directories. A second capture immediately before
installation must still match each reviewed hash, so swapping a source after
validation never promotes its new bytes.

Validation rechecks generated launchd and Monit bytes against the actual renderer,
requires identical policy content for both domains, checks backend identity and
rejects extra files. A rehashed malicious plist cannot introduce an arbitrary
root executable. All root jobs use the fixed independent PF pull command.

## Install user scope

```sh
netorch deploy install-user --bundle /operator/staging/bundle \
  --expected-digest REVIEWED_BUNDLE_SHA256
```

This must run directly as the manifest's user on macOS. It creates durable intent
paused on first installation; subsequent installations preserve existing pause
and every other holder's suspension. It adds its own installation suspension,
stages a new immutable release, syntax-checks Monit, verifies old managed file
hashes and new label absence, stops only owned jobs, installs generated plists,
loads them and reads launchd back. Its own suspension is released only after the
entire operation succeeds. It does not resume the operator or create admissions.

`launchctl bootout` can return before launchd has removed the job, and loading
the same label again can fail until it has. In either scope, installation,
rollback and failed-upgrade recovery therefore wait after stopping a loaded job
that they load again: they read the job with `launchctl print` at once and then
every 0.25 seconds until launchd reports it absent, and load it only then. No
further read is started once 20 seconds have passed for that job; the operation
then goes on and loads the job as it did before this wait existed. The wait
never fails an operation. A job that was not loaded, or that is stopped and not
loaded again, is not waited for.

Existing root jobs, application state, image pins, mounts, kernel arguments,
container resources and Apple runtime configuration are untouched. A caller
must use the separately documented explicit workload operation for a genuinely
new container; networking installation never implies container recreation.
That operation creates only what its recipe grammar covers; a definition that
a workload contract describes, such as one with a named-volume mount, is not
thereby creatable.

## Prepare and explicitly install root scope

```sh
netorch deploy prepare-root --bundle /operator/staging/bundle \
  --output /operator/staging/root-reviewed-bundle
```

Preparation only copies the captured reviewed bundle and returns its exact
digest. It never invokes root, `sudo`, a privileged RPC or a packet filter.
An administrator then invokes a **root-owned installed** Python/package directly:

```sh
/Library/Netorch/runtime/bin/python3 -I -m netorch deploy install-root \
  --bundle /operator/staging/root-reviewed-bundle \
  --expected-digest REVIEWED_BUNDLE_SHA256
```

The initial trusted interpreter/package bootstrap is an explicit administrator
installation of reviewed artifacts, not executing a user's virtual environment
as root. Root installation refuses user-owned or writable code ancestors. Root
and user installation trees and launchd domains are disjoint. Administrator
installation calls the independently owned PF install operation with the exact
captured policy/settings/backend. That owner preserves admissions and negative
intent; new or changed content remains pending. Its snapshot, admission and state
live outside immutable releases. The generated LaunchDaemon then pulls this own
snapshot on its independent schedule. No planner action or target enters root.

The root scheduler must use the same resolved, protected interpreter as the
administrator installer. Supply the physical executable path: this deployment
installer rejects a lexical executable symlink with `O_NOFOLLOW`, even though
the independent PF owner can validate protected interpreter symlink chains.
A root-managed environment created with executable copies can satisfy that
stricter requirement; its base interpreter, standard library and installed
packages must also remain protected. Bootstrap remains an administrator action.
The native launchctl executable is `/bin/launchctl`.
The captured forwarding settings are parsed during rendering: backend hash,
independent owner and polling interval must agree, and the schedule cannot exceed
the profile observation-age bound. Its read-only report directory is separately
provisioned root-owned and publicly traversable, for example
`/Library/Application Support/NetorchReports`; it cannot be placed inside private
root release, admission or state trees. Reports are readable by the coordinator
but remain unwritable to it. Provider bindings must use the protected `root-report`
reader; ordinary user snapshot files cannot confer root admission.

Keep the report directory outside newly created private common ancestors too.
For example, installing private owner state below `/Library/Netorch` can create
that parent with mode `0700`; `/Library/Netorch/reports` would then be unreadable
to the user coordinator even if its own mode were `0755`. The separate report
directory above avoids that conflict. Provisioning refuses inaccessible report
ancestry and never relaxes permissions on existing private owner state.

Administrator admission and root operator resume remain explicit owner commands,
after reviewing the resolved content and bounded-risk decision. Installing a new
image of this framework never inherits admission solely by profile name. A
backend/observer semantic change invalidates the previous bound authority.

Privileged installation, state, launchd and log ancestry must be root-owned,
unwritable by other users and free of ACLs. The installer reuses the independent
PF owner's strict ACL checks and refuses incomplete ACL inspection. Generated
root artifacts and operational records receive descriptor-based metadata and
content readback; immutable release bytes are fenced again before the root
owner installer, and installed plist bytes immediately before launchd bootstrap.
Existing launchd stdout/stderr targets must be protected, single-link regular
files without ACLs; links, foreign owners or writable targets block bootstrap.
These rules apply during installation, rollback and failed-upgrade recovery.
User installation keeps its separate permission rules, including existing
deny-only ACL support; it cannot supply privileged authority.

## Partial failure, recovery and rollback

Every operation keeps an installation journal separate from reconciliation
journals. Failure, including an interrupt, records its phase and stops further
work. A kill, a dropped session or lost power cannot record anything; the journal
then keeps the in-progress phase it had reached. No speculative
automatic rollback, container stop, global PF flush, lock deletion or runtime
restart runs. The operator inspects current evidence before an explicit recovery:

```sh
netorch deploy recover --state-dir /operator/state/netorch --scope user \
  --expected-digest FAILED_BUNDLE_SHA256
netorch deploy rollback --state-dir /operator/state/netorch --scope user \
  --expected-digest CURRENT_BUNDLE_SHA256
```

Recovery of a failed upgrade verifies the retained predecessor and exact failed
journal, accepts only old or new owned job bytes, restores predecessor files/jobs
and preserves current intent. It writes the receipt back as the failed
installation found it: the journal holds that receipt, so the restored release
still names its own predecessor and can be rolled back to it. A failed first
installation removes only verified new job files and leaves its private staged
release and gated root snapshot as evidence. No application or administrator
admission data is deleted.

Recovery accepts a journal in `failed`, a journal left in an in-progress
installation phase, which it treats as the failed phase, and a journal left in
`recovering` by a recovery that was itself stopped. It reads the journal under
the lock the installer holds from its first read to its last write, so an
in-progress phase read there was left by a process that is gone; while one
runs, recovery reports busy. Three stops need no more than the same command
with the bundle's digest:

- before the first journal write, when only the user suspension exists:
  recovery releases that suspension, reports `hold-released` and changes
  nothing else. It does so only when no installation journal is open and the
  suspension is held by exactly that digest;
- while the release is being staged: no job has changed, the incomplete release
  is not read as evidence and is retained;
- after the user suspension was released but before the journal was closed:
  recovery takes the suspension again for its own run. A suspension held by
  another holder, or damaged intent, still inhibits recovery.

Rollback is an explicit reversal of a **committed** release. It verifies all
retained files, fences the exact current digest and restoration boundaries, and
restores the previous jobs. Root rollback also uses its own owner installer to
restore reviewed desired policy/backend; it never clears admissions or pause.
Only one predecessor is retained in the receipt to bound journal growth: the
receipt of a new release names the release it replaced without that release's
own predecessor, and an installation journal holds the replaced receipt as it
was, with its one predecessor and nothing older. A journal written by an earlier
version holds the replaced receipt without its predecessor; recovering such a
journal restores the release as that version did, with no release to roll back
to. With the record of the release being installed the journal holds up to
three release records. An installation whose journal would not fit the state
store's bound for one record (1 MiB) is refused before it takes its suspension
or opens a journal, so nothing is changed and nothing needs recovery. Older
release files can be retained according to the site's separate cleanup policy.
A committed rollback revalidates the predecessor's interpreter and platform
contract before any transition or native effect. Retained receipts do not prove
current executable trust. A root predecessor must still use the invoking trusted
interpreter; relocating or replacing that runtime is a separate maintenance step.

A release rollback is not an application-data restore or kernel-state proof.

Rollback reads the installation journal before it writes anything. A failed or
unfinished installation or recovery belongs to `recover`: rollback refuses and
leaves that journal unchanged. Its own journal records the scope and the bundle
digests of both releases, so a rollback that failed or was stopped is repeated
with the same command and digest. The repeat accepts a job file of either of
the two releases, tolerates a job it had already removed, boots out the jobs of
both releases before it loads the predecessor's. If the predecessor's receipt
is already in place, it revalidates that release's retained and installed job
bytes and requires every restored label to be currently loaded before releasing
its hold and closing the journal. A receipt alone is not fresh evidence after
an interruption. Changed files or an absent/unreadable job leave the hold and
journal unchanged for inspection; completion does not repair them. A first
attempt still requires the current release's exact job bytes. A journal left
by a failed rollback of an earlier version has no scope or digests and is not
resumed.

Without a receipt there is no release to roll back, and rollback refuses. A job
that only the previous release has is new to the installation. Rollback checks
it as an installation checks a new job, before it takes its suspension, writes
its journal or stops anything: a file of that job's name in the launchd
directory refuses the rollback, and so does a label of that name that
`launchctl print` does not report absent. Only a repeated rollback accepts such
a file, and only with the previous release's exact bytes. Its first attempt
writes that file before it loads the job, so with the file launchd is not asked
about the label, and without it the label must be absent as on a first attempt.
An upgrade or a recovery does not wait for a job that it stops and does not load
again. A rollback started while launchd still reports such a job is refused by
this check; nothing has changed then, and the same command is repeated.

An interrupted rollback also stops and retains its phase. An unexpected foreign
file, changed boundary, damaged intent, replaced release, unavailable restore
material or ambiguous state inhibits recovery instead of inventing a repair.
Failed releases are retained for inspection and cannot be overwritten; retry
with a separately reviewed new release or retire evidence only after checking
live references. An installation whose release directory is already retained is
refused before it takes its suspension or opens a journal, so that refusal
leaves nothing to recover. No timer clears an installation suspension.

Before any privileged scheduler stop or policy replacement, the administrator
installer takes a holder-specific root installation suspension and invokes the
owner's verified withdrawal/state-draining operation. It releases that holder
only after the restored/new scheduler is read back. That scheduler starts a pass
as soon as it is loaded and holds the owner's lock meanwhile; an owner command
that reports the lock busy (exit 75, nothing done) is repeated for at most
5 seconds before the operation fails. A failed first root install
without a predecessor leaves this holder in place when no existing operator
pause otherwise inhibits the owner; recovery reports `root_gate_retained`.
Resolve that retained gate through the independent owner's reviewed lifecycle
operation after establishing a replacement scheduler, never a blanket resume.

## What verification establishes

Portable tests execute real closed parsing, source capture, deterministic render,
filesystem staging, admission, independent PF planning and phase-aware recovery
against fake launchctl/Monit/PF effects. They include a complete seven-workload
deployment, changed-content pending, crash/failure paths, stable operator pause,
foreign job protection and source replacement between validation and use.
Privileged adversarial tests additionally cover ACL-bearing ancestry, journals,
retained releases and log leaves; content replacement before owner installation
or scheduler bootstrap; and operational-record changes during capture. The
portable root lab models protected temporary ancestry without weakening real
checks against writable shared directories.

Native `monit -t` establishes config syntax. Launchctl readback establishes job
registration, not workload readiness or packets. Platform acceptance still
requires the declared macOS/runtime versions, actual user Bonjour consent,
first/reply packets, state draining, application discovery/reconnect and the
separately approved boot/login availability test. Hardware acceptance is reported
as unestablished by the installer; it cannot be manufactured by a successful mock.

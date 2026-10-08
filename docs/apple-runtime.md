# Apple Container: enrollment, live evidence and recovery

> **0.3 stage boundary:** this guide describes retained owner mechanisms and mock
> contracts. Native authority expansion is unavailable while the accepted support
> matrix is empty. Existing installed owners stay in place; see
> [read-only workflow](getting-started.md) and [migration gates](site-migration.md).

`netorch.apple_runtime` is the shared versioned reader. It observes existing
containers and their native published ports; it does not install/upgrade the
vendor runtime or take over application configuration. An independent PF owner
uses this reader directly as root, with every vendor CLI subprocess explicitly
dropped to the enrolled account's UID/GID, cleared supplementary groups, minimal
environment and explicit HOME. The coordinator invokes its user endpoint through
an explicit private binding. No root endpoint exists.

## Private runtime settings

`runtime_settings.py` contains immutable settings types and a bounded closed
loader. Operator data supplies:

| Table | Fields and purpose |
|---|---|
| Account | UID, GID, HOME of the genuine vendor runtime user |
| Runtime | Absolute CLI path, exact accepted version, legacy-risk acknowledgement, optional `start_timeout_seconds` |
| Networks | Scope, native network name/gateway, launchd helper domain/label, expected program and UID |
| Service contracts | Service/name/scope, full native configuration fingerprint, persistent mount identities, hashed file receipts, optional tolerated stopped peer names |
| Paths | Private generated policy, user admissions, durable intent and state directory |
| Fleet start (optional) | launchd label and program of the vendor API job, label prefix of the per-guest runtime jobs; left out, the all-stopped guard applies |
| Runtime start (optional, inside fleet start) | Application root and install root for which the supervisor may run the vendor's own start command, optional bound of that call; left out, nothing here starts the vendor runtime |

No receiver IP is enrolled. Media receivers come from genuine current LAN
DNS-SD records; DHCP changes and additional eligible devices need no code edit.
Every setting belongs to its private installation; examples are documentation
data, not discoverable host defaults.

Enrollment fingerprints the **complete native container configuration** rather
than replacing it with a minimal resource definition. Images, entrypoints,
environment, mounts, socket publications, CPUs, memory, labels, sysctls and
runtime options therefore cannot silently drift past the reader. The fingerprint
is useful evidence without exporting application secrets. Kernel files and other
inputs absent from native inspect output require explicit hashed file receipts.
Receipt checks do not pretend a native API exposes a property it does not expose.

Hashed startup receipts support files up to 512 MiB, including custom kernels.
Verification reads at most 1 MiB per chunk and checks a five-second local budget,
the shorter shared reader deadline and descriptor/path metadata before accepting
the hash. Oversized, changed or timed-out files become unknown; file data is never
printed in observations.

Both the opened descriptor and the final pathname must retain device, inode,
owner/group, mode, link count, ctime, mtime and size throughout hashing. A final
ACL check remains within the same deadline. Every reader maintains its own ACL
cache keyed by fresh pathname/inode/ctime/owner/mode metadata, so a changed ACL
cannot reuse an earlier proof; cached proofs never bypass an expired deadline.

The runtime reader accepts complete native macOS ACL output only when every
entry is a strictly parsed denial. This permits macOS's usual `everyone deny
delete` on a user's home directory while refusing grants, mixed lists, missing
indexes, unknown rights/flags and ambiguous principals. Optional native inherited
markers and the closed native inheritance flags are recognized; they grant no
authority. Native output is ASCII-only, bounded to 64 KiB and read with a fixed
`/bin/ls -lde` command in the bounded subprocess runner's C locale. The grammar
follows [Apple's maintained `ls` source](https://github.com/apple-oss-distributions/file_cmds/blob/main/ls/print.c).
Unsupported names/output become unknown. Privileged PF code, settings and
mutation boundaries retain their separate stricter no-ACL rule.

Persistent paths bind kind, owner and inode, and one of two things that say
which file system the inode belongs to. The default is the device number. A
device number is assigned when a volume is mounted and can be another number
after a restart, while the volume and its inodes are the same; every pass after
such a restart reads `identity-mismatch` until the host is enrolled again. The
other binding is the volume's own identifier (`volume_uuid`, a lower-case UUID).
For it the reader opens the directory or file without following a link, requires
the descriptor to be the object it has just examined, and reads the identifier
of the volume that holds it with one `fgetattrlist` call in its own process. A
path that cannot be opened, a failed call, a volume without an identifier and
any other reply are `identity-mismatch`; nothing falls back to the device
number. A directory or file names exactly one of the two; a socket is bound by
neither. Hashed receipts also bind
contents. Socket leaves can change inode when their existing owner restarts;
their protected path, parent, owner and type still have to agree. Symlink and
shared-writer ambiguity produces unknown. Writable nested/aliased mounts belonging
to another inventoried container are rejected; read-only sharing is allowed.

A site that keeps a second definition over the same writable path without ever
running it, for example a retained test definition, can enroll that definition's
name in the contract's `tolerated_stopped_peers`. The peer is then accepted only
while the inventory reports it exactly `stopped`; running, stopping or unknown it
is rejected as before, and so is every name that is not listed. The list is
closed: at most 16 distinct vendor container names in sorted order, none of them
an enrolled workload. It is part of the contract and settings digests only when
it is not empty, so an enrollment without it keeps its digests and admissions.

## Capture once, derive identity fields

These are explicit read-only native diagnostics followed by private file creation:

```sh
python -m netorch.apple_runtime --settings /operator/site/runtime-input.json \
  enroll --output /operator/site/enrollment.next.json
python -m netorch.apple_runtime --settings /operator/site/enrollment.next.json \
  derive-policy --source /operator/site/network-input.json \
  --output /operator/site/network.next.json
```

Outputs are exclusive-created mode 0600 files. Existing files are not overwritten.
`enroll` preserves the actual definition and captures metadata; `derive-policy`
statically fills generated service-contract hashes. Port/scope policy remains
authored once in the input table. Neither command creates an admission, changes
application configuration, resumes intent or invokes PF. Review the generated
files and promote them through the separately guarded deployment procedure.

`enroll` stores device numbers unless it is given `--identity volume-uuid`. With
that option every mounted directory and file is stored with its volume
identifier and without a device number, and so is every receipt that names a
device number, after it has been verified as written. A receipt that already
names a volume is verified and kept. The binding is chosen at each enrollment:
one repeated without the option stores device numbers again. A contract with at
least one volume-bound identity is hashed as `apple-runtime-enrollment-v2`,
every other contract as `apple-runtime-enrollment-v1`, so an existing enrollment
keeps its stored bytes and its service contract hashes. Moving to the volume
binding is an enrollment like any other: derive the policy and admit again on
both sides. The reader, and the root owner in its own process, must be able to
open each volume-bound directory or file for reading; under the device binding
only a hashed receipt is opened. Whether macOS privacy protection lets a
background job do that for a given location, for example a removable volume or
a protected folder of the account, is a native acceptance item; a refused open
reads `identity-mismatch`. The call is covered by fake providers and by hosted
macOS userspace checks; a restart that changes a device number has not been run
under this binding.

## A complete live observation

Each pass has an eight-second aggregate deadline, with smaller process limits:

1. Verify the exact CLI version against its reader contract.
2. Read the kernel's boot session identifier and the actual helper PID, start
   time, program, UID and running launchd state. Cached installer receipts do
   not prove a live helper.
3. Inspect native NAT network mode/plugin/subnet/gateway and confirm the selected
   interface actually owns the policy's host IPv4 address.
4. Read complete inventory and independently inspect each named container.
   Conflicting list/inspect/configuration/identity evidence is unknown.
5. Check full configuration fingerprint, mount/receipt identities and peer
   writers. For services with a bounded automatic-port range, read the actual
   guest procfs range and require exact equality with policy.
6. Derive guest generations from configuration, current start time, current
   network generation and current address. Derive native publication only from
   that same service's exact host address/protocol/range/target declaration.
   Report the attachment's hardware address as `mac` when the runtime states
   one in the form its encoder writes (six two-digit lower-case hexadecimal
   groups joined by colons). A missing value, or one in any other form, is left
   out: the address is then unknown, and the independent root owner accepts no
   direct guest target without it.
7. Reread helper and native network evidence to detect a changed generation.

The boot is named by `sysctl -n kern.bootsessionuuid`, which must print exactly
one upper-case UUID on one line; anything else, the nil UUID included, is an
unknown read. The kernel makes that identifier once, when its power-management
root domain starts
([`initializeBootSessionUUID`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOPMrootDomain.cpp#L4297-L4308),
[`kern.bootsessionuuid`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_sysctl.c#L3015-L3017)).
The boot time is not used. The kernel shifts its stored boot time whenever the
calendar clock is set
([`clock_set_calendar_microtime`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/kern/clock.c#L729-L800)),
and the printed value also carries a date in the local time zone
([`S_timeval`](https://github.com/apple-oss-distributions/system_cmds/blob/system_cmds-1012/sysctl/sysctl.c#L748-L773)),
so a clock step or a time-zone change would read as another generation and make
the forwarding owner retire and re-activate every profile. Generation strings
therefore differ from those of releases that hashed the boot time. Owners on
either side of that change agree on no generation and plan nothing, so the user
scope and the root scope run the same release.

Running state from the admitted version's native API plus the exact source
configuration establishes vendor publication provenance. An unrelated listener
with the same numeric port never supplies that provenance. This is not proof of
application health: a runtime forwarder can be alive while its application is
unhealthy. Native packet and application acceptance remain separate gates.

Malformed, oversized, duplicate, unavailable, timed-out, stale or disagreeing
evidence becomes unknown. Missing named configurations are not proven stopped
containers. An API inventory reporting all guests stopped is unknown, since an
API service restart can produce that apparent state. The decoder accepts the one
envelope the accepted versions print: `id`, `configuration` and a nested
`status`. A flat row, a publication row with another shape or a repeated one,
and an attachment row that is not an object are unknown; unfamiliar output
never falls back to a permissive interpretation.

The all-stopped rule is the default. Settings that declare `fleet_start` replace
it with evidence for each stopped guest; see
[Starting a fully stopped fleet](#starting-a-fully-stopped-fleet).

## User endpoint and Monit

```sh
python -m netorch.apple_runtime --settings /operator/site/runtime-settings.json request
python -m netorch.apple_runtime --settings /operator/site/runtime-settings.json observe
python -m netorch.apple_runtime --settings /operator/site/runtime-settings.json \
  probe --service media-controller
python -m netorch.apple_runtime --settings /operator/site/runtime-settings.json \
  start --service media-controller
python -m netorch.apple_runtime --settings /operator/site/runtime-settings.json runtime-probe
python -m netorch.apple_runtime --settings /operator/site/runtime-settings.json runtime-start
```

The endpoint accepts only the fixed owner protocol. A caller's policy must match
the installed private policy. It cannot submit arbitrary native commands.
Publication reconciliation is an idempotent verification of already-configured,
independently admitted native publication. It cannot stop/recreate an application
to remove a socket or add a missing publication. Such changes belong to an
explicit application maintenance operation.

`probe` returns 0 for verified running, **42 only for a complete proven stopped
read**, and 69 for unknown or inhibited recovery. Only 42 triggers Monit's start
rule. Recovery takes the shared user operation lock, rereads durable intent,
performs two complete stopped observations in the same network generation,
starts the existing enrolled name, then requires running readback. The
coordinator holds that lock for each of its passes, so `start` waits for it: at
most 5 seconds, trying every 0.25 seconds. If the lock is still held it exits
75 with `{"error":"busy"}` on standard error and has observed and started
nothing. Running but
unhealthy guests, unknown observations and all-stopped inventories never cause
automatic restart. Initial all-stopped provisioning is a distinct explicitly
approved operator operation in [workloads.md](workloads.md). Where `fleet_start`
is declared, an all-stopped inventory is no longer excluded as such: each
stopped guest is judged on the evidence described below.

The vendor `start` call of that sequence is cut off after four seconds, like
every other vendor call, unless the runtime settings carry
`start_timeout_seconds`: a whole number from 1 to 120, left out by default and
never written as `null`. The setting bounds that one call. The observations
before and after it keep the eight-second pass and its smaller limits, and the
running readback stays the only statement that the workload started. A call
that is cut off ends recovery as unknown; the vendor service may still complete
the start, which a later probe then reports. Recovery holds the user operation
lock for the whole sequence, three passes and the start call: about 28 seconds
at most without the setting and about 144 with its largest value. Until it ends, the
coordinator's pass, `pause` and every other command that takes that lock report
busy and have to be repeated. The probe takes no lock, and the supervisor's
check timeout (`monitors[].timeout_seconds`) is written on the probe's check,
not on the recovery command. Initial provisioning does not read the setting.

Networking jobs and Monit do not replace the site's initial application startup
chain after login. Preserve that existing maintained owner during migration;
without `fleet_start` the routine all-stopped guard deliberately cannot
bootstrap the fleet, and with it Monit starts workloads only. It starts the
vendor runtime only where the settings also declare `runtime_start`, under the
three conditions of [Starting the vendor runtime](#starting-the-vendor-runtime).
See the [site migration responsibility map](site-migration.md) before
claiming unattended reboot availability.

Operator pause inhibits custom networking and recovery. A hold on one service
([state contract](state-machine.md)) does the same for that workload alone: its
probe returns 69 whether it runs or not, its start refuses and its publication
is not verified for networking, while a different stopped workload still
returns 42 and is started. A hold on a service that is not enrolled here
inhibits every workload. Vendor publications are part of existing application
definitions; an operator pause or a hold is not permission to stop those
applications. Missing native publication or a changed definition
therefore reports a maintenance requirement rather than hidden recreation.

## Starting a fully stopped fleet

After a boot every guest is stopped, but the API alone cannot prove it: whenever
its service starts, it lists every stored definition as stopped, whether or not
a guest outlived the restart. The settings may therefore name where independent
evidence is found:

```json
"fleet_start": {
  "api_label": "example.vendor.api",
  "api_executable": "/Library/ExampleVendor/libexec/api-server",
  "runtime_label_prefix": "example.vendor."
}
```

| Member | Value |
|---|---|
| `api_label` | launchd label of the vendor API job: a letter or digit, then up to 127 letters, digits, dots, underscores or hyphens |
| `api_executable` | that job's program, an absolute canonical path |
| `runtime_label_prefix` | prefix of the per-guest runtime jobs: a letter or digit, then letters, digits, dots or hyphens, ending in a dot, at most 97 characters; one guest's job is `<prefix><runtimeHandler>.<name>` |

The object is closed and these three members are required; the one optional
member is `runtime_start`, described in
[Starting the vendor runtime](#starting-the-vendor-runtime). Leave the key out to
keep the all-stopped guard: an explicit `null` is refused, and settings without
the key keep their bytes and digests. With it, every network must state the same
`helper_domain`; the jobs are looked up there.

With the declaration a pass reads the following in addition, and anything
missing or unfamiliar is unknown:

1. Before the inventory and once more at the very end of the pass,
   `launchctl print <helper_domain>/<api_label>` must show a running job with a
   process ID whose program is `api_executable`, and `ps` must show that
   process running that program as the enrolled account. Both reads must agree.
   The process ID and start time join the network generation, so the two
   observations of a recovery cannot lie on either side of an API restart.
2. For each guest that the inventory lists as stopped, the job
   `<runtime_label_prefix><runtimeHandler>.<name>` is printed in `gui/<uid>` and
   in `user/<uid>` of the enrolled account, or in `system` alone when that is the
   helper domain. The handler comes from the enrolled configuration, which must
   also carry the guest's own name as its `id`. The guest is absent only when
   every print ends with exit status 113 and no standard output, the service
   manager's answer for a label it has no job for. A job that is printed makes
   that guest unknown (`generation-mismatch`); any other outcome makes it
   unknown (`unavailable`). Other guests are not affected.

A guest listed as running is read as before. Recovery itself is unchanged: the
lock, the durable intent read twice, two stopped observations in one network
generation, one `start`, running readback. An operator pause therefore keeps a
fully stopped fleet stopped, and a stop of everything without a pause is undone
like the stop of one workload. Workloads start one after another, in whatever
order the supervisor fires its rules.

This evidence starts no vendor runtime. A site that wants unattended recovery
after a boot either names another tool that starts the runtime after login or
adds `runtime_start` to the declaration, as the next section describes. Without
either the API job is never the declared running job, every workload stays
unknown and nothing is started. A runtime job that stays loaded without a
process, for example after the API service was away while its guest ended, also
keeps that guest unknown until an operator removes the job or starts the guest.

The declaration belongs in every settings object from which a network generation
is computed: the user's runtime settings and the `observer` of the root
forwarding owner. The API job's identity is part of that generation, so owners
that do not carry the same declaration compute different generations and the
coordinator plans nothing (`network-unknown`). Adding it to the root
installation changes every root admission digest; each profile is admitted
again, as after any change of the trusted observer. A wrong label or program
makes every workload unknown, running ones included, so read the result of
`observe` before the settings reach the root owner.

The rule follows from the vendor's source, which agrees at tags 1.2.0, 1.4.1 and
1.5.0. The API service is the job `com.apple.container.apiserver`
([`SystemStart`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerCommands/System/SystemStart.swift#L115-L122)).
It lists every stored definition as stopped when it starts
([`loadAtBoot`](https://github.com/apple/container/blob/1.5.0/Sources/Services/ContainerAPIService/Server/Containers/ContainersService.swift#L92-L161)),
labels a guest's runtime job `com.apple.container.<runtimeHandler>.<id>` from
that guest's configuration
([`fullLaunchdServiceLabel`](https://github.com/apple/container/blob/1.5.0/Sources/Services/ContainerAPIService/Server/Containers/ContainersService.swift#L1016-L1018)),
and registers it in `system`, `user/<uid>` or `gui/<uid>` according to the
session the API service itself was started from
([`getDomainString`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerPlugin/ServiceManager.swift#L124-L136)).
Source reading is not a capture. The exit status and the output of a missing
job, and the lines of a loaded one, are checked against the real service manager
on the hosted CI runner only, which is evidence for that runner image. The
launchd behaviour of a production build, a runtime job that survives an API
restart and the time a start takes remain native acceptance items.

## Starting the vendor runtime

The vendor's API service runs only after its own start command has run: that
command writes a launch file below the application root and loads it, and the
file is in no directory the service manager searches by itself. After a boot
the service is therefore not loaded until somebody runs the command again. A
site whose supervisor is its only starter can let the supervisor do that, with
one more member inside `fleet_start`:

```json
"fleet_start": {
  "api_label": "com.apple.container.apiserver",
  "api_executable": "/opt/vendor/bin/container-apiserver",
  "runtime_label_prefix": "com.apple.container.",
  "runtime_start": {
    "app_root": "/operator/Library/Application Support/com.apple.container",
    "install_root": "/opt/vendor"
  }
}
```

| Member | Value |
|---|---|
| `app_root` | the vendor's application data root, an absolute canonical path |
| `install_root` | the vendor's install root, an absolute canonical path |
| `timeout_seconds` | optional bound of the one vendor call, a whole number from 5 to 120; left out it is 20 |

The object is closed, both roots are required, and an explicit `null` is
refused for the object and for the bound. Left out, nothing changes: the key is
not part of the canonical form, so settings without it keep their bytes and
digests, with or without `fleet_start`. Each path, and `api_executable` with it,
has exactly one spelling: no empty component, no final slash, no control
character, no other character at which a line ends (next line U+0085, line
separator U+2028, paragraph separator U+2029) and no surrounding space, so
that the vendor's own normalisation leaves it as it is and one printed line
carries it whole. With the member,
`api_label` must be the vendor's `com.apple.container.apiserver`, the only job
its start command loads, and the helper domain must be `gui/<uid>` of the
enrolled account, the domain into which a supervisor in that account's login
session loads.

Two commands exist with the declaration, and both refuse without it:

- `runtime-probe` returns 0 while the API job is the declared one and has its
  process, **42 only where a start is permitted** by everything below, and 69
  otherwise and whenever the durable intent blocks. It takes no lock and starts
  nothing.
- `runtime-start` runs as the enrolled account only. It takes the user operation
  lock like `start`, reads the state twice with the intent read after each,
  makes one vendor call and reads the result back. It starts no workload, never
  repeats the call, and never unloads, stops or repairs anything. In this
  release it is refused with status 78 like every other mutation.

Three conditions hold before the call, and each is read on both passes:

1. **The reviewed launch file is already the expected one.**
   `<app_root>/apiserver/apiserver.plist` exists as a regular file of the
   enrolled account with one link, mode 0600 or 0644, no ACL grant and no
   final symbolic link, and every directory above it is closed to group and
   other writers. It is decoded in the reader's own process, in its XML or
   binary form and at most 64 KiB long, and must equal member for member and
   type for type what the vendor's command writes for the declaration: the
   label, the two program arguments
   (`api_executable`, `start`), exactly the two root variables, the three
   session types in the vendor's order, the one Mach service and run-at-load.
   The command also takes the program from its own directory, so
   `container-apiserver` beside the enrolled `executable` must resolve to
   `api_executable`. A missing or different file refuses: the runtime was
   never started by an operator with these roots, and that first start is not
   the supervisor's to make. The supervisor only repeats a start whose launch
   file it would write again unchanged.

   The same judgement covers the vendor's configuration, which the start must
   not change. Before anything else the vendor's command copies the account's
   own file `<home>/.config/container/config.toml` over the copy
   `<app_root>/config/config.toml`; where the account has no such file it
   leaves the copy alone. That file is therefore either absent or a regular
   file whose bytes equal the copy. A file that differs, a copy that is
   missing (the command would create it), a symbolic link at either final
   name, a directory or another kind of object, and a file larger than 1 MiB
   refuse like a launch file that differs, and nothing of either file is
   printed or recorded. An edit of the configuration takes effect at an
   operator's own start, never at the supervisor's. `<home>` is the home the
   vendor's command finds: the account's entry in the user database, and the
   `HOME` variable only where there is none. The runner passes the enrolled
   `home` as `HOME`, so both places are read where they differ, and a file in
   either must equal the copy. The closed environment carries no
   `XDG_CONFIG_HOME`: an operator who keeps the configuration elsewhere
   through that variable of their own shell is not followed. The supervisor's
   command looks below the home only, and the copy such an operator's start
   made stays as it is while no file is there.
2. **Both roots are pinned for the call.** The call is
   `system start --app-root <app_root> --install-root <install_root>
   --disable-kernel-install`, and both roots are also given as
   `CONTAINER_APP_ROOT` and `CONTAINER_INSTALL_ROOT`, the only additions to the
   runner's closed environment. The options are what pins them: the vendor's
   command takes its roots from the options, whose defaults do not read those
   variables, and writes the option values into the launch file. The API
   service takes its roots from the environment that file gives it, and at
   start it deletes every stored definition it cannot load, for example because
   the runtime plugin is not below its install root.
3. **Only a proven absence starts anything.** The service manager itself must
   say that the job is not loaded: `launchctl print gui/<uid>/<api_label>` ends
   with status 113 and no standard output, while `launchctl print gui/<uid>`
   answers and the same label is not loaded in `user/<uid>` either. The
   session of the caller must be the one whose domain is declared
   (`launchctl managername` answers `Aqua`), because the vendor's command loads
   into the domain of the session that runs it. The label must not be disabled
   (`launchctl print-disabled gui/<uid>`): a label that list does not hold is
   not disabled, a list in another form is unknown. The enrolled CLI must be
   the accepted version.

A job that is loaded with exactly the declared launch file, program, arguments
and roots but has no process (`state = not running`, no process ID) is not
absent. It gets only the vendor's `system status`, whose first request makes the
service manager run the loaded job and which writes nothing; the same
conditions apply except the listing of the domain. Any other state, including a
job loaded with another program, another root or from another file, is unknown
and gets no call. The print is compared exactly. Only the printer's indentation
is removed: there is one `path =` line and one `program =` line, each argument
and each root is the whole rest of its line, and a value that differs by white
space at its end is another value.

After the call the launch file must still be the expected one, the loaded job
must print the declared launch file, program, arguments and both roots and have
a process of the enrolled account running that program, and one inventory read
must succeed. Otherwise the result is unknown; the vendor service may still
come up, which a later probe then reports. The exit status of the call must be
0; its output is not read, because the vendor's command logs to standard error
when it succeeds.

An operator pause, a suspension and a damaged intent keep a stopped runtime
stopped: the probe returns 69 and the start refuses at both reads. A hold on
one enrolled service does not, since the runtime serves every workload. A
runtime that is stopped without a pause, for example with the vendor's own stop
command, is started again like a stopped workload. Pause before any maintenance
of the vendor runtime, an upgrade included: the launch file does not say which
version wrote it, so after an upgrade in place the first start should be the
operator's.

Three things follow from running the vendor's own command and not loading the
file directly. It copies the account's configuration file, if there is one,
into the application root on every start; condition 1 permits the start only
where that copy changes nothing, so a configuration edited since the last
start waits for an operator's own start. On a host without
the vendor's base file-system image it tries to download that image, whatever
the options, inside the same bound. And it waits up to 60 seconds of its own
for the service to answer, so a bound below that can end the call while the
service is still starting; the result is then unknown. `runtime-start` holds
the user operation lock for two reads, the call and the readback: about 44
seconds at most with the default bound and about 144 with the largest.

Two properties of the application root make the supervisor refuse for good,
because the identity check of the launch file can never pass. A symbolic link
anywhere in the path of `app_root`, or at the launch file itself, is not
followed: an operator cures it by starting the runtime once with the resolved
path as `--app-root` and declaring that path. On macOS a character outside
ASCII anywhere in that path is refused by the reader of access-control lists;
no declaration cures that, and such a site keeps its own starter of the
runtime or moves the application root.

A deployment gives its supervisor at most one monitor with the role `runtime`,
which may carry a recovery command like a workload monitor; see
[deployment](deployment.md). The declaration is read by the user's reader only.
It does not enter the network generation, so the `observer` of the root
forwarding owner need not carry it, and observation passes are unchanged by it.

All of this follows from the vendor's source, read at tags 1.2.0, 1.4.1 and
1.5.0, where the start command, the launch-file encoder and the configuration
loader are the same files byte for byte. The command takes its roots from options
([`SystemStart`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerCommands/System/SystemStart.swift#L35-L45))
whose defaults are not the environment's
([`ApplicationRoot`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerPlugin/ApplicationRoot.swift#L24-L44),
[`InstallRoot`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerPlugin/InstallRoot.swift#L26-L45)),
copies the configuration
([`copyConfigurationToReadOnly`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerPersistence/ConfigurationLoader.swift#L192-L224),
from the place
[`PathUtils`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerPersistence/PathUtils.swift#L29-L36)
names), resolves the program beside itself, keeps the
`CONTAINER_` and proxy variables of its environment
([`filterEnvironment`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerPlugin/PluginLoader.swift#L311-L318)),
sets both roots from the options, writes the six members and loads the file
([`run`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerCommands/System/SystemStart.swift#L75-L164),
[`LaunchPlist`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerPlugin/LaunchPlist.swift#L47-L64))
into the domain of its session
([`register`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerPlugin/ServiceManager.swift#L37-L40),
[`getDomainString`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerPlugin/ServiceManager.swift#L101-L136)).
The API service reads its roots from its environment
([`APIServer.Start`](https://github.com/apple/container/blob/1.5.0/Sources/APIServer/APIServer%2BStart.swift#L45-L49))
and removes what it cannot load
([`loadAtBoot`](https://github.com/apple/container/blob/1.5.0/Sources/Services/ContainerAPIService/Server/Containers/ContainersService.swift#L140-L158)).
The status command asks the service manager and then the service, and writes
nothing
([`SystemStatus`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerCommands/System/SystemStatus.swift#L44-L66)).
Which home the vendor's command finds is the answer of the system's own
library and not in the vendor's source; the last CoreFoundation that Apple
published asks the user database before `HOME`
([`CFPlatform.c`](https://github.com/apple-oss-distributions/CF/blob/CF-1153.18/CFPlatform.c#L213-L227)),
and both places are read for that reason.
Source reading is not a capture. The forms of `launchctl print-disabled`, of
`launchctl managername`, of the `path`, `arguments` and `environment` parts of a
job print and of a loaded job without a process are assumed; a text in another
form is unknown, and five `darwin` contract tests show the real forms on the
hosted CI runner only. That a job loaded from the supervisor's own session
runs, the time the call takes and the absence of a download on a given host
remain native acceptance items.

## Runtime and login gates

The reviewed vendor target is Apple Container 1.5.0 with its compatible
Socktainer release. Select and verify the exact installed pair separately;
support for an older reader shape does not establish that release's security or
Socktainer compatibility. Runtime upgrade, archive/image provenance, restore
rehearsal and login security policy remain explicit separate decisions. No
framework command upgrades them or chooses automatic login. A resolver behind
a user-session runtime remains unavailable before that session starts.

Version decoders and mocked contracts are implemented; this release has not
completed a vendor-runtime upgrade or native installation acceptance campaign.
See the [test tiers](testing.md). Upstream command provenance:
[Apple Container 1.5.0 reference](https://github.com/apple/container/blob/1.5.0/docs/command-reference.md).

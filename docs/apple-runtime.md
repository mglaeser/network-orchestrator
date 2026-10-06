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
| Runtime | Absolute CLI path, exact accepted version, legacy-risk acknowledgement |
| Networks | Scope, native network name/gateway, launchd helper domain/label, expected program and UID |
| Service contracts | Service/name/scope, full native configuration fingerprint, persistent mount identities, hashed file receipts |
| Paths | Private generated policy, user admissions, durable intent and state directory |
| Fleet start (optional) | launchd label and program of the vendor API job, label prefix of the per-guest runtime jobs; left out, the all-stopped guard applies |

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

Persistent paths bind kind, owner, device and inode. Hashed receipts also bind
contents. Socket leaves can change inode when their existing owner restarts;
their protected path, parent, owner and type still have to agree. Symlink and
shared-writer ambiguity produces unknown. Writable nested/aliased mounts belonging
to another inventoried container are rejected; read-only sharing is allowed.

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

## A complete live observation

Each pass has an eight-second aggregate deadline, with smaller process limits:

1. Verify the exact CLI version against its reader contract.
2. Read host boot identity and actual helper PID, start time, program, UID and
   running launchd state. Cached installer receipts do not prove a live helper.
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
7. Reread helper and native network evidence to detect a changed generation.

Running state from the admitted version's native API plus the exact source
configuration establishes vendor publication provenance. An unrelated listener
with the same numeric port never supplies that provenance. This is not proof of
application health: a runtime forwarder can be alive while its application is
unhealthy. Native packet and application acceptance remain separate gates.

Malformed, oversized, duplicate, unavailable, timed-out, stale or disagreeing
evidence becomes unknown. Missing named configurations are not proven stopped
containers. An API inventory reporting all guests stopped is unknown, since an
API service restart can produce that apparent state. The supported decoders
cover explicitly versioned nested CLI and resource-shaped envelopes; unfamiliar
output never falls back to a permissive interpretation.

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
starts the existing enrolled name, then requires running readback. Running but
unhealthy guests, unknown observations and all-stopped inventories never cause
automatic restart. Initial all-stopped provisioning is a distinct explicitly
approved operator operation in [workloads.md](workloads.md). Where `fleet_start`
is declared, an all-stopped inventory is no longer excluded as such: each
stopped guest is judged on the evidence described below.

Networking jobs and Monit do not replace the site's initial application startup
chain after login. Preserve that existing maintained owner during migration;
without `fleet_start` the routine all-stopped guard deliberately cannot
bootstrap the fleet, and with it Monit starts workloads only, never the vendor
runtime. See the [site migration responsibility map](site-migration.md) before
claiming unattended reboot availability.

Operator pause inhibits custom networking and recovery. Vendor publications are
part of existing application definitions; an operator pause is not permission
to stop those applications. Missing native publication or a changed definition
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

The object is closed and all three members are required. Leave the key out to
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

Nothing here starts the vendor runtime. A site that wants unattended recovery
after a boot names another tool that starts the runtime after login. Without
one the API job is never the declared running job, every workload stays unknown
and nothing is started. A runtime job that stays loaded without a process, for
example after the API service was away while its guest ended, also keeps that
guest unknown until an operator removes the job or starts the guest.

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

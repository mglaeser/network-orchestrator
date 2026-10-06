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
| Service contracts | Service/name/scope, full native configuration fingerprint, persistent mount identities, hashed file receipts, optional tolerated stopped peer names |
| Paths | Private generated policy, user admissions, durable intent and state directory |

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
   Report the attachment's hardware address as `mac` when the runtime states
   one in the form its encoder writes (six two-digit lower-case hexadecimal
   groups joined by colons). A missing value, or one in any other form, is left
   out: the address is then unknown, and the independent root owner accepts no
   direct guest target without it.
7. Reread helper and native network evidence to detect a changed generation.

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
approved operator operation in [workloads.md](workloads.md).

Networking jobs and Monit do not replace the site's initial application startup
chain after login. Preserve that existing maintained owner during migration;
the routine all-stopped guard deliberately cannot bootstrap the fleet. See the
[site migration responsibility map](site-migration.md) before claiming unattended
reboot availability.

Operator pause inhibits custom networking and recovery. Vendor publications are
part of existing application definitions; an operator pause is not permission
to stop those applications. Missing native publication or a changed definition
therefore reports a maintenance requirement rather than hidden recreation.

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

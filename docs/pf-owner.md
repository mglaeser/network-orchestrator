# Independent Darwin PF owner

> **0.3 stage boundary:** this guide describes retained owner mechanisms and mock
> contracts. Native authority expansion is unavailable while the accepted support
> matrix is empty. Existing installed owners stay in place; see
> [read-only workflow](getting-started.md) and [migration gates](site-migration.md).

The PF owner is a real executable service, not a plan adapter. It is deliberately
**not called by the unprivileged coordinator**. A local administrator installs a
protected desired snapshot; launchd independently runs a fixed pull pass:

```text
<root-owned-managed-python> -I -m netorch.pf_owner reconcile --root-dir <protected-directory>
```

The job has no socket, Mach service, privileged RPC, or sudoers grant. The normal
executor can read its published observations, but cannot send it an action,
address, port range, rules file, or admission. PF remains a site administration
facility; Apple does not provide it as a supported application networking API.
See [Apple TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api).

## Data and executable boundaries

The protected root directory is root-owned mode `0700`, under physical,
root-owned ancestors with no group/other write access or ACL grants. Its files
are single-link regular files mode `0600`:

| File | Purpose |
|---|---|
| `installation.json` | Closed installation identity, independently observed runtime settings, owner/anchor, published report path, interval and optional inhibition path |
| `policy.json` | Strictly parsed desired catalog, copied by the administrator installer |
| `admissions.json` | Root's independent resolved-content approvals; installation never broadens this set |
| `operator-intent.json` | Durable operator pause and operation-owned suspensions, outside installed releases |
| `backend.sh` | Administrator-owned bounded mutation script; SHA-256 must match the installation |
| `live.json` | Exact known rule/target evidence for withdrawal and state invalidation, never authority to activate |
| `journal.json` | Phase, actions and possible candidate state, sufficient to retire an interrupted known write |
| `owner.lock` | Persistent non-stealable `flock` inode; no PID/age lock stealing |
| `reference.json` | Only this owner's PF enable token |

Transient parser/rule files are confined to that protected directory. The
published snapshot lives under a separately protected root-owned directory and
is readable at mode `0644`. It contains only this owner's profile observations,
not raw inspection output, account credentials, or user environment variables.
A profile's `states` entry says only whether states for its target remain; the
kernel's state rows, which name peers and LAN clients, are not copied into it.
`admitted` records exact protected approval. The separate `root_ready` flag
requires that approval, unblocked final root intent and an exact verified final
plan/readback. Downstream planning requires both flags; a truthful observation
of rules awaiting withdrawal cannot grant discovery readiness during a pause.

The scheduled Python interpreter, package and its dependency environment must
be administrator-owned under protected ancestors. A root job must not import
from a user-writable checkout, user Homebrew directory, or user-owned virtual
environment. Python isolated mode is mandatory. A separately reviewed
administrator bootstrap installs the protected interpreter and package
environment. The provisioner installs captured networking policy, the backend
and schedules; the PF module checks the executable and package boundary
before any live operation, plus the actual prefix/base prefix, absolute Python
search paths, imported stdlib/dependency/extension files and JSON schemas. A
venv symlink does not make a user-owned Homebrew interpreter safe. Provisioning
must protect the entire environment before starting the privileged interpreter;
the live check adds readback rather than permitting an initially untrusted import.
Each pass captures fresh metadata and deduplicates at most 4,096 code/ancestor
paths. Darwin ACL inspection uses bounded batches of at most 256 paths, a 64 KiB
argument budget, 512 KiB output limit and one shared eight-second deadline;
metadata is reread afterward. No cross-pass trust cache hides ownership changes.

The native Container CLI and each observed network-helper executable must also
be administrator-owned regular single-link files, under protected physical
ancestors, with no group/other write permission or ACL grants. Both visible
symlink paths and resolved targets are checked in a separate bounded batch
before root accepts runtime observations. Dropping native probes to the runtime
user does not make a user-replaceable observer trustworthy. The framework does
not install these vendor binaries; their trusted installation is a prerequisite.

## User Mach bootstrap and dropped credentials

The root LaunchDaemon and the runtime user's process have different execution
contexts. Apple Container 1.5.0's
[XPC client](https://github.com/apple/container/blob/1.5.0/Sources/ContainerXPC/XPCClient.swift)
creates Mach-service connections with flags zero. Its
[service manager](https://github.com/apple/container/blob/1.5.0/Sources/ContainerPlugin/ServiceManager.swift)
selects `gui/<uid>` for Aqua sessions and `user/<uid>` for Background sessions.
Apple's [XPC contract](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
requires the remote name to exist in an accessible Mach bootstrap namespace.
Dropping POSIX UID/GID alone does not establish access from a System bootstrap
to that user's registered names; this is an architecture inference from those
contracts, not a completed hardware claim.

The installed Apple `launchctl(1)` manual documents `asuser` as adopting the
user's Mach bootstrap/audit context **without** changing UID/GID or environment;
user and GUI domains share Mach-name lookups. The root observer therefore uses
fixed `/bin/launchctl asuser <enrolled-uid> <protected-python> -I -S` and the
protected `observer_child.py` file. That stdlib-only child clears supplementary
groups, sets GID and UID, verifies the credentials, changes to `/`, scrubs the
environment and directly executes the protected native CLI. It permits only
version, inventory, container/network inspection and one literal read of the
guest's `/proc/sys/net/ipv4/ip_local_port_range`. The parent keeps its original
bounded process-group timeout/output limit. Native host metadata tools remain
in the root context. The ordinary user runtime path is unchanged.

There is no shell, vendor daemon bootstrap, privileged socket/RPC, sudoers grant,
workload start, arbitrary guest exec or application modification in this path.
A missing user bootstrap or failed credential transition returns unknown,
causing normal independent withdrawal instead of treating the fleet as stopped.
Public CI verifies fixed invocation, credential ordering, scrubbing, operation
grammar and failure behavior through mocks. A separately authorized physical
acceptance must still demonstrate a root LaunchDaemon querying the actual user
API/network helper, including login/logout/reboot behavior; mocks cannot prove
Mach lookup availability on a particular macOS/runtime installation.

## Exact admission

An approval binds all resolved parameters included by `profile_digest`, plus:

- Strategy version `darwin-pf-v1`.
- Installed Bash backend SHA-256 and an automatic fingerprint of the immutable
  installed Python implementation, bundled schemas, full Python version and
  validator dependency versions. Planner/observer/parser/interpreter changes
  therefore invalidate old root authority even if a strategy-version bump is
  accidentally omitted.
- Root-owned runtime-observation configuration (including accepted target
  contracts and runtime identity).
- Owned anchor and the explicit Apple DNS coexistence exception.

The administrator first runs `review-admission`. It returns the resolved
profile, scope, service, prior approval and proposed digest. The subsequent
`admit` requires that exact digest and, for a shared guest address, explicit
`--acknowledge-bounded-risk`. A file swap, wider range, changed interface,
changed observer contract, changed backend, or changed strategy does not inherit
approval merely because a profile ID is unchanged.

```text
python -I -m netorch.pf_owner review-admission --root-dir <root-dir> --profile <profile>
python -I -m netorch.pf_owner admit --root-dir <root-dir> --profile <profile> \
  --expected-digest <reviewed-digest> --acknowledge-bounded-risk
```

The installer accepts `--policy`, `--settings`, and `--backend` only as a local
administrator operation. Each input is read once through a descriptor, bounded,
and checked against its final pathname identity. It publishes validated copies
under the persistent lock. Existing admissions, intent and recovery journals
remain unchanged. New installations start paused and unadmitted. The installer
neither starts containers nor loads PF rules nor silently adopts an occupied
anchor.

## Reconciliation and failure semantics

1. Read protected policy/admission/intent under the persistent kernel lock.
2. Validate owned anchor shape and stock NAT/RDR wildcard hooks. Foreign filter
   rules, child anchors, tables or unexpected rule drift stop mutation. Never
   reload `/etc/pf.conf`, edit Apple anchors or flush global states.
3. Independently inspect the running runtime as the admitted ordinary runtime
   account. Validate exact container definition, network helper generation,
   current instance, address and MAC. Stored endpoint facts do not activate.
4. Read owned rules and the complete kernel state table. A malformed, truncated,
   inaccessible, stale or changed-schema read is unknown, never absent.
5. Apply pure planning to those fresh observations and the root's approvals.
   Immediately before each activation, reread durable gates, desired content,
   approvals and fresh runtime evidence. Verify current LAN interface/address,
   forwarding, route/ARP for direct guest targets and host socket coexistence.
6. Parse candidate rules first, reread the old anchor immediately before loading,
   load only the owned anchor, and compare exact normalized readback. NAT
   statements precede RDR statements. A healthy pass does not reload rules.
7. Withdraw stale/missing/changed guest targets, then invalidate states from and
   to the exact old guest address and read back absence. Activate a replacement
   only in a later pass with fresh identity evidence.
8. Publish a typed snapshot. Unknown never restarts a container or other service.

The independent endpoint check reads the selected address's actual contiguous
IPv4 netmask. The admitted LAN scope must be equal to or narrower than that
live prefix. A matching host address alone cannot authorize a wider source
network; missing, duplicate or malformed mask observations inhibit activation.

The state reader checks every numerical endpoint of a row, IPv4 `:port` and
IPv6 `[port]` suffixes, the direction of its arrows and a complete
protocol-specific status tail. A colon by itself is not evidence of IPv6. An
unrecognized row makes the whole inventory unknown. It never supplies an empty
owned-state result or permits a successful drain report.

macOS exports a state as `struct pfsync_state` with the hosts `lan`, `gwy`,
`ext_lan` and `ext_gwy`
([xnu `bsd/net/pfvar.h`, tag `xnu-12377.121.6`, lines 1119-1125](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pfvar.h#L1119-L1125)).
The printer of that lan/gwy/ext state model writes `gwy ARROW ext`, and
`lan ARROW gwy ARROW ext` when a translation changed the address or the port
([FreeBSD 8.4 `contrib/pf/pfctl/pf_print_state.c`, `print_state`, lines 215-228](https://github.com/freebsd/freebsd-src/blob/release/8.4.0/contrib/pf/pfctl/pf_print_state.c#L215-L228);
`print_host` is lines 157-184 and the status tail lines 230-271). It does not
put a translated endpoint in parentheses. The reader accepts these forms:

- an interface label, which is `all`, `ALL` or an interface name, followed by
  a protocol: a name of the protocol database (lower-case letters, digits and
  `+`, `-`, `.`, `/`, as in
  [`private/etc/protocols`, tag `files-968`](https://github.com/apple-oss-distributions/files/blob/files-968/private/etc/protocols))
  or a number;
- two endpoints joined by one arrow, or three endpoints joined by two arrows
  of the same direction;
- an endpoint written `a.b.c.d:port` or `address[port]`. A port of zero is
  read only as `[0]`, and only a protocol other than tcp and udp may leave the
  port out;
- a leading `~` on at most one endpoint. The reader gives this marker no
  meaning and drops it before it reads the address;
- a status tail of two TCP state names or `PROXY:SRC`/`PROXY:DST` for tcp, two
  of `NO_TRAFFIC`, `SINGLE` and `MULTIPLE` for udp, and two numbers for
  `icmp`. Any other protocol has two of those three names, or two numbers
  when a level has no name; `gre` and `esp` may also carry the levels the
  kernel header names for them, `INITIATING` and `ESTABLISHED`
  ([`pfvar.h` lines 1612-1632](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pfvar.h#L1612-L1632)),
  and `icmp6`/`ipv6-icmp` are read with numbers as well;
- the display of the
  [OpenBSD printer](https://github.com/openbsd/src/blob/b1a43ff550949e2a4899e600bb41c53aef12ecfd/sbin/pfctl/pf_print_state.c#L151-L296)
  with one arrow and a translated endpoint in parentheses on either side, as
  before. It never combines with a second arrow or with the `~` marker.

Every IPv4 address that a row names counts when the states of a target are
looked for, whichever endpoint carries it. Arrows of mixed direction, a missing
endpoint, a third arrow, two endpoints without an arrow between them, a port
above 65535, a tcp or udp endpoint without a port and a control character
inside a row are refused. Only a line feed ends a row.

The forms without parentheses are macOS display forms as an existing site's
own state reader is tested with them: sanitized rows, not a raw capture that
was reviewed in this repository. The parser regressions keep those shapes;
every address and port in them is a documentation value. They are not hardware
acceptance. Any other native format must remain unknown until its complete
grammar is established by reviewed captured output; the native qualification
gate remains closed.

A runtime inspection exception is unknown and withdraws existing guest exposure.
A corrupt root admission record also inhibits activation and retires known
exposure. Partial writes journal the exact candidate before mutation; the next
pass accepts only the old or known candidate kernel view, withdraws it and drains
its states. An explicit administrator journal acknowledgement is required before
activation resumes. Unknown foreign drift is never overwritten as recovery.

Within one pass the owner applies every planned withdrawal before it invalidates
any state, as the administrator withdrawal does. A state readback that fails
then fails the pass with all planned rules already retired; it cannot leave the
rule of a later profile loaded. Drains and activations keep their planned order.

The owner holds only its own PF enable reference and keeps it while paused or
empty. It never globally disables PF or releases a token owned by another
service. A reference is operational runtime coexistence, not evidence of packet
reachability.

## Structural versus bounded profiles

Native host socket publication is performed by Apple Container as the ordinary
runtime account. PF **cannot claim publication ownership**. A structural
`host-redirect` first requires independently verified matching native publication
readback. Its target is the fixed host socket, not a recyclable guest address.
It never kills all states to the host address, because that would interrupt
unrelated services. Structural safety relies on the admitted native publication
contract; changes to that contract require review.

`guest-direct` and `udp-return` target current dynamic guest addresses. Their
reviewed bounded safety model explicitly accepts the observation race between
passes. An unreachable runtime does not prove a guest has stopped; it causes
withdrawal. This cannot provide an absolute no-misdelivery guarantee on a shared
address pool. That guarantee requires the separately reviewed architecture
choice of isolated single-member networks, not a different programming language.

For UDP return traffic, the owner's rule pair uses static source ports on
outbound NAT and omits the replacement target port on inbound RDR. The source
and destination scope is the admitted LAN subnet, rather than one receiver IP.
The range must exactly match the service's automatic socket range. Never widen
it to mask capacity problems. Multiple Apple media receivers therefore use the
same admitted service capability and fresh device discovery without receiver IP
allowlists.

Darwin `pf.conf(5)` translation grammar has **no filter-rule `label` option** for
NAT/RDR. Profile IDs are comments in rendered input and protected journal data,
not unsupported appended labels. Darwin's `pfctl(8)` documents address/network
state invalidation; this implementation does not invent OpenBSD state-ID or
label kill support.

## Explicit DNS availability fallback

A `guest-direct` profile may name `fallback_publication`, referencing an exact
same-service, same-scope, same-protocol native publication (for example host
1053 to guest 53). Its approval binds both resolved strategies and the complete
backing publication contract. Merely naming a port or another service cannot
provide a fallback. The field is optional; policies without it retain their
original v1 profile digest. Profiles using it use resolved digest version 2.

Only the independent PF owner's current kernel route/ARP checks select the
fallback. The runtime service must still be freshly verified, and the native
publication must independently be admitted and read back present. Unknown
runtime identity is insufficient for either strategy. If direct access becomes
unverifiable, root withdraws its guest rules and drains old guest states first;
only a later fresh pass exposes the fixed native host socket. It reports
`effective_strategy: degraded-fallback`, because client identity is no longer
preserved by that path. Returning to the direct path also retires the old
strategy before a later activation. No broad host-address state kill occurs.

## DNS coexistence

Host port conflicts are blocked from complete numeric Darwin socket inventory.
The optional root-admitted Apple DNS exception allows only port 53 wildcard
sockets owned by the verified Apple `mDNSResponder` process: Apple signature,
launchd program/account/PID and current process UID/parent/executable must agree.
An explicit LAN-address bind, another process with the same name, or an
unrecognized socket schema is not exempt. This exception does not assert that
port 53 is closed when the owner is paused.

## Deployment, rollback and acceptance

Provisioning renders the launchd job, installs the protected managed release,
stages desired inputs, and registers the independently scheduled daemon through
its administrator phase. User provisioning never invokes this privileged owner.
A changed code/backend contract installs pending until new admission; there is
no silent privilege expansion during upgrades.

For an upgrade or rollback, the installer holds its own durable suspension,
then invokes `withdraw --operation installation --holder <bundle-digest>` before
stopping the root job. This requires exact ownership of that existing suspension
and preserves the operator's pause value. The installer releases only its own
suspension after verified replacement startup. A plain administrator `withdraw`
sets operator pause and safely quiesces the owner before uninstallation.

Rollback is a protected prior **code and desired-policy** deployment. It does
not replay stored endpoint addresses or blindly restore kernel states. Pause,
withdraw known owned rules and guest states, select the prior reviewed release,
and obtain fresh observation/admission before resuming. Preserve the protected
journal until the interrupted operation has been inspected and acknowledged.
Stopping the scheduler without first withdrawing exposure is not a safe pause.

CI exercises real owner control flow with fake runtime/kernel tools in a temporary
root, including file swaps, changed admissions, stale generations, interrupted
writes, state draining, foreign drift, independent suspensions and denied target
validation. It never invokes native PF. Native acceptance remains necessary for
OS/version-specific hook order, first outgoing request and reply, boundary ports,
original client identity, cold boot, recreation, restore and multi-receiver
capacity. Mock success is not packet evidence.

A complete synthetic catalog with TCP/UDP native DNS fallback is provided in
[`examples/network-dns-fallback.json`](../examples/network-dns-fallback.json).
Use it as policy data together with matching private runtime definitions; it is
not a discovery cache or a runtime device-address allowlist. It uses only
documentation IP ranges. Match native publications in the actual admitted
container definition before installation; a synthetic configuration is never
proof that a real socket exists.

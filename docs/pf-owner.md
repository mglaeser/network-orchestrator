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
| `installation.json` | Closed installation identity, independently observed runtime settings, owner/anchor, published report path, interval, optional inhibition path (a user-side intent file that can only add inhibition), the optional decision to take a lost PF enable reference again, the optional [cold-start decision](#after-a-reboot), the optional [translation-order decision](#translation-order-for-the-udp-return-pair) and the optional [decision to keep host paths](#host-paths-while-runtime-evidence-is-unknown) |
| `policy.json` | Strictly parsed desired catalog, copied by the administrator installer |
| `admissions.json` | Root's independent resolved-content approvals; installation never broadens this set |
| `operator-intent.json` | Durable operator pause, operation-owned suspensions and holds on single services, outside installed releases |
| `backend.sh` | Administrator-owned bounded mutation script; SHA-256 must match the installation |
| `live.json` | Exact known rule/target evidence for withdrawal and state invalidation, never authority to activate |
| `journal.json` | Phase, actions and possible candidate state, sufficient to retire an interrupted known write; each record names the boot session it was written in when that could be read |
| `owner.lock` | Persistent non-stealable `flock` inode; no PID/age lock stealing |
| `reference.json` | Only this owner's PF enable token |

Transient parser/rule files are confined to that protected directory. The
published snapshot lives under a separately protected root-owned directory and
is readable at mode `0644`. It contains only this owner's profile observations,
not raw inspection output, account credentials, or user environment variables.
A profile's `states` entry says only whether a state of its own rules remains
(see "Retained states"); the kernel's state rows, which name peers and LAN
clients, are not copied into it. A profile that the pass deferred carries
`deferred` with the reason; no other profile has that entry.
A rule pair that the pass left loaded and
[withheld](#translation-order-for-the-udp-return-pair) carries `withheld` with
the reason in the same way, and is not `root_ready`. So does a
[host path that the pass kept](#host-paths-while-runtime-evidence-is-unknown)
without runtime evidence.
`admitted` records exact protected approval. The separate `root_ready` flag
requires that approval, unblocked final root intent, an exact verified final
plan/readback and, on the same pass, a readback of the owner's PF enable
reference. Downstream planning requires both flags; a truthful observation
of rules awaiting withdrawal cannot grant discovery readiness during a pause.
A hold on the profile's service blocks that profile in the same way. Two more
keys, `held` and `gate_revision`, are described under
[Holding one service](#holding-one-service).

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
- The decision to take a lost PF enable reference again, when the installation
  makes it. An installation without it has the digests it had before.
- The [cold-start decision](#after-a-reboot), when the installation makes one.
  An installation without it has the digests it had before.
- The [translation-order decision](#translation-order-for-the-udp-return-pair),
  when the installation makes it. An installation without it has the digests it
  had before.
- The [decision to keep host paths](#host-paths-while-runtime-evidence-is-unknown),
  when the installation makes it. An installation without it has the digests it
  had before.

The administrator first runs `review-admission`. It returns the resolved
profile, scope, service, prior approval, the installation's cold-start and
translation-order decisions and its decision to keep host paths where it made
them, and the proposed digest. The subsequent
`admit` requires that exact digest and, for a shared guest address, explicit
`--acknowledge-bounded-risk`. A profile declared with `source_scope: "any"`
requires `--acknowledge-any-source`; the bounded-risk flag does not satisfy it,
and `review-admission` prints `any_source_acknowledgement_required: true` for
such a profile only. A file swap, wider range, changed interface,
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

The owned anchor is one name directly below `com.apple/`. It is either the
product form `com.apple/netorch.<owner>`, which must name this installation's
own owner, or one pinned component that begins with a lower-case letter and
consists of `a-z`, `0-9`, `.` and `-`. In both forms the complete name, as it
is passed to `pfctl` with `com.apple/` in front, has at most 63 bytes: a
pinned component has at most 53 characters, and the product form exists for
an owner identifier of at most 45. An existing site can therefore keep the one
anchor its previous manager used, if that name fits, instead of having two
managers' rules loaded side by side during a move. The installation record
and the argument check of the backend script apply the same grammar to a
pinned name, but the script bounds only the component, at 63 characters, and
not the complete name. Of the product form the script checks less still: it
does not know the owner and cannot check whose product form it is given, and
it lets the product form of every identifier through, up to a component of 71
characters. No record names what only the script lets through. Nested anchors
are refused.

The bound of 63 bytes has two sources. The kernel does not create an anchor
component of 64 bytes or more
([xnu `pf_find_or_create_ruleset`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pf_ruleset.c#L353-L358)).
Apple does not publish its `pfctl`. The nearest published source of that tool
copies the whole `-a` argument, parent and slash included, into a buffer of 64
bytes and stops at 64 bytes or more, on a dry run as well
([FreeBSD 8.4 `contrib/pf/pfctl/pfctl.c`, `pfctl_rules`, lines 1401-1406](https://github.com/freebsd/freebsd-src/blob/release/8.4.0/contrib/pf/pfctl/pfctl.c#L1401-L1406);
lines 1446-1451 in release 9.3.0). Until a real `pfctl` has answered, the
record therefore holds the complete name to the bound of one component. A
hosted test records what the tool of one hosted macOS image answers for
arguments of 62, 63, 64 and 73 bytes, and asserts only that 63 are accepted.

The installation record refuses a longer name wherever the record is read: by
the installer, by every pass, by `withdraw`, `admit` and `review-admission`,
and where the retained provisioning reads the forwarding settings of a
bundle. A pass and a withdrawal read the record before they call the backend.
An owner whose identifier has 46 to 63 characters pins its anchor. The command
does not name the rule: like every refusal of the owner it prints
`{"error":"PFError","reason":"independent owner operation failed; inspect protected journal","schema_version":1}`
on standard error and exits 65, and this refusal writes nothing to the
journal, because the record is read before a pass begins. The cause is the
length itself: count the bytes of `anchor` in the settings given to the
installer, or in the installed record that `status` prints. A record whose
component has more than 63 bytes, the product form of an identifier of 56 or
more characters, can never have loaded a rule: the kernel does not create the
anchor. For a record whose component fits and whose complete name does not
(the product form of an identifier of 46 to 55 characters, which earlier
releases accepted), that is not established, because it depends on what the
real tool takes; such an installation is withdrawn with the release that
installed it, before the upgrade.

A pinned name never lets the owner take over rules it did not write. Every
pass stops with a drift error, before any write, while the anchor holds rules
that are not the owner's own records, and the backend refuses a replacement
when the loaded rules are not the ones it was told to expect. The hand-over
is: the previous manager empties the anchor, and the owner's next pass finds
it empty. A later installation cannot change an installed anchor, and root
admission binds the name, so an approval given under one anchor does not hold
under another. How the platform tools list a component with dots, and the
order of a real hand-over, are not verified on a host.

## Reconciliation and failure semantics

1. Read protected policy/admission/intent under the persistent kernel lock.
2. Validate owned anchor shape and stock NAT/RDR wildcard hooks. Foreign filter
   rules, child anchors, tables or unexpected rule drift stop mutation. Never
   reload `/etc/pf.conf`, edit Apple anchors or flush global states.
3. Independently inspect the running runtime as the admitted ordinary runtime
   account. Validate exact container definition, network helper generation,
   current instance and address, and read the guest's hardware address where
   the runtime states one. Stored endpoint facts do not activate.
4. Read owned rules and the complete kernel state table. A malformed, truncated,
   inaccessible, stale or changed-schema read is unknown, never absent.
5. Apply pure planning to those fresh observations and the root's approvals.
   Immediately before each activation, reread durable gates, desired content,
   approvals and fresh runtime evidence. Verify current LAN interface/address,
   forwarding, route/ARP for direct guest targets and host socket coexistence.
   A check that is not met defers that one profile to the next pass.
6. Parse candidate rules first, reread the old anchor immediately before loading,
   load only the owned anchor, and compare exact normalized readback. NAT
   statements precede RDR statements. A healthy pass does not reload rules.
7. Withdraw stale/missing/changed guest targets. While a retained state of a
   withdrawn rule exists, invalidate states from and to the exact old guest
   address and read back that none is left. Activate a replacement only in a
   later pass with fresh identity evidence.
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

The reader returns the protocol of a row and, for every endpoint that names an
IPv4 address, that address and its port, whichever endpoint carries it. Arrows
of mixed direction, a missing endpoint, a third arrow, two endpoints without an
arrow between them, a port above 65535, a tcp or udp endpoint without a port
and a control character inside a row are refused. Only a line feed ends a row.

The forms without parentheses are macOS display forms as an existing site's
own state reader is tested with them: sanitized rows, not a raw capture that
was reviewed in this repository. The parser regressions keep those shapes;
every address and port in them is a documentation value. They are not hardware
acceptance. Any other native format must remain unknown until its complete
grammar is established by reviewed captured output; the native qualification
gate remains closed.

### Retained states

A row of the state table is a retained state of an owned record when

- its protocol is the profile's (the name, or the number the printer writes for
  a protocol without a name),
- one of its endpoints is the record's target with a port inside the profile's
  target ports (for a UDP return profile: inside its ports), and
- another of its endpoints is a peer: an IPv4 address inside the scope's LAN
  prefix that is not the target. The host's own LAN address is a peer only in
  a row in which every IPv4 address is the target or lies inside the prefix.

These are the properties of the rendered rules. A redirect matches one protocol
from the LAN prefix to the host and translates to the target and its port; the
return rule matches the target's ports towards the LAN prefix. The kernel keeps
the target with that port as the `lan` host of a state made under a translation
rule and the peer as its external host, for a redirect and for an outbound
translation alike
([xnu `bsd/net/pf.c`, tag `xnu-12377.121.6`, lines 5620-5732](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pf.c#L5620-L5732)).
The properties, not the position of an endpoint in the row, decide which
endpoint is which. A guest's own connections, to hosts outside the LAN or from
other ports, are not retained states: they do not delay a retirement, and a
retirement that finds no retained state leaves them alone. The invalidation
that a retained state calls for is by address, though, so it ends them too
(below).

The host's own LAN address lies inside the prefix that a redirect matches, so a
packet that arrives with it as its source creates a state that names only the
target and that address. The runtime's own translation of a flow that the guest
opens to an address outside the LAN names the target and the host's address as
well, and that outside address. This is why the host's address is a peer only
in a row that names no address outside the prefix.

When the installed policy no longer describes the record (the profile was
removed, its digest or kind changed, or the policy cannot be read during an
administrator withdrawal), the rule that was loaded is not known any more and
every row that names the target counts. A host redirect has no retained states:
its target is the host itself.

The published `states` entry, the plan's `retained-states` decision, the drain
of a pass and the drains of the administrator `withdraw` use this one rule and
the one validated reader. A drain reads the table first. If no retained state
exists it invalidates nothing. Otherwise it invalidates states from and to the
target and reads the table again; the backend only issues the two scoped
invalidations, and a state that is still listed is not drained. The two
selectors name the target's address alone (`pfctl -k <target>` and
`pfctl -k 0.0.0.0/0 -k <target>`), so they end every state of that address at
that moment, the guest's own connections to hosts outside the LAN included;
the guest's applications have to open those again.
An invalidation that fails and a table that cannot be read, before or after
it, are errors and not an open drain: they end the pass `failed` and make
`withdraw` fail.

Two limits are known. The rule looks at the target, its port and the peer; the
host endpoint's port is not consulted. It therefore cannot tell two profiles
apart that publish different host ports onto one target port of one guest. Nor
can it tell a state of the rule from a flow that the guest itself opens to a
LAN peer from a port of the rule: for a UDP return profile that is every flow
from the published range to the LAN, also one that the runtime's own
translation carries after the rule is withdrawn. The same holds for a flow
between a port of the rule on the guest and the host's own LAN address, in a
row that names no address outside the prefix. In these cases the retirement
stays `states-retained`, with an invalidation on each pass, for as long as such
a state is listed again when the table is read back, and each of those
invalidations ends the guest's other connections as well. And that a macOS state
table shows the client and the target with its port as endpoints of such a
state, and what the scoped invalidation removes, follows from the kernel source
and the printer lineage cited here, not from a capture reviewed in this
repository. Both belong to native acceptance.

A runtime inspection exception is unknown and withdraws existing guest exposure.
It withdraws every other rule as well, a rule that ends at the host's own
address included. What an installation can choose to
[keep](#host-paths-while-runtime-evidence-is-unknown) is such a rule on a pass
in which the read of the rule's service ran out of time, or whose evidence for
it is merely too old.
A corrupt root admission record also inhibits activation and retires known
exposure. Partial writes journal the exact candidate before mutation; the next
pass accepts only the old or known candidate kernel view, withdraws it and drains
its states. An explicit administrator journal acknowledgement is required before
activation resumes. Unknown foreign drift is never overwritten as recovery.

Every pass first records phase `applying` with its planned actions, also when it
will change nothing. A pass that stops while its journal still has exactly that
first record, with no candidate, wrote no rule: the next pass needs no
acknowledgement and plans from fresh evidence. That first record may name its
boot session, as every record of a pass does when the session is known. A
failure that awaits its acknowledgement is recorded as `failed` again by each
later pass, in every record it writes including those that carry a candidate, so
neither stopping one of them nor a reboot at that moment can cancel the
acknowledgement. What a pass does with its records after a reboot is described
under [After a reboot](#after-a-reboot).

A [host path that a pass keeps](#host-paths-while-runtime-evidence-is-unknown)
is not written at all; what follows holds for every other planned action.
Within one pass the owner applies every planned withdrawal before it invalidates
any state, as the administrator withdrawal does. A retained state that stays
then defers its profile with all planned rules already retired; it cannot leave
the rule of a later profile loaded. Drains and activations keep their planned
order. An invalidation that fails, or a state table that cannot be read during
a drain, fails the pass, also with all planned rules already retired.

### Deferral and writes in doubt

The acknowledgement exists for one situation: the kernel may hold something
other than what the owner's records say. That is a write in doubt: a rule load
that fails or whose readback differs from the journalled candidate, a candidate
or a record that cannot be written, an enable reference that cannot be taken
or identified, protected installation or policy content that changes during the
pass, admissions that cannot be read when they are checked again, an
invalidation of the states of a withdrawn rule that fails, a state table that
cannot be read before or after that invalidation, a final
readback that differs from the records, a final state table that cannot be
read, or a report that cannot be written. Each ends the pass `failed`, as does
a state table that cannot be read when the pass starts.

A precondition that is not met before anything was written for a profile is not
that situation. The pass defers that one profile, goes on with its other
actions and ends `inhibited`. The next pass reads everything again; nothing is
retried inside a pass. The reasons are a closed vocabulary:

| Reason | What the pass found before it wrote anything for the profile |
|---|---|
| `inhibited` | A pause, suspension or damaged intent that appeared during the pass |
| `not-admitted` | The profile's admission no longer matches |
| `evidence-unavailable` | The fresh runtime observation, the state table or the plan from them could not be had |
| `target-changed` | Fresh evidence no longer supports the planned target |
| `endpoint-unverified` | The interface, route or neighbour check did not pass or could not run |
| `ports-unverified` | The host socket check did not pass or could not run |
| `states-retained` | The invalidation for the already withdrawn rule was issued without error, the table was read again, and a retained state of that rule is still listed |
| `translation-order-unverified` | Only where the installation chose that check, before the activation of a rule pair with an outbound translation: the hooks of the main ruleset are not the accepted ones in their order, a sibling anchor holds a translation rule or a child, or one of these listings could not be read in time ([translation order](#translation-order-for-the-udp-return-pair)) |

A deferred profile has no rule loaded and is never `root_ready`. Its reason is
recorded as `deferred` in the journal's final record (`{profile: reason}`), in
the result of the pass, whose `pending` list includes the profile, and in the
profile's published data. All three are absent when nothing was deferred. A
profile with `states-retained` keeps its withdrawn record, so the plan holds it
at "drain only" and no replacement target is activated for it while the state
remains. A pass that still owes an acknowledgement ends `failed` whatever it
deferred.

A loaded rule pair whose [translation order](#translation-order-for-the-udp-return-pair)
a pass could not verify is not deferred: its rules stay loaded. It is
*withheld*, which is recorded under the key `withheld` in the same three places
and in the same shape. A
[host path that a pass kept](#host-paths-while-runtime-evidence-is-unknown)
without runtime evidence is withheld in the same way. Being withheld does not
put a profile into `pending`. A withheld pair is listed there only when the
final plan of the pass blocks it for a reason of its own, as every loaded
profile is; a kept host path is never listed there.

A final runtime observation that fails is not a write either. The pass then
treats every service as unknown, as it does when its first observation fails:
it ends `inhibited`, reports no profile `root_ready` and leaves the loaded
rules to the next pass, whose own first observation decides what to retire.

The owner holds only its own PF enable reference and keeps it while paused or
empty. It never globally disables PF or releases a token owned by another
service. A reference is operational runtime coexistence, not evidence of packet
reachability.

Every pass that leaves a rule loaded reads that reference back through the
backend's `references` and `enabled` reads: the kernel must list the saved token
and report PF enabled. The readback acquires nothing. If it fails, or the token
is not listed, the pass reports no profile as `root_ready`, ends `inhibited` and
records the reason `enable-reference-unverified` in the journal (`listing-notice`
when this readback itself was refused for an [unexpected notice](#a-listing-with-an-unexpected-notice)
of the tool; a notice in another read of the pass does not change the reason of
a readback that completed without the token or that failed). The rules stay
loaded and no state is invalidated for this reason; the first pass that verifies
again reports readiness again. A reference is acquired only as part of an
activation, so a reference that another tool removed stays missing, and the
profiles not ready, until a profile is next activated.

An installation can decide otherwise with `"enable_reference": "reacquire"` in
`installation.json`. A pass that then reads its reference back as not held takes
it again, once, and reads it back a second time. Taking the reference enables
PF and so puts every loaded rule back into effect; the pass therefore does it
only under the conditions of an activation:

- the readback was complete and did not list the saved token (a read that
  failed, or a listed token while PF is not shown enabled, acquires nothing);
- the pass is not inhibited by a pause, a suspension or a damaged intent, read
  again immediately before, and owes no acknowledgement;
- its final fresh evidence still verifies every rule it leaves loaded;
- it did not already acquire a reference at an activation.

If the second readback verifies, the pass reports readiness as usual. If it does
not, the outcome is the one above: `inhibited`, reason
`enable-reference-unverified`, no profile `root_ready`, rules untouched, and the
next pass tries once more. Either way the result of that pass carries
`"reference": "reacquired"` and the scheduled job writes it to its log, so
enabling PF again is never silent. An acquisition that raises ends the pass like a
failed activation, with a `failed` journal and an acknowledgement owed: a
reference may then have been taken without being recorded, and another attempt
on every pass would take another one each time.

This decision overrides an administrator's `pfctl -d`. Disabling PF drops every
enable reference, so while a rule of this owner is loaded the next pass enables
PF again, within one interval. With `reacquire`, the way to keep this owner's
forwarding off is its pause (`pause`, or `withdraw` before stopping the job),
not disabling PF. `"reacquire"` is the only value that can be written; `"verify"`
and `null` are refused, so an installation without the decision keeps its stored
bytes. Choosing it, or taking it back, changes the digest of every admission of
that owner: each profile is pending until it is admitted again, and `admit` and
`review-admission` show the decision where it was made; without it they print
what they printed before.

## Structural versus bounded profiles

Native host socket publication is performed by Apple Container as the ordinary
runtime account. PF **cannot claim publication ownership**. A structural
`host-redirect` first requires independently verified matching native publication
readback. Its target is the fixed host socket, not a recyclable guest address.
It never kills all states to the host address, because that would interrupt
unrelated services. Structural safety relies on the admitted native publication
contract; changes to that contract require review.

Every rule is bounded by the admitted LAN prefix of its scope, as the source of
a redirect and as the destination of the return translation, with one declared
exception. A structural `host-redirect` whose policy says `source_scope: "any"`
is rendered `from any`, and differs from the LAN-scoped rule in that one token.
Its translation target is the host's own address, and the native publication
behind it carries no source restriction (Apple Container 1.2.0 and 1.5.0,
[`PublishPort`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerResource/Container/PublishPort.swift#L41-L55):
host address, host port, container port, protocol, count). The setting
therefore changes which destination port leads to that publication for a
source outside the LAN prefix, not who can reach the publication. The renderer
refuses the token by itself for anything else: another value, another kind, a
bounded declaration, a fallback in effect, or a target other than the scope's
host address. `guest-direct` and `udp-return` rules always keep the LAN prefix.

Such a profile uses resolved digest version 3, which also binds the digest of
its backing publication: root approves the redirect together with the socket
it exposes, and a change of that publication reopens the redirect's admission.
The planner inhibits it on every pass (`risk-unacknowledged`) unless the
matching admission carries the acknowledgement, and the published `admitted`
flag requires the same. Changing an admitted LAN-scoped redirect to `any`, or
back, changes its digest: the loaded rule is withdrawn and nothing is loaded
until root admits the new digest. As for every host redirect, withdrawal does
not kill states that already exist.

Evidence that an unrestricted source serves the clients it was declared for is
a first packet from a source outside the LAN prefix, through the forwarding
router, and its reply; a LAN client proves nothing about this setting. The
instance report asks for it under a requirement of its own,
`ANY-SOURCE-INGRESS`, with the acceptance method `external-first-packet`
([instances](instances.md)); the method `first-packet` keeps its one meaning.
Nothing of this has been observed on a host. That the loaded listing of a
`from any` rule equals its normalized dry-run listing, on which every pass
depends, is an open native check.

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

### Translation order for the UDP return pair

Translation rules are first match across the hooks of the main ruleset, and the
vendor's network adds translation hooks of its own there. If one of them is
evaluated before the hook of the owned anchor's parent, or if a sibling anchor
below the same parent holds a translation rule, a guest's packet is translated
by someone else and the static-port rule never applies. The pair then fails
without a sign: its rules load, their readback is exact, and the replies leave
from another port. By default the owner checks only that the two parent hooks
exist.

An installation can require more with `"translation_order": "verified"` in
`installation.json`. A profile whose rules hold an outbound translation, which
is the UDP return pair, is then activated, and reported ready, only by a pass on
which both of these hold:

1. The translation listing of the main ruleset consists of exactly these lines
   in this order, each with or without a trailing ` all`:
   `nat-anchor "com.apple/*"`, optionally
   `nat-anchor "com.apple.internet-sharing"`, `rdr-anchor "com.apple/*"`,
   optionally `rdr-anchor "com.apple.internet-sharing"`. Any other line, another
   order or a repeated line is not verified.
2. The parent anchor has at most 64 children, each listed once under a name
   that is one component directly below it of letters, digits, `_`, `.` and
   `-` (at most 63 characters, not beginning with a mark), and every child
   other than the owned anchor has neither a translation rule nor a child of
   its own. Each sibling is read by itself; a wildcard listing is not proof.

A listing that cannot be read is not verified, and neither is a check that used
up its time. The check gates two things and withdraws nothing:

- **Activation.** A pair that is not loaded is activated only by a pass whose
  check passed immediately before that activation. Otherwise the profile is
  deferred with the reason `translation-order-unverified`: nothing is written
  for it, the pass goes on with its other profiles, and the next pass reads
  everything again.
- **Readiness.** A pair that is loaded is never withdrawn, and none of its
  states is invalidated, for this reason. An unverified translation order can
  cost the path; it cannot expose a guest, and retiring the pair would cost the
  path for certain. A pass that leaves such a pair loaded makes the check once,
  after its actions, so that no withdrawal and no invalidation of any profile
  waits for these reads. If the check does not pass, each loaded pair is
  *withheld*: its rules stay loaded and unchanged, it is not `root_ready`, and
  the pass ends `inhibited`. A pass that activates a pair therefore checks
  twice: immediately before the activation, and after its actions.

A withheld pair is not a deferred profile, because a deferred profile has no
rule loaded. It is reported where a deferral is and in the same shape, under the
key `withheld` (`{profile: reason}`): in the journal's final record, in the
result of the pass and in the profile's published data. All three are absent
when nothing is withheld. A pair is not listed in `pending` for being withheld;
it is listed there when the final plan of the pass also blocks it, for example
because the last observation of the pass no longer verifies its service. The
reasons are a second closed vocabulary with two words:
`translation-order-unverified`, and `runtime-unknown` for a
[host path kept without runtime evidence](#host-paths-while-runtime-evidence-is-unknown).

What an operator sees for a withheld pair is a profile that is loaded and not
ready, with `withheld` in its published data and in the journal that `status`
prints. Nothing has to be acknowledged, reloaded or resumed: the first pass
whose check passes reports the pair ready again. What to do is to find what the
check found. List the main translation rules (`pfctl -s nat`) and the children
of the parent anchor (`pfctl -a com.apple -s Anchors`) as root and compare them
with the two conditions. A vendor hook in another place, a further hook, or a
sibling that holds rules or children belongs to other software and is changed
there. A line or a name of another form than the ones above is to be reported:
the accepted forms are a closed list. An installation that wants the earlier
behaviour instead takes the decision back and admits its profiles again.

Profiles without an outbound translation are never checked, never deferred and
never withheld for this reason, and without the decision none of these listings
is read.

One check makes at most 66 calls of the backend: the hooks, the children, and
one for each of at most 64 siblings. Each call keeps its own bound of four
seconds, and the whole check has a bound of eight: no call starts once that is
used up, and a check that ends after it has not passed. Eight seconds leave each
of 66 calls about 120 ms, where a call that answers is a shell start and one or
two listings. A check therefore takes at most twelve seconds, and none of its
reads happens before the pass has recorded its planned actions. A pass makes one
check before each activation of a pair and at most one after its actions.

`"verified"` is the only value that can be written; `"present"` and `null` are
refused, so an installation without the decision keeps its stored bytes and its
admission digests. Choosing it, or taking it back, changes the digest of every
admission of that owner: each profile is pending until it is admitted again,
and `review-admission` and `admit` show the decision where it was made.

The listings are read by three read-only operations of the backend script,
`translation-hooks`, `siblings` and `sibling <name>`, under the strict rule for
a listing that names no anchor. Here an empty answer is the one that counts as
proof, and the public `pfctl` of this lineage answers the listing of a missing
anchor with a line on standard error and exit status 0
([FreeBSD 8.4 `contrib/pf/pfctl/pfctl.c`, `pfctl_show_anchors`, lines 1919-1955](https://github.com/freebsd/freebsd-src/blob/release/8.4.0/contrib/pf/pfctl/pfctl.c#L1919-L1955);
its caller at lines 2192-2193 ignores the result).

A sibling's name is taken from the listing of children as the printer prints
it. That printer writes each child as two spaces, its full path and a line feed
(lines 1949-1950 of the same file). Only that indentation is removed, and what
remains must have the form of condition 2 exactly. A line with any other white
space, an empty line or a second name on a line makes the listing unusable: the
check does not pass and no name of that listing is handed on. The owner, and
then the script, check a name against that form before `pfctl` is given it, and
it is only ever given to these two listings. The form is wider than the one of
the owned anchor, because a sibling is somebody else's anchor and need not
follow the rule this owner sets for its own name.

A read of the check that is refused for an
[unexpected notice](#a-listing-with-an-unexpected-notice) does not end the pass,
so no error names it. The pass hands the refused operation and the number of
unexpected lines back with its result, under `listing_notice`, and the entry
point writes them to standard error in the line that a refused listing writes
when it ends a command. The listing to capture by hand is then `pfctl -s nat`
for `translation-hooks`, `pfctl -a com.apple -s Anchors` for `siblings`, and
`-s nat` and `-s Anchors` of each sibling for `sibling`; the line does not name
the sibling. The journal's reason for such a pass is `listing-notice` unless its
reference readback found something more specific.

Limits. The four hook lines and their order are the ones an existing site's own
helper requires on its system and has run against; no published source gives
them, and Apple does not publish its `pfctl`. The form of the children listing,
one indented full path per line, is that of the public printer cited above. A
hosted dry run shows how one system's parser prints the four hook lines back; it
shows nothing about a live main ruleset. A different real listing costs the
pair, never safety: the pair is not activated, or is loaded and not reported
ready, and the reason says why. That includes a child of the parent anchor whose
name is outside the form above, and a child that has a child of its own. Which
children a stock system lists below `com.apple`, and whether those have
children of their own at times, is not established by any source here; either
would keep the pair from being activated or ready. Which hooks are evaluated
first, and that a sibling's rule can take a packet before the owned rule,
follow from first-match translation and were not observed on a host.

Darwin `pf.conf(5)` translation grammar has **no filter-rule `label` option** for
NAT/RDR. Profile IDs are comments in rendered input and protected journal data,
not unsupported appended labels. Darwin's `pfctl(8)` documents address/network
state invalidation; this implementation does not invent OpenBSD state-ID or
label kill support.

The backend script names an explicit exit for every check, because the bash 3.2
that macOS installs as `/bin/bash` does not end a `set -e` script after a
failing `[[ ... ]]` statement. Its rule files must be regular, single-link,
owned by root and mode `0600`; their group is not compared, since a new file
takes the group of its directory and mode `0600` gives the group no access. A
listing that names no anchor (states, status, references, the main hooks) fails
on a nonzero exit status and on any standard-error text other than the two ALTQ
notices `pfctl` writes on every call, so a failed read is not taken for an empty
table. Listings of the owned anchor check the exit status only: that anchor does
not exist before its first load, and the diagnostic `pfctl` writes for a missing
anchor is not published. The script has no operation that releases a PF enable
reference. Its three operations for the
[translation-order check](#translation-order-for-the-udp-return-pair) only print
listings.

### A listing with an unexpected notice

The script tells the two refusals of a listing that names no anchor apart. A
listing that fails ends the operation with status 1. A listing that ends with
status 0 and a line on standard error that is not one of the two notices ends
it with status 76, after the script wrote the number of such lines, and nothing
else, to its own standard error. Nothing was read in either case and the
outcome is the same: no rule is loaded, kept ready or reported on the strength
of that read. The owner records the second case under the closed reason
`listing-notice` wherever it records the first. It is the `reason` of the
journal record that would say `kernel-state-unknown`, of the record that would
say `enable-reference-unverified` because the reference readback was refused, of
the final record of a pass that deferred a profile, or withheld a loaded pair,
because of such a read (the profile keeps its own reason) and of the `failed`
record of a pass that the refused read ended. A record has one reason, and a
notice never takes the place
of a finding: where the reference readback of a pass completed without the
token, or failed, the final record says `enable-reference-unverified`, also
when another read of that pass was refused for a notice. A command that ends
with the reason writes one line to standard error: the reason, the backend
operation that was refused (`inspect` or `replace` for the main hooks, `states`,
`enabled` for the status, `references`) and the number of unexpected lines. A
pass that absorbed a refused read of its
[translation-order check](#translation-order-for-the-udp-return-pair) writes the
same line although it completes, with `translation-hooks`, `siblings` or
`sibling` as the operation. For
a root job installed from a deployment manifest, standard error is the job's
launchd stderr target, `<label>.err.log` in the job's `log_directory`; a job
installed any other way writes the line wherever its installation directs
standard error. The unexpected line itself is the tool's text. It is kept in no
record and not in the published report, and the owner does not write it to
standard error either, where it never puts raw tool output. The allowed notices
are a closed list in the script, so the reason does
not go away by itself. When it appears, run the named listing by hand as root
(`pfctl -s nat`, `-s states`, `-s info` or `-s References`), keep what it writes
to standard error and report it: a notice that the tool writes on every call
is added to the list with a release, and until then the owner stays withdrawn
or not ready, as after a read that failed. What Apple's `pfctl` writes for these
four listings as root is not established by a published source or a capture.

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
runtime identity is insufficient to select or to activate either strategy. A
fallback rule that is already loaded outlasts it only where the installation
chose to
[keep host paths](#host-paths-while-runtime-evidence-is-unknown), under the
conditions named there.
If direct access becomes
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

## Host paths while runtime evidence is unknown

The planner retires every rule of a service on the first pass that cannot
establish the service's identity, and the owner carries that out. For a rule
that names a guest address this is the point: the address may belong to another
guest by now. A host redirect, and a `guest-direct` profile in its
[fallback form](#explicit-dns-availability-fallback), name no guest. Their rule
translates to the host's own address, to the port of a native publication.
Retiring it takes the web port or name resolution away from every device on the
LAN until a later pass has evidence again.

An installation can decide to keep such a rule with
`"runtime_unknown": "keep-host-paths"` in `installation.json`. The decision
keeps and never activates. It cannot bring a rule into existence and it never
enables PF for one; it spares a rule that a pass with verified evidence loaded.
A profile that the plan of a pass retires is kept instead if and only if all
five of these hold on that pass:

1. **Its record ends at the host.** The record is active, its kind is
   `host-redirect` (which is also what the fallback form is recorded as), its
   target is the host address of the profile's scope, it was rendered from the
   policy the profile has now, and its rules are exactly what the renderer
   writes for that profile with the host address as the target. No rule of such
   a record names another target.
2. **The pass only lacks the evidence.** Two things must say so: the plan's
   reason for the withdrawal, and the observation of the profile's service
   that the plan was made from. The two lists below are complete.
3. **The loaded rules are the recorded ones.** Every pass reads the anchor back
   when it starts and again before it reports. A pass that finds anything else
   there ends as before: with the drift error before it judges anything, or
   `failed` with nothing reported as kept.
4. **Something listens behind the rule.** Root's own socket inventory of this
   pass, read by the reader of the host socket check, lists a socket of the
   rule's protocol on every port the rule translates to, on the scope's host
   address or on the wildcard, held by an IPv4 or a dual-stack socket. For TCP
   that is a socket in the listening state. UDP has no such state; there it is
   a socket bound to the port. An inventory that cannot be read establishes no
   listener.
5. **The owner's enable reference is held.** This pass's own readback, made
   with the reader that ends every pass, lists the owner's token and shows PF
   enabled. A loaded rule carries nothing while PF is disabled, and the owner
   does not enable PF for a rule it has no evidence for: a reference that is
   not held, and a readback that failed, keep nothing.

### The plan's reason

What the plan of the pass has for the profile's withdrawal, and what the
decision makes of it. These are all reasons of the planner.

| Reason | Outcome with the decision |
|---|---|
| `network-unknown`: the snapshot has no network generation | kept only if the service's observation is `unknown` with `timed-out` |
| `snapshot-stale`: the snapshot is older than the profile allows, or dated ahead of the clock | kept only if the service's observation is one of the two that state no finding (below) |
| `endpoint-unknown`: the service's observation is unknown, older than the profile allows or dated ahead of the clock | the same |
| `publication-not-ready`: inherited from the native publication behind the rule | as above if every reason the plan has for that publication is one of the three; retired otherwise |
| `paused`, `suspended`, `held`, `intent-damaged` | retired: an authority |
| `not-admitted`, `admission-future`, `risk-unacknowledged` | retired: an authority |
| `endpoint-absent`, `contract-mismatch`, `endpoint-invalid` | retired: a finding about the service |
| `policy-changed`, `target-replaced` | retired: a finding about the rule |
| `profile-unknown`, `invalid-readback` | retired: the profile's own readback |
| `verified`, `ready`, `retained-states` | no withdrawal is planned; nothing is judged |

### The observation of the service

None of the three reasons is one statement, so the observation that the plan
was made from must state no finding either. There are two such observations.

| Observation of the rule's service | Outcome with the decision |
|---|---|
| `unknown`, `timed-out` | kept: a read ran out of time |
| `present` | kept only if age alone made the plan retire (below) |
| `absent` | retired, however old the snapshot is |
| not in the snapshot | retired |
| `unknown`, `unavailable` | retired: a tool answered with an error, or the observer raised |
| `unknown`, `identity-mismatch`, `generation-mismatch`, `incomplete`, `malformed`, `inaccessible` | retired: what a read found |
| `unknown` with any other reason | retired |

**A read that ran out of time.** The bundled observer reports `timed-out`
where a bounded call did not end within its bound, or where a time budget was
used up before a call could start. Without a network generation, for every
service at once, when that happens to a read of the runtime as a whole: the
tool's version, the boot session, the job or the process of a network helper,
a network or its interface, the job of the vendor's API where it is observed,
the listing, the second read of the helpers, the networks and that job after
the containers, or the eight seconds of the whole observation. For one service,
with the rest of the observation intact, when it happens to a read that belongs
to its container: the container's inspection; the check of an enrolled mount or
receipt, which has five seconds for each, after the container's configuration
was compared with the enrolled one; the read of the port range inside a running
guest; and, where the job of the vendor's API is observed, the service
manager's answer about the job of a guest that the vendor lists as stopped. In
the last case the observer says neither that the service is absent nor that it
runs. A stopped container holds no port, so the fourth condition is what
retires its rule then.

**An answer with an error is not such a read.** The observer reports
`unavailable` when a tool exits with an error or writes to its standard error:
the service manager saying that it has no job of a helper or of the API, which
is what a stopped runtime looks like, an interface or a network that does not
exist, a failed listing, an error or a stray line for one container, and a
user session that could not be entered. The owner records `unavailable` as
well when the observer raised, which includes the observer's refusal to run a
tool that a user could replace and settings it cannot use. All of that retires
every rule, with or without the decision.

**Evidence that is present and too old.** The plan checks age before anything
else, so its reason does not say what an old snapshot holds. Such evidence
keeps a rule only if the planner's plan of the same snapshot, the same
admissions and the same intent, made with the time the snapshot was taken as
its clock, has exactly one action for the profile: the verified no-op that
leaves a loaded rule untouched. The owner's readback of its own records
belongs to the pass and is dated at that time for this plan, and so are the
admissions it gives the runtime's publications. Everything else is taken as it
is. For a fallback form that means that the direct path, which the owner checks
only for evidence that is present and not too old, is not checked again: the
form that is loaded is the one that is judged. Old evidence that states another
instance, another network generation, another contract, an address outside the
guest network or a publication that is absent, unknown or another one retires
the rule, as it would if it were fresh. So does evidence whose observations are
older than their snapshot allows or dated ahead of it, an admission that was
given after the snapshot was taken, and a snapshot dated ahead of the clock,
which names no time at which it was taken. The bundled observer dates a
snapshot and everything in it at the start of the observation, so evidence is
too old where the observation took longer than the profile allows or the
calendar clock was set forward meanwhile.

### What a pass does

Which profiles the judgement can concern is settled before the pass writes its
first journal record, from the records, the policy, the plan and the snapshot
the plan was made from; nothing is read for it. A pass that has such a
candidate judges before its first action, before any withdrawal, invalidation
or activation, so that no rule is loaded and unjudged while the pass acts. It
reads the enable reference, which is at most two bounded calls of the backend
script, and, only if the reference is held, the socket inventory once for each
protocol of a candidate, which is one bounded call each. At most four calls,
the first two bounded by four seconds each and the others by two, therefore
stand before the first withdrawal of such a pass. That is what the judgement
costs the retirement of every other rule. A pass without a candidate, and every
pass of an installation without the decision, reads none of this.

The plan keeps its order. A rule that is not kept is withdrawn and drained
where the plan has it, with the others: every planned withdrawal before any
invalidation, as [above](#reconciliation-and-failure-semantics). An error of
another kind than a failed read at one of the judgement's reads ends the pass
`failed` before anything is written; the next pass owes an acknowledgement and
retires every rule.

A rule that is kept is not written: no withdrawal, no drain, no change of its
record. The profile is *withheld* with the reason `runtime-unknown`, in the
journal's final record, in the result of the pass and in its published data,
exactly as a [withheld pair](#translation-order-for-the-udp-return-pair) is. It
is not `root_ready`, it is never in `pending`, and the pass ends `inhibited`.
The planned actions in the journal still list its withdrawal and its drain, as
the plan had them; `withheld` says that they were not carried out. A pass that
ends `failed` after its judgement reports nothing as kept.

**The enable reference is never taken while a rule is kept.** Taking it enables
PF, which puts every loaded rule into effect, and a kept rule is not a verified
one. A pass that keeps a rule and activates another profile reads the reference
back once more, right before that rule is loaded. If it is held and listed, the
rule is loaded without the call that could take the reference. If it is not, or
the readback failed, every kept rule is retired first, rule and record, with no
state invalidated, as at the drain of a host redirect; then the reference is
taken and the activation goes on as it does without the decision, with no rule
loaded that the pass has no evidence for. With `"enable_reference":
"reacquire"`, the end of a pass that keeps a rule does not take a lost
reference again either, even where its final evidence verifies that rule: the
pass reports the reference as unverified, and the next pass decides. Without
evidence it finds the fifth condition unmet and retires the rule; with evidence
the rule is verified and the reference is taken as for every verified rule.

The judgement is made again on every pass, and nothing of it is remembered. No
count and no deadline ends it: a rule stays kept for as long as the five
conditions hold on each pass. The `unknown_limit` of a profile is not consulted.

- **Evidence returns.** The plan verifies the rule again, the pass writes
  nothing for it and reports it ready. A pass that was planned without evidence
  reports the rule withheld even when its final observation has the evidence
  again; the next pass reports it ready.
- **The listener goes.** The next pass withdraws the rule. Its return does not
  bring the rule back: that takes a pass with verified evidence.
- **The enable reference goes.** The next pass withdraws the rule, whatever the
  installation chose for a lost reference.
- **An authority changes.** A pause, a suspension, a hold on the service, a
  damaged intent, an admission that lapsed, changed or lost its acknowledgement,
  a journal that awaits its acknowledgement, a profile that was removed from the
  policy or whose policy changed, with or without a new admission: the next
  pass retires the rule like any other. An authority that changes while a pass
  is running is honoured by the next pass, as it is for every rule that a pass
  leaves loaded.
- **The state table cannot be read, or the anchor drifted.** The pass ends as
  it always did: every rule is retired, or the pass stops with the drift error.
  The decision is not consulted.
- **A reboot.** The kernel has no rule any more. With `self-heal` the records
  are dropped and nothing is kept, because nothing is loaded; by default every
  pass stops with the drift error, as for any active record. Nothing is
  activated without evidence in either mode.

What an operator sees is a profile that is loaded and not ready, with
`"withheld": "runtime-unknown"` in its published data and in the journal that
`status` prints. Nothing has to be acknowledged or resumed. What to do is to
find out why the reads of that service run out of time.

### The price

**No bound in time.** While the reads of a service keep running out of time, a
kept rule sends the traffic it matches to whatever listens on that host port:
LAN traffic, and traffic from every source for a redirect declared with
`source_scope: "any"`. Nothing ends that but one of the five conditions.

**The listener check asks only that something listens.** The owner does not
know whose socket that is. The fourth condition establishes that a socket
exists, not that the admitted publication of the admitted service holds it;
the process and its account are not asked. An activation asks far more: the
enrolled container verified, its publication read back present, the admission,
the interface and the host socket check. While the reads run out of time the
owner cannot tell whether the container behind the publication is still the
admitted one. The vendor's runtime holds a published port in the container's
own runtime service, bound to the publication's host address, and that service
closes it when the container is cleaned up (apple/container,
`Sources/Services/RuntimeLinux/Server/RuntimeService.swift`,
`startSocketForwarders` at tag 1.2.0 lines 887-958, tag 1.4.1 lines 1008-1079
and tag 1.5.0 lines 1014-1085; the call of `stopSocketForwarders` at lines
1284, 1408 and 1413). In the kernel this owner is written for, a process of
another user that is not root cannot bind an IPv4 port while a socket holds it
on a specific address, unless that holder asked to share it; once no socket
holds it, any process can, and a bind to the wildcard address needs no
privilege even below port 1024 (apple-oss-distributions/xnu, tag
xnu-12377.121.6, `bsd/netinet/in_pcb.c`, `in_pcbbind`, lines 1017-1049 and
989-1004). A process that binds the port after the container has gone
therefore receives the traffic of the admitted port for as long as the reads
run out of time. The planner's position that "a configured socket declaration
is not evidence that the matching service owns today's socket" is exactly what
this decision sets aside, for rules that were activated under verified
evidence and for as long as the evidence stays unknown. An installation without
the decision does not pay this price and loses the path on each such pass.

**A client of the runtime's account.** The safety contract records as a
residual that such a client can redirect an admitted port by changing the
runtime. A change that the observer can read retires the rule on the next pass,
with or without the decision. With the decision, a change that is made while
the reads of that container, or of the runtime as a whole, run out of time is
not noticed for as long as they do. Whether such a client can make a read run
out of time has not been examined; an installation that makes the decision has
to assume that it can.

**The reads of the judgement stand before the first withdrawal.** On a pass
with a candidate, the retirement of every other rule waits for at most four
bounded calls, as described above.

**A kept rule is bound to the policy and to its record, not to what else an
admission binds.** The record holds the digest of the policy it was rendered
from, and the rule is compared with what the renderer writes now. Neither
holds the installation, the owner's implementation or the time of the
admission. A change of the installation or an upgrade changes the digest of
every admission of that owner, and choosing this decision or taking it back
does so as well; a pass that runs before the profile is admitted again retires
every rule as `not-admitted`. If the profile is admitted again before a pass
ran in between, the plan has no such reason, and a rule whose service gives no
answer in time is kept without ever having been verified under what was
admitted. The same holds for an admission that was given again for any other
reason. To avoid that, let one pass run after the change and before admitting
again, or run `withdraw` first.

What the decision never does: it translates nothing to a guest address without
evidence, it activates nothing, it takes no enable reference for a kept rule,
and it reports nothing ready. Every rule that names a guest, the direct form
and the UDP return pair, is retired on the first unknown exactly as without it.

`"keep-host-paths"` is the only value that can be written; `"retire"` and `null`
are refused, so an installation without the decision keeps its stored bytes and
its admission digests. `admit` and `review-admission` show the decision where
it was made; without it they print what they printed before.

Limits. For UDP the inventory cannot tell a socket that receives from every
peer from one that is connected to a single peer; both are bound to the port.
For a service whose read ran out of time, the observation of the publication
behind the rule is not asked on its own: the bundled observer gives a
publication the state and the reason of a service that is not present, so the
two cannot differ there.
A change of the native publication's declaration in the policy does not retire
a kept host redirect whose source is the LAN, because the digest of such a
redirect does not bind the publication; without runtime evidence nothing else
can show the change. The digest of a fallback profile, and of a redirect with
an unrestricted source, binds the publication, and such a change retires them
as `not-admitted`. How the runtime holds a published port in the socket
inventory of a real host has not been captured: the vendor source cited above
says that it is a socket on the publication's host address, and the condition
accepts an IPv4 or dual-stack socket on the wildcard or on the host address
and nothing else, so a port that is held in another form is never a listener
and the rule is retired as without the decision.

## After a reboot

Packet rules and states are kernel memory; `live.json` is a file. After a reboot
the owned anchor is empty while the records still describe the rules of the boot
before. What the owner then does is the administrator's decision, stored in
`installation.json`:

| `cold_start` | After a proven reboot |
|---|---|
| absent (the default) | The administrator stays in charge. While a record is active, every pass stops with the drift error and writes nothing until the administrator runs `withdraw`. |
| `"self-heal"` | The pass drops its records and goes on as an ordinary pass of an empty installation. |

`"self-heal"` is the only value that can be written; `"administrator"` and `null`
are refused, so an installation without the decision keeps its stored bytes and
its admission digests. Choosing the value, or taking it back, changes the digest
of every admission of that owner: each profile is pending until it is admitted
again, and `review-admission` and `admit` show the decision where it was made;
without it they print what they printed before. The value is the root owner's
half of an instance's accepted unattended recovery. Nothing compares the two
documents, so write it only for an instance that made that decision.

A reboot is proven by three facts that root reads in the same pass:

1. The kernel's boot session now: one bounded read of
   `/usr/sbin/sysctl -n kern.bootsessionuuid`. Exactly one upper-case UUID is an
   answer; anything else is a failed read.
2. The boot session in the last journal record. Every record that a pass or a
   `withdraw` writes carries `boot_session` when that read succeeded and no such
   member when it did not.
3. The owned anchor is verifiably empty: `inspect` succeeded and returned what
   an empty rule file normalizes to.

Both sessions must be well formed and differ. A journal without the member (an
earlier release, or a pass whose read failed), a session that cannot be read
now, an anchor that was emptied within one boot and an anchor that holds
anything are not a cold start. They are handled as before, by the drift rule and
by the administrator.

On a cold start:

- With `self-heal` the records are dropped and the journal is replaced by an
  `inhibited` record with reason `cold-start`. The pass then continues and skips
  no check: pause, suspensions, a damaged intent, a missing admission and
  unknown runtime evidence stop it exactly as they stop the pass of a new
  installation. A write that the previous boot cut short needs no
  acknowledgement, because neither its rules nor its states exist any more. A
  failure that a pass had recorded stays owed across any number of boots: the
  journal is replaced by a `failed` record with the same reason and nothing is
  activated before `acknowledge-journal`.
- Without the decision, records of which none is active are dropped as well. A
  journal that needed an acknowledgement still needs it, as a `failed` record
  with reason `cold-start`. With an active record nothing is changed.
- In both modes the remembered targets are dropped, never invalidated: after a
  boot those addresses can belong to other guests. The candidate that a journal
  kept from another boot is not adopted either.

`withdraw` does not need the anchor to match the records, or the journal's
candidate, when the anchor is verifiably empty: there is no rule to retire, so
it loads nothing, still requires the empty readback and retires the records.
That is the administrator's way out in the default mode: `withdraw`, then
`resume`. Within one boot, where somebody emptied the anchor, it still
invalidates the states of every remembered guest address and fails while one
remains. After a proven reboot it invalidates nothing and reports
`"guest_states_drained": false` and `"cold_start": true`. A withdrawal after a
reboot that fails half-way keeps the earlier boot session in its journal record,
so repeating it is still a withdrawal after a reboot.

Limits. "Verifiably empty" rests on the read that a new installation already
relies on. The backend script reports a missing anchor and an empty one alike,
and a failed read of the anchor that ends with status 0 and no output is not
told apart from either. A reboot is proven only when the last journal record
before it was written by this release and its pass could read the boot session:
a journal that an earlier release wrote last proves nothing. The boot-session
read as root under launchd, and the anchor and the stock hooks right after a
boot, are not established by fake or hosted runs; they need captures on a real
host.

## Holding one service

A hold on one service ([state contract](state-machine.md)) retires that
service's profiles and leaves the others loaded. Root keeps its own holds in
`operator-intent.json`:

```text
python -I -m netorch.pf_owner hold --root-dir <root-dir> --service <service> \
  --operation <operation> --holder <holder>
python -I -m netorch.pf_owner unhold --root-dir <root-dir> --service <service> \
  --operation <operation> --holder <holder>
```

`hold` is available like `pause` and `suspend` and refuses a service that the
protected policy does not name. `unhold` is blocked in this stage like `release`.

Root's own file and the inhibition path are merged as a union: pause, damage,
suspensions and, per service, holds. Nothing in the user-side file clears a
pause, suspension, hold or damage of root's own. The user's operation names are
hashed into keys and never interpreted; its holder strings are validated
identifiers that are never used as a path, a command or a rule. Root reads that
file as before, one pinned regular file of bounded size that is strictly parsed,
and an unreadable or malformed file is damage. A held service that the
protected policy does not name makes the merged intent damaged for that pass;
root does not guess which of its services was meant. Root writes nothing into
the user's file and runs nothing that it names.

A workload manager that stops a guest needs to know when forwarding to it is
gone, and it may not ask root. The report therefore carries two more keys per
profile, each present only as stated:

| Key | Value | Present |
|---|---|---|
| `held` | `true` | Only when the profile's service is held in the intent the pass read last, the one `root_ready` is computed from. |
| `gate_revision` | The `revision` of the inhibition-path file in that same read. | Only when an inhibition path is set, the file was read undamaged and the number is at most 2^53 - 1, which every JSON reader represents exactly. |

A planned stop is then: place the hold and keep the printed revision R; wait,
with a bound, for a fresh report in which every listed profile of the service
has `state: absent`, `held: true`, an empty `states` and a `gate_revision` of
at least R; stop the guest; do the work; start the guest; release the hold. No
clock is compared and nothing is called. The comparison relies on the revision
of one file only growing; a manager does not carry a revision over to a file
that was replaced during a repair. A report with `held: true` and
`state: present` comes from a pass that planned before the hold arrived; the
next pass retires the rules. While a held service has profiles of this owner a
pass ends `inhibited`, as during a pause, and prints its result. A hold that
arrives between a pass's plan and its activation of a profile of that service
stops that activation the way a pause does: nothing is written for that
profile, it is deferred with the reason `inhibited`, no acknowledgement is
owed, and the pass after the release activates it.

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

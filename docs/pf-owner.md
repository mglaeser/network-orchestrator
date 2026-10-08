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
| `installation.json` | Closed installation identity, independently observed runtime settings, owner/anchor, published report path, interval, optional inhibition path (a user-side intent file that can only add inhibition), the optional decision to take a lost PF enable reference again and the optional [cold-start decision](#after-a-reboot) |
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

The administrator first runs `review-admission`. It returns the resolved
profile, scope, service, prior approval, the installation's cold-start decision
where it made one, and the proposed digest. The subsequent
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
has at most 63 characters of `a-z`, `0-9`, `.` and `-`. An existing site can
therefore keep the one anchor its previous manager used, instead of having two
managers' rules loaded side by side during a move. The installation record
and the argument check of the backend script apply the same grammar; the
script does not know the owner and cannot check whose product form it is
given. Nested anchors and longer components are refused: the kernel does not
create an anchor component of 64 characters or more
([xnu `pf_find_or_create_ruleset`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pf_ruleset.c#L353-L358)).

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
- another of its endpoints is an address inside the scope's LAN prefix that is
  neither the target nor the host's own LAN address.

These are the properties of the rendered rules. A redirect matches one protocol
from the LAN prefix to the host and translates to the target and its port; the
return rule matches the target's ports towards the LAN prefix. The kernel keeps
the target with that port as the `lan` host of a state made under a translation
rule and the peer as its external host, for a redirect and for an outbound
translation alike
([xnu `bsd/net/pf.c`, tag `xnu-12377.121.6`, lines 5620-5732](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pf.c#L5620-L5732)).
The properties, not the position of an endpoint in the row, decide which
endpoint is which. A guest's own connections, to hosts outside the LAN or from
other ports, are not retained states: they do not delay a retirement and a
retirement does not reset them.

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
invalidations, and a state that is still listed is not drained.

Two limits are known. The rule looks at the target, its port and the peer; the
host endpoint's port is not consulted. It therefore cannot tell two profiles
apart that publish different host ports onto one target port of one guest. Nor
can it tell a state of the rule from a flow that the guest itself opens to a
LAN peer from a port of the rule: for a UDP return profile that is every flow
from the published range to the LAN, also one that the runtime's own
translation carries after the rule is withdrawn. In both cases the retirement
stays `states-retained`, with an invalidation on each pass, for as long as such
a state is listed again when the table is read back. And that a macOS state
table shows the client and the target with its port as endpoints of such a
state, and what the scoped invalidation removes, follows from the kernel source
and the printer lineage cited here, not from a capture reviewed in this
repository. Both belong to native acceptance.

A runtime inspection exception is unknown and withdraws existing guest exposure.
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

Within one pass the owner applies every planned withdrawal before it invalidates
any state, as the administrator withdrawal does. A retained state that stays
then defers its profile with all planned rules already retired; it cannot leave
the rule of a later profile loaded. Drains and activations keep their planned
order.

### Deferral and writes in doubt

The acknowledgement exists for one situation: the kernel may hold something
other than what the owner's records say. That is a write in doubt: a rule load
that fails or whose readback differs from the journalled candidate, a candidate
or a record that cannot be written, an enable reference that cannot be taken
or identified, protected installation or policy content that changes during the
pass, admissions that cannot be read when they are checked again, a final
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
| `states-retained` | A retained state of the already withdrawn rule remains, or its invalidation or readback failed |

A deferred profile has no rule loaded and is never `root_ready`. Its reason is
recorded as `deferred` in the journal's final record (`{profile: reason}`), in
the result of the pass, whose `pending` list includes the profile, and in the
profile's published data. All three are absent when nothing was deferred. A
profile with `states-retained` keeps its withdrawn record, so the plan holds it
at "drain only" and no replacement target is activated for it while the state
remains. A pass that still owes an acknowledgement ends `failed` whatever it
deferred.

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
records the reason `enable-reference-unverified` in the journal. The rules stay
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
reference.

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
stops that activation the way a pause does, with a failed pass that needs the
administrator's acknowledgement.

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

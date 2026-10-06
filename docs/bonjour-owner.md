# Supervised native Bonjour discovery owner

> **0.3 stage boundary:** this guide describes retained owner mechanisms and mock
> contracts. Native authority expansion is unavailable while the accepted support
> matrix is empty. Existing installed owners stay in place; see
> [read-only workflow](getting-started.md) and [migration gates](site-migration.md).

The reusable implementation extends the existing browse/resolve/proxy-register
approach. Apple's maintained `/usr/bin/dns-sd` talks to the native
mDNSResponder stack. Python owns parsing, provenance, leases and supervision.
There is no new raw mDNS stack, general multicast reflector, compiled adapter,
root Bonjour service, extra VM or fixed HomePod IP.

## Data and independent authority

The private canonical network policy supplies owner identity, service identity,
LAN interface/address, guest subnet, DNS-SD types, dependencies and maximum
record age/count. A separate mode-0600 settings file names that policy, owner
bindings, admissions, durable intent, state directory and each guest interface
with its expected IPv4 address. The bundled example uses documentation-only
addresses and must be replaced with private site data before deployment.

The endpoint accepts only `observe` and `reconcile-discovery` from the versioned
owner protocol. A request supplies policy hashes, current generations and a
boolean intent. It cannot supply records, commands, raw packet rules or an IP to
publish. It cannot restart containers or invoke privileged networking tools.
Bindings describe independently readable runtime and forwarding owners. The
Bonjour owner excludes its own binding when collecting evidence, avoiding
recursive self-observation. Observations never grant packet-rule authority.

Both scanner and publisher independently read the established owner reports,
admissions and durable intent. Their transport plan must show every discovery
dependency as verified. Exact dependency digests, target IPv4, service generation
and network generation must agree with fresh complete readback. A coordinator's
optimistic `active` flag alone cannot create a registration.

## Export: guest services to reachable LAN endpoints

Browse only configured service types on the named guest interface. Resolve the
genuine instance, SRV port, IPv4 address and raw TXT bytes. The source address
must equal the current announcing service's inspected guest address. The
service generation is the independently inspected running instance generation.

A source record is exportable only when exactly one verified publication owned
by that same service, generation, scope and protocol maps its guest port to the
LAN endpoint. A coincident numeric listener or another container's publication
does not qualify. The published instance name and TXT bytes are preserved;
only the hostname, address and mapped port change. Each record has its own
stable synthetic `netorch-container-…` hostname to prevent sibling A-record
ownership conflicts.

For `_home-assistant._tcp` only, `internal_url` and `base_url` values that point
exactly to the resolved guest hostname/address are projected to the reachable
LAN address and mapped port. Scheme, path, query and fragment are preserved.
External URLs, credentials-bearing URLs and opaque/binary TXT data are untouched.

## Import: genuine Apple media endpoints into the guest network

Browse the configured AirPlay/RAOP/companion/media-remote types on the named LAN
interface. Eligibility comes from a genuine `_airplay._tcp` record advertising
an allowed `AudioAccessory*` or `AppleTV*` model, or the existing owner's
`am=AppleTV*` fallback. Matching is case-insensitive; duplicate model/am keys
are rejected. This is discovery eligibility, not authentication of a device.

Related records must have the same hostname **and** IPv4 as an eligible AirPlay
endpoint. Hostnames compare using ASCII DNS case equivalence, preserving observed
spelling; Unicode case folding is not used. An unrelated service sharing an IP
does not qualify. All eligible
devices in the configured LAN are supported; no per-device IP list is needed.
DHCP changes replace registrations. The port, instance and TXT remain genuine.
Each projected record uses a separate stable `netorch-lan-…` hostname and the
real LAN device address on the guest interface. Projected records are excluded
from the reverse path to prevent loops, including case variations of both reserved
projection prefixes in names and hostnames.

Discovery digest version 3 retains the version 2 selection semantics above and
binds the corrected native `...STARTING...` banner and browse-label grammar
described below. This is a source-format correction, not a broader device
selector. Version 1 and 2
requests, candidates and cached readbacks are rejected at the owner boundary;
unchanged policy cannot retain an older implementation's discovery authority.
Fresh planning and observation are required. Transport policy digests are
unchanged. This does not open the current native qualification gate.

Discovery digest version 4 binds the changes to record reading, selection and
leasing made after 0.3.2; each is described where this document covers that
behavior. Version 1 to 3 requests, candidates and cached readbacks are
rejected at the owner boundary in the same way.

Discovery does not supply the audio/video return path. A verified UDP-return
dependency is required by the canonical import policy. The forwarding owner
remains its sole writer and its independent safety/approval boundary is retained.

## Native CLI parsing and confirmation

Every DNS-SD command carries an explicit interface argument. Independently
verify that the interface exists, owns its expected IPv4 and has a nonzero
interface index. Require exactly one matching `Using interface N` line;
success exit status alone is insufficient. Wrong-interface, malformed,
duplicate, ambiguous, oversized, denied and timed-out output fails closed.

Browse Add/Rmv rows preserve Unicode names and spaces without shell evaluation.
SRV and IPv4 must resolve uniquely. TXT is read with `-Q … TXT IN`, whose native
raw hexadecimal output preserves binary, empty and non-UTF-8 entries. Every
TXT byte is passed back through Apple's `\xHH` registration grammar. No shell
interpolation, string splitting or fabricated cache entry is used.

Synthetic native-format fixtures follow Apple's timestamp width, including the
single leading hour-padding space before 10:00. Registration callbacks parse the
timestamp prefix once and retain the full exact name, including consecutive
spaces. These fixtures are source-derived contracts, not production captures.
Asynchronous registration reads retain incomplete trailing lines until their
newline; a split pipe read is not a conflicting identity. Every SRV/A/TXT callback must parse; a valid row cannot hide a malformed callback
or unexpected query row. Fixed native banners are separately recognized,
including the timestamped `...STARTING...` line that `dns-sd` prints once before
its event loop for every operation; a near-miss of that line stays malformed.
Browse callbacks use Apple's exact fixed-width columns before the unescaped
instance label. Leading/trailing spaces and Unicode separators remain part of
that label; only byte line endings split native output. Distinct labels such as
`Speaker` and ` Speaker` cannot collapse or remove one another. SRV's
single optional shell-friendly TXT continuation stays opaque bytes because that
native display can contain non-UTF-8 data; only `-Q` provides authoritative TXT.
Browse/register instance labels remain unescaped, while native escaped
resolve/query fullnames pass through unchanged. This follows Apple's
[reply construction](https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-2881.120.11/mDNSShared/uds_daemon.c)
and [fullname API](https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-2881.120.11/mDNSShared/dnssd_clientlib.c).

Each `-P` registration must independently confirm both the exact unchanged
service name and its own A-record hostname. Auto-renaming, conflict, removal,
any child exit other than the client's own timer (see below) and missing
confirmation invalidate it. This uses the maintained
[Apple DNS-SD client implementation](https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-2881.120.11/Clients/dns-sd.c).

## Supervision, leases and recovery

launchd supervises one scanner process. It starts a separate publisher watchdog
process, which alone owns all registration children. Separate non-stealable
scanner/publisher locks prevent duplicate writers. Each native read has an
external wall-clock/output bound in addition to the CLI timer; a scan also has
a fixed total budget. Partial passes cannot refresh an old source lease.

The scanner rests `poll_seconds` between two passes unless the settings give
`pass_seconds` (5 to 120). `poll_seconds` (1 to 10) also paces the publisher's
independent evidence, which has to stay younger than each dependency's own
limit, so a slower scan has a value of its own. A pass interval longer than half
of an owned policy's `max_age_seconds` is refused: a pass's candidate must
still be fresh when the next pass has been written. The scanner's heartbeat is
healthy for three of its own intervals, and for at least 60 seconds.

The watchdog performs no blocking native read in its event loop. Fresh
independent proof collection runs separately. Record deadlines use monotonic
time; a backwards wall-clock adjustment cannot extend an unchanged source
lease. A stalled scan, stale owner evidence, failed interface check, removed
admission, changed generation, changed policy or damaged intent withdraws owned
registrations. The durable pause is checked directly each watchdog tick.

If the scanner dies, the watchdog detects the changed parent relationship,
withdraws children and exits. It cannot adopt a replacement scanner's files.
SIGTERM cleanup terminates only its own spawned client process groups. No
foreign process is signalled and no DNS cache is manually seeded or flushed.
The separate Monit heartbeat check detects a stalled scanner/publisher; a
Bonjour health failure never authorizes a container restart. Native mDNS cache
propagation remains outside the local child's lifetime guarantee.

Every native registration also carries `dns-sd -t` with at most 120 seconds,
bounded by its remaining record lease rounded up to whole seconds. Apple's
client terminates itself on that timer even if the publisher is killed. This
second lifetime bound prevents indefinitely orphaned registrations; normal
supervision renews from fresh evidence after client expiry. Actual renewal and
cache propagation behavior remain native acceptance gates.

A client that exits with status 0 at or after its own `-t` lifetime, without an
`Error code` line, has ended on that timer: `Clients/dns-sd.c` lines 1315-1320 at
the revision above arm it with `exit(0)`, and lines 245-246 show the other
`exit(0)`, which prints that line first. This is the expiry of one record, not a
failure. The publisher replaces that client alone, with the lease that is left
and only after the old client has ended, so it never runs two clients for one
record. Sibling registrations keep running. A record that was confirmed keeps
the policy's state while its replacement confirms; the five-second confirmation
limit bounds that, and the observation's `record_count` leaves the record out
until then. The record is not registered between the two clients. A replacement that
fails, and every other exit (another status, a signal, status 0 before the
lifetime or after an `Error code` line), is a registration-child failure as
before. Renewal still needs fresh evidence: without it the lease ends and the
policy withdraws.

Bounded scan denial and registration-child failure are isolated by discovery
policy. The affected policy withdraws or becomes unknown while sibling policies
continue refreshing valid records. Global policy/intent corruption still
invalidates all owned registrations.

One candidate file holds every policy's records. When a pass would exceed that
file's size or structure bound, the bulkiest policy loses its records with the
reason `incomplete` until the rest fits; the other policies keep their lease.
The durable request file can outlive a policy change. An entry for an
identifier the policy no longer declares is ignored, because only declared
policies are ever read, and the endpoint's next write removes it under the
lock. A request file that is itself malformed still invalidates every owned
registration.

Root dependencies use only a protected fresh report from the independent root
owner with exact policy/generation, its own current admission proof and an
operational readiness flag fenced by root pause/suspension and verified readback. The user
admission file cannot approve a root profile, and this read-only readiness view
cannot invoke root or expand its scope.

Fresh complete absence with verified interfaces is observable at cold start;
it permits the coordinator to request activation after transport is verified.
An active declaration whose registrations are all confirmed reads `present`
even when there are none: a guest that advertises nothing on a published port,
or a link without an eligible device, is "active, nothing to publish". The
observation's `record_count` tells the two apart. An import declaration without
`_airplay._tcp` could only ever be in that state, because eligibility is decided
on a device's `_airplay._tcp` record; this owner refuses to load settings whose
policy gives it such a declaration.
A fixed endpoint request waits at most seven seconds for matching readback,
then returns actual evidence. It never reports success from process launch alone.

## Local Network privacy and native acceptance

Retain an explicitly chosen user executable identity. Record that identity and
any required Local Network consent before deploying the launch agent. A denied
native operation has its own `local-network-denied` reason. Do not move the
service to root to bypass consent, grant broad firewall exceptions or reset
privacy/background-item databases. Apple's identity/consent behavior is
described in [TN3179](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy).

Public CI uses strict recorded-format fixtures, fake bounded native clients and
property tests; it never registers services, plays audio or modifies PF.
Deployment acceptance must separately verify real interface ownership,
register/browse/resolve parity, withdrawal deadline, child/scanner crash,
multiple changing devices, reload/reboot reconnection and actual return traffic.
Only an explicitly coordinated physical test can prove audible playback.

Rollback pauses durable intent, observes withdrawal, unloads the generated
Bonjour launch job and restores the prior reviewed release/settings through
the provisioning transaction. It preserves the established packet-rule owner,
container definitions and application configuration. Run exactly one discovery
publisher when rolling back; never overlap an older standalone proxy with this
owner.

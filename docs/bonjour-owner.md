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
that label; only a line feed ends a line of native output, so a carriage return
is part of the label too and such a label is refused like any other control
character. Distinct labels such as
`Speaker` and ` Speaker` cannot collapse or remove one another. SRV's
single optional shell-friendly TXT continuation stays opaque bytes because that
native display can contain non-UTF-8 data; only `-Q` provides authoritative TXT.
Browse/register instance labels remain unescaped, while native escaped
resolve/query fullnames pass through unchanged. This follows Apple's
[reply construction](https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-2881.120.11/mDNSShared/uds_daemon.c)
and [fullname API](https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-2881.120.11/mDNSShared/dnssd_clientlib.c).

Replies are data. The words of a diagnostic are not searched in them, so a
device whose name, host name or TXT reads like one (`Error code display`, a
serial number ending in `-65570`) is read like any other. A diagnostic is read
where the client prints one. The lines are those of `Clients/dns-sd.c` at the
revision linked below, with their line numbers:

| Operation | Banners | Reply (data) | Diagnostic |
| --- | --- | --- | --- |
| every | `Using interface N` (2135), `DATE: ---…---` (515), `...STARTING...` (2396-2397) | | on the error stream: `Unknown interface …` (2104), `… failed <code>` (2392), `Error code <code>` (246) |
| `-B` | `Browsing for <type>.local.` (2157), table heading (763) | `Add`/`Rmv` row ending in the unescaped name (768-769) | `Error code <code>` in place of a row (766) |
| `-L` | `Lookup <name>.<type>.local.` (2181), which echoes the name | `<full name> can be reached at …` (828-834), then at most one line of TXT display (837, 781-813) | `<full name> No Such Record` (830) or `<full name> error code <code>` (831) in place of the reply |
| `-G` | table heading (1253) | `Add`/`Rmv` row (1276) | `No Such Record` (1281) or `Error code <code>` (1283) appended to the row |
| `-Q` | table heading (1115) | `Add`/`Rmv` row with hexadecimal data (1182-1188) | `No Such Record` (1193) or `No Authorization` (1195) appended to the row; `Query Timed Out` (1199) |
| `-P` | `Registering Service …` (1501-1527), which echoes name, host, port and TXT | `Got a reply for service …` (918-923), `Got a reply for record …` (1435-1441) | a reply that ends in `Error <code>` (940, 1441) or `Name in use, please choose another` (936, 1440) |

Any content of the error stream fails a scan command. On the output stream
every line has to be a banner, a well-formed reply of the operation that was
run or, directly after a resolve reply, its one line of TXT display; any other
line fails the command. The reason is `local-network-denied` only for that
operation's own error line with code -65570 (for a query: `No Authorization`),
and `malformed` otherwise. The TXT display cannot pose as such a line: every
reply starts with a timestamp and two spaces, and the display never holds two
adjacent spaces. The words of a diagnostic are searched as text only in the
error stream and in what the client prints before its event loop, that is
before the first timestamp, and there not in the two lines that echo the
arguments. The registration reader follows the same rule: the echo line and
the replies are data, a reply that ends in `Error -65570` is a denial, and
every other complete line is searched as before.

A browse reply carries the instance name unescaped (`mDNSShared/uds_daemon.c`
line 624 at the same revision), so a name can hold a line feed and continue on
lines of its own. A browse therefore accepts the client's banners only where
the source prints them, before the first reply. After a reply it accepts
replies only. A date line that follows a timestamp is accepted for a change of
day alone, that is directly before a timestamp with an earlier time of day
(`printtimestamp_F`, lines 512-518). Anything else is the rest of a name and
fails the browse: a name cannot pose as a banner, and an `Error code` line that
follows a row is reported as `malformed`, never as a denial. Nor can it pose as
a row: the shortest row the client prints has 74 bytes, a label at most 63. One
device can thus no longer remove another from the result by naming itself
`<name>`, a line end and a banner.

The name `.` is refused as a browse row and is never passed to `-P`: the client
reads it as the empty name and would register the computer's own name instead
(line 1498). These reading rules are part of discovery digest version 4.

Each `-P` registration must independently confirm both the exact unchanged
service name and its own A-record hostname. Auto-renaming, conflict, removal,
any child exit and missing confirmation invalidate it. This uses the maintained
[Apple DNS-SD client implementation](https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-2881.120.11/Clients/dns-sd.c).

## Supervision, leases and recovery

launchd supervises one scanner process. It starts a separate publisher watchdog
process, which alone owns all registration children. Separate non-stealable
scanner/publisher locks prevent duplicate writers. Each native read has an
external wall-clock/output bound in addition to the CLI timer; a scan also has
a fixed total budget. Partial passes cannot refresh an old source lease.

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

Bounded scan denial and registration-child failure are isolated by discovery
policy. The affected policy withdraws or becomes unknown while sibling policies
continue refreshing valid records. Global policy/intent corruption still
invalidates all owned registrations.

Root dependencies use only a protected fresh report from the independent root
owner with exact policy/generation, its own current admission proof and an
operational readiness flag fenced by root pause/suspension and verified readback. The user
admission file cannot approve a root profile, and this read-only readiness view
cannot invoke root or expand its scope.

Fresh complete absence with verified interfaces is observable at cold start;
it permits the coordinator to request activation after transport is verified.
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

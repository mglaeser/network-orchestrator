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
genuine instance, SRV port, IPv4 address and raw TXT bytes. The source host
must currently hold the announcing service's inspected guest address. A guest
may hold further addresses, an alias for example. Its record is read by the
guest address where the address answer holds it. Where an alias outside the
guest network answers first, an instance on a published port is read a second
time (below); an alias inside the guest network is read as it stands, as
before, and an instance for whose second read there is no room is left out.
The published address and port still come from the verified publication alone.
The service generation is the independently inspected running instance generation.

The address is read with `-m`, and with it the client can show one of a
host's addresses alone ([below](#one-instance-and-the-scan-as-a-whole)). The
runtime gives each guest exactly one address of the guest network (the scope's
`guest_cidr`), the guest address among them, so an answer that holds an
address of that network names a host of it and is read as it stands. An answer
whose addresses all lie outside the guest network, an alias alone for example,
may be the first part of the guest's own answer. Where the projection could
export the instance, that is where its port is the guest port of exactly one
verified publication of the policy for the type's protocol and the loop
exclusion does not refuse it, its host is read once more without `-m`. That
client shows every reply until its own `-t` timer: one more command of
`scan_seconds` for such an instance. The instance is read by the guest address
where the second answer holds it, as before where that answer holds another
address of the guest network, and otherwise it is left out and counted in
`skipped`, never dropped in silence. A record that an earlier pass exported is
then withdrawn in this pass whatever the miss tolerance, as for every answer
that cannot be used ([below](#supervision-leases-and-recovery)). The second
read is made only where it can end, with one second to spare, before the
earlier of the scan's own time and the scanner's wait for the scan (45
seconds, or half the lease where that is less); without that room the instance
is left out, and a scan whose own time is used up fails as before. In every
other respect it is the first read: the same interface line, rows,
diagnostics, failures and forms of a read that did not complete. No import
makes a second command, and neither does an answer that holds the guest
address or no address at all, an instance on any other port, which is read as
it stands whatever its addresses, or an instance that the loop exclusion
refuses (a record this owner projected into the guest network). An alias
inside the guest network cannot be told from another guest's address and is
read as it stands.

A source record is exportable only when exactly one verified publication owned
by that same service, generation, scope and protocol maps its guest port to the
LAN endpoint. A coincident numeric listener or another container's publication
does not qualify. The published instance name and TXT bytes are preserved;
only the hostname, address and mapped port change. Each record has its own
stable synthetic hostname under the policy's export prefix (`netorch-container-…`
unless the policy names another) to prevent sibling A-record ownership conflicts.

For `_home-assistant._tcp` only, `internal_url` and `base_url` values that point
exactly to the resolved guest hostname/address are projected to the reachable
LAN address and mapped port. The host name compares by ASCII DNS case
equivalence, like every other name here. Scheme, path, query and fragment are preserved.
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
Each projected record uses a separate stable hostname under the policy's import
prefix (`netorch-lan-…` unless the policy names another) and the
real LAN device address on the guest interface. Projected records are excluded
from the reverse path to prevent loops, including case variations of both reserved
projection prefixes in names and hostnames.

The two prefixes are one pair for the whole policy: its optional
`discovery_names` object, described under
[discovery strategies](configuration.md#discovery-strategies). The owner reads
the pair from the policy alone; its settings file cannot change it. A pair
other than the default is a member of every discovery digest, so the
coordinator and the owner compute the same value and a request, candidate or
readback made under another pair is refused. A policy without the object
keeps its digests, so this needs no new digest version. Records that an
earlier run registered under other prefixes are ordinary records to this
one, not its own. Change the pair only while the owner is stopped and its
registrations have ended; after a kill the clients end on their own timer
within 120 seconds.

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

Discovery digest version 5 additionally binds truthful renewal health, complete
final-pipe inspection, exact registration-interface identity, and the refusal
to revive a source explicitly rejected in the current pass. Versions 1 to 4
requests, candidates and readbacks are rejected by the enforcing owner. The
new tests exercise each boundary with an actual prior digest. No transport
approval or native qualification follows from this discovery version change.

Discovery does not supply the audio/video return path. A verified UDP-return
dependency is required by the canonical import policy, unless its entry says
`"return_path": "independent"` ([configuration](configuration.md)). The owner
then projects the eligible records without waiting for a return path; it
still waits for every dependency the entry lists. The forwarding owner
remains the return path's sole writer and its independent safety/approval
boundary is retained.

## Native CLI parsing and confirmation

Every DNS-SD command carries an explicit interface argument. Independently
verify that the interface exists, owns its expected IPv4 and has a nonzero
interface index. Require exactly one matching `Using interface N` line;
success exit status alone is insufficient. Wrong-interface, malformed,
duplicate, ambiguous, oversized, denied and timed-out output fails closed.

Browse Add/Rmv rows preserve Unicode names and spaces without shell evaluation.
SRV must resolve uniquely, and so must IPv4 for an import; an export accepts
the inspected guest address among several, and reads an answer that shows
addresses outside the guest network alone a second time where the projection
could export the instance
([export](#export-guest-services-to-reachable-lan-endpoints)). TXT is read with `-Q … TXT IN`, whose native
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
every other complete line is searched as before. The echo line is data only
where it is exactly the line the client prints for the record it was given,
with the TXT as ShowTXTRecord shows it (781-813): a diagnostic on the error
stream can follow a stdout line that a full block cut, so a cut echo is
searched like any other line.

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
any child exit other than the client's own timer (see below) and missing
confirmation invalidate it. This uses the maintained
[Apple DNS-SD client implementation](https://github.com/apple-oss-distributions/mDNSResponder/blob/mDNSResponder-2881.120.11/Clients/dns-sd.c).

## One instance and the scan as a whole

A failure that is confined to one instance's own resolution costs that
instance alone, not its policy. A scan runs one browse for a type and then three
commands for each browsed instance. An instance whose own replies cannot be
used is left out of that pass: it gets no lease, a registration made for it
earlier is withdrawn, and the healthy records of the policy are projected and
leased as usual. Three rules bound what may be left out:

- A reply that names another interface than the one asked for fails the scan,
  in the resolve as in the address and TXT queries: the scope was not
  honoured, and that concerns every instance.
- A scan, that is one type on one interface, leaves out at most four
  instances. A fifth unusable instance fails the scan with `incomplete`, and
  the names after it are not asked about.
- A pass leaves instances of a policy out only if it read at least one
  instance of that policy completely: of any of its types, and whether or not
  that instance is then selected. Where instances would be left out and none
  was read, the pass fails for that policy with `incomplete`, because a pass
  in which nothing could be read does not show that the reader works.

The candidate carries the number of instances left out as `skipped` (absent
while there is none; at most four for each type, fewer where `max_records` is
lower), and the observation shows it as `skipped_count` beside `record_count`.
That count is the only trace of a device that is being left out. Everything that
concerns the scan as a whole still fails it, and a failed scan withdraws the
policy unless the settings count it as a miss
([below](#supervision-leases-and-recovery)):

| Failure | Detected by | Outcome |
| --- | --- | --- |
| A command does not complete: time limit, output bound | the bounded runner | the scan fails |
| A command cannot prove itself: exit status, any error stream, a missing or second `Using interface N` line | `confirmed_output` | the scan fails |
| A diagnostic of the client in any command, a denial among them, or any other line that is neither a banner nor a well-formed reply | `confirmed_output`, the command's reader | the scan fails |
| A reply for another interface than the one asked for, in the resolve, the address query or the TXT query | the command's reader | the scan fails |
| The browse: more names than `max_records`, a name that cannot be passed on | `browse_names` | the scan fails |
| The time budget of the scan is used up | `scan` | the scan fails |
| A fifth unusable instance in one scan | `scan` | the scan fails |
| Resolve: no reply (a browse entry whose instance is gone), replies that differ, a port outside 1-65535, a target outside `.local.` or not UTF-8 | `resolve_endpoint` | the instance is left out |
| Address: none, several for an import, several without the guest address for an export; for an export also an answer outside the guest network, for an instance the projection could export, whose second read holds neither the guest address nor another address of that network, or for whose second read there is no room | `resolve_ipv4`, `scan` | the instance is left out |
| TXT: no record, records that differ, a record shorter than one of its strings declares | `resolve_txt` | the instance is left out |
| The answers form no valid record: a host name longer than 255 bytes | `scan` | the instance is left out |
| Instances to leave out and no instance of the policy read in the same pass | `scan_policy` | the policy is withdrawn |
| More usable records than the policy's `max_records`, a duplicate or an unverified dependency in the projection | `scan_policy`, `project_records` | the policy is withdrawn |
| A candidate whose `skipped` is not an integer from 1 to its bound, or whose `tolerated_failure` is not `malformed` or `incomplete` beside at least one record, stale or foreign evidence | `lease_records` | the policy is withdrawn |

An instance is left out only by a command that has proved itself, that is
seen to have entered its event loop (its `...STARTING...` line) and whose every
output line was a banner or a well-formed reply. Nothing the client reports as
an error and nothing unreadable is passed over, so a denial, a daemon that is
not running, a wrong interface or a client that never waited for a reply cannot
hide behind the count.
Leaving an instance out can only shorten what is published: each record is
built from that instance's own three answers. For a record that is shorter
than it declares, the client's resolve display reads `<< invalid data >>`
(`Clients/dns-sd.c` line 788 at the revision above); it is accepted as the
display, and the query then shows the record to be unusable. An instance that
does not answer costs one command that waits `scan_seconds`. A pass in which
instances are left out can therefore take up to `4 * scan_seconds` longer for
each type it scans than a pass that reads every instance, and a type whose
scan fails at the fifth has waited up to `5 * scan_seconds`. The scanner
writes the candidates of all its policies once, after the last scan of the
pass and with the time the pass began, and its heartbeat after that, so this
time ages the candidate of every policy of the pass. This is part of
discovery digest version 4.

An export instance whose address is read a second time
([export](#export-guest-services-to-reachable-lan-endpoints)) costs one more
command, whether it is then published or left out. Each second read adds up to
`scan_seconds`, the client's own `-t` timer, and is made only where it ends
before the earlier of the scan's 45 seconds and the scanner's wait for the
scan, so the bound of one scan and the budget of a pass are unchanged.

Which of these cases the client can show is read from its source
(`Clients/dns-sd.c` at the revision above), not captured from a host. The scan
passes `-m` to the resolve, address and TXT commands, and with it the client
leaves after the first reply that is not marked as followed by more (lines
841-844, 1209-1212 and 1287-1290). A host with two IPv4 addresses therefore
shows two rows only if both replies are delivered together; with one row an
import reads that address, and so does an export, except that for an instance
the projection could export an address outside the guest network is read a
second time without `-m`
([export](#export-guest-services-to-reachable-lan-endpoints)). TXT records that differ are
likewise two records listed together; an `Add`, `Rmv`, `Add` sequence for a
record that changed is read as its last value. The address command asks for
intermediate results (line 2306) and prints a negative answer as
`No Such Record` (lines 1280-1281), which fails the scan as every diagnostic
does; a host without an IPv4 address is left out only if the client prints no
row at all.

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
registrations. The durable pause and the holds are read directly each watchdog
tick. A hold on a policy's service withdraws that policy's registrations and
stops its scans, and the other policies keep theirs unless they depend on a
transport profile of the held service; a hold on a service that the installed
policy does not name withdraws all of them.

If the scanner dies, the watchdog detects the changed parent relationship,
withdraws children and exits. It cannot adopt a replacement scanner's files.
SIGTERM cleanup terminates only its own spawned client process groups. No
foreign process is signalled and no DNS cache is manually seeded or flushed.
The separate Monit heartbeat check detects a stalled scanner/publisher; a
Bonjour health failure never authorizes a container restart. Native mDNS cache
propagation remains outside the local child's lifetime guarantee.

A record that one completed pass does not find is withdrawn in that pass. The
settings can give `miss_tolerance` (1 to 8; 1 unless given), because a guest's
advertisement is not answered within every browse window: the record is then
kept until that many consecutive completed passes of its policy have missed it.
A policy whose discovery entry states `misses` (1 to 8,
[configuration](configuration.md#discovery-strategies)) takes that number
instead of the owner's setting, so one policy can withdraw on the first miss
while another keeps its records through several; a policy without the member
follows the setting.
Only a completed pass counts as a miss, unless the settings say otherwise for
a failed one (`failed_pass`, below). A failed pass, a pass skipped because
its dependencies were not ready, a scanner restart and a change of the policy
digest or of the guest or network generation forget what was read; the next
miss then withdraws as without a tolerance. A kept record stays among the
sources its pass judges, with the time it was last seen. A record read again
under its name and type takes its place, what the pass would not project now
is dropped, and kept records never push a policy over `max_records`. Because
the time is not refreshed, the lease, the client's own lifetime and the
publisher's deadline end a kept record at `max_age_seconds` whatever the
tolerance says. `miss_tolerance` is the owner's own and an input of no digest.
A policy's `misses` is a member of that policy and of its discovery digest, so
a request, candidate or readback made for the entry without it, or with
another number, is refused. Either way the lease that the digest binds still
bounds every record.

An instance that the current completed pass explicitly resolved and left out
is removed from missed-source memory by its exact name and service type. Its
older value cannot be republished beside healthy records or revived by a later
empty browse. This includes stale browse entries and unusable address, SRV or
TXT answers; a record absent from the browse is the separate tolerated-miss
case. A wholly unanswered failed pass follows only the explicit `failed_pass`
setting below.

The publisher refuses a whole candidate for one expired record. The scanner
therefore keeps a missed record only while its lease lasts longer than a rest
and two passes at their full time budget, counted from the start of the pass,
so that it cannot end between two candidates. The budget of a pass is the sum
of the limits its reads carry: ten seconds for each other owner's report, four
for the interface checks of each scope, 45 for each batch of up to eight
service types of each owned policy, and five of slack. For the example's two
policies that is 119 seconds, and a rest and two passes are 243. The
condition is each policy's own: its tolerance, its lease. A policy that follows
the owner's setting and whose `max_age_seconds` leaves no such room keeps
withdrawing on the first miss. Settings are refused where a tolerance above 1
could never keep anything. A lease has room when it exceeds that time by one
more rest, the least age of a missed record. The owner's `miss_tolerance` above
1 needs such a lease in at least one of the owned policies that follow it, and
a policy that states `misses` above 1 needs it itself. Where every owned policy
states its own number, the setting governs none of them and is compared with
no lease. The example's 120-second leases do not have it.

A pass that fails is weaker evidence that a record is gone than a completed
pass that did not find it. The settings can therefore give `failed_pass` with
its one value `"miss"`. Without the key a failed pass withdraws its policy at
once, as above; settings with the key are refused where no owned policy
tolerates a miss, because it could never have an effect. With it, and for a
policy that tolerates misses, a pass whose read did not complete counts as one
miss for every record the scanner remembers for that policy. Each is kept
exactly as a completed pass keeps a record it did not find: with the time it
was last seen, its count one higher, under the same lease condition and record
bound, and judged by the reports of that pass. Nothing is refreshed, not even
a record that another scan of the same pass has just read. A record whose
count reaches its tolerance is dropped, so failed and missed passes count
together and as many of them in a row as the tolerance withdraw a record. When
nothing is left to keep, the failure stands as without the setting: the
candidate carries its reason, nothing of the policy is published and what was
remembered is forgotten.

A read did not complete where what one client left is exactly one of three
forms, and in no other case. The forms are read from the client's source
(`Clients/dns-sd.c` at the revision above), not captured from a host, and
each is compared sign for sign, for the command that was run:

- The daemon is not running. `main` has printed the interface line and the
  line of its operation (lines 2135, 2157 and 2181; the address and TXT
  commands print no such line). The operation's call fails, and `main` writes
  `<call> failed -65563 (Service Not Running)` to the error stream and returns
  -1, which is status 255 (lines 2390-2394). The call is the one of that
  operation: `DNSServiceBrowse`, `DNSServiceResolve`, `DNSServiceGetAddrInfo`
  or `DNSServiceQueryRecord`.
- The daemon stopped while the client waited. After those lines the client
  has printed its date and start lines, and the reply callback ends it with
  `Error code -65563` on the error stream and status 0 before it prints
  anything for that reply (lines 245-246).
- The bounded runner stopped the client at the command's own time limit,
  `scan_seconds` and one second, before the client had shown a reply. The
  runner hands on what the client had written by then: nothing on the error
  stream, and on standard output either nothing or exactly those lines. The
  client flushes its output only in a reply callback and when it ends (lines
  772, 843, 1211 and 1289), so one that has had no reply has shown nothing.
  A client that had printed a denial, another interface or anything else
  before it was stopped is not on the list.

All three carry the reason `malformed`, which is what a pass has always
written for them. Every other failure withdraws at once, with or without the
setting:

- a denial, and a call that fails with any other code, the code of a missing
  authorization (-65555) among them;
- any other status, any other text on the error stream and any line on
  standard output that is not one of those lines, in its place;
- a command that does not show the verified interface first and once, that
  names another one or reports an unknown one;
- output at or over its bound, and a client that did not end cleanly after it
  had printed a reply, because replies are not read then;
- every line a reader refuses in an answer, a reply for another interface
  among them;
- more names or records than `max_records`, a duplicate, an unverified
  dependency and whatever else the pass refuses after it has read, except a
  pass in which no listed instance answered (below);
- a client that cannot be started and every other error that is not the
  reader's own;
- a scan whose time is used up, as the next paragraph says;
- a pass in which one scan failed in one of these ways, whatever another scan
  of it did.

One refusal of the pass itself counts the same way: a pass of a policy in
which the browse listed instances and none of them answered its resolve at
all. Each such instance printed no reply line, so it was left out, and the
pass read nothing; it fails with `incomplete`, at the rule that nothing is
left out unless something was read
([above](#one-instance-and-the-scan-as-a-whole)) or where a scan reached its
fifth such instance before it had read one. With the setting it counts as one
miss, also beside another scan of the pass whose read did not complete, and
its candidate names the reason of the failure it carried records through:
`incomplete` for such a pass, `malformed` where another scan of the pass
failed first by a read that did not complete; where nothing can be kept it
stands with `incomplete`. An instance that printed
any reply line has answered, also where its replies cannot be used (replies
that differ, a port or target that cannot be published), and a pass with such
an instance and nothing read keeps failing, beside another scan whose read did
not complete as well; so does a scan at its fifth instance left out where
another scan of the pass read one.

A scan has 45 seconds for one service type, and the scanner waits as long
for it, or half the lease where that is less. A scan whose time is used up is
never a miss, and it does not matter which of the three places notices it:
the scan has no time left for its next command (the reason `timed-out`); a
command fails, whatever it left, that started with less of the scan's time
left than its own limit and one second more; or the scanner stops waiting for
the scan, also where another scan of the pass has already failed by a read
that did not complete. A command can therefore be a read that did not
complete only if it started with its own limit and one second more left in
the scan. That second is there because the scan's time and the scanner's wait
end within moments of each other: no failure that would count is raised that
late.

A pass skipped for its dependencies, a pass that fails as a whole (an owner
report or an interface check), a scanner restart and a changed digest or
generation forget as before.

A failed pass that counted as a miss stays visible. Its candidate has
`tolerated_failure` with the reason, which is `malformed`, or `incomplete`
for a pass in which no listed instance answered, in the place of `reason`, and
the observation of a policy that reads `present` from that
candidate shows the same member beside `record_count`. A pass that completes
writes neither. The policy keeps reading `present` while its records are
kept, so whoever wants to know that passes are failing reads that member. The
publisher refuses a candidate whose `tolerated_failure` is anything else or
comes without a record. `failed_pass` is the owner's own and an input of no
digest.

Every native registration also carries `dns-sd -t` with at most 120 seconds,
bounded by its remaining record lease rounded up to whole seconds. Apple's
client terminates itself on that timer even if the publisher is killed. This
second lifetime bound prevents indefinitely orphaned registrations; normal
supervision renews from fresh evidence after client expiry, or shortly before
it where the settings say so (below). Actual renewal and
cache propagation behavior remain native acceptance gates.

A client that exits with status 0 at or after its own `-t` lifetime, with clean
output, has ended on that timer: `Clients/dns-sd.c` lines 1315-1320 at the
revision above arm it with `exit(0)`. Clean is judged on the whole output,
including what arrived after the last poll that saw the client running: it must
end with a newline, show the line `Using interface <index>` for the requested
interface exactly once with no foreign interface line, be at most 1 MiB and
pass the content checks of a
running client, that is, contain outside the exact echo line of this record no
`-65570`, `No Authorization`, `Error code`,
`error code` or `Unknown interface`, no line with `DNSService` followed by
`returned` or `failed`, and no `Got a reply for service` or
`Got a reply for record` line other than the two timestamped confirmations of
this record. In the libdispatch build that these lines belong to, a
registration has two more ends with status 0, and neither output is clean:
lines 245-246 print an `Error code` line first, and lines 2104 and 2405-2408
print `Unknown interface` and the usage. This is the expiry of one record, not a
failure. The publisher replaces that client alone, with the lease that is left
and, unless the settings give `renewal_overlap_seconds` (below), only after the
old client has ended, so that it never runs two clients for one record.
Sibling registrations keep running. A replacement must independently confirm
before the policy can again read `present / verified`; historical confirmation
does not prove a live registration. During an unconfirmed replacement the
policy reads `unknown / unobserved`, even if siblings are still registered.
The five-second confirmation limit bounds that wait. Without the setting the
record is not registered between the two
clients: it leaves the network and returns at least every two minutes. A replacement that
fails, and every other exit (another status, a signal, status 0 before the
lifetime or with output that is not clean), is a registration-child failure as
before. Renewal still needs fresh evidence: without it the lease ends and the
policy withdraws.

The settings can give `renewal_overlap_seconds` (1 to 30; absent unless given,
which is the behaviour above). The publisher then starts the replacement of a
confirmed client at the first turn of its loop at which that client's own
lifetime has at most that many seconds left, with the lease that is left, and
lets the running client end on its own timer. It never signals a client to make
room. The two then run side by side until the running client's lifetime ends:
for the setting less up to one turn of the loop, which is a quarter of a second
and the time the turn takes. For that time two clients hold the identical
record, never more, and each of them still ends by itself within its own
lifetime if the publisher is killed. While both run, the record is confirmed
by the running client and counted once; neither the policy's state nor
`record_count` shows the replacement. When the running client ends, a
replacement that has confirmed holds the record without interruption, and one
that has not is between two clients as described above until it confirms. A
replacement that fails is a registration-child failure and withdraws the policy
like any failed client; one that ends on its own timer before its predecessor
is dropped. No replacement is started early for a client that lives no longer
than the overlap, which is replaced after its end, nor where the lease does not
end at least a second later than the running client does. The two ends are
compared on the publisher's monotonic clock, not through a lifetime rounded to
whole seconds, so the length of a turn does not matter. A lease reaches further
than the running client after a newer sighting, or where it was longer than a
client's 120 seconds from the start. A sighting that arrives when the running
client already has less than the setting left starts the replacement at that
turn, and the two run side by side for what that client then has left. Without
either, nothing is started beside the client, the record ends with its lease as
before, and no renewal moves a lease deadline. Settings with an overlap are
refused unless at least one owned policy's lease, of which a client lives 120
seconds at most, is longer than the overlap.

The setting rests on what the daemon does with a second registration that is
identical to a running one. That was read in the source published as
`mDNSResponder-2881.120.11`, not observed on a host:

- `dns-sd -P` registers its address record with `kDNSServiceFlagsUnique` and
  its service with no flags, that is with automatic renaming left on
  (`Clients/dns-sd.c` lines 1468-1474, 1529-1533 and 2197-2204).
- A record that is identical in name, type, class and data to one already
  registered on the same interface goes on the daemon's list of duplicates, not
  on its active list (`mDNSCore/mDNS.c` lines 1329-1338 and 1756-1771). It is
  not probed, because only active records are (lines 4249-4254), and it is
  acknowledged to its client as registered: at once where it does not probe,
  which is the case for the shared PTR records and for the TXT record, which
  depends on its SRV record (lines 1569-1572 and 1810-1812), and otherwise as
  soon as the first copy is verified (lines 1776-1777, 4292-4299 and
  4323-4329). The address record takes the same path
  (`mDNSShared/uds_daemon.c` lines 796-801 and 1448).
- The client-facing layer counts registrations of the same service name and
  port only to write a log line, so the daemon logs one line for each renewal
  (`mDNSShared/uds_daemon.c` lines 957-967 and 2733-2739). A service that was
  registered under a name of its own is renamed only after a name conflict
  (lines 1071-1086), and an identical record raises none: a packet record
  identical to one of the daemon's own is not a conflict (`mDNSCore/mDNS.c`
  lines 10260-10276).
- When the first of two identical registrations is removed, the duplicate takes
  its place and state, and no goodbye is sent for the removed one
  (`mDNSCore/mDNS.c` lines 2089-2131 and 2230-2243). A client that exits is
  deregistered in exactly that way (`mDNSShared/uds_daemon.c` lines 1365 and
  1787, `mDNSCore/mDNS.c` lines 14929-14944).

The published source leaves out the vendor's own build options. One capture on
the supported release therefore stays part of the native acceptance gate: two
clients for one record, both confirmed under the unchanged name, and no goodbye
on the wire when the first one ends.

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

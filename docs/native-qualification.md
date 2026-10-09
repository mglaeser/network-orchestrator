# Native qualification procedures

These procedures adapt the useful measurement inventory from PR #125. They are
not scripts, authorization, a second acceptance schema or evidence that a test
has run. The native-qualified matrix remains empty. The retained owner entrypoints
remain gated. Complete [parity and readiness](migration-readiness.md) first.

Use one private record per applicable row/profile. Before an owner moves, take
the same measurements on its predecessor and retain failures as well as success.
Record the exact release artifact, source revision, dependency lock, instance
contract and resolved profile digests, OS build, runtime/tool versions, generation,
clock bounds and observer identity. Keep raw evidence private, with hashes and a
manifest linking it to the canonical acceptance record. The current closed
[acceptance schema](../schemas/acceptance-evidence.schema.json) stores an attested
result, not the capture or its authenticity. Do not add unrecognized fields to it.
A fabricated JSON record can pass shape checks; human review of its provenance
and the underlying measurement remains essential.

Every row needs a baseline, the same observation on the candidate, an explicit
pass criterion and retained evidence. Packet sends, registrations, application
connections, source interruption, audio, runtime stops, reboot and restore are
**active stimuli**, even if the observation uses read-only commands. Run them
only in their separately approved window. These procedures never grant sudo or
permit public CI to touch a production host. Use reviewed instance-specific
commands, bounded capture duration/output and exact owned resources, not pasted
placeholder commands or global firewall/state flushing. Keep the full dashboard
health contract before and after each authorized transaction.

A baseline describes the predecessor and cannot count as candidate acceptance.
Native records use `kind` `native-capture` or a clearly identified
`owner-attestation`; synthetic/offline fixtures cannot satisfy these rows.
`framework_sha256`, `contract_sha256`, versions, `observed_at`, `signed_by`,
`result`, `capture_context`, `profile`, schema versions and `source_versions`
must match the existing evaluator's contract. Per-profile records use resolved
profile digests; instance-wide records use `profile: null` and the whole instance
contract digest. Preserve mandatory capture contexts below.

The three residual requirements remain separate: `BOUNDED-IDENTITY` measures a
window, never absolute safety; `IMPORT-VISIBILITY` records explicit owner consent,
not isolation; `LIFECYCLE-WRITERS` records API writer authority, not its removal.
No capture promotes those residuals to fulfilled-verified. In particular, the
missing measured-bound reporting support remains a qualification blocker, not
permission to waive it or to reinterpret an attestation as a safety certificate.

## Per-requirement procedure inventory

| Requirement | Method and tier | Applicability | Baseline on the existing site | Observation and separately authorized stimulus | Pass criterion | Evidence fields |
|---|---|---|---|---|---|---|
| `ROOT-HARD-BOUNDS` | `first-packet`, tier 3 | `root-transport` | The existing owner's loaded rules (`pfctl -a <its anchor> -s nat` and `-s rules`); from a LAN client, the first request and reply through each existing redirect and one request just outside each end of its port range. | Packet capture on the LAN interface and the guest network for the same requests; `pfctl -a <owned anchor> -s nat` and `-s rules`; `pfctl -s Anchors` for the anchors of other owners. | Each owned rule names exactly the admitted interface, protocol, source scope and ports; first packets in range are translated and answered, those just outside are not; anchors and rules of other owners equal the baseline. | One record per transport profile whose strategy is neither `published-port` nor `guest-lan-alias`; `kind` `native-capture`. |
| `ANY-SOURCE-INGRESS` | `external-first-packet`, tier 3 | `any-source` | Whether each existing redirect answers a first request from a source outside the LAN prefix, sent through the forwarding router. | Packet capture on the LAN interface of the first request from outside the prefix and of its reply; `pfctl -a <owned anchor> -s nat` for the source of each rule. | The first packet from outside the prefix is redirected and answered to the same source; only the rules of profiles with an unrestricted source accept it. | One record per transport profile with `source_scope` `any`; a `first-packet` record does not count; `kind` `native-capture`. |
| `BOUNDED-IDENTITY` | `state-drain`, tier 3 | `bounded` | For a planned stop and separately authorized helper-loss/pool-reuse cases with flows in both directions, measure elapsed time until no rule and no state names the old address; retain the generation boundary and uncertainty. | `pfctl -a <owned anchor> -s nat` and `-s rules` and `pfctl -s state` filtered by the old guest address, once a second until both are empty; packet capture on the guest network for packets of the old flows. | For a planned stop, rules and states in both directions are gone before release. For unexpected loss, measure from loss or earliest observable generation change, retaining that distinction. No old flow reaches a reallocated non-target guest after invalidation. Compare the worst observed withdrawal with the declared bound and signed residual; a single fast sample proves no worst-case scheduling bound. | One record per transport profile of the `bounded` gate, after its signed `decisions.bounded` entry; `kind` `native-capture`. Keep the measured bound and signed residual in private evidence. This row cannot become fulfilled-verified: a bounded window never proves absolute identity safety. Current reporting does not ingest measured bounds; native qualification remains blocked. |
| `DISCOVERY-PUBLICATION` | `application-connect`, tier 5 | `exports` | From a LAN client, browse and resolve every exported type (`dns-sd -B`, `dns-sd -L`) for name, host and port, and read each TXT record as raw hexadecimal RDATA (`dns-sd -Q <instance> TXT IN`); connect each with its real client application (site-specific). | The same `dns-sd -B`, `dns-sd -L` and `dns-sd -Q` reads from a LAN client, and the guest's own announcement read the same way on the guest network; the workload's publication as the runtime CLI's inspect reports it; the client application's connection (site-specific). | Each exported record names the host and the port of its own workload's publication; its TXT RDATA from `dns-sd -Q` equals the guest's own byte for byte, apart from declared rewrites (the `dns-sd -L` display is not compared: it escapes bytes and shows an empty string as nothing); the real client connects through it. | One record per discovery selection of direction `export`; `kind` `owner-attestation`. |
| `DISCOVERY-IMPORT` | `cold-application-scan` or `receiver-change`, tier 5 | `imports` | A cold start of the consuming application (not a reload), and a receiver that changes its address or is new: which receivers its own scanner lists (site-specific), and after how long. | The same cold start or receiver change; the application's own device list (site-specific); `dns-sd -B` and `dns-sd -L` on the guest side for the projected records. | After a cold start every receiver of the baseline appears in the application's scanner under its projected name; a changed or new receiver is found and connected; a warm reload counts for nothing. | One record per discovery selection of direction `import`, with the method that was done; `kind` `owner-attestation`. |
| `DISCOVERY-LEASES` | `application-connect`, tier 5 | `discovery` | For each projected record, its interface, its source and how long it stays after its source goes away (`dns-sd -B` add and remove rows with times, while a source is switched off and on). | The same `dns-sd -B` and `dns-sd -L` rows with times on the projected side; the owner's report of each record's age; the application's connection to a live record (site-specific). | Each record is announced on the declared interface only and names its source; it leaves within the declared expiry after its source goes away, whether or not a scan ends, and returns with the source; the application connects to a live record. | One record per discovery selection; `kind` `native-capture`. |
| `CONSENT-IDENTITY` | `local-network-consent`, tier 3 | `discovery` | Which job identity holds Local Network consent (the program of the existing discovery owner's job through the service manager, `launchctl print gui/<uid>/<label>`, and its code signature, `codesign -dv`), and that its browse and registration work in that job. | From the real user LaunchAgent, not Terminal or SSH: the discovery owner's own browse and registration; the service manager (`launchctl print gui/<uid>/<label>`) for its program; the consent the system settings show for that identity. | Browse and registration succeed from the LaunchAgent with the identity that holds consent; after a change of code identity, consent is given again before the record is taken. | One record per discovery selection; `capture_context` must be `user-launchagent`; the host evidence needs a current `local_network_identity` fact; `kind` `native-capture`. |
| `UDP-FIRST-PACKET` | `first-packet`, tier 3 | `bounded-udp` | From a guest, the first outbound UDP request to a LAN responder and its first reply, captured on the LAN interface and the guest network, from a source port at each end of the admitted range and just outside it. | Packet capture on both sides for the same requests, with a responder that is not reached through the DNS redirect; `pfctl -a <owned anchor> -s nat` and `-s rules`. | The first request leaves with its source port and destination unchanged and the first reply reaches the guest on that port; ports outside the range are not translated by the owned rules. | One record per transport profile of the strategy `guest-udp-range-forward`; `kind` `native-capture`. |
| `DNS-CLIENT-IDENTITY` | `dns-client-identity`, tier 5 | `resolver` | Queries over UDP and TCP from two LAN clients, and the client address the resolver application logs for each (site-specific). | A DNS client on two LAN machines, over UDP and TCP; the resolver application's own query log (site-specific). | The resolver logs each client's own address on both transports; a configured native-publication fallback is reported as degraded identity, not as a pass. | `profile` `null` with the complete instance contract digest; `kind` `native-capture`. |
| `HEARD-AUDIO` | `heard-audio`, tier 5 | `media-audio` | Whether a person hears playback started from the application on each representative receiver; a path that never played audibly is recorded as such. | A coordinated person at each receiver; the application's own playback request (site-specific); packet capture of the return path where wanted. | The person confirms audible output on each representative receiver for the exact current policy and runtime; a playing state or a completed call counts for nothing. | One record per discovery selection with a return path; `capture_context` must be `host-person`; `kind` `owner-attestation`. |
| `MULTI-RECEIVER` | `port-budget`, tier 5 | `media-audio` | With the representative number of receivers playing at once: the guest's UDP sockets in use (site-specific), and whether every receiver plays. | `pfctl -s state` for the owned pair and a socket listing read inside the guest (site-specific), idle and with the receivers playing at once. | Every representative receiver plays at once, the ports in use stay inside the admitted range, and the range was not widened to get there. | One record per discovery selection with a return path; `kind` `native-capture`. |
| `BOOT-RECOVERY` | `unattended-reboot`, tier 4 | `all` | An unattended reboot of the existing site in an authorized window: the time from power-on to the first valid DNS answer at another machine, which workloads return, and whether a pause survives. | A DNS client on another machine asking once a second; the service manager (`launchctl print`) for the owner jobs; the runtime CLI's inventory; `pfctl -a <owned anchor> -s nat` and `-s rules`. | The first valid answer arrives within `decisions.unattended_recovery.max_dns_ready_seconds`; every enrolled workload permitted by current intent returns; deliberately held workloads stay stopped, and pause and holds set before reboot remain in force. | `profile` `null` with the complete instance contract digest; the report also needs FileVault observed or declared off, an accepted unattended recovery with its DNS-ready limit, exactly one tool with `starts_fleet` and at least one with `starts_runtime: true`; `kind` `native-capture`. |
| `RESTORE-REHEARSAL` | `restore-rehearsal`, tier 4 | `all` | The existing site's recovery material and its off-host copy, with the hash of every file. | A restore from the off-host copy in an authorized window or onto a scratch profile; the hashes of the restored files; then the service manager, the runtime CLI's inventory and `pfctl -s` for fresh readback. | Every restored file has its recorded hash, and the restored owners reach a fresh healthy readback without reusing stale state. | `profile` `null` with the complete instance contract digest; a reported absent `recovery_material` keeps the row `not-fulfilled`; `kind` `native-capture`. |
| `OWNER-ROLLBACK` | `restore-rehearsal`, tier 4 | `all` | The predecessor's release and instance pair with its hashes, and the current pause and holds. | A rehearsed owner-scoped rollback in an authorized window; the installed job through the service manager; the receipt and the intent, read only; `pfctl -s` for the root owner. | The pinned predecessor pair is installed with its exact bytes, the current pause and holds are kept rather than an older snapshot, and fresh readback is healthy. | `profile` `null` with the complete instance contract digest; `kind` `native-capture`. |
| `PORT-BUDGET` | `port-budget`, tier 3 | `bounded-udp` | The guest's UDP sockets in use (site-specific), idle and under representative load. | `pfctl -s state` for the owned pair and a socket listing read inside the guest (site-specific), idle and under representative load, each counted on its own. | Both counts come from independent reads, the peak stays inside the admitted range, and the range was not widened. | One record per transport profile of the strategy `guest-udp-range-forward`; `kind` `native-capture`. |

## Execution status and limits

No native procedure above was run by the October 9 repository review. The
`acceptance` pytest marker is reserved for future explicitly authorized hardware
harnesses; an empty set of marked tests is not acceptance coverage. Public CI
checks the inventory against the requirements registry and exercises simulated
failure paths and hosted macOS parsing. It does not send packets, create guests,
change consent, reload a production owner or play sound.

A measured failure stops the owner flip. Unknown provenance, incomplete output,
stale generations or a changed executable invalidate the measurement. Retain the
failed phase and current protective intent; do not retry mutation merely because
an administrator session is still alive. Use the existing [migration runbook](migration-runbook.md)
for scoped retries, rollback, all-service health and predecessor retirement.

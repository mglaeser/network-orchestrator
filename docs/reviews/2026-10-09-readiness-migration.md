# Readiness record: release and migration (R-O1 to R-O8)

This record belongs to a readiness check of the repository against what an
existing site does. It covers the findings R-O1 to R-O8: the release gate, the
platform, the root observer's trust in the runtime CLI, acceptance procedures,
supervision and the start of the vendor runtime. Each finding was checked at
`main` `de4cbb5` (release 0.4.2) against the code and the owner's documents:
the [closure record](2026-10-08-closure-and-qualification.md), the
[site-requirements review](2026-10-08-site-requirements-review.md), the
[proposal ledger](2026-10-08-proposal-ledger.json), the
[migration gates](../migration-readiness.md), [runbook](../migration-runbook.md),
[health checkpoints](../migration-health.md) and
[privilege-session design](../migration-privilege-session.md), the
[test tiers](../testing.md), the [site migration](../site-migration.md),
[deployment](../deployment.md), [Apple runtime](../apple-runtime.md),
[PF owner](../pf-owner.md) and [instance](../instances.md) guides, the
[requirements registry](../../src/netorch/requirements.py), the
[acceptance evidence schema](../../schemas/acceptance-evidence.schema.json) and
the [host report](../../src/netorch/host_report.py). No code, schema or guide
is changed. Every finding is a flag, with executable proof where a test can
express it, or a reference to the owner's own text.

[`tests/test_readiness_migration.py`](../../tests/test_readiness_migration.py)
holds two tests. `test_r_o4_every_requirement_of_tier_three_or_more_has_exactly_one_procedure_row`
passes. It reads the procedure table under R-O4, which must lie outside every
code fence and HTML comment, and requires exactly one row for each requirement
of minimum tier 3 or more in the registry and none for another; in each row the
registry's methods, tier and applicability; an evidence cell that states the
scope of a record, the capture context and a kind as the host report requires
them; and a measure cell that names one of the command classes listed above
the table. It does not judge the baselines and the pass criteria beyond their
being present. `test_r_o8_runtime_start_stops_and_holds_once_the_start_budget_is_spent`
is a strict expected failure: it asserts the change proposed under R-O8 and
fails today with an AssertionError that shows what the code does now, while a
set-up that does not hold fails it through `pytest.fail`. The first reads only
this record and the registry; the second runs the repository's code with the
fake tools of the existing tests. They prove nothing about a real host, and
neither carries the `acceptance` marker.

This record is one of four readiness records of 9 October 2026 that are read
as one set, all in this directory: `2026-10-09-readiness-discovery.md`
(findings `R-D`), `2026-10-09-readiness-udp-return.md` (`R-U`),
`2026-10-09-readiness-dns.md` (`R-N`) and this one (`R-O`). The prefix `R-`
keeps their identifiers apart from the review identifiers D1 to D8 of the
[review traceability](../review-traceability.md). The set adds to the closure
record's table "Remaining parity work and current safe behavior", which stays
authoritative for the current list of extraction gaps, and to the gates of the
migration readiness document. It replaces neither, records no acceptance and
opens no gate: the release stays read-only and its accepted platform matrix
stays empty. Where the owner's documents already record a finding, its entry
names his text and says what that text leaves out.

## R-O1: the release gate and the path to a qualified release (reference)

The owner records this in the closure record: its section "What can be closed
independently" ("The public mutation gate in `workflow_gate.py` still refuses
activation before reading mutation inputs, creating state or calling native
tools. No instance flag, environment variable, root invocation or green CI run
overrides it.") and step 7 of its "Subsequent installation qualification
checklist" ("Add qualified support only when the required evidence exists.").
On `main` the gate is `workflow_gate.require_mutation_qualified`, which refuses
every capability. Twenty-six public entry points end through it with status
78, under nine capability names: eleven in `netorch` (four `deploy`
operations, six authority commands and `reconcile --execute-user-owners`),
seven in `netorch.pf_owner`, three in `netorch.apple_runtime` (`start`,
`runtime-start` and an activating `request`), three in `netorch.bonjour_owner`
(`serve`, `publisher` and an activating `endpoint` request) and two in
`netorch.workloads`. `tests/test_workflow_gate.py` and the tests of the single
commands exercise them.

What it leaves out: the closure record does not list the gated entry points
(only the code and the tests do), and it does not say how a qualified release
would open the gate: as one release for every capability, or per capability
and owner in the runbook's order. The gate's docstring says only that "A later
qualified owner migration requires a separately reviewed release; there is no
flag or environment bypass."

## R-O2: the platform matrix and the candidate runtime (reference)

The owner records this in the closure record (step 5 of the "Repository release
closure checklist": "Preserve the limitations above and the empty qualified
platform matrix"; step 2 of the qualification checklist: "pin the platform. A
runtime upgrade or container recreation has its own effects and acceptance; it
is not concealed in an owner refactor."), in the runbook ("Scope and
invariant": "Runtime upgrades, kernel changes, application upgrades, new
helpers/automations and new receiver pairing are not bundled into an extraction
transaction"; phase B: "Keep the platform fixed once its baseline is accepted
for extraction.") and in the instance guide ("Installed legacy versions,
including 1.2.0, remain read-only and unqualified."). On `main`
`platform_contract.ACCEPTED_PLATFORMS` is empty, and `PLATFORM-SUPPORT` is
`not-fulfilled` on every host whose macOS version, build and runtime version
are not the one candidate (macOS 27.0.1 build 26A434 with runtime 1.5.0). The
runtime reader accepts 1.2.0, 1.4.1 and 1.5.0.

What it leaves out: a site may run an older runtime than the candidate, one the
reader accepts, so that every read-only command works there while the platform
row stays `not-fulfilled`; a macOS update changes the build in the same way.
The texts do not say which comes first for such a site: a runtime (and system)
change to the candidate in its own window, with its own baseline and
application re-acceptance, before any extraction; or a reviewed release that
names the site's own platform. Either way the runbook keeps that change out of
an extraction transaction.

## R-O3: the root observer refuses a runtime CLI that a user owns (flag, guidance)

**What an existing site does.** Its runtime can come from a per-user package
manager. The CLI, its install root and the network helper then belong to the
account that installed them, and the site's own tools, which run as that
account, use them as they are.

**What this repository does.** The root forwarding owner reads the runtime
through `pf_owner._runtime_observer`, which first calls
`protected_native_code` on the enrolled `executable`, every network's
`helper_executable` and its own `observer_child.py`, with no `uid`, so the
required owner is root (`owner = 0 if uid is None else uid`). Within one
eight-second deadline, `_capture_code_file` and `protected_ancestors` require
for each path:

- every directory from `/` down to the file's directory, and down to the
  resolved target's directory where the path is a symbolic link: a directory,
  not a symbolic link, owned by root and closed to group and other writers
  (`not stat.S_ISDIR(info.st_mode) or item.is_symlink() or info.st_uid != uid
  or info.st_mode & 0o022` refuses with "protected ancestor is writable or has
  another owner");
- a symbolic link owned by root with one link;
- a resolved target that is a regular file owned by root, closed to group and
  other writers and with one link (`not stat.S_ISREG(info.st_mode) or
  info.st_uid != owner or info.st_mode & 0o022 or info.st_nlink != 1` refuses
  with "privileged code is replaceable").

`_verify_code_capture` then has `_batch_code_acls` require that no captured
path carries an access-control list (`/bin/ls -lde` prints exactly one line for
each path), and reads the metadata of every captured path again: any change
refuses.

The PF owner guide states this ("Data and executable boundaries"): "The native
Container CLI and each observed network-helper executable must also be
administrator-owned regular single-link files, under protected physical
ancestors, with no group/other write permission or ACL grants. [...] Dropping
native probes to the runtime user does not make a user-replaceable observer
trustworthy. The framework does not install these vendor binaries; their
trusted installation is a prerequisite." The refusal is an `UnsafeState`, a
`RuntimeError`: `reconcile` records every service as unknown with the reason
`unavailable`, withdraws every owned rule, and `keep-host-paths` keeps none,
because that reason is not `timed-out`. The user's own runtime reader runs the
same CLI without an ownership check, so `netorch-host` and the user owners work
on such a host; only the root owner cannot read it. The read-only preflight
already reports a fact `runtime_install_method` (`macos_preflight`), which
recognises one per-user package manager's standard location, but no
requirement row reads it. The deployment guide says it in general terms only:
"Root code, policy, admissions and ancestors must be administrator-owned and
protected against user replacement" and "Install reviewed managed tool
artifacts first". It names neither the CLI and helpers that root runs nor what
a host whose runtime was installed per user has to change.

**Evidence.** No new test. The requirement is a documented security position,
not a defect: an expected failure would have to assert that root runs code a
user can replace. Existing tests show it on `main`:
`test_native_observer_guard_checks_links_targets_and_metadata_before_use`,
`test_batched_ancestor_capture_still_rejects_writable_or_foreign_ancestors`
and `test_root_runtime_observer_must_prove_native_binaries_before_reading` in
`tests/test_pf_owner.py`, and `test_an_observer_that_refuses_to_run_retires_every_rule`
in `tests/test_pf_host_paths_observer_reasons.py` (a CLI in a directory a user
can write: the pass withdraws every rule and no profile is ready):
`pytest tests/test_pf_owner.py tests/test_pf_host_paths_observer_reasons.py -k "native_observer_guard or foreign_ancestors or must_prove_native or refuses_to_run"`.

**Proposed change.** Guidance only; no setting, and the refusal stays. Add a
paragraph to the deployment guide, section "1. Inventory and choose authority",
that names the requirement above for the runtime CLI and every network helper
and says what a host whose runtime came from a per-user package manager does
before its first root step. Its read-only check is the owner, mode and
access-control list of each of those paths and of every directory above them
(`ls -lde`), and the preflight's `runtime_install_method` where it recognises
the install. Then:

1. Install the runtime from an administrator-owned installation, for example
   the vendor's own installer, at the version the instance pins, so that the
   CLI, every network helper and every directory above them meet the rules
   above.
2. Point `executable` and every `helper_executable` of the runtime settings and
   of the root owner's `observer` at it, enroll again and move every caller of
   the old path (the site's starter, supervisor and scripts) in the same
   window. With `runtime_start` declared, the launch file names the program, so
   the first start after the move is an operator's own.
3. Treat it as a runtime change: its own window, planned withdrawal before the
   stop, a new baseline and application re-acceptance, outside every
   extraction transaction, as the runbook requires.

**Decision needed.** Whether the paragraph belongs in the deployment guide or
in the inventory of the site migration guide ("record exact runtime/Socktainer
versions and install methods"); whether the report should name the conflict
where `runtime_install_method` reports a per-user install; and whether a site
may combine this reinstall with the change to the candidate runtime of R-O2,
since both are runtime changes outside an extraction.

**Closing acceptance.** `PLATFORM-SUPPORT`, method `root-runtime-observer`,
tier 2: on the real host the root LaunchDaemon reads the runtime through the
enrolled user's bootstrap with the reinstalled CLI and helpers. It passes when
the complete inventory and guest reads succeed from the `root-launchdaemon`
context with the CLI run unprivileged, and the root owner's pass records no
service as `unavailable`. No record counts for this row while
`platform_contract.ACCEPTED_PLATFORMS` is empty: `host_report.build_report`
admits a `PLATFORM-SUPPORT` record only where the matrix lists the instance's
platform (`requirement.id != "PLATFORM-SUPPORT" or listed`). Until a release
lists it, the measurement is evidence in the private history, and the row
stays at best `unverified`.

## R-O4: acceptance procedures for tiers 3 to 5 (flag)

**What an existing site does.** Its existing owners carry its networking
today, and it has no baseline per requirement yet. A measurement after an owner
moves can show "unchanged" or "changed as declared" only against the same
measurement, taken first on those owners.

**What this repository does.** The registry names a method and a minimum tier
for each requirement; 15 of its 43 requirements have a minimum tier of 3 or
more. The acceptance evidence schema records the identity and the result of an
acceptance, not what was measured. The test tiers list what evidence at tiers 3
to 5 "can include", and the migration gates and runbook say what must be
proven and in which order. None of them states, per requirement, the read-only
commands, the baseline and the pass criterion. The pytest marker `acceptance`
is declared in `pyproject.toml` ("explicitly authorized hardware acceptance;
never part of public CI") and deselected by the complete check
(`-m 'not acceptance'`); no test carries it.

**Evidence.** `test_r_o4_every_requirement_of_tier_three_or_more_has_exactly_one_procedure_row`
passes: `pytest tests/test_readiness_migration.py -k r_o4`. It checks what the
introduction lists and nothing more; in particular it does not judge the
baselines and the pass criteria. No strict expected failure: a procedure is a
document, not behavior of the code.

**Proposed change.** Adopt the procedures below in the owner's documents,
with the coverage test. A baseline is the same measurement, taken with the
existing owners before the site's first owner moves, and kept, whatever its
result, in the private evidence history, as the migration gates require ("The
original baseline and all unsuccessful attempts remain part of the private
evidence history"). The acceptance evidence schema cannot carry it: the schema
is closed and has no member for a measured value or for a reference to a
capture, so a record in it states a result and no more. Measured values and
captures therefore live as private artifacts in the private evidence history,
each kept with its SHA-256, and that history, not the record, ties a record to
them. Binding them to a record would need a new member of the schema, for
example a list of artifact hashes, in a version 2 of it, which the current
report does not count. A baseline stays out of the instance's `acceptance`
list in any case, because it describes the existing owners and not the
candidate. Every command is read-only; what changes the host (a reboot, a
planned stop, a restore, a cold start) runs only in its authorized window.

How the report counts a record (`host_report.build_report` and `_acceptance`
at `de4cbb5`). A record carries the schema's required fields: `requirement`,
`profile`, `method`, `tier` (at least the minimum), `observed_at`,
`macos_build`, `runtime_version`, `framework_sha256`, `contract_sha256`,
`signed_by`, `instance_schema_version`, `schema_version`, `kind`,
`capture_context`, `result` and `source_versions` (the versions of the tools
that measured; the report does not compare them). It counts only with `result`
`passed`, a `kind` other than `synthetic`, a `capture_context` other than
`offline-fixture`, the host's current macOS build and runtime version, the
pinned framework artifact, and an entry in the instance's `acceptance` list
with the same values and the evidence file's hash. Other rules decide the row
whatever its record says:

- Host evidence whose `source` is `synthetic` voids every record.
- A reported absent or false `recovery_material` keeps `RESTORE-REHEARSAL`
  `not-fulfilled`.
- A recorded deviation decides after the record: one with a blank statement or
  without a current acceptance gives `not-fulfilled`; an accepted one gives
  `not-fulfilled` for a mandatory proving gate such as `BOUNDED-IDENTITY` and
  `accepted-residual` otherwise, but never lifts a row that is `not-fulfilled`
  for another reason.
- A `PLATFORM-SUPPORT` record counts only where
  `platform_contract.ACCEPTED_PLATFORMS` lists the platform.
- Three rows never count a record (`src/netorch/host_report.py`, lines 904 to
  914):

```python
            if (
                requirement.id
                not in {
                    "BOUNDED-IDENTITY",
                    "IMPORT-VISIBILITY",
                    "LIFECYCLE-WRITERS",
                }
                and (requirement.id != "PLATFORM-SUPPORT" or listed)
                and status != "not-fulfilled"
                and _acceptance(instance, requirement, evidence, now, evidence_directory)
            ):
```

`BOUNDED-IDENTITY` is one of them, and nothing can hold its demonstrated bound
either: the report assesses each bounded profile with `assess_bounded_safety`
without the read, withdrawal and scheduling bounds (lines 735 to 743 and 956
to 964), so the assessment's `withdrawal_bound_seconds` is always `null` and
its reasons always include `withdrawal-bound-unestablished`. A record for that
row is evidence in the private history; closing it needs a release that admits
a demonstrated bound and counts the row. The same holds for
`LIFECYCLE-WRITERS`, named under R-O7 and R-O8, whose status comes only from
the signed lifecycle residual.

The table names each measurement's command class: packet capture, `pfctl` (its
read-only listings), `dns-sd`, a DNS client, the service manager
(`launchctl print`), the runtime CLI (its read-only inventory and inspect), or
a person. A form marked (site-specific) is not an established tool but a
site's own choice, fixed with the baseline: an application's own device list,
log, request or connection, or a socket listing read inside a guest. The last
column says what differs per row: which profiles need a record of their own
(one record per transport profile or per discovery selection is bound by
`contract_sha256` to that profile's resolved digest; an instance-wide record
has `profile` `null` and the complete instance contract digest), a capture
context the report requires, and the `kind` that fits.

| Requirement | Method and tier | Applicability | Baseline on the existing site | Measure (read-only command class) | Pass criterion | Evidence fields |
|---|---|---|---|---|---|---|
| `ROOT-HARD-BOUNDS` | `first-packet`, tier 3 | `root-transport` | The existing owner's loaded rules (`pfctl -a <its anchor> -s nat` and `-s rules`); from a LAN client, the first request and reply through each existing redirect and one request just outside each end of its port range. | Packet capture on the LAN interface and the guest network for the same requests; `pfctl -a <owned anchor> -s nat` and `-s rules`; `pfctl -s Anchors` for the anchors of other owners. | Each owned rule names exactly the admitted interface, protocol, source scope and ports; first packets in range are translated and answered, those just outside are not; anchors and rules of other owners equal the baseline. | One record per transport profile whose strategy is neither `published-port` nor `guest-lan-alias`; `kind` `native-capture`. |
| `ANY-SOURCE-INGRESS` | `external-first-packet`, tier 3 | `any-source` | Whether each existing redirect answers a first request from a source outside the LAN prefix, sent through the forwarding router. | Packet capture on the LAN interface of the first request from outside the prefix and of its reply; `pfctl -a <owned anchor> -s nat` for the source of each rule. | The first packet from outside the prefix is redirected and answered to the same source; only the rules of profiles with an unrestricted source accept it. | One record per transport profile with `source_scope` `any`; a `first-packet` record does not count; `kind` `native-capture`. |
| `BOUNDED-IDENTITY` | `state-drain`, tier 3 | `bounded` | For a planned stop of a guest with flows in both directions, the existing owner's time from the stop request until no rule and no state names the old address, read once a second. | `pfctl -a <owned anchor> -s nat` and `-s rules` and `pfctl -s state` filtered by the old guest address, once a second until both are empty; packet capture on the guest network for packets of the old flows. | Rules and states of the old address in both directions are gone before the guest stops, and no packet of an old flow reaches a guest that reuses the address. The time from the stop request until both are empty is the measured bound, kept with its capture; whether it fits the profile's signed decision is the owner's judgement, not part of the measurement. | One record per transport profile of the `bounded` gate, after its signed `decisions.bounded` entry; `kind` `native-capture`. The report never counts this row and cannot hold the measured bound (see above): closing needs a release that admits a demonstrated bound. |
| `DISCOVERY-PUBLICATION` | `application-connect`, tier 5 | `exports` | From a LAN client, browse and resolve every exported type (`dns-sd -B`, `dns-sd -L`) for name, host and port, and read each TXT record as raw hexadecimal RDATA (`dns-sd -Q <instance> TXT IN`); connect each with its real client application (site-specific). | The same `dns-sd -B`, `dns-sd -L` and `dns-sd -Q` reads from a LAN client, and the guest's own announcement read the same way on the guest network; the workload's publication as the runtime CLI's inspect reports it; the client application's connection (site-specific). | Each exported record names the host and the port of its own workload's publication; its TXT RDATA from `dns-sd -Q` equals the guest's own byte for byte, apart from declared rewrites (the `dns-sd -L` display is not compared: it escapes bytes and shows an empty string as nothing); the real client connects through it. | One record per discovery selection of direction `export`; `kind` `owner-attestation`. |
| `DISCOVERY-IMPORT` | `cold-application-scan` or `receiver-change`, tier 5 | `imports` | A cold start of the consuming application (not a reload), and a receiver that changes its address or is new: which receivers its own scanner lists (site-specific), and after how long. | The same cold start or receiver change; the application's own device list (site-specific); `dns-sd -B` and `dns-sd -L` on the guest side for the projected records. | After a cold start every receiver of the baseline appears in the application's scanner under its projected name; a changed or new receiver is found and connected; a warm reload counts for nothing. | One record per discovery selection of direction `import`, with the method that was done; `kind` `owner-attestation`. |
| `DISCOVERY-LEASES` | `application-connect`, tier 5 | `discovery` | For each projected record, its interface, its source and how long it stays after its source goes away (`dns-sd -B` add and remove rows with times, while a source is switched off and on). | The same `dns-sd -B` and `dns-sd -L` rows with times on the projected side; the owner's report of each record's age; the application's connection to a live record (site-specific). | Each record is announced on the declared interface only and names its source; it leaves within the declared expiry after its source goes away, whether or not a scan ends, and returns with the source; the application connects to a live record. | One record per discovery selection; `kind` `native-capture`. |
| `CONSENT-IDENTITY` | `local-network-consent`, tier 3 | `discovery` | Which job identity holds Local Network consent (the program of the existing discovery owner's job through the service manager, `launchctl print gui/<uid>/<label>`, and its code signature, `codesign -dv`), and that its browse and registration work in that job. | From the real user LaunchAgent, not Terminal or SSH: the discovery owner's own browse and registration; the service manager (`launchctl print gui/<uid>/<label>`) for its program; the consent the system settings show for that identity. | Browse and registration succeed from the LaunchAgent with the identity that holds consent; after a change of code identity, consent is given again before the record is taken. | One record per discovery selection; `capture_context` must be `user-launchagent`; the host evidence needs a current `local_network_identity` fact; `kind` `native-capture`. |
| `UDP-FIRST-PACKET` | `first-packet`, tier 3 | `bounded-udp` | From a guest, the first outbound UDP request to a LAN responder and its first reply, captured on the LAN interface and the guest network, from a source port at each end of the admitted range and just outside it. | Packet capture on both sides for the same requests, with a responder that is not reached through the DNS redirect; `pfctl -a <owned anchor> -s nat` and `-s rules`. | The first request leaves with its source port and destination unchanged and the first reply reaches the guest on that port; ports outside the range are not translated by the owned rules. | One record per transport profile of the strategy `guest-udp-range-forward`; `kind` `native-capture`. |
| `DNS-CLIENT-IDENTITY` | `dns-client-identity`, tier 5 | `resolver` | Queries over UDP and TCP from two LAN clients, and the client address the resolver application logs for each (site-specific). | A DNS client on two LAN machines, over UDP and TCP; the resolver application's own query log (site-specific). | The resolver logs each client's own address on both transports; a configured native-publication fallback is reported as degraded identity, not as a pass. | `profile` `null` with the complete instance contract digest; `kind` `native-capture`. |
| `HEARD-AUDIO` | `heard-audio`, tier 5 | `media-audio` | Whether a person hears playback started from the application on each representative receiver; a path that never played audibly is recorded as such. | A coordinated person at each receiver; the application's own playback request (site-specific); packet capture of the return path where wanted. | The person confirms audible output on each representative receiver for the exact current policy and runtime; a playing state or a completed call counts for nothing. | One record per discovery selection with a return path; `capture_context` must be `host-person`; `kind` `owner-attestation`. |
| `MULTI-RECEIVER` | `port-budget`, tier 5 | `media-audio` | With the representative number of receivers playing at once: the guest's UDP sockets in use (site-specific), and whether every receiver plays. | `pfctl -s state` for the owned pair and a socket listing read inside the guest (site-specific), idle and with the receivers playing at once. | Every representative receiver plays at once, the ports in use stay inside the admitted range, and the range was not widened to get there. | One record per discovery selection with a return path; `kind` `native-capture`. |
| `BOOT-RECOVERY` | `unattended-reboot`, tier 4 | `all` | An unattended reboot of the existing site in an authorized window: the time from power-on to the first valid DNS answer at another machine, which workloads return, and whether a pause survives. | A DNS client on another machine asking once a second; the service manager (`launchctl print`) for the owner jobs; the runtime CLI's inventory; `pfctl -a <owned anchor> -s nat` and `-s rules`. | The first valid answer arrives within `decisions.unattended_recovery.max_dns_ready_seconds`; every enrolled workload runs; a pause and holds set before the reboot are still in force. | `profile` `null` with the complete instance contract digest; the report also needs FileVault observed or declared off, an accepted unattended recovery with its DNS-ready limit, exactly one tool with `starts_fleet` and at least one with `starts_runtime: true`; `kind` `native-capture`. |
| `RESTORE-REHEARSAL` | `restore-rehearsal`, tier 4 | `all` | The existing site's recovery material and its off-host copy, with the hash of every file. | A restore from the off-host copy in an authorized window or onto a scratch profile; the hashes of the restored files; then the service manager, the runtime CLI's inventory and `pfctl -s` for fresh readback. | Every restored file has its recorded hash, and the restored owners reach a fresh healthy readback without reusing stale state. | `profile` `null` with the complete instance contract digest; a reported absent `recovery_material` keeps the row `not-fulfilled`; `kind` `native-capture`. |
| `OWNER-ROLLBACK` | `restore-rehearsal`, tier 4 | `all` | The predecessor's release and instance pair with its hashes, and the current pause and holds. | A rehearsed owner-scoped rollback in an authorized window; the installed job through the service manager; the receipt and the intent, read only; `pfctl -s` for the root owner. | The pinned predecessor pair is installed with its exact bytes, the current pause and holds are kept rather than an older snapshot, and fresh readback is healthy. | `profile` `null` with the complete instance contract digest; `kind` `native-capture`. |
| `PORT-BUDGET` | `port-budget`, tier 3 | `bounded-udp` | The guest's UDP sockets in use (site-specific), idle and under representative load. | `pfctl -s state` for the owned pair and a socket listing read inside the guest (site-specific), idle and under representative load, each counted on its own. | Both counts come from independent reads, the peak stays inside the admitted range, and the range was not widened. | One record per transport profile of the strategy `guest-udp-range-forward`; `kind` `native-capture`. |

**Decision needed.** Where the procedures live (under tiers 3 to 5 of the test
tiers, or beside the gates of the migration readiness document); whether the
`acceptance` marker gets tests, for example offline evaluators that check a
saved capture against a row's pass criterion, or is documented as unused;
whether a version 2 of the acceptance evidence schema binds captures and
measured values by hash; and which pass criteria compare with the baseline
("unchanged") and which are absolute.

**Closing acceptance.** Each row above is its own closing acceptance, within
the counting rules above. The finding closes when the owner has adopted the
procedures with the coverage test and an existing site has its baseline for
every applicable row.

## R-O5: instance values held in programs (reference)

The owner records this in the closure record, row "Source and installed-input
parity" of "Remaining parity work and current safe behavior" ("An inventoried
executable is not proof that all embedded values were extracted"; work:
"account for embedded constants"), and in the site migration guide, step 4 of
"One author, one owner flip": "A program is hashed and searched, never
rendered: one that still holds an address, name or path of the instance blocks
its owner until the value lives in a literal file that the program reads." The
legacy import guide, section "Programs", adds that the search is a tripwire.

What it leaves out: moving a value out of a running program changes the
predecessor itself, before its owner can flip. The texts do not say whether
that edit is a transaction of its own, with the runbook's pre and post
checkpoints and a rollback to the unedited program, or part of the flip, which
the site migration guide wants "with no intentional input difference". We would
make it a transaction of its own; the decision is the owner's.

## R-O6: no in-guest ensure (reference)

The owner records this in the closure record, row "Supervisor behavior" ("no
separate in-guest component repair"; work: "Preserve the existing supervisor
until its actual launcher, status and component-repair behavior are
extracted"), in item 6 of the site-requirements review, and in the instance
guide: the retained supervisor "starts on status 42 only, has no second status
and no in-guest ensure". `instance.retained_supervision_gaps` reports every
component with `recovery: supervisor-ensure` and the `component_exit_code` that
goes with it.

What it leaves out: what an ensure would run. A component declares only `id`,
`health` and `recovery`, and the instance is data only, with no command. The
only command the retained code runs inside a guest is one fixed read of the
guest's local port range. An extraction therefore needs a reviewed, fixed
operation per component; instance text cannot supply it.

## R-O7: no start hook for a workload its manager starts (flag)

**What an existing site does.** Some workloads are started through their
manager's own step, for example the up command of a compose-style manager,
which also applies the manager's configuration before it starts the container.

**What this repository does.** Recovery of a workload issues the vendor's bare
start of the existing definition: `apple_runtime.recover_service` calls
`Reader(settings, runner).native(["start", contract.name], timeout=bound)`.
The instance vocabulary cannot say that a workload is started otherwise.
`workloads[].recovery` is `manual-only`, `proven-stopped` or `disabled`.
`lifecycle_tools[]` can declare the manager (kind `application-manager`, with
`container_api_access: true`), but no member ties a workload to the tool whose
step starts it, and the closed schema refuses any such member.
`retained_supervision_gaps` looks at the start statuses, `supervisor-ensure`
components and deadlines, and at nothing about how a workload is started. The
gap is therefore silent: such an instance validates, its list of supervision
gaps is empty, and `netorch-host supervision-gaps`, which prints that list,
reports nothing for it.

**Evidence.** No test, because there is no seam: the vocabulary has no
declaration, so a test of the proposed gap would have to invent the member's
spelling, and a strict expected failure built on an invented spelling would
never turn into a pass. The facts above were checked on `main` with the
synthetic `examples/instance.json` and one added tool of kind
`application-manager` with `container_api_access: true`: the instance
validates and `retained_supervision_gaps` returns no gap. A workload member
that names that tool, or a `recovery` value for it, is refused as a violation
of the closed schema.

**Proposed change.**

1. In `schemas/instance.schema.json` and `instance_model.Workload`, an optional
   workload member, for example `starter`, naming the id of the lifecycle tool
   whose own step starts that workload. Left out, it means the vendor's start,
   which is today's meaning, and it stays out of the canonical form, so
   existing instances keep their bytes and digests.
2. `retained_supervision_gaps` reports `/workloads/<index>/starter` wherever it
   names a tool whose kind is not `vendor-cli`, so that `supervision-gaps` exits 1
   and that workload's transaction stays blocked, as the runbook says for
   functionality "the retained framework cannot yet express".
3. The extraction itself stays as the closure record's "Supervisor behavior"
   row describes it: the manager remains that workload's starter until its step
   is extracted. The retained recovery does not run a manager's step, because
   that step can recreate or reconfigure a container, and recovery "never
   recreates running/unknown definitions" (test tiers).

**Decision needed.** Whether to add the member (a change of the instance
schema, with the version decision `CONTRIBUTING.md` asks for) or to record such
workloads as `recovery: manual-only` with a signed lifecycle residual; and
whether a later release should ever start a workload through its manager's
step.

**Closing acceptance.** `LIFECYCLE-WRITERS`, method `process-inventory`, tier
2: on the real host, the process inventory during a boot and during a recovery
shows exactly one starter per workload, the declared one. The report counts no
record for this row today (see the counting rules under R-O4: its status comes
only from the signed lifecycle residual, at best `accepted-residual`), so the
inventory is evidence in the private history, and closing needs a release that
counts the row. `BOOT-RECOVERY`, method `unattended-reboot`, tier 4: after an
unattended reboot each such workload runs with its contract digest unchanged.

## R-O8: no attempt budget for the start of the vendor runtime (flag)

**What an existing site does.** The readiness check records nothing site
specific for this finding. It concerns a bound that this repository's own
declaration lacks; how an existing site bounds its runtime starts, we do not
know.

**What this repository does.** `runtime-start`
(`apple_runtime.start_runtime`, proposal #92) makes one vendor call on every
firing and has no budget of its own. The restart budget (proposal #91) is
consulted only by workload recovery (`recover_service` calls `_spend_start`),
which counts per service; the Apple runtime guide, section "Restart budget":
"Only starts that recovery issues are counted". A runtime monitor may set
`recovery_repeat_cycles`, rendered as `repeat every N cycles`, and the
deployment guide says that "The rule has no attempt budget". While the runtime
cannot come up, every N cycles one more vendor start runs. Each holds the user
operation lock for "about 44 seconds at most with the default bound", so every
other command that takes that lock waits and can end busy, and on a host
without the vendor's base file-system image each start tries to download it.
A separate change of this round corrects the deployment guide's paragraph on
the budget: it counts workload starts only, and `runtime-start` does not read
it. That change pins the statement with
`tests/test_runtime_start_budget_scope.py::test_runtime_start_does_not_spend_the_restart_budget`.

**Evidence.** `test_r_o8_runtime_start_stops_and_holds_once_the_start_budget_is_spent`:
`pytest tests/test_readiness_migration.py -k r_o8 --runxfail`. The test
declares `runtime_start` with the proposed member `start_budget` (3 starts in
600 seconds). Today's loader refuses that member as one the closed
`runtime_start` object does not know; on exactly that refusal, and only where
the same settings without the member load, the test goes on without it, and
any other refusal fails it as a broken set-up. The vendor's start fails and
leaves no job loaded, and the supervisor's rule fires whenever the probe
answers 42. Today the test fails with "R-O8 today: runtime-start issued 4
vendor starts within one window of 600 seconds for a start budget of 3; the
settings loader does not know start_budget, so nothing bounds the start". With
a throwaway prototype of the change below, made outside this tree with that
member, the test passed, and its strict marker reported that pass as a failure
of the suite, as intended.

**Proposed change.** A new optional member of `fleet_start.runtime_start` in
the runtime settings, for example `start_budget`, with the shape and bounds of
`restart_budget`: `starts` from 1 to 10 and `window_seconds` from 60 to 86400,
both required, the object closed. Left out, nothing changes: the key stays out
of the canonical form, so settings without it keep their bytes and digests, and
an explicit `null` is refused. Like `restart_budget`, it needs the durable
intent in the state directory. Reusing `restart_budget` is not proposed: the
corrected deployment guide says that it counts workload starts only, so
reusing it would change what unchanged settings do, which this round leaves to
an explicit setting.

In `apple_runtime.start_runtime`, under the operation lock, after the two reads
and before the vendor call (where `recover_service` calls `_spend_start`):
where `start_budget` is stated, count each vendor call that `runtime-start`
issues in a record of its own in the state directory, for example
`runtime-starts.json` with the closed shape of `recovery-starts.json` and one
list, written before the call. A record of its own keeps the two apart:
workload recovery rewrites `recovery-starts.json` with the enrolled services
only, so a runtime entry there would be dropped by the next workload start, and
under a key outside the service pattern it would be content that recovery does
not know, which holds the workload being recovered. Once the budget is spent:
no vendor call, a durable inhibition that `runtime-probe` honours so that it
answers 69 and the rule stops matching, exit status 69, and a release by the
operator that clears the inhibition and the record. The brakes of the workload
budget apply unchanged: a record that cannot be read starts nothing, a record
that cannot be written starts nothing, a clock that gives no usable time
counts as a spent budget. This reuses the record and the hold of the restart
budget as mechanisms, not literally: a hold on one service does not keep the
runtime down, which the Apple runtime guide states ("A hold on one enrolled
service does not, since the runtime serves every workload") and
`test_a_hold_on_one_workload_does_not_keep_the_runtime_down` proves.

The same change updates the deployment guide's sentences as the separate change
corrects them, and the Apple runtime guide's sections "Starting the vendor
runtime" and "Restart budget"; it replaces the pinned test
`test_runtime_start_does_not_spend_the_restart_budget` with one that pins both
statements, that `restart_budget` still counts workload starts only and that
`start_budget` bounds `runtime-start`; and it removes the strict marker of this
record's test.

**Decision needed.**

1. The member's name and place. The test encodes `start_budget` inside
   `runtime_start`; another spelling changes the test's helper in the same
   change.
2. The form of the inhibition: a holder suspension, for example with the
   operation `runtime-restart-budget` and the holder `supervisor`, which every
   release that knows suspensions reads, but which inhibits every owner that
   reads this intent (a stopped runtime already stops its workloads); or a new
   member of the intent, a format change that older releases read as damaged,
   as they did with holds.
3. Whether the `system status` activation of a loaded idle job counts.

**Closing acceptance.** `LIFECYCLE-WRITERS`, method `process-inventory`, tier
2, on a scratch profile in an authorized window where the vendor's start is
made to fail; a reboot is not part of it. It passes when the service manager
and the process inventory show exactly `starts` vendor starts within the
window and none after them, the probe answers 69, the rule stops firing, the
intent shows the inhibition, and the operator's release gives a whole budget
again. The report counts no record for this row today (see the counting rules
under R-O4), so the record is evidence in the private history; closing needs a
release that counts the row.

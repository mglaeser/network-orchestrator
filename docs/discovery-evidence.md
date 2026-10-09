# Discovery evidence and remaining qualification

The discovery test suite distinguishes three kinds of evidence. Synthetic
native-format cases describe the parser and lifecycle contract, including
malformed inputs and races. Sanitized native recordings establish that specific
observed CLI output forms are understood. Production acceptance establishes
behavior in the actual deployment context. Passing the first two never grants
the third or enables a blocked migration.

## Recorded corpus

`tests/recordings/discovery/` contains 21 bounded, read-only native `dns-sd`
captures taken on 2026-10-09 using macOS 27.0.1 (26A434), ARM64, in an interactive
user context. The CLI did not expose a separately captured tool version, so
`tool_version` is null. The OS/build identifies the observed environment, not
an inferred source-code revision.

The corpus contains one complete captured browse for each of `_airplay._tcp`,
`_raop._tcp` and `_hap._tcp`, and SRV, IPv4 and raw TXT reads for two selected
instances of each type. A two-second browse is an observation window, not proof
of a complete LAN inventory. Separate commands are point-in-time reads and do
not make a transactional discovery snapshot.

Each closed JSON envelope records the capture context, original stream hashes,
explicit transformations and limitations, plus hashes of the sanitized streams.
The source hashes identify the private capture used for review; they do not
authenticate a public fixture independently. No original private capture is
included. Public fixtures consistently replace instance names, hostnames and
addresses; opaque TXT identifiers, MAC-like values and keys are neutralized.
Protocol/model/version fields, timestamps, flags, table headings, row order and
ports remain observed values. TXT lengths and hexadecimal output are rebuilt
where substitutions change bytes. Neutral TXT identity fields cannot test
pairing, identity uniqueness or authentication.

`tests/test_discovery_recorded_evidence.py` checks:

- Every row in the three captured browse outputs and refusal of an undersized
  record limit; Unicode and escaped multiword labels remain significant.
- Six complete SRV/address/raw-TXT parse paths and byte-preserving registration
  argument rendering, without starting a registration.
- The bounded scanner's complete command sequence using a deliberately reduced
  browse containing just the two endpoints whose resolves were captured. This
  reduction is explicitly a test transformation, not another native capture.
- Import association through matching AirPlay hostname **and** IPv4, including
  refusal to import the RAOP-only sample without a captured AirPlay anchor.
- Wrong-interface and malformed trailing callback rejection. These negative
  variants are generated from recordings and are not claimed as observed output.

The fixtures are inert data. `tests.recorded` checks the envelope and payload
hashes without executing commands. Tests use injected runners; public CI never
contacts the captured LAN.

## Boundary regressions

`tests/test_discovery_evidence_audit.py` adds independent negative cases for
selector cleanup on rejected registration arguments and non-OS spawn failures,
positive integer heartbeat PID validation, and canonical JSON Pointer array
indexes in literal policy derivation. Resource tests use actual local selectors
and a substituted process constructor; they do not invoke Bonjour.

Heartbeat health checks structure and freshness. It does not prove that a PID
still exists, that launchd consent is sufficient, or that any client can use a
projected service. A scanner pass longer than the heartbeat freshness threshold
can report unhealthy while a bounded read is still running; a health failure
never authorizes a container restart. Similarly, the computed pass budget is a
configured allowance, not a guarantee against OS scheduling or filesystem stalls.
The publisher independently enforces source lease expiry.

## Still required before migration

The recorded reads do **not** qualify the following:

- `dns-sd` running under the intended launchd user job, including Local Network
  consent, interface identity changes, sleep/wake and daemon recovery.
- Registration callbacks, duplicate-name behavior, clean withdrawal, native
  expiry, overlap renewal and parent/child termination in that context.
- Real guest-interface export, alias reread behavior, discovery loop exclusion
  between actual interfaces, or application URLs that name another guest.
- HA's shared Zeroconf scanner and native Apple TV integration across reload,
  address change and an approved restart; additional HomePods/Apple TVs.
- UDP/audio/video return traffic, audible playback and every dashboard service's
  health after each migration step.
- Measured pass duration versus configured record leases and retained-miss
  allowance at the site's observed device count.

These remain the explicit gates in [native qualification](native-qualification.md)
and the [site migration plan](site-migration.md). No supported-host qualification
record, migration authority, production service change or playback follows from
adding this corpus.

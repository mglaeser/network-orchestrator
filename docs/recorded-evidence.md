# Recorded evidence, test inventory and remaining gaps

This corpus adds offline regression evidence from real macOS and container
observations. It does **not** declare the framework production qualified. The
native support matrix and mutation gates remain closed. The existing production
owners were observed; the replacement framework was not installed or exercised
as their production successor.

## What is recorded

The 2026-10-09 collection used bounded read-only native commands, directory
metadata and existing guest procfs reads. It installed no service, changed no
forwarding policy, restarted no container, registered no accessory and played
no audio. Background discovery commands were time limited and reaped. Public
fixtures contain no executable instructions and never trigger native collection.

| Corpus | Boundary replayed | What this cannot establish |
|---|---|---|
| `discovery/` | Browse callbacks, SRV/address/raw TXT parsing, import association and registration argv construction | Pairing, actual registration/withdrawal, launchd consent, shared application caches or receiver audio |
| `runtime/` | Complete launchd inventory grammar, selected job/process records, projected container/network JSON and volume response decoding | Current process identity, root observer access, guest lifecycle, crash recovery or reboot |
| `packet/` | Interface/route/socket parsing, missing neighbour and denied privileged-read behavior | Kernel hook order, PF state removal, packet translation, return traffic or real owner activation |
| `preflight/` | Native macOS fact parsers, collection serialization and conservative host-report interpretation | Current security posture, unattended recovery, candidate-runtime compatibility or platform acceptance |

The collection observed macOS 27.0.1 build 26A434 on ARM64 and Container CLI
1.2.0. A recording from that runtime is not a qualification of the declared 1.5.0
candidate. Hosted macOS CI is a third context and does not remove this mismatch.

Each JSON fixture contains a closed schema, capture date/context/tool/platform,
original stream digests, explicitly described transformations/limitations and
sanitized stream digests. Large tables use ordered text chunks to retain every
byte without raising production JSON string limits. The loader checks the
joined payload against its digest. Hashes detect drift; they are not independent
authentication of provenance.

Identity replacements use invented labels, documentation addresses and neutral
opaque TXT fields. Some fixtures explicitly project selected fields or an
interface excerpt. Their limitations identify what was removed. Do not infer
identity, credentials, pairing, complete network inventory or original command
arguments from a sanitized projection. See [discovery details](discovery-evidence.md)
and the runtime corpus README for exact scope.

## How every test run reports its evidence

The normal pull-request and main-branch CI suite includes all recordings on each
supported Python version. No credentials, LAN reachability, administrator access
or production runner are required. After pytest, CI publishes:

- `junit.xml`: collected test outcomes.
- `coverage.xml`: line/branch coverage, with the existing 90% combined gate.
- `test-evidence.json`: every collected test, phase outcomes, fixtures/markers and
  recording IDs actually loaded during setup, call or teardown in the current
  pytest execution context (fresh threads/subprocesses and later cached-fixture
  consumption are not traced). It includes the
  hash of each fixture file and explicitly lists tests without recorded loads.
- `test-inventory.json`: every tracked or nonignored source file, its digest,
  Python function/nested-callable ranges, comments/docstrings and statement
  coverage. Source hashes before/after the run and the saved coverage-file digest
  bind attribution; changed or unbound inputs are refused. Shared-line nested
  bodies and deferred generator spans are marked ambiguous and omitted from per-function attribution. Test indices connect functions to observed execution contexts and
  recorded-load tests without repeating thousands of long node IDs.

Run the same workflow locally:

```sh
python -m pytest -m 'not acceptance' --cov=netorch --cov-branch \
  --cov-context=test --cov-report=term-missing --cov-report=xml \
  --junitxml=junit.xml --evidence-report=test-evidence.json --evidence-coverage=.coverage
python tools/test_inventory.py --evidence test-evidence.json \
  --coverage .coverage --output test-inventory.json
```

The inventory does not mark a file or function reviewed merely because it was
executed. Nor does a recording load prove that an assertion checked those bytes,
that every function reached by that test consumed them, or that the expected
answer was independently correct. The replay tests assert specific independently
reviewed parser and refusal outcomes. Tests of the reporting mechanism verify
nested-scope attribution, setup loads, failed outcomes, missing evidence,
ignored/deleted files, symlink refusal and digest integrity.

## Why not every test is a production recording

A healthy running predecessor cannot supply authentic recordings of the new
framework's first installation, interrupted deployment, malicious JSON, forged
admission, partial writes, expired lease, clock reversal or future API mismatch.
Copying a healthy recording into each such test would create traceability without
relevant evidence. Relabelling an injected failure as observed production data
would be false. These tests therefore remain explicit synthetic, property or
fault-injection proofs, supplemented by native-format replays where relevant.

The request for actual production evidence for **every** test is not satisfied
by this corpus, and the reports deliberately expose that gap. Full-suite success
means the declared automated assertions passed; it does not mean every assertion
was measured in production. Do not delete adversarial tests or relax refusal
behavior to improve the recorded-input count.

Two observed successful reads illustrate this distinction: an empty VPN list
cannot independently establish that VPNs are absent, and an Internet Sharing
preference without `NAT.Enabled` cannot establish that sharing is disabled. The
recorded tests assert **unknown**, not an inferred healthy default. A denied PF
read is likewise not an empty kernel table. Direct shell socket output and empty
subprocess output were observed as different capture contexts; neither result
is silently substituted for the other.

## Native work still required before migration

The [qualification gates](native-qualification.md), [migration readiness](migration-readiness.md)
and [migration health](migration-health.md) remain mandatory. In particular:

1. Privileged PF readback requires local administrator authentication. The current
   unprivileged denial gives no PF kernel grammar, state or hook-order evidence.
2. The replacement owners must be evaluated in their real root/user launchd
   contexts on the exact candidate platform, with bounded recovery and rollback.
3. Packet/UDP return paths, multiple changing receivers, discovery renewal and
   HA's own shared scanner need end-to-end observations from the proposed setup.
4. Pairing, audio and application acceptance require the relevant supported
   lifecycle and, for audibility, a person. No fake accessory was needed or
   created for this corpus.
5. Every vital dashboard service must pass the baseline and post-step health
   gate during migration. Current parser fixtures cannot prove future health.

A private evidence session retains the reviewed captures and a cleanup manifest.
Temporary collectors, copied instrumentation and audit scratch outputs are
removed after their reports are retained. Collection and replay must never leave
an installed debug service, running probe, fake accessory, widened firewall rule
or extra production logging behind.

The [source review ledger](reviews/2026-10-09-recorded-evidence-audit.json) records
47 production source/backend files and 707 reviewed named symbols with source
hashes, boundary notes, associated test modules and remaining evidence. It is
a review record, not a universal assertion-correctness certificate. CI supplies
the finer execution inventory for the revision actually tested.

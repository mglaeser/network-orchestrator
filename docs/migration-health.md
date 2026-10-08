# Offline migration health checkpoints

Every proposed owner transition requires the complete reviewed dashboard roster
before the change, after it, after any rollback, and during its soak. The same
roster applies to every owner. An unchanged external service remains an
observation-only sentinel: observing it does not authorize changing its host.

`python -m netorch.migration_health` checks a saved recording of the **existing**
dashboard API. It is not a collector, supervisor, remote client or privileged
interface. It makes no request, refresh, repair, announcement or file write.
It never grants native qualification or calls a migration operation.

## Contract and recording

Keep the canonical health contract in the private instance repository. Its
fields are closed and required:

| Field | Meaning |
|---|---|
| `schema_version` | Integer `1` |
| `plan_sha256` | SHA256 of the exact reviewed private migration plan bytes |
| `catalog_sha256` | SHA256 of the reviewed private catalog and check mapping |
| `steps` | Distinct bounded step IDs in the reviewed plan |
| `services` | Complete roster, each with `id`, `category`, `checks`, `max_age_seconds` |

`checks` contains the exact existing dashboard check names, including the
functional checks expanded by its adapters. Each list is nonempty and unique.
Categories are `service`, `device`, or `webpage`. Freshness is between one and
300 seconds; the dashboard's ordinary hourly cache is not enough. The contract
must be canonical JSON plus one newline. Its digest is SHA256 of canonical JSON
**without** that final newline. There are no optional-service, ignore-failure,
shell-command or credential fields.

Use the existing dashboard's supported authenticated refresh and read mechanism
in the approved window. Record a new generation and checkpoint boundary before
requesting the refresh. Keep credentials out of command arguments, logs and
recordings. Keep the complete authenticated `/api/services` response private;
do not substitute its disk cache or `/healthz`, which proves only that its HTTP
process answers. Catalog/templates and check implementations must match the
reviewed mapping, verified independently at collection time. A digest copied into
an envelope does not establish that match.

The snapshot envelope has exactly these fields:

```json
{
  "schema_version": 1,
  "contract_sha256": "<64 lowercase hex characters>",
  "catalog_sha256": "<64 lowercase hex characters>",
  "step": "discovery",
  "phase": "post",
  "generation": "attempt-one",
  "started_at": 1800000000,
  "completed_at": 1800000040,
  "source": "dashboard-api",
  "dashboard": {"services": [], "configError": null, "running": false}
}
```

This is a shape illustration, deliberately invalid evidence: the placeholders
and empty roster cannot pass. `dashboard` is the actual saved API object. Each
service must have its exact ID and a result with `status`, `checkedAt`, `checks`,
and `running`. Each check requires its original `name` and boolean `ok`.
Metadata is ignored and never executed or printed. The API's plural categories
`services`, `devices`, and `webpages` map explicitly to the singular contract
categories. Earlier dashboard versions may omit `category`; the reviewed catalog
remains its author in that case.

## Evaluate one checkpoint

```sh
python -m netorch.migration_health \
  --contract migration-health-contract.json \
  --snapshot checkpoint.json \
  --step discovery --phase post --generation attempt-one \
  --since 1800000000
```

Replace the illustrative time with the recorded checkpoint boundary. The caller
supplies the expected step, phase, generation and boundary independently of the
snapshot. A retry gets a new generation and boundary. Allowed phases are `pre`,
`post`, `rollback`, and `soak`. A recording may not cover more than 300 seconds;
all service completion timestamps must fall within that recording and remain
fresh when evaluated. The checkpoint completion time must not be in the future.

Exit zero means **only that recorded health and coverage pass**. Exit one means
a blocker, including missing/extra services or checks, duplicates, a refresh
still running, configuration error, unknown result, false/nonboolean check,
staleness, future time or mismatched generation/context. Exit 65 means invalid
or unavailable input. Error output never echoes check messages or credentials.

Even exit zero reports `mutation_available: false`, `native_qualified: false`,
and `provenance_authenticated: false`. JSON can be fabricated. This evaluator
does not authenticate a server, verify an evidence signature, establish exact
template parity, bind a live deployment or prove that a process stays healthy
after the recording. Trusted collection, release/instance/owner generation,
artifact retention and the existing acceptance ledger remain separate gates.

## What a green dashboard cannot prove

Keep the independent checks in the [readiness gates](migration-readiness.md):
native PF rule and state retirement, the first packet from the intended origin,
original DNS client identity, genuine cold application discovery, multiple
receiver reconnection, audible audio, camera video/audio, component health,
restore and unattended reboot. These use existing qualified owners and supported
application interfaces during an approved window. A webpage, login screen,
process listing, TTS service success or all-green dashboard is insufficient.

There is no automatic repair on a failed checkpoint. Stop advancing, preserve
the operation's hold and evidence, and use the exact reviewed owner-scoped
recovery branch. Revalidate the full roster after recovery. Pre-existing faults
must be recorded and resolved or explicitly reconsidered before a window; they
are never silently converted into exceptions by this tool.

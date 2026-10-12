# Offline migration health checkpoints

Every proposed owner transition requires the complete reviewed dashboard roster
before the change, after it, after any rollback, and during its soak. The same
roster applies to every owner. **SEV1, SEV2 and SEV3 are crucial: all their checks
must be fresh and operational after every step, before the next component moves.**
This is an explicit minimum, not permission to ignore SEV4/5: the existing stricter
all-entry checkpoint remains in force. Every category is included. An unchanged
external service remains an observation-only sentinel; observing it does not
authorize changing its host.

Starting with framework 0.4.5, `python -m netorch.migration_health` accepts a saved
`GET /api/v1/status?max_age_seconds=300` response under a version 2 contract.
Legacy version 1 contracts retain their strict `/api/services` behavior; they do
not gain severity semantics or silently accept the new wire format.

The evaluator is **implemented offline validation**, not a collector, supervisor,
remote client, privileged interface or migration runner. It makes no request,
refresh, repair, announcement or file write. It cannot authenticate a recording,
qualify an owner, grant admission or authorize a migration. The staged human
workflow is in the [migration runbook](migration-runbook.md).

## Reviewed contract

Keep the canonical contract in the private instance repository. Fields are
closed and required:

| Field | Version 2 meaning |
|---|---|
| `schema_version` | Integer `2` |
| `dashboard_api` | Exactly `"status-v1"` |
| `critical_severity_max` | Integer `3`; configured SEV1–3 are crucial |
| `plan_sha256` | SHA256 of the exact reviewed private migration plan bytes |
| `catalog_sha256` | SHA256 of the reviewed private catalogue and check mapping |
| `steps` | Distinct bounded step IDs in the reviewed plan |
| `services` | Complete roster; each row has `id`, `category`, `severity`, `checks`, `max_age_seconds` |

Severity is a required integer 1–5 and must match the frozen private template
value. Use current installed templates, not example defaults. A mid-window
severity change, including a downgrade to SEV4/5, invalidates the checkpoint and
requires a reviewed catalogue/contract revision. The live API cannot choose which
services are critical. Severity describes configured failure priority, not a
currently declared incident.

`checks` contains the exact existing dashboard check names, including functional
checks expanded by adapters. Lists are nonempty and unique. Categories are
`service`, `device`, or `webpage`; API plural categories map explicitly to these.
Freshness is between one and 300 seconds. Canonical JSON has one final newline;
the contract digest is SHA256 of canonical JSON **without** that newline. Plan
and catalogue digests bind their exact file bytes. There is no optional-service,
ignore-failure, shell-command or credential field.

Version 1 has only `schema_version`, `plan_sha256`, `catalog_sha256`, `steps` and
`services`; its rows omit severity. The evaluator does not reinterpret old
recordings or mutate contracts when upgrading.

## Collect a checkpoint in the approved window

1. Independently verify the deployed dashboard API/checker and template hashes
   against the reviewed private catalogue. Freeze every entry, its severity and
   expanded check names. Record the owner/release/input generation and a new
   step/phase/attempt identifier outside the recording.
2. Record the checkpoint start boundary. Through the dashboard's existing
   supported authenticated refresh workflow, request a complete fresh batch.
   A status GET **does not** trigger checks. The normal hourly cache is not a
   five-minute migration baseline.
3. Read `GET /api/v1/status?max_age_seconds=300` with the existing dashboard login
   over its protected management path. Wait within the original 300-second budget
   for a complete batch. Never change credentials or read the vault to manufacture
   access. No new API token, login role or public exposure is introduced.
4. Reject transport/authentication failure, HTTP errors, Problem Details,
   non-JSON/truncated responses, or an unavailable observer. Save the complete
   actual status response privately with the independently retained context.
   Do not filter the roster, replace timestamps, convert unknown to healthy or
   reconstruct an API response from `results.json`.
5. Evaluate the recording using the external expected context. Require complete
   all-entry success, including the explicit SEV1–3 result, plus the independent
   native gates. Only then may the next component move. A retry needs a new
   generation and boundary; it does not reset the authorized operation budget.

The API's `/api/v1/openapi.json` is documentation, not health evidence. `/healthz`
proves only the dashboard HTTP process answers. HTTP 200 means a summary was
served, not that its components are healthy. Keep credentials out of arguments,
URLs, logs and recordings; the response itself contains private topology and
must not be committed to the public framework.

The version 2 snapshot envelope has exactly these fields:

```json
{
  "schema_version": 2,
  "contract_sha256": "<64 lowercase hex characters>",
  "catalog_sha256": "<64 lowercase hex characters>",
  "step": "discovery",
  "phase": "post",
  "generation": "attempt-one",
  "started_at": 1800000000,
  "completed_at": 1800000040,
  "source": "dashboard-status-api-v1",
  "dashboard": {}
}
```

This is a shape illustration, deliberately invalid evidence: placeholders and
an empty dashboard cannot pass. `dashboard` must be the **unmodified actual API
object**, including `schema_version: "1"`, `generated_at`, aggregate `status`,
`observation` and the complete `components` list. Each component supplies its
ID, category, severity, effective status/reason, check timestamps and freshness,
refresh flag and check names/statuses. Additive metadata is bounded and ignored;
it is never executed or printed. Do not normalize away contradictions.

Version 1 recordings instead use envelope version 1, source `dashboard-api` and the
original `/api/services` object with `services`, `configError`, `running` and each
service's `result`. Existing version 1 requirements remain unchanged.

## Evaluate one checkpoint

```sh
python -m netorch.migration_health \
  --contract migration-health-contract.json \
  --snapshot checkpoint.json \
  --step discovery --phase post --generation attempt-one \
  --since 1800000000
```

Replace the illustrative time with the independently recorded boundary. Allowed
phases are `pre`, `post`, `rollback`, and `soak`. Capture must fit within 300 seconds;
all required check completions must fall within that recording and remain fresh
at evaluation. Generated time cannot precede checks or exceed capture completion.
The API age/expiry fields must agree with its actual timestamps and requested
freshness. The response threshold cannot exceed 300 seconds. The evaluator
recomputes aggregate counts/status and affected severity and refuses contradictions.
Both global and component refresh flags must be false. An old successful result
retained during a refresh cannot pass.

Exit 0 means **only that recorded all-entry health and coverage pass**. Exit 1
means a blocker; exit 65 means invalid or unavailable input. Failures include
missing/extra entries or checks, duplicate IDs/names, changed category/severity,
refresh in progress, unknown/degraded status, wrong status reason, failed checks,
stale/future/inconsistent times, mismatched generation or contradictory aggregate
fields. Errors never echo check messages, metadata or credentials.

Version 2 also reports `critical_services`, `noncritical_services` and
`critical_health_passed`. The latter is false for any shared context/roster
problem or crucial-entry failure. **It is not an alternative success signal:**
a SEV4/5 failure can leave crucial entries healthy while still failing
`recorded_health_passed`. All-entry success and native acceptance are required.

Even exit 0 reports `mutation_available: false`, `native_qualified: false` and
`provenance_authenticated: false`. JSON can be fabricated; hashes copied into an
envelope cannot prove deployed template parity, authenticate a server or bind an
actual refresh generation. Timestamps only reject observations outside the
recorded window. Trusted collection, exact source/context parity, evidence
retention and the existing acceptance ledger remain separate gates. If a
checkpoint cannot obtain a complete fresh batch, stop; never manufacture it.

## What a green dashboard cannot prove

The wired-adapter incident is a concrete counterexample: the resolver's published
high port can answer while incoming physical-LAN port 53 is still bound to an
obsolete interface. Require independent physical-LAN UDP and TCP DNS replies and
original-client query-log identity alongside **every** step's pre/post, rollback
and soak checkpoints. Host/container-originated queries cannot substitute for
that path. See [wired selection and its evidence boundary](wired-interface-selection.md).

Keep the independent checks in the [readiness gates](migration-readiness.md):
native PF rule and state retirement, the first packet from the intended origin,
original DNS client identity, genuine cold application discovery, multiple
receiver reconnection, audible audio, camera video/audio, component health,
restore and unattended reboot. These use existing qualified owners and supported
application interfaces during an approved window. A webpage, login screen,
process listing, TTS service success or all-green dashboard is insufficient.
Severity cannot exempt a dependency or native qualification requirement.

There is no automatic repair on a failed checkpoint. Stop advancing, preserve
the operation's hold and evidence, and use the exact reviewed owner-scoped
recovery branch. Prove the candidate inactive before restoring the predecessor;
never reactivate both. Revalidate the full roster after recovery. Pre-existing
faults stay recorded and must be resolved or explicitly reconsidered before a
window; this tool never silently converts them into exceptions.

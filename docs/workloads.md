# Explicit initial workload provisioning

> **0.3 stage boundary:** this guide describes retained owner mechanisms and mock
> contracts. Native authority expansion is unavailable while the accepted support
> matrix is empty. Existing installed owners stay in place; see
> [read-only workflow](getting-started.md) and [migration gates](site-migration.md).

`netorch.workloads` provides an operator-only path to create a fresh installation
from private recipes. It is separate from the networking executor and Monit
recovery. It never stops, deletes, replaces or silently recreates a container.
Existing full native configuration must match its enrolled fingerprint before
it is retained or explicitly initially started.

## Data instead of setup scripts

The bounded closed recipe has `schema_version: 1` and a `workloads` array. Each
row contains `service`, an immutable digest-pinned `image`, typed `options`
(`flag`/`value`), and literal process `arguments`. Flags are a fixed supported
allowlist. Identity, platform, network and published ports are generated from
the existing policy/enrollment tables. A recipe cannot override `--name`,
`--network`, `--platform`, `--publish`, run `--rm`, or supply another executable.
Environment inheritance is forbidden; literal `KEY=value` input is required.
No shell, `eval`, command substitution or executable configuration is used.

Resources, entrypoint, process arguments, DNS, bind mounts, socket publications,
kernel and sysctls can be preserved in the private recipe. Mount sources must
match the enrolled persistent identities exactly. Kernel and environment-file
inputs need hashed receipts. Custom init images also need immutable digest pins.
The 1.5.0 kernel-argument flag is rejected on older reader contracts.

Normal application secret storage stays with its existing application. A private
recipe may contain a secret environment value, so recipes and journals are
never public artifacts. The plan displays only names, actions, start mode and
content digests; it omits native argv and environment. The network policy itself needs
no application secrets.

All referenced images must already be in the native cache. Image retrieval is
an explicit preparatory vendor step, using the site's approved digest/registry
policy. Initial creation does not silently upgrade the runtime or images.
Every native invocation remains bounded, including failures during creation.

## Plan and deliberate activation

```sh
python -m netorch.workloads --settings /operator/site/runtime-settings.json \
  --recipes /operator/site/workloads.json plan --start-initial
python -m netorch.workloads --settings /operator/site/runtime-settings.json \
  --recipes /operator/site/workloads.json provision \
  --expected-digest REVIEWED_PROVISION_SHA256 --start-initial
```

Use the returned `provision_digest` for `--expected-digest`. It binds the recipe,
entire network policy, runtime settings/enrollment, resolved native creation
arguments and explicit initial start mode. A change to ports, host addresses,
network names, paths, resource flags, compiler semantics or start mode therefore
requires a fresh reviewed plan. `recipe_digest` identifies only the authored
application recipe and cannot authorize provisioning. To create stopped guests,
omit `--start-initial` from both commands; approval of a stopped plan cannot
authorize a start. No raw argument or secret value is returned with either hash.

Provisioning must run as the enrolled unprivileged operator. It requires an
existing durable operator pause and no competing maintenance suspension. It
first verifies the entire plan, actual vendor version/network/helper and all
persistent identities. It takes its own holder-owned suspension and journal.
Every write has a fresh target/inventory/identity check. Missing names are
created stopped; `--start-initial` deliberately starts these or validated
existing stopped names even when initial fleet state is all stopped. Monit
cannot invoke this bootstrap path; its own start rule reaches a fully stopped
fleet only where the runtime settings declare
[`fleet_start`](apple-runtime.md#starting-a-fully-stopped-fleet).

Already-running enrolled containers are retained with zero lifecycle changes.
Unexpected names, changed resources, different mounts, duplicate names or
unknown running state stop the operation. A successful vendor exit must be
followed by actual stopped/running readback. Newly created definitions must be
captured and re-derived through enrollment before any network admission.

On success, only this operation's suspension is released; operator pause remains
set. No automatic admission or resume happens. On partial failure, remaining
writes stop and the private journal plus operation suspension remain. No new
container is deleted and no previous application is restarted as guessed
rollback. Inspect actual state and reconcile its recipe/enrollment before
explicitly acknowledging the recorded interrupted operation:

```sh
python -m netorch.workloads --settings /operator/site/runtime-settings.json \
  acknowledge --expected-digest INSPECTED_FAILED_PROVISION_SHA256 \
  --holder EXACT_RECORDED_PROVISION_HOLDER --phase failed
```

The digest, holder and phase must exactly match the protected
`workload-journal.json`. Use `--phase applying` only after inspecting an
interrupted process that left that phase recorded. Acknowledgement needs the
enrolled user, existing state store and durable operator pause; it requires no
recipes or policy reload and performs no native operation. It preserves completed
rows, records the inspected phase, releases only the exact `initial-provision`
holder and retains every other hold plus operator pause. It never deletes,
starts, repairs or rolls back a container, admits exposure or resumes the site.

Acknowledgement is persisted before releasing its hold. If that final intent
write fails, retry the exact command while its recorded holder remains present.
After acknowledgement, a newly reviewed provisioning plan may proceed only when
all competing holds have also been resolved by their respective owners.
`netorch acknowledge-journal` is for the networking executor's separate journal;
it cannot acknowledge a workload provisioning run.
The framework intentionally has no destructive automatic workload rollback.

For a change to an existing application's definition, use its maintained private
deployment/recovery manager under the same operator pause and maintenance gates,
then reenroll it. The network installer preserves mounts, image, resources,
kernel arguments and app data. This distinction is what prevents a port-policy
edit from becoming an unreviewed application replacement.

The seven-workload end-to-end tests exercise the actual initial-create/start,
enrollment and observation path with a fake native command transport. They also
cover retained workloads, partial creation failure, pause preservation,
unapproved recipes, closed flags and secret-free plans. They perform no actual
network operations, audio or privileged native commands.

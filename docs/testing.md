# Test strategy and evidence tiers

Version 0.3 has an empty native-qualified support matrix. Public native mutation
entrypoints refuse before state or tools; tests of retained execution internals
use explicit injected seams and never bypass production guards.

A test establishes a claim at a boundary. A platform simulation can prove owner
control flow, but cannot prove the platform's packet behavior. Keep provenance,
versions, expected result and evidence tier explicit. Do not label fake output as
a captured production fixture.

## Automated public CI

CI runs hosted macOS with Python 3.12, 3.13 and 3.14. Every job, including
formatting, type checking and dependency audits, runs on macOS. Other host
operating systems are outside this framework's scope.
Every matrix job installs reviewed hash-locked dependencies, checks package
consistency, runs unit/property/mock/process tests, validates synthetic policy,
runs the mock demonstration, builds wheel/sdist and smoke-tests an installed
wheel from outside the checkout.

The macOS job also compiles synthetic PF previews with `pfctl -n -f`; it never
loads or enables rules. This checks hosted Darwin grammar, not production hook
order, retained states or packet behavior. The fixed backend has a Bash syntax
check, and installed-wheel smoke tests include all executable owner modules and
packaged schema/backend resources.

A separate job enforces the tracked-file public host-data guard, Ruff lint/format, strict mypy and dependency advisory
checks. A scheduled advisory lookup does not update or deploy anything.
Dependabot proposes dependency/Action updates for review. Actions are SHA-pinned
with read-only repository permissions; workflows require no production secrets,
services, Apple account or privileged self-hosted runner.

Mypy targets Darwin explicitly and keeps strict checking and unreachable-code
warnings enabled. Hosted macOS userspace checks are evidence for their recorded
runner version; they do not qualify a production macOS build or run guests.

The combined line/branch coverage gate is 90%. Coverage records execution, not
correctness. The test intent and rejected unsafe behavior matter more than a high
number. Add regressions at the smallest tier that proves each reported failure.

```sh
python -m pytest -m 'not acceptance' --cov=netorch --cov-branch --cov-report=term-missing
ruff check .
ruff format --check .
mypy
python -m netorch.privacy_check --root . --exceptions schemas/privacy-exceptions.json
python -m build --no-isolation
pip-audit -r requirements-dev-lock.txt --strict
```

Use the project's managed development environment and reviewed locks. No test
in the public default suite loads PF, changes launchd, starts a guest, registers
Bonjour, triggers Local Network consent or plays audio.

## Tier 1: pure, property and model tests

These tests need no network, root account, runtime or service. Use RFC 5737 address
ranges, injected clocks, closed synthetic observations and fake owners.

| Area | Required claims |
|---|---|
| Instance/import | Canonical byte equality, literal-only extraction, exact source/owner conformance, no executable/live-endpoint data, two privacy guards |
| Host view | Six verbs make no writes, owner calls or network probes; synthetic/unsigned/stale/wrong-context evidence cannot qualify native support |
| Input | Duplicate keys at every depth, nonfinite values, booleans in numeric fields, unknown fields/versions and invalid types are rejected |
| Policy | Duplicate IDs, bad references, overlapping claims, wrong address scopes and incompatible guest/return ranges are rejected |
| Content | Canonical key ordering preserves digests; authority-relevant content changes invalidate admission |
| Observation | Only complete fresh reads prove present/absent; timeout, denial, busy, malformed, stale and contradictory results stay unknown |
| Planning | Unknown never starts recovery; stale generations cannot activate; no-op requires exact current readback |
| Pause | Operator pause survives holder release, crash, reinstall and rollback; a holder cannot release another hold |
| Execution | Every injected partial failure stops subsequent writes, preserves phase and requires fresh evidence |
| Privilege | User execution cannot invoke external-root; a user admission cannot supply root authority |
| Transport | NAT and target-less RDR remain separate; each rendered rule stays within admitted interface/protocol/port scope |
| Discovery | Exact same-service publication, genuine model/related-record selection, byte-preserving TXT, count/age/generation/dependency bounds |
| Persistence | Atomic/private writes, revision conflicts and retained negative intent; damaged durable state inhibits |

Hypothesis generates inputs and action sequences, then minimizes failures.
Stateful pause/suspend/release/crash tests establish order-sensitive invariants.
Keep readable regressions for discovered boundary cases. A mock owner's changed
state is a simulation, never evidence that a kernel accepted rules or a receiver
played sound.

## Tier 2: executable owners and userspace contracts

These tests run the real code with fake bounded platform tools and temporary
protected files. They prove control flow and exact parsing without exercising
native network effects.

### Apple runtime and lifecycle

Fake readers cover declared nested/flat Apple CLI formats, version identity,
container definition/enrollment, persistent file inodes, helper process/launchd
identity, interface addresses, network and started-instance generations, live
automatic socket ranges and inspection races. Tests reject wrong mounts/contracts,
unknown resource shapes, duplicate attachments/publications, other guest writers,
all-stopped outage ambiguity, timeout and successful incomplete output.

Recovery rechecks independently proven stopped state, pause and admission before
starting. It never recreates running/unknown definitions. Only the workload probe
can return reserved status 42, and only for a proven stopped enrolled workload
with gates permitting start. Unknown, timeout, denial, signal and networking
health failures cannot initiate a start.

Initial workload tests exercise digest-bound planning and exact fixed CLI create
arguments for missing declared workloads, image pins, range equality, persistent
mount identity and existing-definition preservation. Initial provisioning is a
separate maintenance operation, not a recovery action.

Root-observer tests cover the fixed Mach-bootstrap wrapper and credential drop:
only read operations cross it, groups are cleared, UID/GID are verified before
native exec, and environment/cwd are scrubbed. These injected tests never run
`launchctl asuser` or change real credentials. The actual root LaunchDaemon's
ability to read the enrolled user's API remains a native acceptance gate.

### Bonjour parsing and supervision

Native-format fixtures cover `dns-sd` browse Add/Rmv rows, exact interface
acknowledgement, endpoint/IP resolution and raw hex TXT RDATA, including empty,
NUL and non-UTF-8 entries. Wrong-interface exit zero, unknown rows, conflicts,
renaming, malformed lengths and output floods cannot become success.

A fake native executable tests actual child readiness and process-group cleanup.
Injected clocks and proof readers establish independent registration expiry when
the scanner stalls, backward wall-clock resistance, parent death cleanup, child
exit, changed policy/generation, pause and stale dependency withdrawal. A
single policy failure cannot discard healthy sibling registrations. These tests
establish local supervision contracts, not native packet registration.

Fixed endpoint tests reject arbitrary operations, coordinator-supplied records,
wrong policy hashes and mismatched readback. The owner independently rereads its
policy, fresh runtime/report evidence and durable intent. Read-only root readiness
comes only from a protected fresh report of an independently admitted root
profile; a user snapshot or user approval does not supply it.

### PF owner and backend

A temporary-root harness exercises the independent pull owner, protected policy
capture, content/implementation-bound admission, activation rechecks, actual
readback parser contracts, healthy no-op passes and withdrawal/state-drain ordering.
Fake kernels inject foreign drift, partial loads, stale generations, busy locks,
truncated rules/states, source swaps, denied target validation and interrupted
journals. The native Bash backend is syntax/argument tested with fake effects.
No fake PF result is presented as Darwin grammar or state semantics acceptance.

### Provisioning and recovery

Deterministic render tests use complete multi-workload synthetic deployments.
They verify byte/hash inventory, source capture races, no extra files, fixed root
job commands, separate user/root domains, private permissions, generated Monit
syntax contracts and owned job protection. Fake launchctl/Monit/PF effects test
installation, upgrade, no-op, first-install failure, predecessor recovery and
committed rollback at each phase. Current pause and unrelated holder suspensions
survive. Unknown journals, changed predecessors, foreign jobs and rewritten
source artifacts inhibit recovery.

Package tests validate wheels outside the checkout and exercise module/CLI entry
points without native effects. Changing implementation semantics must change its
independently bound owner contract or digest version; hashing unchanged settings
alone cannot detect new meaning.

Hosted macOS CI remains userspace evidence. GitHub's arm64 macOS runner does not
provide supported nested virtualization for actual Apple Container networking,
and its image is not an operator's exact OS build. It cannot certify production
PF, Bonjour consent or physical devices. See
[GitHub hosted-runner limits](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

## Tier 3: isolated native packet and discovery acceptance

Run on a physical test host or in an explicitly authorized maintenance window
with an owned scratch profile and verified recovery material. Do not attach an
open public pull-request workflow to a production self-hosted runner.

Record actual OS/runtime/tool/code versions, digests, interface identities and
fixture provenance. Required evidence can include:

- First outbound UDP request to a LAN responder on port 80 and its first reply; ingress just below, at both ends of, and
  just above the admitted range; no out-of-range translation.
- Native PF hook precedence, owned NAT/RDR grammar/readback and retained-state
  invalidation after a generation change.
- Original client identity for the direct DNS path and explicit degraded identity
  for a configured native-publication fallback.
- Direct guest address reuse with a non-target workload, when shared pools are
  used; promptly verified withdrawal rather than an absolute race-free claim.
- Interface absence, replacement, renamed device or address change.
- Bonjour genuine record parity, exact corresponding publication, binary TXT,
registration callbacks, lease expiry, child/scanner crash and multiple devices.
  Include publisher SIGKILL and native client self-expiry/renewal continuity.
- Local Network privacy in the actual user job, SSH and Monit contexts; rebuild
  and fresh-account behavior when relevant.
- Root LaunchDaemon observation through the selected user's Mach bootstrap:
  native CLI remains unprivileged, complete API/guest reads succeed, and absent
  user sessions or denied namespace access remain unknown.
- Guest UDP exhaustion/collision and idle/two-receiver occupancy measurements;
  measured capacity problems must not silently widen admission.

Use scoped scratch anchors and isolated test networks. Renderer equivalence is
not packet evidence. A warm Home Assistant/pyatv cache can conceal a dead inward
projection: use the running application shared scanner and a cold start, genuine
receiver address change, new receiver or supported administrator discovery
subscription. A reload alone is insufficient. Avoid global firewall flushing, unowned state deletion and
runtime-wide stops in routine diagnostics. Reuse existing safe evidence when it
proves the exact same versioned claim.

## Tier 4: lifecycle, reboot and restore

Owner crash, container recreation, runtime stop/start, pool reconstruction, helper
relaunch, reboot, upgrade and restore require separate maintenance authorization.
Runtime-wide actions may interrupt every workload and LAN DNS. Recovery material
must have been restored in a rehearsal, not merely copied.

Record generation boundaries, admission changes, preserved pause, start order,
withdrawal/state readback, discovery recovery and time to first valid resolver
answer from another machine. A root network owner does not make a user-session
runtime available before login; the site's chosen login/resolver architecture
must pass its own availability objective.

An old release receipt or backup cannot prove current routes, guest ownership or
kernel state. Restore code/desired data, obtain fresh evidence and review admission
before exposure. Keep kernel/runtime upgrades and framework refactoring separate.

## Tier 5: applications and human confirmation

Verify discovery and reconnection inside the actual application using its normal
shared scanner, stored integration and supported lifecycle. Standalone discovery
cannot replace this evidence. Confirm additional changing-address/multiple-device
cases when that is a requirement.

A successful TTS/media service call, non-empty audio file or reported `playing`
state does not prove that a speaker was audible. A separately coordinated person
must confirm physical output. Public/backend synthesis tests must not play audio.
The framework does not create application integrations, helpers or automations to
manufacture acceptance.

## Reporting

For each claimed capability publish the tested boundary, precise result, versions,
policy/release digest, fixture provenance, evidence tier and remaining gates.
Report tests as failed or unrun when appropriate. Public artifacts must contain
synthetic/redacted facts, never credentials, raw environment variables, private
packet payloads or installation identifiers. A large passing mock suite cannot
close an unrun hardware gate.

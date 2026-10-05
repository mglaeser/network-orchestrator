# Test strategy and evidence tiers

Tests establish a claim at a particular boundary. A simulation of a platform is
useful for orchestration behavior but cannot prove the platform itself behaves
that way. Keep fixture provenance, expected result and evidence tier explicit.

## Automated public CI

CI runs on Ubuntu with Python 3.12, 3.13 and 3.14, plus hosted macOS with Python
3.14. Every matrix job installs the same reviewed hash-locked dependency set,
checks package consistency, runs unit/property/mock tests, validates sample
policy, runs the mock demonstration, builds a wheel/source distribution and
installs the wheel outside the checkout.

A separate Linux job enforces Ruff lint/format and strict mypy, and audits the
complete runtime/development dependency lock. A scheduled audit repeats the advisory lookup weekly;
it does not update or deploy anything. Dependabot proposes dependency and Action
changes for review.

The combined line/branch coverage threshold is 90%. Coverage indicates executed
paths; it does not establish quality or hardware correctness. Each reported
failure should produce a regression at the smallest tier that proves it.

## Tier 1: pure, property and mock tests

These tests need no network, root account, container runtime or running service.
Use synthetic documentation-range addresses, injected clocks, fake readers and
mock owners. They can establish:

| Area | Required assertions |
|---|---|
| Strict input | Reject duplicate keys at every depth, nonfinite values, unknown fields, unsupported versions and invalid types |
| Semantic policy | Reject duplicate IDs, unknown references, overlapping claims, invalid address scope and incompatible port ranges; discovery references only transport profiles, so recursive dependency cycles cannot be expressed |
| Canonical content | Object key ordering does not change a digest; every authority-relevant change does |
| Admission | Modified resolved content is pending; a profile name alone carries no approval |
| Observation | Only complete fresh reads yield present/absent; malformed, inaccessible, busy and timed-out input remains unknown |
| Planning | Unknown never starts recovery; stale generations cannot authorize activation; no-op needs verified readback |
| Pause | Operator pause survives operation release, crash, reinstall and rollback; holders cannot release another holder's suspension |
| Execution | Stop after each injected partial failure; preserve the operation journal and reobserve before further writes |
| Privilege | The live user executor never calls an external-root owner |
| Discovery | Match the announcing service's own publication, retain provenance, enforce independently verified dependencies, record age and service/network generations; unknown interfaces publish nothing |
| Persistence | Atomic replacement, revisions and retained intent survive failures; corrupt durable intent fails closed |

Hypothesis generates values and action sequences, then checks safety invariants.
Stateful tests are especially useful when pause, suspend, release and crash order
affect behavior. Keep the minimized counterexample as a readable regression.

The mock owner is intentionally labelled a simulation. Its state changes show
whether the planner and coordinator follow their contract. They do not show
whether a real PF command loaded a rule, a receiver heard audio, or a guest
retained its identity.

## Tier 2: process and userspace contracts

Use fake provider executables in temporary directories to establish framing,
timeouts, bounded output, exit handling, subprocess-group cleanup and response
validation. A successful-empty, truncated, wrong-shape or denied response must not
be reported healthy. Do not use shell evaluation to implement a provider.

The discovery coordinator has a fixed `reconcile-discovery` operation rather
than a DNS-SD implementation. Test that it sends the resolved policy and exact
digest with expected service/network generations, rejects mismatched readback,
processes scoped cleanup before transport operations, reports unavailable cleanup
as pending, and cannot publish immediately
after a dependency was repaired in the same pass. Missing publisher evidence must
request cleanup and leave activation inhibited until a later complete observation.
These are owner/coordinator contract tests, not evidence of native registration.

Digest tests must also cover version boundaries. Changing transport or discovery
semantics requires a digest strategy/schema version bump or an independently
enforced versioned owner implementation contract; hashing unchanged data cannot
detect an implementation change by itself.

Unprivileged macOS tests may establish a tool's argument and reader contract on
that OS. A fixture must carry tool/version/capture metadata or be marked synthetic.
The public workflow deliberately does not load PF rules, start guests, register
Bonjour services, change launchd jobs or trigger Local Network consent.

Hosted macOS runners cannot establish real Apple Container guest networking:
GitHub documents that nested virtualization is unsupported on arm64 macOS
runners. Runner images also differ from an operator's exact OS build. Public CI
must not be presented as a hardware certification.

## Tier 3: isolated hardware acceptance

Perform these outside public CI, on a physical test host or an explicitly
authorized maintenance window with a scratch profile and recovery material.
Never attach an open public pull-request workflow to a production self-hosted
runner.

Required evidence for a platform owner can include:

- First outbound UDP request and reply; inbound probes just below, at both ends
  of, and just above the admitted range.
- NAT/redirect readback and retained-state invalidation after a target-generation
  change, including states that survive rule removal.
- Interface absent, replaced, renamed or address-changed behavior.
- Unknown observation timeout followed by verified withdrawal.
- Shared-pool address reuse with a non-target guest, when the deployment uses
  direct-to-guest forwarding.
- Local Network privacy in the actual job identity and launch context.
- Root owner failure and independent repair at the documented operation phase.

Use an owned scratch anchor and isolated guest network. A renderer comparison is
not packet evidence. Reuse safe observations whenever they prove the claim; avoid
global firewall flushing and runtime-wide stops in routine tests.

## Tier 4: destructive lifecycle acceptance

A reboot, runtime restart, pool reconstruction, owner crash, upgrade or restore
needs a separate window and material that has actually been restored in a
rehearsal. Runtime-wide changes can interrupt all workloads and LAN DNS.

Record start order, generation boundaries, admission hashes, preserved pause,
first rule/readback completion and first discovery pass. Verify no recovery fires
before its dependency gates are ready. A changed OS/runtime version reopens the
relevant platform contracts.

## Tier 5: application and person acceptance

Application discovery may depend on a shared cache that a standalone probe does
not exercise. Verify the real application's discovery path, a cold start or
address change, and reconnect behavior. DNS client identity and a HomeKit client's
view require application-level acceptance. A playback API success does not prove
audible output; record a listener's confirmation when audio is in scope.

Keep real credentials and application state outside the framework. Never alter
pairings, helpers or automations merely to satisfy an orchestration test. Public
fixtures should not contain the resulting private captures.

## Release record

For a published framework release, record revision, interpreter versions,
dependency locks, CI outcomes and distribution checksums. For a deployment,
add platform owner versions, OS build, policy/admission digests, fixture provenance,
generation test evidence and the hardware/application tests actually run.

Do not mark an unrun gate passed. Use `unknown` with a reason. Test results are
bounded by the tested version and envelope, not by a future guarantee.

## Sources

- [pytest integration practices](https://pytest.org/en/stable/explanation/goodpractices.html)
- [Hypothesis stateful testing](https://hypothesis.readthedocs.io/en/latest/stateful.html)
- [GitHub-hosted runner limitations](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub workflow security](https://docs.github.com/en/actions/reference/security/secure-use)
- [Secure hash-checked pip installs](https://pip.pypa.io/en/stable/topics/secure-installs/)

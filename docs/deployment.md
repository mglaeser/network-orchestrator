# Deployment and owner integration

Netorch can load an external site configuration and run a complete mocked
orchestration on a managed Python interpreter. Connecting native owners is a
separate deployment exercise. The initial release does not install a root
service, upgrade a runtime, choose a login policy or modify a production host.

## Keep site data outside the repository

A suggested operator-controlled layout is:

```text
site/
  network.json        reviewed policy or generated catalog
  bindings.json       trusted local user-provider executable bindings
  admissions.json    independently approved resolved profile hashes
  observations.json  bounded observations, timestamp and generation
state/
  intent.json        durable operator pause and holder-owned suspension
  journal.json       finite operation phase and failures
  receipt.json       completed operation evidence
```

Names above are conceptual records; use the CLI's documented state-file format.
Choose access modes and backup policy appropriate to the installing account.
Keep mutable intent and journals outside anything a release reinstalls. Keep
application secrets, data directories and configuration owned by the application.
The synthetic examples are not production bindings and must not be applied as
real network policy.

## Stage 1: derive and inspect

1. Identify every native, third-party and custom owner and its current source.
2. Capture bounded read-only observations with version/provenance metadata.
3. Derive literal owner facts without executing configuration. Report anything
   that needs shell evaluation as underivable.
4. Run validation, cross-owner lint, status and plans off-host where practical.
5. Make no authoritative catalog copy by hand while the old owner remains the
   source. A regeneration check must detect drift.

The framework's static input format intentionally rejects executable fragments.
It does not parse arbitrary administrator scripts. A site needing a legacy-source
reader should write a bounded, literal-only adapter and supply fixtures that prove
what it derives and what it refuses.

## Stage 2: integrate one user owner

Provider bindings are explicit local executable paths, not commands embedded in
network policy. Implement the existing user owner's structured request/response
contract. Start with observation, then compare its preview to the current owner
inputs. Use injected failures and readback before enabling any writes.

The provider runs as the account that invokes Netorch. That binding is a trust
decision; the framework cannot restrict a malicious executable's account-level
authority. The process wrapper validates framing and responses, bounds work and
terminates an overrun process group.

A live `reconcile` needs a reviewed policy, explicit local binding and state
directory. Initialize intent with `init-state`, which starts paused. `reconcile`
defaults to a read-only plan; `--execute-user-owners` explicitly requests user
owner writes. It reobserves state and refuses stale plans. It does not call an
`external-root` owner. Such actions are reported as requiring the independent
owner rather than silently treated as successful.

After preparing external policy, admissions and a private mode-0600 binding file,
the first live-owner inspection can use the following placeholder paths:

```sh
netorch init-state --state-dir /operator/state/netorch
netorch observe --config /operator/site/network.json \
  --bindings /operator/site/bindings.json
netorch reconcile --config /operator/site/network.json \
  --bindings /operator/site/bindings.json \
  --admissions /operator/site/admissions.json \
  --state-dir /operator/state/netorch
```

Replace the paths with protected locations outside the checkout. `observe` calls
the reviewed provider's bounded read operation. The reconciliation above returns
decisions without owner writes. Resuming intent and supplying
`--execute-user-owners` is a separate operator decision after readback and adapter
acceptance; neither step can invoke an external-root owner.

Pause and operation suspension must remain separate. Only the operator resumes an
operator pause; an operation holder releases only its own suspension. Unreadable
or unsupported intent fails closed. Time alone does not clear either record.

## Stage 3: integrate an independent root owner

The existing root owner keeps its privilege boundary and schedule. It pulls its
own installed admitted snapshot and its own live observations. There is no
planner-to-root invocation path or automatic authorization through a user CLI.

Admission binds a profile ID to canonical resolved content, including scope,
protocol, range, strategy, service contract and owner. A widened range, changed
target contract, different interface or strategy must become pending. The root
installer must load an immutable validated snapshot and protect against replacing
content between validation and use. It must never source that snapshot as code.

Changing implementation semantics without changing data can otherwise preserve
an obsolete approval. Every transport or discovery behavior change must bump its
digest strategy/schema version or use an independently enforced, versioned owner
implementation contract. The owner must reopen admission when the approved
contract changes; a package version printed in logs alone does not enforce this.

Every real privileged owner must additionally enforce:

- One writer and one lock for its owned resources.
- Stable instance and network-generation observations with a defined age limit.
- Preserved operator pause and operation suspensions.
- Verified withdrawal and retained-state invalidation when ownership is unknown,
  stale, absent or mismatched.
- Actual platform readback after mutation, including states that outlive rules.
- Scope confined to the admitted interfaces, protocols, addresses and ports.
- No global ruleset rewrite, unowned anchor flush or broad firewall grant.

A successful mock does not replace these checks. A root implementation that does
not meet them remains blocked for live adoption.

## Direct guest identity: a required design decision

An IP address in a packet-filter rule names an address, not a workload. Shared
dynamic address pools can reuse that address, and retained packet states can
outlive a rule change. A polling framework cannot certify an absolute
never-forward-to-another-workload guarantee on such a pool.

Version 1 deliberately accepts only **bounded** safety for direct-to-guest and
UDP-return profiles: a documented and explicitly accepted residual window, with
independently enforced observation age and unknown limits, rule withdrawal,
state draining and readback. Runtime-wide operations must obey the same gates.
The model has no proof record for an isolated guest boundary that no other
workload can hold, so it rejects a structural declaration for these profiles.
Sites requiring that guarantee need a separately proven platform design and a
future reviewed model extension.

Do not silently convert an absolute requirement into a bounded one. A generation
change, runtime stop, rebuilt pool or relaunch of the network helper requires new
observations. Stored facts cannot authorize forwarding in a new generation.

## Discovery owner integration

Discovery declarations select record projection and dependencies; they do not
turn multicast into a general tunnel. Native Bonjour, a selected-record proxy,
or a maintained third-party owner still owns actual registrations.

The coordinator calls only the existing user owner's fixed
`reconcile-discovery` operation. Its request binds the whole policy, resolved
discovery policy and dependencies to exact digests and expected service/network
generations. The publisher independently verifies these inputs against its own
current policy and fresh observations; the request is not authority to invent a
record. It returns complete post-operation readback bound to those generations.
No DNS-SD listener, reflector or registration subprocess is bundled in Netorch.

An inactive discovery decision is processed before packet transport operations;
unavailable publishers remain pending, rather than being reported withdrawn.
Activation uses only dependencies already verified in the initial fresh snapshot.
A transport profile repaired in the same pass does not immediately authorize
publication: the next cycle must observe it as verified. Missing or unknown
publisher evidence requests scoped cleanup and leaves the pass inhibited until a
later cycle has complete evidence. Missing or unconfirmed interfaces publish
nothing; an owner may not fall back to all interfaces.

Require the actual announcing service's publication from the same runtime
snapshot, not merely a matching port number. Preserve record identity and
provenance; allow only reviewed endpoint transformations. Reject a missing or
ambiguous publication. Verify the named interface exists and owns the expected
address; interface index zero must not widen scope accidentally.

Registrations need a bounded age independent of completed polling passes. A
hung pass or exited registration process must withdraw its records. Imports
depend on the transport profile's verified availability so the application is not
promised an unusable endpoint. An API success alone is not proof of correct
advertisement.

Native adapter consent must be checked in its actual user job identity and launch
context. A command launched from a terminal may have different Local Network
privacy behavior than a LaunchAgent. Root is not the consent workaround.

## Workload lifecycle and DNS availability

Existing owners keep their mounts, image pins, kernel arguments, recovery data
and service-manager behavior. Networking refactoring does not imply a container
recreation or runtime upgrade. Upgrade as a separate reviewed change, then freeze
versioned reader fixtures and rerun the relevant acceptance.

If a runtime requires an interactive user session, the root forwarding owner's
availability does not make workloads available before login. A sole LAN resolver
inside that runtime can cause an unattended-reboot DNS outage. The site must
choose and document its boot/login policy or an independent resolver architecture,
with a measured first-answer acceptance time. Netorch does not choose automatic
login or a security-policy exception for the operator.

## Failure and recovery

On an unexpected partial failure, stop writes, preserve the journal, report the
last completed phase, and obtain fresh readback. Do not automatically replay an
old plan or run speculative rollback commands. The existing owner selects the
documented recovery appropriate to the observed phase. Only after reviewing that
state, `acknowledge-journal --plan-digest ...` acknowledges the exact interrupted
operation. It does not repair, roll back, approve policy or clear operator pause.

An intent record is durable negative authority, not a disposable log. A receipt
does not establish current truth. A kernel lock returning busy is a bounded
read-only retry condition; it is not authorization to remove a live lock.

Before an invasive acceptance test, create and verify appropriate recovery
material. Restore rehearsal, cleanup policy and backup retention are separate
operator decisions. Cleanup must check references before deleting files used by
installed owners. Reinstalling an old release must preserve current pause intent.

## Promotion checklist

- [ ] Pure, mock, process and package CI passes on supported interpreters/OSes.
- [ ] All real owners have versioned, labelled observation fixtures.
- [ ] Content-bound admission and pending changes are enforced at the owner boundary.
- [ ] Pause/suspension semantics survive crashes and release rollback.
- [ ] Each direct-guest profile has an accepted bounded policy enforced independently.
- [ ] Discovery readback matches resolved policy and service/network generations.
- [ ] Wrong-generation withdrawal and retained-state invalidation pass on hardware.
- [ ] Real interfaces, NAT first packet/reply and discovery job consent pass.
- [ ] Restore rehearsal and required lifecycle acceptance have actual evidence.
- [ ] Application-level discovery/reconnect and any person-confirmed behavior pass.
- [ ] The site records OS/tool versions, digests, evidence tier and unrun gates.

Use the [testing guide](testing.md) to select the tier that can establish each
claim. Public CI cannot close a hardware gate by generating a nicer mock.

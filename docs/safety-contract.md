# Safety review, evidence and extraction gates

The host-independent read-only layer does not replace the existing owners or
qualify a host for mutation. `netorch.safety_contract` evaluates safety evidence
without invoking an owner, opening a socket, performing Bonjour operations or
running native tools. These assessments are report data, never admission.

## Existing boundary and remaining evidence

| Review rule | Existing enforcement | What still needs host evidence |
|---|---|---|
| Resolved-content admission | Root binds the complete resolved profile, scope, workload contract, strategy, backend, observer, Python implementation and dependency versions. A changed digest stays pending. | Render/install conformance and the explicit host admission. |
| No unprivileged call into root | Root independently pulls protected inputs. The user executor only observes its report. No privileged RPC or sudoers entry exists. | User-domain runtime/API clients remain able to redirect admitted ports by changing the runtime; record this residual. |
| Bounded guest identity | Fresh helper and guest identities fence activation. Changed generations withdraw before later activation; unknown retires immediately. Old guest states are drained from and to the address. | Native allocator/reset, first-packet/reply and state invalidation acceptance; a signed age/count decision per bounded profile. |
| Pause and suspensions | Separate durable operator pause and holder-owned operation records survive reinstall and rollback. Damage inhibits. | Native reboot/restore acceptance does not follow from model tests. |
| Unknown and readiness | Complete typed observations, age decay, exact dependency readback and independent Bonjour leases. Unknown never calls workload recovery. | Consent and application evidence in the actual launch context; a warm-cache reload is not inward-discovery proof. |

The renderer emits only the reviewed bounded rule shapes. It does not open a
broad filter pass, disable PF, flush global state or use a receiver address as
an authentication source. Native publication, discovery, return traffic,
application state and audible output are distinct claims. A listener or a
`playing` state does not prove that a person heard audio.

## T, K and the withdrawal window

A bounded profile's instance decision records maximum observation age **T**,
maximum unknown-pass tolerance **K**, a residual statement, the signer and the
UTC signature time. The existing owner is stricter than a larger K: its
effective value is **1**, because the first unknown retires known exposure.
The report exposes both values; it does not add a delayed-withdrawal algorithm.

The conditional operational window is:

```text
max(nominal interval, 10 seconds) × effective K
    + verified scheduling slack
    + aggregate identity-read bound
    + aggregate withdrawal-and-state-invalidation bound
```

Each term must be established. The ten-second launchd floor is not an upper
bound on scheduling. An individual subprocess timeout is not the duration of
an entire owner pass, which may perform several independent reads and writes.
An unavailable owner has no demonstrated finite withdrawal bound. Therefore
the current read-only report leaves `withdrawal_bound_seconds` unset unless
those aggregate terms are supplied with separately validated native evidence.
Setting T does not cause the kernel to expire a PF rule automatically.

`assess_bounded_safety` returns `not-fulfilled` for an unsigned or future
decision, a bound exceeding T, or an absolute no-misdelivery requirement.
Configured limits without proving evidence are `fulfilled-unverified`. Even
with finite evidence and a valid signature, the strongest bounded outcome is
`accepted-residual`, with `zero_misdelivery_guaranteed=false`. No framework
report can close an absolute *never* requirement for a shared guest-address
pool; structural isolation needs a separate architecture decision.

## Versioned synthetic allocator contract

The model follows exact tagged upstream sources:

- [Container 1.5.0's dependency pin](https://github.com/apple/container/blob/1.5.0/Package.swift#L24)
  is containerization **0.47.0**. The older 0.40.1 dependency belongs to
  [Container 1.2.0](https://github.com/apple/container/blob/1.2.0/Package.swift#L24).
- [DefaultNetworkService](https://github.com/apple/container/blob/1.5.0/Sources/Services/Network/Server/DefaultNetworkService.swift#L35)
  derives the address pool from the observed subnet and releases leases when
  the owning session disconnects.
- [AttachmentAllocator](https://github.com/apple/container/blob/1.5.0/Sources/Services/Network/Server/AttachmentAllocator.swift#L28)
  retains a hostname's allocation until release.
- [RotatingAddressAllocator 0.47.0](https://github.com/apple/containerization/blob/0.47.0/Sources/ContainerizationExtras/RotatingAddressAllocator.swift#L53)
  allocates from the queue head and releases to its tail.

`RotatingAllocatorModel` is an explicitly synthetic, memory-bounded test model.
It verifies delayed reuse within one generation and immediate re-dealing when
a new helper rebuilds the pool. It does not observe live addresses, predict
the next native lease, or certify a runtime upgrade. Re-check the sources and
repeat the native contract tests whenever the runtime dependency changes.

## Planned stop, one owner at a time

For a targeted workload or runtime-wide stop, the administrator/lifecycle owner:

1. Takes its own durable suspension, preserving operator pause and other holders.
2. Lets the independently scheduled PF owner withdraw the exact owned rules.
3. Verifies readback and invalidation of states from and to each old guest target.
4. Stops the workload/runtime only after quiescence is established.
5. Starts it through its existing declared lifecycle owner.
6. Obtains fresh runtime, helper, workload and publication identities.
7. Releases only its own suspension; restores only unchanged admitted policy.
8. Verifies transport and discovery separately, then completes host acceptance.

A runtime CLI, API bridge or management UI can bypass this planned sequence.
Such a restart is unplanned and uses the bounded withdrawal path; it is not
evidence that the planned-stop guarantee was followed. Unknown or failed
withdrawal stops the procedure. It never authorizes a speculative restore of
saved addresses or states.

## Recovery and platform qualification

The reserved recovery failure code remains **42**, above the signal range.
`recovery_exit_code` returns it only for a fresh, complete absence after the
initial PF/Bonjour readiness gate. Unknown, stale, future, timeout and cold-start
observations return uncertainty code1. The one cold start that returns 42 is a
fresh absence that the caller states was established with the declared
fleet-start evidence (`fleet_start_proven`). A supervisor must match **42 exactly**,
never every nonzero exit status. This pure helper does not modify live Monit
rules or start a recovery loop.

Reader compatibility is separate from mutation qualification. Existing readers
recognize several CLI envelope versions; that does not prove support on a
macOS build. The candidate platform and initially empty hardware-accepted matrix
live in the platform contract. Missing native evidence keeps the new instance
workflow read-only. A later owner-input extraction must declare its platform
gate, protect qualification evidence, preserve pause/withdraw/drain paths on an
unsupported target, and retain the existing packet behavior. This stage does
not rewrite an installed owner or deploy onto a host.

## Public capability boundary in 0.3

`netorch.workflow_gate` makes the empty accepted matrix mechanically effective
at the public entrypoints. Native activation, admission, installation, recovery,
publication, initial provisioning and release of a safety gate stop with
`stage-not-qualified` and exit78 **before** loading mutation inputs, creating
owner state or calling native tools. Root privilege, a declared `qualified`
field, a successful simulation and environment variables cannot bypass it.
There is no qualification-writing command or enable flag in this release.

The retained owner implementations are immutable semantic references for mock
conformance and a future separately qualified owner migration. Direct calls to
their internals from tests are not an advertised deployment capability. Existing
CLI conformance tests explicitly inject a local test seam to exercise those
internals; the public denial tests use the real gate and forbid every state or
native call. No installed legacy owner is changed by importing this package.

The allowed public surface is:

| Operation | Availability in this stage |
|---|---|
| Validate, render, build, simulate, review admission and plan | Available; static output does not authorize installation. |
| Observe, inspect health and capture enrollment | Available as bounded reads; enrollment output is unadmitted data. |
| Prepare a protected deployment bundle | Static preparation only; installing the bundle is blocked. |
| Pause, take an independent suspension, request exact scoped withdrawal | Available through the existing validation and ownership checks. |
| Execute reconciliation or start scanner/publisher processes | Blocked. |
| Install, admit, recreate/provision workloads or recover/start a service | Blocked. |
| Resume, release a suspension, acknowledge an interrupted activation journal | Blocked; these can remove an activation inhibitor. |

Endpoint requests receive the same classification before their complete
existing authorization checks: observation and explicit withdrawal/drain are
eligible, activation and unknown operations are blocked. A Bonjour withdrawal
requires the literal boolean `false`; `0`, missing values and future operation
names cannot become negative authority. Native publication removal still
belongs to the existing application-maintenance owner and is never simulated
as successful. On an unsupported host, withdrawal must continue using its
existing verified owner; this package does not replace that owner implicitly.

## What CI proves

Pure tests cover missing/invalid/future signatures, nonfinite or unknown bounds,
K versus effective K, the launchd floor, a residual that cannot become an
absolute guarantee, allocator rotation/rebuild and all uncertainty reasons
avoiding code42. Isolated PF tests additionally cover resolved-field mutation,
generation replacement, stale/unknown identity and bidirectional state drainage.
These are tier1 contracts. Native PF semantics, host consent, guest packet
delivery, cold boot, restore, client identity and heard audio remain at their
separate proving tiers; synthetic output never stands in for kernel captures.

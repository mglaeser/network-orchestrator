# Configuration and site data

> **0.3 stage boundary:** this guide describes retained owner mechanisms and mock
> contracts. Native authority expansion is unavailable while the accepted support
> matrix is empty. Existing installed owners stay in place; see
> [read-only workflow](getting-started.md) and [migration gates](site-migration.md).

Netorch's package contains logic; the installation supplies data. The executable
provider bindings and mutable state are separate from the reviewed network policy.
Nothing in a policy can select an executable, run a shell, authorize root work or
create application credentials.

The complete synthetic starting point is [examples/network.json](../examples/network.json).
The closed offline schema is [network.schema.json](../schemas/network.schema.json).
Use documentation examples for learning, then keep the real policy outside this
public checkout. This release models IPv4; it does not silently derive IPv6 rules.

## Policy tables

| Collection | Fields | Meaning |
|---|---|---|
| `scopes` | `id`, `interface`, `host_ipv4`, `lan_cidr`, `guest_cidr` | Explicit host interface/address and disjoint LAN/guest boundaries |
| `owners` | `id`, `privilege`, `capabilities` | Runtime/transport/discovery responsibilities; `user` or `external-root` |
| `services` | `id`, `owner`, `contract_sha256`, optional `automatic_ports` | Service observation owner and independently verified runtime contract |
| `profiles` | `id`, `service`, `scope`, `kind`, `protocol`, `ports`, optional `target_ports`, `safety`, optional `owner` | An independently admitted transport behavior |
| `discovery` | `id`, `owner`, `service`, `scope`, `direction`, `types`, `dependencies`, `max_age_seconds`, `max_records` | Bounded genuine-record import/export tied to verified transport |

Top-level fields are `schema_version` (currently `1`), `site` (an operator label)
and these five collections. IDs are stable lowercase names. Transport and
discovery IDs cannot collide. Port ranges have inclusive `first` and `last`.
The service's owner observes its workload; a profile's owner can independently
override the execution responsibility. Discovery owners must be user-level.

The service contract hash is a site-defined digest of reviewed workload identity
and required runtime settings. The real observation owner must reconstruct and
verify that contract from actual runtime state. Copying a hash from desired policy
into an observation without checking the workload supplies no evidence. The
framework does not invent a universal runtime contract or authorize recreation.

The shipped Apple Container reader provides a versioned enrollment contract:
complete native configuration fingerprint, protected persistent identities and
hashed startup receipts. `enroll` captures it and `derive-policy` generates the
service hash; see [Apple runtime](apple-runtime.md). Other observation owners
must supply equally explicit contracts rather than copy desired hashes.

## Transport strategies

| Kind | Source ports | Target ports | Required evidence |
|---|---|---|---|
| `publication` | Host publication range | Guest listener range | Runtime-owned mapping for the exact service/instance |
| `host-redirect` | LAN-facing range | Same service's native host publication | Verified backing publication from the same scope/protocol/instance |
| `guest-direct` | LAN-facing range | Explicit guest range, or identity mapping | Current guest generation, bounded-risk admission and retained states |
| `udp-return` | Admitted return range | Omitted | UDP automatic range equality, static source-port preservation and target-less inbound RDR |

Equal port-range widths are required where translation is specified. Overlapping
claims are rejected. Host redirects cannot use an unrelated listener as proof.
Direct guest and UDP-return strategies require `safety.kind: "bounded"`, a
nonempty risk `statement`, explicit acknowledgment and a real owner that enforces
the contract. A shared address pool cannot offer structural no-reuse guarantees
through polling. Structural direct-guest proofs are not modeled in version 1.

Every safety declaration sets `max_age_seconds` and `unknown_limit`.
The planner immediately retires known unsafe exposure on unknown identity;
`unknown_limit` is an existing reader's maximum bounded retry contract, not a
permission to keep a stale target. Values must match tested owner behavior.

An optional `fallback_publication` on `guest-direct` names a native publication
for the exact same service, scope, protocol and guest target range. It is not a
second port table or an arbitrary listener. The independent PF owner can select
that verified host path only after its own direct route/neighbor check proves
direct access unavailable; the service must still be fresh and verified. Plans
and reports mark `effective_strategy: degraded-fallback`, since client identity
changes. Retire/drain the old guest path before switching, and withdraw fallback
before later restoring direct access. See [the fallback example](../examples/network-dns-fallback.json)
and [PF owner](pf-owner.md) for admission and readback requirements.

## Discovery strategies

`direction` is `import` or `export`. `types` are explicit DNS-SD service types,
such as `_airplay._tcp` or `_hap._tcp`. Dependencies can reference only transport
profiles; the model intentionally has no arbitrary dependency graph.

Exports require the actual source service's native publication and match its
guest address, port and generation. Imports select genuine eligible endpoints
within the configured LAN/interface, then related records from the same endpoint.
Apple-media import declares a UDP-return dependency. Selection has wall-clock age,
record-count and loop/provenance bounds. Binary TXT fields remain lossless.

The shipped Bonjour owner implements native scanning, registration and independent
expiration. Netorch coordinates its fixed operation; it does not fabricate records, pair
devices, publish arbitrary IPs or install a multicast reflector. An absent or
unconfirmed interface is cleanup-only, never a wildcard interface fallback.

## One authoring location

Choose one mode per setting:

1. **Existing owner is authoritative.** Derive its literal facts into a generated
   policy using `derive`; do not maintain a second hand-edited catalog.
2. **Reviewed policy is authoritative.** Generate the relevant existing owner's
   input, compare output/readback and retire the old authoring location in the
   same migration. Such generation is an owner-specific integration, not an
   implicit side effect of `validate` or `derive`.

The source manifest supports bounded JSON fragments and strictly literal `.env`
values mapped through JSON pointers. See [owner-facts.json](../examples/owner-facts.json)
and [static-owner.env](../examples/static-owner.env). The importer never sources
shell files, expands variables or evaluates code. Conflicting authors, executable
fragments, duplicate keys and unsupported fields fail validation. So does a
literal file with a carriage return or any other control character except tab
and line feed: only a line feed ends a line.

`derive --check --output ...` checks byte-for-byte canonical equivalence against
the authored sources. Keep this check in the private installation's provisioning
pipeline when migration mode is used.

## Admission is separate authority

An admission record contains a profile ID, its exact resolved SHA-256, approving
owner label, approval time and bounded-risk acknowledgment. The public
[admissions.json](../examples/admissions.json) is a **simulation fixture**.
Do not reuse it for real approval.

An `approved_by` label is not a cryptographic signature. Trust comes from the
independent owner's protected admission store and approving procedure. A user
cannot authorize root simply by writing JSON or supplying a matching digest.
Digests bind the resolved scope, profile, service, observation owner and execution
owner; changing any authority-relevant field reopens admission. Behavior changes
also require a versioned digest strategy or independently enforced owner contract.

## Observations and operator intent

Observations are short-lived evidence, never desired settings. Only complete,
fresh readers establish `present` or `absent`; inaccessible, truncated, busy,
malformed or timed-out readers report `unknown` with a closed reason. The stored
network and service generations must represent actual runtime lifecycle changes.

Initialize the independent private state directory with `init-state`; it starts
paused. Operator pause and operation-owned suspensions form an activation block.
Neither expires; only the operator resumes, and only the matching holder releases
its suspension. Release installation and rollback preserve this directory.

Provider bindings are trusted local code, mode `0600`, separate from network
policy. Read the [owner protocol](owner-protocol.md) before implementing them.
The CLI bounds their execution but is not a sandbox for malicious adapters.

## Unsupported assumptions

This release supplies executable Apple runtime and Bonjour adapters, an independent
PF owner, and separate user/root provisioning. It does not install a packet stack,
upgrade the vendor runtime, choose automatic login or replace application settings.
The existing application startup chain remains independently owned; an optional
[`fleet_start`](apple-runtime.md#starting-a-fully-stopped-fleet) declaration lets
the supervisor start proven-stopped workloads after a boot, never the vendor
runtime. Missing or
unsafe native prerequisites stay unknown/pending. Public CI proves model and
mock contracts plus hosted PF grammar; consult the [deployment gates](deployment.md)
for real packets, consent, boot/restore and application acceptance.

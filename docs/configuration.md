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
| `profiles` | `id`, `service`, `scope`, `kind`, `protocol`, `ports`, optional `target_ports`, `safety`, optional `owner`, optional `source_scope` | An independently admitted transport behavior |
| `discovery` | `id`, `owner`, `service`, `scope`, `direction`, `types`, `dependencies`, `max_age_seconds`, `max_records`, optional `return_path`, optional `misses` | Bounded genuine-record import/export tied to verified transport |

Top-level fields are `schema_version` (currently `1`), `site` (an operator label)
and these five collections. IDs are stable lowercase names of at most 64
characters. The ID of an `external-root` owner, and of every profile such an
owner executes, may have at most 63: that owner's installation record takes
an owner ID of at most that length, and its protected admission and rule
records, which are keyed by profile ID, take a profile ID of at most that
length. A longer one is refused when the policy is validated. An owner that
keeps the product's own anchor, which is named after its ID, needs an ID of
at most 45 characters; that is a rule of its installation record, not of the
policy, and an owner with a longer ID
[pins its anchor](pf-owner.md#exact-admission).
Transport and discovery IDs cannot collide. Port ranges have inclusive `first`
and `last`.
The service's owner observes its workload; a profile's owner can independently
override the execution responsibility. Discovery owners must be user-level.
A policy may carry one more top-level field, the optional `discovery_names`
object described under [discovery strategies](#discovery-strategies).

The service contract hash is a site-defined digest of reviewed workload identity
and required runtime settings. The real observation owner must reconstruct and
verify that contract from actual runtime state. Copying a hash from desired policy
into an observation without checking the workload supplies no evidence. The
framework does not invent a universal runtime contract or authorize recreation.

The shipped Apple Container reader provides a versioned enrollment contract:
complete native configuration fingerprint, protected persistent identities and
hashed startup receipts. `enroll` captures it and `derive-policy` generates the
service hash; see [Apple runtime](apple-runtime.md). An enrollment that binds a
volume identifier instead of a device number is hashed under a second strategy
name, so the two forms never share a hash. Other observation owners
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

An optional `source_scope` says which sources a profile's rule matches. The
default `lan` is the scope's `lan_cidr`. It may be written or left out, and the
canonical policy leaves it out, so a policy that does not use the setting keeps
its bytes, digests and admissions. `any` matches every source. It is accepted
only for a `host-redirect` with `safety.kind: "structural"`, whose translation
target is the host's own address and whose one backing publication must be
verified first, as for every host redirect. `guest-direct` (with or without a
fallback), `udp-return` and `publication` profiles are always LAN-scoped, and an
explicit `null` or any other value is refused. A wider `lan_cidr` is not a
substitute: that prefix also bounds the UDP return pair and the receivers that
may be imported. The native publication has no source restriction of its own,
so `any` changes which destination port leads to it for a source outside the
LAN prefix, not who can reach the published port. Such a profile uses resolved
digest version 3, which also binds the digest of its backing publication, and
root admits it only with its own acknowledgement; see [PF owner](pf-owner.md).

## Discovery strategies

`direction` is `import` or `export`. `types` are explicit DNS-SD service types,
such as `_airplay._tcp` or `_hap._tcp`. Dependencies can reference only transport
profiles; the model intentionally has no arbitrary dependency graph.

Exports require the actual source service's native publication and match its
guest address, port and generation. Imports select genuine eligible endpoints
within the configured LAN/interface, then related records from the same endpoint.
The bundled discovery owner decides eligibility on a device's `_airplay._tcp`
record, so it refuses to load an import declaration of its own that does not
list that type: such a declaration could never import anything.
Apple-media import declares a UDP-return dependency. Selection has wall-clock age,
record-count and loop/provenance bounds. Binary TXT fields remain lossless.

That dependency is the default, not a necessity. `return_path` is `"required"`
unless it is stated, and an import of `_airplay._tcp` or `_raop._tcp` records
then lists a UDP-return profile of its own service and scope. `"independent"`
lifts that one requirement, for a site that imports receivers for discovery
only or admits the return path as a separate decision. Such an entry lists no
UDP-return profile at all, and the setting is refused on an export. Nothing
else changes: the owner still waits for every dependency the entry does list,
for its consuming service, and for pause and suspension. The default is left
out of the canonical policy and of the entry's digest, so an existing policy
keeps its digests. An independent entry has a digest of its own; an approval
given for the same entry without the setting does not apply to it.

`misses` is the entry's own miss tolerance, an integer from 1 to 8: the number
of consecutive completed passes that may fail to find a record of this entry
before its discovery owner withdraws that record. With 1 a record is withdrawn
in the first pass that does not find it. Whether a pass that fails counts as
well is the owner's own matter; the bundled owner counts a read that did not
complete when its settings say so (`failed_pass`). An entry that states the
member
replaces its owner's own setting for that entry alone, and an entry without it
follows that setting; for the bundled owner that is `miss_tolerance` of its
settings file ([Bonjour owner](bonjour-owner.md#supervision-leases-and-recovery)).
A site whose exports tolerate missed passes and whose imports do not states
the number where the two differ. The member has no default and no `null`
spelling. An entry that leaves it out keeps its canonical form and both
digests; an entry that states it, `1` included, is another policy with a
digest of its own, as for every member of an entry. The coordinator does not
act on the number. It never lengthens a lease: `max_age_seconds` still ends
every record, and the bundled owner refuses to load settings under which a
stated tolerance above 1 could never keep a record because the entry's lease
leaves no room for it.

The shipped Bonjour owner implements native scanning, registration and independent
expiration. Netorch coordinates its fixed operation; it does not fabricate records, pair
devices, publish arbitrary IPs or install a multicast reflector. An absent or
unconfirmed interface is cleanup-only, never a wildcard interface fallback.

Every projected record gets a host name of its own whose first label begins
with a fixed prefix: one for a guest service published on the LAN, one for a
LAN endpoint published on the guest network. The optional top-level object
`discovery_names` names the pair for the whole policy:

```json
"discovery_names": {"export_prefix": "example-guest-", "import_prefix": "example-link-"}
```

Both members are required. A prefix is lower-case `[a-z][a-z0-9-]*` of at most
47 bytes: the bundled owner appends 16 hexadecimal digits and one DNS label
holds 63. The two differ and neither begins with the other. Without the
object the pair is `netorch-container-` and `netorch-lan-`, and a policy that
spells exactly that pair is the same policy, with the same canonical form and
digests.

The pair is site-wide on purpose. A record whose instance name or host name
begins with either prefix, in any ASCII case, is never projected in either
direction, by any declaration; that is the loop exclusion. Choose prefixes
that no genuine name on either network begins with. A named pair is part of
the policy digest and of every discovery digest, so discovery evidence made
under another pair is refused; transport profile digests do not change.

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
and line feed: only a line feed ends a line. JSON Pointer array indexes follow
[RFC 6901 section 4](https://www.rfc-editor.org/rfc/rfc6901#section-4): ASCII decimal
without leading zeros (`0` or a nonzero digit followed by digits), referring to
an existing element. Padded indexes, Unicode digits, `-` and out-of-range indexes
are refused; object keys retain their literal spelling.

`derive --check --output ...` checks byte-for-byte canonical equivalence against
the authored sources. Keep this check in the private installation's provisioning
pipeline when migration mode is used.

## Admission is separate authority

An admission record contains a profile ID, its exact resolved SHA-256, approving
owner label, approval time and bounded-risk acknowledgment. For a profile with
`source_scope: "any"` the same stored member records the acknowledgement of the
unrestricted source instead. A profile is never both bounded and unrestricted,
and the digest binds the scope, so the one member is unambiguous. The public
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

`init-state` initializes the independent private state directory, which starts
paused. This release refuses that command with status 78 before it creates
anything. Operator pause and operation-owned suspensions form an activation block.
Neither expires; only the operator resumes, and only the matching holder releases
its suspension. A hold blocks one service in the same way and is released by its
holder ([state contract](state-machine.md)). Release installation and rollback
preserve this directory.

Provider bindings are trusted local code, mode `0600`, separate from network
policy. Read the [owner protocol](owner-protocol.md) before implementing them.
The CLI bounds their execution but is not a sandbox for malicious adapters.

## Unsupported assumptions

This release supplies executable Apple runtime and Bonjour adapters, an independent
PF owner, and separate user/root provisioning. It does not install a packet stack,
upgrade the vendor runtime, choose automatic login or replace application settings.
The existing application startup chain remains independently owned; an optional
[`fleet_start`](apple-runtime.md#starting-a-fully-stopped-fleet) declaration lets
the supervisor start proven-stopped workloads after a boot, and the vendor
runtime only with its optional member
[`runtime_start`](apple-runtime.md#starting-the-vendor-runtime). Missing or
unsafe native prerequisites stay unknown/pending. Public CI proves model and
mock contracts plus hosted PF grammar; consult the [deployment gates](deployment.md)
for real packets, consent, boot/restore and application acceptance.

JSON integers are exact integer tokens: schema versions, port bounds, safety
bounds and discovery limits reject integral floats such as `8000.0`. They are
never coerced before hashing or native argument construction.

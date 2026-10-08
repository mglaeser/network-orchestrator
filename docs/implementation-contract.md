# Implementation contract

Netorch is a macOS-only policy and orchestration layer over existing owners. It does
not confer privilege or replace an operating system packet implementation.

Version 0.3 adds the canonical host model in `netorch.instance_model`, strict loading
in `netorch.instance`, and the six-verb read-only `netorch.host_cli` entrypoint.
The profile/platform/requirements registries are closed code libraries. The
native-qualified support matrix is empty; public native mutation entrypoints
refuse before reading state or calling tools. These new interfaces are documented
in [instances](instances.md).

The retained owner policy model is in `netorch.model`. These frozen dataclasses are the shared API:

- `PortRange(first: int, last: int)`
- `Scope(id, interface, host_ipv4, lan_cidr, guest_cidr)`
- `Owner(id, privilege, capabilities: tuple[str, ...])`; privilege is `user` or
  `external-root`.
- `Service(id, owner, contract_sha256, automatic_ports: PortRange | None)`
- `Safety(kind, max_age_seconds, unknown_limit, statement)`; kind is `structural`
  or `bounded`. `statement` is a nonempty risk declaration for bounded policies.
- `Profile(id, service, scope, kind, protocol, ports: PortRange,
  target_ports: PortRange | None, safety: Safety, owner: str | None = None,
  fallback_publication: str | None = None, source_scope: str = "lan")`; kind is
  `publication`, `host-redirect`, `guest-direct` or `udp-return`; protocol `tcp`
  or `udp`; source scope `lan` or `any`.
- `Discovery(id, owner, service, scope, direction, types: tuple[str, ...],
  dependencies: tuple[str, ...], max_age_seconds, max_records,
  misses: int | None = None)`; `misses` is 1 to 8.
- `Config(schema_version, site, scopes, owners, services, profiles, discovery)`;
  collection fields are tuples, with `scope(id)`, `owner(id)`, `service(id)`,
  `profile(id)` and `profile_owner(profile_or_id)` lookup methods.

Configuration syntax is the dataclass field names. Optional `automatic_ports` and
`target_ports` and `fallback_publication` may be omitted; `statement` may be null
for structural policies. Fallback is allowed only for guest-direct and must bind
an exact same-service native publication; see [configuration](configuration.md).
`source_scope` may be omitted and `to_dict` leaves the default `lan` out; `any`
is allowed only for a structural host redirect, uses profile digest version 3
and binds `netorch.config.backing_publication(config, profile)`.
A discovery entry's `misses` may be omitted and `to_dict` leaves it out while it
is `None`; stated, it is that entry's own miss tolerance and a member of its
discovery digest; see [configuration](configuration.md).
`netorch.config.load_config(path)` and `parse_config(text)` return a `Config`.
`netorch.config.to_dict(config)` returns JSON data.
`netorch.config.profile_digest(config, profile)` binds the resolved profile, scope,
service and owner to canonical SHA-256. `config_digest(config)` covers all policy.

`Service.owner` names the runtime/observation owner. `Profile.owner` can explicitly
override it for transport execution; omitted/null means the service owner.
`Discovery.owner` is an explicit user-level owner with the `discovery` capability.
A service can therefore retain its user runtime manager, externally owned PF
transport and separately owned user-level Bonjour projection. Admission binds
the resolved profile owner and service observation owner independently.

`netorch.codec` provides strict JSON and canonical digest functions. No duplicated
keys, nonfinite numbers, remote schema retrieval or executable configuration.

State/plan interfaces live in `netorch.state` and `netorch.planner`:

- `Observation(state, reason, observed_at, generation, data)` uses exactly
  `present`, `absent`, `unknown`; complete reads only establish present/absent.
- `Snapshot(observed_at, network_generation, services, profiles)` uses dicts of
  observations keyed by stable IDs. Endpoint data contains `ipv4`,
  `contract_sha256`; profile data contains `policy_digest`, `target_ipv4`,
  `target_generation`, `network_generation` and actual `states` list.
- `Admission(profile, digest, approved_by, approved_at, risk_acknowledged)`;
  admissions map IDs to entries and bind exact resolved content.
- `Intent(revision, operator_paused, suspensions, damaged=False, holds={})` stores
  operator pause independently from operation-ID -> holder records and from
  service -> operation-ID -> holder holds. Methods preserve pause, enforce
  suspension and hold ownership, and increment the revision on change. `blocked`
  is the site-wide inhibition; `blocks(service)` adds a hold on that service.
- `Action(profile, owner, operation, reason, target_ipv4=None,
  target_generation=None, effective_strategy=None)`; operations are
  `activate`, `withdraw`, `drain`, `noop`, `pending`, `blocked`.
  The only non-null effective strategy is `degraded-fallback`.
- `Plan(policy_digest, snapshot_digest, intent_revision, actions)`.
- `plan(config, snapshot, admissions, intent, now)` is pure. Fresh unknown/stale
  observations never initiate recovery; stale existing targets are withdrawn and
  their retained states drained. No-op only follows verified readback.

Discovery interfaces in `netorch.discovery_plan`:

- `DiscoveryAction(id, owner, active, reason, policy_digest, service_generation,
  network_generation)` is a fixed activation/cleanup decision, with independently
  checked runtime generations.
- `discovery_digest(config, item)` binds resolved discovery declarations and their
  dependency profile digests.
- `plan_discovery(config, snapshot, transport_plan, intent, now)` independently
  verifies dependency readback and publisher/interface evidence. No records are
  fabricated and no packet mechanism is invoked.
- Discovery observations share `Snapshot.profiles` with disjoint IDs, and contain
  policy digest, confirmed interface and service/network generations. Unconfirmed
  or missing evidence requests cleanup before activation in a later fresh cycle.

The executor is an independent module. `MockOwner` is a simulation only; an
`external-root` owner is never invoked by a live unprivileged executor. Root owners
pull their own admitted content and observations on their existing schedule.

Executable macOS implementations are `netorch.apple_runtime`,
`netorch.bonjour_owner`, `netorch.pf_owner`, `netorch.workloads` and
`netorch.deployment`. They use injected readers/runners for tests and fixed native
arguments in production. Root admission additionally binds installed Python,
implementation/schema bytes, dependency versions, backend and observer settings.
`netorch.owners.effective_admissions` derives only read-only downstream readiness
from protected fresh independently admitted root evidence with `root_ready: true`.
It cannot call, admit or resume root.

All examples use synthetic service identities and RFC 5737 address ranges. Local
configuration, production bindings, observations and private runtime data belong
outside the checkout. Python 3.12+; no native runtime installation is implied.

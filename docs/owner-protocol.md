# Existing-owner integration protocol

This protocol lets private installation adapters reuse current service managers.
No adapter or host configuration is inferred from a filename or port number.

## Local bindings

Keep a mode-0600 binding file outside the repository, under a protected private
parent. A binding is trusted operator code configuration, separate from networking
policy. Its executable and dependencies must be reviewed and remain unprivileged.
An adapter can do anything the operator can do; Netorch is not a sandbox for
malicious plugins. The built-in client never constructs a shell command or adds a
privileged RPC. It refuses process bindings for external-root owners.

```json
{
  "schema_version": 1,
  "owners": [
    {"id": "runtime-owner", "kind": "process", "argv": ["/absolute/private/owner-adapter"]},
    {"id": "forwarding-owner", "kind": "root-report", "path": "/absolute/protected/report-directory/owner-observation.json"}
  ]
}
```

The example paths are placeholders, not installed executables. A process adapter
receives one bounded JSON request on stdin, returns one JSON envelope on stdout,
and exits. It may use stderr privately but framework diagnostics do not export
those contents. Deadline: 10 seconds; combined output/input bound: 1 MiB. The
caller uses an absolute argv vector, a minimal environment, no shell, and an owned
POSIX process group. Timeout/output overflow terminates the group.

## Observe

```json
{
  "protocol_version": 1,
  "operation": "observe",
  "owner": "runtime-owner",
  "config": {"...": "validated policy object"}
}
```

Response:

```json
{
  "protocol_version": 1,
  "owner": "runtime-owner",
  "result": {
    "observed_at": 1000,
    "network_generation": "example-network-1",
    "services": {},
    "profiles": {}
  }
}
```

Each service/profile entry is an observation:

```json
{
  "state": "present",
  "reason": "verified",
  "observed_at": 1000,
  "generation": "example-instance-1",
  "data": {
    "ipv4": "198.51.100.20",
    "contract_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
}
```

Service facts must actually be read and validated by the service's observation
owner. Profile readback belongs to the profile's execution owner. The merger
rejects claims for another owner's objects. A `root-report` binding requires a
protected root-owned report and ancestors; it is read-only, with no executable
request or authority to enable anything. `snapshot-file` remains useful for
portable/legacy observation but cannot establish independent root admission.

Profile data contains `policy_digest`, `target_ipv4`, `target_generation`,
`network_generation`, and a complete `states` array. State entries are owner-scoped
opaque identifiers; do not publish payloads or unrelated kernel state. An absent
rule may still have retained states. An unreadable state table is unknown, never
an empty array. All owners must agree on the live network-generation identity.

Version, reason, freshness and complete-read checks are mandatory. Do not report
absent because a command returned empty output; establish that the invocation and
snapshot were complete. Treat implausible all-stopped runtime lists, consent denial
and API/helper restarts according to the platform acceptance contract.

## User-owned reconciliation

```json
{
  "protocol_version": 1,
  "operation": "reconcile",
  "owner": "runtime-owner",
  "policy_digest": "<whole-policy-sha256>",
  "profile_digest": "<exact-resolved-profile-sha256>",
  "profile": "example-publication",
  "action": "activate",
  "target_ipv4": "198.51.100.20",
  "target_generation": "example-instance-1"
}
```

`action` is a fixed operation: activate, withdraw or drain. Never interpret it as
shell text. The adapter resolves a known profile through its own already validated
configuration; it must not choose arbitrary commands/paths from the request.
Reobserve identity and admission before effects. For withdrawal, remove only the
known owned profile. For drain, invalidate only verified owned retained targets,
using exact supported selectors and readback. A changed precondition must fail.

Return the post-operation observation in the same response envelope. Activation
must show exact digest/target/generations; withdrawal must show absent rules; drain
must provide a complete empty `states` array. Exit zero alone is insufficient.

### Native publication maintenance handoff

Apple Container publications are part of a workload's definition. Networking
pause, admission changes or unknown evidence do not authorize stopping or
recreating that workload to remove a host socket. A fixed native adapter can
return exit **78** with this exact envelope for a `reconcile` request concerning
a known `publication` profile:

```json
{
  "protocol_version": 1,
  "owner": "runtime-owner",
  "error": "native-publication-maintenance"
}
```

The client maps only this complete matching maintenance response to a pending
external-owner handoff. It does not treat arbitrary exit codes/errors, another
operation or another profile kind as a handoff. The executor records
`waiting-external-owner`, preserves pause and cannot claim withdrawal/readiness.
Explicit application maintenance must change that definition, then reenroll it.
No false absent result or hidden container recreation is permitted.

## Existing privileged owner

The planner and executor do not invoke this protocol to mutate external-root
owners. A site administrator separately configures the existing privileged owner
to pull its protected admitted snapshot, obtain its own fresh observations and
respect durable pause/suspension. Admission binds resolved fields, not just an ID.
Changed parameters remain pending. User observations are not trusted assertions.

That owner needs one writer/lock/anchor, safe file metadata/descriptor handling,
validated current runtime identity, scoped rules and state invalidation, and an
explicit risk class. No global state flush or base firewall rewrite is allowed.
The bundled [independent PF owner](pf-owner.md) and
[domain-separated provisioner](provisioning.md) implement these requirements.
Administrator installation/admission is explicit and cannot be called by the
user coordinator.

## Discovery owner

Use the pure `netorch.discovery` contracts inside the installation's existing
publisher or adapter. Inputs must be genuine records and runtime publication
provenance, not synthetic live entries. `status` exposes whether transport
dependencies have exact verified readback. The long-lived publisher must withdraw
records when dependencies lose verification or record wall-clock age expires,
confirm the selected interface, cap floods, avoid loops and clean up registrations
after child exit. Its state cannot be assumed from a successful process launch.

The coordinator implements the fixed user-owner operation below. The bundled
`netorch.bonjour_owner --settings PATH endpoint` implements it with independent
native CLI scanning, a lease watchdog and exact readback. The separate `serve`
command runs the long-lived user job; it does not implement a new DNS-SD stack.
The generated deployment preserves an explicitly chosen publisher launch identity.
A new process/consent identity, user session, native DNS-SD behavior and actual
application shared scanner require separately documented host acceptance.

```json
{
  "protocol_version": 1,
  "operation": "reconcile-discovery",
  "owner": "bonjour-manager",
  "policy_digest": "<whole-policy-sha256>",
  "discovery_digest": "<resolved-discovery-and-dependency-sha256>",
  "discovery": "camera-export",
  "active": true,
  "service_generation": "example-instance-1",
  "network_generation": "example-network-1",
  "config": {"...": "validated policy object"}
}
```

The owner independently validates configuration, its identity, resolved digests,
fresh runtime generations, transport dependencies, interface and genuine source
records. It cannot accept arbitrary registration data or commands from the request.
An inactive request withdraws only registrations owned by that declaration; it
does not disable other discovery services or widen an interface scope.

Discovery observations use `Snapshot.profiles[discovery_id]`; transport and
discovery IDs are disjoint. Their `data` contains `policy_digest` (the resolved
discovery digest), `interface_confirmed` (a boolean), `service_generation`, and
`network_generation`. Include them in observation responses as well as fixed
operation readback. Exact current generations are required for both inactive and
active reconciliation. Complete absence with a confirmed interface permits
activation only after transport dependencies already have verified readback in
the initial snapshot. Unknown, stale, generation-changed or unconfirmed evidence
requests cleanup and inhibits activation until a later complete observation.

The executor processes discovery cleanup before transport operations. Unavailable
cleanup is pending, never reported as successful. Returned unknown or mismatched
readback stops subsequent writes and records a failed journal. Every long-lived
publisher must independently enforce lease age and dependency validity between
coordinator calls; a successful historical receipt cannot keep a record alive.

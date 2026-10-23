# Native camera recording publications

A camera bridge can be reachable, paired, show live video and report motion
while its recording stream remains unreachable. HomeKit Data Stream (HDS) uses a
separate TCP listener negotiated by the application. Fixed UI/HomeKit ports and
Bonjour export therefore do not establish recording-path health.

This is a preservation and qualification contract for an existing service owner,
not a new forwarding implementation or permission to recreate a container. The
current native activation gate stays closed. Site addresses, range values, image
locks, pairing identities and operational evidence belong in the private instance.

## One range, existing owners

For a camera that already uses a bounded guest automatic socket range, express
that range once in `port_ranges`. Reference it from the camera workload's
`automatic_port_range` and from both `ports` and `target_ports` of its native TCP
`published-port` transport. Keep its existing fixed TCP publications and discovery
selection separate. Do not add a PF redirect, UDP publication, reflector or second
lifecycle owner to reproduce a native TCP publication.

The declaration is only part of the contract:

| Layer | Preserved data and owner | Required evidence |
|---|---|---|
| Desired ports | Named range and native TCP transport in the private instance | Exactly the same named host and guest range, no missing ends, remapping, widening or competing claim |
| Container definition | Existing service manager; immutable image, resources, network/MTU, capability set, persistent mount identity, first process and fixed publications | Complete enrolled definition plus kernel/init digests and creation-source parity; a container name alone is insufficient |
| Guest allocation | Existing kernel boot argument and service startup check | Current `ip_local_port_range`, `ip_local_reserved_ports` and full kernel command line; expected effective values, no conflicting override, before the application is accepted healthy |
| Application state | Existing persistent volume and application owner | Pairing/identity records preserved; compare private metadata or hashes without publishing secrets or replacing the volume inode |
| Recovery and provisioning | Existing service manager, retained receipt and shared supervisor | Fresh create and retained-definition paths enforce the same contract; mismatch stops safely rather than silently migrating |
| Transport and outcome | Native runtime publication and real HomeKit client | First TCP connection traverses the host/guest boundary; actual motion produces a saved recording that a person plays in the client |

`kernel_arguments_sha256` and `init_process_sha256` are opaque content pins. They
cannot establish that a running guest applied a setting. Runtime inspection may
omit the kernel arguments; record creation inputs and independently inspect the
current guest command line and effective sysctls. A read failure, empty value or
unknown definition is not parity. The retained runtime observer already reads the
guest automatic range when `automatic_ports` is declared, including for native
TCP publications. It does not independently verify every site-specific startup
invariant or reserved-port setting; those remain the existing service owner's
checks and native qualification evidence.

A Linux automatic range affects automatic **TCP and UDP** allocations for the
whole guest, including outbound connections. A TCP-only publication does not
publish UDP. All guest wildcard TCP listeners in that range are potentially
reachable through the publication, not just HDS; application authentication,
interface binding and token-path behavior must be reviewed. Loopback-only
listeners and persisted listeners outside the range need separate assessment.
Do not widen publication to all ephemeral ports or restrict it to one camera.

## Reporting and acceptance

Starting in 0.4.8:

- `PORT-RANGES` applies to every declared automatic range. For a `camera` with
  such a range it refuses missing, partial, copied-numeric, renumbered or
  UDP-only publication declarations: one native TCP row must use the identical
  named reference on both sides. This is declaration parity, not native proof.
- `PORT-BUDGET` covers each non-alias transport of any automatic-range workload,
  including native TCP publications and its fixed ports. Each profile needs a
  bound `port-budget` record. One private observation may support those separate
  records, but a UDP workload's acceptance cannot stand in for the camera.
- `CAMERA-RECORDING` applies to camera workloads that declare an automatic range.
  It requires tier 5 `playable-recording` evidence with `capture_context:
  host-person`, `profile: null` and the whole current instance contract digest.
  The private record must cover all applicable camera workloads; adding a
  workload or changing its definition invalidates it. The ledger has no
  workload-scoped acceptance reference, so an arbitrary transport or discovery
  profile cannot be substituted. Live view, UI health, motion logs, a recording
  callback or completed service call cannot satisfy this method.

A camera with no declared automatic range does not acquire one, a publication,
or a recording requirement from this change. Its required application behavior
still belongs in the private migration plan. Older schema-1 documents remain
valid: 0.4.8 adds one closed acceptance-method value without changing data layout.
Older readers reject that new value; they must not be used to evaluate a plan
that relies on it. This stricter report adds qualification requirements, not new
packet semantics, admission authority or an automatic migration.

The predecessor's operational acceptance is a baseline. It never qualifies a
new framework/owner revision. Preserve exact source/platform/contract provenance
and keep failed observations. The report checks bound attestations, not their
authenticity or the underlying private capture; human provenance review remains
required. A single playable clip does not prove reboot recovery, cable-change
recovery, sustained live audio/video or representative multi-camera concurrency.

## Staged migration and rollback

1. Freeze the existing service owner, publication definition, startup/receipt
   format, installed hashes and private application identity. Record the whole
   dashboard roster and fresh SEV1–3 health. Preserve an independently reachable
   management path.
2. Compare the candidate in read-only shadow mode. Check the exact retained
   fixed publications and one bounded native TCP range, kernel/init contract,
   volume identity, discovery exports, supervisor and recovery inputs. Shadow
   mode must not bind another copy of the ports or start another publisher.
3. Change one owner only in its separately authorized window, after the normal
   qualification gates. If the service owner is not changing, leave it active;
   migrating Bonjour or root PF does not transfer this native publication.
4. Obtain fresh complete health checkpoints and the required native/application
   acceptance. Preserve pairing; do not create a replacement accessory to pass.
   Schedule motion/playback stimuli separately from passive checkpoints. Missing
   or stale proof blocks retirement, not ordinary service operation.
5. Roll back only the changed owner's pinned code and desired data, preserving
   current holds/pause and application state. Do not remove the working bounded
   publication as a networking rollback shortcut. Retire old files only after
   all live and durable references are gone and recovery/soak gates pass.

See [native procedures](native-qualification.md),
[readiness gates](migration-readiness.md), and the
[staged migration runbook](migration-runbook.md). Offline tests exercise rendering,
current-range refusal, evidence binding and failure cases; they do not play video,
change production networking or prove native qualification.

# Runtime recording projections

These files replay read-only observations collected on macOS 27.0.1 (26A434),
ARM64, using Apple Container 1.2.0 where applicable. Each JSON file carries the
private source capture identifier, original stream hashes, exact transformations,
sanitized stream hashes and limitations. The source capture identifier is the
fixture ID. Original captures stay private; they are not required by CI.

- The three launchd domain projections retain every service row, including
  PID-zero loaded jobs, status grammar, row counts, indentation and block shape.
  Private service names, process identifiers and descriptive values are replaced.
- The API, network-helper and guest job prints retain native job/process grammar
  and nested coalition states. Their paired `ps` receipts use the same synthetic
  account and executable identities. Arguments and environment were redacted
  during collection and cannot validate runtime-start flags or roots.
- The matching guest inspection and network inspection intentionally retain only
  fields used by these replay assertions. They omit application data, environment,
  images, mounts and publication settings. They cannot prove complete enrollment
  or provisioning parity.
- The volume reply preserves the native 24-byte attribute header and replaces the
  private 16-byte UUID. It is stored as hexadecimal text; its original stream hash
  refers to the raw reply, as stated in its transformation description.

`tests/test_runtime_recordings.py` supplies positive grammar replays and explicit
negative controls. The synthetic fault injections in
`tests/test_runtime_evidence_audit.py` are separate from native recordings.
Neither is a native mutation, root/launchd execution, crash/reboot, rollback,
application health or hardware acceptance test. No qualification gate is changed.
The process runner bounds process groups and inherited-pipe waits; a process that
detaches from that group needs its native lifecycle owner's independent fence.

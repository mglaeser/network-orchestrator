# From a release to a private deployment

This walkthrough assembles the implemented framework. It uses placeholder paths
and never supplies real host defaults. Native promotion requires the separately
documented acceptance gates; successful mocked deployment is not that evidence.

1. Obtain a reviewed release and verify its SHA-256 inventory. Install a managed
   Python 3.12–3.14, the hash-locked runtime dependencies and the reviewed wheel
   in an isolated operator runtime. Native Apple Container and Monit remain
   separately installed maintained dependencies. Record their exact versions.
   The independent privileged owner additionally needs a root-owned interpreter,
   package/dependencies and protected ancestors; never run a user virtualenv as
   root. Use that trusted administrator bootstrap before `install-root`.
2. Keep all site data outside the checkout. Author one networking table, private
   runtime settings, optional initial workload recipes, owner bindings, Bonjour
   settings and deployment manifest. Use the schemas/examples for shapes.
   During migration derive from literal existing owner inputs until each setting
   flips to a single new author. Do not retain a competing old schedule/writer.
3. Initialize durable negative intent:
   `netorch init-state --state-dir /operator/state/netorch`. Initial intent is
   paused. If installing genuinely new workloads, explicitly plan/provision
   them with [workloads.md](workloads.md); existing workloads need no recreation.
4. Capture actual enrollment and statically derive contract hashes using
   [apple-runtime.md](apple-runtime.md). Review the complete preserved definition,
   persistent identities and required non-inspectable input receipts. Do not
   manually maintain a duplicate table of these generated fingerprints.
5. Bind the native user reader to `python -m netorch.apple_runtime --settings
   PATH request`, the user discovery endpoint to `python -m netorch.bonjour_owner
   --settings PATH endpoint`, and the independent PF observation to the
   **`root-report`** binding. The report directory is root-owned, traversable and
   separate from root-private state. The file contains only non-secret typed
   evidence. User code cannot modify it or invoke the root writer.
6. Review and admit user publication profiles by exact content:

   ```sh
   netorch review-admission --config /operator/site/network.json --profile camera-web
   netorch admit --config /operator/site/network.json --profile camera-web \
     --state-dir /operator/state/netorch \
     --expected-digest REVIEWED_PROFILE_SHA256 --approved-by OPERATOR
   ```

   Repeat for each intended user publication. This never admits external-root
   policy or resumes pause. Bounded-risk policy also requires explicit
   `--ack-bounded-risk`. The root owner has a separate resolved review/admit
   procedure binding backend, observer, implementation and exact policy.
7. Fill deployment artifact/backend hashes, then render, verify, plan and install
   user scope. Separately prepare the reviewed root bundle and have an
   administrator explicitly install/admit its protected independent PF owner.
   Follow [provisioning.md](provisioning.md) and [pf-owner.md](pf-owner.md).
   Installation alone keeps new content pending and never clears pause.
8. Verify real LaunchAgent identity and native Local Network consent, exact
   interface/publication evidence, PF rule and retained-state behavior, restore
   rehearsal and boot/login behavior. Do not widen ports or privileges to hide a
   failed test. Accepted bounded guest-address risk remains a recorded decision.
9. Resume the appropriate operator records only after promotion. User intent
   never bypasses root intent. The independent root pull activates its own
   admitted policy. Downstream user planning derives root readiness only from
   fresh protected evidence of an actually verified admitted root profile; a
   user-authored root approval is ignored. Bonjour requires its dependencies
   verified in a later fresh cycle before registration.
10. Observe current state with `netorch observe` / read-only `reconcile`. launchd
    runs the small coordinator and supervised DNS-SD owner; Monit handles
    scheduling/recovery checks and uses only reserved status 42 for proven
    stopped recovery. Monit logs use native syslog. The coordinator's
    `--quiet-unchanged` emits only meaningful state transitions, with current
    bounded state in `status.json`; vendor application logging stays with its
    owner. Configure native log retention for the chosen launchd log directories.

There is no second packet transport, mDNS responder, persistent networking
container, all-powerful networking daemon, native TTS service or new application
configuration layer. SSH/SMB/router settings, vendor runtime lifecycle, image
builds, application integrations and secrets stay with their existing owners.
The framework orchestrates their networking contracts and supplies the native
custom adapters needed for publications, redirects, direct DNS/fallback, bounded
UDP returns, selected-record import/export and safe recovery.

Preserve the existing user runtime/application initial startup chain when
migrating a site. Routine all-stopped observations deliberately remain unknown;
networking jobs and Monit do not bootstrap an initially stopped fleet after
login. [Site migration](site-migration.md) separates that maintained startup
owner from networking supervision and the explicit new-install provisioner.

Upgrade, interrupted installation recovery and rollback preserve current pause,
other holders, root admissions and application data. Rollback restores a
verified predecessor's networking jobs/settings; changing code or observer
semantics does not resurrect obsolete root authority. See the executable
transition tables and explicit recovery commands in the provisioning guide.

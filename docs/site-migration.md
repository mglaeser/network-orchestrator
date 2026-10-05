# Migrating a complete existing site

A migration moves networking authority and generated schedules; it is not a
workload rebuild. This runbook preserves the existing application startup chain,
images, mounts, kernel options, application state and native login policy while
adopting one reusable networking framework. Adapt its private tables and record
actual acceptance before retiring an existing owner.

## Responsibility map

| Responsibility | Retained owner | Netorch role |
|---|---|---|
| Account login, FileVault, power recovery and Local Network consent | Native OS/site administrator | Record decisions and acceptance; never change them implicitly |
| Runtime installation/upgrade and session startup | Vendor runtime and existing user startup manager | Accepted version/helper identity and fresh observations |
| Existing application's initial start after login | Existing application deployment/startup manager | Preserve this chain during networking migration; observe enrolled definitions |
| Proven stopped enrolled workload | Explicit user lifecycle adapter under durable gates | Double-check stopped state, start existing name and verify running |
| Genuinely new declared workload | Explicit reviewed initial provisioning | Create missing names only, optionally start initially, then enroll |
| Native host socket publications | Apple Container definition | Exact same-service readback; maintenance handoff for changes |
| Custom scoped redirects/direct ingress/UDP return | Independent protected PF owner | Root admission, fresh target, readback, withdrawal and state invalidation |
| Selected guest export and Apple media import | User Bonjour owner with native Apple stack | Genuine records, precise projection and independent leases |
| Application secrets, pairing, DNS policy, reverse proxy routes and integrations | Existing applications/router | Preserve their settings and data |

Network pause withdraws custom PF exposure and discovery leases. It inhibits new
network activation and guarded recovery. It **does not remove vendor host
publications or stop applications**. A native socket removal/change is an explicit
maintenance handoff, followed by re-enrollment and admission review.

## Cold start and all-stopped behavior

The versioned runtime API can temporarily report all guests stopped during an API
service restart. Routine observation treats that fleet-wide result as unknown;
Monit must not interpret it as permission to start every container. Individual
proven-stopped recovery is different from initial fleet bootstrap.

Preserve the existing user startup manager that deliberately starts the runtime
and applications after the selected login/session event. It must have one owner
and obey the site's separately reviewed runtime-wide maintenance gates. Do not
remove it merely because the framework installs coordinator, Bonjour and Monit
jobs: those networking jobs do not replace initial workload bootstrap.

For a fresh installation, the explicit `workloads ... provision --start-initial`
operation can start validated initially stopped definitions while operator pause
is set. It is a reviewed maintenance action, not a Monit retry or automatic
per-boot bypass. Normal runtime initialization and an unattended-reboot start chain
remain a separately chosen application/vendor-owner procedure.

If no maintained startup chain exists, resolve that architecture decision before
retiring old jobs or promising reboot availability. Specify who starts the vendor
runtime, who starts each workload, what defines completed bootstrap, how root
exposure is gated during pool rebuild and the maximum time to the first valid
resolver answer. The framework does not silently create automatic login or a
root workload runtime to fill this gap.

## Authority migration sequence

1. Inventory existing sources, owned anchors, publications, Bonjour directions,
   bridges, port ranges, launchd/Monit roles and application startup managers.
   Capture protected definition/enrollment evidence and verify recovery material.
2. Derive literal facts and compare generated policy to the actual owner inputs.
   Keep one author per setting. Mark anything requiring script evaluation as
   underivable rather than executing it.
3. Prepare private tables, managed user/root code environments and immutable bundle
   hashes. Keep application state, admissions and negative intent outside releases.
   Use a separate root-owned publicly traversable report directory; root-private
   state and release paths are not report locations.
4. Plan user/root installation without effects. Review every new job and owner.
   Keep the existing runtime/application startup chain in the responsibility map.
5. In the approved window, pause the relevant user and root records, take the
   operation's own suspension and obtain complete owned withdrawal/state readback.
   Stopping a scheduler alone does not prove its rules or registrations are gone.
6. Retire only the replaced networking schedule/writer through its documented
   owner procedure. Do not overlap two PF writers or two Bonjour publishers. Do
   not retire unrelated Login Items, runtime startup or application supervision.
7. Install the new reviewed user/root bundle in separate domains. Root installation
   requires the trusted administrator-owned package and explicit resolved
   admission; user policy cannot grant it. Changed semantics/settings remain
   pending. Preserve current operator pause and unrelated holder suspensions.
8. Confirm native user job identity/consent, protected report visibility, complete
   live runtime/publication evidence, PF grammar/hook/state behavior and exact
   guest allocator range. Fresh root readiness must be independently admitted,
   permitted by current root intent and verified; admission alone is insufficient.
9. Resume only the operator records intended for promotion. Release only the
   migration holder's suspension. Observe independent root activation, then a
   later fresh verified dependency cycle before Bonjour advertisement.
10. Confirm application discovery/reconnect and required physical behavior in
    coordinated tests. Record separately approved reboot/restore evidence before
    claiming unattended recovery. Backend success is not audible-output evidence.

No failed or unknown observation authorizes a broad range expansion, extra
firewall grant, manual application cache seed, root consent workaround or hidden
container recreation. Report missing acceptance and select the relevant owner.

## References and rollback

Installed plists reference immutable release paths. Settings may reference stable
private source/state paths explicitly; they are copied byte-exact, not recursively
rewritten. Check every reference before deleting old files. Retain required
predecessor/recovery material according to the site's separately approved policy.

On failure, preserve the finite installation/reconciliation journal and negative
intent. Use the exact failed/current digest with the documented explicit recovery
or rollback command. Restore only verified owned files/jobs and obtain fresh
runtime/kernel evidence; do not replay stored guest addresses or old packet
states. Returning to the previous publisher also requires the new one withdrawn
and stopped first, so only one owner is active.

A release rollback restores networking code/desired settings. It is not an
application-data restore or permission to clear pause. See
[provisioning](provisioning.md), [PF](pf-owner.md), [Bonjour](bonjour-owner.md),
[runtime](apple-runtime.md) and [evidence tiers](testing.md).

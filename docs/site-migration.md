# Existing-host migration and stop conditions

Version 0.3 implements the read-only extraction stage. No owner is promoted by
this release. Retained 0.2 owner internals and mock installation tests document
future mechanics; native authority-expanding entrypoints are gated. Never replace
a working installed owner merely because a source checkout has a newer version.

## Readiness and inventory

Before a mutation, record exact runtime/Socktainer versions and install methods,
launch context and startup chain; OS build, hardware and Local Network identity;
source and installed hashes; the PF baseline and actual anchor order; admissions,
pause, holder gates and references; Monit status rules and independent application
components. Read-only collection may be incomplete. Unknown protected inputs,
source drift and unavailable kernel evidence remain explicit blockers.

Recovery material must exist off-host and one restore must be rehearsed before
any destructive operation. Unattended reboot/DNS recovery requires an owner
choice about login/power behavior and an external client measurement, not a
networking refactor. Runtime/Socktainer upgrades are separately approved changes,
with pinned versions, a DNS outage window, planned withdrawal before stopping,
application reacceptance and recaptured version-labelled fixtures.

## One author, one owner flip

1. Freeze actual inputs and hashes. Parse JSON, plist, TOML and other literal data
   statically. Hash code without executing it. Mark underivable values instead of
   evaluating scripts or guessing defaults.
2. Keep a generated view while old inputs are authoritative. A re-import check
   must reproduce the committed bytes. This is a view, not a second authority.
3. Compare candidate rendered inputs to frozen installed inputs byte for byte,
   including headers/newlines. The candidates are rendered from the instance by
   `netorch.render`, which uses each frozen literal file as its own template and
   replaces only the mapped values, or by the site's own generator. The
   renderer yields a comparison only for a file whose every value is classified
   as rendered or as the owner's own constant; identical bytes of a file in
   which nothing was replaced prove nothing. Verify current hashes, authoring
   provenance and installed names. No comparison of text establishes packet
   behavior.
4. Before a flip, name the old embedded constants and files it removes, establish
   rules 1–6, and show the synthetic instances still validate. A program is
   hashed and searched, never rendered: one that still holds an address, name or
   path of the instance blocks its owner until the value lives in a literal file
   that the program reads. The search is a tripwire, not a proof. A program that
   computes a name from parts, or holds a single-word name or a port number,
   passes it; what is established is that the literal inputs are reproduced from
   the instance byte for byte and that the program that reads them is exactly
   the reviewed one. A flip is one owner in one reviewed commit, with no
   intentional input difference.
5. After eligibility and a separate approved window, use that owner's established
   suspend/withdraw/readback procedure. Preserve names, state locations, pause,
   unrelated holders, runtime startup, application configuration and one writer.
6. Repeat provisioning must be a no-op. Any behavior difference, namespace/order
   change or new scope is a later declared change with independent admission and
   native acceptance. Remove old files only after proving no running job, launcher,
   kernel image, recovery path or durable gate still references them.

Order: Bonjour; recovery adapter and Monit configuration; each workload in a
separate window, resolver last; root inputs last. No root rewrite or planner-to-root
call is introduced. The current release refuses promotion; this sequence describes
conditions for a subsequent qualified release.

## Planned stop: bounded target or runtime-wide stop

Take the operation's own durable suspension, keeping operator pause independent.
The existing root owner withdraws only its owned rules and, while a state of a
withdrawn rule remains, kills states for the old guest in both directions.
Complete kernel readback must confirm retirement before a workload/runtime
stop. Stop/start remains with the existing lifecycle
owner. Obtain fresh network and workload generations, exact preserved contracts
and current admission. Reapply only allowed admitted content, verify it, and let
discovery require the subsequent verified transport cycle. Release only this
operation's suspension; never clear another holder or operator pause.

Unknown withdrawal, an unavailable reader, an unexpected API all-stopped result
or a failed stop causes an explicit partial state. It cannot authorize recovery,
new exposure, a wider range or speculative rollback. In the root owner the
partial state is a write in doubt, which needs an acknowledgement; a
precondition that is not met before anything was written defers only that
profile to the next pass, with its reason in the owner's journal and report.
The finite withdrawal bound
needs measured scheduling/read/apply bounds; a nominal launchd interval is no
upper bound. Shared-pool direct targets retain signed address-reuse risk.

## Fully served and rollback

A host is fully served only when every owner has exact frozen-input conformance,
no names/state move, all applicable registry requirements have sufficient retained
verified evidence or signed accepted residuals, and its acceptance ladder is
complete. This includes genuine cold application discovery, heard audio where
applicable, client-preserving DNS, port boundaries, lifecycle, restore and
unattended reboot. Synthetic CI proves none of these physical outcomes.

Rollback is owner-scoped to the previously pinned release and instance commit,
under verified withdrawal. Restore only owned code/desired data; preserve current
negative intent and obtain fresh runtime/kernel observations. Application data is
not automatically restored by a networking rollback. If required recovery material
is absent, stop and report that condition. A folder name alone is never authority
to delete files, gates, journals, locks or kernel references.

Native SSH, SMB, screen sharing and unrelated listeners/anchors remain separately
owned. Ordinary guest egress remains vendor NAT. Existing application start-after-
login and management tools remain explicit lifecycle writers; Monit is not a
second fleet-bootstrap loop. Component failure does not default to restarting its
parent workload. See [safety contract](safety-contract.md), [legacy import](legacy-import.md)
and [testing](testing.md).

# Wired adapter replacement and DNS path qualification

A physical adapter replacement can change the BSD interface name while the host
keeps its intended IPv4 address. A resolver answering its published high port
does not establish that incoming LAN port 53 traverses the current PF interface.
The same stale device name can break Bonjour independently of application health.

## Durable policy and observed state

The extraction-stage instance supports an explicit `host.lan.selection` of
`auto-wired`, with `link: wired`, its declared `ipv4`/`cidr`, and
`hardware_id: null`. The selected device name and hardware address are observed
host state, not a second desired setting. Existing instances without `selection`
retain their hardware-identity comparison and serialization. Choosing the new
mode is a declared policy change, not a silent reinterpretation of an old pin.

The shared selector is extracted from the existing native owner helper. It uses
bounded `networksetup -listallhardwareports` and `ifconfig -a` reads. It requires
exactly one occurrence of the intended IPv4 address, an inventoried physical
cabled Ethernet device, active/up/running flags and valid negotiated cable media.
Missing or ambiguous ownership, wireless/virtual links, malformed inventory,
contradictory MAC evidence and invalid link state are refusals. The exact macOS
redacted link-MAC sentinel is unavailable evidence, not a second hardware identity;
the independent hardware inventory must still supply a valid unicast MAC.

There is no default-route fallback, remembered-device fallback, Wi-Fi selection,
MAC spoofing, address assignment, DHCP edit or resolver-policy change. The router
must reserve the intended IPv4 address for the replacement adapter's actual MAC.
Negotiating a slower supported copper link does not by itself change identity.

Read-only preflight supplies a current selection proof bound to the packaged
helper, address and resolved interface. It does not admit policy, run an owner or
prove packet delivery. Stale, missing or incompatible proof blocks readiness.
Native reads are subject to the overall preflight deadline and fixed output limits.

## Extraction and ownership

Until an accepted owner flip, existing owner inputs remain authoritative. Render
the selection token into the existing owner's **policy field**, preserving the
separately declared address. Never render a transient resolved device name back
as durable intent. Static import/render parity must include the helper artifact,
all consuming jobs, install receipts, restore/provisioning paths and host checks.

The retained v0.2 network-policy `scope.interface` is a resolved literal field.
It deliberately rejects `auto-wired`; otherwise PF or `ifconfig` could receive
the token as a device name. It has no dynamic selector adapter. Its activation
gate stays closed. Supporting the data contract in the recommended read-only
workflow is not permission to use those old owners as a replacement.

Each existing PF or discovery owner resolves through its existing reconciliation
cycle. There is one shared selector source, installed as protected copies in the
appropriate authority domains, and no added daemon, watcher or recovery loop.
On identity loss or change, only validated owned rules/registrations may be
withdrawn. Unknown kernel state is an inspection failure, not overwrite authority.
Admission, enable, pause and hold intent survives. PF state can outlive rules;
state retirement and first-packet behavior require their separate qualification.

Adoption and fresh installation are different operations. Where the existing
installer offers `--adopt-wired`, use that reviewed admission-preserving path.
An ordinary `--apply` that also enables a service is not an equivalent substitute.
Never delete a regular-file operation lock, flush global PF rules or restart
healthy workloads to make a forwarding check appear green. Restore must preserve
the dynamic intent, current admissions and prepared application lifecycle guards.

## Required incident regression and native evidence

| Scenario | Offline proof | Native qualification still required |
|---|---|---|
| Adapter name changes, intended address retained | The shared selector chooses the new eligible device; instance intent remains unchanged | Current protected owner copy/readback and all consumer convergence |
| Address absent, duplicated or on Wi-Fi/virtual link | Selector refuses; preflight never reports valid dynamic identity | Only validated owned assets withdraw; independent assets and intent remain |
| Malformed inventory, invalid mask/media/MAC or command failure | Bounded refusal; child cleanup; no route fallback or raw diagnostic leak | Real job/privilege/consent contexts on the qualified OS build |
| Resolver high port succeeds while LAN ingress fails | Green dashboard data never grants native qualification or mutation | Fresh UDP **and** TCP queries from an independent physical LAN client to port 53, correlated with resolver logs showing the original client address |
| Replug, different adapter or reboot | Simulated changes are labeled simulations | Authorized cable/replacement/reboot window, bounded recovery and whole-roster health |
| Bonjour survives adapter change | Selection/render and refusal tests | Current advertisements, cold consuming-application discovery, reconnect and applicable real-client pairing |

For **every** migration step, retain the complete fresh authenticated dashboard
checkpoint and independent LAN DNS evidence before and after the step, after
rollback and during soak. A query from the host, a container, its gateway or the
resolver's high port cannot satisfy the physical-LAN claim. Correlate unique
queries with actual client identities and record observer origin, transport,
destination port, time, generation and outcome privately. No new dashboard check
name is fabricated to stand in for a probe that does not exist.

An adapter change invalidates prior interface-dependent captures, static source
pins and assumptions that actually changed; it does not erase historical evidence.
Re-import and compare current installed inputs. Preserve unrelated application
work and pin the integrated source that includes already-deployed safeguards.
Use the existing [migration readiness gates](migration-readiness.md),
[native procedures](native-qualification.md) and
[health checkpoint contract](migration-health.md). All production qualification
remains explicit and separate from passing replay tests.

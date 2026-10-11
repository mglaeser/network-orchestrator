# Wired adapter incident compatibility review

The reported incident exposed two distinct paths: a resolver could answer its
published high port while physical-LAN DNS and discovery still named an old
adapter. This review preserves the accepted extraction architecture and existing
owners. It does not migrate a host or qualify packet delivery.

## Confirmed findings and disposition

| Finding | Demonstration | Correction and evidence boundary |
|---|---|---|
| Retained `scope.interface` accepted `auto-wired` as a literal device | Nine regression cases failed before the guard; old PF, runtime and Bonjour consumers would receive the token | Reject at the policy boundary before native observation, rendering or state construction. Existing literal policies remain supported; activation stays gated. |
| Instance identity required a replacement-sensitive MAC | Model/schema and report inspection | Explicit optional `host.lan.selection`, with `auto-wired`, wired link and null hardware pin. The selected interface is observed state. Golden legacy instance, transport and discovery digests remain unchanged. |
| Read-only identity collection alone did not prove physical wired selection | Inactive Wi-Fi and bridge counterexamples to the legacy address parser | The explicit new mode invokes the extracted shared native selector. No route fallback or inferred identity from unrelated reads. Legacy collection is not promoted to dynamic selection evidence. |
| Malformed netmask accepted by the existing helper | Invalid dotted-mask replay selected the interface | Validate contiguous masks before accepting inventory; exercise malformed and noncontiguous inputs. |
| Media substring accepted invalid native evidence | `none 1000baseT garbage` selected an interface | Anchor supported negotiated-media grammar, including legitimate lower-speed and direct/autoselect forms. |
| Failed bounded read could leave its child unreaped | Oversized-output child was reaped only by a later wait in the reproducer | Kill and reap the exact owned child before returning failure; keep the outer managed deadline and process group. |
| Auto-wired declaration and selector address domains differed | Reserved address declarations validated but could never be selected | Share the canonical unicast predicate and refuse impossible new-mode declarations early. |
| Distribution and runtime versions disagreed | Project metadata declared 0.4.3 while CLI code declared 0.4.2 | Align both to 0.4.4 and test distribution/runtime/CLI consistency. |
| Dashboard health could be mistaken for physical path acceptance | Synthetic checkpoint with successful published-port checks still cannot establish LAN delivery | Preserve false native/mutation/provenance claims; require independent physical-LAN UDP/TCP53 and original-client evidence beside every migration checkpoint. |

The candidate helper is extracted, not a newly designed discovery or recovery
owner. Its source provenance and deliberate hardening differences are in the
[resource documentation](../../platform/macos/network/README.md). Updating the
framework package does not replace protected or user-installed owner copies.

## Test and data inventory

- `test_reserved_interface_policy.py`: malformed configuration refuses before
  CLI, PF, runtime and Bonjour effects; ordinary literal fields retain meaning.
- `test_auto_wired_instance.py`: closed policy shapes, legacy bytes/digests,
  same-policy adapter changes, fresh proof consistency and incompatible artifacts.
- `test_auto_wired_preflight.py`: fixed packaged command, bounded deadlines,
  unknown/refusal states, no literal-token invocation, no raw-output leakage.
- `test_auto_wired_import_render.py`: actual import, projection, reimport and
  byte-identical owner rendering; address-only changes preserve the selector
  policy and a resolved device name cannot become the durable policy.
- `test_wired_recorded_evidence.py`: paired sanitized native hardware/link
  recordings; pure selector replay; explicit synthetic corruption/replacement;
  failed-child cleanup and package resource contract.
- `test_wired_migration_health.py`: published checks cannot grant native authority
  or substitute for differently named required client probes at any phase.
- `test_release_version.py`: distribution and running-code identity agree.

Both new recordings retain original-byte hashes, sanitization descriptions,
platform/context metadata and limitations. They are loaded through the existing
per-test evidence tracker and replayed by every PR's full macOS matrix. Python
coverage does not measure Perl branches. Native inventory replay is parser
evidence, not a physical interface interruption, root readback or application test.
The existing complete suite, source/evidence inventory, privacy checks and
installed-wheel checks remain required; the wheel smoke includes the Perl resource.

## Migration disposition

Keep current source and installed artifact comparisons in the private dossier.
Reproducible imports from an older checkout are historical evidence if newer
integrated owner sources are installed. Preserve application lifecycle safeguards,
operation locks, enable/admission/pause intent and independently owned services.
Use admission-preserving adoption rather than an ordinary apply that also enables
a service. Do not repin old effective inputs or promote cached health to acceptance.

The new read-only policy does not implement dynamic selection in retained v0.2
owners. An actual owner extraction still requires byte/consumer parity, protected
artifact verification and all applicable [native gates](../native-qualification.md).
The qualified platform matrix remains empty. Router reservations, physical-client
DNS, original client identity, shared application discovery, pairing, cable
replacement, restore and reboot are not established by this repository review.

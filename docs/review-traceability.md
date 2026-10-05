# Review requirements implemented as framework contracts

The design incorporates an independent review without distributing that review's
private installation details, ownership statements, packet captures or addresses.

| Concern | Framework response | Proof tier |
|---|---|---|
| Reused guest address plus retained states | Generation-fenced plans; retire and drain before replacement; bounded-risk declaration | Pure/mock plus required physical owner acceptance |
| Admission reused after widening scope | SHA-256 over exact resolved policy, scope, owners and service contract | Mutation/property tests; external root enforcement required |
| Planner becoming root authority | External-root process binding forbidden; live executor returns handoff | Mock/client/static contract tests |
| Reboot/login dependency | Explicit deployment gate; no automatic-login/runtime change | Deployment documentation; hardware acceptance |
| Runtime upgrade/provenance | Record and pin accepted runtime/owner release before fixture freeze | Deployment matrix; separate maintenance procedure |
| Pause cleared by recovery | Independent operator pause and holder-owned suspensions; no TTL | Hypothesis state-machine tests |
| Unknown causes recovery | Three observation states and closed reasons; no recovery operation | Pure/reader/timeout tests |
| Catalog adds competing authority | Static source derivation; byte-equality check; one source flipped at a time | Derive/schema tests |
| Local Network consent denial | Closed denial reason and deployment gate; no root workaround | Adapter fixtures; real user-session acceptance |
| Coincident port treated as provenance | Exact source service/generation/publication matching | Collision/ambiguity fixtures |
| Records outlive failed passes | Wall-clock freshness and record caps independent of pass counts | Injected-clock/flood tests |
| UDP reverse-redirect regression | Split NAT/target-less RDR preview and same range contract | Pure preview plus mandatory first-packet hardware test |

Portable CI does not close hardware gates. The package does not promise an
absolute no-misdelivery guarantee on a shared dynamic address pool, production
Bonjour parity, successful application reconnection or audible playback. These
claims require accepted owner behavior and real platform/client evidence.

Support a released native/vendor alternative when it can replace a custom
responsibility with a complete tested contract. Reevaluate at runtime upgrades:
physical-LAN attachment, reserved addresses, reliable events and supported
pre-login startup may remove existing workarounds.

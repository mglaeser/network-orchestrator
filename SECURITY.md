# Security policy

## Supported versions

The latest unretracted `0.1.x` release receives fixes. This project is alpha;
release and model tests do not certify a native owner or a production deployment.
Use a reviewed tagged revision and locked dependencies. Recheck platform and
provider compatibility before upgrading.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** control on this repository when private
vulnerability reporting is enabled. If that control is unavailable, open a public
issue containing only a request for a private reporting channel; omit exploit
details and private installation data until a private channel is available.

Provide the affected revision, environment class, trust boundary and a synthetic
reproduction. Never attach credentials, real provider bindings, private network
snapshots or packet payloads publicly. The project does not promise a response
time or a bounty.

## Trust boundaries

- Policy is untrusted data. Duplicate keys, unsupported schema versions, unknown
  fields and nonfinite numbers are rejected. Bundled schemas are used offline.
- Provider bindings are explicitly trusted executable paths controlled by the
  installing operator. They are not supplied by a network advertisement or policy
  record. Treat a provider as having the authority of the account running it.
- The unprivileged executor never calls an external-root owner. Such an owner must
  validate its own admitted content, observations, gates and readback independently.
- Anyone with container-runtime API control can affect the runtime's observations.
  Admission does not turn a user-controlled runtime into an independent identity
  authority.
- Direct rules to dynamic shared-pool addresses have residual risk unless a
  structural boundary prevents reuse. Fresh polling alone cannot prove an absolute
  never-misroute claim.
- Historical receipts and cached observations are not kernel truth. Unknown
  observations must remain visible and must not trigger recovery.
- Discovery requests carry resolved policy, its exact digest and expected service
  and network generations. An existing user publisher must independently verify
  eligible records, interfaces and transport dependencies. Unknown publisher or
  interface evidence must not authorize publication. Netorch supplies no DNS-SD
  stack and cannot certify a private publisher from process exit status alone.
- Admission hashes bind data, not arbitrary future implementation behavior.
  Transport or discovery semantics must change their digest strategy/schema
  version or use an independently enforced versioned owner implementation
  contract. An old approval must not silently acquire new meaning.

## CI and release security

Public CI uses ephemeral hosted Linux/macOS runners, minimal token permissions,
full SHA action pins and hashed dependencies. It receives no production secrets
and cannot deploy a native service. Fork pull requests must never run on a
production self-hosted runner. Privileged workflow events must not check out
untrusted code.

Dependency and action updates require review. Generated fixtures must be
sanitized; synthetic fixtures must be labelled synthetic. A release intended for
production additionally requires the site's hardware acceptance and independent
owner review described in the deployment guide.

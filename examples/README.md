# Synthetic deployment starters

These files describe one coherent **example**, using RFC 5737 documentation
addresses, synthetic paths and reserved `example.invalid` image names. They
contain no enrolled machine facts and are not production-ready settings.

| File | Role |
|---|---|
| [network.json](network.json) | Desired service, scope, port and discovery policy |
| [network-dns-fallback.json](network-dns-fallback.json) | Optional direct DNS strategy with an exact native publication fallback |
| [runtime-settings.json](runtime-settings.json) | User runtime observer/account, network-helper identity and enrolled workload contracts |
| [owner-bindings.json](owner-bindings.json) | User process bindings plus a read-only protected root-report binding |
| [forwarding-settings.json](forwarding-settings.json) | Independently scheduled root owner and its own complete protected observer settings |
| [workloads.json](workloads.json) | Optional explicit initial workload creation recipes; not automatic recovery/recreation |
| [deployment.json](deployment.json) | Release artifacts, launchd jobs, monitoring and persistent installation boundaries |

Every all-zero SHA-256 and `device: 0` / `inode: 0` is a placeholder. Replace
image digests, backend/artifact hashes, configuration fingerprints and persistent
filesystem identities with verified values. The repeated-letter service hashes
in `network.json` are also synthetic and must be derived from actual enrollment.
Passing a shape loader does not approve these placeholders or establish reachability.

Start from copies in a private site directory. Adapt service/container names,
UID/GID/home, interface/address/subnets, workload mounts, executable paths and
the existing runtime network. The synthetic helper label
`org.example.vendor-helper` is **not** an Apple launchd label: inspect the actual
vendor helper and replace its domain, label, executable and UID consistently.
Runtime/helper executables used by root must live under protected root-owned
ancestors; the `/Library/ExampleVendor/` paths illustrate that separate boundary.

For existing workloads, the explicit read-only `netorch.apple_runtime enroll`
command captures the real container configuration fingerprints and mount
identities. `derive-policy` then produces matching service contract hashes.
Neither operation admits networking or replaces containers. Copy the reviewed
enrolled runtime settings into `forwarding-settings.json`'s `observer` object;
root must observe independently rather than trusting the user's live report.
Hash the shipped PF backend and final artifacts, then adapt the deployment
manifest. When using the provided manifest, save `owner-bindings.json` as its
referenced private `bindings.json` artifact. Protect that file at mode `0600`.

The optional workload recipes generate publications only from the policy table;
there is no second port list in recipes. Their CPU/RAM values and the media
service's automatic UDP range are examples to review for the actual workload.
Use supported digest-pinned ARM64 images and cache them through explicit vendor
operations before planning initial creation. Existing definitions are preserved
only when their complete enrolled fingerprint agrees. An operator must review
the exact resolved provisioning digest; no recipe is an instruction to modify a
running application.

See [deployment](../docs/deployment.md),
[runtime enrollment](../docs/apple-runtime.md),
[independent PF ownership](../docs/pf-owner.md) and
[Bonjour ownership](../docs/bonjour-owner.md) for the complete boundaries and
acceptance requirements.

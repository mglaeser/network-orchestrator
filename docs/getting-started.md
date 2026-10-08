# Read-only host workflow

This release does not install or activate networking owners. The native-qualified
support matrix is empty. It can validate a new synthetic instance and inspect an
existing host without local-network traffic or owner calls. The later promotion
path is in [site migration](site-migration.md).

Install the reviewed wheel and hash-locked dependencies in managed Python
3.12–3.14. Keep the public framework, private instance repository and local host
state in separate locations. Pin release version, artifact SHA-256, source
revision, dependency-lock hash and schema version in the private instance.
[The release pin](instances.md#the-release-pin) says where each of these values
comes from and how to rebuild the wheel from the tagged commit.
The synthetic example deliberately has placeholder release hashes and no native
acceptance; it is not a deployment default.

```sh
netorch-host validate --instance examples/instance.json
netorch-host plan --instance examples/instance.json
netorch-host report --instance examples/instance.json
```

All seven verbs are read-only: `validate`, `preflight`, `status`, `plan`, `check`,
`report` and `supervision-gaps`. `check` exits nonzero while requirements are
unfulfilled, and `supervision-gaps` while the instance states a supervision member
that the retained supervisor cannot honour. The host
command refuses root and never calls an owner, Bonjour or a local-network socket.
No verb installs, admits, resumes, restarts or applies anything. `--collect-local`
is an explicit option for preflight/status/report only, using a fixed bounded
macOS command set. It does not accept commands from instance data and records
inaccessible facts as unknown rather than invoking sudo or requesting consent.

Use `--data-dir` for content-referenced workload contracts; `--evidence` reads a
closed retained host-evidence document. Only `preflight --collect-local
--emit-evidence` prints one; the ordinary output of every verb is a report and
is not accepted there. `--framework-artifact` plus
`--dependency-lock` verify release material, and `--evidence-dir` resolves retained
acceptance evidence. Hashes alone do not prove administrator approval or native
behavior. See [instances](instances.md) for exact formats and command examples.
The two release options compare the pinned files on disk with the pin; they do
not establish that the running package was installed from them.

For an existing host, import literal owner inputs statically; never source a
legacy script. The generated view must re-import byte-identically. Executable
inputs are underivable and missing protected inputs stay unknown. Do not author
a second competing networking file. Pin current installed names, paths and
source hashes, and record installed/source differences before considering a flip.

For a new host, author the instance directly from the closed schema. Supply only
static choices and contracts: no live guest/receiver IPs, shell, templates,
conditionals, executable paths or secrets. The synthetic bounded and structural
variants prove schema independence only. The framework is macOS-only; the
candidate runtime is Apple Container 1.5.0 on the named macOS build, not a claim
that this combination is hardware-qualified.

The retained 0.2 owner internals, renderers and temporary mock installers are
regression mechanisms. Their public native activation/admission/install/recovery
entrypoints refuse in this release. Production owners already installed on a
host remain in place. A later owner migration needs a separately reviewed
release, exact conformance and that host's acceptance; no override flag grants it.

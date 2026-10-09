# Explicit initial workload provisioning

> **0.3 stage boundary:** this guide describes retained owner mechanisms and mock
> contracts. Native authority expansion is unavailable while the accepted support
> matrix is empty. Existing installed owners stay in place; see
> [read-only workflow](getting-started.md) and [migration gates](site-migration.md).

`netorch.workloads` provides an operator-only path to create a fresh installation
from private recipes. It is separate from the networking executor and Monit
recovery. It never stops, deletes, replaces or silently recreates a container.
Existing full native configuration must match its enrolled fingerprint before
it is retained or explicitly initially started.

## Data instead of setup scripts

The bounded closed recipe has `schema_version: 1` and a `workloads` array. Each
row contains `service`, an immutable digest-pinned `image`, typed `options`
(`flag`/`value`), and literal process `arguments`. Flags are a fixed supported
allowlist. Identity, platform, network and published ports are generated from
the existing policy/enrollment tables. A recipe cannot override `--name`,
`--network`, `--platform`, `--publish`, run `--rm`, or supply another executable.
Environment inheritance is forbidden; literal `KEY=value` input is required.
No shell, `eval`, command substitution or executable configuration is used.

Resources, entrypoint, process arguments, DNS, bind mounts,
kernel and kernel arguments can be preserved in the private recipe. Mount sources must
match the enrolled persistent identities exactly. Kernel and environment-file
inputs need hashed receipts. Custom init images also need immutable digest pins.
`--kernel-arg` is accepted on each reader version: the vendor's `create` defines
it at 1.2.0, 1.4.1 and 1.5.0. The vendor CLI has no sysctl option, so `--sysctl`
is refused; a guest sysctl that must hold from boot can be written as the Linux
boot parameter `sysctl.<name>=<value>` in a kernel argument.

An environment file is held to the same rule as `--env`. The vendor's `create`
reads a line without `=` as a bare name and gives it the value that name has in
the environment of the calling process
([`Parser.envFile`](https://github.com/apple/container/blob/1.5.0/Sources/Services/ContainerAPIService/Client/Parser.swift#L145-L225),
the same text at tags 1.2.0 and 1.4.1). This package runs the vendor's tool with
`PATH`, `LANG`, `LC_ALL` and `HOME` only. Such a name therefore takes one of
those four values or, unless the tool's own process has set that name, nothing;
no other variable of the operator is inherited. In neither case does the guest
receive what the file seems to state. `plan` therefore reads every environment
file a recipe names, at most 1 MiB and only when its bytes are the ones its
receipt hashes, and refuses the plan unless each line is blank, a comment or
`NAME=value`:

- The file is UTF-8 without a byte order mark or a null character. A line ends
  at a line feed, a carriage return, a line tabulation, a form feed, U+0085,
  U+2028 or U+2029, where the vendor's parser cuts it.
- Leading spaces and tabs are ignored. A line that then begins with `#` is a
  comment.
- A name is one or more printable ASCII characters without a space or `=`. The
  value is everything after the first `=`, unchanged: quotes stay and nothing
  in it is a comment.
- What the vendor would read differently or refuse only at creation is refused
  here: other white space before a name, a name outside ASCII, and a `#` or `=`
  directly followed by a combining mark, a joiner, a modifier or any other
  character outside ASCII that is not a plain letter, digit, punctuation mark,
  symbol or space. The vendor's parser reads a combining character together
  with the sign before it as one other character, so that `=` is none for it.

The refusal is the command's redacted error. No line, name or position is
shown, since the file may hold secrets.

A recipe cannot publish a host socket: `--publish-socket` is refused. While the
vendor's `create` builds its configuration it removes an existing file or
directory at the host path, unless that is a socket, and creates missing parent
directories; a row naming a data directory would delete it. No enrolled identity
binds that path yet. An existing definition that publishes a socket is still
fingerprinted, observed and retained; only creating one from a recipe is refused.

Normal application secret storage stays with its existing application. A private
recipe may contain a secret environment value, so recipes and journals are
never public artifacts. The plan displays only names, actions, start mode and
content digests; it omits native argv and environment. The network policy itself needs
no application secrets.

All referenced images must already be in the native cache. Image retrieval is
an explicit preparatory vendor step, using the site's approved digest/registry
policy. Initial creation does not silently upgrade the runtime or images.
`plan` looks up the image of every recipe and each custom init image with the
vendor's `image inspect` and refuses unless the answer is exactly one image; the
vendor's `create` fetches both in the same way
([`Utility`](https://github.com/apple/container/blob/1.5.0/Sources/Services/ContainerAPIService/Client/Utility.swift#L94-L131),
the same lines at tags 1.2.0 and 1.4.1). That command leaves the init image named
by the runtime's own configuration out of its listing
([`ImageInspect`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerCommands/Image/ImageInspect.swift#L53-L67)),
so a recipe that names that image is refused; leave the option out. The init
image and the kernel that `create` takes when a recipe names none are not
looked up.

A listed image shows that its name is in the local store, and no more than
that. It does not show that the content for the platform is complete: the
vendor's `fetch` finds an image by name, then asks for the configuration of the
platform `create` wants, and pulls when that content is missing
([`ClientImage.fetch`](https://github.com/apple/container/blob/1.5.0/Sources/Services/ContainerAPIService/Client/ClientImage.swift#L354-L378)),
while `image inspect` lists such an image all the same and leaves out the
variants it cannot read
([`toImageResource`](https://github.com/apple/container/blob/1.5.0/Sources/Services/ContainerAPIService/Client/ClientImage+ImageResource.swift#L26-L43));
a pull can be limited to one platform
([`ImagePull`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerCommands/Image/ImagePull.swift#L41-L55)).
Nor does it show that the stored image has the digest its name carries: the
vendor's `image tag` gives an existing image any reference that parses, one in
digest form included
([`ImageTag`](https://github.com/apple/container/blob/1.5.0/Sources/ContainerCommands/Image/ImageTag.swift#L38-L44),
[`ImageStore.tag`](https://github.com/apple/containerization/blob/0.47.0/Sources/Containerization/Image/ImageStore/ImageStore.swift#L205-L215)).
A download during the bounded `create` is therefore not excluded. What the
lookup does refuse is a recipe whose image, or custom init image, is not in the
store under the name the recipe gives.
Every native invocation remains bounded, including failures during creation.

## Plan and deliberate activation

```sh
python -m netorch.workloads --settings /operator/site/runtime-settings.json \
  --recipes /operator/site/workloads.json plan --start-initial
python -m netorch.workloads --settings /operator/site/runtime-settings.json \
  --recipes /operator/site/workloads.json provision \
  --expected-digest REVIEWED_PROVISION_SHA256 --start-initial
```

Use the returned `provision_digest` for `--expected-digest`. It binds the recipe,
entire network policy, runtime settings/enrollment, resolved native creation
arguments and explicit initial start mode. A change to ports, host addresses,
network names, paths, resource flags, compiler semantics or start mode therefore
requires a fresh reviewed plan. `recipe_digest` identifies only the authored
application recipe and cannot authorize provisioning. To create stopped guests,
omit `--start-initial` from both commands; approval of a stopped plan cannot
authorize a start. No raw argument or secret value is returned with either hash.

Provisioning must run as the enrolled unprivileged operator. It requires an
existing durable operator pause and no competing suspension or service hold. It
first verifies the entire plan, actual vendor version/network/helper and all
persistent identities. It takes its own holder-owned suspension and journal.
Every write has a fresh target/inventory/identity check. Missing names are
created stopped; `--start-initial` deliberately starts these or validated
existing stopped names even when initial fleet state is all stopped. Before
each start, a fresh inspection must still show the expected configuration and
stopped state. The same current-handler and historical-handler launchd absence
proof used by recovery must succeed across system, GUI and user domains, then
complete domain inventories are reread immediately before the vendor start.
A surviving idle job, unknown inventory or job that reappears at that fence
blocks the start and preserves the failure journal and suspension. These reads
bound a race; they do not make an external service manager transaction atomic.
Monit
cannot invoke this bootstrap path; its own start rule reaches a fully stopped
fleet only where the runtime settings declare
[`fleet_start`](apple-runtime.md#starting-a-fully-stopped-fleet).

Already-running enrolled containers are retained with zero lifecycle changes.
Unexpected names, changed resources, different mounts, duplicate names or
unknown running state stop the operation. A successful vendor exit must be
followed by actual stopped/running readback. Newly created definitions must be
captured and re-derived through enrollment before any network admission.

On success, only this operation's suspension is released; operator pause remains
set. No automatic admission or resume happens. On partial failure, remaining
writes stop and the private journal plus operation suspension remain. No new
container is deleted and no previous application is restarted as guessed
rollback. Inspect actual state and reconcile its recipe/enrollment before
explicitly acknowledging the recorded interrupted operation:

```sh
python -m netorch.workloads --settings /operator/site/runtime-settings.json \
  acknowledge --expected-digest INSPECTED_FAILED_PROVISION_SHA256 \
  --holder EXACT_RECORDED_PROVISION_HOLDER --phase failed
```

The digest, holder and phase must exactly match the protected
`workload-journal.json`. Use `--phase applying` only after inspecting an
interrupted process that left that phase recorded. Acknowledgement needs the
enrolled user, existing state store and durable operator pause; it requires no
recipes or policy reload and performs no native operation. It preserves completed
rows, records the inspected phase, releases only the exact `initial-provision`
holder and retains every other hold plus operator pause. It never deletes,
starts, repairs or rolls back a container, admits exposure or resumes the site.

Acknowledgement is persisted before releasing its hold. If that final intent
write fails, retry the exact command while its recorded holder remains present.
After acknowledgement, a newly reviewed provisioning plan may proceed only when
all competing holds have also been resolved by their respective owners.
`netorch acknowledge-journal` is for the networking executor's separate journal;
it cannot acknowledge a workload provisioning run.
The framework intentionally has no destructive automatic workload rollback.

For a change to an existing application's definition, use its maintained private
deployment/recovery manager under the same operator pause and maintenance gates,
then reenroll it. The network installer preserves mounts, image, resources,
kernel arguments and app data. This distinction is what prevents a port-policy
edit from becoming an unreviewed application replacement.

A workload contract of the read-only instance model can describe a definition
that this path cannot create, such as one with a named-volume mount, because a
recipe takes absolute bind sources only; describing a definition does not make
it creatable.

The seven-workload end-to-end tests exercise the actual initial-create/start,
enrollment and observation path with a fake native command transport. They also
cover retained workloads, partial creation failure, pause preservation,
unapproved recipes, closed flags and secret-free plans. They perform no actual
network operations, audio or privileged native commands.

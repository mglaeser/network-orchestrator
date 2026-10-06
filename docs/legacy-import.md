# Existing-owner migration and byte conformance

Existing installations begin with a generated view, not a second hand-edited
settings table. Import, validation, planning, conformance and privacy checks are
read-only development tools. They never source shell, invoke a legacy manager,
register Bonjour, open a local-network socket or install/start/reload anything.
Successful CI does not authorize a production owner migration.

## Import sources without execution

`netorch.legacy_import.import_sources(manifest)` reads a bounded, versioned local
evidence manifest. Each source has exactly `id`, `owner`, `path`, `format`,
`sha256` and `mapping`; the outer object has exactly `schema_version: 1` and
`sources`. IDs are distinct lowercase identifiers. Paths are local evidence
paths; they are not executable paths in the instance model. A non-null SHA256
pins the exact source bytes; a changed pin refuses import rather than silently
accepting a new owner contract.

Formats are closed JSON, XML property-list data, TOML, literal assignment files,
and literal data lists. Only explicit source-JSON-pointer to destination-pointer
mappings are emitted. Duplicate JSON/plist keys, duplicate TOML/assignment keys,
unsupported types, oversized/deep input, malformed text and unavailable mappings
are refused or represented as underivable. The pointer subset deliberately
excludes escaping, empty segments and ambiguous array indices.

Property lists require complete dictionary/array/scalar structure. Text outside
scalar values cannot be silently discarded; scalar elements cannot contain child
elements. Date and binary-data objects are outside the JSON projection contract
and are refused before the standard-library decoder runs.

Assignment files and data lists are read the way a line-feed-delimited reader
reads them: only a line feed ends a line and only spaces and tabs are trimmed.
A carriage return, form feed, NEL or any other control or line-separator
character makes the whole file underivable. If such a character were treated as
a line break, text that the owner reads as part of a comment could be imported
as a setting. A bare literal consists of letters, digits and `: / . _ - @`, so a
digest-pinned image reference needs no quotes. A property list must contain
exactly one root object; a second one is refused, not silently preferred.

Literal assignment data contains only comments, blank lines and standalone
assignments with quoted or bare literals. A key is a name of ASCII letters,
digits and underscores that does not begin with a digit. Upper and lower case
are both accepted and are significant: `port` and `PORT` are two keys. A
prefixed line such as `export NAME=value`, a space beside the `=`, variable
substitution, command substitution, sourcing, function bodies, conditionals,
executable statements, shell escapes and expressions are underivable. The
entire file must be a literal data file: extracting one plausible assignment
from executable code could mistake a test/default/conditional value for
production settings.
`source-inventory` records the full executable's digest and an explicit
`executable-source-not-evaluated` issue; it cannot map settings.

Credential/environment selectors and nested credential/environment objects are
rejected, including common camelCase, acronym, separator and API-key spellings.
Unmapped source fields are not copied. Diagnostics contain a closed
reason, source ID and optional selector, never the source body or parser error
text. Operators must still select sanitized owner inputs: this is a static
migration boundary, not a secret detector for arbitrary mislabeled data.

Every capture is a bounded, regular, single-link file read with `O_NOFOLLOW` on
the final component and matching device/inode/UID/GID/mode/link count/size/times
before opening and after reading. Parent directories may be site-managed; these
captures do not confer privileged trust. No captured kernel state, live guest
address, receiver address, PF token, lease or receipt becomes desired data.

The result separates mapped `values`, exact `sources` digests and `underivable`
records. `owner_digest(owner)` hashes the source-ID/digest list in sorted order.
`generated_bytes(result)` is the canonical report plus exactly one LF.
`check_generated_view(manifest, report)` freshly imports and compares those bytes
exactly. Even an otherwise equivalent source whitespace change changes the
source receipt and therefore fails the re-import gate.

`project_instance(result, template)` fills explicitly available null slots,
rejects unresolved inputs, and invokes the independent closed instance parser.
It cannot fill authored values, relax a schema, insert code, or create an
accepted decision. Any mapped destination under `decisions`, `acceptance`,
`deviations`, `authoring` or `framework` is refused, even where the template
holds a null slot: signatures, acceptance records, provenance and the release
pin are written by a person. A partial generated report is useful evidence; it
is not a complete or approved deployable instance.

A literal file holds text only. Where the instance schema admits nothing but an
integer in the destination slot, mapped text in plain decimal form (digits
only, no sign, no leading zero, at most ten digits) is converted to that
integer; any other text for such a slot is refused and the error names the
field. The instance parser still checks the field's range. Nothing else is
converted: digits mapped to a text field stay text, and text never becomes a
Boolean. The generated view keeps every value as it was read.

## Flip only one owner with exact parity

`netorch.conformance.compare_artifacts(manifest)` compares explicit captured and
already-rendered data files. Its local manifest contains exactly
`schema_version: 1`, `owner` and a bounded `artifacts` list. Every artifact has
`id`, `captured` and `rendered`. It does not invoke the renderer. Reported values
are hashes, sizes and an `identical` Boolean, never input contents. `captured`
and `rendered` must be two different files: a manifest that names one file in
both roles, under any spelling of its path, is refused. Every comparison records
the manifest's `owner`. File identities come from the descriptors whose bytes
were read, so replacing a parent link afterwards cannot substitute another
identity. Captured and rendered roles remain disjoint across the entire manifest;
swapping two captures into each other's rendered slots is also refused.

`promote_owner(instance, owner, import_result, comparisons)` requires:

1. One generated authoring record for that owner, including closed sections and
   stable subjects, with the freshly captured aggregate source digest.
2. No underivable source for that owner.
3. Every source ID compared exactly once by a comparison made for that owner,
   its capture digest equal to the fresh source receipt, and identical
   captured/rendered bytes. A comparison made for another owner, or for none,
   promotes no one.
4. A provenance-only change to `mode: authored` and `source_sha256: null`.

`check_owner_flip(before, after, owner)` rejects any accompanying desired change,
rename, state movement, unrelated owner flip or subject change. Full instance
schema validation remains required. Comments, ordering, whitespace, final LF
and headers are part of byte identity; a header-only change must be a separate
later declared and accepted change. Source inventory that shows installed and
repository owners differ is a migration blocker, not permission to overwrite
an installed owner with older repository code.

The tools prove source/output conformance only. They cannot establish kernel
rule order, listener identity, packet delivery, device discovery, audibility,
capacity, data recovery, unattended login or reboot acceptance. Those remain
separate requirements and evidence-ledger records.

## Privacy guards in both repositories

`netorch.privacy.scan_framework` performs a generic framework check for private
IPv4 literals, IPv6 literals, hardware addresses, chosen interface names, home
paths and site-like reverse-DNS namespaces. RFC5737 documentation networks,
loopback and native Apple namespaces are distinguished from private instance
values. A value that ends a sentence is reported like any other; a following dot
joins it to a longer token only when another component follows the dot.

Private IPv4 includes the shared address space of carrier-grade NAT (RFC 6598),
which overlay networks commonly use. An IPv6 literal is reported when it lies in
global unicast, unique-local (RFC 4193) or site-local space, or is the
IPv4-mapped form of a private IPv4 address. The RFC 3849 documentation prefix,
loopback, the unspecified address, link-local and multicast addresses are not
reported. Neither is a literal in space that is not assigned for unicast use: no
host has such an address, and ordinary code reads the same way (the slice in
`values[1::2]`, the scope in `ab::cd`). A hardware address is six or eight
two-digit octets joined by colons, or by hyphens when a hexadecimal letter
occurs (six decimal pairs joined by hyphens are a date and time). It is reported
with kind `hardware-address` unless it is locally administered, a group address,
all zero or in the six-octet RFC 7042 documentation range `00:00:5e:00:53:xx`.
Fixtures use exactly these unreported forms.

The generic check does not detect host names under `.local`, or reverse-DNS
names whose first label is not one of `me`, `com`, `net`, `org`, `io`, `dev` and
`app`. In code the same shapes are attribute access (`self.local`,
`de.strip()`), so such patterns would report far more code than host data. The
instance pass knows the chosen names and namespace and searches for exactly
those.

An instance's CI additionally
uses `instance_literals(instance)` to scan its pinned framework for its own
addresses, stable adapter identity, home path, network/name pins, namespace,
workload names and range endpoints. Low-entropy chosen port literals require
careful, narrow exceptions; they are not automatically ignored.

Provide the VCS tracked-file inventory for CI. The fallback tree walk prunes only
tool/build state and refuses unchecked symlinks, oversized/non-UTF8 files,
excessive files/findings or more than 64 MiB of aggregate text. Exceptions name
an exact relative path, one kind, a written reason and the exact value SHA256. The public synthetic
example and the platform contract have explicit, reviewed exceptions; no
private site folder or broad directory exemption belongs in framework CI.
Findings contain relative path, line, column, kind and SHA256 of the matched
value, allowing repair without echoing private information into CI logs.

Tests use synthetic documentation addresses and temporary files. They cover
closed parser shapes, duplicate/unknown/deep/oversize inputs, source changes,
no-eval behavior, ambiguous captures, secret selector rejection, exact header
and newline differences, complete per-owner parity, provenance-only promotion,
privacy refusal and narrow exceptions. None performs a native network test or
production owner operation.

## Runnable CI checks

Run the public guard from a framework checkout:

```sh
python -m netorch.privacy_check --root . --exceptions schemas/privacy-exceptions.json
```

The entry point invokes only fixed local `git --no-pager -c
core.fsmonitor=false -c core.hooksPath=/dev/null ls-files --cached --others
--exclude-standard -z` metadata, bounded to five seconds and 4 MiB. It checks
tracked files even if their names are now ignored, and checks nonignored candidate
files before commit. It does not inspect ignored host state or execute a Git hook,
filter, shell or network command. The checked-in exception data names finite
file/kind/value-SHA256 pairs for synthetic fixtures, classifier CIDRs, the
product's default namespace and exact native or tooling tokens that only look
like a namespace. An unhashed exception is refused by the CI entry point. No
wildcard/path-prefix/whole-test-tree exception is implemented.

For the private instance's CI, add its canonical instance file:

```sh
python -m netorch.privacy_check --root ../framework \
  --exceptions ../framework/schemas/privacy-exceptions.json \
  --instance instance.json
```

That second pass checks this instance's exact chosen values. It cannot reuse the
public generic fixture exceptions. If a true numeric coincidence with a platform
invariant requires a waiver, `--instance-exceptions` accepts a separate finite
file/kind/reason/**exact value SHA256** list. An unhashed exception is refused for
this pass. Record and review those waivers with the instance; they cannot permit
arbitrary copied site values in a test file.

Exit status is `0` for pass, `1` for findings and `2` for refusal/incomplete scan.
Output contains canonical JSON, locations and hashes only. A failed Git read,
malformed inventory, unavailable file, noncanonical/invalid instance, timeout or
oversized output never becomes a successful privacy result. Offline tests cover
the real tracked/candidate/ignored Git split and mocked unknown output, both
entry points, separate exception authority and non-disclosure.

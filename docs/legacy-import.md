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
`sources`. A source may also carry the five keys that only the
[renderer](#render-literal-inputs-from-the-instance) reads: `composed`,
`translated`, `constants`, `unexamined` and `independent`. An import accepts
them without reading or copying them, and any other key is refused as before.
IDs are distinct lowercase identifiers. Paths are local evidence
paths; they are not executable paths in the instance model. A non-null SHA256
pins the exact source bytes; a changed pin refuses import rather than silently
accepting a new owner contract.

Formats are closed JSON, XML property-list data, TOML, literal assignment files,
and literal data lists. Only explicit source-JSON-pointer to destination-pointer
mappings are emitted. Duplicate JSON/plist keys, duplicate TOML/assignment keys,
unsupported types, oversized/deep input, malformed text and unavailable mappings
are refused or represented as underivable. The pointer subset deliberately
excludes escaping, empty segments and ambiguous array indices: an index has one
spelling, without a leading zero and in ASCII digits.

Every destination has exactly one mapping in the whole manifest. A second
mapping to the same destination, or to a destination inside another mapped
one, refuses the import whatever the mappings yield. A null, an absent value or
an underivable source does not make room for a second author.

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
`executable-source-not-evaluated` issue; it cannot map settings and carries none
of the five renderer keys. That issue is a receipt: the program was recorded by
its hash and not read. It supplies no value, and it is not an unread data input:
by itself it blocks neither a projection (`project_instance` below) nor the
literal inputs of the same owner (see "Programs" and the section on flipping
one owner).

Credential/environment selectors and nested credential/environment objects are
rejected, including common camelCase, acronym, separator and API-key spellings,
`passphrase`, and compound names that end in a password word, such as
`PGPASSWORD` or `DBPASSWD`. `pass` alone is not a listed word, so `compass` and
`bypass_cache` remain ordinary keys.
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
rejects unread data inputs, and invokes the independent closed instance parser.
A program receipt alone does not block the projection; unsupported syntax or an
unavailable mapped value in a data source still does. A destination may name a
list member by its `id` (`/workloads/<id>/name`) as well as by its position:
the identifier names the same member after another one is inserted, and it is
the only form the renderer accepts. Both forms of one member are one
destination.
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

## Render literal inputs from the instance

`netorch.render.render_sources(manifest, instance, collect=None)` produces the
rendered side of a byte comparison. It is a library function like the importer:
it has no command, writes no file, and installs or executes nothing. It reads
the manifest that `import_sources` reads, and a valid instance.

The captured file is its own template. The importer's decoder reads the
capture, a scanner locates the byte span of every scalar leaf, the spans of the
leaves that the manifest maps are replaced by the instance's values in the
lexical style of the captured literal, and every other byte is kept. Comments,
order, whitespace, quoting and line ends are never touched. There is no
template language and no second copy of a file's text. Before a result is
reported, the rendered bytes are decoded again with the importer's decoder: the
set of leaves must be the same, every leaf that was not rendered must be
unchanged, and every rendered leaf must read back as the intended value. JSON,
XML property lists, literal assignment files and literal data lists are
rendered. TOML is not.

### Manifest keys

Five optional entry keys stand beside `mapping`. A selector is a pointer into
the capture, as in `mapping`.

| Key | Form | Meaning |
|---|---|---|
| `mapping` | selector to instance pointer | The leaf is the instance value itself. An import fills the instance from it; the renderer writes it back. |
| `composed` | selector to a list of 1 to 16 parts, each `{"text": "..."}` or `{"pointer": "..."}`, with at least one pointer and no two texts in a row | The leaf is fixed text and instance values joined, such as a path below a pinned directory. One pointer alone is the instance value itself, with its own type. |
| `translated` | selector to `{"pointer": "...", "values": {"<instance spelling>": "<owner spelling>"}}`, with 1 to 64 pairs and no owner spelling used twice | The leaf is the owner's word for an instance value. A number or Boolean of the instance is looked up in its JSON spelling (`4096`, `true`). A value outside the table is refused, never passed through. |
| `constants` | list of at most 1024 distinct selectors; a selector covers its whole subtree | Leaves the owner authors itself. They are kept as captured and checked as described below. |
| `unexamined` | list of at most 64 distinct selectors, each containing a credential or environment key word | A subtree kept as captured and never inspected, so that a job definition with an environment dictionary can be classified without reading it. |
| `independent` | list of at most 16 distinct selectors, each naming one constant leaf | The owner's statement that this constant only happens to repeat an instance setting. |

An import refuses a second mapping to one destination, and so does the
renderer. A further place that holds the same value is a composition of that
one pointer. Fixed text, that is a `text` part or an owner spelling, has at most
4096 characters and no control character. A credential or environment key word
is refused in every other selector and in every pointer, and a constant's
subtree never covers such a key: a leaf below one is either `unexamined` or
unclassified.

An instance pointer resolves in the canonical instance document, in which
`names` holds the resolved names, so a derived default is rendered like a pin. A
list member that carries an `id` is addressed by it (`/workloads/<id>/name`,
`/transport/<id>/ports/first`). A position into such a list is refused, because
it would silently name another member after an insertion. A list of plain
values, such as `dependencies`, has only positions. Pointers into `decisions`,
`acceptance`, `deviations`, `authoring` and `framework` are refused: these are
the sections an import never fills.

### What counts as rendered

Every scalar leaf of the capture must be exactly one of mapped, composed,
translated, constant or unexamined. A source is **complete** when no leaf is
left unclassified and no constant repeats an instance setting. Only a complete
source yields a byte comparison (`RenderResult.comparisons(owner)`), and only
its bytes are handed to `collect`. Replacing nothing in a template reproduces
it trivially, so identical bytes mean something only when every leaf is
accounted for.

A text constant repeats a setting when it equals one of the instance's string
settings or contains a specific one as a delimited token. The settings are the
LAN address and prefix, the account home, the runtime network name, the
namespace, the ten resolved names and the container names. A setting is
specific when it holds a character other than a letter; a single
dictionary-like word is compared as a whole value only. Such a constant becomes
a mapping or a composition, or the owner lists it under `independent`.
`independent` is a bounded, explicit waiver of the one-author rule and is
refused where it is unnecessary: an entry for a leaf that repeats nothing is an
issue, so the list cannot grow into a general permission. The fixed text of a
composition and the owner spellings of a translation may not repeat a setting
at all. Equal numbers are only counted (`integer_coincidences`), because
numbers coincide too often to be evidence.

An examined text leaf of the rendered file that contains an IPv4 literal other
than the instance's LAN address or prefix refuses the source. This is the
instance's own rule applied to what is rendered from it: a guest or receiver
address is state, never an input.

### Writing a value

| Captured literal | Value written as | Refused |
|---|---|---|
| JSON string | JSON string in the capture's escaping: non-ASCII characters either as they are or as `\u` escapes | any other escaping of the captured literal, such as `\/` |
| JSON integer, `true`, `false` | canonical decimal; the other word | a fractional number, `null`, a container |
| `<string>` text | text with `&` and `<` escaped, and `>` too if the capture escapes it | CDATA, a character reference, a comment inside the text, `<string/>` |
| `<integer>`, `<true/>`, `<false/>` | canonical decimal; the other element | `<real>`, a hexadecimal or padded integer, `<true></true>` |
| bare, single-quoted or double-quoted assignment value | the same quoting | a value the quoting cannot hold: a space in a bare value, the quote itself, `$`, a backquote, a backslash |
| list item | the item | anything outside `[A-Za-z0-9_.:-]{1,128}` |

A value is written in the one spelling that, applied to the captured value,
reproduces the captured literal. Otherwise the leaf is refused; nothing is
normalised. Where the capture leaves a choice open that the new value would
need, the leaf is refused as well: a non-ASCII character for a JSON string that
holds none, or a `>` for property-list text that holds none. An integer of the
instance is written into a text literal as canonical decimal digits when the
captured text is that spelling of a number. A Boolean is never written into
text and text never into a number.

### Result and reasons

`RenderResult.to_dict()` holds the manifest's own SHA-256 and the instance
digest, and for each source its identifier, owner, format, captured and
rendered hashes and sizes, `identical`, `complete` and the number of leaves in
each class. It holds no value of a file or of the instance. The instance
pointers that an owner's complete inputs consume are reported as a count and a
hash; `RenderResult.pointers(owner)` lists them for the caller. A malformed
manifest, a changed capture pin, an unavailable capture or an invalid instance
raises `RenderError`. What concerns one source is an issue with a closed
reason, and that source then yields no result:

| Reason | Meaning |
|---|---|
| `unsupported-static-syntax` | the importer cannot read the capture |
| `format-not-renderable` | a TOML source carries a mapping or one of the five keys |
| `mapped-value-unavailable` | a selector names nothing in the capture |
| `non-scalar-mapping` | a selector or a pointer names something other than one text, integer or Boolean |
| `duplicate-selector` | one leaf is planned twice |
| `constant-overlaps-mapping` | a constant or unexamined subtree covers a planned leaf |
| `instance-value-unavailable` | a pointer names nothing in the instance, or `null`, or a member by its position |
| `value-not-in-translation` | the instance value has no owner spelling |
| `fixed-text-repeats-setting` | fixed manifest text holds an instance setting |
| `type-mismatch` | text for a number, a Boolean for text, and the like |
| `literal-style-unsupported` | no spelling, or no single one, reproduces the captured literal |
| `value-not-representable` | the style of the literal cannot hold the value |
| `live-address-in-owner-input` | the rendered file would hold another IPv4 address |
| `independent-without-duplicate` | an `independent` entry names no constant that repeats a setting |
| `render-self-check-failed` | the importer does not read the rendered bytes back as intended |

### Programs

A program stays inventory: pinned by its hash, never evaluated, never rendered.
For every `source-inventory` entry the renderer returns an
`InventoryCheck(id, owner, sha256, scanned, embedded_literals)`: the program's
bytes were searched, as text, for the instance's specific string settings.
Bytes that are not UTF-8 text, or that contain a NUL, are not searched, and
`scanned` is then false. A TOML source that carries only an empty `mapping`
supplies nothing and is pinned and searched in the same way.

The search is a tripwire, not a proof. A program that computes a name from
parts, or holds a single-word name or a port number, passes it. What is
guaranteed is narrower and firm: the literal inputs are reproduced from the
instance byte for byte, and the program that reads them is exactly the reviewed
one, because its hash is part of the owner digest.

### What the renderer does not do

- **Structure is frozen.** Values change, never the number of lines, keys or
  elements. An instance change that needs a new element needs a new capture,
  which changes the pinned hash and is reviewed again.
- **Nothing is written.** `collect` receives bytes in memory. Where they go is
  a decision of a later stage that introduces an apply path; this release has
  none.
- **Evidence is not authenticated.** A site may still compare the output of its
  own generator with `compare_artifacts`. `promote_owner` checks that what it
  is given agrees with the fresh captures, not who produced it. Use one
  manifest for the import and for the rendering; the result records its hash.
- **The recipe is not pinned in the instance.** After a flip the authoring
  record carries no hash. The proof is of the moment of promotion; the manifest
  hash and the instance digest in the result allow it to be repeated.
- **An identifier that contains a credential or environment word**, such as
  `token` or `env`, cannot be addressed, exactly as in an import.

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

`promote_owner(instance, owner, import_result, comparisons, inventory=())`
requires:

1. One generated authoring record for that owner, including closed sections and
   stable subjects, with the freshly captured aggregate source digest.
2. No unread data source for that owner. The receipt of an inventoried program
   is not one; unsupported syntax or an unavailable mapped value is.
3. For every program of that owner one inventory check made for that owner,
   with the hash of the fresh receipt, `scanned` true and no embedded literal.
   A program is not compared, because nothing renders it. A program that was
   not searched, or that still holds a setting, blocks its owner. A TOML source
   may have such a check instead of a comparison, never both.
4. Every other source ID compared exactly once by a comparison made for that
   owner, its capture digest equal to the fresh source receipt, and identical
   captured/rendered bytes. At least one source must be compared: an owner
   whose inputs are only programs has nothing rendered from the instance and is
   not promoted. A comparison or a check made for another owner, or for none,
   promotes no one.
5. A provenance-only change to `mode: authored` and `source_sha256: null`.

`RenderResult.comparisons(owner)` and `RenderResult.checks(owner)` supply the
third and fourth item for the inputs the renderer handles.

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
declared baseline extension identifiers and proxy and VPN service names,
workload names and range endpoints. Low-entropy chosen port literals require
careful, narrow exceptions; they are not automatically ignored.

A chosen name and the namespace are found in any letter case and as a label of
a longer dotted name: `<namespace>.forwarding`, `<workload>.local`,
`host.<workload>` and `www.<workload>.example` are findings. Further letters,
digits, hyphens or underscores make another name, so `<workload>2` is not a
finding. A name that lies inside a longer chosen value at the same place, such
as an instance name that is a label of its own namespace, is reported once, as
the longer value. Addresses, ports, the adapter identity and the home path keep
exact boundaries and letter case. A finding carries the hash of the text as it
was found; an exception therefore exempts one exact spelling.

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
privacy refusal and narrow exceptions. The renderer's span scanners are compared
with the importer's decoder on generated documents, and generated files are
rendered with unchanged values and with one changed value. None performs a
native network test or production owner operation.

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

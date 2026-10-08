"""Render literal owner inputs from an instance; nothing is written or executed.

The captured file is its own template. The importer's decoder reads it, a span
scanner locates the bytes of every scalar leaf, the spans of the leaves that the
manifest maps are replaced by the instance's values in the lexical style of the
captured literal, and every other byte is kept. There is no template language
and no second copy of a file's text. The rendered bytes are decoded again with
the importer's decoder before a result is reported.

A program stays inventory: it is pinned by its hash, never evaluated and never
rendered. Its text is searched for the instance's specific string settings.
That search is a tripwire, not a proof.

Diagnostics hold identifiers, hashes, counts and closed reasons only, never a
value from a source or from the instance.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import plistlib
import re
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.parsers import expat

from .codec import CodecError, canonical_bytes, strict_loads
from .conformance import ByteComparison, InventoryCheck, compare_bytes
from .derive import DeriveError
from .instance import (
    _ADDRESS,
    _CONTROL,
    InstanceError,
    instance_digest,
    instance_to_dict,
    resolved_names,
    validate_instance,
)
from .instance_model import Instance
from .legacy_import import (
    _AUTHORED_SECTIONS,
    _FORMATS,
    _ID,
    _RENDER_KEYS,
    _SHA,
    Issue,
    _decode,
    _lookup,
    _member,
    _pointer,
    _secret_key,
    read_static,
)
from .legacy_import import ImportError as StaticImportError

_BARE = re.compile(r"[A-Za-z0-9:/._@-]+")
_ITEM = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
# The one spelling of an integer: no sign, no leading zero, at most ten digits.
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,9}")
_JSON_INTEGER = re.compile(rb"-?(?:0|[1-9][0-9]*)")
_INDEX = re.compile(r"0|[1-9][0-9]*")
_WORD = "[A-Za-z0-9_]"
_MAX_TEXT = 4096

Leaf = tuple[str, ...]
Scalar = str | int | bool


class RenderError(ValueError):
    """The manifest, a capture or the instance cannot be used for rendering."""


class _Refused(Exception):
    """One leaf cannot be rendered; the argument is a closed reason, never a value."""


@dataclass(frozen=True)
class RenderedSource:
    """Hashes and counts for one literal source; no value of the file or the instance."""

    id: str
    owner: str
    format: str
    captured_sha256: str
    rendered_sha256: str
    captured_bytes: int
    rendered_bytes: int
    identical: bool
    leaves: int
    mapped: int
    composed: int
    translated: int
    constants: int
    unexamined: int
    independent: int
    unclassified: int
    duplicate_constants: int
    integer_coincidences: int

    @property
    def complete(self) -> bool:
        """Every leaf is accounted for and no constant repeats an instance setting."""
        return self.unclassified == 0 and self.duplicate_constants == 0

    def comparison(self) -> ByteComparison:
        return ByteComparison(
            self.id,
            self.captured_sha256,
            self.rendered_sha256,
            self.captured_bytes,
            self.rendered_bytes,
            self.identical,
            self.owner,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "owner": self.owner,
            "format": self.format,
            "captured_sha256": self.captured_sha256,
            "rendered_sha256": self.rendered_sha256,
            "captured_bytes": self.captured_bytes,
            "rendered_bytes": self.rendered_bytes,
            "identical": self.identical,
            "complete": self.complete,
            "leaves": self.leaves,
            "mapped": self.mapped,
            "composed": self.composed,
            "translated": self.translated,
            "constants": self.constants,
            "unexamined": self.unexamined,
            "independent": self.independent,
            "unclassified": self.unclassified,
            "duplicate_constants": self.duplicate_constants,
            "integer_coincidences": self.integer_coincidences,
        }


@dataclass(frozen=True)
class RenderResult:
    """What one manifest yields for one instance, bound to both by their hashes."""

    manifest_sha256: str
    instance_digest: str
    sources: tuple[RenderedSource, ...]
    inventory: tuple[InventoryCheck, ...]
    issues: tuple[Issue, ...]
    consumed: tuple[tuple[str, str], ...] = ()

    def comparisons(self, owner: str) -> tuple[ByteComparison, ...]:
        """Parity evidence; a source that is not completely classified yields none.

        Replacing nothing in a template reproduces it trivially, so identical
        bytes mean something only when every leaf of the source is accounted for.
        """
        return tuple(
            item.comparison() for item in self.sources if item.owner == owner and item.complete
        )

    def checks(self, owner: str) -> tuple[InventoryCheck, ...]:
        """The inventory checks of the owner's programs and searched data files."""
        return tuple(item for item in self.inventory if item.owner == owner)

    def pointers(self, owner: str) -> frozenset[str]:
        """Instance values the owner's complete literal inputs are rendered from."""
        return frozenset(pointer for name, pointer in self.consumed if name == owner)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "manifest_sha256": self.manifest_sha256,
            "instance_digest": self.instance_digest,
            "sources": [item.to_dict() for item in self.sources],
            "inventory": [item.to_dict() for item in self.inventory],
            "issues": [
                {"source": item.source, "reason": item.reason, "selector": item.selector}
                for item in self.issues
            ],
            "consumed": [
                {
                    "owner": owner,
                    "pointers": len(self.pointers(owner)),
                    "sha256": hashlib.sha256(
                        canonical_bytes(sorted(self.pointers(owner)))
                    ).hexdigest(),
                }
                for owner in sorted({name for name, _ in self.consumed})
            ],
        }


# ---------------------------------------------------------------- leaves and spans


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    kind: str  # string | integer | boolean | other
    style: str  # json | plist-text | plist-element | bare | double | single | item


def _leaves(node: Any, path: Leaf = ()) -> dict[Leaf, Any]:
    """Every scalar of a decoded document; a list index is spelled like an object key."""
    result: dict[Leaf, Any] = {}
    if isinstance(node, dict):
        for key, value in node.items():
            result.update(_leaves(value, (*path, str(key))))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            result.update(_leaves(value, (*path, str(index))))
    else:
        result[path] = node
    return result


def _json_spans(raw: bytes) -> dict[Leaf, _Span]:
    spans: dict[Leaf, _Span] = {}
    size = len(raw)

    def blank(index: int) -> int:
        while index < size and raw[index] in b" \t\n\r":
            index += 1
        return index

    def string_end(index: int) -> int:
        if raw[index : index + 1] != b'"':
            raise RenderError("Malformed JSON text")
        index += 1
        while index < size:
            if raw[index] == 0x5C:  # a backslash escapes the byte that follows
                index += 2
            elif raw[index] == 0x22:
                return index + 1
            else:
                index += 1
        raise RenderError("Malformed JSON text")

    def value(index: int, path: Leaf) -> int:
        index = blank(index)
        head = raw[index : index + 1]
        if head == b"{":
            index = blank(index + 1)
            if raw[index : index + 1] == b"}":
                return index + 1
            while True:
                index = blank(index)
                end = string_end(index)
                key = json.loads(raw[index:end])
                index = blank(end)
                if raw[index : index + 1] != b":":
                    raise RenderError("Malformed JSON text")
                index = blank(value(index + 1, (*path, key)))
                if raw[index : index + 1] == b"}":
                    return index + 1
                if raw[index : index + 1] != b",":
                    raise RenderError("Malformed JSON text")
                index += 1
        if head == b"[":
            index = blank(index + 1)
            if raw[index : index + 1] == b"]":
                return index + 1
            position = 0
            while True:
                index = blank(value(index, (*path, str(position))))
                position += 1
                if raw[index : index + 1] == b"]":
                    return index + 1
                if raw[index : index + 1] != b",":
                    raise RenderError("Malformed JSON text")
                index += 1
        if head == b'"':
            end = string_end(index)
            spans[path] = _Span(index, end, "string", "json")
            return end
        end = index
        while end < size and raw[end] not in b",]} \t\n\r":
            end += 1
        token = raw[index:end]
        if token in (b"true", b"false"):
            kind = "boolean"
        else:
            kind = "integer" if _JSON_INTEGER.fullmatch(token) else "other"
        spans[path] = _Span(index, end, kind, "json")
        return end

    if blank(value(0, ())) != size:
        raise RenderError("Malformed JSON text")
    return spans


@dataclass
class _Element:
    tag: str
    path: Leaf
    start: int
    key: str | None = None
    count: int = 0
    text: list[str] = field(default_factory=list)


def _plist_spans(raw: bytes) -> dict[Leaf, _Span]:
    """Byte spans from the offsets the XML parser reports for each start and end tag."""
    spans: dict[Leaf, _Span] = {}
    stack: list[_Element] = []
    parser = expat.ParserCreate()

    def start(name: str, _attributes: dict[str, str]) -> None:
        index = parser.CurrentByteIndex
        if not raw.startswith(b"<" + name.encode("ascii"), index):
            raise RenderError("Unexpected property-list offset")
        if name in ("plist", "key") or not stack:
            stack.append(_Element(name, (), index))
            return
        parent = stack[-1]
        if parent.tag == "dict":
            path: Leaf = (*parent.path, parent.key or "")
        elif parent.tag == "array":
            path = (*parent.path, str(parent.count))
        else:
            path = parent.path
        stack.append(_Element(name, path, index))

    def text(data: str) -> None:
        if stack and stack[-1].tag == "key":
            stack[-1].text.append(data)

    def end(name: str) -> None:
        index = parser.CurrentByteIndex
        element = stack.pop()
        if name == "plist" or not stack:
            return
        parent = stack[-1]
        if name == "key":
            parent.key = "".join(element.text)
            return
        parent.count += 1
        if name in ("dict", "array"):
            return
        kind = {"string": "string", "integer": "integer", "true": "boolean", "false": "boolean"}
        # The importer admits no attribute here, so the first ">" ends the start tag.
        opened = raw.index(b">", element.start) + 1
        if raw[opened - 2 : opened] == b"/>":
            spans[element.path] = _Span(
                element.start, opened, kind.get(name, "other"), "plist-element"
            )
        elif not raw.startswith(b"</" + name.encode("ascii"), index):
            raise RenderError("Unexpected property-list offset")
        else:
            # Also <true></true>: read as a Boolean, but only <true/> is ever written.
            spans[element.path] = _Span(opened, index, kind.get(name, "other"), "plist-text")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    parser.Parse(raw, True)
    return spans


def _lines(raw: bytes) -> list[tuple[int, int]]:
    """Every line with spaces and tabs trimmed, exactly as the importer reads it."""
    result: list[tuple[int, int]] = []
    offset = 0
    for line in raw.split(b"\n"):
        start, end = offset, offset + len(line)
        while start < end and raw[start] in b" \t":
            start += 1
        while end > start and raw[end - 1] in b" \t":
            end -= 1
        result.append((start, end))
        offset += len(line) + 1
    return result


def _assignment_spans(raw: bytes) -> dict[Leaf, _Span]:
    spans: dict[Leaf, _Span] = {}
    for start, end in _lines(raw):
        line = raw[start:end]
        if not line or line.startswith(b"#"):
            continue
        # The key is whatever the importer's grammar admits before the first "=".
        key, _, expression = line.partition(b"=")
        begin = start + len(key) + 1
        quote = expression[:1]
        if len(expression) >= 2 and quote == expression[-1:] and quote in (b'"', b"'"):
            style = "double" if quote == b'"' else "single"
            spans[(key.decode("utf-8"),)] = _Span(begin + 1, end - 1, "string", style)
        else:
            spans[(key.decode("utf-8"),)] = _Span(begin, end, "string", "bare")
    return spans


def _list_spans(raw: bytes) -> dict[Leaf, _Span]:
    spans: dict[Leaf, _Span] = {}
    count = 0
    for start, end in _lines(raw):
        line = raw[start:end]
        if not line or line.startswith(b"#"):
            continue
        spans[("items", str(count))] = _Span(start, end, "string", "item")
        count += 1
    return spans


_SPANS: dict[str, Callable[[bytes], dict[Leaf, _Span]]] = {
    "json": _json_spans,
    "plist": _plist_spans,
    "literal-env": _assignment_spans,
    "text-list": _list_spans,
}
# What the importer treats as unsupported syntax, plus the span scanners' own refusals.
_UNREADABLE = (
    StaticImportError,
    DeriveError,
    CodecError,
    UnicodeError,
    ValueError,
    plistlib.InvalidFileException,
    ET.ParseError,
    expat.ExpatError,
    RecursionError,
)


def _document(raw: bytes, fmt: str) -> Any:
    """A source decoded and bounded exactly as an import does it."""
    document = _decode(raw, fmt)
    canonical_bytes(document)  # The importer's bound on nodes and types.
    return document


# ---------------------------------------------------------------- writing a value


def _spelled(value: Scalar, span: _Span) -> list[bytes | None]:
    """Every spelling this renderer writes for a value in the style of one literal.

    The list has the same length and order for any value of a style, so the
    spelling that reproduces a captured literal can be applied to a new value.
    ``None`` marks a value the style cannot hold.
    """
    if span.style == "json":
        if span.kind == "string" and isinstance(value, str):
            return [
                json.dumps(value, ensure_ascii=False).encode("utf-8"),
                json.dumps(value, ensure_ascii=True).encode("ascii"),
            ]
        if span.kind == "integer" and type(value) is int:
            return [str(value).encode("ascii")]
        if span.kind == "boolean" and isinstance(value, bool):
            return [b"true" if value else b"false"]
        return []
    if span.style == "plist-element":
        if span.kind == "boolean" and isinstance(value, bool):
            return [b"<true/>" if value else b"<false/>"]
        return []
    if span.kind == "integer" and type(value) is int:
        return [str(value).encode("ascii")]
    if span.kind != "string" or not isinstance(value, str):
        return []
    held = None if _CONTROL.search(value) else value
    if span.style == "plist-text":
        if held is None:
            return [None, None]
        partly = held.replace("&", "&amp;").replace("<", "&lt;")
        # XML character data cannot hold "]]>": only the spelling that escapes ">" writes it.
        bare = None if "]]>" in held else partly.encode("utf-8")
        return [partly.replace(">", "&gt;").encode("utf-8"), bare]
    if span.style == "bare":
        return [held.encode("utf-8") if held is not None and _BARE.fullmatch(held) else None]
    if span.style in ("double", "single"):
        quote = '"' if span.style == "double" else "'"
        if held is None or any(char in held for char in (quote, "$", "`", "\\")):
            return [None]
        return [held.encode("utf-8")]
    return [held.encode("utf-8") if held is not None and _ITEM.fullmatch(held) else None]


def _encode(new: Scalar, captured: Any, literal: bytes, span: _Span) -> tuple[bytes, Scalar]:
    """Write a value in the one spelling that reproduces the captured literal too.

    Returns the bytes and the value an import reads back from them. A Boolean
    is never written into text and text never into a number; an integer is
    written into text as canonical decimal digits.
    """
    written: Scalar = new
    if isinstance(new, bool):
        if span.kind != "boolean":
            raise _Refused("type-mismatch")
    elif isinstance(new, int):
        if span.kind == "boolean":
            raise _Refused("type-mismatch")
        if not _DECIMAL.fullmatch(str(new)):
            raise _Refused("value-not-representable")
        if span.kind == "string":
            # The captured text must itself be the canonical spelling of an integer.
            if not isinstance(captured, str) or not _DECIMAL.fullmatch(captured):
                raise _Refused("literal-style-unsupported")
            written = str(new)
    elif span.kind != "string":
        raise _Refused("type-mismatch")
    before = _spelled(captured, span)
    after = _spelled(written, span)
    candidates = [after[index] for index, spelling in enumerate(before) if spelling == literal]
    if not candidates:
        raise _Refused("literal-style-unsupported")
    result = candidates[0]
    if any(item != result for item in candidates):
        # Two spellings reproduce the capture and would write the new value differently,
        # or only one of them could write it at all.
        raise _Refused("literal-style-unsupported")
    if result is None:
        raise _Refused("value-not-representable")
    return result, written


def _same(left: Any, right: Any) -> bool:
    return type(left) is type(right) and bool(left == right)


# ---------------------------------------------------------------- instance values


def settings_view(instance: Instance) -> dict[str, Any]:
    """The instance as owners consume it: canonical data with every name resolved."""
    view = instance_to_dict(instance)
    view["names"] = resolved_names(instance)
    return view


def setting_literals(instance: Instance) -> tuple[str, ...]:
    """String settings of which an owner input or a program must not hold a second copy."""
    literals = {
        instance.host.lan.ipv4,
        instance.host.lan.cidr,
        instance.host.account.home,
        instance.host.runtime.network,
        instance.namespace,
        *resolved_names(instance).values(),
        *(workload.name for workload in instance.workloads),
    }
    return tuple(sorted(literals, key=lambda item: (-len(item), item)))


def _search(literals: Iterable[str]) -> re.Pattern[str] | None:
    """One pattern for the specific settings as delimited tokens, the longest first.

    A setting is specific when it holds a character other than a letter; a
    single dictionary-like word is too common to search free text for. A
    setting that itself ends in a delimiter, such as a name prefix, needs no
    delimiter after it.
    """
    specific = sorted(
        {item for item in literals if re.search(r"[^A-Za-z]", item)},
        key=lambda item: (-len(item), item),
    )
    if not specific:
        return None
    choices = "|".join(
        re.escape(item) + (f"(?!{_WORD})" if re.fullmatch(_WORD, item[-1]) else "")
        for item in specific
    )
    return re.compile(f"(?<!{_WORD})(?:{choices})")


@dataclass(frozen=True)
class _Settings:
    view: dict[str, Any]
    literals: frozenset[str]
    search: re.Pattern[str] | None
    integers: frozenset[int]
    addresses: frozenset[str]

    def occurrences(self, text: str) -> int:
        """Places in free text that hold a specific setting."""
        return 0 if self.search is None else len(self.search.findall(text))

    def repeats(self, value: str) -> bool:
        """A discrete literal repeats a setting when it equals one or embeds a specific one."""
        return value in self.literals or self.occurrences(value) > 0

    def live_address(self, value: str) -> bool:
        """The instance's own rule for its data: no address but the declared LAN."""
        return any(found not in self.addresses for found in _ADDRESS.findall(value))


def _settings(instance: Instance) -> _Settings:
    view = settings_view(instance)
    literals = setting_literals(instance)
    return _Settings(
        view,
        frozenset(literals),
        _search(literals),
        frozenset(
            value
            for path, value in _leaves(view).items()
            if type(value) is int and path[0] not in _AUTHORED_SECTIONS
        ),
        frozenset({instance.host.lan.ipv4, instance.host.lan.cidr}),
    )


def _instance_value(settings: _Settings, pointer: str) -> Scalar:
    """Resolve an instance pointer; a member that carries an ``id`` is addressed by it."""
    value: Any = settings.view
    for part in _pointer(pointer):
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif (
            isinstance(value, list)
            and value
            and all(isinstance(item, dict) and "id" in item for item in value)
        ):
            # A position would silently name another member after an insertion.
            value = _member(value, part)
            if value is None:
                raise _Refused("instance-value-unavailable")
        elif isinstance(value, list) and _INDEX.fullmatch(part) and int(part) < len(value):
            value = value[int(part)]
        else:
            raise _Refused("instance-value-unavailable")
    if value is None:
        raise _Refused("instance-value-unavailable")
    if not isinstance(value, (str, int)):
        raise _Refused("non-scalar-mapping")
    return value


# ---------------------------------------------------------------- the manifest


@dataclass(frozen=True)
class _Part:
    text: str | None = None
    pointer: str | None = None


@dataclass(frozen=True)
class _Plan:
    form: str  # mapped | composed | translated
    selector: str
    leaf: Leaf
    parts: tuple[_Part, ...]
    values: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class _Entry:
    id: str
    owner: str
    path: str
    format: str
    sha256: str | None
    plans: tuple[_Plan, ...]
    constants: tuple[tuple[str, Leaf], ...]
    unexamined: tuple[tuple[str, Leaf], ...]
    independent: tuple[tuple[str, Leaf], ...]
    classifies: bool


def _parts(pointer: Any) -> list[str]:
    try:
        return _pointer(pointer)
    except StaticImportError:
        raise RenderError("Unsupported JSON pointer") from None


def _selector(selector: Any) -> Leaf:
    parts = _parts(selector)
    if any(_secret_key(part) for part in parts):
        raise RenderError("Credential and environment values are not instance data")
    return tuple(parts)


def _destination(pointer: Any) -> str:
    parts = _parts(pointer)
    if parts[0] in _AUTHORED_SECTIONS:
        raise RenderError("Authored instance sections are never rendered into an owner input")
    if any(_secret_key(part) for part in parts):
        raise RenderError("Credential and environment values are not instance data")
    return str(pointer)


def _fixed_text(text: Any, minimum: int) -> str:
    if (
        not isinstance(text, str)
        or not minimum <= len(text) <= _MAX_TEXT
        or _CONTROL.search(text) is not None
    ):
        raise RenderError("Fixed manifest text must be bounded and free of control characters")
    return text


def _table(value: Any, bound: int) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > bound:
        raise RenderError("Render mappings must be bounded objects")
    return value


def _selectors(value: Any, bound: int) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > bound
        or any(not isinstance(item, str) for item in value)
        or len(set(value)) != len(value)
    ):
        raise RenderError("Selector lists must be bounded lists of distinct selectors")
    return value


def _composition(selector: str, target: Any) -> _Plan:
    if not isinstance(target, list) or not 1 <= len(target) <= 16:
        raise RenderError("A composed leaf needs one to sixteen parts")
    parts: list[_Part] = []
    for part in target:
        if isinstance(part, dict) and set(part) == {"text"}:
            if parts and parts[-1].text is not None:
                raise RenderError("Fixed parts of a composed leaf must be separated by a pointer")
            parts.append(_Part(text=_fixed_text(part["text"], 1)))
        elif isinstance(part, dict) and set(part) == {"pointer"}:
            parts.append(_Part(pointer=_destination(part["pointer"])))
        else:
            raise RenderError("A composed part is one fixed text or one instance pointer")
    if all(part.pointer is None for part in parts):
        raise RenderError("A composed leaf names at least one instance value")
    return _Plan("composed", selector, _selector(selector), tuple(parts))


def _translation(selector: str, target: Any) -> _Plan:
    if (
        not isinstance(target, dict)
        or set(target) != {"pointer", "values"}
        or not isinstance(target["values"], dict)
        or not 1 <= len(target["values"]) <= 64
    ):
        raise RenderError("A translated leaf needs a pointer and one to sixty-four spellings")
    values = {key: _fixed_text(item, 0) for key, item in target["values"].items()}
    if len(set(values.values())) != len(values):
        raise RenderError("Two instance values cannot share one owner spelling")
    pointer = _Part(pointer=_destination(target["pointer"]))
    return _Plan("translated", selector, _selector(selector), (pointer,), tuple(values.items()))


def _entry(entry: Any) -> _Entry:
    """One manifest entry in the importer's closed shape, with the keys only a renderer reads."""
    required = {"id", "owner", "path", "format", "sha256", "mapping"}
    if not isinstance(entry, dict) or set(entry) - _RENDER_KEYS != required:
        raise RenderError("Unsupported static source contract")
    sid, owner, fmt, path = (entry[key] for key in ("id", "owner", "format", "path"))
    if any(not isinstance(value, str) or not _ID.fullmatch(value) for value in (sid, owner)):
        raise RenderError("Static source IDs must be unique closed identifiers")
    if (
        not isinstance(fmt, str)
        or fmt not in _FORMATS
        or not isinstance(path, str)
        or not path
        or len(path) > 4096
        or "\x00" in path
    ):
        raise RenderError("Invalid static source format or path")
    expected = entry["sha256"]
    if expected is not None and (not isinstance(expected, str) or not _SHA.fullmatch(expected)):
        raise RenderError("Invalid static source digest")
    plans = [
        _Plan("mapped", selector, _selector(selector), (_Part(pointer=_destination(pointer)),))
        for selector, pointer in _table(entry["mapping"], 1024).items()
    ]
    plans.extend(
        _composition(selector, target)
        for selector, target in _table(entry.get("composed", {}), 1024).items()
    )
    plans.extend(
        _translation(selector, target)
        for selector, target in _table(entry.get("translated", {}), 1024).items()
    )
    constants = [(item, _selector(item)) for item in _selectors(entry.get("constants", []), 1024)]
    unexamined = [
        (item, tuple(_parts(item))) for item in _selectors(entry.get("unexamined", []), 64)
    ]
    if any(not any(_secret_key(part) for part in leaf) for _, leaf in unexamined):
        raise RenderError("Only a credential or environment subtree may stay unexamined")
    independent = [(item, _selector(item)) for item in _selectors(entry.get("independent", []), 16)]
    classifies = bool(plans) or bool(_RENDER_KEYS & set(entry))
    if fmt == "source-inventory" and classifies:
        raise RenderError("Executable owner sources cannot provide desired settings")
    return _Entry(
        sid,
        owner,
        path,
        fmt,
        expected,
        tuple(plans),
        tuple(constants),
        tuple(unexamined),
        tuple(independent),
        classifies,
    )


# ---------------------------------------------------------------- rendering


def _intended(plan: _Plan, settings: _Settings, kind: str) -> Scalar:
    """The value a planned leaf holds for this instance."""
    if plan.form == "translated":
        value = _instance_value(settings, plan.parts[0].pointer or "")
        spelled = value if isinstance(value, str) else json.dumps(value)
        table = dict(plan.values)
        if any(settings.repeats(owner_spelling) for owner_spelling in table.values()):
            raise _Refused("fixed-text-repeats-setting")
        if spelled not in table:
            raise _Refused("value-not-in-translation")
        written = table[spelled]
        if kind == "boolean" and written in ("true", "false"):
            return written == "true"
        if kind == "integer" and _DECIMAL.fullmatch(written):
            return int(written)
        return written
    if len(plan.parts) == 1:
        # One pointer alone is the instance value itself, whatever its type.
        return _instance_value(settings, plan.parts[0].pointer or "")
    pieces: list[str] = []
    for part in plan.parts:
        if part.text is not None:
            if settings.repeats(part.text):
                raise _Refused("fixed-text-repeats-setting")
            pieces.append(part.text)
        else:
            value = _instance_value(settings, part.pointer or "")
            if isinstance(value, bool):
                raise _Refused("type-mismatch")
            pieces.append(str(value))
    return "".join(pieces)


def _covers(prefixes: Iterable[tuple[str, Leaf]], leaf: Leaf) -> bool:
    return any(leaf[: len(prefix)] == prefix for _, prefix in prefixes)


def _render(
    entry: _Entry, raw: bytes, settings: _Settings
) -> tuple[RenderedSource | None, bytes, set[str], list[Issue]]:
    """Render one literal source; any issue means that no result is reported for it."""
    issues: list[Issue] = []
    try:
        document = _document(raw, entry.format)
    except _UNREADABLE:
        # No error text: it can contain the input's own expression.
        return None, b"", set(), [Issue(entry.id, "unsupported-static-syntax")]
    leaves = _leaves(document)
    try:
        spans = _SPANS[entry.format](raw)
    except _UNREADABLE:
        return None, b"", set(), [Issue(entry.id, "render-self-check-failed")]
    ordered = sorted(spans.values(), key=lambda span: span.start)
    if (
        set(spans) != set(leaves)
        or any(not 0 <= span.start <= span.end <= len(raw) for span in ordered)
        or any(left.end > right.start for left, right in itertools.pairwise(ordered))
    ):
        return None, b"", set(), [Issue(entry.id, "render-self-check-failed")]
    edits: dict[Leaf, bytes] = {}
    expected: dict[Leaf, Scalar] = {}
    counts = {"mapped": 0, "composed": 0, "translated": 0}
    used: set[str] = set()
    for plan in entry.plans:
        try:
            if plan.leaf in edits:
                raise _Refused("duplicate-selector")
            if plan.leaf not in leaves:
                try:
                    _lookup(document, plan.selector)
                except StaticImportError:
                    raise _Refused("mapped-value-unavailable") from None
                raise _Refused("non-scalar-mapping")
            span = spans[plan.leaf]
            if span.kind == "other":
                raise _Refused("non-scalar-mapping")
            new = _intended(plan, settings, span.kind)
            if isinstance(new, str) and settings.live_address(new):
                raise _Refused("live-address-in-owner-input")
            edits[plan.leaf], expected[plan.leaf] = _encode(
                new, leaves[plan.leaf], raw[span.start : span.end], span
            )
        except _Refused as refusal:
            issues.append(Issue(entry.id, str(refusal), plan.selector))
            continue
        counts[plan.form] += 1
        used.update(part.pointer for part in plan.parts if part.pointer is not None)
    planned = {plan.leaf for plan in entry.plans}
    for selector, prefix in (*entry.constants, *entry.unexamined):
        try:
            _lookup(document, selector)
        except StaticImportError:
            issues.append(Issue(entry.id, "mapped-value-unavailable", selector))
        if any(leaf[: len(prefix)] == prefix for leaf in planned):
            issues.append(Issue(entry.id, "constant-overlaps-mapping", selector))
    waived = {leaf: selector for selector, leaf in entry.independent}
    constants = unexamined = independent = unclassified = duplicates = coincidences = 0
    live = False
    for leaf, value in leaves.items():
        if _covers(entry.unexamined, leaf):
            # Kept as captured and never inspected.
            unexamined += 1
        elif leaf in planned:
            continue
        elif any(_secret_key(part) for part in leaf):
            # Never inspected either, and never covered by a constant's subtree.
            unclassified += 1
        elif isinstance(value, str) and settings.live_address(value):
            # A guest or receiver address is state, never an owner input.
            live = True
        elif not _covers(entry.constants, leaf):
            unclassified += 1
        else:
            constants += 1
            if isinstance(value, str) and settings.repeats(value):
                if leaf in waived:
                    # The owner states that this constant only happens to repeat a setting.
                    independent += 1
                    del waived[leaf]
                else:
                    duplicates += 1
            elif (type(value) is int and value in settings.integers) or (
                isinstance(value, str)
                and _DECIMAL.fullmatch(value)
                and int(value) in settings.integers
            ):
                coincidences += 1
    if live:
        issues.append(Issue(entry.id, "live-address-in-owner-input"))
    # A statement for a leaf that repeats nothing would hide a later real duplicate.
    issues.extend(
        Issue(entry.id, "independent-without-duplicate", selector) for selector in waived.values()
    )
    if issues:
        return None, b"", set(), issues
    output = bytearray(raw)
    for leaf in sorted(edits, key=lambda item: spans[item].start, reverse=True):
        output[spans[leaf].start : spans[leaf].end] = edits[leaf]
    rendered = bytes(output)
    # The renderer is trusted only as far as the importer reads its output back.
    try:
        again = _leaves(_document(rendered, entry.format))
    except _UNREADABLE:
        again = {}
    if set(again) != set(leaves) or any(
        not _same(again[leaf], expected.get(leaf, leaves[leaf])) for leaf in leaves
    ):
        return None, b"", set(), [Issue(entry.id, "render-self-check-failed")]
    comparison = compare_bytes(entry.id, raw, rendered, owner=entry.owner)
    source = RenderedSource(
        entry.id,
        entry.owner,
        entry.format,
        comparison.captured_sha256,
        comparison.rendered_sha256,
        comparison.captured_bytes,
        comparison.rendered_bytes,
        comparison.identical,
        len(leaves),
        counts["mapped"],
        counts["composed"],
        counts["translated"],
        constants,
        unexamined,
        independent,
        unclassified,
        duplicates,
        coincidences,
    )
    return source, rendered, used, []


def _searched(raw: bytes, settings: _Settings) -> int | None:
    """Places in a text that hold a specific setting; ``None`` when it is no searchable text."""
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError:
        return None
    return None if "\x00" in text else settings.occurrences(text)


def render_sources(
    manifest: str | Path,
    instance: Instance,
    *,
    collect: MutableMapping[str, bytes] | None = None,
) -> RenderResult:
    """Render every literal source of an import manifest from one valid instance.

    Nothing is written. ``collect`` receives the rendered bytes of the sources
    that are complete, keyed by source ID. A malformed manifest, a changed
    capture pin, an unavailable capture or an invalid instance raises
    ``RenderError``; what concerns one source is reported as an issue with a
    closed reason, and that source then yields no result.
    """
    path = Path(manifest)
    try:
        validate_instance(instance)
    except InstanceError:
        raise RenderError("Rendering requires a valid instance") from None
    try:
        manifest_bytes = read_static(path)
        data = strict_loads(manifest_bytes)
    except (StaticImportError, CodecError):
        raise RenderError("Unsupported static import manifest") from None
    if (
        not isinstance(data, dict)
        or set(data) != {"schema_version", "sources"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or not isinstance(data["sources"], list)
        or not 1 <= len(data["sources"]) <= 128
    ):
        raise RenderError("Unsupported static import manifest")
    entries = [_entry(item) for item in data["sources"]]
    if len({entry.id for entry in entries}) != len(entries):
        raise RenderError("Static source IDs must be unique closed identifiers")
    # An import refuses a second mapping to one destination; so does its inverse.
    destinations = [
        plan.parts[0].pointer for entry in entries for plan in entry.plans if plan.form == "mapped"
    ]
    if len(set(destinations)) != len(destinations):
        raise RenderError("Mapped value has more than one author")
    settings = _settings(instance)
    sources: list[RenderedSource] = []
    inventory: list[InventoryCheck] = []
    issues: list[Issue] = []
    consumed: set[tuple[str, str]] = set()
    complete: dict[str, bytes] = {}
    for entry in entries:
        capture = Path(entry.path)
        try:
            raw = read_static(capture if capture.is_absolute() else path.parent / capture)
        except StaticImportError:
            raise RenderError("Static source is unavailable") from None
        sha = hashlib.sha256(raw).hexdigest()
        if entry.sha256 is not None and entry.sha256 != sha:
            raise RenderError("Static source digest changed; capture requires explicit review")
        if entry.format not in _SPANS:
            # A program always; a data format without a renderer when it supplies nothing.
            if entry.classifies:
                issues.append(Issue(entry.id, "format-not-renderable"))
            else:
                found = _searched(raw, settings)
                inventory.append(
                    InventoryCheck(entry.id, entry.owner, sha, found is not None, found or 0)
                )
            continue
        source, rendered, used, found_issues = _render(entry, raw, settings)
        issues.extend(found_issues)
        if source is None:
            continue
        sources.append(source)
        if source.complete:
            consumed.update((entry.owner, pointer) for pointer in used)
            complete[entry.id] = rendered
    if collect is not None:
        # Only now: a refused manifest hands out nothing at all.
        collect.update(complete)
    return RenderResult(
        hashlib.sha256(manifest_bytes).hexdigest(),
        instance_digest(instance),
        tuple(sources),
        tuple(inventory),
        tuple(issues),
        tuple(sorted(consumed)),
    )

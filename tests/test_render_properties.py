"""Generated captures: a span is exactly one literal, and only a changed value moves.

The span scanners are compared with the importer's decoder on generated
documents, and whole files are rendered from generated instance values. The
files are assembled from pieces, so the expected bytes do not depend on what
the renderer itself believes a span to be. Synthetic data only.
"""

from __future__ import annotations

import itertools
import json
import plistlib
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import ParseError

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from hypothesis.errors import Unsatisfiable

from netorch import render
from netorch.codec import strict_loads
from netorch.instance import InstanceError
from netorch.legacy_import import _decode
from netorch.render import render_sources
from tests.test_render_sources import PLIST_HEAD, changed, manifest, source

GENERATED = settings(max_examples=120, deadline=None, suppress_health_check=list(HealthCheck))
RENDERED = settings(max_examples=40, deadline=None, suppress_health_check=list(HealthCheck))

# ---- the span scanners against the importer's decoder

TEXT = st.text(alphabet=st.characters(exclude_categories=["Cs"]), max_size=10)
JSON_VALUE = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(-(10**12), 10**12),
        st.floats(allow_nan=False, allow_infinity=False),
        TEXT,
    ),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(TEXT, children, max_size=4),
    max_leaves=12,
)
JSON_LAYOUT = st.tuples(
    st.sampled_from([None, 0, 1, 3, "\t"]),
    st.sampled_from([(",", ":"), (", ", ": "), (" ,\r\n", "\t: \n")]),
    st.booleans(),
    st.sampled_from(["", " ", "\n", "\r\n\t "]),
)
KINDS = {str: "string", bool: "boolean", int: "integer"}


def disjoint(spans: dict[Any, Any]) -> bool:
    ordered = sorted(spans.values(), key=lambda span: span.start)
    return all(left.end <= right.start for left, right in itertools.pairwise(ordered))


@GENERATED
@given(JSON_VALUE, JSON_LAYOUT)
def test_json_span_is_the_literal_the_importer_decodes(value: Any, layout: Any) -> None:
    indent, separators, ascii_only, margin = layout
    text = json.dumps(value, indent=indent, separators=separators, ensure_ascii=ascii_only)
    raw = (margin + text + margin).encode("utf-8")
    leaves = render._leaves(strict_loads(raw))
    spans = render._json_spans(raw)
    assert set(spans) == set(leaves) and disjoint(spans)
    for leaf, span in spans.items():
        decoded = json.loads(raw[span.start : span.end])
        assert type(decoded) is type(leaves[leaf]) and decoded == leaves[leaf]
        assert span.kind == KINDS.get(type(decoded), "other")
        if span.kind != "other":
            assert raw[span.start : span.end] in render._spelled(decoded, span)


PLIST_TEXT = st.text(
    alphabet=st.characters(exclude_categories=["Cs", "Cc", "Zl", "Zp"], exclude_characters="￾￿"),
    max_size=10,
)
PLIST_VALUE = st.recursive(
    st.one_of(
        st.booleans(),
        st.integers(-(2**63), 2**64 - 1),
        st.floats(allow_nan=False, allow_infinity=False),
        PLIST_TEXT,
    ),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(PLIST_TEXT, children, max_size=4)
    ),
    max_leaves=12,
)


@GENERATED
@given(PLIST_VALUE, st.booleans())
def test_property_list_span_is_the_literal_the_importer_decodes(value: Any, sort: bool) -> None:
    raw = plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=sort)
    leaves = render._leaves(_decode(raw, "plist"))
    spans = render._plist_spans(raw)
    assert set(spans) == set(leaves) and disjoint(spans)
    for leaf, span in spans.items():
        literal = raw[span.start : span.end]
        assert span.kind == KINDS.get(type(leaves[leaf]), "other")
        if span.kind == "other":
            assert float(literal) == leaves[leaf]
        else:
            assert literal in render._spelled(leaves[leaf], span)


MARGIN = st.sampled_from(["", " ", "\t", " \t "])
NOTE = st.sampled_from(["", "", "# note", "#A=1", "  # indented note  ", "#"])
KEY = st.from_regex(r"[A-Z][A-Z0-9_]{0,6}", fullmatch=True)
BARE = st.from_regex(r"[A-Za-z0-9:/._@-]{1,12}", fullmatch=True)
QUOTABLE = st.characters(exclude_categories=["Cs", "Cc", "Zl", "Zp"], exclude_characters="$`\\\"'")
QUOTED = st.text(alphabet=st.one_of(QUOTABLE, st.sampled_from(" #=")), max_size=10)
ASSIGNED = st.one_of(
    st.tuples(st.just("bare"), BARE),
    st.tuples(st.just("double"), st.one_of(QUOTED, QUOTED.map(lambda text: text + "'"))),
    st.tuples(st.just("single"), st.one_of(QUOTED, QUOTED.map(lambda text: '"' + text))),
)
QUOTES = {"bare": "", "double": '"', "single": "'"}


@GENERATED
@given(
    st.dictionaries(KEY, st.tuples(ASSIGNED, MARGIN, MARGIN, NOTE), max_size=6),
    st.booleans(),
)
def test_assignment_span_is_the_value_the_importer_reads(lines: Any, final: bool) -> None:
    text = ""
    for key, ((style, value), before, after, note) in lines.items():
        quote = QUOTES[style]
        text += f"{note}\n\n{before}{key}={quote}{value}{quote}{after}\n"
    raw = (text if final else text.removesuffix("\n")).encode("utf-8")
    leaves = render._leaves(_decode(raw, "literal-env"))
    spans = render._assignment_spans(raw)
    assert set(spans) == set(leaves) and disjoint(spans)
    for key, ((style, value), *_rest) in lines.items():
        span = spans[(key,)]
        assert (span.style, span.kind) == (style, "string")
        assert raw[span.start : span.end].decode("utf-8") == value == leaves[(key,)]
        assert render._spelled(value, span) == [value.encode("utf-8")]


ITEM = st.from_regex(r"[A-Za-z0-9_.:-]{1,10}", fullmatch=True)


@GENERATED
@given(st.lists(st.tuples(ITEM, MARGIN, MARGIN, NOTE), max_size=8, unique_by=lambda row: row[0]))
def test_list_span_is_the_item_the_importer_reads(rows: Any) -> None:
    raw = "".join(f"{note}\n{before}{item}{after}\n\n" for item, before, after, note in rows)
    leaves = render._leaves(_decode(raw.encode(), "text-list"))
    spans = render._list_spans(raw.encode())
    assert set(spans) == set(leaves) and disjoint(spans)
    for index, (item, *_rest) in enumerate(rows):
        span = spans[("items", str(index))]
        assert raw.encode()[span.start : span.end].decode() == item == leaves[("items", str(index))]


# ---- whole files rendered from generated instance values

WORDS = "abcdefghij klmnop'=#:;,.!?()[]@%+-_|~^*/"
JSON_WORDS = WORDS + '"\\<>&' + "éü漢\U0001f600"
PLIST_WORDS = WORDS + '"<>&' + "éü漢\U0001f600"
SPACE = st.sampled_from(["", " ", "\n", "\t", "\r\n  "])
CONSTANT = st.from_regex(r"[a-z]{1,6}", fullmatch=True)
NUMBER = st.integers(1, 2**31 - 1)


class Pieces:
    """A file assembled from byte pieces; a slot is the piece that holds one mapped literal."""

    def __init__(self) -> None:
        self.parts: list[bytes] = []
        self.slots: dict[str, int] = {}
        self.styles: dict[str, str] = {}
        self.constants: list[str] = []

    def add(self, data: str | bytes) -> None:
        self.parts.append(data if isinstance(data, bytes) else data.encode("utf-8"))

    def slot(self, selector: str, style: str, literal: bytes) -> None:
        self.slots[selector] = len(self.parts)
        self.styles[selector] = style
        self.parts.append(literal)

    def raw(self) -> bytes:
        return b"".join(self.parts)

    def replaced(self, selector: str, literal: bytes) -> bytes:
        parts = list(self.parts)
        parts[self.slots[selector]] = literal
        return b"".join(parts)


def spell(style: str, value: Any) -> bytes:
    """The literal of a value in one style, written without the renderer."""
    if style == "json-raw":
        return json.dumps(value, ensure_ascii=False).encode("utf-8")
    if style == "json-ascii":
        return json.dumps(value, ensure_ascii=True).encode("ascii")
    if style == "json-number":
        return str(value).encode()
    if style == "json-boolean":
        return b"true" if value else b"false"
    if style == "json-digits":
        return b'"' + str(value).encode() + b'"'
    if style in ("plist-escaped", "plist-open"):
        text = value.replace("&", "&amp;").replace("<", "&lt;")
        return (text.replace(">", "&gt;") if style == "plist-escaped" else text).encode("utf-8")
    if style == "plist-boolean":
        return b"<true/>" if value else b"<false/>"
    return str(value).encode("utf-8")


def undetermined(style: str, old: Any, new: Any) -> bool:
    """The capture holds no evidence for a choice that the new value would need."""
    if style in ("json-raw", "json-ascii"):
        return old.isascii() and not new.isascii()
    if style in ("plist-escaped", "plist-open"):
        return ">" not in old and ">" in new
    return False


def bare_cdata_end(style: str, value: Any) -> bool:
    """A text holding "]]>" written with ">" bare, which XML character data cannot hold."""
    return style == "plist-open" and isinstance(value, str) and "]]>" in value


POINTERS = {
    "text": [f"/host/baseline/network_extensions/{index}" for index in range(3)],
    "number": ["/host/account/uid", "/supervision/health_seconds"],
    "boolean": ["/host/baseline/filevault", "/host/baseline/power_restart"],
}


def with_values(values: dict[str, Any]) -> Any:
    def mutate(data: dict[str, Any]) -> None:
        texts = [values[pointer] for pointer in POINTERS["text"] if pointer in values]
        data["host"]["baseline"]["network_extensions"] = texts
        for pointer, value in values.items():
            if pointer not in POINTERS["text"]:
                section, *middle, last = pointer.strip("/").split("/")
                node = data[section]
                for part in middle:
                    node = node[part]
                node[last] = value

    try:
        return changed(mutate)
    except InstanceError:
        # A generated text the closed instance refuses, such as one shaped like an address.
        assume(False)


def draw_values(data: st.DataObject, text: st.SearchStrategy[str], kinds: str) -> dict[str, Any]:
    """Instance values for a prefix of the text slots and any of the other slots."""
    count = data.draw(st.integers(1, 3))
    texts = data.draw(st.lists(text, min_size=count, max_size=count))
    values: dict[str, Any] = dict(zip(POINTERS["text"][:count], texts, strict=True))
    if "number" in kinds:
        values["/host/account/uid"] = data.draw(NUMBER)
        if data.draw(st.booleans()):
            values["/supervision/health_seconds"] = data.draw(st.integers(5, 120))
    if "boolean" in kinds:
        for pointer in POINTERS["boolean"]:
            if data.draw(st.booleans()):
                values[pointer] = data.draw(st.booleans())
    return values


def other_value(data: st.DataObject, text: st.SearchStrategy[str], pointer: str, old: Any) -> Any:
    if pointer in POINTERS["text"]:
        return data.draw(text.filter(lambda value: value != old))
    if pointer == "/supervision/health_seconds":
        return data.draw(st.integers(5, 120).filter(lambda value: value != old))
    if pointer in POINTERS["number"]:
        return data.draw(NUMBER.filter(lambda value: value != old))
    return not old


def check(
    data: st.DataObject,
    directory: Path,
    fmt: str,
    pieces: Pieces,
    pointers: dict[str, str],
    values: dict[str, Any],
    text: st.SearchStrategy[str],
    distinct: bool = False,
) -> None:
    """Unchanged values reproduce the file; one changed value moves exactly its literal."""
    # XML text cannot hold "]]>" with ">" bare: such a capture is never generated.
    assume(not any(bare_cdata_end(pieces.styles[s], values[p]) for s, p in pointers.items()))
    raw = pieces.raw()
    (directory / "input").write_bytes(raw)
    composed = {
        selector: [{"pointer": pointer}]
        for selector, pointer in pointers.items()
        if data.draw(st.booleans())
    }
    mapping = {
        selector: pointer for selector, pointer in pointers.items() if selector not in composed
    }
    entry = source("input", "input", fmt, mapping, composed=composed, constants=pieces.constants)
    path = manifest(directory, [entry])
    collected: dict[str, bytes] = {}
    result = render_sources(path, with_values(values), collect=collected)
    assert result.issues == () and collected == {"input": raw}
    found = result.sources[0]
    assert found.identical and found.complete
    assert found.mapped + found.composed == len(pointers)
    assert found.constants == found.leaves - len(pointers)

    selector = data.draw(st.sampled_from(sorted(pointers)))
    pointer, style = pointers[selector], pieces.styles[selector]
    new = other_value(data, text, pointer, values[pointer])
    if distinct:
        assume(str(new) not in {str(value) for value in values.values()})
    # Nor such a new value where the expected file would write it bare (refusals stay checked).
    assume(undetermined(style, values[pointer], new) or not bare_cdata_end(style, new))
    collected.clear()
    result = render_sources(path, with_values(values | {pointer: new}), collect=collected)
    if undetermined(style, values[pointer], new):
        assert [(issue.reason, issue.selector) for issue in result.issues] == [
            ("literal-style-unsupported", selector)
        ]
        assert collected == {}
    else:
        assert result.issues == ()
        assert collected == {"input": pieces.replaced(selector, spell(style, new))}
        assert not result.sources[0].identical and result.sources[0].complete


def json_literal(data: st.DataObject, pointer: str, value: Any) -> tuple[str, bytes]:
    if isinstance(value, bool):
        style = "json-boolean"
    elif isinstance(value, int):
        style = data.draw(st.sampled_from(["json-number", "json-digits"]))
    else:
        style = data.draw(st.sampled_from(["json-raw", "json-ascii"]))
    return style, spell(style, value)


@RENDERED
@given(data=st.data())
def test_json_file_is_reproduced_and_only_a_changed_value_moves(
    data: st.DataObject, tmp_path_factory: pytest.TempPathFactory
) -> None:
    text = st.text(alphabet=JSON_WORDS, min_size=1, max_size=12)
    values = draw_values(data, text, "number boolean")
    pieces, pointers = Pieces(), {}
    pieces.add(data.draw(SPACE) + "{")
    slots = data.draw(st.permutations(sorted(values)))
    for index, pointer in enumerate(slots):
        pieces.add(("," if index else "") + data.draw(SPACE))
        shape = data.draw(st.sampled_from(["leaf", "array", "object"]))
        key = f"k{index}"
        pieces.add(json.dumps(key) + data.draw(SPACE) + ":" + data.draw(SPACE))
        constant = json.dumps(data.draw(st.one_of(CONSTANT, st.integers(0, 99), st.none())))
        if shape == "leaf":
            selector = f"/{key}"
        elif shape == "array":
            selector = f"/{key}/1"
            pieces.add(
                "[" + data.draw(SPACE) + constant + data.draw(SPACE) + "," + data.draw(SPACE)
            )
            pieces.constants.append(f"/{key}/0")
        else:
            selector = f"/{key}/m"
            pieces.add('{"c"' + data.draw(SPACE) + ":" + constant + "," + data.draw(SPACE) + '"m":')
            pieces.constants.append(f"/{key}/c")
        pieces.slot(selector, *json_literal(data, pointer, values[pointer]))
        pointers[selector] = pointer
        pieces.add(data.draw(SPACE) + {"leaf": "", "array": "]", "object": "}"}[shape])
    pieces.add(data.draw(SPACE) + "}" + data.draw(SPACE))
    check(data, tmp_path_factory.mktemp("json"), "json", pieces, pointers, values, text)


@RENDERED
@given(data=st.data())
def test_property_list_is_reproduced_and_only_a_changed_value_moves(
    data: st.DataObject, tmp_path_factory: pytest.TempPathFactory
) -> None:
    text = st.text(alphabet=PLIST_WORDS, min_size=1, max_size=12)
    layout = st.sampled_from(["", "\n", "\t", "\n\t<!-- note -->\n", " "])
    values = draw_values(data, text, "number boolean")
    pieces, pointers = Pieces(), {}
    pieces.add(PLIST_HEAD + b"<dict>")
    for index, pointer in enumerate(data.draw(st.permutations(sorted(values)))):
        value = values[pointer]
        key = f"k{index}"
        pieces.add(data.draw(layout) + f"<key>{key}</key>" + data.draw(layout))
        nested = data.draw(st.booleans())
        if nested:
            constant = data.draw(CONSTANT)
            pieces.add(f"<array><string>{constant}</string>" + data.draw(layout))
            pieces.constants.append(f"/{key}/0")
        selector = f"/{key}/1" if nested else f"/{key}"
        if isinstance(value, bool):
            pieces.slot(selector, "plist-boolean", spell("plist-boolean", value))
        elif isinstance(value, int):
            pieces.add("<integer>")
            pieces.slot(selector, "plain", spell("plain", value))
            pieces.add("</integer>")
        else:
            style = data.draw(st.sampled_from(["plist-escaped", "plist-open"]))
            pieces.add("<string>")
            pieces.slot(selector, style, spell(style, value))
            pieces.add("</string>")
        pointers[selector] = pointer
        pieces.add((data.draw(layout) + "</array>") if nested else "")
    pieces.add(data.draw(layout) + "</dict></plist>" + data.draw(st.sampled_from(["", "\n"])))
    check(data, tmp_path_factory.mktemp("plist"), "plist", pieces, pointers, values, text)


def test_text_with_the_cdata_end_is_never_written_with_a_bare_gt(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    # The minimal falsifying example of the property above: this capture is no XML.
    pointer = POINTERS["text"][0]
    pieces = Pieces()
    pieces.add(PLIST_HEAD + b"<dict><key>k0</key><string>")
    pieces.slot("/k0", "plist-open", spell("plist-open", "]]>"))
    pieces.add("</string></dict></plist>")
    with pytest.raises(ParseError):
        _decode(pieces.raw(), "plist")

    @settings(RENDERED, database=None)
    @given(data=st.data())
    def generated(data: st.DataObject) -> None:
        directory = tmp_path_factory.mktemp("plist")
        check(data, directory, "plist", pieces, {"/k0": pointer}, {pointer: "]]>"}, st.just("x"))

    # The generator discards it before anything is drawn or rendered.
    with pytest.raises(Unsatisfiable):
        generated()


@RENDERED
@given(data=st.data())
def test_assignment_file_is_reproduced_and_only_a_changed_value_moves(
    data: st.DataObject, tmp_path_factory: pytest.TempPathFactory
) -> None:
    style = data.draw(st.sampled_from(["bare", "double", "single"]))
    alphabet = {
        "bare": "abcXYZ019:/._@-",
        "double": WORDS + "<>&é漢",
        "single": WORDS.replace("'", "") + '"<>&é漢',
    }[style]
    text = st.text(alphabet=alphabet, min_size=1, max_size=12)
    values = draw_values(data, text, "number")
    pieces, pointers = Pieces(), {}
    for index, pointer in enumerate(data.draw(st.permutations(sorted(values)))):
        pieces.add(data.draw(NOTE) + "\n" + data.draw(MARGIN))
        if data.draw(st.booleans()):
            pieces.add(f"C{index}=" + data.draw(CONSTANT) + "\n")
            pieces.constants.append(f"/C{index}")
        quoting = style
        if not isinstance(values[pointer], str):
            quoting = data.draw(st.sampled_from(sorted(QUOTES)))
        pieces.add(f"K{index}=" + QUOTES[quoting])
        pieces.slot(f"/K{index}", "plain", spell("plain", values[pointer]))
        pointers[f"/K{index}"] = pointer
        pieces.add(QUOTES[quoting] + data.draw(MARGIN) + "\n")
    pieces.add(data.draw(NOTE))
    check(data, tmp_path_factory.mktemp("env"), "literal-env", pieces, pointers, values, text)


@RENDERED
@given(data=st.data())
def test_list_file_is_reproduced_and_only_a_changed_value_moves(
    data: st.DataObject, tmp_path_factory: pytest.TempPathFactory
) -> None:
    # Items are distinct: lower-case constants, upper-case text and digits never meet.
    text = st.text(alphabet="ABCXYZ_.:-", min_size=1, max_size=12)
    values = draw_values(data, text, "number")
    assume(len(set(map(str, values.values()))) == len(values))
    pieces, pointers = Pieces(), {}
    constants = data.draw(st.lists(CONSTANT, max_size=3, unique=True))
    rows = data.draw(st.permutations([*sorted(values), *constants]))
    for index, row in enumerate(rows):
        pieces.add(data.draw(NOTE) + "\n" + data.draw(MARGIN))
        if row in values:
            pieces.slot(f"/items/{index}", "plain", spell("plain", values[row]))
            pointers[f"/items/{index}"] = row
        else:
            pieces.add(row)
            pieces.constants.append(f"/items/{index}")
        pieces.add(data.draw(MARGIN) + "\n")
    directory = tmp_path_factory.mktemp("list")
    check(data, directory, "text-list", pieces, pointers, values, text, distinct=True)

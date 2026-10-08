"""Where the importer's key guard sees a word boundary, and what finding it costs.

Only ``_`` and ``-`` separate words, only ASCII letters and digits make a
boundary inside a run of letters, and only one final line feed is set aside.
The expression that finds the boundary inside an acronym repeats nothing, so a
long run of capitals is read once, and so are the letters and digits before a
password word. A key of the greatest length each caller can meet is judged like
a short one.
"""

from __future__ import annotations

import itertools
import re
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from netorch import legacy_import
from netorch.legacy_import import ImportError, _secret_key, import_sources
from tests.test_importer_credential_capitals import VALUE, refused_before, write_source

UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER = UPPER.lower()

NO_BREAK_SPACE = "\N{NO-BREAK SPACE}"
SOFT_HYPHEN = "\N{SOFT HYPHEN}"
ZERO_WIDTH_SPACE = "\N{ZERO WIDTH SPACE}"
MINUS = "\N{MINUS SIGN}"


def beside(char: str) -> list[str]:
    """Keys in which only ``char`` stands between a listed word and its neighbour."""
    return [
        f"my{char}token",
        f"token{char}my",
        f"my{char}toKen{char}my",
        f"api{char}key",
        f"db{char}password",
    ]


def test_only_an_underscore_and_a_hyphen_separate_words() -> None:
    # Every ASCII character that is neither a letter nor a digit nor one of the
    # two separators, every connector and dash of Unicode beside them, and four
    # characters that look like a space or a hyphen.
    others = [chr(code) for code in range(128) if not chr(code).isalnum()]
    others += [
        chr(code) for code in range(128, 0x20000) if unicodedata.category(chr(code)) in {"Pc", "Pd"}
    ]
    others += [NO_BREAK_SPACE, SOFT_HYPHEN, ZERO_WIDTH_SPACE, MINUS]
    others = [char for char in others if char not in "_-"]
    assert len(others) > 80 and ":" in others and "." in others and " " in others
    for char in others:
        refused = [key for key in beside(char) if refused_before(key) or _secret_key(key)]
        assert refused == [], f"U+{ord(char):04X}"
    for char in "_-":
        assert [key for key in beside(char) if not _secret_key(key)] == []


E_ACUTE = "\N{LATIN SMALL LETTER E WITH ACUTE}"
SHARP_S = "\N{LATIN SMALL LETTER SHARP S}"
LONG_S = "\N{LATIN SMALL LETTER LONG S}"
DOTLESS_I = "\N{LATIN SMALL LETTER DOTLESS I}"
CYRILLIC_A = "\N{CYRILLIC SMALL LETTER A}"
FULLWIDTH_A = "\N{FULLWIDTH LATIN SMALL LETTER A}"
CAPITAL_E_ACUTE = "\N{LATIN CAPITAL LETTER E WITH ACUTE}"
CAPITAL_SIGMA = "\N{GREEK CAPITAL LETTER SIGMA}"
CAPITAL_YA = "\N{CYRILLIC CAPITAL LETTER YA}"
KELVIN = "\N{KELVIN SIGN}"
DOTTED_I = "\N{LATIN CAPITAL LETTER I WITH DOT ABOVE}"
FULLWIDTH_CAPITAL_A = "\N{FULLWIDTH LATIN CAPITAL LETTER A}"
OTHER_LOWER = [E_ACUTE, SHARP_S, LONG_S, DOTLESS_I, CYRILLIC_A, FULLWIDTH_A]
OTHER_CAPITALS = [CAPITAL_E_ACUTE, CAPITAL_SIGMA, CAPITAL_YA, KELVIN, DOTTED_I, FULLWIDTH_CAPITAL_A]
OTHER_DIGITS = [
    "\N{ARABIC-INDIC DIGIT THREE}",
    "\N{DEVANAGARI DIGIT THREE}",
    "\N{FULLWIDTH DIGIT THREE}",
    "\N{SUPERSCRIPT TWO}",
    "\N{VULGAR FRACTION ONE HALF}",
]


def test_only_ascii_letters_and_digits_make_a_boundary() -> None:
    # Each expression has classes of ASCII characters only. Beside every key
    # that stays data stands the same key with an ASCII character at the place:
    # that one is refused, so the script alone decides.
    stays = []
    # A capital after a lower-case letter or a digit: the character before the capital.
    assert _secret_key("aToken") and _secret_key("3Token")
    stays += [char + "Token" for char in OTHER_LOWER + OTHER_DIGITS]
    # The capital itself.
    assert _secret_key("tokenE")
    stays += ["token" + char for char in OTHER_CAPITALS]
    # The last capital of an acronym: the capital before it, the capital, the
    # lower-case letter after it.
    assert _secret_key("EToken") and _secret_key("TOKENXx") and _secret_key("TOKENXe")
    stays += [char + "Token" for char in OTHER_CAPITALS]
    stays += ["TOKEN" + char + "x" for char in OTHER_CAPITALS]
    stays += ["TOKENX" + char for char in OTHER_LOWER]
    assert [key for key in stays if refused_before(key) or _secret_key(key)] == []
    # Letters and digits before a password word: ASCII ones, and the four other
    # letters that case-insensitive matching equates with ASCII letters.
    assert _secret_key("x3password") and _secret_key("X" + LONG_S + "password")
    stays = [char + "password" for char in (E_ACUTE, SHARP_S, CYRILLIC_A, *OTHER_DIGITS)]
    stays += ["x" + char + "passWord" for char in (E_ACUTE, CAPITAL_E_ACUTE, ".", " ")]
    assert [key for key in stays if refused_before(key) or _secret_key(key)] == []


# Every character at which ``str.splitlines`` ends a line, and other white space.
LINE_ENDS = ["\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\N{LINE SEPARATOR}"]
LINE_ENDS += ["\N{PARAGRAPH SEPARATOR}", "\t", " ", "\0", NO_BREAK_SPACE]


def test_only_one_final_line_feed_is_set_aside() -> None:
    assert _secret_key("toKen\n") and _secret_key("token\n") and _secret_key("dbpassWord\n")
    stays = ["toKen\n\n", "token\n\n", "\ntoKen", "toKen\nx"]
    for char in LINE_ENDS:
        stays += ["toKen" + char, "token" + char, "dbpassWord" + char]
        stays += ["toKen" + char + "\n", "toKen\n" + char, char + "toKen"]
    assert [key for key in stays if refused_before(key) or _secret_key(key)] == []


def described(text: str) -> list[int]:
    """The places before a capital that stands between a capital and a lower-case letter."""
    return [
        index
        for index in range(1, len(text) - 1)
        if text[index - 1] in UPPER and text[index] in UPPER and text[index + 1] in LOWER
    ]


def test_the_first_boundary_expression_finds_the_places_of_the_earlier_one() -> None:
    # The earlier expression took a whole run of capitals into its first group.
    # Every string of at most 13 capitals and lower-case letters, and every
    # string of at most 6 characters out of two capitals, a lower-case letter, a
    # digit and a separator: the same places, and the same key written with a
    # mark at each of them.
    earlier = re.compile(r"([A-Z]+)([A-Z][a-z])")
    acronym = legacy_import._WORD_STARTS[0]
    count = 0
    different = []
    for alphabet, longest in (("Aa", 13), ("ABa9_", 6)):
        for length in range(longest + 1):
            for chars in itertools.product(alphabet, repeat=length):
                text = "".join(chars)
                count += 1
                places = [found.start(2) for found in acronym.finditer(text)]
                if (
                    places != described(text)
                    or places != [found.start(2) for found in earlier.finditer(text)]
                    or acronym.sub(r"\1_\2", text) != earlier.sub(r"\1_\2", text)
                ):
                    different.append(text)
    assert count == 2**14 - 1 + (5**7 - 1) // 4
    assert different[:8] == []


@pytest.mark.parametrize("length", [2, 3, 64, 4096, 65535])
def test_a_boundary_expression_reads_a_fixed_number_of_characters(length: int) -> None:
    acronym, camel = legacy_import._WORD_STARTS
    # Neither expression repeats anything or offers a choice: at a place a scan
    # reads three characters, or two, and goes on. The earlier first expression
    # took a run of capitals as one match and gave it back letter by letter,
    # once from every capital of the run where no lower-case letter followed.
    for expression in (acronym, camel):
        assert not set("+*?{|") & set(expression.pattern)
    key = "X" * length + "x"
    assert [found.span() for found in acronym.finditer(key)] == [(length - 2, length + 1)]
    assert [found.span() for found in camel.finditer("x" + "X" * length)] == [(0, 2)]
    # With that established, a key that is one run of capitals of the greatest
    # length a decoded source may hold is answered like any other.
    assert not _secret_key("X" * (length + 1))
    assert not _secret_key("X" * (length - 1) + "token")
    assert _secret_key("X" * (length - 1) + "Token")


class CountedScan:
    """The scan of letters and digits, counting the characters it reads."""

    def __init__(self, scan: re.Pattern[str]) -> None:
        self.scan = scan
        self.read = 0

    def match(self, key: str, start: int) -> re.Match[str]:
        found = self.scan.match(key, start)
        assert found is not None
        # The run, and the character that ends it.
        self.read += found.end() - start + 1
        return found


@pytest.mark.parametrize(
    "unit,times",
    [("xY", 2048), ("x_", 2048), ("example_", 512), ("exampleItem", 372), ("X", 4096), ("9", 4096)],
)
def test_the_letters_and_digits_before_a_password_word_are_read_once(
    monkeypatch: pytest.MonkeyPatch, unit: str, times: int
) -> None:
    # A password word may start after letters and digits that follow a possible
    # boundary. A run of them is read from its first boundary only, also where
    # every second character of it starts a word: each character once, and one
    # more for each place the scan starts at.
    key = unit * times
    counted = CountedScan(legacy_import._LETTERS_AND_DIGITS)
    monkeypatch.setattr(legacy_import, "_LETTERS_AND_DIGITS", counted)
    assert not _secret_key(key)
    assert len(key) <= counted.read <= 2 * len(key) + 2
    assert _secret_key(key + "passWord")


# A key of the greatest length each caller can meet: a pointer part of 2,047
# characters (a pointer holds at most 2,048), and a key of 65,536 characters
# inside a decoded source. The word stands at the far end.
POINTER_PART = 2047
SOURCE_KEY = 65536
# The ending that holds the word, the kind of boundary before it, and an ending
# of the same shape that holds no word between boundaries.
ENDINGS = {
    "after a separator": ("passWord", "passWords"),
    "after a lower-case letter": ("dbToKen", "dbToKens"),
    "after an acronym": ("HTTPToKen", "HTTPTOken"),
    "before a suffix word": ("toKenFile", "toKenfile"),
}
FILLERS = {"separators": "example_", "capitals": "exampleItem"}


def long_key(length: int, filler: str, ending: str) -> str:
    """``length`` characters: the filler repeated, a separator, the ending."""
    room = length - len(ending) - 1
    key = (filler * (room // len(filler) + 1))[:room] + "_" + ending
    assert len(key) == length
    return key


LONG_KEYS = [
    pytest.param(filler, refused, data, id=f"{name} {kind}")
    for name, filler in FILLERS.items()
    for kind, (refused, data) in ENDINGS.items()
]


def imported(tmp_path: Path, data: Any, mapping: dict[str, str]) -> dict[str, Any]:
    result = import_sources(write_source(tmp_path, data, mapping))
    assert not result.underivable
    return result.values


@pytest.mark.parametrize("filler,refused,data", LONG_KEYS)
def test_a_pointer_part_of_the_greatest_length_is_judged_to_its_end(
    tmp_path: Path, filler: str, refused: str, data: str
) -> None:
    key = long_key(POINTER_PART, filler, refused)
    for source, mapping in (
        ({key: VALUE}, {f"/{key}": "/chosen"}),
        ({"chosen": VALUE}, {"/chosen": f"/{key}"}),
    ):
        with pytest.raises(ImportError, match="Credential"):
            import_sources(write_source(tmp_path, source, mapping))
    # The same key without the word at its end is ordinary data at both places.
    key = long_key(POINTER_PART, filler, data)
    assert imported(tmp_path, {key: VALUE}, {f"/{key}": "/chosen"}) == {"chosen": VALUE}
    assert imported(tmp_path, {"chosen": VALUE}, {"/chosen": f"/{key}"}) == {key: VALUE}


@pytest.mark.parametrize("filler,refused,data", LONG_KEYS)
def test_a_key_of_the_greatest_length_inside_a_mapped_value_is_judged_to_its_end(
    tmp_path: Path, filler: str, refused: str, data: str
) -> None:
    key = long_key(SOURCE_KEY, filler, refused)
    with pytest.raises(ImportError, match="Credential"):
        import_sources(write_source(tmp_path, {"chosen": [{key: VALUE}]}, {"/chosen": "/chosen"}))
    key = long_key(SOURCE_KEY, filler, data)
    source = {"chosen": [{key: VALUE}]}
    assert imported(tmp_path, source, {"/chosen": "/chosen"}) == source


def test_the_greatest_lengths_are_the_callers_bounds(tmp_path: Path) -> None:
    # One character more and the key never reaches the guard: the pointer is
    # refused as a pointer, and the source is reported as unreadable.
    key = long_key(POINTER_PART + 1, "example_", "passWords")
    with pytest.raises(ImportError, match="pointer"):
        import_sources(write_source(tmp_path, {key: VALUE}, {f"/{key}": "/chosen"}))
    key = long_key(SOURCE_KEY + 1, "example_", "passWords")
    result = import_sources(write_source(tmp_path, {"chosen": {key: VALUE}}, {"/chosen": "/c"}))
    assert [issue.reason for issue in result.underivable] == ["unsupported-static-syntax"]
    assert result.values == {}

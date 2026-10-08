"""A capital inside a credential word must not hide the word from the importer's key guard.

The guard used to split a key into words first and to look for a credential
word between the splits afterwards. A split that fell inside the word, as in
``passWord`` (``pass`` and ``Word``) or ``APIkey`` (``AP`` and ``Ikey``), hid
the word, and the importer mapped the value. A word now counts where it starts
and ends at a possible word boundary, whatever lies between. A password word
may, as before, also start after letters and digits that follow a boundary.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from netorch.legacy_import import ImportError, _secret_key, generated_bytes, import_sources
from tests.test_importer_literals import PLIST_HEAD
from tests.test_legacy_import import entry, manifest

GUIDE = Path(__file__).resolve().parents[1] / "docs" / "legacy-import.md"
REFUSAL = "Credential and environment values are not instance data"
VALUE = "synthetic-credential-must-not-be-emitted"

# The closed list, written out a second time on purpose: the tests must notice
# a word that leaves the guard.
SIMPLE = ("env", "environment", "token", "secret", "credential", "credentials", "authorization")
# The password words: letters and digits may stand between a boundary and one of them.
PASSWORDS = ("password", "passwd", "passphrase")
COMPOUND = (("private", "key"), ("api", "key"), ("pass", "phrase"))
JOINTS = ("", "_", "-")
# Every listed word in lower case, and where the second part of a compound word starts.
FORMS: dict[str, int | None] = {word: None for word in SIMPLE + PASSWORDS} | {
    first + joint + second: len(first + joint) for first, second in COMPOUND for joint in JOINTS
}
# The forms that the guard knew two steps back, before passphrases were listed.
EARLIEST_FORMS = [form for form in FORMS if "phrase" not in form]

# The guard as it was on the base of this change, copied verbatim (it already
# took a password word after letters and digits), and the guard one step
# earlier: the oracles for "whatever was refused before is still refused".
_EARLIER = re.compile(
    r"(?:^|[_-])(env|environment|token|secret|credential|credentials|authorization"
    r"|private_?key|api_?key|pass_phrase|[a-z0-9]*(?:password|passwd|passphrase))(?:$|[_-])",
    re.I,
)
_EARLIEST = re.compile(
    r"(?:^|[_-])(env|environment|password|passwd|token|secret|credential|credentials"
    r"|authorization|private_?key|api_?key)(?:$|[_-])",
    re.I,
)


def refused_before(key: str) -> bool:
    words = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", words).replace("-", "_")
    return _EARLIER.search(words) is not None


def refused_earliest(key: str) -> bool:
    words = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", words).replace("-", "_")
    return _EARLIEST.search(words) is not None


# The rule, written by another method than the guard uses: the earlier
# expression, in which the mark that the two splitting expressions insert is
# told apart from a real separator, is optional between the letters of a word,
# and may stand among the letters and digits before a password word.
MARK = chr(0xE000)


def _rule() -> re.Pattern[str]:
    def spelled(part: str) -> str:
        return f"{MARK}?".join(part)

    words = [spelled(word) for word in SIMPLE]
    words += [f"{spelled(first)}[_{MARK}]?{spelled(second)}" for first, second in COMPOUND]
    words += [f"[a-z0-9{MARK}]*{spelled(word)}" for word in PASSWORDS]
    return re.compile(f"(?:^|[_{MARK}])(?:{'|'.join(words)})(?:$|[_{MARK}])", re.I)


_RULE = _rule()


def refused_by_rule(key: str) -> bool:
    assert MARK not in key
    marked = re.sub(r"([A-Z]+)([A-Z][a-z])", rf"\1{MARK}\2", key)
    marked = re.sub(r"([a-z0-9])([A-Z])", rf"\1{MARK}\2", marked).replace("-", "_")
    return _RULE.search(marked) is not None


def with_capitals(form: str, capitals: Iterable[int]) -> str:
    chosen = set(capitals)
    return "".join(char.upper() if index in chosen else char for index, char in enumerate(form))


def letter_positions(form: str) -> list[int]:
    return [index for index, char in enumerate(form) if char.isalpha()]


def regular(form: str) -> list[str]:
    """One case throughout, or a capital only where a word of the key starts."""
    spellings = [form, form.upper(), with_capitals(form, [0])]
    second = FORMS[form]
    if second is not None:
        spellings += [with_capitals(form, [second]), with_capitals(form, [0, second])]
    return spellings


def irregular(form: str) -> list[str]:
    """Capitals at every place inside the word."""
    letters = letter_positions(form)
    spellings: list[str] = []
    for index in letters[1:]:
        if index != FORMS[form]:
            # passWord and PassWord: a capital after a lower-case letter.
            spellings += [with_capitals(form, [index]), with_capitals(form, [0, index])]
    for count in range(2, len(letters)):
        # PAssword to PASSWORd: an acronym, then lower case.
        spellings.append(with_capitals(form, letters[:count]))
    for count in range(1, len(letters)):
        # pASSWORD to passworD: lower case, then capitals to the end.
        spellings.append(with_capitals(form, letters[count:]))
    return spellings


def upper_first(spelling: str) -> str:
    return spelling[:1].upper() + spelling[1:]


# Where a word may stand in a key so that it starts and ends at a possible boundary.
PLACES: dict[str, Callable[[str], str]] = {
    "the whole key": lambda spelling: spelling,
    "after an underscore": lambda spelling: "site_" + spelling,
    "after a hyphen": lambda spelling: "site-" + spelling,
    "before an underscore": lambda spelling: spelling + "_file",
    "before a hyphen": lambda spelling: spelling + "-file",
    "between separators": lambda spelling: "site-" + spelling + "_file",
    "after a prefix word": lambda spelling: "db" + upper_first(spelling),
    "after a digit": lambda spelling: "v2" + upper_first(spelling),
    "before a suffix word": lambda spelling: spelling + "File",
    "between two words": lambda spelling: "db" + upper_first(spelling) + "File",
}


def placed_spellings(form: str, spellings: list[str]) -> list[str]:
    keys = [place(spelling) for spelling in spellings for place in PLACES.values()]
    # After an acronym a word starts only where a lower-case letter follows its capital.
    keys += ["HTTP" + upper_first(spelling) for spelling in spellings if spelling[1].islower()]
    return keys


def write_source(tmp_path: Path, data: Any, mapping: dict[str, str]) -> Path:
    (tmp_path / "owner.json").write_text(json.dumps(data))
    return manifest(tmp_path, [entry(mapping=mapping)])


def placed(location: str, key: str) -> tuple[Any, dict[str, str], dict[str, Any]]:
    """A JSON source, an explicit mapping, and the view they give if the key is ordinary data."""
    if location == "selector":
        return {key: VALUE}, {f"/{key}": "/chosen"}, {"chosen": VALUE}
    if location == "selector-parent":
        return {key: {"inner": VALUE}}, {f"/{key}/inner": "/chosen"}, {"chosen": VALUE}
    if location == "destination":
        return {"chosen": VALUE}, {"/chosen": f"/{key}"}, {key: VALUE}
    if location == "destination-parent":
        return {"chosen": VALUE}, {"/chosen": f"/{key}/inner"}, {key: {"inner": VALUE}}
    if location == "nested":
        return {"chosen": {key: VALUE}}, {"/chosen": "/chosen"}, {"chosen": {key: VALUE}}
    if location == "nested-in-a-list":
        data = {"chosen": [{"plain": 1}, [{key: VALUE}]]}
        return data, {"/chosen": "/chosen"}, data
    assert location == "nested-object"
    data = {"chosen": {key: {"inner": {"deep": VALUE}}}}
    return data, {"/chosen": "/chosen"}, data


# Both callers of the guard: the parts of a selector and of a destination
# pointer, and the keys inside a mapped value.
LOCATIONS = [
    "selector",
    "selector-parent",
    "destination",
    "destination-parent",
    "nested",
    "nested-in-a-list",
    "nested-object",
]
NEWLY_REFUSED = [
    "passWord",
    "PassWord",
    "toKen",
    "APIkey",
    "dbPassWord",
    "myAPIkey",
    # Letters before a password word and a capital inside it.
    "dbpassWord",
    "passpHrase",
]
ALREADY_REFUSED = ["password", "PASSWORD", "dbPassword", "api_key", "apiToken", "PGPASSWORD"]
# Named by the guard's docstring, by its earlier tests and by the review that asked for this.
NAMED_DATA = [
    "monkey",
    "tokenizer",
    "secretary",
    "environmental",
    "SECRETARY",
    "TOKENIZER",
    "MAXTOKEN",
    "ENVELOPE",
]
E_ACUTE = "\N{LATIN SMALL LETTER E WITH ACUTE}"
CAPITAL_E_ACUTE = "\N{LATIN CAPITAL LETTER E WITH ACUTE}"
STAYS_DATA = [
    *NAMED_DATA,
    # The word starts at a boundary and does not end at one, capitals inside or not.
    "toKenizer",
    "passWords",
    "SECRETARy",
    "apiKeyring",
    "tokens",
    "TOKENs",
    "envoy",
    "passwordless",
    "PermitEmptyPasswords",
    # The word ends at a boundary and does not start at one.
    "myseCret",
    "mytoKen",
    "MYAPIkey",
    "XTOKEN",
    # A separator inside a simple word, or more than one between the parts of a compound word.
    "pass_word",
    "to-ken",
    "private__key",
    "api-_key",
    "api_-key",
    "pass__phrase",
    # A compound word written with a separator starts at a boundary like any other word.
    "mypass_phrase",
    "bypass_phrase",
    # Characters that are not separators the guard knows, before or after a capital.
    "db.password",
    "api.key",
    "api key",
    "private.key",
    "private key",
    "my.toKen",
    "my.Token",
    "my token",
    "db passWord",
    "passWord.old",
    "toKen/2",
    "toKen ",
    " toKen",
    # Only ASCII letters make a boundary: no other lower-case letter before a
    # capital, and no other capital after a lower-case letter or in an acronym.
    "d" + E_ACUTE + "Token",
    "token" + CAPITAL_E_ACUTE,
    CAPITAL_E_ACUTE + "Token",
    # A digit makes a boundary only before a capital, and ends no acronym.
    "token2",
    "toKen2",
    "2toKen",
    "passWord1",
    "ENVX9",
    "TOKENX2",
    # Only one final line feed is set aside, and only at the end.
    "toKen\n\n",
    "\ntoKen",
    "toKen\r\n",
]


# Half of a compound word, plurals and neighbours of the listed words: the list is closed.
NOT_LISTED = [
    "private",
    "api",
    "key",
    "keys",
    "apikeys",
    "privatekeys",
    "envs",
    "passwords",
    "pass",
    "phrase",
    "passphrases",
    "pwd",
    "tokens",
    "secrets",
    "cred",
    "creds",
    "auth",
    "authorize",
]


@pytest.mark.parametrize("location", LOCATIONS)
@pytest.mark.parametrize("key", NEWLY_REFUSED + ALREADY_REFUSED)
def test_a_credential_key_is_refused_wherever_the_importer_meets_it(
    tmp_path: Path, key: str, location: str
) -> None:
    data, mapping, _ = placed(location, key)
    with pytest.raises(ImportError, match="Credential") as error:
        import_sources(write_source(tmp_path, data, mapping))
    # The refusal is one fixed sentence: neither the value nor the key is in it.
    assert error.value.args == (REFUSAL,)
    assert VALUE not in str(error.value)


@pytest.mark.parametrize(
    "fmt,raw",
    [
        ("toml", b'[chosen]\nplain = 1\npassWord = "' + VALUE.encode() + b'"\n'),
        (
            "plist",
            PLIST_HEAD
            + b"<dict><key>chosen</key><dict><key>APIkey</key><string>"
            + VALUE.encode()
            + b"</string></dict></dict></plist>",
        ),
    ],
    ids=["toml", "plist"],
)
def test_the_other_data_formats_are_guarded_alike(tmp_path: Path, fmt: str, raw: bytes) -> None:
    (tmp_path / "owner").write_bytes(raw)
    with pytest.raises(ImportError, match="Credential") as error:
        import_sources(manifest(tmp_path, [entry("owner", fmt, mapping={"/chosen": "/chosen"})]))
    assert error.value.args == (REFUSAL,)


def test_only_mapped_keys_are_judged_and_no_value_is(tmp_path: Path) -> None:
    # An unmapped key is neither refused nor copied, and a value may spell a listed word.
    data = {"lan": "192.0.2.11", "passWord": VALUE, "names": ["passWord", "APIkey"]}
    result = import_sources(write_source(tmp_path, data, {"/lan": "/address", "/names": "/names"}))
    assert result.values == {"address": "192.0.2.11", "names": ["passWord", "APIkey"]}
    assert VALUE.encode() not in generated_bytes(result)


@pytest.mark.parametrize("location", ["selector", "destination", "nested"])
@pytest.mark.parametrize("key", NAMED_DATA)
def test_a_word_that_is_only_part_of_a_key_is_still_imported(
    tmp_path: Path, key: str, location: str
) -> None:
    data, mapping, expected = placed(location, key)
    result = import_sources(write_source(tmp_path, data, mapping))
    assert result.values == expected
    assert not result.underivable


@pytest.mark.parametrize("form", FORMS)
def test_regular_spellings_were_refused_before_and_still_are(form: str) -> None:
    keys = placed_spellings(form, regular(form))
    assert [key for key in keys if not refused_before(key)] == []
    if form in EARLIEST_FORMS:
        assert [key for key in keys if not refused_earliest(key)] == []
    assert [key for key in keys if not _secret_key(key)] == []


@pytest.mark.parametrize("form", FORMS)
def test_capitals_inside_a_listed_word_do_not_hide_it(form: str) -> None:
    keys = placed_spellings(form, irregular(form))
    hidden = [key for key in keys if not refused_before(key)]
    assert hidden, "every listed word could be hidden by a capital inside it"
    missed = [key for key in keys if not _secret_key(key)]
    assert not missed, f"{len(missed)} of {len(keys)} spellings pass the guard: {missed[:8]}"


@pytest.mark.parametrize("form", FORMS)
def test_every_capitalisation_of_a_listed_word_is_refused(form: str) -> None:
    letters = letter_positions(form)
    missed = [
        key
        for size in range(len(letters) + 1)
        for capitals in itertools.combinations(letters, size)
        if not _secret_key(key := with_capitals(form, capitals))
    ]
    assert not missed, f"{len(missed)} of {2 ** len(letters)} pass the guard: {missed[:8]}"


@pytest.mark.parametrize(
    "key",
    [
        # The word inside a longer one first, the same word between boundaries later.
        "tokenizer_token",
        "tokenizer_toKen",
        "MAXTOKEN-toKen",
        "passwords_passWord",
        # Of a word and a longer one that starts with it, only the shorter ends at a boundary.
        "envIronmentx",
        "eNvIronmentx",
        "credentialSx",
        "credenTialSx",
        # Only the longer one does.
        "environMent",
        "credenTials",
        # Of two password words after the same letters, only the first, or only
        # the second, ends at a boundary.
        "dbpasswordOldpasswords",
        "dbpasswordsOldpassWord",
    ],
)
def test_every_place_and_every_word_is_tried(key: str) -> None:
    assert _secret_key(key)


@pytest.mark.parametrize("key", STAYS_DATA)
def test_a_word_that_does_not_start_and_end_at_a_boundary_stays_data(key: str) -> None:
    assert not refused_earliest(key)
    assert not refused_before(key)
    assert not _secret_key(key)


@pytest.mark.parametrize("key", NOT_LISTED)
def test_a_word_that_is_not_on_the_list_stays_data(key: str) -> None:
    for spelling in (
        key,
        key.upper(),
        with_capitals(key, [0]),
        "site_" + key,
        "db" + upper_first(key),
    ):
        assert not refused_before(spelling)
        assert not _secret_key(spelling)


@pytest.mark.parametrize("form", FORMS)
def test_a_listed_word_glued_to_a_letter_or_a_digit(form: str) -> None:
    after = [form + "x", form + "9", form.upper() + "X", form.upper() + "9"]
    spellings = regular(form) + irregular(form)
    before = ["x" + spelling for spelling in spellings if spelling[0].islower()]
    before += ["9" + form, "X" + form, "X" + form.upper()]
    # Glued to what follows it, no word ends at a boundary.
    assert [key for key in after if refused_before(key) or _secret_key(key)] == []
    if form in PASSWORDS:
        # Letters and digits may stand before a password word. The capitals
        # inside it hid it there as well.
        assert [key for key in before if not _secret_key(key)] == []
        assert [key for key in before if not refused_before(key)] != []
    else:
        # Whatever the capitals inside: after a lower-case letter a lower-case word does not start.
        assert [key for key in before if refused_before(key) or _secret_key(key)] == []


# The capitals of a key decide where its boundaries are. The first key of a pair
# holds the word between two boundaries; in the second a capital beside the
# word, or the lack of one, leaves its start or its end without a boundary.
BOUNDARY_PAIRS = [
    # After a capital a word starts only as a capital and a lower-case letter.
    ("DBToken", "DBTOken"),
    ("DBToken", "DBtoken"),
    ("DBToken", "DBTOKEN"),
    ("XToken", "XTOKEN"),
    # "api" is half of a listed word; another acronym is no part of one.
    ("APIkey", "APItoken"),
    # Before capitals a word ends only in a lower-case letter.
    ("tokenID", "tokeNID"),
    ("tokenID", "TOKENID"),
    # After a lower-case letter or a digit a word starts only with a capital.
    ("dbToken", "dbtoKen"),
    ("v2Token", "v2token"),
    # Before a capital a word ends; before a lower-case letter or a digit it
    # ends only at a separator.
    ("tokenX", "tokenx"),
    ("token_2", "token2"),
    ("toKen_s", "toKens"),
]


@pytest.mark.parametrize("refused,imported", BOUNDARY_PAIRS)
def test_capitals_beside_a_word_decide_where_it_may_start_and_end(
    refused: str, imported: str
) -> None:
    assert _secret_key(refused)
    # Imported on the base as well: the change does not reach these spellings.
    assert not refused_before(imported)
    assert not _secret_key(imported)


@pytest.mark.parametrize(
    "key", ["bypassWord", "compassWd", "overpassPhrase", "dbpassWord", "x9passWd", "PGpassWord"]
)
def test_a_password_word_may_begin_inside_a_longer_word(key: str) -> None:
    # Letters and digits may stand before a password word, and a boundary inside
    # it does not hide it. Together the two rules refuse a key that neither
    # earlier guard refused, also where "pass" ends an ordinary word.
    assert not refused_earliest(key)
    assert not refused_before(key)
    assert _secret_key(key)


@pytest.mark.parametrize(
    "key",
    [
        "compass",
        "bypass",
        "bypass_cache",
        "bypassCache",
        "bypassWords",
        "bypass.Word",
        "bypass_Word",
        "compassWidth",
        "overpassPhrases",
    ],
)
def test_pass_alone_is_still_no_listed_word(key: str) -> None:
    assert not refused_before(key)
    assert not _secret_key(key)


KELVIN = "\N{KELVIN SIGN}"
LONG_S = "\N{LATIN SMALL LETTER LONG S}"
DOTTED_I = "\N{LATIN CAPITAL LETTER I WITH DOT ABOVE}"
DOTLESS_I = "\N{LATIN SMALL LETTER DOTLESS I}"


@pytest.mark.parametrize(
    "key",
    [
        "to" + KELVIN + "en",
        "pa" + LONG_S + "sword",
        "ap" + DOTLESS_I + "key",
        "AP" + DOTTED_I + "KEY",
        "my_" + LONG_S + "ecret",
        "token\n",
    ],
)
def test_spellings_that_only_the_earlier_expression_explains_are_still_refused(key: str) -> None:
    # Case-insensitive matching equates four other letters with k, s and i, and
    # ``$`` also matched before one final line feed.
    assert refused_earliest(key)
    assert refused_before(key)
    assert _secret_key(key)


def test_one_final_line_feed_does_not_hide_a_word_with_a_capital_inside() -> None:
    assert not refused_before("toKen\n")
    assert _secret_key("toKen\n")


def test_every_short_key_gets_the_answer_of_the_rule() -> None:
    # Every key of at most four of these characters: both cases of the shortest
    # listed word, both separators, a digit, other letters and a line feed.
    keys = [
        "".join(chars)
        for length in range(5)
        for chars in itertools.product("eEnNvV_-9xX\n", repeat=length)
    ]
    # Every capitalisation of that word with up to two characters on either
    # side: a letter of either case, a digit, both separators, a character the
    # guard does not know and a line feed.
    edges = [
        "".join(chars)
        for length in range(3)
        for chars in itertools.product("xX9_-.\n", repeat=length)
    ]
    words = [
        with_capitals("env", capitals)
        for size in range(4)
        for capitals in itertools.combinations(range(3), size)
    ]
    keys += [before + word + after for before in edges for word in words for after in edges]
    # Every sequence of at most four of these pieces: the two halves of a
    # password word in four capitalisations each, letters, a digit, a
    # separator and a character the guard does not know.
    pieces = ["pass", "Pass", "PASS", "pAss", "wd", "Wd", "WD", "wD", *"xX9_."]
    keys += [
        "".join(chosen)
        for length in range(5)
        for chosen in itertools.product(pieces, repeat=length)
    ]
    answers = [(key, refused_earliest(key), refused_before(key), _secret_key(key)) for key in keys]
    # Neither earlier guard refuses a key that is imported now.
    assert [key for key, earliest, before, now in answers if (earliest or before) and not now] == []
    assert [key for key, _, _, now in answers if now != refused_by_rule(key)][:8] == []
    changed = [key for key, _, before, now in answers if now != before]
    assert changed, "the keys include some whose answer the change touches"
    assert all(re.search(r"[A-Z]+[A-Z][a-z]|[a-z0-9][A-Z]", key) for key in changed)


PIECES = [
    *FORMS,
    *(form.upper() for form in FORMS),
    *(with_capitals(form, [0]) for form in FORMS),
    *("db", "my", "HTTP", "File", "key", "Key", "private", "api", "izer", "ring"),
    *("pass", "Pass", "phrase", "word", "Word", "wd"),
    *("x", "X", "s", "S", "a", "A", "9", "_", "-", ".", " ", "\n"),
    *(KELVIN, LONG_S, DOTTED_I, DOTLESS_I),
]


@st.composite
def generated_keys(draw: st.DrawFn) -> str:
    text = "".join(draw(st.lists(st.sampled_from(PIECES), max_size=5)))
    flipped = draw(st.sets(st.integers(0, max(len(text) - 1, 0)), max_size=4))
    return "".join(char.swapcase() if index in flipped else char for index, char in enumerate(text))


@settings(max_examples=1500, deadline=None, derandomize=True)
@given(generated_keys())
def test_whatever_was_refused_before_is_still_refused(key: str) -> None:
    before, now = refused_before(key), _secret_key(key)
    assert now or not before
    assert now or not refused_earliest(key)
    # An answer changes only where one of the two splitting expressions finds a boundary.
    assert now == before or re.search(r"[A-Z]+[A-Z][a-z]|[a-z0-9][A-Z]", key)


@settings(max_examples=1500, deadline=None, derandomize=True)
@given(generated_keys())
def test_the_guard_is_the_earlier_rule_with_the_boundaries_optional_inside_a_word(key: str) -> None:
    assert _secret_key(key) == refused_by_rule(key)


def test_a_view_without_such_keys_keeps_the_bytes_it_had(tmp_path: Path) -> None:
    # One source of every format. Keys that hold a listed word without both
    # boundaries stand at selectors, at destinations and, in the three formats
    # with nested keys, inside the mapped values.
    sources = {
        "settings.json": (
            "json",
            b'{"listen":{"address":"192.0.2.11","port":8443},"names":["example-one","example-two"],'
            b'"monkey":{"tokenizer":"plain","MAXTOKEN":64,"passWords":[{"SECRETARY":true}]}}',
            {
                "/listen": "/host/listen",
                "/names/1": "/host/name",
                "/monkey": "/tokenizer/apiKeyring",
            },
        ),
        "owner.toml": (
            "toml",
            b'interval = 30\n\n[environmental]\nmyseCret = "plain"\ntoKenizer = [1, 2]\n',
            {"/interval": "/supervision/seconds", "/environmental": "/secretary"},
        ),
        "job.plist": (
            "plist",
            PLIST_HEAD
            + b"<dict><key>Label</key><string>example-job</string>"
            + b"<key>TOKENIZER</key><dict><key>mytoKen</key><true/></dict></dict></plist>",
            {"/Label": "/label", "/TOKENIZER": "/tokens"},
        ),
        "owner.env": (
            "literal-env",
            b"# literal settings\nHOST='192.0.2.12'\nENVELOPE=plain\n",
            {"/HOST": "/address", "/ENVELOPE": "/envelope"},
        ),
        "types.list": (
            "text-list",
            b"# comment\n_example._tcp\nexample-item\n",
            {"/items": "/types"},
        ),
        "start.sh": ("source-inventory", b"#!/bin/sh\nexit 0\n", {}),
    }
    entries = []
    for number, (name, (fmt, raw, mapping)) in enumerate(sources.items()):
        (tmp_path / name).write_bytes(raw)
        entries.append(entry(name, fmt, id=f"source-{number}", mapping=mapping))
    view = generated_bytes(import_sources(manifest(tmp_path, entries)))
    values = json.loads(view)["values"]
    assert values["tokenizer"]["apiKeyring"]["passWords"] == [{"SECRETARY": True}]
    assert values["secretary"] == {"myseCret": "plain", "toKenizer": [1, 2]}
    assert values["tokens"] == {"mytoKen": True}
    # The digest of the view the importer wrote before this change.
    assert hashlib.sha256(view).hexdigest() == (
        "da500b9edcacc9ab3a0ef61a0e3f15c10278a4df828d1b6c27a97bcf133f738c"
    )


def test_the_guide_gives_examples_that_are_true() -> None:
    text = " ".join(GUIDE.read_text().split())
    rejected = [
        *("password", "dbPassword", "passWord", "APIkey", "api_key", "PGPASSWORD", "DBPASSWD"),
        *("DBToken", "tokenID", "bypassWord"),
    ]
    data = [
        *("tokenizer", "MAXTOKEN", "accesstoken", "tokens", "token2", "passwords"),
        *("db.password", "my token", "DBTOken", "tokeNID", "APItoken", "compass", "bypass_cache"),
    ]
    for key in rejected:
        assert f"`{key}`" in text
        assert _secret_key(key)
    for key in data:
        assert f"`{key}`" in text
        assert not _secret_key(key)
    # The capitals of a key decide where its boundaries are.
    for pair in [("DBToken", "DBTOken"), ("tokenID", "tokeNID"), ("APIkey", "APItoken")]:
        assert "`{}` is rejected and `{}` is imported".format(*pair) in text
    # "Two neighbouring words that together spell a listed word".
    assert "`pass` followed by `Word`" in text
    assert _secret_key("firstPassWord")
    # A password word whose first letters end a longer word.
    assert "`bypassWord` is rejected, because `passWord` follows the letters `by`" in text
    assert "`pass` alone is not a listed word" in text
    # Every listed word is named, the compound words with a space between their parts.
    for word in SIMPLE + PASSWORDS:
        assert f"`{word}`" in text
    for first, second in COMPOUND:
        assert f"`{first} {second}`" in text
    assert "not a secret detector" in text

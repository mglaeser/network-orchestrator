"""Compound password names and passphrases are credential keys; similar ordinary words are not."""

from __future__ import annotations

import json

import pytest

from netorch.legacy_import import ImportError, generated_bytes, import_sources

SECRET = "synthetic-credential-must-not-be-emitted"


def source(identifier, mapping, path=None, fmt="json"):
    return {
        "id": identifier,
        "owner": "example",
        "path": path or identifier + ".json",
        "format": fmt,
        "sha256": None,
        "mapping": mapping,
    }


def run(tmp_path, files, sources):
    for name, content in files.items():
        text = content if isinstance(content, str) else json.dumps(content)
        (tmp_path / name).write_text(text)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema_version": 1, "sources": sources}))
    return import_sources(path)


def placed(key, location):
    """Source data, mapping and the values an import of an ordinary key yields."""
    if location == "selector":
        return {key: SECRET}, {"/" + key: "/chosen"}, {"chosen": SECRET}
    if location == "target":
        return {"chosen": SECRET}, {"/chosen": "/" + key}, {key: SECRET}
    data = {"chosen": [{key: SECRET}]}
    return data, {"/chosen": "/chosen"}, data


# Credential words


@pytest.mark.parametrize(
    "key",
    [
        "PGPASSWORD",
        "DBPASSWD",
        "WEBPASSWORD",
        "pgpassword",
        "dbpasswd",
        "passphrase",
        "PASSPHRASE",
        "passPhrase",
        "pass_phrase",
        "pass-phrase",
        "SSH_PASS_PHRASE",
        "keyPassPhrase",
        "KEYPASSPHRASE",
        "sshpassphrase",
    ],
)
@pytest.mark.parametrize("location", ["selector", "target", "nested"])
def test_password_compounds_and_passphrase_are_credential_keys(tmp_path, key, location):
    data, mapping, _ = placed(key, location)
    with pytest.raises(ImportError, match="Credential") as error:
        run(tmp_path, {"first.json": data}, [source("first", mapping)])
    assert SECRET not in str(error.value)


@pytest.mark.parametrize(
    "key",
    [
        "compass",
        "COMPASS",
        "compass_heading",
        "bypass",
        "bypass_cache",
        "BYPASS_CACHE",
        "bypassCache",
        "bypass_phrase",
        "passes",
        "PASSES",
        "passthrough",
        "pass_through",
        "passenger",
        "passport",
        "passive",
        "encompass",
        "paraphrase",
    ],
)
@pytest.mark.parametrize("location", ["selector", "target", "nested"])
def test_ordinary_keys_with_the_same_letters_are_imported(tmp_path, key, location):
    data, mapping, expected = placed(key, location)
    result = run(tmp_path, {"first.json": data}, [source("first", mapping)])
    assert result.values == expected
    assert not result.underivable


@pytest.mark.parametrize("key", ["password", "passwd", "dbPassword", "DB_PASSWD", "PASSWORD_FILE"])
def test_password_words_recognised_before_are_still_refused(tmp_path, key):
    data, mapping, _ = placed(key, "nested")
    with pytest.raises(ImportError, match="Credential"):
        run(tmp_path, {"first.json": data}, [source("first", mapping)])


def test_compound_password_line_of_a_literal_file_is_never_mapped(tmp_path):
    text = f"PGPASSWORD={SECRET}\nADDRESS=192.0.2.11\n"
    with pytest.raises(ImportError, match="Credential"):
        run(
            tmp_path,
            {"owner": text},
            [source("first", {"/PGPASSWORD": "/chosen"}, "owner", "literal-env")],
        )
    result = run(
        tmp_path,
        {"owner": text},
        [source("first", {"/ADDRESS": "/address"}, "owner", "literal-env")],
    )
    assert result.values == {"address": "192.0.2.11"}
    assert SECRET.encode() not in generated_bytes(result)


# One author for every destination

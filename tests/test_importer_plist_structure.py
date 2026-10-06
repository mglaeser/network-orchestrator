"""Malformed XML must not silently become valid owner settings."""

from __future__ import annotations

import pytest

from netorch.legacy_import import generated_bytes
from tests.test_importer_literals import PLIST_HEAD, assert_refused, import_one


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"<string><key>private-sentinel</key></string>",
        b"<date>private-sentinel</date>",
        b"<dict><key>Label</key><date>private-sentinel</date></dict>",
        b"<dict>private-sentinel<key>Label</key><string>example</string></dict>",
        b"<dict><key>Label</key>private-sentinel<string>example</string></dict>",
        b"<dict><key>Label</key><string>example</string>private-sentinel</dict>",
        b"private-sentinel<dict><key>Label</key><string>example</string></dict>",
        b"<dict><key>Label</key><string>example</string></dict>private-sentinel",
        b"<dict><key>Label</key><true>private-sentinel</true></dict>",
        b"<dict><key>Label</key><false>private-sentinel</false></dict>",
        b"<dict><key>Label</key><array>private-sentinel<string>example</string></array></dict>",
        b"<dict><key>Label</key><array><string>example</string>private-sentinel</array></dict>",
    ],
)
def test_malformed_property_list_is_underivable_without_leaking_its_body(tmp_path, body):
    result = import_one(tmp_path, "plist", PLIST_HEAD + body + b"</plist>", {"/Label": "/label"})
    assert_refused(result)
    assert b"private-sentinel" not in generated_bytes(result)


def test_xml_layout_whitespace_and_comments_preserve_values(tmp_path):
    body = (
        b"\n<!-- ordinary XML layout -->\n<dict>\n\t<key>Label</key>\r\n"
        b"<array>\n<string> example </string>\n<true/>\n</array>\n</dict>\n"
    )
    result = import_one(tmp_path, "plist", PLIST_HEAD + body + b"</plist>", {"/Label": "/label"})
    assert result.values == {"label": [" example ", True]}
    assert not result.underivable

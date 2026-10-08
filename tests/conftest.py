"""Diagnostic only: name every failed test as an annotation of the hosted job."""

from __future__ import annotations

import os
from typing import Any


def pytest_terminal_summary(terminalreporter: Any) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    for kind in ("failed", "error"):
        for report in terminalreporter.stats.get(kind, []):
            text = str(getattr(report, "longrepr", ""))[-1800:]
            text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            terminalreporter.write_line(f"::error title={kind} {report.nodeid}::{text}")

"""Hosted macOS userspace contract: a new file takes the group of its directory.

The backend script's rule-file check compares owner, mode and link count and no
group (`safe_file`, docs/pf-owner.md). The reason is that the group of a new
file is the group of its directory, not of the process that creates it, so a
rule file that root writes below a directory of another group does not have
group 0. This test shows that rule on a Darwin host. A pass is evidence for the
runner image that ran it and qualifies no production macOS build.
"""

from __future__ import annotations

import os
import sys
import tempfile
from typing import Any

import pytest


def recorded(capsys: Any, title: str, seen: str) -> None:
    """On the hosted runner, keep what was observed as a notice of the job."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        text = seen.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        # Capture is lifted for one line of its own: the runner reads commands at line starts.
        with capsys.disabled():
            print(f"\n::notice title={title}::{text}")


@pytest.mark.darwin
@pytest.mark.skipif(sys.platform != "darwin", reason="hosted macOS userspace contract")
def test_a_new_file_takes_the_group_of_its_directory_not_of_the_process(capsys: Any) -> None:
    """The one write outside the test's own directory: an empty private file in
    the system's temporary directory, removed before the assertions."""
    directory = "/private/tmp"
    group = os.stat(directory).st_gid
    fd, name = tempfile.mkstemp(prefix="netorch-rule-file-group-", dir=directory)
    try:
        created = os.fstat(fd)
    finally:
        os.close(fd)
        os.unlink(name)
    recorded(
        capsys,
        "group of a new file",
        f"directory group {group}, process group {os.getegid()}, file group {created.st_gid}",
    )
    # The rule can only be seen where the two groups differ.
    assert group != os.getegid(), "the directory has the process's own group on this host"
    assert created.st_gid == group

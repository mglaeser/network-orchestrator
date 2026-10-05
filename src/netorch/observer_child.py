"""Fixed root-started credential dropper after launchctl adopts user bootstrap.

This file is invoked by absolute protected path with Python -I -S, so it imports
only stdlib. It offers no daemon/socket/RPC and refuses non-root invocation.
The independently scheduled root owner supplies enrolled values and permits
only bounded read operations; no workload or network mutation is supported.
"""

from __future__ import annotations

import os
import re
import sys


def _path(value: str) -> bool:
    return (
        value.startswith("/")
        and os.path.normpath(value) == value
        and len(value) <= 4096
        and not any(ord(character) < 32 for character in value)
    )


def _name(value: str) -> bool:
    return (
        bool(value)
        and not value.startswith("-")
        and len(value) <= 256
        and not any(ord(character) < 32 for character in value)
    )


def read_operation(arguments: list[str]) -> bool:
    """Closed native read grammar; exec has one literal procfs read only."""
    return (
        arguments in (["--version"], ["list", "--all", "--format", "json"])
        or (len(arguments) == 2 and arguments[0] == "inspect" and _name(arguments[1]))
        or (len(arguments) == 3 and arguments[:2] == ["network", "inspect"] and _name(arguments[2]))
        or (
            len(arguments) == 6
            and arguments[:3] == ["exec", "--user", "0"]
            and _name(arguments[3])
            and arguments[4:] == ["/bin/cat", "/proc/sys/net/ipv4/ip_local_port_range"]
        )
    )


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    try:
        if sys.platform != "darwin" or os.geteuid() != 0 or len(values) < 5:
            raise ValueError("root-started observer child required")
        uid_text, gid_text, home, executable, *arguments = values
        if (
            not re.fullmatch(r"[1-9][0-9]{0,9}", uid_text)
            or not re.fullmatch(r"0|[1-9][0-9]{0,9}", gid_text)
            or not _path(home)
            or not _path(executable)
            or not read_operation(arguments)
        ):
            raise ValueError("invalid observer-only arguments")
        uid, gid = int(uid_text), int(gid_text)
        if uid >= 2**32 - 1 or gid >= 2**32 - 1:
            raise ValueError("invalid observer account")
        # launchctl asuser deliberately preserves root credentials. Drop them
        # before loading any vendor binary or user application configuration.
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        if os.getuid() != uid or os.geteuid() != uid or os.getgid() != gid or os.getegid() != gid:
            raise PermissionError("observer credential readback differs")
        os.chdir("/")
        os.umask(0o077)
        os.execve(
            executable,
            [executable, *arguments],
            {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LC_ALL": "C",
                "LANG": "C.UTF-8",
                "HOME": home,
            },
        )
    except (OSError, ValueError):
        print('{"error":"observer-bootstrap-or-credentials-unavailable"}', file=sys.stderr)
        return 69


if __name__ == "__main__":
    raise SystemExit(main())

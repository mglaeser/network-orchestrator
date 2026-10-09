"""Bounded POSIX subprocess groups; no shell and bounded inherited-pipe waits."""

from __future__ import annotations

import math
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

# Every child gets these four and nothing of the caller's own environment.
_CLOSED_ENVIRONMENT = ("PATH", "LANG", "LC_ALL", "HOME")
_VARIABLE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


def _added_variables(value: Any) -> bool:
    """Named additions only: a caller can add a variable, never replace one of the four."""
    return (
        isinstance(value, Mapping)
        and len(value) <= 8
        and all(
            isinstance(name, str)
            and _VARIABLE.fullmatch(name) is not None
            and name not in _CLOSED_ENVIRONMENT
            and isinstance(text, str)
            and "\0" not in text
            for name, text in value.items()
        )
    )


class ProcessError(RuntimeError):
    """An operation did not produce a complete bounded result."""


class ProcessTimeout(ProcessError):
    """A command was stopped at its time limit.

    ``stdout`` and ``stderr`` are what it had written by then, at most the
    output bound, where the runner that raised this says so; None otherwise.
    The message never holds them.
    """

    def __init__(
        self, *args: object, stdout: bytes | None = None, stderr: bytes | None = None
    ) -> None:
        super().__init__(*args)
        self.stdout = stdout
        self.stderr = stderr


class OutputLimit(ProcessError):
    pass


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: bytes
    stderr: bytes


def run(
    argv: list[str],
    *,
    input_data: bytes = b"",
    timeout: float = 5.0,
    max_output: int = 1_048_576,
    run_uid: int | None = None,
    run_gid: int | None = None,
    account_home: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> Result:
    """Capture a process group within explicit time/input/output bounds.

    A child's exit does not complete the operation while inherited pipes remain
    open. Cleanup attempts to kill the owned group and reap the immediate child.
    A child that deliberately leaves that group is outside this runner's cleanup
    authority; this is not a process-tree sandbox. Native owners need their own
    lifecycle fence for daemons that detach or are registered with launchd.
    Error messages deliberately omit arguments, environment and captured output.
    `environment` names variables that one call adds to the closed environment.
    The time limit raises ProcessTimeout, which carries what the command had
    written by then as attributes, never in its message.
    """
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(arg, str) or "\0" in arg for arg in argv)
        or not os.path.isabs(argv[0])
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0 < timeout <= sys.float_info.max
        or not math.isfinite(timeout)
        or type(max_output) is not int
        or max_output <= 0
        or not isinstance(input_data, bytes)
        or len(input_data) > max_output
        or (run_uid is not None and (type(run_uid) is not int or run_uid <= 0))
        or (run_gid is not None and (type(run_gid) is not int or run_gid < 0))
        or ((run_uid is None) != (run_gid is None))
        or (
            account_home is not None
            and (
                not isinstance(account_home, str)
                or not os.path.isabs(account_home)
                or "\0" in account_home
            )
        )
        or (environment is not None and not _added_variables(environment))
    ):
        raise ValueError("invalid bounded command")
    credentials: dict[str, Any] = {}
    if run_uid is not None:
        if os.geteuid() != 0 and (run_uid != os.geteuid() or run_gid != os.getegid()):
            raise PermissionError("account mismatch")
        if os.geteuid() == 0:
            credentials = {"user": run_uid, "group": run_gid, "extra_groups": []}
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
        env={
            **(environment or {}),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C",
            "HOME": account_home or os.path.expanduser("~"),
        },
        **credentials,
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    out = bytearray()
    err = bytearray()
    pending = memoryview(input_data)
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream, label in ((proc.stdout, "out"), (proc.stderr, "err")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            if pending:
                os.set_blocking(proc.stdin.fileno(), False)
                selector.register(proc.stdin, selectors.EVENT_WRITE, "in")
            else:
                proc.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProcessTimeout("command did not complete within its deadline")
                for key, _ in selector.select(min(remaining, 0.1)):
                    fd = key.fd
                    if key.data == "in":
                        try:
                            count = os.write(fd, pending[:65536])
                            pending = pending[count:]
                        except BrokenPipeError:
                            pending = memoryview(b"")
                        if not pending:
                            selector.unregister(fd)
                            proc.stdin.close()
                        continue
                    try:
                        chunk = os.read(fd, 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(fd)
                        continue
                    (out if key.data == "out" else err).extend(chunk)
                    if len(out) + len(err) > max_output:
                        raise OutputLimit("command exceeded its combined output bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProcessTimeout("command did not complete within its deadline")
            try:
                status = proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise ProcessTimeout("command did not complete within its deadline") from exc
        return Result(status, bytes(out), bytes(err))
    except BaseException as exc:
        with suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        if isinstance(exc, ProcessTimeout):
            # What the command had written when it was stopped. Its group is
            # gone, so what is left in its pipes is read without waiting.
            for stream, seen in ((proc.stdout, out), (proc.stderr, err)):
                with suppress(OSError):
                    os.set_blocking(stream.fileno(), False)
                    while len(out) + len(err) < max_output:
                        chunk = os.read(stream.fileno(), max_output - len(out) - len(err))
                        if not chunk:
                            break
                        seen.extend(chunk)
            exc.stdout, exc.stderr = bytes(out), bytes(err)
        raise
    finally:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()

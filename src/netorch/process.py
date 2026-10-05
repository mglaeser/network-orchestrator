"""Bounded POSIX subprocesses; no shell and no descendant left holding pipes."""

from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass


class ProcessError(RuntimeError):
    """An operation did not produce a complete bounded result."""


class ProcessTimeout(ProcessError):
    pass


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
) -> Result:
    """Capture a process group within explicit time/input/output bounds.

    A child's exit does not complete the operation while inherited pipes remain
    open. Exceptions kill the entire owned group and reap the immediate child.
    Error messages deliberately omit arguments, environment and captured output.
    """
    if (
        not isinstance(argv, list)
        or not argv
        or not os.path.isabs(argv[0])
        or any(not isinstance(arg, str) or "\0" in arg for arg in argv)
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
        or type(max_output) is not int
        or max_output <= 0
        or not isinstance(input_data, bytes)
        or len(input_data) > max_output
    ):
        raise ValueError("invalid bounded command")
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
        env={
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C",
            "HOME": os.path.expanduser("~"),
        },
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
    except BaseException:
        with suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        raise
    finally:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()

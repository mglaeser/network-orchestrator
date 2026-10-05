"""Private, descriptor-checked state and a single non-stealable owner lock."""

from __future__ import annotations

import contextlib
import fcntl
import os
import secrets
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .codec import MAX_JSON_BYTES, canonical_bytes, strict_loads


class UnsafeState(RuntimeError):
    pass


class Busy(RuntimeError):
    pass


def _check_file(fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise UnsafeState("state file must be private, single-link and owned by this user")


class Store:
    """State directory is independent of installed release/source directories.

    Callers must provision a protected ancestor tree. This user store is not a
    privileged-policy installer and never makes root trust a user-owned file.
    """

    def __init__(self, directory: Path) -> None:
        directory = directory.absolute()
        if directory.is_symlink():
            raise UnsafeState("state directory cannot be a symlink")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory = directory
        fd = self._open_directory()
        try:
            info = os.fstat(fd)
            self._check_directory_info(info)
            self._identity = (info.st_dev, info.st_ino)
        finally:
            os.close(fd)

    @staticmethod
    def _check_directory_info(info: os.stat_result) -> None:
        if (
            info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or not stat.S_ISDIR(info.st_mode)
        ):
            raise UnsafeState("state directory must be private and owned by this user")

    def _open_directory(self) -> int:
        try:
            return os.open(self.directory, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
        except OSError as exc:
            raise UnsafeState("state directory is unavailable or unsafe") from exc

    def _check_directory_fd(self, fd: int) -> None:
        info = os.fstat(fd)
        self._check_directory_info(info)
        if (info.st_dev, info.st_ino) != self._identity:
            raise UnsafeState("state directory identity changed")

    def _check_current_directory(self, fd: int) -> None:
        """Verify both the held descriptor and today's final pathname identity."""
        self._check_directory_fd(fd)
        current = self._open_directory()
        try:
            self._check_directory_fd(current)
        finally:
            os.close(current)

    @contextlib.contextmanager
    def _directory_fd(self) -> Iterator[int]:
        fd = self._open_directory()
        try:
            self._check_directory_fd(fd)
            yield fd
        finally:
            os.close(fd)

    def _path(self, name: str) -> Path:
        if (
            not isinstance(name, str)
            or not name
            or "/" in name
            or name in {".", ".."}
            or any(ord(character) < 32 for character in name)
            or len(name.encode("utf-8")) > 255
        ):
            raise UnsafeState("invalid state name")
        return self.directory / name

    def read(self, name: str) -> Any:
        self._path(name)
        with self._directory_fd() as parent:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                _check_file(fd)
                with os.fdopen(os.dup(fd), "rb") as stream:
                    raw = stream.read(1_048_577)
                if len(raw) > 1_048_576:
                    raise UnsafeState("state exceeds its size bound")
                self._check_current_directory(parent)
                return strict_loads(raw.decode("utf-8"))
            finally:
                os.close(fd)

    def write(self, name: str, value: Any) -> None:
        self._path(name)
        with self._directory_fd() as parent:
            try:
                existing = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                pass
            else:
                try:
                    _check_file(existing)
                finally:
                    os.close(existing)
            payload = canonical_bytes(value) + b"\n"
            if len(payload) > MAX_JSON_BYTES:
                raise UnsafeState("serialized state exceeds its size bound")
            temporary: str | None = None
            fd: int | None = None
            for _attempt in range(8):
                candidate = f".write-{secrets.token_hex(16)}"
                try:
                    fd = os.open(
                        candidate,
                        os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=parent,
                    )
                except FileExistsError:
                    continue
                temporary = candidate
                break
            if fd is None or temporary is None:
                raise UnsafeState("could not allocate an exclusive state temporary")
            try:
                _check_file(fd)
                remaining = memoryview(payload)
                while remaining:
                    written = os.write(fd, remaining)
                    if written <= 0:
                        raise UnsafeState("state write did not make progress")
                    remaining = remaining[written:]
                os.fsync(fd)
                self._check_current_directory(parent)
                os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
                temporary = None
                os.fsync(parent)
            finally:
                os.close(fd)
                if temporary is not None:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(temporary, dir_fd=parent)

    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        with self._directory_fd() as parent:
            fd = os.open(
                "owner.lock",
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            try:
                _check_file(fd)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise Busy("another operation holds the owner lock") from exc
                self._check_current_directory(parent)
                yield
            finally:
                os.close(fd)

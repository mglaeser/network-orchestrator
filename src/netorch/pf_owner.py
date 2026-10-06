"""Independent privileged Darwin PF owner.

The normal executor never invokes this module. An administrator installs a
root-owned policy/admission snapshot and launchd schedules fixed pull passes.
All decisions use fresh independently observed runtime and kernel evidence.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import math
import os
import plistlib
import re
import stat
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from functools import lru_cache
from importlib.metadata import version
from pathlib import Path
from typing import Any, Protocol

from .codec import MAX_JSON_BYTES, canonical_bytes, digest, strict_loads
from .config import parse_config, profile_digest, to_dict
from .model import Config, Profile, Scope
from .planner import Action, plan
from .process import Result, run
from .state import (
    Admission,
    Intent,
    Observation,
    Snapshot,
    intent_from_dict,
    intent_to_dict,
    snapshot_to_dict,
)
from .storage import Store, UnsafeState
from .workflow_gate import NOT_QUALIFIED, StageNotQualified, require_mutation_qualified

STRATEGY = "darwin-pf-v1"
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_REASON = "unobserved"


class PFError(RuntimeError):
    """A complete independently verified pass could not be performed."""


@dataclass(frozen=True)
class Installation:
    owner: str
    anchor: str
    observer: Mapping[str, Any]
    backend_sha256: str
    report_path: str
    intent_path: str | None = None
    interval_seconds: int = 10
    allow_apple_dns_coexistence: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.owner, str)
            or not isinstance(self.anchor, str)
            or not _ID.fullmatch(self.owner)
            or self.anchor != f"com.apple/netorch.{self.owner}"
        ):
            raise PFError("invalid independent PF owner identity")
        if not isinstance(self.backend_sha256, str) or not _HASH.fullmatch(self.backend_sha256):
            raise PFError("invalid installed backend digest")
        if type(self.interval_seconds) is not int or not 1 <= self.interval_seconds <= 60:
            raise PFError("invalid reconciliation interval")
        if type(self.allow_apple_dns_coexistence) is not bool:
            raise PFError("invalid coexistence admission")
        for value in (self.report_path, self.intent_path):
            if value is not None and (
                not isinstance(value, str) or not os.path.isabs(value) or "\x00" in value
            ):
                raise PFError("owner paths must be absolute")
        if not isinstance(self.observer, Mapping):
            raise PFError("invalid independent observer configuration")
        # Freeze nested settings by strict serialization, not caller references.
        object.__setattr__(self, "observer", strict_loads(canonical_bytes(dict(self.observer))))

    @classmethod
    def from_dict(cls, raw: Any) -> Installation:
        required = {
            "schema_version",
            "owner",
            "anchor",
            "observer",
            "backend_sha256",
            "report_path",
            "intent_path",
            "interval_seconds",
            "allow_apple_dns_coexistence",
        }
        if (
            not isinstance(raw, dict)
            or set(raw) != required
            or type(raw["schema_version"]) is not int
            or raw["schema_version"] != 1
        ):
            raise PFError("unsupported installation schema")
        return cls(**{key: value for key, value in raw.items() if key != "schema_version"})

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, **asdict(self)}


@lru_cache(maxsize=1)
def implementation_digest() -> str:
    """Automatic semantic invalidation across immutable installed releases.

    Protected release trees may never be upgraded in place. A new scheduled
    process imports a complete release and fingerprints its trusted Python
    implementation, so changing planner/observer code cannot retain old root
    authority merely because somebody forgot a strategy-version bump.
    """
    directory = Path(__file__).parent
    files = sorted(directory.glob("*.py"))
    schemas = _schema_paths(directory)
    return digest(
        {
            "python": sys.version,
            "dependencies": {
                name: version(name)
                for name in (
                    "jsonschema",
                    "attrs",
                    "jsonschema-specifications",
                    "referencing",
                    "rpds-py",
                )
            },
            "implementation": {
                path.name: hashlib.sha256(read_once(path)).hexdigest() for path in files
            },
            "schemas": {path.name: hashlib.sha256(read_once(path)).hexdigest() for path in schemas},
        }
    )


def _schema_paths(directory: Path) -> tuple[Path, ...]:
    """The same bundled schemas used by parser/deployment, with source fallback."""
    return tuple(
        directory / name
        if (directory / name).is_file()
        else directory.parents[1] / "schemas" / name
        for name in ("network.schema.json", "deployment.schema.json")
    )


def admitted_digest(config: Config, profile: Profile, installation: Installation) -> str:
    """Bind root authority to resolved policy, strategy and trusted observation."""
    return digest(
        {
            "strategy": STRATEGY,
            "implementation_sha256": implementation_digest(),
            "profile_digest": profile_digest(config, profile),
            "backend_sha256": installation.backend_sha256,
            "observer": dict(installation.observer),
            "anchor": installation.anchor,
            "allow_apple_dns_coexistence": installation.allow_apple_dns_coexistence,
        }
    )


def read_once(
    path: Path, *, uid: int | None = None, mode: int | None = None, maximum: int = MAX_JSON_BYTES
) -> bytes:
    """Pin one regular single-link inode and reject pathname swaps after reading."""
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        identity = _code_metadata_identity(opened)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or identity != _code_metadata_identity(before)
        ):
            raise UnsafeState("input inode is unsafe")
        if uid is not None and opened.st_uid != uid:
            raise UnsafeState("input owner differs")
        if mode is not None and stat.S_IMODE(opened.st_mode) != mode:
            raise UnsafeState("input mode differs")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(maximum + 1)
        after = path.lstat()
        if (
            len(data) > maximum
            or _code_metadata_identity(after) != identity
            or _code_metadata_identity(os.fstat(fd)) != identity
        ):
            raise UnsafeState("input changed while being read")
        return data
    finally:
        os.close(fd)


def protected_ancestors(
    path: Path,
    *,
    uid: int = 0,
    _captures: dict[Path, os.stat_result] | None = None,
    _deadline: float | None = None,
) -> None:
    """No writable/symlink ancestor may replace root policy or executable code."""
    if not path.is_absolute():
        raise UnsafeState("protected path must be absolute")
    for item in reversed((path, *path.parents)):
        if _deadline is not None and time.monotonic() >= _deadline:
            raise UnsafeState("protected code inspection exceeded its aggregate deadline")
        info = item.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or item.is_symlink()
            or info.st_uid != uid
            or info.st_mode & 0o022
        ):
            raise UnsafeState("protected ancestor is writable or has another owner")
        if _captures is None:
            reject_acl(item)
        else:
            _capture_code_metadata(item, info, _captures)


def reject_acl(path: Path, *, timeout: float = 2.0) -> None:
    """Mode bits cannot authorize an ACL-bearing privileged trust boundary."""
    if sys.platform == "darwin":
        observed = run(["/bin/ls", "-lde", str(path)], timeout=timeout, max_output=65536)
        if observed.returncode or observed.stderr or len(observed.stdout.splitlines()) != 1:
            raise UnsafeState("ACL-bearing or unknown protected path is refused")
    elif hasattr(os, "listxattr"):
        attributes = os.listxattr(path, follow_symlinks=False)
        if any(
            name in attributes for name in ("system.posix_acl_access", "system.posix_acl_default")
        ):
            raise UnsafeState("ACL-bearing protected path is refused")


def _capture_code_metadata(
    path: Path, info: os.stat_result, captures: dict[Path, os.stat_result]
) -> None:
    if (
        not path.is_absolute()
        or len(str(path)) > 4096
        or any(ord(character) < 32 for character in str(path))
    ):
        raise UnsafeState("invalid protected code path")
    previous = captures.get(path)
    if previous is not None and _code_metadata_identity(previous) != _code_metadata_identity(info):
        raise UnsafeState("protected code metadata changed during capture")
    captures[path] = info
    if len(captures) > 4096:
        raise UnsafeState("protected code inventory exceeds its bounded capacity")


def _code_metadata_identity(info: os.stat_result) -> tuple[int, ...]:
    # Reading a symlink or mapped code may update atime without changing trust.
    # Fence identity, content/ownership/mode and change timestamps, not access.
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        getattr(info, "st_flags", 0),
    )


def _batch_code_acls(paths: tuple[Path, ...], deadline: float) -> None:
    """Fresh per-pass ACL checks, with deduplicated bounded Darwin invocations."""
    if sys.platform != "darwin":
        for path in paths:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UnsafeState("protected code inspection exceeded its aggregate deadline")
            reject_acl(path, timeout=remaining)
        return
    cursor = 0
    while cursor < len(paths):
        selected: list[str] = []
        argument_bytes = 0
        while cursor < len(paths) and len(selected) < 256:
            name = str(paths[cursor])
            if argument_bytes + len(os.fsencode(name)) + 1 > 65536:
                break
            selected.append(name)
            argument_bytes += len(os.fsencode(name)) + 1
            cursor += 1
        remaining = deadline - time.monotonic()
        if not selected or remaining <= 0:
            raise UnsafeState("protected code inspection exceeded its aggregate deadline")
        result = run(["/bin/ls", "-lde", *selected], timeout=remaining, max_output=524288)
        # Every validated absolute path has one ordinary metadata line. An ACL
        # adds entries, while a missing/diagnostic path adds stderr or an error.
        if result.returncode or result.stderr or len(result.stdout.splitlines()) != len(selected):
            raise UnsafeState("ACL-bearing or unknown protected code path is refused")


def _capture_code_file(
    executable: Path, owner: int, captured: dict[Path, os.stat_result], deadline: float
) -> None:
    protected_ancestors(executable.parent, uid=owner, _captures=captured, _deadline=deadline)
    original = executable.lstat()
    if stat.S_ISLNK(original.st_mode):
        if original.st_uid != owner or original.st_nlink != 1:
            raise UnsafeState("privileged executable symlink is replaceable")
        _capture_code_metadata(executable, original, captured)
    resolved = executable.resolve(strict=True)
    protected_ancestors(resolved.parent, uid=owner, _captures=captured, _deadline=deadline)
    info = resolved.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != owner
        or info.st_mode & 0o022
        or info.st_nlink != 1
    ):
        raise UnsafeState("privileged code is replaceable")
    _capture_code_metadata(resolved, info, captured)


def _verify_code_capture(captured: dict[Path, os.stat_result], deadline: float) -> None:
    _batch_code_acls(tuple(sorted(captured)), deadline)
    # Fence both visible links and resolved target metadata after the ACL read.
    for path, initial in captured.items():
        if time.monotonic() >= deadline or _code_metadata_identity(
            path.lstat()
        ) != _code_metadata_identity(initial):
            raise UnsafeState("protected code changed during bounded inspection")


def protected_native_code(paths: tuple[Path, ...], *, uid: int | None = None) -> None:
    """Trust administrator-owned observer binaries without repeating Python checks."""
    if not paths or len(paths) > 34:
        raise UnsafeState("native observer code inventory is invalid")
    owner = 0 if uid is None else uid
    captured: dict[Path, os.stat_result] = {}
    deadline = time.monotonic() + 8.0
    for path in dict.fromkeys(paths):
        _capture_code_file(path, owner, captured, deadline)
    _verify_code_capture(captured, deadline)


def protected_code(interpreter: Path, package: Path, *, uid: int | None = None) -> None:
    """Protect the complete live root import environment, not only a venv symlink.

    An explicit uid scopes isolated file-boundary tests. The live CLI never
    supplies one: it checks administrator ownership of stdlib, import paths,
    imported extension/dependency files, package files and schema resources.
    Provisioning must protect the complete environment before starting Python;
    this is additional live readback, not permission to import untrusted code.
    """
    owner = 0 if uid is None else uid
    deadline = time.monotonic() + 8.0
    captured: dict[Path, os.stat_result] = {}

    def check_directory(path: Path) -> None:
        protected_ancestors(path, uid=owner, _captures=captured, _deadline=deadline)

    def check_file(executable: Path) -> None:
        _capture_code_file(executable, owner, captured, deadline)

    for executable in (interpreter, package):
        check_file(executable)
    if uid is None:
        for prefix in (sys.prefix, sys.base_prefix):
            check_directory(Path(prefix))
        for entry in sys.path:
            path = Path(entry)
            if not path.is_absolute():
                raise UnsafeState("privileged Python search path is not absolute")
            if path.is_dir():
                check_directory(path)
            elif path.exists():
                check_file(path)
            else:
                # The normal stdlib zip can be absent; no user may create it later.
                check_directory(path.parent)
        imported = {
            Path(filename)
            for module in tuple(sys.modules.values())
            if isinstance(filename := getattr(module, "__file__", None), str)
            and Path(filename).is_absolute()
        }
        for path in sorted(imported):
            check_file(path)
        for path in (*package.parent.glob("*.py"), *_schema_paths(package.parent)):
            check_file(path)
    _verify_code_capture(captured, deadline)


def _ports(profile: Profile) -> str:
    p = profile.ports
    return str(p.first) if p.first == p.last else f"{p.first}:{p.last}"


def render_profile(
    config: Config, profile: Profile, target: str, *, effective_strategy: str | None = None
) -> str:
    """Executable rule text derives only from the root-protected closed model."""
    scope = config.scope(profile.scope)
    ipaddress.IPv4Address(target)
    label = f" # netorch:{profile.id}"  # Comments do not alter Darwin PF grammar.
    source = scope.lan_cidr
    ports = _ports(profile)
    if profile.kind == "publication":
        raise PFError("native publications are owned by the runtime, never PF")
    if profile.kind == "udp-return":
        return (
            f"nat on {scope.interface} inet proto udp from {target} port {ports} "
            f"to {source} -> {scope.host_ipv4} static-port{label}\n"
            f"rdr on {scope.interface} inet proto udp from {source} to {scope.host_ipv4} "
            f"port {ports} -> {target}{label}\n"
        )
    target_ports = (
        config.profile(profile.fallback_publication).ports
        if effective_strategy == "degraded-fallback" and profile.fallback_publication is not None
        else profile.target_ports or profile.ports
    )
    replacement = (
        str(target_ports.first)
        if target_ports.first == target_ports.last
        else f"{target_ports.first}:{target_ports.last}"
    )
    return (
        f"rdr on {scope.interface} inet proto {profile.protocol} from {source} "
        f"to {scope.host_ipv4} port {ports} -> {target} port {replacement}{label}\n"
    )


def compose_rules(records: Mapping[str, Mapping[str, Any]]) -> str:
    """PF grammar requires all NAT statements before all RDR statements."""
    lines = [line for key in sorted(records) for line in str(records[key]["rules"]).splitlines()]
    return "\n".join(
        [line for line in lines if line.startswith("nat ")]
        + [line for line in lines if line.startswith("rdr ")]
    ) + ("\n" if lines else "")


def _state_endpoint(token: str) -> str | None:
    """Validate one numerical endpoint; return its IPv4 address, if any.

    The nonverbose PF printer uses IPv4:port and IPv6[port], with no suffix
    for port zero. Translation endpoints are unwrapped by the row parser.
    No DNS names, diagnostics or partially parsed address can prove absence.
    """
    address = token
    port: str | None = None
    if "[" in token or "]" in token:
        matched = re.fullmatch(r"([^\[\]]+)\[([0-9]{1,5})\]", token)
        if matched is None:
            raise PFError("malformed PF endpoint")
        address, port = matched.groups()
        family = 6
    elif token.count(":") == 1:
        address, port = token.split(":")
        family = 4
    else:
        family = None
    if port is not None and (
        re.fullmatch(r"[0-9]{1,5}", port) is None or not 1 <= int(port) <= 65535
    ):
        raise PFError("malformed PF endpoint port")
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise PFError("malformed PF endpoint address") from exc
    if (family is not None and parsed.version != family) or "%" in address:
        raise PFError("unsupported PF endpoint address")
    if isinstance(parsed, ipaddress.IPv4Address):
        return str(parsed)
    # Preserve conservative matching for IPv4-mapped IPv6 observations too.
    return str(parsed.ipv4_mapped) if parsed.ipv4_mapped is not None else None


def _state_status(token: str, protocol: str) -> bool:
    if protocol in {"icmp", "icmp6", "ipv6-icmp"}:
        values = token.split(":")
        return len(values) == 2 and all(
            re.fullmatch(r"[0-9]{1,3}", value) is not None and int(value) <= 255 for value in values
        )
    if protocol == "tcp":
        if token in {"PROXY:SRC", "PROXY:DST"}:
            return True
        states = {
            "CLOSED",
            "LISTEN",
            "SYN_SENT",
            "SYN_RCVD",
            "ESTABLISHED",
            "CLOSE_WAIT",
            "FIN_WAIT_1",
            "CLOSING",
            "LAST_ACK",
            "FIN_WAIT_2",
            "TIME_WAIT",
        }
    else:
        states = {"NO_TRAFFIC", "SINGLE", "MULTIPLE"}
    values = token.split(":")
    return len(values) == 2 and all(value in states for value in values)


def state_addresses(raw: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Validate complete numerical nonverbose PF rows, never empty-on-error.

    Every original and translated endpoint on both sides is checked before any
    IPv4 target is extracted. IPv6-only rows require valid IPv6 addresses, not
    merely a colon somewhere in the output. New printer formats remain unknown
    until reviewed fixtures establish their complete grammar.
    """
    result: list[tuple[str, tuple[str, ...]]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        if len(line) > 4096 or any(ord(c) < 32 and c != "\t" for c in line):
            raise PFError("unsupported PF state observation")
        pieces = line.split()
        if (
            not 6 <= len(pieces) <= 8
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,15}", pieces[0]) is None
            or pieces[1] not in {"tcp", "udp", "icmp", "icmp6", "ipv6-icmp"}
            or not _state_status(pieces[-1], pieces[1])
        ):
            raise PFError("unsupported PF state observation")
        body = pieces[2:-1]
        arrows = [index for index, token in enumerate(body) if token in {"->", "<-"}]
        if len(arrows) != 1:
            raise PFError("unsupported PF state direction")
        arrow = arrows[0]
        addresses: list[str] = []
        for side in (body[:arrow], body[arrow + 1 :]):
            if not 1 <= len(side) <= 2:
                raise PFError("incomplete PF state endpoints")
            for index, token in enumerate(side):
                if index == 1:
                    if not token.startswith("(") or not token.endswith(")"):
                        raise PFError("malformed PF translated endpoint")
                    token = token[1:-1]
                address = _state_endpoint(token)
                if address is not None:
                    addresses.append(address)
        result.append((line, tuple(addresses)))
    return tuple(result)


class Backend(Protocol):
    def inspect(self) -> str: ...
    def normalize(self, rules: str) -> str: ...
    def replace(self, expected: str, candidate: str) -> str: ...
    def states(self) -> str: ...
    def drain(self, ipv4: str) -> None: ...
    def ensure_reference(self) -> None: ...
    def reference_held(self) -> bool: ...
    def endpoint(self, scope: Scope, ipv4: str, mac: str | None, *, direct: bool) -> bool: ...
    def ports_clear(self, scope: Scope, profile: Profile, *, apple_dns: bool) -> bool: ...


class ShellBackend:
    """Fixed administrator-owned Bash mutation mechanics, bounded by Python."""

    def __init__(self, root: Store, installation: Installation) -> None:
        self.root = root
        self.installation = installation
        self.script = root.directory / "backend.sh"
        payload = read_once(self.script, uid=0, mode=0o600, maximum=65536)
        if hashlib.sha256(payload).hexdigest() != installation.backend_sha256:
            raise PFError("installed mutation backend changed")

    def _call(self, operation: str, *arguments: str) -> str:
        result = run(
            ["/bin/bash", str(self.script), operation, self.installation.anchor, *arguments],
            timeout=4.0,
        )
        if result.returncode != 0:
            raise PFError("bounded PF backend operation failed")
        return result.stdout.decode("utf-8", errors="strict").strip()

    def _rules_file(self, name: str, text: str) -> Path:
        path = self.root.directory / name
        # Persist text as a private single-link file, never shell interpolation.
        with self.root._directory_fd() as parent:
            temporary = f".{name}-{os.urandom(12).hex()}"
            fd = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            try:
                with os.fdopen(os.dup(fd), "wb") as stream:
                    stream.write(text.encode("utf-8"))
                    stream.flush()
                    os.fsync(stream.fileno())
                self.root._check_current_directory(parent)
                os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(fd)
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=parent)
        return path

    def inspect(self) -> str:
        return self._call("inspect")

    def normalize(self, rules: str) -> str:
        return self._call("normalize", str(self._rules_file("parse.rules", rules)))

    def replace(self, expected: str, candidate: str) -> str:
        old = self._rules_file("expected.rules", expected)
        new = self._rules_file("candidate.rules", candidate)
        return self._call("replace", str(old), str(new))

    def states(self) -> str:
        return self._call("states")

    def drain(self, ipv4: str) -> None:
        address = str(ipaddress.IPv4Address(ipv4))
        self._call("drain", address)
        if any(address in addresses for _, addresses in state_addresses(self.states())):
            raise PFError("scoped PF states remain after invalidation")

    def ensure_reference(self) -> None:
        try:
            saved = self.root.read("reference.json")
        except FileNotFoundError:
            saved = None
        if saved is not None:
            if (
                not isinstance(saved, dict)
                or set(saved) != {"token"}
                or not re.fullmatch(r"[0-9]{1,20}", str(saved["token"]))
            ):
                raise PFError("owned PF reference record is damaged")
            token = saved["token"]
            for line in self._call("references").splitlines():
                fields = line.split()
                if len(fields) >= 6 and fields[-2] == "days" and fields[-4] == token:
                    self._call("enabled")
                    return
        output = self._call("enable")
        matches = re.findall(r"(?im)^token\s*:\s*([0-9]{1,20})\s*$", output)
        if len(matches) != 1:
            raise PFError("new PF enable reference could not be identified")
        self.root.write("reference.json", {"token": matches[0]})
        token = matches[0]
        visible = False
        for line in self._call("references").splitlines():
            fields = line.split()
            if len(fields) >= 6 and fields[-2] == "days" and fields[-4] == token:
                visible = True
        if not visible:
            raise PFError("new owned PF reference did not verify")
        self._call("enabled")
        # Keep this owned reference through pause/empty rules; container runtime
        # availability must not be changed by releasing another service's PF.

    def reference_held(self) -> bool:
        """Read only: the kernel lists this owner's saved token and PF is enabled.

        Uses the backend's two existing reads, `references` and `enabled`. It
        never acquires or releases a reference; `ensure_reference` alone
        acquires one, at an activation. It raises when a read fails or does
        not show PF enabled.
        """
        try:
            saved = self.root.read("reference.json")
        except FileNotFoundError:
            return False
        if (
            not isinstance(saved, dict)
            or set(saved) != {"token"}
            or not isinstance(saved["token"], str)
            or not re.fullmatch(r"[0-9]{1,20}", saved["token"])
        ):
            raise PFError("owned PF reference record is damaged")
        listed = False
        for line in self._call("references").splitlines():
            fields = line.split()
            if len(fields) >= 6 and fields[-2] == "days" and fields[-4] == saved["token"]:
                listed = True
        if not listed:
            return False
        self._call("enabled")
        return True

    @staticmethod
    def _native(argv: list[str]) -> str:
        result = run(argv, timeout=2.0, max_output=262144)
        if result.returncode or result.stderr:
            raise PFError("native kernel observation is unknown")
        return result.stdout.decode("utf-8", errors="strict")

    def endpoint(self, scope: Scope, ipv4: str, mac: str | None, *, direct: bool) -> bool:
        interface = self._native(["/sbin/ifconfig", scope.interface])
        lines = interface.splitlines()
        if (
            not lines
            or re.fullmatch(
                re.escape(scope.interface) + r": flags=[0-9a-fA-F]+(?:<[^<>]+>)?(?: .+)?",
                lines[0],
            )
            is None
            or sum(re.match(r"^[^\s:]+:", line) is not None for line in lines) != 1
        ):
            return False
        selected = [
            inet_fields
            for line in interface.splitlines()
            if (inet_fields := line.split())[:2] == ["inet", scope.host_ipv4]
        ]
        if (
            len(selected) != 1
            or len(selected[0]) < 4
            or selected[0][2] != "netmask"
            or selected[0].count("netmask") != 1
            or re.fullmatch(r"0x[0-9a-fA-F]{8}", selected[0][3]) is None
        ):
            return False
        # Admission cannot widen the live interface's own prefix. Merely
        # finding the host address would accept a /8 policy on a /24 LAN.
        mask = int(selected[0][3], 16)
        inverse = (~mask) & 0xFFFFFFFF
        if inverse & (inverse + 1):
            return False
        try:
            # IPv4Network's dotted-mask parser accepts inverse hostmasks. The
            # native field is a netmask: require contiguous MSB ones explicitly.
            actual = ipaddress.IPv4Network((scope.host_ipv4, mask.bit_count()), strict=False)
            declared = ipaddress.IPv4Network(scope.lan_cidr, strict=True)
        except ValueError:
            return False
        if not declared.subnet_of(actual):
            return False
        if not direct:
            return True
        if self._native(["/usr/sbin/sysctl", "-n", "net.inet.ip.forwarding"]).strip() != "1":
            return False
        route = self._native(["/sbin/route", "-n", "get", "-inet", ipv4])
        fields: dict[str, str] = {}
        for line in route.splitlines():
            if ":" in line:
                key, value = line.strip().split(":", 1)
                if key in fields:
                    return False
                fields[key] = value.strip()
        if (
            fields.get("route to") != ipv4
            or not re.fullmatch(r"bridge[0-9]{1,5}", fields.get("interface", ""))
            or not re.fullmatch(r"<[A-Z0-9_,]+>", fields.get("flags", ""))
            or any(flag in fields.get("flags", "") for flag in ("GATEWAY", "REJECT", "BLACKHOLE"))
        ):
            return False
        if (
            mac is None
            or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac)
            or int(mac[:2], 16) & 1
            or mac == "00:00:00:00:00:00"
        ):
            return False
        arp = self._native(["/usr/sbin/arp", "-n", ipv4]).split()
        if (
            len(arp) < 7
            or arp[:3] != ["?", f"({ipv4})", "at"]
            or arp[4:6] != ["on", fields["interface"]]
        ):
            return False
        try:
            normalized = ":".join(f"{int(x, 16):02x}" for x in arp[3].split(":"))
        except ValueError:
            return False
        return (
            normalized == mac
            and len(arp[3].split(":")) == 6
            and all(x in {"[bridge]", "[ethernet]", "ifscope", "permanent"} for x in arp[6:])
            and sum(x in {"[bridge]", "[ethernet]"} for x in arp[6:]) == 1
        )

    def ports_clear(self, scope: Scope, profile: Profile, *, apple_dns: bool) -> bool:
        raw = self._native(["/usr/sbin/netstat", "-anlv", "-W", "-p", profile.protocol])
        rows = parse_socket_inventory(raw, profile.protocol)
        for row in rows:
            address, port, pid, command, _family = row
            selected_address = address
            if address != "*":
                numeric = ipaddress.ip_address(address.split("%", 1)[0])
                if isinstance(numeric, ipaddress.IPv6Address) and numeric.ipv4_mapped is not None:
                    selected_address = str(numeric.ipv4_mapped)
            if not profile.ports.first <= port <= profile.ports.last or selected_address not in {
                "*",
                "0.0.0.0",
                "::",
                scope.host_ipv4,
            }:
                continue
            if (
                not apple_dns
                or port != 53
                or address not in {"*", "::"}
                or command != "mDNSResponder"
                or pid <= 0
                or not self._apple_dns_pid(pid)
            ):
                return False
        return True

    def _apple_dns_pid(self, pid: int) -> bool:
        signature = run(
            [
                "/usr/bin/codesign",
                "--verify",
                "--strict",
                '-R=anchor apple and identifier "com.apple.mDNSResponder"',
                "/usr/sbin/mDNSResponder",
            ],
            timeout=2.0,
        )
        if signature.returncode:
            return False
        identity = self._native(
            ["/bin/ps", "-p", str(pid), "-o", "uid=", "-o", "ppid=", "-o", "comm="]
        ).split()
        uid = self._native(["/usr/bin/id", "-u", "_mdnsresponder"]).strip()
        if identity != [uid, "1", "/usr/sbin/mDNSResponder"]:
            return False
        for label in ("com.apple.mDNSResponder.reloaded", "com.apple.mDNSResponder"):
            job = run(["/bin/launchctl", "print", f"system/{label}"], timeout=2.0)
            if job.returncode:
                continue
            fields = job.stdout.decode("utf-8").splitlines()
            return (
                sum(re.fullmatch(rf"\s*pid = {pid}\s*", line) is not None for line in fields) == 1
                and any(line.strip() == "program = /usr/sbin/mDNSResponder" for line in fields)
                and any(line.strip() == "username = _mdnsresponder" for line in fields)
            )
        return False


def parse_socket_inventory(raw: str, protocol: str) -> tuple[tuple[str, int, int, str, str], ...]:
    """Closed Darwin netstat schema, including diagnostics and complete rows."""
    lines = raw.splitlines()
    header = (
        "Proto Recv-Q Send-Q Local Address Foreign Address (state) rxbytes txbytes "
        "rhiwat shiwat process:pid state options gencnt flags flags1 usecnt rtncnt fltrs"
    )
    if (
        len(lines) < 2
        or lines[0] != "Active Internet connections (including servers)"
        or " ".join(lines[1].split()) != header
        or protocol not in {"tcp", "udp"}
    ):
        raise PFError("unsupported socket observation schema")
    rows: list[tuple[str, int, int, str, str]] = []
    for line in lines[2:]:
        parts = line.split()
        tcp = protocol == "tcp"
        owner_index = 10 if tcp else 9
        if len(parts) < owner_index + 9 or parts[0] not in {
            f"{protocol}4",
            f"{protocol}6",
            f"{protocol}46",
        }:
            raise PFError("unsupported socket observation row")
        if (
            not parts[1].isdigit()
            or not parts[2].isdigit()
            or any(not value.isdigit() for value in parts[6 if tcp else 5 : owner_index])
        ):
            raise PFError("malformed socket counters")
        if tcp and parts[5] not in {
            "CLOSED",
            "LISTEN",
            "SYN_SENT",
            "SYN_RCVD",
            "ESTABLISHED",
            "CLOSE_WAIT",
            "FIN_WAIT_1",
            "CLOSING",
            "LAST_ACK",
            "FIN_WAIT_2",
            "TIME_WAIT",
        }:
            raise PFError("malformed socket state")
        tail = parts[-8:]
        if (
            not re.fullmatch(r"[0-9a-fA-F]{5,8}", tail[0])
            or not re.fullmatch(r"[0-9a-fA-F]{8}", tail[1])
            or not re.fullmatch(r"[0-9a-fA-F]{16}", tail[2])
            or any(not re.fullmatch(r"[0-9a-fA-F]{8}", x) for x in tail[3:5])
            or any(not x.isdigit() for x in tail[5:7])
            or not re.fullmatch(r"[0-9a-fA-F]{6}", tail[7])
        ):
            raise PFError("malformed socket metadata")
        command, separator, pid_text = " ".join(parts[owner_index:-8]).rpartition(":")
        if not separator or not pid_text.isdigit():
            raise PFError("unresolved socket process")
        family = "IPv6" if parts[0] == f"{protocol}6" else "IPv4"
        parsed: list[tuple[str, int]] = []
        for endpoint in parts[3:5]:
            if endpoint == "*.*":
                parsed.append(("*", 0))
                continue
            address, separator, port_text = endpoint.rpartition(".")
            if not separator or not port_text.isdigit() or int(port_text) > 65535:
                raise PFError("malformed socket endpoint")
            if address != "*":
                try:
                    ipaddress.ip_address(address.split("%", 1)[0])
                except ValueError as exc:
                    raise PFError("malformed socket address") from exc
            parsed.append((address, int(port_text)))
        if tcp and parts[5] != "LISTEN":
            continue
        address, port = parsed[0]
        # Kernel/unbound sockets may legitimately have pid=0 or port=0. Keep
        # them in the complete inventory; a selected port remains a collision
        # unless its positive process identity independently proves the sole
        # signed Apple DNS exception.
        rows.append((address, port, int(pid_text), command, family))
        if parts[0].endswith("46") and address == "*":
            rows.append(("::", port, int(pid_text), command, "IPv6"))
    return tuple(rows)


def _records(raw: Any) -> dict[str, dict[str, Any]]:
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "records"}
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or not isinstance(raw["records"], dict)
    ):
        raise PFError("owned kernel record is damaged")
    records = raw["records"]
    for key, value in records.items():
        required = {
            "active",
            "kind",
            "effective_strategy",
            "target_ipv4",
            "target_generation",
            "network_generation",
            "policy_digest",
            "rules",
        }
        if (
            not isinstance(key, str)
            or not _ID.fullmatch(key)
            or not isinstance(value, dict)
            or set(value) != required
            or type(value["active"]) is not bool
            or value["kind"] not in {"host-redirect", "guest-direct", "udp-return"}
            or value["effective_strategy"] not in {None, "degraded-fallback"}
            or not isinstance(value["rules"], str)
            or len(value["rules"]) > 16384
            or not isinstance(value["policy_digest"], str)
            or not _HASH.fullmatch(value["policy_digest"])
        ):
            raise PFError("owned profile record is damaged")
        if not isinstance(value["target_ipv4"], str):
            raise PFError("owned target address is not canonical")
        ipaddress.IPv4Address(value["target_ipv4"])
        if any(
            not isinstance(value[x], str) or not value[x] or len(value[x]) > 256
            for x in ("target_generation", "network_generation")
        ):
            raise PFError("owned generation record is damaged")
        if not value["active"] and value["rules"]:
            raise PFError("withdrawn profile retains rules")
        if any(
            not line.startswith(("nat ", "rdr ")) or f" # netorch:{key}" not in line
            for line in value["rules"].splitlines()
        ):
            raise PFError("owned rule record is damaged")
    return {key: dict(value) for key, value in records.items()}


def _read_admissions(raw: Any) -> dict[str, dict[str, Any]]:
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "strategy", "profiles"}
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or raw["strategy"] != STRATEGY
        or not isinstance(raw["profiles"], dict)
    ):
        raise PFError("root admission record is damaged")
    for key, value in raw["profiles"].items():
        if (
            not isinstance(key, str)
            or not _ID.fullmatch(key)
            or not isinstance(value, dict)
            or set(value) != {"digest", "approved_at", "approved_by", "risk_acknowledged"}
            or not isinstance(value["digest"], str)
            or not _HASH.fullmatch(value["digest"])
            or not isinstance(value["approved_by"], str)
            or not value["approved_by"]
            or type(value["risk_acknowledged"]) is not bool
            or isinstance(value["approved_at"], bool)
            or not isinstance(value["approved_at"], (int, float))
            or not math.isfinite(value["approved_at"])
            or value["approved_at"] < 0
        ):
            raise PFError("root profile admission is damaged")
    return dict(raw["profiles"])


def _effective_admissions(
    config: Config, installation: Installation, raw: Any
) -> dict[str, Admission]:
    records = _read_admissions(raw)
    result: dict[str, Admission] = {}
    for profile in config.profiles:
        record = records.get(profile.id)
        if (
            config.profile_owner(profile).id == installation.owner
            and record is not None
            and record["digest"] == admitted_digest(config, profile, installation)
        ):
            result[profile.id] = Admission(
                profile.id,
                profile_digest(config, profile),
                record["approved_by"],
                record["approved_at"],
                record["risk_acknowledged"],
            )
    return result


def _inhibition(root: Store, installation: Installation) -> Intent:
    try:
        own = intent_from_dict(root.read("operator-intent.json"))
    except (OSError, ValueError, UnsafeState):
        own = Intent(damaged=True)
    if installation.intent_path is None:
        return own
    try:
        # A user-supplied gate can only remove already admitted root authority.
        external = intent_from_dict(
            strict_loads(read_once(Path(installation.intent_path), mode=0o600))
        )
    except (OSError, ValueError, UnsafeState):
        external = Intent(damaged=True)
    return Intent(
        revision=max(own.revision, external.revision),
        operator_paused=own.operator_paused or external.operator_paused,
        suspensions={
            **own.suspensions,
            **{
                f"external:{hashlib.sha256(key.encode()).hexdigest()}": holder
                for key, holder in external.suspensions.items()
            },
        },
        damaged=own.damaged or external.damaged,
    )


def _snapshot(
    config: Config,
    runtime: Snapshot,
    records: Mapping[str, Mapping[str, Any]],
    backend: Backend,
    now: float,
    owner: str,
) -> Snapshot:
    states = state_addresses(backend.states())
    profiles = dict(runtime.profiles)
    for profile in config.profiles:
        if config.profile_owner(profile).id != owner:
            continue
        record = records.get(profile.id)
        data: dict[str, Any] = {"states": ()}
        if record is not None:
            target = record["target_ipv4"]
            # Only the fact that states remain is evidence for planning. Raw
            # kernel rows name a guest's remote peers and the clients on the
            # LAN: they stay out of the snapshot that is hashed for the plan
            # and out of the world-readable report, and they cannot grow
            # either one beyond its serialization bound.
            matching = (
                ()
                if record["kind"] == "host-redirect"
                or not any(target in addresses for _, addresses in states)
                else ("retained",)
            )
            data = {
                key: record[key]
                for key in (
                    "target_ipv4",
                    "target_generation",
                    "network_generation",
                    "policy_digest",
                )
            }
            data["states"] = matching
            data["effective_strategy"] = record["effective_strategy"]
            present = bool(record["active"])
            generation = record["target_generation"]
        else:
            present = False
            generation = None
        if profile.fallback_publication is not None:
            service = runtime.services.get(profile.service)
            valid = False
            if (
                service is not None
                and service.at(now, profile.safety.max_age_seconds).state == "present"
            ):
                guest = service.data.get("ipv4")
                mac = service.data.get("mac")
                if isinstance(guest, str) and isinstance(mac, str):
                    with contextlib.suppress(OSError, RuntimeError, ValueError):
                        valid = backend.endpoint(
                            config.scope(profile.scope), guest, mac, direct=True
                        )
            data["direct_available"] = valid
        profiles[profile.id] = Observation(
            "present" if present else "absent",
            "verified" if present else "confirmed-absent",
            now,
            generation,
            data,
        )
    return Snapshot(runtime.observed_at, runtime.network_generation, runtime.services, profiles)


def _write_report(installation: Installation, snapshot: Snapshot) -> None:
    destination = Path(installation.report_path)
    protected_ancestors(destination.parent)
    temporary = destination.with_name(f".{destination.name}-{os.urandom(16).hex()}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        payload = canonical_bytes(snapshot_to_dict(snapshot)) + b"\n"
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(payload)
            stream.flush()
            # Root launchd intentionally uses umask 077. Set the report's
            # deliberate public readback mode explicitly before atomic rename.
            os.fchmod(fd, 0o644)
            os.fsync(stream.fileno())
        if destination.exists() or destination.is_symlink():
            info = destination.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
                raise UnsafeState("owner report destination is unsafe")
        os.replace(temporary, destination)
        parent = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def _reference_verified(backend: Backend, records: Mapping[str, Mapping[str, Any]]) -> bool:
    """Whether loaded rules can count on PF being enabled under this owner's reference.

    A loaded rule carries nothing while PF is disabled, and only the owner's own
    reference keeps PF enabled when another service releases its own. Without an
    active record there is no rule to carry anything and nothing to verify. A
    read that fails, or that does not list the reference, is not a verification.
    """
    if not any(record["active"] for record in records.values()):
        return True
    try:
        return backend.reference_held() is True
    except (OSError, RuntimeError, ValueError):
        return False


def reconcile(
    root: Store,
    observer: Callable[[Config, Mapping[str, Any]], Snapshot],
    backend_factory: Callable[[Store, Installation], Backend],
    *,
    now: Callable[[], float] = time.time,
    report: Callable[[Installation, Snapshot], None] = _write_report,
) -> dict[str, Any]:
    """One independently scheduled pull pass; no caller supplies a plan or target.

    The protected live journal is solely evidence for withdrawal/draining, never
    an activation source. Replacement targets require a later fresh pass after
    previous rules and states have been read back absent.
    """
    with root.lock():
        installation = Installation.from_dict(root.read("installation.json"))
        config = parse_config(canonical_bytes(root.read("policy.json")))
        if config.owner(installation.owner).privilege != "external-root":
            raise PFError("installed owner is not independently privileged")
        owned = {
            profile.id
            for profile in config.profiles
            if config.profile_owner(profile).id == installation.owner
        }
        if any(config.profile(key).kind == "publication" for key in owned):
            raise PFError("PF owner cannot claim runtime publication authority")
        backend = backend_factory(root, installation)
        try:
            records = _records(root.read("live.json"))
        except FileNotFoundError:
            records = {}
        observed_rules = backend.inspect()
        intent = _inhibition(root, installation)
        try:
            journal = root.read("journal.json")
        except FileNotFoundError:
            journal = None
        needs_ack = False
        if journal is not None:
            if not isinstance(journal, dict) or journal.get("phase") not in {
                "committed",
                "inhibited",
                "failed",
                "applying",
                "acknowledged",
            }:
                raise PFError("PF journal is damaged")
            if journal["phase"] in {"failed", "applying"}:
                needs_ack = True
                candidate_records = journal.get("candidate_records")
                if candidate_records is not None:
                    possible = _records({"schema_version": 1, "records": candidate_records})
                    if observed_rules == backend.normalize(compose_rules(possible)):
                        records = possible
                        root.write("live.json", {"schema_version": 1, "records": records})
                # Safely retire known exposure; explicit administrator ack is
                # required before any activation after an interrupted pass.
                intent = Intent(intent.revision, intent.operator_paused, intent.suspensions, True)
        if observed_rules != backend.normalize(compose_rules(records)):
            raise PFError("owned PF rules drifted; no overwrite or activation")
        try:
            runtime = observer(config, installation.observer)
        except (OSError, RuntimeError, ValueError):
            stamp = now()
            runtime = Snapshot(
                stamp,
                None,
                {
                    service.id: Observation("unknown", "unavailable", stamp, None)
                    for service in config.services
                },
                {},
            )
        stamp = now()
        try:
            snapshot = _snapshot(config, runtime, records, backend, stamp, installation.owner)
        except (OSError, RuntimeError, ValueError):
            # Unknown state metadata must not retain known active exposure. The
            # anchor was already exactly identified, so withdrawal is safe;
            # no activation or claimed state-drain success follows this read.
            retired = {
                key: {**value, "active": False, "rules": ""} for key, value in records.items()
            }
            root.write(
                "journal.json",
                {
                    "schema_version": 1,
                    "phase": "applying",
                    "candidate_records": retired,
                    "started_at": stamp,
                },
            )
            if compose_rules(records):
                backend.replace(compose_rules(records), "")
                if backend.inspect() != backend.normalize(""):
                    raise PFError("unknown-state withdrawal readback failed") from None
            root.write("live.json", {"schema_version": 1, "records": retired})
            for value in retired.values():
                if value["kind"] != "host-redirect":
                    with contextlib.suppress(OSError, RuntimeError, ValueError):
                        backend.drain(value["target_ipv4"])
            root.write(
                "journal.json",
                {
                    "schema_version": 1,
                    "phase": "failed",
                    "candidate_records": retired,
                    "failed_at": stamp,
                    "reason": "kernel-state-unknown",
                },
            )
            uncertain = Snapshot(
                stamp,
                runtime.network_generation,
                {},
                {key: Observation("unknown", "incomplete", stamp, None) for key in owned},
            )
            report(installation, uncertain)
            return {
                "schema_version": 1,
                "phase": "failed",
                "changed": [f"{key}:withdraw" for key in records],
                "pending": sorted(owned),
            }
        # Runtime-native publication observations are read by this root's own
        # trusted observer. Their admission is separate from PF authority.
        try:
            admissions = _effective_admissions(config, installation, root.read("admissions.json"))
        except (OSError, RuntimeError, ValueError):
            admissions = {}
            needs_ack = True
            intent = Intent(intent.revision, intent.operator_paused, intent.suspensions, True)
        for profile in config.profiles:
            if (
                profile.kind == "publication"
                and config.profile_owner(profile).id != installation.owner
            ):
                admissions[profile.id] = Admission(
                    profile.id, profile_digest(config, profile), "runtime-observation", stamp, False
                )
        candidate = plan(config, snapshot, admissions, intent, stamp)
        actions = [action for action in candidate.actions if action.profile in owned]
        # Policies removed from the desired catalog must retire both rules and
        # states too. Removing a profile is never an implicit ownership handoff.
        for key in sorted(set(records) - owned):
            record = records[key]
            actions.extend(
                (
                    Action(
                        key,
                        installation.owner,
                        "withdraw",
                        "not-admitted",
                        record["target_ipv4"],
                        record["target_generation"],
                    ),
                    Action(
                        key,
                        installation.owner,
                        "drain",
                        "not-admitted",
                        record["target_ipv4"],
                        record["target_generation"],
                    ),
                )
            )
        # Retire every rule before invalidating any state, as the administrator
        # withdrawal and the unknown-state path do. A state readback that fails
        # for one profile must not leave a later profile's rule loaded, and a
        # sibling rule that is still loaded must not keep creating states for
        # the address being drained. Everything else keeps its planned order.
        actions = [action for action in actions if action.operation == "withdraw"] + [
            action for action in actions if action.operation != "withdraw"
        ]
        root.write(
            "journal.json",
            {
                "schema_version": 1,
                "phase": "applying",
                "actions": [asdict(action) for action in actions],
                "started_at": stamp,
            },
        )
        changed: list[str] = []
        try:
            for action in actions:
                if action.operation in {"blocked", "pending", "noop"}:
                    continue
                # Re-read durable gates and desired identity at every mutation;
                # an unprivileged planner cannot turn a stale pass into root RPC.
                latest = Installation.from_dict(root.read("installation.json"))
                latest_config = parse_config(canonical_bytes(root.read("policy.json")))
                if latest.to_dict() != installation.to_dict() or to_dict(latest_config) != to_dict(
                    config
                ):
                    raise PFError("protected desired snapshot changed during pass")
                if action.operation == "activate":
                    if _inhibition(root, installation).blocked:
                        raise PFError("inhibition appeared before activation")
                    profile = config.profile(action.profile)
                    current_admissions = _effective_admissions(
                        config, installation, root.read("admissions.json")
                    )
                    if action.profile not in current_admissions:
                        raise PFError("admission changed before activation")
                    fresh = observer(config, installation.observer)
                    fresh_snapshot = _snapshot(
                        config, fresh, records, backend, now(), installation.owner
                    )
                    fresh_plan = plan(
                        config, fresh_snapshot, admissions, _inhibition(root, installation), now()
                    )
                    if action not in fresh_plan.actions:
                        raise PFError("runtime changed before activation")
                    assert action.target_ipv4 is not None and action.target_generation is not None
                    scope = config.scope(profile.scope)
                    service = fresh.services.get(profile.service)
                    mac = None if service is None else service.data.get("mac")
                    if not backend.endpoint(
                        scope,
                        action.target_ipv4,
                        mac if isinstance(mac, str) else None,
                        direct=profile.kind != "host-redirect"
                        and action.effective_strategy != "degraded-fallback",
                    ) or not backend.ports_clear(
                        scope, profile, apple_dns=installation.allow_apple_dns_coexistence
                    ):
                        raise PFError("kernel target or socket coexistence is unverified")
                    backend.ensure_reference()
                    update = dict(records)
                    update[action.profile] = {
                        "active": True,
                        "kind": "host-redirect"
                        if action.effective_strategy == "degraded-fallback"
                        else profile.kind,
                        "effective_strategy": action.effective_strategy,
                        "target_ipv4": action.target_ipv4,
                        "target_generation": action.target_generation,
                        "network_generation": fresh.network_generation,
                        "policy_digest": profile_digest(config, profile),
                        "rules": render_profile(
                            config,
                            profile,
                            action.target_ipv4,
                            effective_strategy=action.effective_strategy,
                        ),
                    }
                elif action.operation == "withdraw":
                    if action.profile not in records:
                        continue
                    update = {key: dict(value) for key, value in records.items()}
                    update[action.profile]["active"] = False
                    update[action.profile]["rules"] = ""
                else:
                    target = action.target_ipv4
                    if target is None:
                        raise PFError("state invalidation has no independently known target")
                    # Structural native host publications keep socket ownership;
                    # killing all host-IP states would disrupt unrelated services.
                    retiring = records.get(action.profile)
                    if retiring is None or retiring["kind"] != "host-redirect":
                        backend.drain(target)
                    update = dict(records)
                    if action.profile in update and not update[action.profile]["active"]:
                        del update[action.profile]
                before = compose_rules(records)
                after = compose_rules(update)
                root.write(
                    "journal.json",
                    {
                        "schema_version": 1,
                        "phase": "applying",
                        "actions": [asdict(item) for item in actions],
                        "candidate_records": update,
                        "started_at": stamp,
                    },
                )
                if before != after:
                    backend.replace(before, after)
                    if backend.inspect() != backend.normalize(after):
                        raise PFError("PF write readback did not match candidate")
                records = update
                root.write("live.json", {"schema_version": 1, "records": records})
                changed.append(f"{action.profile}:{action.operation}")
            final_runtime = observer(config, installation.observer)
            if backend.inspect() != backend.normalize(compose_rules(records)):
                raise PFError("owned rules changed before final readback")
            final = _snapshot(config, final_runtime, records, backend, now(), installation.owner)
            final_intent = _inhibition(root, installation)
            if needs_ack:
                final_intent = Intent(
                    final_intent.revision,
                    final_intent.operator_paused,
                    final_intent.suspensions,
                    True,
                )
            status = plan(config, final, admissions, final_intent, now())
            verified_profiles = {
                action.profile
                for action in status.actions
                if action.operation == "noop" and action.reason == "verified"
            }
            # Read on every pass that leaves a rule loaded, not only at an
            # activation: another tool can disable PF at any time, which also
            # drops every enable reference.
            reference_verified = _reference_verified(backend, records)
            phase = (
                "failed"
                if needs_ack
                else (
                    "committed"
                    if reference_verified
                    and all(
                        action.operation == "noop"
                        for action in status.actions
                        if action.profile in owned
                    )
                    else "inhibited"
                )
            )
            root.write(
                "journal.json",
                {
                    "schema_version": 1,
                    "phase": phase,
                    "actions": [asdict(action) for action in actions],
                    "finished_at": now(),
                    **({} if reference_verified else {"reason": "enable-reference-unverified"}),
                },
            )
            try:
                current_root_approvals = _effective_admissions(
                    config, installation, root.read("admissions.json")
                )
            except (OSError, RuntimeError, ValueError):
                current_root_approvals = {}
            published = {}
            for key, observed_profile in final.profiles.items():
                if key not in owned:
                    continue
                data = dict(observed_profile.data)
                approval = current_root_approvals.get(key)
                profile = config.profile(key)
                valid_approval = (
                    approval is not None
                    and approval.approved_at <= now()
                    and (profile.safety.kind != "bounded" or approval.risk_acknowledged)
                )
                data["admitted"] = valid_approval
                # Approval and truthful kernel exposure are separate facts from
                # current operational readiness. A final pause, suspension,
                # changed target or incomplete verification must not authorize
                # discovery until the next independent pass retires exposure.
                data["root_ready"] = (
                    valid_approval
                    and not final_intent.blocked
                    and key in verified_profiles
                    and reference_verified
                )
                data["admission_digest"] = (
                    admitted_digest(config, profile, installation) if valid_approval else None
                )
                data["policy_digest"] = profile_digest(config, config.profile(key))
                published[key] = Observation(
                    observed_profile.state,
                    observed_profile.reason,
                    observed_profile.observed_at,
                    observed_profile.generation,
                    data,
                )
            report(
                installation, Snapshot(final.observed_at, final.network_generation, {}, published)
            )
            return {
                "schema_version": 1,
                "phase": phase,
                "changed": changed,
                "pending": [
                    action.profile
                    for action in status.actions
                    if action.profile in owned and action.operation in {"pending", "blocked"}
                ],
            }
        except BaseException:
            failed_journal = root.read("journal.json")
            failed_journal["phase"] = "failed"
            failed_journal["failed_at"] = now()
            root.write("journal.json", failed_journal)
            raise


def withdraw(
    root: Store,
    backend_factory: Callable[[Store, Installation], Backend],
    *,
    operation: str | None = None,
    holder: str | None = None,
) -> dict[str, Any]:
    """Administrator quiescence before stopping the independent scheduler.

    Uses exact known kernel ownership solely to retire; never invokes runtime
    recovery, replays prior endpoints, or unpauses an operation-owned gate.
    """
    with root.lock():
        installation = Installation.from_dict(root.read("installation.json"))
        intent = intent_from_dict(root.read("operator-intent.json"))
        if intent.damaged:
            raise PFError("damaged durable intent requires administrator repair")
        if operation is not None or holder is not None:
            if operation is None or holder is None or intent.suspensions.get(operation) != holder:
                raise PFError("withdrawal operation does not own its durable suspension")
            # Installation quiescence must not manufacture an operator pause.
            paused = intent
        else:
            paused = intent.pause()
        root.write("operator-intent.json", intent_to_dict(paused))
        backend = backend_factory(root, installation)
        try:
            records = _records(root.read("live.json"))
        except FileNotFoundError:
            records = {}
        live = backend.inspect()
        if live != backend.normalize(compose_rules(records)):
            try:
                previous = root.read("journal.json")
                possible = _records({"schema_version": 1, "records": previous["candidate_records"]})
            except (OSError, KeyError, RuntimeError, ValueError) as exc:
                raise PFError("cannot independently identify owned withdrawal state") from exc
            if live != backend.normalize(compose_rules(possible)):
                raise PFError("foreign PF drift prevents quiescence")
            records = possible
        retired = {key: {**record, "active": False, "rules": ""} for key, record in records.items()}
        root.write(
            "journal.json",
            {
                "schema_version": 1,
                "phase": "applying",
                "candidate_records": retired,
                "reason": "administrator-withdrawal",
            },
        )
        try:
            if compose_rules(records):
                backend.replace(compose_rules(records), "")
            if backend.inspect() != backend.normalize(""):
                raise PFError("withdrawal rules remain")
            root.write("live.json", {"schema_version": 1, "records": retired})
            for record in retired.values():
                if record["kind"] != "host-redirect":
                    backend.drain(record["target_ipv4"])
            root.write("live.json", {"schema_version": 1, "records": {}})
            root.write(
                "journal.json",
                {"schema_version": 1, "phase": "inhibited", "reason": "administrator-withdrawal"},
            )
            return {
                "schema_version": 1,
                "withdrawn": True,
                "guest_states_drained": True,
                "operator_paused": paused.operator_paused,
                "reference_preserved": True,
            }
        except BaseException:
            journal = root.read("journal.json")
            journal["phase"] = "failed"
            root.write("journal.json", journal)
            raise


def install(
    root_directory: Path, policy_input: Path, settings_input: Path, backend_input: Path
) -> dict[str, Any]:
    """Stage a new protected desired snapshot without granting new authority.

    Inputs are read once, descriptor-pinned, parsed completely, then atomically
    copied into the protected directory under its persistent lock. Updates keep
    admissions, operator pause, suspensions and recovery journals unchanged.
    """
    protected_ancestors(root_directory.parent)
    policy = parse_config(read_once(policy_input))
    settings = Installation.from_dict(strict_loads(read_once(settings_input)))
    backend = read_once(backend_input, maximum=65536)
    if hashlib.sha256(backend).hexdigest() != settings.backend_sha256:
        raise PFError("reviewed backend and installation digest differ")
    if policy.owner(settings.owner).privilege != "external-root":
        raise PFError("installation must name an existing external-root owner")
    if any(
        policy.profile_owner(profile).id == settings.owner and profile.kind == "publication"
        for profile in policy.profiles
    ):
        raise PFError("root PF installation cannot take native publication ownership")
    root = Store(root_directory)
    protected_ancestors(root.directory)
    with root.lock():
        try:
            previous = Installation.from_dict(root.read("installation.json"))
        except FileNotFoundError:
            previous = None
        if previous is not None and (
            previous.owner != settings.owner
            or previous.anchor != settings.anchor
            or previous.report_path != settings.report_path
            or previous.intent_path != settings.intent_path
        ):
            raise PFError("installed ownership or report identity cannot be silently migrated")
        try:
            existing = root.read("admissions.json")
        except FileNotFoundError:
            existing = {"schema_version": 1, "strategy": STRATEGY, "profiles": {}}
            root.write("admissions.json", existing)
        _read_admissions(existing)
        try:
            root.read("operator-intent.json")
        except FileNotFoundError:
            root.write("operator-intent.json", intent_to_dict(Intent(operator_paused=True)))
        # The admitted set is never broadened by desired settings, an upgrade,
        # a wider port range or a different backend/observer strategy.
        root.write("policy.json", to_dict(policy))
        root.write("installation.json", settings.to_dict())
        path = root.directory / "backend.sh"
        temporary = root.directory / f".backend-{os.urandom(16).hex()}"
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(os.dup(fd), "wb") as stream:
                stream.write(backend)
                stream.flush()
                os.fsync(stream.fileno())
            if path.exists() or path.is_symlink():
                read_once(path, uid=os.geteuid(), mode=0o600, maximum=65536)
            os.replace(temporary, path)
            parent = os.open(root.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            os.close(fd)
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()
        pending = [
            profile.id
            for profile in policy.profiles
            if policy.profile_owner(profile).id == settings.owner
            and (
                profile.id not in existing["profiles"]
                or existing["profiles"][profile.id]["digest"]
                != admitted_digest(policy, profile, settings)
            )
        ]
        return {
            "schema_version": 1,
            "installed": True,
            "admissions_preserved": True,
            "pending": pending,
        }


def admit(
    root: Store,
    identifier: str,
    *,
    acknowledge_bounded_risk: bool,
    expected_digest: str | None = None,
    approved_by: str = "local-administrator",
    now: float | None = None,
) -> dict[str, Any]:
    """Administrator action only; display exact resolved before/after admission."""
    with root.lock():
        installation = Installation.from_dict(root.read("installation.json"))
        config = parse_config(canonical_bytes(root.read("policy.json")))
        profile = config.profile(identifier)
        if config.profile_owner(profile).id != installation.owner or profile.kind == "publication":
            raise PFError("profile is outside this PF owner's authority")
        if profile.safety.kind == "bounded" and not acknowledge_bounded_risk:
            raise PFError("bounded guest-reuse risk requires explicit acknowledgement")
        raw = root.read("admissions.json")
        records = _read_admissions(raw)
        resolved = admitted_digest(config, profile, installation)
        if expected_digest is not None and expected_digest != resolved:
            raise PFError("reviewed admission digest changed; no authority granted")
        record: dict[str, Any] = {
            "digest": resolved,
            "approved_at": time.time() if now is None else now,
            "approved_by": approved_by,
            "risk_acknowledged": acknowledge_bounded_risk,
        }
        # Validate timestamps/labels through the public immutable admission type.
        Admission(
            identifier,
            resolved,
            record["approved_by"],
            record["approved_at"],
            record["risk_acknowledged"],
        )
        previous = records.get(identifier)
        records[identifier] = record
        root.write(
            "admissions.json", {"schema_version": 1, "strategy": STRATEGY, "profiles": records}
        )
        return {
            "schema_version": 1,
            "profile": identifier,
            "previous": previous,
            "admitted": record,
            "resolved": {
                "profile": next(
                    item for item in to_dict(config)["profiles"] if item["id"] == identifier
                ),
                "scope": asdict(config.scope(profile.scope)),
                "service": asdict(config.service(profile.service)),
                "strategy": STRATEGY,
                "implementation_sha256": implementation_digest(),
                "backend_sha256": installation.backend_sha256,
                "observer_sha256": digest(dict(installation.observer)),
            },
        }


def launchd_job(installation: Installation, root_directory: Path, interpreter: Path) -> bytes:
    """Root daemon pulls fixed protected files; no socket, Mach service or grant."""
    if not root_directory.is_absolute() or not interpreter.is_absolute():
        raise PFError("launchd executable and state paths must be absolute")
    return plistlib.dumps(
        {
            "Label": f"org.netorch.pf.{installation.owner}",
            "ProgramArguments": [
                str(interpreter),
                "-I",
                "-m",
                "netorch.pf_owner",
                "reconcile",
                "--root-dir",
                str(root_directory),
            ],
            "RunAtLoad": True,
            "StartInterval": installation.interval_seconds,
            "ProcessType": "Background",
            "StandardOutPath": str(root_directory / "scheduler.log"),
            "StandardErrorPath": str(root_directory / "scheduler-error.log"),
            "Umask": 0o077,
        },
        sort_keys=True,
    )


def _runtime_observer(config: Config, raw: Mapping[str, Any]) -> Snapshot:
    # Import only at the live boundary. The root-protected settings object is
    # validated again by the shipped runtime observer, never supplied by user RPC.
    from .apple_runtime import observe_runtime
    from .observer_child import read_operation
    from .runtime_settings import RuntimeSettings

    settings = RuntimeSettings.from_dict(dict(raw))
    protected_native_code(
        (
            Path(settings.executable),
            *(Path(network.helper_executable) for network in settings.networks),
            Path(__file__).with_name("observer_child.py"),
        )
    )

    def observer_runner(arguments: list[str], **kwargs: Any) -> Result:
        if arguments[0] != settings.executable:
            return run(arguments, **kwargs)
        if (
            kwargs.pop("run_uid", None) != settings.account.uid
            or kwargs.pop("run_gid", None) != settings.account.gid
            or kwargs.pop("account_home", None) != settings.account.home
            or not read_operation(arguments[1:])
        ):
            raise PFError("independent observer requested an unauthorized native operation")
        return run(
            [
                "/bin/launchctl",
                "asuser",
                str(settings.account.uid),
                sys.executable,
                "-I",
                "-S",
                str(Path(__file__).with_name("observer_child.py")),
                str(settings.account.uid),
                str(settings.account.gid),
                settings.account.home,
                settings.executable,
                *arguments[1:],
            ],
            **kwargs,
        )

    return observe_runtime(config, settings, observer_runner)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Independently scheduled administrator-owned Darwin PF service"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("reconcile", "status", "pause", "resume", "acknowledge-journal", "withdraw"):
        command = commands.add_parser(name)
        command.add_argument("--root-dir", required=True, type=Path)
        if name == "withdraw":
            command.add_argument("--operation")
            command.add_argument("--holder")
    for name in ("suspend", "release"):
        command = commands.add_parser(name)
        command.add_argument("--root-dir", required=True, type=Path)
        command.add_argument("--operation", required=True)
        command.add_argument("--holder", required=True)
    command = commands.add_parser("install")
    command.add_argument("--root-dir", required=True, type=Path)
    command.add_argument("--policy", required=True, type=Path)
    command.add_argument("--settings", required=True, type=Path)
    command.add_argument("--backend", required=True, type=Path)
    command = commands.add_parser("review-admission")
    command.add_argument("--root-dir", required=True, type=Path)
    command.add_argument("--profile", required=True)
    command = commands.add_parser("admit")
    command.add_argument("--root-dir", required=True, type=Path)
    command.add_argument("--profile", required=True)
    command.add_argument("--expected-digest", required=True)
    command.add_argument("--acknowledge-bounded-risk", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command in {
            "reconcile",
            "install",
            "admit",
            "resume",
            "release",
            "acknowledge-journal",
        }:
            require_mutation_qualified("privileged-owner-mutation")
        if sys.platform != "darwin" or os.geteuid() != 0:
            raise PFError("live privileged owner requires a local macOS administrator")
        protected_code(Path(sys.executable), Path(__file__))
        if args.command == "install":
            result = install(args.root_dir, args.policy, args.settings, args.backend)
        else:
            protected_ancestors(args.root_dir)
            root = Store(args.root_dir)
            if args.command == "reconcile":
                result = reconcile(root, _runtime_observer, ShellBackend)
            elif args.command == "withdraw":
                result = withdraw(root, ShellBackend, operation=args.operation, holder=args.holder)
            elif args.command == "admit":
                result = admit(
                    root,
                    args.profile,
                    expected_digest=args.expected_digest,
                    acknowledge_bounded_risk=args.acknowledge_bounded_risk,
                )
            elif args.command == "review-admission":
                with root.lock():
                    installation = Installation.from_dict(root.read("installation.json"))
                    config = parse_config(canonical_bytes(root.read("policy.json")))
                    profile = config.profile(args.profile)
                    if config.profile_owner(profile).id != installation.owner:
                        raise PFError("profile is outside installed owner")
                    result = {
                        "profile": asdict(profile),
                        "scope": asdict(config.scope(profile.scope)),
                        "service": asdict(config.service(profile.service)),
                        "strategy": STRATEGY,
                        "implementation_sha256": implementation_digest(),
                        "expected_digest": admitted_digest(config, profile, installation),
                        "previous": _read_admissions(root.read("admissions.json")).get(profile.id),
                        "risk_acknowledgement_required": profile.safety.kind == "bounded",
                    }
            elif args.command == "status":
                result = {
                    "schema_version": 1,
                    "installation": {
                        key: value
                        for key, value in root.read("installation.json").items()
                        if key != "observer"
                    },
                    "journal": root.read("journal.json"),
                    "intent": root.read("operator-intent.json"),
                }
            elif args.command == "acknowledge-journal":
                with root.lock():
                    journal = root.read("journal.json")
                    if journal.get("phase") != "failed":
                        raise PFError("only a failed journal may be acknowledged")
                    journal["phase"] = "acknowledged"
                    root.write("journal.json", journal)
                    result = {
                        "schema_version": 1,
                        "acknowledged": True,
                        "operator_pause_preserved": True,
                    }
            else:
                with root.lock():
                    intent = intent_from_dict(root.read("operator-intent.json"))
                    if args.command == "pause":
                        intent = intent.pause()
                    elif args.command == "resume":
                        intent = intent.resume()
                    elif args.command == "suspend":
                        intent = intent.suspend(args.operation, args.holder)
                    else:
                        intent = intent.release(args.operation, args.holder)
                    root.write("operator-intent.json", intent_to_dict(intent))
                    result = intent_to_dict(intent)
        if (
            args.command != "reconcile"
            or result.get("changed")
            or result.get("phase") != "committed"
        ):
            print(canonical_bytes(result).decode("utf-8"))
        return 0
    except StageNotQualified as exc:
        print(canonical_bytes(exc.to_dict()).decode("utf-8"), file=sys.stderr)
        return NOT_QUALIFIED
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        # Operational stderr never exposes addresses, credentials or raw tools.
        print(
            canonical_bytes(
                {
                    "schema_version": 1,
                    "error": type(exc).__name__,
                    "reason": "independent owner operation failed; inspect protected journal",
                }
            ).decode("utf-8"),
            file=sys.stderr,
        )
        return 75 if type(exc).__name__ == "Busy" else 65


if __name__ == "__main__":
    raise SystemExit(main())

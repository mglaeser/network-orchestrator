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
from dataclasses import asdict, dataclass, replace
from functools import lru_cache
from importlib.metadata import version
from pathlib import Path
from typing import Any, Protocol

# The runtime reader is imported at the live boundary, after protected_code() has
# listed the imported files. Its volume provider is the one part that loads code
# from outside this package (ctypes), so it is imported here and listed as well.
from . import darwin_volume  # noqa: F401
from .codec import MAX_JSON_BYTES, canonical_bytes, digest, strict_loads
from .config import parse_config, profile_digest, profile_view, to_dict
from .model import Config, Profile, Scope
from .planner import Action, plan
from .process import Result, run
from .state import (
    Admission,
    Intent,
    Observation,
    Snapshot,
    attribute_holds,
    intent_from_dict,
    intent_to_dict,
    snapshot_to_dict,
)
from .storage import Store, UnsafeState
from .workflow_gate import NOT_QUALIFIED, StageNotQualified, require_mutation_qualified

STRATEGY = "darwin-pf-v1"
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
# One component directly below the platform namespace: the product's own form, as
# before, or a site's pinned name. The kernel refuses a component of 64 characters
# or more, so a pinned name has at most 63. The backend script checks the same.
_ANCHOR = re.compile(r"com\.apple/(?:netorch\.[a-z][a-z0-9-]{0,62}|[a-z][a-z0-9.-]{0,62})\Z")
# A sibling of the owned anchor is somebody else's anchor. Its name is read from
# a listing and is only ever given to two read-only listings: one component
# directly below the same parent, of letters, digits, `_`, `.` and `-`, at most
# 63 characters. The backend script checks the same before the tool sees it.
_SIBLING = re.compile(r"com\.apple/[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\Z")
# The kernel prints its boot session with uuid_unparse_upper: one upper-case UUID.
_BOOT_SESSION = re.compile(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\Z")
_REASON = "unobserved"
# Why a pass left one profile to the next pass: a precondition that was not met
# before anything was written for it. A write in doubt is never one of these.
DEFERRAL_REASONS = frozenset(
    {
        "inhibited",
        "not-admitted",
        "evidence-unavailable",
        "target-changed",
        "endpoint-unverified",
        "ports-unverified",
        "states-retained",
        "translation-order-unverified",
    }
)
# Why a pass does not report a loaded rule pair ready although it leaves its
# rules loaded: something its use rests on was not verified by that pass, and
# the lack of it cannot expose anything. A withheld pair is not a deferred
# profile: a deferred profile has no rule loaded.
WITHHOLDING_REASONS = frozenset({"translation-order-unverified"})
# 2**53 - 1: every JSON reader of the published report represents it exactly.
_MAX_GATE_REVISION = 9007199254740991
# The backend script's own exit status for a listing that ended with status 0
# and a line on standard error that is not a known notice. A listing that failed
# has status 1, like every other failure of the script.
_LISTING_NOTICE_STATUS = 76
# The operations of the script that read such a listing.
_LISTING_OPERATIONS = frozenset(
    {
        "inspect",
        "replace",
        "states",
        "enabled",
        "references",
        "translation-hooks",
        "siblings",
        "sibling",
    }
)
# What the owner records for it wherever it records a read that failed.
LISTING_NOTICE = "listing-notice"
# The translation hooks of the main ruleset in the one order that is accepted:
# the hook of the namespace every owned anchor lives below, then the vendor's
# sharing hook where it exists, for outbound translation and again for
# redirection. Translation rules are first match across these hooks, so a
# vendor hook that is evaluated first translates a guest's packet before the
# owned rule sees it. The forms are the ones an existing site's own helper
# requires and has run against; no published source gives them.
_TRANSLATION_HOOKS = (
    ("nat-anchor", "com.apple/*", True),
    ("nat-anchor", "com.apple.internet-sharing", False),
    ("rdr-anchor", "com.apple/*", True),
    ("rdr-anchor", "com.apple.internet-sharing", False),
)
# More children of the parent anchor than this are not read one by one.
_MAX_SIBLINGS = 64
# The bound of one whole translation-order check, in seconds, beside the bound
# of each backend call. A check makes at most 2 + _MAX_SIBLINGS calls: the
# hooks, the children and one per sibling. A call that answers is a shell start
# and one or two listings; eight seconds leave each of 66 calls about 120 ms,
# and they are two of the bounds of a single call, so one slow answer does not
# use them up. When the bound is used up the check has not passed.
_TRANSLATION_CHECK_SECONDS = 8.0


class PFError(RuntimeError):
    """A complete independently verified pass could not be performed."""


class PFListingNotice(PFError):
    """A listing ended with status 0 and a line that is not a known notice.

    Nothing was read, so everything that follows is what follows a listing that
    failed. Only which backend operation was refused and how many unexpected
    lines the script counted are kept: the lines are the tool's text and never
    leave the script.
    """

    def __init__(self, operation: str, unexpected_lines: int | None) -> None:
        super().__init__("a PF listing carried an unexpected notice; nothing was read")
        self.operation = operation
        self.unexpected_lines = unexpected_lines


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
    # What a pass does when it reads its PF enable reference back as not held.
    # "verify": withhold readiness and acquire nothing, as before.
    enable_reference: str = "verify"
    # What a pass does with its remembered records after a proven reboot.
    # "administrator": nothing by itself while a record is active, as before.
    cold_start: str = "administrator"
    # What must hold in the main ruleset for a rule pair with an outbound
    # translation. "present": the two parent hooks exist, as before.
    translation_order: str = "present"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.owner, str)
            or not isinstance(self.anchor, str)
            or not _ID.fullmatch(self.owner)
            or not _ANCHOR.fullmatch(self.anchor)
            # The product form still names this installation's own owner, so a
            # pin cannot claim another owner's anchor of that form.
            or (
                self.anchor.startswith("com.apple/netorch.")
                and self.anchor != f"com.apple/netorch.{self.owner}"
            )
        ):
            raise PFError("invalid independent PF owner identity")
        if not isinstance(self.backend_sha256, str) or not _HASH.fullmatch(self.backend_sha256):
            raise PFError("invalid installed backend digest")
        if type(self.interval_seconds) is not int or not 1 <= self.interval_seconds <= 60:
            raise PFError("invalid reconciliation interval")
        if type(self.allow_apple_dns_coexistence) is not bool:
            raise PFError("invalid coexistence admission")
        if not isinstance(self.enable_reference, str) or self.enable_reference not in {
            "verify",
            "reacquire",
        }:
            raise PFError("invalid enable-reference decision")
        if not isinstance(self.cold_start, str) or self.cold_start not in {
            "administrator",
            "self-heal",
        }:
            raise PFError("invalid cold-start decision")
        if not isinstance(self.translation_order, str) or self.translation_order not in {
            "present",
            "verified",
        }:
            raise PFError("invalid translation-order decision")
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
            or set(raw) - {"enable_reference", "cold_start", "translation_order"} != required
            or type(raw["schema_version"]) is not int
            or raw["schema_version"] != 1
            # One spelling per decision: a key exists only for the choice that
            # is not the default, so the default values and null are not input.
            or ("enable_reference" in raw and raw["enable_reference"] != "reacquire")
            or ("cold_start" in raw and raw["cold_start"] != "self-heal")
            or ("translation_order" in raw and raw["translation_order"] != "verified")
        ):
            raise PFError("unsupported installation schema")
        return cls(**{key: value for key, value in raw.items() if key != "schema_version"})

    def to_dict(self) -> dict[str, Any]:
        value = {"schema_version": 1, **asdict(self)}
        if self.enable_reference == "verify":
            # Left out while it is the default: an installation that never made
            # the decision keeps the bytes it was stored with.
            del value["enable_reference"]
        if self.cold_start == "administrator":
            # Left out while it is the default: an installation that never made
            # the decision keeps the bytes it was stored with.
            del value["cold_start"]
        if self.translation_order == "present":
            # Left out while it is the default: an installation that never made
            # the decision keeps the bytes it was stored with.
            del value["translation_order"]
        return value


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
            # No input while it is the default, so earlier digests stay valid.
            # Choosing it voids every admission of this owner.
            **(
                {}
                if installation.enable_reference == "verify"
                else {"enable_reference": installation.enable_reference}
            ),
            **(
                {}
                if installation.cold_start == "administrator"
                else {"cold_start": installation.cold_start}
            ),
            **(
                {}
                if installation.translation_order == "present"
                else {"translation_order": installation.translation_order}
            ),
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
    if profile.source_scope != "lan":
        # Do not rely on validation here. Only a structural rule whose translation
        # target is the host's own address may match every source: never a guest
        # address, a fallback in effect or the UDP return pair.
        if (
            profile.source_scope != "any"
            or profile.kind != "host-redirect"
            or profile.safety.kind != "structural"
            or effective_strategy is not None
            or target != scope.host_ipv4
        ):
            raise PFError("an unrestricted source is rendered only for a host redirect")
        source = "any"
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


def _state_endpoint(token: str, *, port_required: bool) -> tuple[str, int | None] | None:
    """Validate one numerical endpoint; return its IPv4 address and port, if any.

    The nonverbose PF printer uses IPv4:port and IPv6[port]. Only a protocol
    other than tcp and udp may leave the suffix out, and a zero port is read
    only as the `[0]` that a macOS state table shows. Translation parentheses
    and the `~` marker are unwrapped by the row parser.
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
    if port is None:
        if port_required:
            raise PFError("missing PF endpoint port")
    elif re.fullmatch(r"[0-9]{1,5}", port) is None or not (
        1 <= int(port) <= 65535 or (family == 6 and port == "0")
    ):
        raise PFError("malformed PF endpoint port")
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise PFError("malformed PF endpoint address") from exc
    if (family is not None and parsed.version != family) or "%" in address:
        raise PFError("unsupported PF endpoint address")
    number = None if port is None else int(port)
    if isinstance(parsed, ipaddress.IPv4Address):
        return str(parsed), number
    # Preserve conservative matching for IPv4-mapped IPv6 observations too.
    return (str(parsed.ipv4_mapped), number) if parsed.ipv4_mapped is not None else None


def _state_status(token: str, protocol: str) -> bool:
    """Whether the token is a complete status tail for the row's protocol.

    The printer names two TCP states or a proxy phase for tcp, two flow levels
    for udp and two numbers for icmp. Every other protocol has two flow levels,
    or two numbers when a level lies outside the three named ones. The kernel
    header names the levels of GRE and ESP differently (NO_TRAFFIC, INITIATING,
    ESTABLISHED), so both sets are read for those two. The IPv6 form of icmp
    is read with numbers, as before, and with flow levels, which the printer
    of this state model writes for every protocol other than IPv4 icmp.
    """
    values = token.split(":")
    if len(values) != 2:
        return False
    numeric = all(
        re.fullmatch(r"[0-9]{1,3}", value) is not None and int(value) <= 255 for value in values
    )
    if protocol == "icmp":
        return numeric
    if protocol in {"icmp6", "ipv6-icmp"} and numeric:
        return True
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
        if protocol in {"gre", "esp"}:
            states |= {"INITIATING", "ESTABLISHED"}
    if all(value in states for value in values):
        return True
    # The printer falls back to numbers only for a level beyond the three
    # named ones. The tcp and udp tails are read as before, by name only.
    return protocol not in {"tcp", "udp"} and numeric and max(map(int, values)) >= 3


@dataclass(frozen=True, slots=True)
class StateRow:
    """One validated state row: its text, its protocol and its IPv4 endpoints.

    `endpoints` holds, in printed order, the address and the port of every
    endpoint that names an IPv4 address. The port is None where the row prints
    none.
    """

    line: str
    protocol: str
    endpoints: tuple[tuple[str, int | None], ...]


def state_rows(raw: str) -> tuple[StateRow, ...]:
    """Validate complete numerical nonverbose PF rows, never empty-on-error.

    A row is `interface protocol endpoints status`. The kernel's state has a
    lan, a gwy and an ext host, and the printer of that model writes
    `gwy ARROW ext`, or `lan ARROW gwy ARROW ext` for a translated state: one
    or two arrows of one direction. One endpoint may carry the `~` marker that
    a macOS state table shows. The display with a single arrow and a translated
    endpoint in parentheses on either side is still read; it never mixes with a
    second arrow or with the marker.

    Every endpoint of a row is checked before any IPv4 target is extracted,
    and every IPv4 address the row names is returned with its port, whatever
    its position.
    IPv6-only rows require valid IPv6 addresses, not merely a colon somewhere
    in the output. New printer formats remain unknown until reviewed fixtures
    establish their complete grammar.
    """
    result: list[StateRow] = []
    # Only a line feed ends a row. A form feed, a vertical tab or a Unicode
    # line separator inside the output is refused below, not read as a break.
    for line in raw.split("\n"):
        if not line.strip():
            continue
        if len(line) > 4096 or any(
            (ord(c) < 32 and c != "\t") or c in "\x7f\x85\u2028\u2029" for c in line
        ):
            raise PFError("unsupported PF state observation")
        pieces = line.split()
        if (
            not 6 <= len(pieces) <= 8
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,15}", pieces[0]) is None
            # A name of the protocol database or a number: the row stays
            # opaque, but its endpoints and status tail are still complete.
            or re.fullmatch(r"[a-z0-9][a-z0-9+./-]{0,31}", pieces[1]) is None
            or not _state_status(pieces[-1], pieces[1])
        ):
            raise PFError("unsupported PF state observation")
        body = pieces[2:-1]
        arrows = [token for token in body if token in {"->", "<-"}]
        if len(arrows) not in {1, 2} or len(set(arrows)) != 1:
            raise PFError("unsupported PF state direction")
        sides: list[list[str]] = [[]]
        for token in body:
            if token in arrows:
                sides.append([])
            else:
                sides[-1].append(token)
        # A second arrow already separates the translated endpoint, so only a
        # one-arrow row may add a parenthesised endpoint to a side.
        limit = 2 if len(arrows) == 1 else 1
        endpoints: list[str] = []
        for side in sides:
            if not 1 <= len(side) <= limit:
                raise PFError("incomplete PF state endpoints")
            endpoints.append(side[0])
            if len(side) == 2:
                if not side[1].startswith("(") or not side[1].endswith(")"):
                    raise PFError("malformed PF translated endpoint")
                endpoints.append(side[1][1:-1])
        # One endpoint may carry the marker, and none beside parentheses. It
        # belongs to the display and is never part of an address.
        marked = sum(token.startswith("~") for token in endpoints)
        if marked > 1 or (marked and len(endpoints) != len(sides)):
            raise PFError("malformed PF endpoint marker")
        named: list[tuple[str, int | None]] = []
        for token in endpoints:
            endpoint = _state_endpoint(
                token.removeprefix("~"), port_required=pieces[1] in {"tcp", "udp"}
            )
            if endpoint is not None:
                named.append(endpoint)
        result.append(StateRow(line, pieces[1], tuple(named)))
    return tuple(result)


def state_addresses(raw: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Each validated row with every IPv4 address it names, whatever its position.

    A view of `state_rows`: the same parse, without protocols and ports.
    """
    return tuple(
        (row.line, tuple(address for address, _ in row.endpoints)) for row in state_rows(raw)
    )


# The printer writes a protocol's number when the protocol database has no
# name for it. A profile names tcp or udp only.
_PROTOCOL_NUMBER = {"tcp": "6", "udp": "17"}


def retained_states(
    config: Config | None,
    key: str,
    target: str,
    record: Mapping[str, Any] | None,
    rows: tuple[StateRow, ...],
) -> bool:
    """Whether a state remains that the rules of one record can have created.

    A rendered rule matches one protocol and a peer inside the scope's LAN
    prefix, and translates to the target with a port of the profile. The
    kernel keeps the target with that port and the peer as hosts of a state
    made under such a rule. A row is therefore a state of the record when it
    has the profile's protocol, names the target with a port inside the
    profile's target ports at one endpoint, and names at another endpoint an
    address of the LAN prefix that is neither the target nor the host's own
    address. These properties decide which endpoint is which; its position in
    the row does not. A guest's own connections lack one of them.

    When the installed policy no longer describes the record (no policy, no
    record, the profile is gone, or its digest or kind differs), the rule that
    was loaded is not known any more and every row that names the target
    counts.

    The host endpoint's port is not consulted: two profiles that publish
    different host ports onto one target port of one guest are not told apart.
    The caller excludes a host redirect, whose target is the host itself.
    """
    if config is not None and record is not None:
        profile = next((item for item in config.profiles if item.id == key), None)
        if (
            profile is not None
            and record["kind"] == profile.kind
            and record["policy_digest"] == profile_digest(config, profile)
        ):
            scope = config.scope(profile.scope)
            lan = ipaddress.IPv4Network(scope.lan_cidr)
            ports = profile.target_ports or profile.ports
            protocols = {profile.protocol, _PROTOCOL_NUMBER.get(profile.protocol)}
            return any(
                row.protocol in protocols
                and any(
                    address == target and port is not None and ports.first <= port <= ports.last
                    for address, port in row.endpoints
                )
                and any(
                    address not in {target, scope.host_ipv4}
                    and ipaddress.IPv4Address(address) in lan
                    for address, _ in row.endpoints
                )
                for row in rows
            )
    return any(address == target for row in rows for address, _ in row.endpoints)


class Backend(Protocol):
    def inspect(self) -> str: ...
    def normalize(self, rules: str) -> str: ...
    def replace(self, expected: str, candidate: str) -> str: ...
    def states(self) -> str: ...
    # Issues the scoped invalidations only; the caller reads the table back.
    def drain(self, ipv4: str) -> None: ...
    def ensure_reference(self) -> None: ...
    def reference_held(self) -> bool: ...
    def endpoint(self, scope: Scope, ipv4: str, mac: str | None, *, direct: bool) -> bool: ...
    def ports_clear(self, scope: Scope, profile: Profile, *, apple_dns: bool) -> bool: ...
    def boot_session(self) -> str: ...
    # Read-only listings for the translation-order check. None of them is
    # called unless the installation chose that check.
    def translation_hooks(self) -> str: ...
    def sibling_anchors(self) -> str: ...
    def sibling(self, anchor: str) -> str: ...


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
        return self._printed(operation, *arguments).strip()

    def _printed(self, operation: str, *arguments: str) -> str:
        """What the operation printed, untrimmed: for a listing that is read line by line."""
        result = run(
            ["/bin/bash", str(self.script), operation, self.installation.anchor, *arguments],
            timeout=4.0,
        )
        if result.returncode == _LISTING_NOTICE_STATUS and operation in _LISTING_OPERATIONS:
            # Beside that status the script writes one number to its standard
            # error. Anything else there is not a count and is not read.
            counted = re.fullmatch(rb"([1-9][0-9]{0,5})\n", result.stderr)
            raise PFListingNotice(operation, None if counted is None else int(counted[1]))
        if result.returncode != 0:
            raise PFError("bounded PF backend operation failed")
        return result.stdout.decode("utf-8", errors="strict")

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
        # The two scoped invalidations, from and to the address, and nothing
        # else. Whether a state of a record remains is read back by the caller
        # with `retained_states`.
        self._call("drain", str(ipaddress.IPv4Address(ipv4)))

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

    def translation_hooks(self) -> str:
        """The translation listing of the main ruleset, as the tool prints it."""
        return self._call("translation-hooks")

    def sibling_anchors(self) -> str:
        """The children of the anchor that the owned anchor lives below, as the tool prints them.

        Untrimmed: a name is taken from its line exactly as it was printed.
        """
        return self._printed("siblings")

    def sibling(self, anchor: str) -> str:
        """The translations and the children of one sibling anchor; empty when it has none.

        The name comes from a listing. Its form is checked here and again by the
        script before the tool is given it, and the owned anchor is not a sibling.
        """
        if (
            not isinstance(anchor, str)
            or _SIBLING.fullmatch(anchor) is None
            or anchor == self.installation.anchor
        ):
            raise PFError("sibling anchor has no accepted form")
        return self._call("sibling", anchor)

    def reference_held(self) -> bool:
        """Read only: the kernel lists this owner's saved token and PF is enabled.

        Uses the backend's two existing reads, `references` and `enabled`. It
        never acquires or releases a reference; `ensure_reference` alone
        acquires one, at an activation or where the installation chose
        `reacquire`. It raises when a read fails or does not show PF enabled.
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

    def boot_session(self) -> str:
        """The identifier the kernel generated for this boot.

        `kern.bootsessionuuid` is a read-only string that the kernel fills once
        per boot and that the clock does not move. Exactly one upper-case UUID
        is a read; a failed, empty, repeated or differently spelled answer is
        not, and the caller then knows nothing about the boot.
        """
        answer = self._native(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"])
        session = answer.removesuffix("\n")
        if _BOOT_SESSION.fullmatch(session) is None:
            raise PFError("boot session observation is unknown")
        return session

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


def _gate(installation: Installation) -> Intent | None:
    """The user-side file as root reads it: one pinned file, strictly parsed, or damaged."""
    if installation.intent_path is None:
        return None
    try:
        # A user-supplied gate can only remove already admitted root authority.
        return intent_from_dict(strict_loads(read_once(Path(installation.intent_path), mode=0o600)))
    except (OSError, ValueError, UnsafeState):
        return Intent(damaged=True)


def _merged(root: Store, external: Intent | None) -> Intent:
    """Root's own intent with the user-side gate added: a union, the gate clears nothing."""
    try:
        own = intent_from_dict(root.read("operator-intent.json"))
    except (OSError, ValueError, UnsafeState):
        own = Intent(damaged=True)
    if external is None:
        return own
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
        # The same union per service: root's own records stay and the user's are
        # added under hashed operation names, which are never interpreted.
        holds={
            service: {
                **own.holds.get(service, {}),
                **{
                    f"external:{hashlib.sha256(key.encode()).hexdigest()}": holder
                    for key, holder in external.holds.get(service, {}).items()
                },
            }
            for service in {*own.holds, *external.holds}
        },
    )


def _inhibition(root: Store, installation: Installation) -> Intent:
    return _merged(root, _gate(installation))


def _attributed(config: Config, intent: Intent) -> Intent:
    """A held service that root's own policy does not name is damage for this pass."""
    return attribute_holds(intent, {service.id for service in config.services})


def _installed_policy(root: Store) -> Config | None:
    """The installed policy for `retained_states`, or None when it cannot be read.

    Without it no retired rule is described, so every state of a target counts.
    """
    try:
        return parse_config(canonical_bytes(root.read("policy.json")))
    except (OSError, RuntimeError, ValueError):
        return None


def _own_states_gone(
    backend: Backend,
    config: Config | None,
    key: str,
    target: str,
    record: Mapping[str, Any] | None,
) -> bool:
    """Invalidate the states of a retired record if one remains; read back that none does.

    The scoped invalidation is issued only while the state table shows such a
    state. Both reads go through the validated reader, so a table that cannot
    be read raises here and is never taken for an empty one.
    """
    if not retained_states(config, key, target, record, state_rows(backend.states())):
        return True
    backend.drain(target)
    return not retained_states(config, key, target, record, state_rows(backend.states()))


def _snapshot(
    config: Config,
    runtime: Snapshot,
    records: Mapping[str, Mapping[str, Any]],
    backend: Backend,
    now: float,
    owner: str,
) -> Snapshot:
    states = state_rows(backend.states())
    profiles = dict(runtime.profiles)
    for profile in config.profiles:
        if config.profile_owner(profile).id != owner:
            continue
        record = records.get(profile.id)
        data: dict[str, Any] = {"states": ()}
        if record is not None:
            target = record["target_ipv4"]
            # Only the fact that states of this record's own rules remain is
            # evidence for planning. Raw kernel rows name a guest's remote
            # peers and the clients on the LAN: they stay out of the snapshot
            # that is hashed for the plan and out of the world-readable
            # report, and they cannot grow either one beyond its
            # serialization bound.
            matching = (
                ()
                if record["kind"] == "host-redirect"
                or not retained_states(config, profile.id, target, record, states)
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


def _stopped_before_any_write(journal: Mapping[str, Any]) -> bool:
    """Whether an unfinished journal is exactly the record made before any write.

    Every pass records phase ``applying`` with its planned actions before it
    knows whether it will change anything, and journals the exact candidate
    immediately before each change. A journal that still has only that first
    shape means the process stopped before a candidate existed: no rule was
    being written, so there is nothing to retire and nothing to acknowledge.
    Every other unfinished shape remains an interrupted write. The record may
    name the boot session it was written in, as every record of a pass does.
    """
    return (
        journal["phase"] == "applying"
        and set(journal) - {"boot_session"} == {"schema_version", "phase", "actions", "started_at"}
        and ("boot_session" not in journal or _journal_session(journal) is not None)
    )


def _boot_session(backend: Backend) -> str | None:
    """This boot's kernel session, or None when it could not be read.

    A failed read stops nothing and proves nothing: the pass goes on as it
    always did, its journal records name no boot, and no later pass can take
    such a record for evidence of a reboot.
    """
    try:
        session = backend.boot_session()
    except (OSError, RuntimeError, ValueError):
        return None
    if not isinstance(session, str) or _BOOT_SESSION.fullmatch(session) is None:
        return None
    return session


def _journal_session(journal: Any) -> str | None:
    """The boot session a journal record says it was written in, if it says so."""
    if not isinstance(journal, dict):
        return None
    session = journal.get("boot_session")
    if not isinstance(session, str) or _BOOT_SESSION.fullmatch(session) is None:
        return None
    return session


def _another_boot(journal: Any, session: str | None) -> bool:
    """Whether the last journal record provably belongs to another boot than this one.

    Both sessions must be known. A record without one (an earlier release, or a
    pass whose read failed) never proves a reboot, and neither does a boot whose
    own session cannot be read.
    """
    recorded = _journal_session(journal)
    return session is not None and recorded is not None and recorded != session


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


def _reference_held(
    backend: Backend, records: Mapping[str, Mapping[str, Any]]
) -> tuple[bool | None, bool]:
    """Whether loaded rules can count on PF being enabled under this owner's reference.

    A loaded rule carries nothing while PF is disabled, and only the owner's own
    reference keeps PF enabled when another service releases its own. Without an
    active record there is no rule to carry anything and nothing to verify. A
    read that fails, or that does not list the reference, is not a verification.
    The two are told apart: False is a complete read that does not list the
    reference; None is a read that failed, after which nothing is known.

    The second value says whether that read was refused for an unexpected
    notice of the tool, which the caller records as the reason.
    """
    if not any(record["active"] for record in records.values()):
        return True, False
    try:
        held = backend.reference_held()
    except (OSError, RuntimeError, ValueError) as unread:
        return None, isinstance(unread, PFListingNotice)
    return (held if isinstance(held, bool) else None), False


def _translates_outbound(rules: str) -> bool:
    """Whether rendered rules hold an outbound translation: the UDP return pair does."""
    return any(line.startswith("nat ") for line in rules.splitlines())


def translation_hooks_in_order(listing: Any) -> bool:
    """Whether the main ruleset's translation listing is exactly the accepted hooks in order.

    Each line is one of the four hook forms, with or without the trailing
    ` all` the printer may add; the two parent hooks are required, the two
    sharing hooks may be absent; every line appears at most once and in the
    fixed order. Any other line, order or repetition is not verified. Empty
    lines are not hooks.
    """
    if not isinstance(listing, str):
        return False
    position = 0
    for line in listing.split("\n"):
        if not line:
            continue
        # Every hook up to the one this line names is passed; a required hook
        # that is passed over is missing or comes later than it may.
        while True:
            if position == len(_TRANSLATION_HOOKS):
                return False
            kind, anchor, required = _TRANSLATION_HOOKS[position]
            position += 1
            if line in (f'{kind} "{anchor}"', f'{kind} "{anchor}" all'):
                break
            if required:
                return False
    return not any(required for _, _, required in _TRANSLATION_HOOKS[position:])


def _listed_children(listing: Any) -> list[str] | None:
    """The names in a listing of an anchor's children, or None when it is not such a listing.

    A name is taken as the printer prints it. The printer of this lineage
    writes each child as two spaces, its full path and a line feed (FreeBSD
    8.4.0 `contrib/pf/pfctl/pfctl.c`, `pfctl_show_anchors`, lines 1949-1950).
    Only that indentation is removed, and what remains must be a sibling's name
    exactly: a line with any other white space, an empty line or any other
    form makes the whole listing unusable, before a name of it is handed on.
    """
    if not isinstance(listing, str):
        return None
    lines = listing.split("\n")
    if lines[-1] == "":
        # The line feed that ends the last line.
        lines.pop()
    names: list[str] = []
    for line in lines:
        if not line.startswith("  ") or _SIBLING.fullmatch(line[2:]) is None:
            return None
        names.append(line[2:])
    return names


def _translation_order_verified(
    backend: Backend, anchor: str, *, clock: Callable[[], float] = time.monotonic
) -> tuple[bool, PFListingNotice | None]:
    """Whether nothing can translate a guest's packet before the owned rule does.

    Two facts, each from a fresh read: the hooks of the main ruleset are the
    accepted ones in order, and no sibling of the owned anchor holds a
    translation rule or a child. The siblings are the children of the parent
    anchor; there may be at most 64, each named once in the form of a sibling,
    and every one but the owned anchor is read by itself. A listing that cannot
    be read, or anything outside these bounds, is not verified.

    The whole check has a bound of its own beside the bound of each call. No
    call starts once it is used up, and a check that ends after it has not
    passed, so a check takes at most that bound and the bound of one call.

    The second value is the notice when a read was refused for an unexpected
    notice of the tool: the caller records the reason and passes on which
    listing it was.
    """
    deadline = clock() + _TRANSLATION_CHECK_SECONDS
    try:
        if clock() >= deadline or not translation_hooks_in_order(backend.translation_hooks()):
            return False, None
        if clock() >= deadline:
            return False, None
        names = _listed_children(backend.sibling_anchors())
        if names is None or len(names) > _MAX_SIBLINGS or len(set(names)) != len(names):
            return False, None
        for name in names:
            if name == anchor:
                continue
            if clock() >= deadline or backend.sibling(name) != "":
                return False, None
    except (OSError, RuntimeError, ValueError) as unread:
        return False, unread if isinstance(unread, PFListingNotice) else None
    return clock() < deadline, None


def _deferrals(deferred: Mapping[str, str]) -> dict[str, str]:
    """A pass's deferred profiles with their reasons, in one order; the vocabulary is closed."""
    if not DEFERRAL_REASONS.issuperset(deferred.values()):
        raise PFError("unknown deferral reason")
    return dict(sorted(deferred.items()))


def _withholdings(withheld: Mapping[str, str]) -> dict[str, str]:
    """A pass's withheld pairs with their reasons, in one order; the vocabulary is closed."""
    if not WITHHOLDING_REASONS.issuperset(withheld.values()):
        raise PFError("unknown withholding reason")
    return dict(sorted(withheld.items()))


def _refused_listing(notice: PFListingNotice) -> dict[str, Any]:
    """Which listing was refused for a notice and how many lines the script counted.

    Closed words and a number, never the tool's text: what a command writes to
    standard error when such a read ends it, and what a pass hands back when it
    absorbed one in the translation-order check.
    """
    refused: dict[str, Any] = {"operation": notice.operation}
    if notice.unexpected_lines is not None:
        refused["unexpected_lines"] = notice.unexpected_lines
    return refused


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
        # Every journal record of this pass names the boot it was written in,
        # when that is known, and carries no such key when it is not.
        session = _boot_session(backend)
        boot = {} if session is None else {"boot_session": session}
        intent = _inhibition(root, installation)
        try:
            journal = root.read("journal.json")
        except FileNotFoundError:
            journal = None
        needs_ack = False
        cold = False
        if journal is not None:
            if not isinstance(journal, dict) or journal.get("phase") not in {
                "committed",
                "inhibited",
                "failed",
                "applying",
                "acknowledged",
            }:
                raise PFError("PF journal is damaged")
            # A cold start: the last journal record was written by a kernel that
            # no longer runs, and the owned anchor is verifiably empty. No rule
            # and no state that this owner created exists any more.
            cold = _another_boot(journal, session) and observed_rules == backend.normalize("")
            heal = installation.cold_start == "self-heal"
            if cold and (heal or not any(record["active"] for record in records.values())):
                # The remembered records describe nothing in this kernel. They
                # are dropped, never drained: their addresses may belong to
                # other guests now. With an active record the default leaves the
                # drift below to the administrator; `self-heal` drops it too and
                # goes on as an ordinary pass, which skips no check.
                owed = journal["phase"] == "failed" or (
                    not heal
                    and journal["phase"] == "applying"
                    and not _stopped_before_any_write(journal)
                )
                if records:
                    records = {}
                    root.write("live.json", {"schema_version": 1, "records": records})
                if heal or owed:
                    # Written after the records: this record ends the proof of
                    # the cold start, so nothing may still depend on that proof.
                    # A failure that a pass recorded stays owed across the boot,
                    # in either mode. A pass that the previous boot merely cut
                    # short left nothing behind; without the decision it stays
                    # owed as before. The candidate of the previous boot is not
                    # carried over.
                    journal = {
                        "schema_version": 1,
                        "phase": "failed" if owed else "inhibited",
                        "reason": "cold-start",
                        **boot,
                    }
                    root.write("journal.json", journal)
            if journal["phase"] in {"failed", "applying"} and not _stopped_before_any_write(
                journal
            ):
                needs_ack = True
                candidate_records = journal.get("candidate_records")
                # A candidate of another boot describes nothing in this kernel.
                if candidate_records is not None and not cold:
                    possible = _records({"schema_version": 1, "records": candidate_records})
                    if observed_rules == backend.normalize(compose_rules(possible)):
                        records = possible
                        root.write("live.json", {"schema_version": 1, "records": records})
                # Safely retire known exposure; explicit administrator ack is
                # required before any activation after an interrupted write.
                intent = replace(intent, damaged=True)
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
        except (OSError, RuntimeError, ValueError) as unread:
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
                    # As for the first record of an ordinary pass below.
                    "phase": "failed" if needs_ack else "applying",
                    "candidate_records": retired,
                    "started_at": stamp,
                    **boot,
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
                    # The same outcome either way; the record says which it was.
                    "reason": LISTING_NOTICE
                    if isinstance(unread, PFListingNotice)
                    else "kernel-state-unknown",
                    **boot,
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
            intent = replace(intent, damaged=True)
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
                # This record replaces the journal. A failure that still awaits
                # its acknowledgement stays recorded as failed, so that a process
                # death right after this write cannot pass for a pass that had
                # nothing to answer for.
                "phase": "failed" if needs_ack else "applying",
                "actions": [asdict(action) for action in actions],
                "started_at": stamp,
                **boot,
            },
        )
        changed: list[str] = []
        acquired = False
        deferred: dict[str, str] = {}
        # A read that this pass absorbed, in a deferral or in the check of a
        # loaded pair, was refused for an unexpected notice of the tool. The
        # outcome is that of a read that failed; the final journal record names
        # the notice unless the reference readback established something more
        # specific.
        noticed = False
        # The first read of the translation-order check that was refused for a
        # notice in this pass: its operation and count are handed back with the
        # result, so that the listing can be told from the others.
        order_notice: PFListingNotice | None = None
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
                    # Nothing has been written for this profile in this pass.
                    # A precondition that is not met leaves it without a rule
                    # and defers it to the next pass, which reads everything
                    # again; this pass goes on with its other actions.
                    profile = config.profile(action.profile)
                    if _attributed(config, _inhibition(root, installation)).blocks(profile.service):
                        deferred[action.profile] = "inhibited"
                        continue
                    current_admissions = _effective_admissions(
                        config, installation, root.read("admissions.json")
                    )
                    if action.profile not in current_admissions:
                        deferred[action.profile] = "not-admitted"
                        continue
                    try:
                        fresh = observer(config, installation.observer)
                        fresh_snapshot = _snapshot(
                            config, fresh, records, backend, now(), installation.owner
                        )
                        fresh_intent = _inhibition(root, installation)
                        fresh_plan = plan(config, fresh_snapshot, admissions, fresh_intent, now())
                    except (OSError, RuntimeError, ValueError) as unread:
                        noticed = noticed or isinstance(unread, PFListingNotice)
                        deferred[action.profile] = "evidence-unavailable"
                        continue
                    if action not in fresh_plan.actions:
                        deferred[action.profile] = (
                            "inhibited"
                            if _attributed(config, fresh_intent).blocks(profile.service)
                            else "target-changed"
                        )
                        continue
                    assert action.target_ipv4 is not None and action.target_generation is not None
                    scope = config.scope(profile.scope)
                    service = fresh.services.get(profile.service)
                    mac = None if service is None else service.data.get("mac")
                    try:
                        verified = backend.endpoint(
                            scope,
                            action.target_ipv4,
                            mac if isinstance(mac, str) else None,
                            direct=profile.kind != "host-redirect"
                            and action.effective_strategy != "degraded-fallback",
                        )
                    except (OSError, RuntimeError, ValueError):
                        verified = False
                    if not verified:
                        deferred[action.profile] = "endpoint-unverified"
                        continue
                    try:
                        clear = backend.ports_clear(
                            scope, profile, apple_dns=installation.allow_apple_dns_coexistence
                        )
                    except (OSError, RuntimeError, ValueError):
                        clear = False
                    if not clear:
                        deferred[action.profile] = "ports-unverified"
                        continue
                    if installation.translation_order == "verified" and _translates_outbound(
                        render_profile(
                            config,
                            profile,
                            action.target_ipv4,
                            effective_strategy=action.effective_strategy,
                        )
                    ):
                        # Only for a pair with an outbound translation, and only
                        # where the installation chose it: nothing may translate
                        # the guest's packets before the pair does.
                        ordered, notice = _translation_order_verified(backend, installation.anchor)
                        if notice is not None:
                            noticed = True
                            order_notice = order_notice or notice
                        if not ordered:
                            deferred[action.profile] = "translation-order-unverified"
                            continue
                    # From here on a failure is a write in doubt, not a deferral:
                    # the enable reference and the rule load change the kernel.
                    backend.ensure_reference()
                    acquired = True
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
                        # The rule is retired and was read back. While a state
                        # of it remains, or cannot be read back as gone, the
                        # retired record stays: the plan keeps this profile at
                        # "drain only" and no target is activated for it.
                        try:
                            gone = _own_states_gone(
                                backend, config, action.profile, target, retiring
                            )
                        except (OSError, RuntimeError, ValueError) as unread:
                            noticed = noticed or isinstance(unread, PFListingNotice)
                            gone = False
                        if not gone:
                            deferred[action.profile] = "states-retained"
                            continue
                    update = dict(records)
                    if action.profile in update and not update[action.profile]["active"]:
                        del update[action.profile]
                before = compose_rules(records)
                after = compose_rules(update)
                root.write(
                    "journal.json",
                    {
                        "schema_version": 1,
                        # An acknowledgement that is owed is owed in every
                        # record of the pass, not only in its first and last:
                        # a later boot discharges an unfinished write of the
                        # boot before it, never a recorded failure.
                        "phase": "failed" if needs_ack else "applying",
                        "actions": [asdict(item) for item in actions],
                        "candidate_records": update,
                        "started_at": stamp,
                        **boot,
                    },
                )
                if before != after:
                    backend.replace(before, after)
                    if backend.inspect() != backend.normalize(after):
                        raise PFError("PF write readback did not match candidate")
                records = update
                root.write("live.json", {"schema_version": 1, "records": records})
                changed.append(f"{action.profile}:{action.operation}")
            try:
                final_runtime = observer(config, installation.observer)
            except (OSError, RuntimeError, ValueError):
                # No write is in doubt: every service is unknown, as when the
                # first observation of a pass fails. Nothing can then be
                # verified or reported ready, and the next pass decides from
                # its own observation what to retire.
                unobserved_at = now()
                final_runtime = Snapshot(
                    unobserved_at,
                    None,
                    {
                        service.id: Observation("unknown", "unavailable", unobserved_at, None)
                        for service in config.services
                    },
                    {},
                )
            if backend.inspect() != backend.normalize(compose_rules(records)):
                raise PFError("owned rules changed before final readback")
            final = _snapshot(config, final_runtime, records, backend, now(), installation.owner)
            final_gate = _gate(installation)
            final_intent = _merged(root, final_gate)
            if needs_ack:
                final_intent = replace(final_intent, damaged=True)
            final_intent = _attributed(config, final_intent)
            status = plan(config, final, admissions, final_intent, now())
            verified_profiles = {
                action.profile
                for action in status.actions
                if action.operation == "noop" and action.reason == "verified"
            }
            deferred = _deferrals(deferred)
            # Read on every pass that leaves a rule loaded, not only at an
            # activation: another tool can disable PF at any time, which also
            # drops every enable reference.
            held, refused = _reference_held(backend, records)
            reacquired = False
            if (
                held is False
                and installation.enable_reference == "reacquire"
                and not acquired
                and not needs_ack
                and not final_intent.blocked
                and all(
                    key in verified_profiles for key, record in records.items() if record["active"]
                )
                and not _inhibition(root, installation).blocked
            ):
                # The administrator chose that a reference which a complete read
                # shows as not held is taken again. Taking it enables PF, which
                # puts every loaded rule back into effect, so it needs what an
                # activation needs: no inhibition, nothing owed, and this pass's
                # final fresh evidence still verifying each rule it leaves
                # loaded. A read that failed is no evidence, and a pass that
                # acquired at an activation does not acquire twice. An exception
                # here ends the pass as it does at an activation: a reference may
                # have been taken without being recorded, and trying again on
                # every pass would take another one each time.
                backend.ensure_reference()
                reacquired = True
                held, refused = _reference_held(backend, records)
            reference_verified = held is True
            # Where the installation chose the translation-order check, a pair
            # that is loaded is gated in its readiness only. The check is made
            # once, here, after every action of the pass, so that no withdrawal
            # and no drain waits for its reads. If it does not pass, or cannot
            # be read, each loaded pair is withheld: its rules stay loaded and
            # unchanged, and it is not reported ready. Nothing is withdrawn or
            # invalidated for this reason: an unverified translation order can
            # cost the path, it cannot expose a guest.
            withheld: dict[str, str] = {}
            if installation.translation_order == "verified":
                pairs = [
                    key
                    for key, record in records.items()
                    if record["active"] and _translates_outbound(record["rules"])
                ]
                if pairs:
                    ordered, notice = _translation_order_verified(backend, installation.anchor)
                    if notice is not None:
                        noticed = True
                        order_notice = order_notice or notice
                    if not ordered:
                        withheld = dict.fromkeys(pairs, "translation-order-unverified")
            withheld = _withholdings(withheld)
            phase = (
                "failed"
                if needs_ack
                else (
                    "committed"
                    if reference_verified
                    and not deferred
                    and not withheld
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
                    # One reason per record, and a notice never hides a finding.
                    # The last reference readback decides: refused for a notice,
                    # it is the notice; completed without listing the token, or
                    # failed, it is the unverified reference, as before, whatever
                    # another read of the pass was refused for. With the
                    # reference verified, a pass that absorbed a notice, in a
                    # deferral or in the check of a loaded pair, ends as after a
                    # read that failed, never `committed`, and names it here.
                    **(
                        {"reason": LISTING_NOTICE}
                        if refused or (noticed and reference_verified)
                        else {}
                        if reference_verified
                        else {"reason": "enable-reference-unverified"}
                    ),
                    **({"deferred": deferred} if deferred else {}),
                    **({"withheld": withheld} if withheld else {}),
                    **boot,
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
                    and (
                        (profile.safety.kind != "bounded" and profile.source_scope == "lan")
                        or approval.risk_acknowledged
                    )
                )
                data["admitted"] = valid_approval
                # Approval and truthful kernel exposure are separate facts from
                # current operational readiness. A final pause, suspension,
                # changed target or incomplete verification must not authorize
                # discovery until the next independent pass retires exposure.
                data["root_ready"] = (
                    valid_approval
                    and not final_intent.blocks(profile.service)
                    and key in verified_profiles
                    and reference_verified
                    and key not in deferred
                    and key not in withheld
                )
                data["admission_digest"] = (
                    admitted_digest(config, profile, installation) if valid_approval else None
                )
                data["policy_digest"] = profile_digest(config, config.profile(key))
                if key in deferred:
                    data["deferred"] = deferred[key]
                if key in withheld:
                    data["withheld"] = withheld[key]
                # What a workload manager waits for before a planned stop, without
                # a call into root: this pass ended knowing the hold, by the
                # revision of the file the manager wrote, and the state and the
                # retained states above are the kernel's readback of this pass.
                if profile.service in final_intent.holds:
                    data["held"] = True
                if (
                    final_gate is not None
                    and not final_gate.damaged
                    and final_gate.revision <= _MAX_GATE_REVISION
                ):
                    data["gate_revision"] = final_gate.revision
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
            pending = [
                action.profile
                for action in status.actions
                if action.profile in owned and action.operation in {"pending", "blocked"}
            ]
            pending.extend(key for key in deferred if key not in pending)
            return {
                "schema_version": 1,
                "phase": phase,
                "changed": changed,
                "pending": pending,
                **({"deferred": deferred} if deferred else {}),
                # Reported where a deferral is and in its shape, but apart from
                # it and not among the pending: a withheld pair has its rules.
                **({"withheld": withheld} if withheld else {}),
                # Enabling PF again is never silent: the result says so, and the
                # scheduled job writes such a result to its log.
                **({"reference": "reacquired"} if reacquired else {}),
                # A read of the translation-order check that was refused for a
                # notice did not end the pass, so no error names its listing.
                # The result does, and the entry point writes it to standard
                # error as it does for a refused listing that ends a command.
                **(
                    {"listing_notice": _refused_listing(order_notice)}
                    if order_notice is not None
                    else {}
                ),
            }
        except BaseException as failure:
            failed_journal = root.read("journal.json")
            failed_journal["phase"] = "failed"
            failed_journal["failed_at"] = now()
            if isinstance(failure, PFListingNotice):
                # Failed as for a listing that failed; the record says which.
                failed_journal["reason"] = LISTING_NOTICE
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
        # A verifiably empty anchor holds no rule to retire and no foreign rule
        # either, so it needs no proof of which rules were this owner's.
        empty = live == backend.normalize("")
        session = _boot_session(backend)
        try:
            last = root.read("journal.json")
        except (OSError, RuntimeError, ValueError):
            last = None
        # In another boot than the last journal record, no state that this
        # owner's rules created exists either, and a remembered address may
        # belong to another guest by now: nothing is invalidated.
        cold = empty and _another_boot(last, session)
        if live != backend.normalize(compose_rules(records)):
            try:
                previous = root.read("journal.json")
                possible = _records({"schema_version": 1, "records": previous["candidate_records"]})
            except (OSError, KeyError, RuntimeError, ValueError) as exc:
                if not empty:
                    raise PFError("cannot independently identify owned withdrawal state") from exc
            else:
                if live == backend.normalize(compose_rules(possible)):
                    records = possible
                elif not empty:
                    raise PFError("foreign PF drift prevents quiescence")
        retired = {key: {**record, "active": False, "rules": ""} for key, record in records.items()}
        root.write(
            "journal.json",
            {
                "schema_version": 1,
                "phase": "applying",
                "candidate_records": retired,
                "reason": "administrator-withdrawal",
                # Until it has completed, a withdrawal after a cold start keeps
                # naming the boot of the record that proves the cold start, so
                # that it is still proven when a failed attempt is repeated.
                **(
                    {}
                    if session is None
                    else {"boot_session": _journal_session(last) if cold else session}
                ),
            },
        )
        try:
            if not empty and compose_rules(records):
                backend.replace(compose_rules(records), "")
            if backend.inspect() != backend.normalize(""):
                raise PFError("withdrawal rules remain")
            root.write("live.json", {"schema_version": 1, "records": retired})
            if not cold:
                policy = _installed_policy(root)
                for key, record in retired.items():
                    if record["kind"] != "host-redirect" and not _own_states_gone(
                        backend, policy, key, record["target_ipv4"], record
                    ):
                        raise PFError("scoped PF states remain after invalidation")
            root.write("live.json", {"schema_version": 1, "records": {}})
            root.write(
                "journal.json",
                {
                    "schema_version": 1,
                    "phase": "inhibited",
                    "reason": "administrator-withdrawal",
                    **({} if session is None else {"boot_session": session}),
                },
            )
            return {
                "schema_version": 1,
                "withdrawn": True,
                "guest_states_drained": not cold,
                "operator_paused": paused.operator_paused,
                "reference_preserved": True,
                **({"cold_start": True} if cold else {}),
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
    acknowledge_any_source: bool = False,
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
        if profile.source_scope != "lan" and not acknowledge_any_source:
            # A different statement than the bounded one, which does not satisfy it.
            raise PFError("an unrestricted source requires explicit acknowledgement")
        raw = root.read("admissions.json")
        records = _read_admissions(raw)
        resolved = admitted_digest(config, profile, installation)
        if expected_digest is not None and expected_digest != resolved:
            raise PFError("reviewed admission digest changed; no authority granted")
        record: dict[str, Any] = {
            "digest": resolved,
            "approved_at": time.time() if now is None else now,
            "approved_by": approved_by,
            # One stored field, so the record format is unchanged. The digest binds
            # the source scope and therefore which acknowledgement the field means.
            "risk_acknowledged": acknowledge_bounded_risk
            or (profile.source_scope != "lan" and acknowledge_any_source),
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
                # Shown only where it was chosen; an admission without it covers the default.
                **(
                    {}
                    if installation.enable_reference == "verify"
                    else {"enable_reference": installation.enable_reference}
                ),
                **(
                    {}
                    if installation.cold_start == "administrator"
                    else {"cold_start": installation.cold_start}
                ),
                **(
                    {}
                    if installation.translation_order == "present"
                    else {"translation_order": installation.translation_order}
                ),
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
    for name in ("suspend", "release", "hold", "unhold"):
        command = commands.add_parser(name)
        command.add_argument("--root-dir", required=True, type=Path)
        if name in {"hold", "unhold"}:
            command.add_argument("--service", required=True)
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
    command.add_argument("--acknowledge-any-source", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command in {
            "reconcile",
            "install",
            "admit",
            "resume",
            "release",
            "unhold",
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
                    acknowledge_any_source=args.acknowledge_any_source,
                )
            elif args.command == "review-admission":
                with root.lock():
                    installation = Installation.from_dict(root.read("installation.json"))
                    config = parse_config(canonical_bytes(root.read("policy.json")))
                    profile = config.profile(args.profile)
                    if config.profile_owner(profile).id != installation.owner:
                        raise PFError("profile is outside installed owner")
                    result = {
                        "profile": profile_view(profile),
                        "scope": asdict(config.scope(profile.scope)),
                        "service": asdict(config.service(profile.service)),
                        "strategy": STRATEGY,
                        "implementation_sha256": implementation_digest(),
                        **(
                            {}
                            if installation.enable_reference == "verify"
                            else {"enable_reference": installation.enable_reference}
                        ),
                        **(
                            {}
                            if installation.cold_start == "administrator"
                            else {"cold_start": installation.cold_start}
                        ),
                        **(
                            {}
                            if installation.translation_order == "present"
                            else {"translation_order": installation.translation_order}
                        ),
                        "expected_digest": admitted_digest(config, profile, installation),
                        "previous": _read_admissions(root.read("admissions.json")).get(profile.id),
                        "risk_acknowledgement_required": profile.safety.kind == "bounded",
                        **(
                            {"any_source_acknowledgement_required": True}
                            if profile.source_scope != "lan"
                            else {}
                        ),
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
                    elif args.command == "hold":
                        # A name the protected policy does not have would be
                        # damage for every pass: refuse it instead of storing it.
                        policy = parse_config(canonical_bytes(root.read("policy.json")))
                        if args.service not in {service.id for service in policy.services}:
                            raise PFError("the protected policy does not name this service")
                        intent = intent.hold(args.service, args.operation, args.holder)
                    elif args.command == "unhold":
                        intent = intent.unhold(args.service, args.operation, args.holder)
                    else:
                        intent = intent.release(args.operation, args.holder)
                    root.write("operator-intent.json", intent_to_dict(intent))
                    result = intent_to_dict(intent)
        if (
            args.command != "reconcile"
            or result.get("changed")
            or result.get("phase") != "committed"
            or result.get("reference")
        ):
            print(canonical_bytes(result).decode("utf-8"))
        if args.command == "reconcile" and "listing_notice" in result:
            # The pass absorbed a refused read of its translation-order check
            # and completed. Which listing it was goes to standard error in the
            # line that a refused listing writes when it ends a command.
            print(
                canonical_bytes(
                    {
                        "schema_version": 1,
                        "error": PFListingNotice.__name__,
                        "reason": LISTING_NOTICE,
                        **result["listing_notice"],
                    }
                ).decode("utf-8"),
                file=sys.stderr,
            )
        return 0
    except StageNotQualified as exc:
        print(canonical_bytes(exc.to_dict()).decode("utf-8"), file=sys.stderr)
        return NOT_QUALIFIED
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        # Operational stderr never exposes addresses, credentials or raw tools.
        failure: dict[str, Any] = {
            "schema_version": 1,
            "error": type(exc).__name__,
            "reason": "independent owner operation failed; inspect protected journal",
        }
        if isinstance(exc, PFListingNotice):
            # Still none of the tool's text: the closed reason, which of the
            # backend's own operations was refused, and how many unexpected
            # lines the script counted when it could count them.
            failure["reason"] = LISTING_NOTICE
            failure["operation"] = exc.operation
            if exc.unexpected_lines is not None:
                failure["unexpected_lines"] = exc.unexpected_lines
        print(canonical_bytes(failure).decode("utf-8"), file=sys.stderr)
        return 75 if type(exc).__name__ == "Busy" else 65


if __name__ == "__main__":
    raise SystemExit(main())

"""Versioned Apple Container reader and narrowly gated user lifecycle owner.

No shell, socket bind, PF write, discovery fabrication or container recreation is
performed here. Native inspectors are run as the enrolled runtime account even
when an independently scheduled root owner calls the reader.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

from .codec import canonical_bytes, canonical_json, digest, strict_load, strict_loads
from .config import config_digest, load_config, parse_config, profile_digest, to_dict
from .darwin_volume import volume_uuid
from .model import Config, Profile
from .pf_owner import reject_acl as reject_privileged_acl
from .process import OutputLimit, ProcessTimeout, Result, run
from .runtime_settings import (
    FileIdentity,
    FleetStart,
    RuntimeContract,
    RuntimeNetwork,
    RuntimeSettings,
    contract_digest,
    load_settings,
    settings_to_dict,
)
from .state import (
    Intent,
    Observation,
    Snapshot,
    admissions_from_dict,
    attribute_holds,
    intent_from_dict,
    observation_to_dict,
    snapshot_to_dict,
)
from .storage import Busy, Store
from .workflow_gate import (
    NOT_QUALIFIED,
    StageNotQualified,
    require_mutation_qualified,
    require_request_qualified,
)

Runner = Callable[..., Result]
ACLKey = tuple[str, int, int, int, int, int]
STOPPED = 42
UNKNOWN = 69
BUSY = 75
# The coordinator holds the state lock for one whole pass of its 10-second
# example schedule. A start waits at most half of that for the pass to end.
START_LOCK_WAIT_SECONDS = 5.0
START_LOCK_RETRY_SECONDS = 0.25


class RuntimeReadError(RuntimeError):
    def __init__(self, reason: str = "malformed") -> None:
        super().__init__("native runtime evidence is incomplete or disagrees")
        self.reason = reason


class NativePublicationMaintenance(RuntimeReadError):
    """A fixed vendor socket requires its existing application maintenance owner."""


# One loaded job as the service manager prints it; `Reader.helper` reads the
# network helper with the same three expressions.
_JOB_RUNNING = re.compile(r"^\s*state = running\s*$", re.MULTILINE)
_JOB_PID = re.compile(r"^\s*pid = ([1-9]\d*)\s*$", re.MULTILINE)
_JOB_PROGRAM = re.compile(r"^\s*program = (.+?)\s*$", re.MULTILINE)
# The service manager's exit status for a label it has no job for.
_JOB_NOT_LOADED = 113
_RUNTIME_HANDLER = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")


class Reader:
    def __init__(self, settings: RuntimeSettings, runner: Runner = run) -> None:
        self.settings = settings
        self.runner = runner
        self.deadline = time.monotonic() + 8
        self.checked_acls: set[ACLKey] = set()

    def remaining(self, maximum: float) -> float:
        remaining = min(maximum, self.deadline - time.monotonic())
        if remaining <= 0:
            raise ProcessTimeout("runtime pass deadline exhausted")
        return remaining

    def native(self, arguments: list[str], *, timeout: float | None = None) -> bytes:
        result = self.runner(
            [self.settings.executable, *arguments],
            # A caller's own bound replaces both the per-call cap and the pass
            # deadline; recovery alone names one, for its single `start` call.
            timeout=self.remaining(4) if timeout is None else timeout,
            run_uid=self.settings.account.uid,
            run_gid=self.settings.account.gid,
            account_home=self.settings.account.home,
        )
        if result.returncode or result.stderr:
            raise RuntimeReadError("unavailable")
        return result.stdout

    def tool(self, arguments: list[str]) -> str:
        result = self.runner(arguments, timeout=self.remaining(3), max_output=262_144)
        if result.returncode or result.stderr:
            raise RuntimeReadError("unavailable")
        return result.stdout.decode("utf-8", "strict")

    def version(self) -> None:
        text = self.native(["--version"]).decode("ascii", "strict")
        matched = re.fullmatch(r"container CLI version (\d+\.\d+\.\d+)(?: [^\n]*)?\n?", text)
        if matched is None or matched[1] != self.settings.accepted_version:
            raise RuntimeReadError("identity-mismatch")

    def inventory(self) -> list[dict[str, Any]]:
        raw = strict_loads(self.native(["list", "--all", "--format", "json"]))
        if not isinstance(raw, list) or len(raw) > 1024:
            raise RuntimeReadError()
        items = [decode_snapshot(item, self.settings.accepted_version) for item in raw]
        names = [item["id"] for item in items]
        if len(names) != len(set(names)):
            raise RuntimeReadError()
        return items

    def inspect(self, name: str) -> dict[str, Any]:
        raw = strict_loads(self.native(["inspect", name]))
        if not isinstance(raw, list) or len(raw) != 1:
            raise RuntimeReadError()
        result = decode_snapshot(raw[0], self.settings.accepted_version)
        if result["id"] != name:
            raise RuntimeReadError("identity-mismatch")
        return result

    def network(self, config: Config, network: RuntimeNetwork) -> dict[str, Any]:
        raw = strict_loads(self.native(["network", "inspect", network.name]))
        if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], dict):
            raise RuntimeReadError()
        item = raw[0]
        conf, status = item.get("configuration"), item.get("status")
        scope = config.scope(network.scope)
        if (
            not isinstance(conf, dict)
            or not isinstance(status, dict)
            or item.get("id") != network.name
            or conf.get("name") != network.name
            or conf.get("mode") != "nat"
            or conf.get("plugin") != "container-network-vmnet"
            or status.get("ipv4Subnet") != scope.guest_cidr
            or status.get("ipv4Gateway") != network.gateway
            or ipaddress.IPv4Address(network.gateway) not in ipaddress.IPv4Network(scope.guest_cidr)
        ):
            raise RuntimeReadError("identity-mismatch")
        interface = self.tool(["/sbin/ifconfig", scope.interface])
        if scope.host_ipv4 not in re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)\b", interface):
            raise RuntimeReadError("identity-mismatch")
        return item

    def helper(self, network: RuntimeNetwork) -> dict[str, Any]:
        report = self.tool(
            ["/bin/launchctl", "print", f"{network.helper_domain}/{network.helper_label}"]
        )
        pid = re.search(r"^\s*pid = ([1-9]\d*)\s*$", report, re.MULTILINE)
        program = re.search(r"^\s*program = (.+?)\s*$", report, re.MULTILINE)
        if (
            re.search(r"^\s*state = running\s*$", report, re.MULTILINE) is None
            or pid is None
            or program is None
            or program[1] != network.helper_executable
        ):
            raise RuntimeReadError("identity-mismatch")
        process = self.tool(
            ["/bin/ps", "-p", pid[1], "-o", "uid=", "-o", "lstart=", "-o", "comm="]
        ).strip()
        found = re.fullmatch(r"(\d+)\s+(.{24})\s+(.+)", process)
        if (
            found is None
            or int(found[1]) != network.helper_uid
            or found[3] != network.helper_executable
        ):
            raise RuntimeReadError("identity-mismatch")
        return {
            "pid": int(pid[1]),
            "started": found[2],
            "uid": int(found[1]),
            "executable": found[3],
        }

    def api(self, fleet: FleetStart, domain: str) -> dict[str, Any]:
        """The vendor API job behind the inventory: loaded, running, the declared program."""
        report = self.tool(["/bin/launchctl", "print", f"{domain}/{fleet.api_label}"])
        pid, program = _JOB_PID.search(report), _JOB_PROGRAM.search(report)
        if (
            _JOB_RUNNING.search(report) is None
            or pid is None
            or program is None
            or program[1] != fleet.api_executable
        ):
            raise RuntimeReadError("identity-mismatch")
        process = self.tool(
            ["/bin/ps", "-p", pid[1], "-o", "uid=", "-o", "lstart=", "-o", "comm="]
        ).strip()
        found = re.fullmatch(r"(\d+)\s+(.{24})\s+(.+)", process)
        if (
            found is None
            or int(found[1]) != self.settings.account.uid
            or found[3] != fleet.api_executable
        ):
            raise RuntimeReadError("identity-mismatch")
        return {
            "pid": int(pid[1]),
            "started": found[2],
            "uid": int(found[1]),
            "executable": found[3],
        }

    def job_absent(self, domain: str, label: str) -> bool:
        """Whether the service manager itself says it has no job with this label.

        True only for its own "no such job" answer and False for a job it prints.
        Any other outcome is evidence of neither and makes the read unavailable.
        """
        result = self.runner(
            ["/bin/launchctl", "print", f"{domain}/{label}"],
            timeout=self.remaining(3),
            max_output=262_144,
        )
        if result.returncode == _JOB_NOT_LOADED and not result.stdout:
            return True
        if result.returncode == 0 and result.stdout and not result.stderr:
            return False
        raise RuntimeReadError("unavailable")


def decode_snapshot(raw: Any, version: str) -> dict[str, Any]:
    """Decode actual CLI envelopes; Swift resource snapshots alone aren't CLI JSON."""
    if version not in {"1.2.0", "1.4.1", "1.5.0"} or not isinstance(raw, dict):
        raise RuntimeReadError()
    if not isinstance(raw.get("id"), str) or not isinstance(raw.get("configuration"), dict):
        raise RuntimeReadError()
    status = raw.get("status")
    # Every accepted version prints the vendor's `ManagedContainer`: `id`,
    # `configuration` and a nested `status`. A flat row is not this CLI's output,
    # and absence is never inferred from missing fields.
    if not isinstance(status, dict) or set(status) - {"state", "networks", "startedDate"}:
        raise RuntimeReadError()
    state, networks, started = (
        status.get("state"),
        status.get("networks", []),
        status.get("startedDate"),
    )
    if (
        not isinstance(state, str)
        or state not in {"running", "stopped", "stopping", "unknown"}
        or not isinstance(networks, list)
    ):
        raise RuntimeReadError()
    if state == "running" and (not isinstance(started, str) or not started):
        raise RuntimeReadError()
    return {
        "id": raw["id"],
        "configuration": raw["configuration"],
        "state": state,
        "networks": networks,
        "started": started,
    }


def _deny_only_acl(raw: bytes, path: Path) -> None:
    """Validate Apple's bounded C-locale ls output without accepting grant ACEs.

    Runtime mount ancestors can carry the normal everyone/deny-delete ACL. This
    parser is deliberately separate from privileged code/data trust boundaries,
    where even deny-only ACLs remain unsupported. Unknown syntax is not evidence
    that a path is safe.
    """
    if not raw or len(raw) > 65_536 or not raw.endswith(b"\n"):
        raise RuntimeReadError("identity-mismatch")
    try:
        text = raw.decode("ascii", "strict")
        requested = str(path).encode("ascii", "strict").decode("ascii")
    except UnicodeError as exc:
        raise RuntimeReadError("identity-mismatch") from exc
    if any(ord(character) < 32 and character != "\n" for character in text):
        raise RuntimeReadError("identity-mismatch")
    lines = text.splitlines()
    if len(lines) > 513:
        raise RuntimeReadError("identity-mismatch")
    header = re.fullmatch(
        r"(?P<mode>[ds-][r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-])"
        r"(?P<suffix>[+@]?) +[1-9][0-9]* +[A-Za-z0-9_.-]{1,128} +"
        r"[A-Za-z0-9_.-]{1,128} +[0-9]+ +"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +"
        r"(?:[1-9]|[12][0-9]|3[01]) +(?:(?:[01][0-9]|2[0-3]):[0-5][0-9]|[0-9]{4}) +"
        + re.escape(requested),
        lines[0],
    )
    if header is None or (header["suffix"] == "+" and len(lines) == 1):
        raise RuntimeReadError("identity-mismatch")
    if len(lines) > 1 and header["suffix"] not in {"+", "@"}:
        raise RuntimeReadError("identity-mismatch")
    common = ["delete", "readattr", "writeattr", "readextattr", "writeextattr"]
    security = ["readsecurity", "writesecurity", "chown"]
    if header["mode"].startswith("d"):
        permissions = ["list", "add_file", "search", "delete", "add_subdirectory", "delete_child"]
        permissions += common[1:] + security
        flags = ["file_inherit", "directory_inherit", "limit_inherit", "only_inherit"]
    else:
        permissions = ["read", "write", "execute", "delete", "append"]
        permissions += common[1:] + security
        flags = ["limit_inherit"]
    order = {name: index for index, name in enumerate([*permissions, *flags])}
    principal = (
        r"(?:(?:user|group):[A-Za-z0-9_.-]{1,128}|"
        r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})"
    )
    for index, line in enumerate(lines[1:]):
        ace = re.fullmatch(
            rf" {index}: {principal}(?: inherited)? deny ([a-z_]+(?:,[a-z_]+)*)", line
        )
        if ace is None:
            raise RuntimeReadError("identity-mismatch")
        tokens = ace[1].split(",")
        if (
            len(tokens) != len(set(tokens))
            or any(token not in order for token in tokens)
            or not any(token in permissions for token in tokens)
            or [order[token] for token in tokens] != sorted(order[token] for token in tokens)
        ):
            raise RuntimeReadError("identity-mismatch")


def reject_acl(path: Path, *, timeout: float = 2.0) -> None:
    """Refuse ACL grants/unknown runtime evidence; retain conservative metadata checks."""
    if sys.platform != "darwin":
        reject_privileged_acl(path, timeout=timeout)
        return
    observed = run(["/bin/ls", "-lde", str(path)], timeout=timeout, max_output=65_536)
    if observed.returncode or observed.stderr:
        raise RuntimeReadError("identity-mismatch")
    _deny_only_acl(observed.stdout, path)


def _identity_acl(
    path: Path, *, deadline: float | None = None, checked_acls: set[ACLKey] | None = None
) -> None:
    remaining = 2.0 if deadline is None else min(2.0, deadline - time.monotonic())
    if remaining <= 0:
        raise ProcessTimeout("persistent ACL verification deadline exhausted")
    meta = path.lstat()
    key = (str(path), meta.st_dev, meta.st_ino, meta.st_ctime_ns, meta.st_uid, meta.st_mode)
    if checked_acls is not None and key in checked_acls:
        return
    try:
        reject_acl(path, timeout=remaining)
    except ProcessTimeout:
        raise
    except (OSError, RuntimeError) as exc:
        raise RuntimeReadError("identity-mismatch") from exc
    final = path.lstat()
    if key != (
        str(path),
        final.st_dev,
        final.st_ino,
        final.st_ctime_ns,
        final.st_uid,
        final.st_mode,
    ):
        raise RuntimeReadError("identity-mismatch")
    if deadline is not None and time.monotonic() >= deadline:
        raise ProcessTimeout("persistent ACL verification deadline exhausted")
    if checked_acls is not None:
        checked_acls.add(key)


def _volume_of(path: Path, kind: str, meta: os.stat_result) -> str:
    """Identifier of the volume that holds the directory or file `meta` describes.

    The device number still ties the descriptor to that `lstat` inside this call.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags | (os.O_DIRECTORY if kind == "directory" else 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (meta.st_dev, meta.st_ino):
            raise RuntimeReadError("identity-mismatch")
        return volume_uuid(fd)
    finally:
        os.close(fd)


def _volume_bound(identity: FileIdentity) -> FileIdentity:
    """A verified device-bound identity with its device replaced by its volume."""
    path = Path(identity.path)
    meta = path.lstat()
    if (meta.st_dev, meta.st_ino) != (identity.device, identity.inode):
        raise RuntimeReadError("identity-mismatch")
    return replace(identity, device=None, volume_uuid=_volume_of(path, identity.kind, meta))


def check_identity(
    identity: FileIdentity,
    *,
    deadline: float | None = None,
    checked_acls: set[ACLKey] | None = None,
) -> None:
    expires = time.monotonic() + 5
    if deadline is not None:
        expires = min(expires, deadline)

    def within_budget() -> None:
        if time.monotonic() >= expires:
            raise ProcessTimeout("persistent identity verification deadline exhausted")

    path = Path(identity.path)
    for parent in reversed(path.parents):
        within_budget()
        meta = parent.lstat()
        if not stat.S_ISDIR(meta.st_mode) or stat.S_ISLNK(meta.st_mode):
            raise RuntimeReadError("identity-mismatch")
        # Root-owned sticky temporary parents do not permit replacement of an
        # inode-bound operator directory; other shared writable parents do.
        if meta.st_mode & 0o022 and not (meta.st_uid == 0 and meta.st_mode & stat.S_ISVTX):
            raise RuntimeReadError("identity-mismatch")
        _identity_acl(parent, deadline=expires, checked_acls=checked_acls)
        within_budget()
    meta = path.lstat()
    kind = (
        "directory"
        if stat.S_ISDIR(meta.st_mode)
        else "file"
        if stat.S_ISREG(meta.st_mode)
        else "socket"
        if stat.S_ISSOCK(meta.st_mode)
        else "other"
    )
    if kind != identity.kind or meta.st_uid != identity.uid or stat.S_ISLNK(meta.st_mode):
        raise RuntimeReadError("identity-mismatch")
    # Socket permissions belong to the enrolled application; persistent data
    # and hashed startup receipts must not accept an independent writer.
    if identity.kind != "socket" and meta.st_mode & 0o022:
        raise RuntimeReadError("identity-mismatch")
    _identity_acl(path, deadline=expires, checked_acls=checked_acls)
    within_budget()
    if identity.volume_uuid is not None:
        # A device number is assigned when a volume is mounted and can differ
        # after a restart. This binding names the volume and the inode instead.
        try:
            verified = (
                identity.kind in {"directory", "file"}
                and identity.device is None
                and meta.st_ino == identity.inode
                and _volume_of(path, identity.kind, meta) == identity.volume_uuid
            )
        except (OSError, ValueError) as exc:
            # Not opened, not answered or not decoded: nothing was verified.
            raise RuntimeReadError("identity-mismatch") from exc
        if not verified:
            raise RuntimeReadError("identity-mismatch")
        within_budget()
    elif identity.kind != "socket" and (
        meta.st_dev != identity.device or meta.st_ino != identity.inode
    ):
        raise RuntimeReadError("identity-mismatch")
    if identity.sha256 is not None:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            if (
                _receipt_metadata(opened) != _receipt_metadata(meta)
                or not stat.S_ISREG(opened.st_mode)
                or not 0 <= opened.st_size <= 536_870_912
            ):
                raise RuntimeReadError("identity-mismatch")
            hasher = hashlib.sha256()
            consumed = 0
            while True:
                within_budget()
                chunk = os.read(fd, 1_048_576)
                if not chunk:
                    break
                consumed += len(chunk)
                if consumed > opened.st_size:
                    raise RuntimeReadError("identity-mismatch")
                hasher.update(chunk)
            within_budget()
            hashed = hasher.hexdigest()
            after = path.lstat()
            if (
                _receipt_metadata(after) != _receipt_metadata(opened)
                or _receipt_metadata(os.fstat(fd)) != _receipt_metadata(opened)
                or consumed != opened.st_size
                or hashed != identity.sha256
            ):
                raise RuntimeReadError("identity-mismatch")
            # A fresh metadata fence scopes the cache. Do not carry a pre-hash
            # ACL assertion across a permission/owner/ACL change during hashing.
            _identity_acl(path, deadline=expires, checked_acls=checked_acls)
            if _receipt_metadata(path.lstat()) != _receipt_metadata(opened) or _receipt_metadata(
                os.fstat(fd)
            ) != _receipt_metadata(opened):
                raise RuntimeReadError("identity-mismatch")
            within_budget()
        finally:
            os.close(fd)


def _receipt_metadata(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_ctime_ns,
        info.st_mtime_ns,
        info.st_size,
    )


# The type of a mount in guest memory as every accepted version states it. The
# vendor's `Filesystem.FSType` is an enum whose encoder Swift derives: one key
# named after the case, holding the case's values, and `tmpfs` has none. The
# other cases are written under `virtiofs`, `block` and `volume`.
_MEMORY_BACKED: dict[str, dict[str, Any]] = {"tmpfs": {}}
# What that type means is read from the vendor's own Linux runtime, so it is
# established for a definition that names this runtime and for no other. Every
# accepted version writes a definition's runtime into `runtimeHandler`; this
# name is that member's default and the name of the vendor's runtime plugin.
_LINUX_RUNTIME = "container-runtime-linux"


def _mounts(
    configuration: Mapping[str, Any], *, without_guest_memory: bool = False
) -> list[tuple[str, bool]]:
    raw = configuration.get("mounts")
    if not isinstance(raw, list):
        raise RuntimeReadError()
    result = []
    for item in raw:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("source"), str)
            or not isinstance(item.get("options"), list)
        ):
            raise RuntimeReadError()
        # The runtime opens nothing on the host for guest memory: the source of
        # such a mount is a label for the guest, whatever it says, not a path.
        if without_guest_memory and item.get("type") == _MEMORY_BACKED:
            continue
        result.append((item["source"], "ro" not in item["options"]))
    return result


def _check_contract(
    config: Config,
    contract: RuntimeContract,
    current: dict[str, Any],
    inventory: list[dict[str, Any]],
    *,
    deadline: float | None = None,
    checked_acls: set[ACLKey] | None = None,
) -> None:
    if (
        contract_digest(contract) != config.service(contract.service).contract_sha256
        or digest(current["configuration"]) != contract.configuration_sha256
    ):
        raise RuntimeReadError("identity-mismatch")
    if {path for path, _ in _mounts(current["configuration"])} != {
        identity.path for identity in contract.mounts
    }:
        raise RuntimeReadError("identity-mismatch")
    for identity in (*contract.mounts, *contract.receipts):
        check_identity(identity, deadline=deadline, checked_acls=checked_acls)
    for source, writable in _mounts(current["configuration"]):
        if not writable:
            continue
        for peer in inventory:
            if peer["id"] == current["id"]:
                continue
            # An enrolled exception for a retained definition: while it is exactly
            # stopped it writes nothing. Running, stopping or unknown is refused.
            if peer["id"] in contract.tolerated_stopped_peers and peer["state"] == "stopped":
                continue
            # Only a mount with a host path can be a second writer of one. That a
            # memory-backed mount has none is known for a peer that names the
            # vendor's Linux runtime; under another handler, or without the
            # member, every mount of the peer is compared.
            guest_memory = peer["configuration"].get("runtimeHandler") == _LINUX_RUNTIME
            for other, other_writable in _mounts(
                peer["configuration"], without_guest_memory=guest_memory
            ):
                if other_writable and (
                    source == other
                    or source.startswith(other.rstrip("/") + "/")
                    or other.startswith(source.rstrip("/") + "/")
                ):
                    raise RuntimeReadError("identity-mismatch")
                # Different authored paths can alias the same writable object.
                if (
                    other_writable
                    and os.path.exists(other)
                    and os.path.exists(source)
                    and os.path.samefile(other, source)
                ):
                    raise RuntimeReadError("identity-mismatch")


def _hardware_address(attachment: dict[str, Any]) -> str | None:
    """The guest's link address in the one form the vendor encodes, else nothing.

    The independent root owner compares this address with its own neighbour
    read before it accepts a direct guest target. At every accepted version the
    attachment carries an optional `macAddress`, written as six two-digit
    lower-case hexadecimal groups joined by colons. A missing value, or one in
    any other spelling or type, is unknown: it is neither repaired nor replaced.
    """
    value = attachment.get("macAddress")
    if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", value):
        return value
    return None


def _service(
    config: Config,
    contract: RuntimeContract,
    current: dict[str, Any],
    network: RuntimeNetwork,
    generation: str,
    now: float,
    reader: Reader,
) -> Observation:
    if current["state"] == "stopped":
        fleet = reader.settings.fleet_start
        if fleet is not None:
            # The API gives every stored definition this state whenever it starts,
            # so its word alone does not say that the guest is not running. The
            # guest's runtime job carries the configuration's own identifier.
            handler = current["configuration"].get("runtimeHandler")
            if (
                not isinstance(handler, str)
                or _RUNTIME_HANDLER.fullmatch(handler) is None
                or current["configuration"].get("id") != contract.name
            ):
                raise RuntimeReadError("identity-mismatch")
            label = f"{fleet.runtime_label_prefix}{handler}.{contract.name}"
            uid = reader.settings.account.uid
            # An earlier incarnation of the API may have registered the guest in
            # the account's other domain; a job there is as live as one here.
            for domain in (
                ("system",) if network.helper_domain == "system" else (f"gui/{uid}", f"user/{uid}")
            ):
                if not reader.job_absent(domain, label):
                    raise RuntimeReadError("generation-mismatch")
        return Observation(
            "absent",
            "confirmed-absent",
            now,
            None,
            {"contract_sha256": contract_digest(contract), "runtime_state": "stopped"},
        )
    if current["state"] != "running":
        raise RuntimeReadError("incomplete")
    if any(not isinstance(item, dict) for item in current["networks"]):
        raise RuntimeReadError()
    attachments = [item for item in current["networks"] if item.get("network") == network.name]
    if len(attachments) != 1:
        raise RuntimeReadError("identity-mismatch")
    attachment = attachments[0]
    if attachment.get("ipv4Gateway") != network.gateway or not isinstance(
        attachment.get("ipv4Address"), str
    ):
        raise RuntimeReadError("identity-mismatch")
    interface = ipaddress.IPv4Interface(attachment["ipv4Address"])
    subnet = ipaddress.IPv4Network(config.scope(contract.scope).guest_cidr)
    if interface.network != subnet or interface.ip in {
        subnet.network_address,
        subnet.broadcast_address,
    }:
        raise RuntimeReadError("identity-mismatch")
    service = config.service(contract.service)
    if service.automatic_ports is not None:
        ports = (
            reader.native(
                [
                    "exec",
                    "--user",
                    "0",
                    contract.name,
                    "/bin/cat",
                    "/proc/sys/net/ipv4/ip_local_port_range",
                ]
            )
            .decode("ascii")
            .split()
        )
        if ports != [str(service.automatic_ports.first), str(service.automatic_ports.last)]:
            raise RuntimeReadError("identity-mismatch")
    own_generation = "guest-" + digest(
        {
            "configuration": contract.configuration_sha256,
            "started": current["started"],
            "network": generation,
            "ipv4": str(interface.ip),
        }
    )
    mac = _hardware_address(attachment)
    return Observation(
        "present",
        "verified",
        now,
        own_generation,
        {
            "ipv4": str(interface.ip),
            "contract_sha256": service.contract_sha256,
            "runtime_state": "running",
            "configuration_sha256": contract.configuration_sha256,
            **({} if mac is None else {"mac": mac}),
        },
    )


def _publication_row(item: Any) -> bool:
    """The vendor's `PublishPort` has exactly these five fields at every accepted tag."""
    return (
        isinstance(item, dict)
        and set(item) == {"hostAddress", "hostPort", "containerPort", "count", "proto"}
        and isinstance(item["hostAddress"], str)
        and isinstance(item["proto"], str)
        and all(type(item[key]) is int for key in ("hostPort", "containerPort", "count"))
    )


def _publication(
    config: Config,
    profile: Profile,
    current: dict[str, Any],
    service: Observation,
    network_generation: str | None,
    now: float,
) -> Observation:
    if service.state != "present":
        return Observation(service.state, service.reason, now, None, {"states": []})
    pubs = current["configuration"].get("publishedPorts")
    if (
        not isinstance(pubs, list)
        or profile.target_ports is None
        or not all(_publication_row(item) for item in pubs)
    ):
        return Observation("unknown", "malformed", now, None)
    expected = {
        "hostAddress": config.scope(profile.scope).host_ipv4,
        "hostPort": profile.ports.first,
        "containerPort": profile.target_ports.first,
        "count": profile.ports.width,
        "proto": profile.protocol,
    }
    matches = sum(item == expected for item in pubs)
    if matches > 1:
        # The vendor refuses overlapping publications, so a repeated row is not
        # its output; it proves neither presence nor absence.
        return Observation("unknown", "malformed", now, None)
    if not matches:
        # Complete configuration proves no matching native publication. A caller
        # cannot cure this by adding an unrelated host listener or PF rule.
        return Observation("absent", "confirmed-absent", now, None, {"states": []})
    return Observation(
        "present",
        "verified",
        now,
        service.generation,
        {
            "policy_digest": profile_digest(config, profile),
            "target_ipv4": service.data["ipv4"],
            "target_generation": service.generation,
            "network_generation": network_generation,
            "states": [],
            "source": "native-service-publication",
            "service": profile.service,
        },
    )


def _reason(exc: Exception) -> str:
    if isinstance(exc, RuntimeReadError):
        return exc.reason
    if isinstance(exc, ProcessTimeout):
        return "timed-out"
    if isinstance(exc, PermissionError):
        return "inaccessible"
    return "malformed"


# The kernel's identifier of the running boot, as `sysctl -n` prints it. It is
# made once per boot. The boot time is not hashed: the kernel moves it whenever
# the calendar clock is set, and its text carries a date in the local time zone.
_BOOT_SESSION = re.compile(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\n")


def _boot_session(text: str) -> str:
    """Exactly one upper-case identifier on one line; the nil identifier names no boot."""
    if _BOOT_SESSION.fullmatch(text) is None or not text.strip("0-\n"):
        raise RuntimeReadError()
    return text[:-1]


def observe_runtime(
    config: Config,
    settings: RuntimeSettings,
    runner: Runner = run,
    *,
    clock: Callable[[], float] = time.time,
) -> Snapshot:
    reader, now = Reader(settings, runner), clock()
    services: dict[str, Observation] = {}
    profiles: dict[str, Observation] = {}
    generation = None
    inspected: dict[str, dict[str, Any]] = {}
    try:
        if settings.owner not in {
            owner.id
            for owner in config.owners
            if owner.privilege == "user" and "publication" in owner.capabilities
        } or {network.scope for network in settings.networks} != {
            scope.id for scope in config.scopes
        }:
            raise RuntimeReadError("identity-mismatch")
        if set(contract.service for contract in settings.contracts) != {
            service.id for service in config.services
        }:
            raise RuntimeReadError("identity-mismatch")
        reader.version()
        boot = _boot_session(reader.tool(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"]))
        helpers = {network.scope: reader.helper(network) for network in settings.networks}
        networks = {network.scope: reader.network(config, network) for network in settings.networks}
        fleet, domain, api = settings.fleet_start, "", None
        if fleet is not None:
            domains = {network.helper_domain for network in settings.networks}
            if len(domains) != 1:
                raise RuntimeReadError("identity-mismatch")
            (domain,) = domains
            api = reader.api(fleet, domain)
        inventory = reader.inventory()
        if fleet is None and inventory and all(item["state"] == "stopped" for item in inventory):
            raise RuntimeReadError("incomplete")
        identity: dict[str, Any] = {"boot": boot, "helpers": helpers, "networks": networks}
        if api is not None:
            # A restarted API forgets which guests run; it is another generation.
            identity["api"] = api
        generation = "network-" + digest(identity)
        for contract in settings.contracts:
            try:
                listed = [item for item in inventory if item["id"] == contract.name]
                if len(listed) != 1:
                    # Missing named configuration is not a proven stopped guest.
                    raise RuntimeReadError("identity-mismatch")
                current = reader.inspect(contract.name)
                if current != listed[0]:
                    raise RuntimeReadError("generation-mismatch")
                _check_contract(
                    config,
                    contract,
                    current,
                    inventory,
                    deadline=reader.deadline,
                    checked_acls=reader.checked_acls,
                )
                network = next(item for item in settings.networks if item.scope == contract.scope)
                services[contract.service] = _service(
                    config, contract, current, network, generation, now, reader
                )
                inspected[contract.service] = current
            except (ValueError, OSError, RuntimeReadError, ProcessTimeout, OutputLimit) as exc:
                services[contract.service] = Observation("unknown", _reason(exc), now, None)
        if helpers != {network.scope: reader.helper(network) for network in settings.networks}:
            raise RuntimeReadError("generation-mismatch")
        if networks != {
            network.scope: reader.network(config, network) for network in settings.networks
        }:
            raise RuntimeReadError("generation-mismatch")
        if fleet is not None and api != reader.api(fleet, domain):
            raise RuntimeReadError("generation-mismatch")
    except (ValueError, OSError, RuntimeReadError, ProcessTimeout, OutputLimit) as exc:
        generation = None
        services = {
            service.id: Observation("unknown", _reason(exc), now, None)
            for service in config.services
        }
    for profile in config.profiles:
        if profile.kind == "publication":
            service = services.get(profile.service, Observation("unknown", "unobserved", now, None))
            profiles[profile.id] = _publication(
                config, profile, inspected.get(profile.service, {}), service, generation, now
            )
    return Snapshot(now, generation, services, profiles)


def _intent(settings: RuntimeSettings) -> Intent:
    if settings.intent is None:
        return Intent(damaged=True)
    try:
        intent = intent_from_dict(strict_load(settings.intent))
    except (ValueError, OSError):
        return Intent(damaged=True)
    # A hold on a service that is not enrolled here inhibits every workload.
    return attribute_holds(intent, {contract.service for contract in settings.contracts})


def capture_enrollment(
    settings: RuntimeSettings, runner: Runner = run, *, identity_binding: str = "device"
) -> RuntimeSettings:
    """Explicit read-only capture; does not approve policy or edit workloads."""
    if identity_binding not in {"device", "volume-uuid"}:
        raise ValueError("unknown identity binding")
    reader = Reader(settings, runner)
    reader.version()
    inventory = reader.inventory()
    contracts = []
    for contract in settings.contracts:
        current = reader.inspect(contract.name)
        matches = [item for item in inventory if item["id"] == contract.name]
        if len(matches) != 1 or matches[0] != current:
            raise RuntimeReadError("generation-mismatch")
        mounts = []
        for path, _ in _mounts(current["configuration"]):
            meta = Path(path).lstat()
            kind = (
                "directory"
                if stat.S_ISDIR(meta.st_mode)
                else "file"
                if stat.S_ISREG(meta.st_mode)
                else "socket"
                if stat.S_ISSOCK(meta.st_mode)
                else "other"
            )
            identity = FileIdentity(
                path,
                kind,
                meta.st_uid,
                meta.st_dev if kind != "socket" else None,
                meta.st_ino if kind != "socket" else None,
            )
            check_identity(identity, deadline=reader.deadline, checked_acls=reader.checked_acls)
            if identity_binding == "volume-uuid" and kind in {"directory", "file"}:
                identity = _volume_bound(identity)
            mounts.append(identity)
        receipts = []
        for receipt in contract.receipts:
            check_identity(receipt, deadline=reader.deadline, checked_acls=reader.checked_acls)
            # A receipt stays as authored. Only when the volume binding is asked
            # for is the device number that was just verified replaced.
            if (
                identity_binding == "volume-uuid"
                and receipt.kind in {"directory", "file"}
                and receipt.volume_uuid is None
            ):
                receipt = _volume_bound(receipt)
            receipts.append(receipt)
        contracts.append(
            replace(
                contract,
                configuration_sha256=digest(current["configuration"]),
                mounts=tuple(mounts),
                receipts=tuple(receipts),
            )
        )
    return replace(settings, contracts=tuple(contracts))


def derive_policy(config: Config, settings: RuntimeSettings) -> Config:
    """Keep enrolled identity fields generated; port/scope policy stays authored once."""
    if {item.service for item in settings.contracts} != {item.id for item in config.services}:
        raise ValueError("policy services and enrollment differ")
    result = to_dict(config)
    for service in result["services"]:
        service["contract_sha256"] = contract_digest(settings.contract(service["id"]))
    return parse_config(canonical_bytes(result))


@contextlib.contextmanager
def _state_lock(
    store: Store, clock: Callable[[], float], sleep: Callable[[float], None]
) -> Iterator[None]:
    """Take the state lock, waiting a bounded time while another operation holds it."""
    deadline = clock() + START_LOCK_WAIT_SECONDS
    with contextlib.ExitStack() as held:
        while True:
            try:
                held.enter_context(store.lock())
                break
            except Busy:
                if clock() >= deadline:
                    raise
                sleep(START_LOCK_RETRY_SECONDS)
        yield


def recover_service(
    config: Config,
    settings: RuntimeSettings,
    service_id: str,
    runner: Runner = run,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Snapshot:
    """Monit recovery is only a start of a twice-proven stopped enrolled guest."""
    if os.geteuid() == 0 or os.geteuid() != settings.account.uid or settings.state_dir is None:
        raise PermissionError("workload recovery belongs to the enrolled user")
    store = Store(Path(settings.state_dir))
    with _state_lock(store, clock, sleep):
        before = observe_runtime(config, settings, runner)
        service = before.services.get(service_id)
        if _intent(settings).blocks(service_id) or service is None or service.state != "absent":
            raise RuntimeReadError("incomplete")
        fresh = observe_runtime(config, settings, runner)
        if (
            fresh.network_generation != before.network_generation
            or fresh.services[service_id].state != "absent"
            or _intent(settings).blocks(service_id)
        ):
            raise RuntimeReadError("generation-mismatch")
        contract = settings.contract(service_id)
        # Only this call may take longer than a read, and only when the settings
        # say how long. Its result is checked like every other vendor call.
        Reader(settings, runner).native(
            ["start", contract.name], timeout=settings.start_timeout_seconds
        )
        # A successful CLI exit is never the final readiness assertion.
        result = observe_runtime(config, settings, runner)
        if result.services[service_id].state != "present":
            raise RuntimeReadError("incomplete")
        return result


def handle_request(
    config: Config, settings: RuntimeSettings, request: Any, runner: Runner = run
) -> dict[str, Any]:
    if (
        not isinstance(request, dict)
        or type(request.get("protocol_version")) is not int
        or request.get("protocol_version") != 1
        or request.get("owner") != settings.owner
    ):
        raise ValueError("invalid runtime owner envelope")
    if request.get("operation") == "observe":
        if set(request) != {"protocol_version", "operation", "owner", "config"} or config_digest(
            parse_config(canonical_bytes(request["config"]))
        ) != config_digest(config):
            raise ValueError("runtime policy differs from installed policy")
        full = observe_runtime(config, settings, runner)
        result = snapshot_to_dict(
            Snapshot(
                full.observed_at,
                full.network_generation,
                {
                    key: item
                    for key, item in full.services.items()
                    if config.service(key).owner == settings.owner
                },
                {
                    key: item
                    for key, item in full.profiles.items()
                    if config.profile_owner(key).id == settings.owner
                },
            )
        )
    elif request.get("operation") == "reconcile":
        expected_fields = {
            "protocol_version",
            "operation",
            "owner",
            "policy_digest",
            "profile_digest",
            "profile",
            "action",
            "target_ipv4",
            "target_generation",
        }
        if set(request) != expected_fields or request["policy_digest"] != config_digest(config):
            raise ValueError("invalid runtime reconciliation")
        profile = next((item for item in config.profiles if item.id == request["profile"]), None)
        if (
            profile is None
            or profile.kind != "publication"
            or config.profile_owner(profile).id != settings.owner
            or request["profile_digest"] != profile_digest(config, profile)
        ):
            raise ValueError("publication authority mismatch")
        snapshot = observe_runtime(config, settings, runner)
        observed = snapshot.profiles[profile.id]
        # Native published sockets are part of the workload definition. The
        # networking executor must never stop or recreate an application to
        # remove one. Explicit maintenance provisioning owns such a change.
        if request["action"] in {"withdraw", "drain"}:
            raise NativePublicationMaintenance("incomplete")
        if request["action"] != "activate" or settings.admissions is None:
            raise ValueError("unsupported native publication operation")
        admitted = admissions_from_dict(strict_load(settings.admissions)).get(profile.id)
        if (
            _intent(settings).blocks(profile.service)
            or admitted is None
            or admitted.digest != profile_digest(config, profile)
            or admitted.approved_at > time.time()
        ):
            raise RuntimeReadError("incomplete")
        if observed.state == "absent":
            raise NativePublicationMaintenance("incomplete")
        if (
            observed.state != "present"
            or observed.data.get("target_generation") != request["target_generation"]
            or observed.data.get("target_ipv4") != request["target_ipv4"]
        ):
            raise RuntimeReadError("identity-mismatch")
        result = observation_to_dict(observed)
    else:
        raise ValueError("unsupported runtime owner operation")
    return {"protocol_version": 1, "owner": settings.owner, "result": result}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("request")
    commands.add_parser("observe")
    item = commands.add_parser("enroll")
    item.add_argument("--output", type=Path, required=True)
    item.add_argument("--identity", choices=("device", "volume-uuid"), default="device")
    item = commands.add_parser("derive-policy")
    item.add_argument("--source", type=Path, required=True)
    item.add_argument("--output", type=Path, required=True)
    for command in ("probe", "start"):
        item = commands.add_parser(command)
        item.add_argument("--service", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "start":
            require_mutation_qualified("workload-recovery")
        request: Any = None
        if args.command == "request":
            request = strict_loads(sys.stdin.buffer.read(1_048_577))
            require_request_qualified("runtime", request)
        settings = load_settings(args.settings)
        if args.command == "derive-policy":
            value = to_dict(derive_policy(load_config(args.source), settings))
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(os.dup(fd), "wb") as stream:
                    stream.write(canonical_bytes(value) + b"\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(fd)
            print(canonical_json({"derived": True, "admitted": False}))
            return 0
        if args.command == "enroll":
            enrolled = (
                capture_enrollment(settings)
                if args.identity == "device"
                else capture_enrollment(settings, identity_binding=args.identity)
            )
            payload = (canonical_json(settings_to_dict(enrolled)) + "\n").encode()
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(os.dup(fd), "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(fd)
            print(
                canonical_json(
                    {
                        "captured": True,
                        "admitted": False,
                        "service_contracts": {
                            item.service: contract_digest(item) for item in enrolled.contracts
                        },
                    }
                )
            )
            return 0
        if settings.policy is None:
            raise ValueError("runtime policy path is required")
        config = load_config(Path(settings.policy))
        if args.command == "request":
            value = handle_request(config, settings, request)
        elif args.command == "start":
            value = snapshot_to_dict(recover_service(config, settings, args.service))
        else:
            snapshot = observe_runtime(config, settings)
            if args.command == "probe":
                service = snapshot.services.get(args.service)
                if (
                    service is None
                    or _intent(settings).blocks(args.service)
                    or service.state == "unknown"
                ):
                    return UNKNOWN
                return STOPPED if service.state == "absent" else 0
            value = snapshot_to_dict(snapshot)
        print(canonical_json(value))
        return 0
    except StageNotQualified as exc:
        print(canonical_json(exc.to_dict()), file=sys.stderr)
        return NOT_QUALIFIED
    except NativePublicationMaintenance:
        print(
            canonical_json(
                {
                    "protocol_version": 1,
                    "owner": settings.owner,
                    "error": "native-publication-maintenance",
                }
            )
        )
        return 78
    except Busy:
        # Another operation kept the state lock for the whole bounded wait.
        # Nothing was observed or started; the caller may try again.
        print(canonical_json({"error": "busy"}), file=sys.stderr)
        return BUSY
    except (ValueError, OSError, RuntimeReadError, ProcessTimeout, OutputLimit):
        print(
            canonical_json({"error": "runtime-evidence-or-authority-incomplete"}), file=sys.stderr
        )
        return UNKNOWN


if __name__ == "__main__":
    raise SystemExit(main())

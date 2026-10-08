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
import math
import os
import plistlib
import re
import stat
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn

from .codec import canonical_bytes, canonical_json, digest, strict_loads
from .config import config_digest, load_config, parse_config, profile_digest, to_dict
from .darwin_volume import volume_uuid
from .launchd_inventory import domain_services
from .model import Config, Profile
from .pf_owner import reject_acl as reject_privileged_acl
from .process import OutputLimit, ProcessTimeout, Result, run
from .runtime_settings import (
    READ_TIMEOUT_DEFAULT,
    VENDOR_RUNTIME_PREFIX,
    FileIdentity,
    FleetStart,
    RestartBudget,
    RuntimeContract,
    RuntimeNetwork,
    RuntimeSettings,
    RuntimeStart,
    check_fleet_identity,
    contract_digest,
    load_settings,
    parse_settings,
    settings_to_dict,
)
from .state import (
    Intent,
    Observation,
    Snapshot,
    admissions_from_dict,
    attribute_holds,
    intent_from_dict,
    intent_to_dict,
    observation_to_dict,
    snapshot_to_dict,
)
from .storage import Busy, Store, UnsafeState
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
# The hold that recovery places on a service whose restart budget is spent. An
# operator releases it with `unhold` and these two names.
RESTART_BUDGET_OPERATION = "restart-budget"
RESTART_BUDGET_HOLDER = "supervisor"
# Starts that recovery issued, per service, in whole seconds of the calendar
# clock, rounded up: the record has to outlive a boot, which the monotonic
# clock does not.
STARTS_RECORD = "recovery-starts.json"
_RECORDED_SERVICE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_RECORDED_STARTS_MAXIMUM = 10
_CLOCK_LIMIT = 2**53
# Bound of the one vendor call that starts the runtime, unless the settings name one.
RUNTIME_START_TIMEOUT_SECONDS = 20


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
# What the start of the vendor runtime reads in addition. No production capture
# backs these forms: a text that does not match is unknown, and never read as
# an absent job, an idle job or an enabled label. Each line is read exactly:
# the printer's indentation before it is not part of it, white space at its end is.
_JOB_IDLE = re.compile(r"^[\t ]*state = not running$", re.MULTILINE)
_JOB_PROCESS = re.compile(r"^[\t ]*pid = ", re.MULTILINE)
_JOB_PATH = re.compile(r"^[\t ]*path = (.*)$", re.MULTILINE)
_JOB_PROGRAMS = re.compile(r"^[\t ]*program = (.*)$", re.MULTILINE)
_JOB_VARIABLE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*) =>(?: (.*))?")
_DISABLED_SERVICE = re.compile(r'"([^"]+)" => (true|false|enabled|disabled)')
# The vendor's names of its two roots (apple/container `ApplicationRoot` and
# `InstallRoot`, `environmentName`, the same at tags 1.2.0, 1.4.1 and 1.5.0).
_APP_ROOT = "CONTAINER_APP_ROOT"
_INSTALL_ROOT = "CONTAINER_INSTALL_ROOT"
# The vendor's launch file holds six members; a larger file is not that file.
_LAUNCH_FILE_BYTES = 65_536
# The vendor's configuration is a short text of settings; a larger file is not read.
_CONFIGURATION_BYTES = 1_048_576


def _job_block(report: str, name: str) -> list[str] | None:
    """The members of the one block `name = {` of a job print, exactly as printed.

    Only the printer's indentation is removed: a member is a line that begins
    with the indentation of the opening line and one tab, and it is everything
    after them up to the end of the line. Any other line before the closing
    brace, and a block that is not closed, is not such a block.
    """
    lines = report.split("\n")
    opening = f"{name} = {{"
    found = [index for index, line in enumerate(lines) if line.lstrip("\t ") == opening]
    if len(found) != 1:
        return None
    indentation = lines[found[0]][: -len(opening)]
    members: list[str] = []
    for line in lines[found[0] + 1 :]:
        if line == indentation + "}":
            return members
        if not line.startswith(indentation + "\t"):
            return None
        members.append(line[len(indentation) + 1 :])
    return None


def _launch_path(start: RuntimeStart) -> str:
    """Where the vendor's start command writes its launch file (`SystemStart.run`)."""
    return f"{start.app_root}/apiserver/apiserver.plist"


def _launch_dictionary(fleet: FleetStart, start: RuntimeStart) -> dict[str, Any]:
    """The launch file the vendor's start command writes for these two roots.

    apple/container `SystemStart.run` and `LaunchPlist`, the same at tags 1.2.0,
    1.4.1 and 1.5.0: six members when the command is given both roots and its
    environment holds no other `CONTAINER_` or proxy variable, which is how
    `start_runtime` calls it.
    """
    return {
        "Label": fleet.api_label,
        "ProgramArguments": [fleet.api_executable, "start"],
        "EnvironmentVariables": {_APP_ROOT: start.app_root, _INSTALL_ROOT: start.install_root},
        "LimitLoadToSessionType": ["Aqua", "Background", "System"],
        "RunAtLoad": True,
        "MachServices": {fleet.api_label: True},
    }


def _same_members(found: Any, expected: Any) -> bool:
    """Equal member for member and type for type: the number 1 is not `true`."""
    if type(found) is not type(expected):
        return False
    if isinstance(expected, dict):
        return found.keys() == expected.keys() and all(
            _same_members(found[key], item) for key, item in expected.items()
        )
    if isinstance(expected, list):
        return len(found) == len(expected) and all(
            _same_members(*pair) for pair in zip(found, expected, strict=True)
        )
    return bool(found == expected)


def _decoded_launch_file(data: bytes) -> Any:
    """A property list decoded in this process, in its XML or its binary form."""
    try:
        return plistlib.loads(data)
    except Exception as exc:
        # The decoder raises several unrelated types for bytes it cannot read.
        raise RuntimeReadError("identity-mismatch") from exc


def _started_as_declared(report: str, fleet: FleetStart, start: RuntimeStart) -> bool:
    """Whether a printed job is the one the vendor's start command loads for these roots.

    Its launch file, its program, its two arguments and both roots are compared
    exactly: there is one line of each kind, and a value that differs by white
    space at its end is another value. The service manager shows variables of
    its own in the same block, so the block is read whole and only the two
    roots are compared.
    """
    environment = _job_block(report, "environment")
    if (
        _JOB_PATH.findall(report) != [_launch_path(start)]
        or _JOB_PROGRAMS.findall(report) != [fleet.api_executable]
        or _job_block(report, "arguments") != [fleet.api_executable, "start"]
        or environment is None
    ):
        return False
    variables: dict[str, str] = {}
    for line in environment:
        found = _JOB_VARIABLE.fullmatch(line)
        if found is None or found[1] in variables:
            return False
        variables[found[1]] = found[2] or ""
    return (variables.get(_APP_ROOT), variables.get(_INSTALL_ROOT)) == (
        start.app_root,
        start.install_root,
    )


def _label_disabled(listing: str, label: str) -> bool:
    """Whether the service manager's list of disabled services names this label as disabled.

    The list holds the labels somebody enabled or disabled by hand. A label it
    does not hold has no such record and is not disabled by it; the only other
    source, a `Disabled` member of the job's own launch file, is excluded by the
    exact launch file. A list in another form is unknown.
    """
    lines = [line.strip() for line in listing.splitlines()]
    opening = "disabled services = {"
    if lines.count(opening) != 1:
        raise RuntimeReadError()
    body = lines[lines.index(opening) + 1 :]
    if "}" not in body:
        raise RuntimeReadError()
    states = []
    for line in body[: body.index("}")]:
        entry = _DISABLED_SERVICE.fullmatch(line)
        if entry is None:
            raise RuntimeReadError()
        if entry[1] == label:
            states.append(entry[2])
    if len(states) > 1:
        raise RuntimeReadError()
    return bool(states) and states[0] in {"true", "disabled"}


class Reader:
    def __init__(self, settings: RuntimeSettings, runner: Runner = run) -> None:
        self.settings = settings
        self.runner = runner
        # One complete read ends here, after the bound the settings state for
        # it. Each call still gets no more than its own smaller bound.
        seconds = settings.read_timeout_seconds
        self.deadline = time.monotonic() + (READ_TIMEOUT_DEFAULT if seconds is None else seconds)
        self.checked_acls: set[ACLKey] = set()
        self._domain_services: dict[str, frozenset[str]] | None = None
        self._absent_jobs: set[str] = set()

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
        return self.api_process(fleet, report)

    def api_process(self, fleet: FleetStart, report: str) -> dict[str, Any]:
        """The process of a printed API job: running, the declared program, the enrolled account."""
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

    def stopped_guest_job(self, current: dict[str, Any], name: str) -> None:
        """Confirm a stopped API row against the actual vendor runtime jobs."""
        fleet = self.settings.fleet_start
        if fleet is not None:
            check_fleet_identity(fleet)
        handler = current["configuration"].get("runtimeHandler")
        if (
            not isinstance(handler, str)
            or _RUNTIME_HANDLER.fullmatch(handler) is None
            or current["configuration"].get("id") != name
        ):
            raise RuntimeReadError("identity-mismatch")
        label = f"{VENDOR_RUNTIME_PREFIX}{handler}.{name}"
        uid = self.settings.account.uid
        # ServiceManager chooses the registering process's current launchd domain.
        # A previous API incarnation can leave a job in any supported domain; the
        # current network helper is not evidence about that earlier incarnation.
        domains = ("system", f"gui/{uid}", f"user/{uid}")
        for domain in domains:
            if not self.job_absent(domain, label):
                raise RuntimeReadError("generation-mismatch")
        if self._domain_services is None:
            self._domain_services = self._read_domain_services()
        self._require_no_guest_job(self._domain_services, name)
        # Only successful absence proofs are watched. A failed workload does not
        # invalidate independent workloads that were observed successfully.
        self._absent_jobs.add(name)

    def _read_domain_services(self) -> dict[str, frozenset[str]]:
        uid = self.settings.account.uid
        return {
            domain: domain_services(self.tool(["/bin/launchctl", "print", domain]), domain)
            for domain in ("system", f"gui/{uid}", f"user/{uid}")
        }

    @staticmethod
    def _require_no_guest_job(services: dict[str, frozenset[str]], name: str) -> None:
        # Historical handlers need not match the current configuration's spelling
        # or remain installed. Their labels are live native service identities.
        # Dotted container names and dotted old handlers can be ambiguous; refuse
        # that ambiguity instead of decoding a reassuring but unproven handler.
        suffix = "." + name
        if any(
            label.startswith(VENDOR_RUNTIME_PREFIX)
            and label.endswith(suffix)
            and len(label) > len(VENDOR_RUNTIME_PREFIX) + len(suffix)
            for labels in services.values()
            for label in labels
        ):
            raise RuntimeReadError("generation-mismatch")

    def fence_absent_jobs(self) -> None:
        """Reread complete inventories after the other snapshot fences."""
        if self._absent_jobs:
            services = self._read_domain_services()
            for name in self._absent_jobs:
                self._require_no_guest_job(services, name)

    def runtime_job(self, fleet: FleetStart, start: RuntimeStart, domain: str) -> str:
        """The API job as the declared start loads it: `absent`, `idle` or `running`.

        A job that is loaded in any other way, with another launch file, program,
        argument or root, or in a state that is neither running nor exactly
        without a process, is none of the three.
        """
        if self.job_absent(domain, fleet.api_label):
            return "absent"
        report = self.tool(["/bin/launchctl", "print", f"{domain}/{fleet.api_label}"])
        if not _started_as_declared(report, fleet, start):
            raise RuntimeReadError("identity-mismatch")
        if (
            _JOB_IDLE.search(report) is not None
            and _JOB_RUNNING.search(report) is None
            and _JOB_PROCESS.search(report) is None
        ):
            return "idle"
        self.api_process(fleet, report)
        return "running"


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


def check_launch_file(
    settings: RuntimeSettings, fleet: FleetStart, start: RuntimeStart, reader: Reader
) -> None:
    """The reviewed launch file is in place and the start command would write it again.

    The vendor's start command writes its launch file anew on every run and takes
    the program from the directory of the command itself, with links resolved.
    A start is therefore permitted only where both are already what the settings
    declare: the supervisor then repeats a start that an operator made with these
    roots and never makes the first one. The file is a private single-link regular
    file of the enrolled account, read through one descriptor and compared member
    for member. A missing or different file is not the expected one.
    """
    try:
        sibling = Path(settings.executable).with_name("container-apiserver")
        if os.path.realpath(sibling, strict=True) != fleet.api_executable:
            raise RuntimeReadError("identity-mismatch")
        path = Path(_launch_path(start))
        meta = path.lstat()
        check_identity(
            FileIdentity(str(path), "file", settings.account.uid, meta.st_dev, meta.st_ino),
            deadline=reader.deadline,
            checked_acls=reader.checked_acls,
        )
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            if (
                _receipt_metadata(opened) != _receipt_metadata(meta)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) not in {0o600, 0o644}
                or not 0 < opened.st_size <= _LAUNCH_FILE_BYTES
            ):
                raise RuntimeReadError("identity-mismatch")
            data = b""
            while len(data) <= opened.st_size:
                chunk = os.read(fd, opened.st_size + 1 - len(data))
                if not chunk:
                    break
                data += chunk
            if (
                len(data) != opened.st_size
                or _receipt_metadata(os.fstat(fd)) != _receipt_metadata(opened)
                or _receipt_metadata(path.lstat()) != _receipt_metadata(opened)
            ):
                raise RuntimeReadError("identity-mismatch")
        finally:
            os.close(fd)
    except OSError as exc:
        raise RuntimeReadError("identity-mismatch") from exc
    if not _same_members(_decoded_launch_file(data), _launch_dictionary(fleet, start)):
        raise RuntimeReadError("identity-mismatch")


def _listed_home(uid: int) -> str | None:
    """The home directory the user database names for this account, if it names one."""
    # Imported here and not above: the root forwarding owner lists the files it has
    # imported before it imports this module, and it never asks this question.
    import pwd

    try:
        return pwd.getpwuid(uid).pw_dir or None
    except KeyError:
        return None


def _whole_file(path: str) -> bytes | None:
    """The bytes of the regular file with exactly this name; None where nothing has the name.

    One bounded read through one descriptor. A symbolic link at the final name
    is not followed, and neither a link nor a directory, another kind of object
    or a file beyond the bound is a file this returns.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeReadError("identity-mismatch")
        data = b""
        while len(data) <= _CONFIGURATION_BYTES:
            chunk = os.read(fd, _CONFIGURATION_BYTES + 1 - len(data))
            if not chunk:
                return data
            data += chunk
        raise RuntimeReadError("identity-mismatch")
    finally:
        os.close(fd)


def check_configuration(settings: RuntimeSettings, start: RuntimeStart) -> None:
    """The vendor's start command would leave the runtime's configuration as it is.

    Before anything else that command copies the account's own configuration
    file over the copy below the application root, and returns without touching
    that copy where the account has no such file (apple/container
    `ConfigurationLoader.copyConfigurationToReadOnly`, called first by
    `SystemStart.run`; the same at tags 1.2.0, 1.4.1 and 1.5.0). A start by the
    supervisor must not change the configuration. The account's file is
    therefore absent, or it equals that copy byte for byte; a copy that is
    missing would be created, so it is not equal. The command looks below the
    account's home, since the runner's closed environment names no other place.
    That home is the entry of the user database, and the `HOME` variable only
    without one (`CFPlatform.c` of CF-1153.18, the last CoreFoundation Apple
    published); the runner passes the enrolled home as `HOME`, so both are read
    and neither is preferred. Nothing of either file leaves this function.
    """
    homes = {settings.account.home, _listed_home(settings.account.uid) or settings.account.home}
    try:
        for home in sorted(homes):
            own = _whole_file(f"{home}/.config/container/config.toml")
            if own is not None and own != _whole_file(f"{start.app_root}/config/config.toml"):
                raise RuntimeReadError("identity-mismatch")
    except OSError as exc:
        raise RuntimeReadError("identity-mismatch") from exc


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
    reader: Reader,
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
            # Only a mount with a host path can be a second writer of one. That a
            # memory-backed mount has none is known for a peer that names the
            # vendor's Linux runtime; under another handler, or without the
            # member, every mount of the peer is compared.
            guest_memory = peer["configuration"].get("runtimeHandler") == _LINUX_RUNTIME
            for other, other_writable in _mounts(
                peer["configuration"], without_guest_memory=guest_memory
            ):
                if not other_writable:
                    continue
                overlapping = (
                    source == other
                    or source.startswith(other.rstrip("/") + "/")
                    or other.startswith(source.rstrip("/") + "/")
                )
                aliased = (
                    os.path.exists(other)
                    and os.path.exists(source)
                    and os.path.samefile(other, source)
                )
                if not overlapping and not aliased:
                    continue
                # An API restart can report stopped while the peer's job survives.
                # Only independent service-manager evidence permits this exception.
                if peer["id"] in contract.tolerated_stopped_peers and peer["state"] == "stopped":
                    reader.stopped_guest_job(peer, peer["id"])
                else:
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
        reader.stopped_guest_job(current, contract.name)
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
        if settings.fleet_start is not None:
            check_fleet_identity(settings.fleet_start)
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
                    reader=reader,
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
        reader.fence_absent_jobs()
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


def _private_json(path: str) -> Any:
    """One of this owner's own records, by the rule of the state store.

    The store keeps intent and admissions in a directory of mode 0700 that its
    user owns and that is no symbolic link, as regular files of mode 0600 with
    one link, owned by that user. It writes into no other directory and
    replaces no other file, so a record in any other place or form can take
    neither a pause nor an admission, and it is not read here either. The
    directory is held to the store's own check and the record is opened
    relative to the checked directory, without following a symbolic link at
    either name; another type, owner, mode or link count is refused. Nothing
    is created and no lock is taken.
    """
    directory, name = os.path.split(path)
    parent = os.open(directory, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        try:
            # One rule, not two: what the store requires of a directory it writes into.
            Store._check_directory_info(os.fstat(parent))
        except UnsafeState as exc:
            raise ValueError("runtime intent and admissions need a private directory") from exc
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise ValueError("runtime intent and admissions must be private regular files")
            with os.fdopen(os.dup(fd), "rb") as stream:
                return strict_loads(stream.read(1_048_577))
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _intent(settings: RuntimeSettings) -> Intent:
    if settings.state_dir is None or settings.intent != str(
        Path(settings.state_dir) / "intent.json"
    ):
        # Operator pause/unhold and recovery must share one record and lock.
        # A different private unpaused file is not evidence of operator intent.
        return Intent(damaged=True)
    try:
        intent = intent_from_dict(_private_json(settings.intent))
    except (ValueError, OSError):
        return Intent(damaged=True)
    # A hold on a service that is not enrolled here inhibits every workload.
    return attribute_holds(intent, {contract.service for contract in settings.contracts})


def _stored_enrollment(settings: RuntimeSettings) -> bytes:
    """The bytes `enroll` writes for these settings, read back as the loader reads them.

    `load_settings` parses exactly these bytes, the final newline included, so its
    size bound is judged on the stored form. Raises the loader's `ValueError`.
    """
    payload = (canonical_json(settings_to_dict(settings)) + "\n").encode()
    parse_settings(strict_loads(payload))
    return payload


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
            if kind == "other":
                # A pipe, a device or a link. The settings loader reads three
                # kinds only: this one would be stored and never loaded again.
                raise RuntimeReadError("identity-mismatch")
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
    captured = replace(settings, contracts=tuple(contracts))
    # An enrollment is what the settings loader reads from the stored bytes. A
    # mount source that is no canonical absolute path, more identities than a
    # contract may list, or more bytes than the loader takes would be written
    # and then refused by every later command.
    try:
        _stored_enrollment(captured)
    except ValueError as exc:
        raise RuntimeReadError("identity-mismatch") from exc
    return captured


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


def _recorded_starts(store: Store) -> dict[str, list[int]] | None:
    """Starts on record per service, or nothing when the record says nothing.

    No file is the empty record. Content that is not exactly the closed shape
    below, and a file the store refuses, tell nothing about any workload; the
    caller counts that as a spent budget, never as an unused one. A file that
    could not be read at all is no content: that error is left to the caller,
    which starts nothing on it and changes nothing.
    """
    try:
        raw = store.read(STARTS_RECORD)
    except FileNotFoundError:
        return {}
    except (ValueError, UnsafeState):
        return None
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "services"}
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or not isinstance(raw["services"], dict)
        or len(raw["services"]) > 256
    ):
        return None
    services: dict[str, list[int]] = raw["services"]
    for service, entries in services.items():
        if (
            _RECORDED_SERVICE.fullmatch(service) is None
            or not isinstance(entries, list)
            or not 1 <= len(entries) <= _RECORDED_STARTS_MAXIMUM
            or any(type(entry) is not int or not 0 <= entry < _CLOCK_LIMIT for entry in entries)
        ):
            return None
    return services


def _spend_start(
    store: Store,
    settings: RuntimeSettings,
    budget: RestartBudget,
    service_id: str,
    wall: Callable[[], float],
) -> None:
    """Record the start that is about to be issued, or hold the service instead.

    Called under the operation lock for a workload that was proven stopped
    twice. A return means that one more start is inside the budget and is on
    record. Otherwise nothing is started: the service is held, its record is
    cleared so that the operator's `unhold` gives a whole budget again, and the
    recovery ends like one that a hold refused. A record that could not be read
    ends the recovery the same way, with nothing held and nothing rewritten.
    """
    enrolled = {contract.service for contract in settings.contracts}
    try:
        now = wall()
        # A usable time fits an entry of the record. Comparing decides that for
        # every number: one that is not finite, or an integer beyond every
        # float, is outside and is never converted.
        timed = type(now) in {int, float} and 0 <= now < _CLOCK_LIMIT
        recorded = _recorded_starts(store)
        if recorded is not None and timed:
            # An entry that lies in the future is inside the window: a clock that
            # was set back keeps the brake engaged and never releases it.
            inside = [
                entry
                for entry in recorded.get(service_id, [])
                if now - entry < budget.window_seconds
            ]
            if len(inside) < budget.starts:
                kept = {key: value for key, value in recorded.items() if key in enrolled}
                # Rounded up to a whole second: the window of this start never
                # ends early, and at most one second late.
                kept[service_id] = [*inside, math.ceil(now)]
                store.write(STARTS_RECORD, {"schema_version": 1, "services": kept})
                return
        # The hold is stored first: a crash between the two writes leaves the
        # brake engaged, at the price of one more hold after the release.
        try:
            intent = intent_from_dict(store.read("intent.json"))
            intent = intent.hold(service_id, RESTART_BUDGET_OPERATION, RESTART_BUDGET_HOLDER)
            store.write("intent.json", intent_to_dict(intent))
        except (OSError, ValueError, UnsafeState):
            if recorded is not None:
                # Not held. A spent budget must not come back with time: the
                # record of this service is stored so that it counts as spent
                # at every time and under every budget, until a hold is stored,
                # which clears it.
                pinned = {key: value for key, value in recorded.items() if key in enrolled}
                pinned[service_id] = [_CLOCK_LIMIT - 1] * _RECORDED_STARTS_MAXIMUM
                store.write(STARTS_RECORD, {"schema_version": 1, "services": pinned})
            raise
        if recorded is not None:
            cleared = {key: value for key, value in recorded.items() if key in enrolled}
            cleared.pop(service_id, None)
            store.write(STARTS_RECORD, {"schema_version": 1, "services": cleared})
        elif timed:
            # Nothing is known about the other workloads either: each counts as
            # spent for one period from now on. Without a usable clock the
            # record stays as unreadable as it is.
            spent = {key: [math.ceil(now)] * budget.starts for key in enrolled - {service_id}}
            store.write(STARTS_RECORD, {"schema_version": 1, "services": spent})
    except (OSError, ValueError, UnsafeState) as exc:
        # Not read, not recorded or not held: nothing is started on that.
        raise RuntimeReadError("incomplete") from exc
    raise RuntimeReadError("incomplete")


def recover_service(
    config: Config,
    settings: RuntimeSettings,
    service_id: str,
    runner: Runner = run,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    wall: Callable[[], float] = time.time,
) -> Snapshot:
    """Monit recovery is only a start of a twice-proven stopped enrolled guest.

    Where the settings state a restart budget and the guest has spent it, the
    start is replaced by a hold on its service.
    """
    if os.geteuid() == 0 or os.geteuid() != settings.account.uid or settings.state_dir is None:
        raise PermissionError("workload recovery belongs to the enrolled user")
    budget = settings.restart_budget
    if budget is not None and settings.intent != str(Path(settings.state_dir) / "intent.json"):
        # The loader refuses such settings; settings built in code end here.
        raise ValueError("a restart budget needs the durable intent in the state directory")
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
        if budget is not None:
            # An issued start counts whatever becomes of it, so it is on record
            # before the call. A spent budget ends here, with a hold and no start.
            _spend_start(store, settings, budget, service_id, wall)
        # Only this call may take longer than a read, and only when the settings
        # say how long: the workload's own bound, else the installation's, else
        # the reader's. Its result is checked like every other vendor call.
        bound = contract.start_timeout_seconds
        if bound is None:
            bound = settings.start_timeout_seconds
        Reader(settings, runner).native(["start", contract.name], timeout=bound)
        # A successful CLI exit is never the final readiness assertion.
        result = observe_runtime(config, settings, runner)
        if result.services[service_id].state != "present":
            raise RuntimeReadError("incomplete")
        return result


def _declared_start(settings: RuntimeSettings) -> tuple[FleetStart, RuntimeStart, str]:
    """The declaration, and the one domain the enrolled account's start loads into."""
    fleet = settings.fleet_start
    if fleet is None or fleet.runtime_start is None:
        raise ValueError("the settings declare no start of the vendor runtime")
    check_fleet_identity(fleet)
    uid = settings.account.uid
    if os.geteuid() == 0 or os.geteuid() != uid:
        raise PermissionError("the vendor runtime belongs to the enrolled user")
    # The loader refuses anything else; settings built without it are refused again.
    if {network.helper_domain for network in settings.networks} != {f"gui/{uid}"}:
        raise RuntimeReadError("identity-mismatch")
    return fleet, fleet.runtime_start, f"gui/{uid}"


def runtime_state(settings: RuntimeSettings, runner: Runner = run) -> str:
    """What the supervisor may do about the vendor runtime.

    `running`: the API job is the declared one and has its process; nothing to
    do. `absent`: the service manager says the job is not loaded and every
    condition of a start holds. `idle`: the declared job is loaded without a
    process and the same conditions hold. Everything else is unknown and raises.
    """
    fleet, start, domain = _declared_start(settings)
    reader = Reader(settings, runner)
    job = reader.runtime_job(fleet, start, domain)
    if job == "running":
        return job
    # From here on a call would start something, so each condition is read first.
    reader.version()
    check_launch_file(settings, fleet, start, reader)
    check_configuration(settings, start)
    # Earlier API instances may have registered in either other supported
    # domain. Neither a loaded job nor an unavailable read proves absence.
    for other_domain in ("system", f"user/{settings.account.uid}"):
        if not reader.job_absent(other_domain, fleet.api_label):
            raise RuntimeReadError("generation-mismatch")
    if job == "absent":
        # "No such job" is evidence only while the domain itself answers.
        listing = reader.runner(
            ["/bin/launchctl", "print", domain], timeout=reader.remaining(3), max_output=4_194_304
        )
        if listing.returncode or not listing.stdout or listing.stderr:
            raise RuntimeReadError("unavailable")
    # The vendor's command loads into the domain of the session that runs it
    # (`ServiceManager.getDomainString`): only this answer is the declared one.
    if reader.tool(["/bin/launchctl", "managername"]).strip() != "Aqua":
        raise RuntimeReadError("identity-mismatch")
    if _label_disabled(reader.tool(["/bin/launchctl", "print-disabled", domain]), fleet.api_label):
        raise RuntimeReadError("incomplete")
    return job


def start_runtime(
    settings: RuntimeSettings,
    runner: Runner = run,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    """The supervisor's start of the vendor runtime: one call after a twice-read state.

    An absent job gets the vendor's own start command, with both roots given as
    options and as environment and with the kernel prompt disabled. A declared
    job that is loaded without a process gets the vendor's status request, which
    makes the service manager run it and writes nothing. No workload is started
    and nothing is ever unloaded, stopped or repaired.
    """
    fleet, start, domain = _declared_start(settings)
    if settings.state_dir is None:
        raise PermissionError("the vendor runtime belongs to the enrolled user")
    store = Store(Path(settings.state_dir))
    with _state_lock(store, clock, sleep):
        before = runtime_state(settings, runner)
        if _intent(settings).blocked or before == "running":
            raise RuntimeReadError("incomplete")
        fresh = runtime_state(settings, runner)
        if fresh != before or _intent(settings).blocked:
            raise RuntimeReadError("generation-mismatch")
        arguments = ["system", "status"]
        if before == "absent":
            arguments = ["system", "start", "--app-root", start.app_root]
            arguments += ["--install-root", start.install_root, "--disable-kernel-install"]
        called = runner(
            [settings.executable, *arguments],
            timeout=start.timeout_seconds or RUNTIME_START_TIMEOUT_SECONDS,
            run_uid=settings.account.uid,
            run_gid=settings.account.gid,
            account_home=settings.account.home,
            environment={_APP_ROOT: start.app_root, _INSTALL_ROOT: start.install_root},
        )
        # The vendor's command logs to standard error when it succeeds, so only
        # its status is read; and a successful exit is never the final statement.
        if called.returncode:
            raise RuntimeReadError("unavailable")
        reader = Reader(settings, runner)
        check_launch_file(settings, fleet, start, reader)
        if reader.runtime_job(fleet, start, domain) != "running":
            raise RuntimeReadError("incomplete")
        reader.inventory()
        return "started" if before == "absent" else "activated"


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
    # This endpoint answers the owner protocol, whose clients wait ten seconds
    # for it. Its reads keep the bound that fits into those: a longer read would
    # be cut off from outside instead of ending as unknown by itself.
    reading = replace(settings, read_timeout_seconds=None)
    if request.get("operation") == "observe":
        if set(request) != {"protocol_version", "operation", "owner", "config"} or config_digest(
            parse_config(canonical_bytes(request["config"]))
        ) != config_digest(config):
            raise ValueError("runtime policy differs from installed policy")
        full = observe_runtime(config, reading, runner)
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
        snapshot = observe_runtime(config, reading, runner)
        observed = snapshot.profiles[profile.id]
        # Native published sockets are part of the workload definition. The
        # networking executor must never stop or recreate an application to
        # remove one. Explicit maintenance provisioning owns such a change.
        if request["action"] in {"withdraw", "drain"}:
            raise NativePublicationMaintenance("incomplete")
        if request["action"] != "activate" or settings.admissions is None:
            raise ValueError("unsupported native publication operation")
        admitted = admissions_from_dict(_private_json(settings.admissions)).get(profile.id)
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


class _Reading(argparse.ArgumentParser):
    """This module's command line for a caller that only asks what it says.

    Arguments that `main` would refuse, or answer with its help, raise here.
    Nothing is printed and the process is not ended.
    """

    def error(self, message: str) -> NoReturn:
        raise ValueError(message)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        raise ValueError("the command line names no command to run")

    def print_help(self, file: Any = None) -> None:
        return None


def _command_line(
    factory: type[argparse.ArgumentParser] = argparse.ArgumentParser,
) -> argparse.ArgumentParser:
    parser = factory(description=__doc__)
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
    commands.add_parser("runtime-probe")
    commands.add_parser("runtime-start")
    return parser


def probe_settings(arguments: Sequence[str]) -> str | None:
    """The settings file that these arguments make this module read as a probe.

    The workload probe and the runtime probe both read through one reader with
    the bound of those settings. None for every other command and for arguments
    that `main` would refuse. They are read with the parser `main` uses, so
    every spelling that `main` accepts is the same command here. Nothing is
    opened and nothing is run.
    """
    try:
        args = _command_line(_Reading).parse_args(list(arguments))
    except ValueError:
        return None
    return str(args.settings) if args.command in {"probe", "runtime-probe"} else None


def main(argv: list[str] | None = None) -> int:
    args = _command_line().parse_args(argv)
    try:
        if args.command == "start":
            require_mutation_qualified("workload-recovery")
        if args.command == "runtime-start":
            require_mutation_qualified("runtime-start")
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
            # Written are the very bytes the settings loader has just read back: a
            # payload it refuses ends here, before the output file exists.
            payload = _stored_enrollment(enrolled)
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
        if args.command == "runtime-probe":
            # Like the workload probe: 42 alone lets the supervisor run the start.
            state = runtime_state(settings)
            if _intent(settings).blocked:
                return UNKNOWN
            return 0 if state == "running" else STOPPED
        if args.command == "runtime-start":
            print(canonical_json({"runtime": start_runtime(settings)}))
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
    except (ValueError, OSError, RuntimeReadError, ProcessTimeout, OutputLimit, UnsafeState):
        print(
            canonical_json({"error": "runtime-evidence-or-authority-incomplete"}), file=sys.stderr
        )
        return UNKNOWN


if __name__ == "__main__":
    raise SystemExit(main())

"""Private, data-only Apple runtime enrollment and reader settings."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .codec import canonical_bytes, digest, strict_load, strict_loads

_ID = re.compile(r"[a-z][a-z0-9-]*\Z")
_JOB_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_JOB_LABEL_PREFIX = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,95}\.\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_VERSIONS = {"1.2.0", "1.4.1", "1.5.0"}
# The vendor's own container-name rule (apple/container `ManagedContainer.nameValid`,
# the same at tags 1.2.0, 1.4.1 and 1.5.0): any name its inventory can hold.
_PEER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,62}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


@dataclass(frozen=True, slots=True)
class RuntimeAccount:
    uid: int
    gid: int
    home: str


@dataclass(frozen=True, slots=True)
class FileIdentity:
    path: str
    kind: str
    uid: int
    device: int | None = None
    inode: int | None = None
    sha256: str | None = None
    # Binds the volume itself instead of `device`, which is assigned at mount time.
    volume_uuid: str | None = None


@dataclass(frozen=True, slots=True)
class RuntimeContract:
    service: str
    name: str
    scope: str
    configuration_sha256: str
    mounts: tuple[FileIdentity, ...]
    receipts: tuple[FileIdentity, ...] = ()
    # Other definitions over the same writable path that are accepted while the
    # inventory reports them exactly stopped. Empty unless a site enrolls one.
    tolerated_stopped_peers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuntimeNetwork:
    scope: str
    name: str
    gateway: str
    helper_domain: str
    helper_label: str
    helper_executable: str
    helper_uid: int


@dataclass(frozen=True, slots=True)
class FleetStart:
    """Service-manager evidence that lets a fully stopped fleet be read as stopped.

    Without this declaration an inventory in which every guest is stopped stays
    unknown. With it, a stopped guest is absent only while the vendor API job is
    the declared one and the service manager has no runtime job for that guest.
    """

    api_label: str
    api_executable: str
    runtime_label_prefix: str


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    schema_version: int
    owner: str
    executable: str
    accepted_version: str
    account: RuntimeAccount
    networks: tuple[RuntimeNetwork, ...]
    contracts: tuple[RuntimeContract, ...]
    policy: str | None = None
    admissions: str | None = None
    intent: str | None = None
    state_dir: str | None = None
    legacy_risk_acknowledged: bool = False
    # Bound of the vendor `start` call in recovery; unset keeps the reader's own.
    start_timeout_seconds: int | None = None
    fleet_start: FleetStart | None = None

    @classmethod
    def from_dict(cls, value: Any) -> RuntimeSettings:
        return parse_settings(value)

    def contract(self, service: str) -> RuntimeContract:
        for contract in self.contracts:
            if contract.service == service:
                return contract
        raise ValueError("service has no runtime contract")


def _contract_dict(contract: RuntimeContract) -> dict[str, Any]:
    """Canonical form; an empty tolerance list and an identity without a volume
    binding are left out, so earlier digests hold."""
    value = asdict(contract)
    if not value["tolerated_stopped_peers"]:
        del value["tolerated_stopped_peers"]
    for identity in (*value["mounts"], *value["receipts"]):
        if identity["volume_uuid"] is None:
            del identity["volume_uuid"]
    return value


def contract_digest(contract: RuntimeContract) -> str:
    """No raw application configuration or credentials enter the network policy."""
    # A device-bound contract hashes exactly as before. One that binds a volume
    # is a second form of the enrollment and can never share a digest with it.
    volume_bound = any(
        identity.volume_uuid is not None for identity in (*contract.mounts, *contract.receipts)
    )
    strategy = "apple-runtime-enrollment-v2" if volume_bound else "apple-runtime-enrollment-v1"
    return digest({"strategy": strategy, "contract": _contract_dict(contract)})


def _object(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or not required <= set(value)
        or set(value) - required - (optional or set())
    ):
        raise ValueError("invalid runtime settings object")
    return value


def _path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "\0" in value
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise ValueError("runtime path must be absolute and canonical")
    return value


def _identity(value: Any) -> FileIdentity:
    data = _object(value, {"path", "kind", "uid"}, {"device", "inode", "sha256", "volume_uuid"})
    if (
        not isinstance(data["kind"], str)
        or data["kind"] not in {"directory", "file", "socket"}
        or type(data["uid"]) is not int
        or data["uid"] < 0
    ):
        raise ValueError("invalid runtime file identity")
    volume = None
    if "volume_uuid" in data:
        # One spelling per meaning: the key is left out when unused, never null.
        volume = data["volume_uuid"]
        if (
            not isinstance(volume, str)
            or not _UUID.fullmatch(volume)
            or volume == "00000000-0000-0000-0000-000000000000"
            or data["kind"] == "socket"
            or data.get("device") is not None
        ):
            raise ValueError("a volume-bound identity names one volume and no device")
    bound = ("inode",) if volume is not None else ("device", "inode")
    if data["kind"] != "socket" and any(
        type(data.get(key)) is not int or data[key] < 0 for key in bound
    ):
        raise ValueError("persistent identities must bind an inode and a device or a volume")
    if any(
        data.get(key) is not None and (type(data[key]) is not int or data[key] < 0)
        for key in ("device", "inode")
    ):
        raise ValueError("invalid optional identity")
    if data.get("sha256") is not None and (
        not isinstance(data["sha256"], str) or not _HASH.fullmatch(data["sha256"])
    ):
        raise ValueError("invalid receipt hash")
    return FileIdentity(
        _path(data["path"]),
        data["kind"],
        data["uid"],
        data.get("device"),
        data.get("inode"),
        data.get("sha256"),
        volume,
    )


def parse_settings(value: Any) -> RuntimeSettings:
    data = _object(
        value,
        {
            "schema_version",
            "owner",
            "executable",
            "accepted_version",
            "account",
            "networks",
            "contracts",
        },
        {
            "policy",
            "admissions",
            "intent",
            "state_dir",
            "legacy_risk_acknowledged",
            "start_timeout_seconds",
            "fleet_start",
        },
    )
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or not isinstance(data["owner"], str)
        or not _ID.fullmatch(data["owner"])
    ):
        raise ValueError("unsupported runtime settings")
    if not isinstance(data["accepted_version"], str) or data["accepted_version"] not in _VERSIONS:
        raise ValueError("runtime version lacks a reader contract")
    legacy = data.get("legacy_risk_acknowledged", False)
    if type(legacy) is not bool or (data["accepted_version"] == "1.2.0" and not legacy):
        raise ValueError("legacy runtime requires explicit risk acknowledgment")
    # One spelling per meaning: the key is left out when unused, never null.
    start_timeout = data.get("start_timeout_seconds")
    if "start_timeout_seconds" in data and (
        type(start_timeout) is not int or not 1 <= start_timeout <= 120
    ):
        raise ValueError("start timeout must be a whole number of seconds from 1 to 120")
    account = _object(data["account"], {"uid", "gid", "home"})
    if (
        type(account["uid"]) is not int
        or account["uid"] <= 0
        or type(account["gid"]) is not int
        or account["gid"] < 0
    ):
        raise ValueError("runtime account must be unprivileged")
    networks = []
    if not isinstance(data["networks"], list) or not 1 <= len(data["networks"]) <= 32:
        raise ValueError("invalid runtime networks")
    for raw in data["networks"]:
        item = _object(
            raw,
            {
                "scope",
                "name",
                "gateway",
                "helper_domain",
                "helper_label",
                "helper_executable",
                "helper_uid",
            },
        )
        if any(
            not isinstance(item[key], str)
            or not item[key]
            or "\n" in item[key]
            or "\0" in item[key]
            for key in ("scope", "name", "gateway", "helper_domain", "helper_label")
        ):
            raise ValueError("invalid network identity")
        if (
            item["helper_domain"] not in {"system", f"gui/{account['uid']}"}
            or type(item["helper_uid"]) is not int
            or item["helper_uid"] < 0
        ):
            raise ValueError("invalid helper ownership")
        networks.append(
            RuntimeNetwork(
                item["scope"],
                item["name"],
                item["gateway"],
                item["helper_domain"],
                item["helper_label"],
                _path(item["helper_executable"]),
                item["helper_uid"],
            )
        )
    contracts = []
    if not isinstance(data["contracts"], list) or not 1 <= len(data["contracts"]) <= 256:
        raise ValueError("invalid runtime contracts")
    for raw in data["contracts"]:
        item = _object(
            raw,
            {"service", "name", "scope", "configuration_sha256", "mounts"},
            {"receipts", "tolerated_stopped_peers"},
        )
        if (
            any(
                not isinstance(item[key], str) or not _ID.fullmatch(item[key])
                for key in ("service", "name", "scope")
            )
            or not isinstance(item["configuration_sha256"], str)
            or not _HASH.fullmatch(item["configuration_sha256"])
        ):
            raise ValueError("invalid runtime contract")
        if any(
            not isinstance(item.get(key, []), list) or len(item.get(key, [])) > 128
            for key in ("mounts", "receipts")
        ):
            raise ValueError("invalid runtime identities")
        peers = item.get("tolerated_stopped_peers", [])
        if (
            not isinstance(peers, list)
            or len(peers) > 16
            or any(not isinstance(peer, str) or not _PEER.fullmatch(peer) for peer in peers)
            or peers != sorted(set(peers))
        ):
            raise ValueError("invalid tolerated stopped peers")
        contracts.append(
            RuntimeContract(
                item["service"],
                item["name"],
                item["scope"],
                item["configuration_sha256"],
                tuple(_identity(entry) for entry in item["mounts"]),
                tuple(_identity(entry) for entry in item.get("receipts", [])),
                tuple(peers),
            )
        )
    for values in (
        [item.scope for item in networks],
        [item.service for item in contracts],
        [item.name for item in contracts],
    ):
        if len(values) != len(set(values)):
            raise ValueError("duplicate runtime identities")
    if any(contract.scope not in {item.scope for item in networks} for contract in contracts):
        raise ValueError("runtime contract has no network")
    # A tolerated peer is a definition this installation does not manage: an
    # enrolled workload can be started by recovery and is never tolerated.
    if {peer for item in contracts for peer in item.tolerated_stopped_peers} & {
        item.name for item in contracts
    }:
        raise ValueError("a tolerated stopped peer cannot be an enrolled workload")
    paths = {
        key: _path(data[key]) if data.get(key) is not None else None
        for key in ("policy", "admissions", "intent", "state_dir")
    }
    fleet = None
    if "fleet_start" in data:
        # Present means declared. An explicit null is not a second way to leave it out.
        item = _object(data["fleet_start"], {"api_label", "api_executable", "runtime_label_prefix"})
        if (
            not isinstance(item["api_label"], str)
            or not _JOB_LABEL.fullmatch(item["api_label"])
            or not isinstance(item["runtime_label_prefix"], str)
            or not _JOB_LABEL_PREFIX.fullmatch(item["runtime_label_prefix"])
        ):
            raise ValueError("invalid fleet start declaration")
        # That one domain is where the API job and the runtime jobs are looked up.
        if len({network.helper_domain for network in networks}) != 1:
            raise ValueError("fleet start needs one helper domain")
        fleet = FleetStart(
            item["api_label"], _path(item["api_executable"]), item["runtime_label_prefix"]
        )
    return RuntimeSettings(
        1,
        data["owner"],
        _path(data["executable"]),
        data["accepted_version"],
        RuntimeAccount(account["uid"], account["gid"], _path(account["home"])),
        tuple(networks),
        tuple(contracts),
        **paths,
        legacy_risk_acknowledged=legacy,
        start_timeout_seconds=start_timeout,
        fleet_start=fleet,
    )


def load_settings(path: Path | str) -> RuntimeSettings:
    return parse_settings(strict_load(path))


def settings_to_dict(settings: RuntimeSettings) -> dict[str, Any]:
    value = asdict(settings)
    value["contracts"] = [_contract_dict(item) for item in settings.contracts]
    if value["start_timeout_seconds"] is None:
        # Left out while unset: settings stored before the key existed keep their bytes.
        del value["start_timeout_seconds"]
    result: dict[str, Any] = strict_loads(canonical_bytes(value))
    # Left out while undeclared: settings without it keep their bytes and digests.
    if result["fleet_start"] is None:
        del result["fleet_start"]
    return result

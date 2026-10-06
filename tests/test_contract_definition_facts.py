"""A workload contract can state the facts of a real definition, each in one spelling."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from netorch.codec import canonical_bytes, strict_loads
from netorch.host_report import build_report, empty_evidence, verify_contracts
from netorch.instance import (
    instance_contract_digest,
    load_instance,
    parse_instance,
    resolved_discovery_digest,
    resolved_profile_digest,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
Change = Callable[[dict[str, Any]], Any]
# Taken from the tree before the contract schema was widened.
BASE_CONTRACTS = {
    "example-media.json": "733e7f593484fb0df8c51f2af583be8922af3d528cb84736e072b282754cf5a0",
    "example-structural.json": "c8dca430700c180e31dcd60a853bd34e6bbbd2ae9f9661738ae09ffebeb641c5",
    "example-web.json": "a8cf1fc0b73c43ee7e0cabd93f3bccb7b7e8361127e6de54075c65f2fca26dff",
}
BASE_INSTANCES = {
    "instance.json": {
        "contract": "bc7d92900c617507a7d1dfe150df3600fff3d5ad29c1a0a72b467779f16f7a9c",
        "resolved": {
            "example-publication": (
                "c4a4f20fb44b4b46fcbdffd4b2a4205c4149faf106208260fe69ecc9dde88425"
            ),
            "example-return": "080ed8c0a2d16eb4e54110730ed205c4aee77d117c4c8c6facb490c23780a208",
            "example-export": "a87cb58580aef982e565caa79bb489da0f3996ac5e1c3c45709c3811c6f1ff86",
            "example-import": "3a399f2f69074be0231e436d0902815936a10c506b77ec7c6cdf609e002c7af3",
        },
    },
    "instance-structural.json": {
        "contract": "6489191df8f66f366323fcd61091c69a45bc2676f5f215e25f6a218674a3fa5e",
        "resolved": {
            "example-publication": (
                "d9e1f0bbf592e18a6a6ff88177539f55f092748a84953a4eba984390401e24b4"
            ),
            "example-export": "397d48b2f0097fe344366050efc7ff1ffa9e9178445189ed3d8819c3c766e54d",
        },
    },
}
# Every name the vendor library knows at both reviewed tags, in ascending order.
VENDOR_CAPABILITIES = [
    "CAP_AUDIT_CONTROL",
    "CAP_AUDIT_READ",
    "CAP_AUDIT_WRITE",
    "CAP_BLOCK_SUSPEND",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_KILL",
    "CAP_LEASE",
    "CAP_LINUX_IMMUTABLE",
    "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE",
    "CAP_MKNOD",
    "CAP_NET_ADMIN",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_RAW",
    "CAP_PERFMON",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYSLOG",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_CHROOT",
    "CAP_SYS_MODULE",
    "CAP_SYS_NICE",
    "CAP_SYS_PACCT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_WAKE_ALARM",
]
IMAGE = "example.invalid/example-web@sha256:"
VOLUME = {"volume": "example_data", "destination": "/data", "read_only": False}


def helpers() -> Any:
    # Imported on use, so that on a tree without the module this file still collects
    # and each test fails or passes on its own.
    return importlib.import_module("netorch.workload_contract")


def instance_data() -> dict[str, Any]:
    return json.loads((EXAMPLES / "instance.json").read_bytes())


def rewritten(directory: Path, change: Change) -> tuple[Any, bytes]:
    """Rewrite the first example contract and return the instance that pins the result."""
    if (directory / "contracts").exists():
        shutil.rmtree(directory / "contracts")
    shutil.copytree(EXAMPLES / "contracts", directory / "contracts")
    data = instance_data()
    target = directory / data["workloads"][0]["contract"]["data_path"]
    document = json.loads(target.read_bytes())
    change(document)
    raw = canonical_bytes(document) + b"\n"
    target.write_bytes(raw)
    data["workloads"][0]["contract"]["sha256"] = hashlib.sha256(raw).hexdigest()
    return parse_instance(canonical_bytes(data) + b"\n"), raw


def state(directory: Path, change: Change) -> str:
    """How verification of the rewritten first example contract ends."""
    instance, _ = rewritten(directory, change)
    return str(verify_contracts(instance, directory)[0]["state"])


def stated(member: str, value: Any) -> Change:
    return lambda document: document.update({member: value})


def volume_only(mount: dict[str, Any], recovery_class: str = "named-volume") -> Change:
    return lambda document: document.update(mounts=[mount], recovery_class=recovery_class)


def all_digests(instance: Any) -> dict[str, str]:
    return {
        **{item.id: resolved_profile_digest(instance, item) for item in instance.transport},
        **{item.id: resolved_discovery_digest(instance, item) for item in instance.discovery},
    }


def test_checked_in_contracts_keep_their_bytes_hashes_and_every_digest() -> None:
    files = sorted((EXAMPLES / "contracts").glob("*.json"))
    assert {
        item.name: hashlib.sha256(item.read_bytes()).hexdigest() for item in files
    } == BASE_CONTRACTS
    for name, expected in BASE_INSTANCES.items():
        instance = load_instance(EXAMPLES / name)
        rows = verify_contracts(instance, EXAMPLES)
        assert [(row["state"], row["reason"]) for row in rows] == [("present", "complete")] * len(
            instance.workloads
        )
        assert {row["sha256"] for row in rows} <= set(BASE_CONTRACTS.values())
        assert instance_contract_digest(instance) == expected["contract"]
        assert all_digests(instance) == expected["resolved"]


def test_unchanged_document_is_present_and_unknown_keys_stay_refused(tmp_path: Path) -> None:
    assert state(tmp_path, lambda document: None) == "present"
    # Environment and an executable command stay outside, as values and under any name.
    for member, value in (
        ("environment", {"EXAMPLE": "value"}),
        ("environment_sha256", "3" * 64),
        ("entrypoint", ["/bin/example"]),
        ("command", ["--serve"]),
        ("init_process", {"executable": "/bin/example", "arguments": []}),
        ("kernel", "/example/kernel"),
        ("kernel_arguments", ["quiet"]),
    ):
        assert state(tmp_path, stated(member, value)) == "unknown"
    # An optional fact that does not apply is left out; null is not a second spelling.
    for member in ("capabilities", "kernel_sha256", "init_process_sha256", "image_alternates"):
        assert state(tmp_path, stated(member, None)) == "unknown"
    assert state(tmp_path, stated("schema_version", 2)) == "unknown"


def test_unset_mtu_has_exactly_one_spelling(tmp_path: Path) -> None:
    def mtu(value: Any) -> Change:
        return lambda document: document["network"].update(mtu=value)

    assert state(tmp_path, mtu(None)) == "present"
    for value in (576, 1280, 9000):
        assert state(tmp_path, mtu(value)) == "present"
    for value in (0, 575, 9001, "1280", 1280.0, False, [], {}):
        assert state(tmp_path, mtu(value)) == "unknown"
    assert state(tmp_path, lambda document: document["network"].pop("mtu")) == "unknown"


def test_named_volume_is_a_mount_of_its_own_shape_and_needs_its_recovery_class(
    tmp_path: Path,
) -> None:
    assert state(tmp_path, volume_only(VOLUME)) == "present"
    assert state(tmp_path, volume_only({**VOLUME, "read_only": True})) == "present"
    assert state(tmp_path, volume_only({**VOLUME, "volume": "a" * 255})) == "present"
    assert state(tmp_path, volume_only({**VOLUME, "volume": "Example.data-1_a"})) == "present"
    # A definition may have a volume and a bind mount side by side.
    assert (
        state(
            tmp_path,
            lambda document: document.update(
                mounts=[*document["mounts"], VOLUME], recovery_class="named-volume"
            ),
        )
        == "present"
    )
    # The class alone stays valid: it was the only way to say it before.
    assert state(tmp_path, stated("recovery_class", "named-volume")) == "present"
    for recovery_class in ("bind-data", "stateless"):
        assert state(tmp_path, volume_only(VOLUME, recovery_class)) == "unknown"
    for broken in (
        {**VOLUME, "source": "/example/data"},  # both kinds of source
        {**VOLUME, "volume": "/example/data"},  # a path is not a volume name
        {**VOLUME, "volume": "-leading"},
        {**VOLUME, "volume": "example data"},
        {**VOLUME, "volume": ""},
        {**VOLUME, "volume": "a" * 256},
        {**VOLUME, "volume": None},
        {**VOLUME, "destination": "data"},
        {**VOLUME, "format": "ext4"},
        {"volume": "example_data", "destination": "/data"},
        {"volume": "example_data", "read_only": False},
        {"destination": "/data", "read_only": False},
    ):
        assert state(tmp_path, volume_only(broken)) == "unknown"
    # The path rules of a bind mount are unchanged beside a volume.
    for source in ("/example/../outside", "example/data"):
        mounts = [VOLUME, {"source": source, "destination": "/other", "read_only": False}]
        assert (
            state(
                tmp_path,
                lambda document, mounts=mounts: document.update(
                    mounts=mounts, recovery_class="named-volume"
                ),
            )
            == "unknown"
        )


def test_capabilities_are_normalised_sorted_and_never_empty(tmp_path: Path) -> None:
    for valid in (
        {"add": ["CAP_NET_RAW"]},
        {"drop": ["ALL"]},
        {"add": ["ALL"]},
        {"add": ["CAP_NET_BIND_SERVICE", "CAP_NET_RAW"], "drop": ["CAP_MKNOD"]},
        {"add": ["CAP_NET_BIND_SERVICE"], "drop": ["ALL"]},
        {"add": VENDOR_CAPABILITIES},
        {"drop": VENDOR_CAPABILITIES},
    ):
        assert state(tmp_path, stated("capabilities", valid)) == "present"
    assert sorted(VENDOR_CAPABILITIES) == VENDOR_CAPABILITIES and len(VENDOR_CAPABILITIES) == 41
    many = [f"CAP_EXAMPLE_{number:02d}" for number in range(65)]
    assert state(tmp_path, stated("capabilities", {"add": many[:64]})) == "present"
    for broken in (
        {},
        {"add": []},
        {"drop": []},
        {"add": ["CAP_NET_RAW"], "drop": []},
        {"add": ["NET_RAW"]},  # the runtime stores the prefixed form
        {"add": ["cap_net_raw"]},
        {"add": ["CAP_net_raw"]},
        {"add": ["all"]},
        {"add": ["CAP_"]},
        {"add": ["CAP_NET_RAW "]},
        {"add": ["CAP_NET_RAW", "CAP_NET_BIND_SERVICE"]},
        {"drop": ["CAP_NET_RAW", "CAP_MKNOD"]},
        {"add": ["CAP_NET_RAW", "CAP_NET_RAW"]},
        {"add": ["ALL", "CAP_NET_RAW"]},
        {"drop": ["ALL", "CAP_NET_RAW"]},
        {"add": many},
        {"add": "CAP_NET_RAW"},
        {"add": None},
        {"add": ["CAP_NET_RAW"], "drop": None},
        {"keep": ["CAP_NET_RAW"]},
        ["CAP_NET_RAW"],
    ):
        assert state(tmp_path, stated("capabilities", broken)) == "unknown"


def test_kernel_and_first_process_are_stated_as_hashes_only(tmp_path: Path) -> None:
    kernel_arguments_digest = helpers().kernel_arguments_digest
    init_process_digest = helpers().init_process_digest
    process = init_process_digest("/bin/example", ["--serve"])
    assert re.fullmatch("[0-9a-f]{64}", process)
    assert state(tmp_path, stated("kernel_sha256", "3" * 64)) == "present"
    assert state(tmp_path, stated("init_process_sha256", process)) == "present"
    arguments = kernel_arguments_digest(["panic=1", "quiet"])
    assert state(tmp_path, stated("kernel_arguments_sha256", arguments)) == "present"
    for member in ("kernel_sha256", "init_process_sha256"):
        for broken in ("/example/kernel", "3" * 63, "3" * 65, "A" * 64, "", 3, ["3" * 64]):
            assert state(tmp_path, stated(member, broken)) == "unknown"
    # The inputs are ordered lists, not joined text, and the two members never mix.
    assert kernel_arguments_digest([]) == hashlib.sha256(b"[]").hexdigest()
    assert kernel_arguments_digest(["a", "b"]) == hashlib.sha256(b'["a","b"]').hexdigest()
    assert kernel_arguments_digest(("a", "b")) == kernel_arguments_digest(["a", "b"])
    distinct = [[], [""], ["a", "b"], ["b", "a"], ["a b"], ["a,b"], ['a","b'], ["a", "b", ""]]
    assert len({kernel_arguments_digest(item) for item in distinct}) == len(distinct)
    assert (
        process
        == hashlib.sha256(b'{"arguments":["--serve"],"executable":"/bin/example"}').hexdigest()
    )
    processes = [
        ("/bin/example", []),
        ("/bin/example", ["--serve"]),
        ("/bin/example", ["--serve", ""]),
        ("/bin/example --serve", []),
        ("", ["/bin/example", "--serve"]),
        ("/bin/sh", ["-c", "first\nsecond"]),
        ("/bin/sh", ["-c", "first\\nsecond"]),
        ("/bin/sh", ["-c", "first", "second"]),
    ]
    assert len({init_process_digest(*item) for item in processes}) == len(processes)
    assert init_process_digest("/bin/example", []) != kernel_arguments_digest([])
    for call in (
        lambda: kernel_arguments_digest("quiet"),
        lambda: kernel_arguments_digest(b"quiet"),
        lambda: kernel_arguments_digest(["quiet", 1]),
        lambda: kernel_arguments_digest(None),
        lambda: kernel_arguments_digest(["\ud800"]),
        lambda: init_process_digest(["/bin/example"], []),
        lambda: init_process_digest("/bin/example", "--serve"),
        lambda: init_process_digest("/bin/example", [None]),
    ):
        with pytest.raises(ValueError):
            call()


def test_second_admitted_image_is_explicit_distinct_and_bounded(tmp_path: Path) -> None:
    images = [IMAGE + str(number) * 64 for number in (4, 5, 6, 7)]
    assert state(tmp_path, stated("image_alternates", images[:1])) == "present"
    assert state(tmp_path, stated("image_alternates", images[:3])) == "present"
    assert state(tmp_path, stated("image_alternates", [])) == "unknown"
    assert state(tmp_path, stated("image_alternates", images)) == "unknown"
    assert state(tmp_path, stated("image_alternates", images[:3][::-1])) == "unknown"
    assert state(tmp_path, stated("image_alternates", [images[0], images[0]])) == "unknown"
    assert state(tmp_path, stated("image_alternates", images[0])) == "unknown"
    for unpinned in ("example.invalid/example-web:latest", IMAGE + "4" * 63, IMAGE + "G" * 64):
        assert state(tmp_path, stated("image_alternates", [unpinned])) == "unknown"
    # The desired image is never also an alternate, alone or among others.
    assert (
        state(tmp_path, lambda document: document.update(image_alternates=[document["image_lock"]]))
        == "unknown"
    )
    assert (
        state(
            tmp_path,
            lambda document: document.update(
                image_alternates=sorted([document["image_lock"], images[0]])
            ),
        )
        == "unknown"
    )


@pytest.mark.parametrize(
    ("member", "value"),
    [
        ("capabilities", {"add": ["CAP_NET_RAW"]}),
        ("kernel_sha256", "3" * 64),
        ("init_process_sha256", "4" * 64),
        ("image_alternates", [IMAGE + "4" * 64]),
        ("mounts", [VOLUME]),
        ("mtu", None),
    ],
    ids=["capabilities", "kernel", "first-process", "second-image", "named-volume", "unset-mtu"],
)
def test_stating_a_fact_changes_the_contract_hash_and_what_binds_it(
    tmp_path: Path, member: str, value: Any
) -> None:
    def change(document: dict[str, Any]) -> None:
        if member == "mtu":
            document["network"]["mtu"] = value
        else:
            document[member] = value
        if member == "mounts":
            document["recovery_class"] = "named-volume"

    before = parse_instance(canonical_bytes(instance_data()) + b"\n")
    after, raw = rewritten(tmp_path, change)
    workload = before.workloads[0]
    assert hashlib.sha256(raw).hexdigest() != workload.contract.sha256
    assert verify_contracts(after, tmp_path)[0]["state"] == "present"
    # The old reference no longer matches the file: a fact is never added silently.
    assert verify_contracts(before, tmp_path)[0]["state"] == "unknown"
    assert verify_contracts(before, tmp_path)[1] == verify_contracts(after, tmp_path)[1]
    assert instance_contract_digest(before) != instance_contract_digest(after)
    old, new = all_digests(before), all_digests(after)
    own = {
        item.id for item in (*before.transport, *before.discovery) if item.service == workload.id
    }
    assert {identifier for identifier in old if old[identifier] != new[identifier]} == own
    assert own and own != set(old)


def test_documented_hash_inputs_match_the_helpers() -> None:
    text = (ROOT / "docs/instances.md").read_text(encoding="utf-8")
    examples = re.findall(
        r"^(kernel_arguments_sha256|init_process_sha256)  (.+)\n([0-9a-f]{64})$", text, re.MULTILINE
    )
    assert {member for member, _, _ in examples} == {
        "kernel_arguments_sha256",
        "init_process_sha256",
    }
    assert len(examples) >= 3
    for member, written, value in examples:
        assert hashlib.sha256(written.encode("utf-8")).hexdigest() == value
        parsed = strict_loads(written)
        # The documented input is the canonical form itself, not merely equal JSON.
        assert canonical_bytes(parsed) == written.encode("utf-8")
        if member == "kernel_arguments_sha256":
            assert helpers().kernel_arguments_digest(parsed) == value
        else:
            assert set(parsed) == {"arguments", "executable"}
            assert helpers().init_process_digest(parsed["executable"], parsed["arguments"]) == value
    assert any(written == "[]" for _, written, _ in examples)


def test_report_keeps_definition_parity_as_a_separate_acceptance(tmp_path: Path) -> None:
    """Stating facts does not let the report claim that a host carries them."""

    def every_fact(document: dict[str, Any]) -> None:
        document.update(
            capabilities={"add": ["CAP_NET_RAW"], "drop": ["CAP_MKNOD"]},
            kernel_sha256="3" * 64,
            init_process_sha256="4" * 64,
            image_alternates=[IMAGE + "4" * 64],
            mounts=[*document["mounts"], VOLUME],
            recovery_class="named-volume",
        )
        document["network"]["mtu"] = None

    instance, _ = rewritten(tmp_path, every_fact)
    result = build_report(instance, empty_evidence(1000.0), now=1000.0, data_directory=tmp_path)
    assert all(row["state"] == "present" for row in result["contracts"])
    row = next(item for item in result["requirements"] if item["id"] == "WORKLOAD-CONTRACTS")
    assert row["status"] not in {"fulfilled-verified", "not-fulfilled"}
    assert "parity still needs acceptance" in row["reason"]

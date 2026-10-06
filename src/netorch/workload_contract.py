"""Facts of a workload definition that a contract states, and its two hash inputs.

A contract is a declaration that a person accepts. Nothing here reads a host,
runs a tool or compares a contract with an installed definition.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .codec import digest
from .instance import InstanceError


def check_contract_facts(data: dict[str, Any]) -> None:
    """Rules across members of a schema-valid contract; each fact keeps one spelling."""
    if data["recovery_class"] != "named-volume" and any(
        "volume" in mount for mount in data["mounts"]
    ):
        raise InstanceError("a named volume requires the named-volume recovery class")
    alternates = data.get("image_alternates", [])
    if alternates != sorted(alternates) or data["image_lock"] in alternates:
        raise InstanceError("image alternates are ascending and never the desired image")
    for names in data.get("capabilities", {}).values():
        if names != sorted(names) or ("ALL" in names and len(names) != 1):
            raise InstanceError("capability names are ascending and ALL stands alone")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise InstanceError(label + " must be text")
    return value


def _text_list(value: object, label: str) -> list[str]:
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise InstanceError(label + " must be a sequence of text")
    return [_text(item, label) for item in value]


def kernel_arguments_digest(arguments: Sequence[str]) -> str:
    """The value of ``kernel_arguments_sha256``.

    The SHA-256 of the canonical JSON array of the kernel arguments the definition
    was created with, in their order; the empty array when it was created with none.
    """
    return digest(_text_list(arguments, "kernel arguments"))


def init_process_digest(executable: str, arguments: Sequence[str]) -> str:
    """The value of ``init_process_sha256``.

    The SHA-256 of the canonical JSON object holding the executable and the
    arguments of the definition's resolved first process. Its environment is not
    part of the input.
    """
    return digest(
        {
            "arguments": _text_list(arguments, "first process arguments"),
            "executable": _text(executable, "the first process executable"),
        }
    )

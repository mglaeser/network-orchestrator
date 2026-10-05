"""Fixed public capability boundary for the read-only extraction release.

The accepted native platform matrix is empty. Declared facts, successful mocks,
root privileges and operator configuration cannot qualify a mutation. Existing
owner internals remain available to conformance tests, but public entrypoints
must pass this gate before invoking them. A later qualified owner migration
requires a separately reviewed release; there is no flag or environment bypass.
"""

from __future__ import annotations

from typing import Any

NOT_QUALIFIED = 78


class StageNotQualified(RuntimeError):
    """The extraction stage cannot activate or release production authority."""

    def __init__(self, capability: str) -> None:
        super().__init__("read-only extraction stage is not qualified for native mutation")
        self.capability = capability

    def to_dict(self) -> dict[str, str]:
        return {
            "error": "stage-not-qualified",
            "capability": self.capability,
            "reason": (
                "This release is read-only: no accepted native platform matrix or "
                "qualified owner migration exists. Keep the existing owners in place."
            ),
        }


def require_mutation_qualified(capability: str) -> None:
    """Always refuse in this release, before inputs, state or native tools."""
    raise StageNotQualified(capability)


def require_request_qualified(provider: str, request: Any) -> None:
    """Permit only observation and explicit negative authority envelopes.

    This classification conveys no authorization. Existing endpoint validation
    still checks the complete envelope, installed scope, policy and ownership.
    Malformed or future operations cannot fall through into activation.
    """
    if isinstance(request, dict):
        if provider in {"runtime", "bonjour"} and request.get("operation") == "observe":
            return
        if (
            provider == "runtime"
            and request.get("operation") == "reconcile"
            and isinstance(request.get("action"), str)
            and request.get("action") in {"withdraw", "drain"}
        ):
            return
        if (
            provider == "bonjour"
            and request.get("operation") == "reconcile-discovery"
            and request.get("active") is False
        ):
            return
    require_mutation_qualified("endpoint-activation")

"""Real FIFOs must fail before a reader can wait for a writer.

These are bounded subprocess checks, rather than assertions about open flags.
No native networking or root process is invoked.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from netorch.codec import CodecError, read_bounded_file

CASES = (
    "store-read",
    "store-write",
    "store-lock",
    "pf-read",
    "bonjour-private-json",
    "deployment-read",
    "deployment-executable",
    "binding-read",
    "json-read",
    "config-read",
    "deployment-config-read",
    "derive-literal-source",
    "cli-validate",
    "cli-deploy-validate",
    "cli-pause",
    "cli-derive-check",
    "runtime-receipt-swap",
)

CHILD = r"""
import hashlib
import json
import os
import sys
from pathlib import Path

from netorch import apple_runtime, bonjour_owner, cli, codec, config
from netorch import deployment, deployment_config, derive, owners, pf_owner
from netorch.runtime_settings import FileIdentity
from netorch.storage import Store

root, case = Path(sys.argv[1]), sys.argv[2]
pipe = root / "pipe.json"
# This fixture does not claim native ACL or root-ownership acceptance. Exempt
# only the unrelated ACL query so the actual descriptor type is exercised.
deployment._privileged_acl = lambda *args, **kwargs: None

if case == "derive-literal-source":
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "sources": [
        {"path": "pipe.json", "format": "literal-env", "mapping": {"SITE": "/site"}}
    ]}))
if case == "cli-derive-check":
    # Derivation itself succeeds; the existing comparison target is the FIFO.
    valid = config.load_config(Path("examples/network.json"))
    cli.derive = lambda _path: valid
if case == "runtime-receipt-swap":
    receipt = root / "receipt"
    receipt.write_bytes(b"original")
    receipt.chmod(0o600)
    meta = receipt.stat()
    identity = FileIdentity(str(receipt), "file", os.geteuid(), meta.st_dev,
                            meta.st_ino, hashlib.sha256(b"original").hexdigest())
    apple_runtime._identity_acl = lambda *args, **kwargs: None
    real_open = os.open
    def swap_before_open(path, flags, *args, **kwargs):
        if Path(path) == receipt:
            receipt.unlink()
            os.mkfifo(receipt, 0o600)
        return real_open(path, flags, *args, **kwargs)
    apple_runtime.os.open = swap_before_open

calls = {
    "store-read": lambda: Store(root).read("pipe.json"),
    "store-write": lambda: Store(root).write("pipe.json", {}),
    "store-lock": lambda: Store(root).lock().__enter__(),
    "pf-read": lambda: pf_owner.read_once(pipe),
    "bonjour-private-json": lambda: bonjour_owner.private_json(pipe),
    "deployment-read": lambda: deployment._read_file(pipe),
    "deployment-executable": lambda: deployment._protected_executable(pipe),
    "binding-read": lambda: owners._secure_binding_file(pipe),
    "json-read": lambda: codec.strict_load(pipe),
    "config-read": lambda: config.load_config(pipe),
    "deployment-config-read": lambda: deployment_config.load_deployment(pipe),
    "derive-literal-source": lambda: derive.derive(manifest),
    "cli-validate": lambda: cli.main(["validate", "--config", str(pipe)]),
    "cli-deploy-validate": lambda: cli.main(["deploy", "validate", "--manifest", str(pipe)]),
    "cli-pause": lambda: cli.main(["pause", "--state-dir", str(root)]),
    "cli-derive-check": lambda: cli.main(["derive", "--source", "unused", "--check",
                                        "--output", str(pipe)]),
    "runtime-receipt-swap": lambda: apple_runtime.check_identity(identity),
}
try:
    result = calls[case]()
except (OSError, ValueError, RuntimeError):
    print("refused")
else:
    if case.startswith("cli-") and result == 65:
        print("refused")
    else:
        raise AssertionError("nonregular input was not refused")
"""


@pytest.mark.parametrize("case", CASES)
def test_named_pipe_is_refused_without_a_writer(tmp_path: Path, case: str) -> None:
    state = tmp_path / "private"
    state.mkdir(mode=0o700)
    os.mkfifo(state / "pipe.json", 0o600)
    if case == "store-lock":
        os.mkfifo(state / "owner.lock", 0o600)
    elif case == "cli-pause":
        os.mkfifo(state / "intent.json", 0o600)
    # subprocess.run kills and reaps the child if a future regression blocks.
    result = subprocess.run(
        [sys.executable, "-c", CHILD, str(state), case],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.rstrip().endswith("refused")
    assert (state / "pipe.json").is_fifo()


def test_general_data_reader_preserves_regular_file_and_symlink_semantics(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.write_bytes(b"abcdef")
    link = tmp_path / "linked"
    link.symlink_to(data)
    assert read_bounded_file(data, maximum=3) == b"abcd"
    assert read_bounded_file(link, maximum=10) == b"abcdef"
    with pytest.raises(CodecError, match="regular"):
        read_bounded_file(tmp_path)


@pytest.mark.parametrize("maximum", [0, -1, True, 1.5])
def test_general_data_reader_rejects_invalid_limit(tmp_path: Path, maximum: object) -> None:
    with pytest.raises(CodecError, match="limit"):
        read_bounded_file(tmp_path / "missing", maximum=maximum)  # type: ignore[arg-type]

"""Replay projected native camera publications; never collect or contact a host.

The native descriptor count and guest procfs grammar are recorded. Addresses,
names and port endpoints are sanitized; declared policy and mutations are
explicitly synthetic. No packet, recording, pairing or candidate acceptance is
inferred from these structural observations.
"""

from dataclasses import replace

import pytest

from netorch.apple_runtime import Reader, RuntimeReadError, _publication, _service, decode_snapshot
from netorch.codec import strict_loads
from netorch.model import PortRange
from netorch.process import Result
from tests.recorded import load_recording
from tests.test_workloads import fleet


def boundary(tmp_path, *, guest_bytes=None):
    config, settings, _, _, _ = fleet(tmp_path)
    publication = load_recording("runtime", "camera-native-publication")
    procfs = load_recording("runtime", "camera-native-automatic-ports")
    current = decode_snapshot(strict_loads(publication.stdout)[0], "1.2.0")
    ports = PortRange(42000, 43023)
    camera = replace(config.service("camera"), automatic_ports=ports)
    config = replace(
        config,
        services=tuple(camera if item.id == camera.id else item for item in config.services),
    )
    profile = replace(config.profile("camera-web"), ports=ports, target_ports=ports)

    def runner(argv, **kwargs):
        assert argv == [
            settings.executable,
            "exec",
            "--user",
            "0",
            "camera",
            "/bin/cat",
            "/proc/sys/net/ipv4/ip_local_port_range",
        ]
        return Result(0, procfs.stdout if guest_bytes is None else guest_bytes, b"")

    reader = Reader(settings, runner)
    service = _service(
        config,
        settings.contract("camera"),
        current,
        settings.networks[0],
        "network-test",
        1000,
        reader,
    )
    return config, profile, current, service


def test_recorded_native_tcp_range_descriptor_and_procfs_agree(tmp_path):
    config, profile, current, service = boundary(tmp_path)
    rows = current["configuration"]["publishedPorts"]
    assert len(rows) == 5
    assert [row["count"] for row in rows] == [1, 1, 1, 1, 1024]
    assert all(row["proto"] == "tcp" for row in rows)
    result = _publication(config, profile, current, service, "network-test", 1000)
    assert result.state == "present"
    assert result.data["source"] == "native-service-publication"
    assert result.data["target_ipv4"] == "198.51.100.5"


@pytest.mark.parametrize(
    ("field", "value", "state"),
    [
        ("count", 1023, "absent"),
        ("count", True, "unknown"),
        ("hostPort", 42001, "absent"),
        ("containerPort", 42001, "absent"),
        ("proto", "udp", "absent"),
        ("hostAddress", "0.0.0.0", "absent"),
    ],
)
def test_synthetic_descriptor_drift_cannot_pass_recorded_boundary(tmp_path, field, value, state):
    config, profile, current, service = boundary(tmp_path)
    current["configuration"]["publishedPorts"][-1][field] = value
    result = _publication(config, profile, current, service, "network-test", 1000)
    assert result.state == state


@pytest.mark.parametrize("guest_bytes", [b"42000 43022\n", b"", b"42000 43023 extra\n"])
def test_synthetic_guest_drift_rejects_even_intact_native_publication(tmp_path, guest_bytes):
    with pytest.raises(RuntimeReadError) as raised:
        boundary(tmp_path, guest_bytes=guest_bytes)
    assert raised.value.reason == "identity-mismatch"

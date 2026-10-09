"""Offline replays of sanitized native grammar, with explicit non-qualification.

All native calls are replaced with the captured results or stated synthetic
counterexamples. These tests never launch a vendor binary or query the host.
"""

from dataclasses import replace

import pytest

from netorch.apple_runtime import Reader, RuntimeReadError, decode_snapshot
from netorch.codec import strict_loads
from netorch.darwin_volume import OPTIONS, REQUEST, decode_volume_uuid
from netorch.launchd_inventory import domain_services
from netorch.process import Result
from netorch.runtime_settings import FleetStart
from tests.recorded import load_recording
from tests.test_workloads import fleet


@pytest.mark.parametrize(
    ("identifier", "domain", "count"),
    [
        ("launchd-system", "system", 462),
        ("launchd-gui", "gui/1001", 479),
        ("launchd-user", "user/1001", 76),
    ],
)
def test_complete_native_domain_table_including_loaded_idle_jobs(identifier, domain, count):
    recording = load_recording("runtime", identifier)
    assert recording.returncode == 0
    report = recording.stdout.decode()
    labels = domain_services(report, domain)
    assert len(labels) == count
    # Count/status grammar and all rows survived redaction, including PID-zero
    # jobs. Reading only running processes would lose these service identities.
    zero_pid_labels = {
        line.split()[-1] for line in report.splitlines() if line.lstrip().startswith("0 ")
    }
    assert zero_pid_labels and zero_pid_labels <= labels
    with pytest.raises(ValueError):
        domain_services(report[:-2], domain)
    with pytest.raises(ValueError):
        domain_services(report.replace(f"service count = {count}", "service count = 0"), domain)


def test_native_loaded_guest_relationship_survives_sanitization():
    report = load_recording("runtime", "job-ha-runtime").stdout.decode()
    target = report.splitlines()[0].split(" = ")[0]
    domain, label = target.rsplit("/", 1)
    table = load_recording("runtime", "launchd-" + domain.split("/")[0]).stdout.decode()
    assert label in domain_services(table, domain)
    snapshot = strict_loads(load_recording("runtime", "container-inspect-03").stdout)[0]
    decoded = decode_snapshot(snapshot, "1.2.0")
    assert label.endswith("." + decoded["id"])
    assert decoded["id"] == decoded["configuration"]["id"] == "workload-a"
    assert decoded["state"] == "running"
    assert decoded["networks"][0]["ipv4Address"] == "198.51.100.5/24"
    # A flat mock snapshot cannot stand in for the native nested CLI envelope.
    flat = {**snapshot, **snapshot["status"]}
    del flat["status"]
    with pytest.raises(RuntimeReadError):
        decode_snapshot(flat, "1.2.0")


@pytest.mark.parametrize("kind", ["api", "network-helper"])
def test_native_job_and_process_fields_agree_without_reading_redacted_arguments(tmp_path, kind):
    _, settings, _, _, _ = fleet(tmp_path)
    settings = replace(settings, account=replace(settings.account, uid=1001))
    job = load_recording("runtime", "job-" + kind)
    receipt = load_recording("runtime", "process-" + kind)
    report = job.stdout.decode()
    program = next(line.split(" = ")[1] for line in report.splitlines() if "\tprogram = " in line)
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        selected = receipt if argv[0] == "/bin/ps" else job
        assert argv[0] in {"/bin/ps", "/bin/launchctl"}
        return Result(selected.returncode, selected.stdout, selected.stderr)

    reader = Reader(settings, runner)
    if kind == "api":
        result = reader.api_process(
            FleetStart("com.apple.container.apiserver", program, "com.apple.container."), report
        )
    else:
        result = reader.helper(
            replace(settings.networks[0], helper_executable=program, helper_uid=1001)
        )
    assert result["uid"] == 1001 and result["executable"] == program
    assert calls[-1][:3] == ["/bin/ps", "-p", str(result["pid"])]
    assert "\t\tstate = active\n" in report
    # Coalition fields must not substitute for the actual job's state.
    changed = report.replace("\tstate = running\n", "\tstate = not running\n")
    changed = changed.replace("\t\tstate = active\n", "\t\tstate = running\n")
    with pytest.raises(RuntimeReadError):
        reader.api_process(
            FleetStart("com.apple.container.apiserver", program, "com.apple.container."), changed
        )
    assert any("redacted" in limitation for limitation in job.source["limitations"])


def test_native_network_envelope_matches_declared_scope_with_explicit_synthetic_interface(tmp_path):
    config, settings, _, _, _ = fleet(tmp_path)
    captured = load_recording("runtime", "runtime-network-default")

    def runner(argv, **kwargs):
        if argv[0] == settings.executable:
            assert argv[1:] == ["network", "inspect", "default"]
            return Result(captured.returncode, captured.stdout, captured.stderr)
        assert argv == ["/sbin/ifconfig", config.scopes[0].interface]
        # This address is a declared synthetic input, not a native observation.
        return Result(0, b"en0: flags=UP\n\tinet 192.0.2.10 netmask 0xffffff00\n", b"")

    result = Reader(settings, runner).network(config, settings.networks[0])
    assert result["configuration"]["mode"] == "nat"
    assert result["configuration"]["plugin"] == "container-network-vmnet"
    with pytest.raises(RuntimeReadError):
        Reader(settings, runner).network(
            config, replace(settings.networks[0], gateway="198.51.100.2")
        )


def test_native_volume_reply_preserves_header_and_request_but_replaces_private_uuid():
    captured = load_recording("runtime", "volume-uuid-reply")
    reply = bytes.fromhex(captured.stdout.decode())
    assert len(reply) == 40
    assert REQUEST.hex() == "050000000000008000000480000000000000000000000000"
    assert OPTIONS == 12
    assert decode_volume_uuid(reply) == "00112233-4455-6677-8899-aabbccddeeff"
    with pytest.raises(ValueError):
        decode_volume_uuid(reply[:-1])
    with pytest.raises(ValueError):
        decode_volume_uuid(reply[:24] + bytes(16))

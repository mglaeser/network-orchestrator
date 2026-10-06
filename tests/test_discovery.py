from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from netorch.config import load_config
from netorch.discovery import (
    Publication,
    Record,
    project_export,
    select_imports,
    txt_from_json,
    txt_to_json,
)
from netorch.state import Observation


@pytest.fixture
def config():
    return load_config(Path(__file__).resolve().parents[1] / "examples/network.json")


@pytest.fixture
def export_record():
    return Record(
        "Example camera",
        "_hap._tcp",
        "camera-guest.local.",
        9443,
        "198.51.100.13",
        (b"id=example", b"binary=\x00\xff", b"Case=Preserved"),
        "bridge-test",
        1000.0,
        "camera",
        "camera-instance-1",
    )


@pytest.fixture
def endpoint():
    return Observation(
        "present", "verified", 1000.0, "camera-instance-1", {"ipv4": "198.51.100.13"}
    )


def export(
    config, record, endpoint, publications, *, dependencies=None, now=1000.0, confirmed=True
):
    policy = next(item for item in config.discovery if item.id == "camera-export")
    return project_export(
        config,
        policy,
        record,
        endpoint,
        publications,
        frozenset(policy.dependencies) if dependencies is None else dependencies,
        now,
        interface_confirmed=confirmed,
    )


def camera_publication(config):
    return Publication("camera", "camera-instance-1", 9443, 9443, config.scopes[0].host_ipv4)


def test_export_preserves_identity_and_binary_txt(config, export_record, endpoint):
    result = export(config, export_record, endpoint, (camera_publication(config),))
    assert result.state == "present"
    assert result.record.name == export_record.name
    assert result.record.txt == export_record.txt
    assert result.record.ipv4 == "192.0.2.10"
    assert result.record.interface == "en0"
    assert result.record.hostname == "netorch-container-camera.local."


def test_guest_port_collision_does_not_select_another_service(config, export_record, endpoint):
    record = replace(export_record, port=8080)
    own = Publication("camera", "camera-instance-1", 8080, 8787, "192.0.2.10")
    colliding = Publication("web-proxy", "other-instance", 8080, 8080, "192.0.2.10")
    result = export(config, record, endpoint, (colliding, own))
    assert result.state == "present"
    assert result.record.port == 8787
    assert export(config, record, endpoint, (colliding,)).state == "absent"


def test_udp_export_uses_its_own_udp_publication(config, export_record, endpoint):
    policy = next(item for item in config.discovery if item.id == "camera-export")
    policy = replace(policy, types=("_example._udp",))
    record = replace(export_record, service_type="_example._udp")
    udp = replace(camera_publication(config), protocol="udp")
    result = project_export(
        config,
        policy,
        record,
        endpoint,
        (udp,),
        frozenset(policy.dependencies),
        1000,
        interface_confirmed=True,
    )
    assert result.state == "present"
    assert result.record.service_type == "_example._udp"
    tcp = replace(udp, protocol="tcp")
    mismatch = project_export(
        config,
        policy,
        record,
        endpoint,
        (tcp,),
        frozenset(policy.dependencies),
        1000,
        interface_confirmed=True,
    )
    assert mismatch.state == "absent" and mismatch.reason == "publication-not-unique"


@pytest.mark.parametrize(
    "change", ["generation", "service", "host-ip", "guest-port", "protocol", "duplicate"]
)
def test_exact_publication_tuple_must_be_unique(config, export_record, endpoint, change):
    publication = camera_publication(config)
    alterations = {
        "generation": {"generation": "old-instance"},
        "service": {"service": "web-proxy"},
        "host-ip": {"host_ipv4": "192.0.2.11"},
        "guest-port": {"guest_port": 9000},
        "protocol": {"protocol": "udp"},
    }
    entries = (
        (publication, publication)
        if change == "duplicate"
        else (replace(publication, **alterations[change]),)
    )
    result = export(config, export_record, endpoint, entries)
    assert (result.state, result.reason) == ("absent", "publication-not-unique")


@pytest.mark.parametrize(
    "change",
    [
        "type",
        "service",
        "generation",
        "ip",
        "expired",
        "future",
        "loop-name",
        "loop-host",
        "source-interface",
    ],
)
def test_export_rejects_wrong_or_old_record(config, export_record, endpoint, change):
    alterations = {
        "type": {"service_type": "_other._tcp"},
        "service": {"source_service": "web-proxy"},
        "generation": {"source_generation": "old-instance"},
        "ip": {"ipv4": "198.51.100.14"},
        "expired": {"seen_at": 800.0},
        "future": {"seen_at": 1001.0},
        "loop-name": {"name": "netorch-lan-previous"},
        "loop-host": {"hostname": "netorch-lan-previous.local."},
        "source-interface": {"interface": "en0"},
    }
    result = export(
        config,
        replace(export_record, **alterations[change]),
        endpoint,
        (camera_publication(config),),
    )
    assert result.state != "present"


def test_export_requires_dependencies_interface_and_fresh_source(config, export_record, endpoint):
    publication = (camera_publication(config),)
    assert (
        export(config, export_record, endpoint, publication, dependencies=frozenset()).reason
        == "dependency-unverified"
    )
    assert export(config, export_record, endpoint, publication, confirmed=False).state == "unknown"
    stale = replace(endpoint, observed_at=800.0)
    assert export(config, export_record, stale, publication).reason == "source-unverified"
    denied = Observation("unknown", "local-network-denied", 1000.0, None)
    assert export(config, export_record, denied, publication).state == "unknown"


def import_records(
    config,
    records,
    *,
    policy=None,
    dependencies=None,
    now=1000.0,
    interface="bridge-test",
    confirmed=True,
):
    policy = policy or next(item for item in config.discovery if item.id == "media-import")
    return select_imports(
        config,
        policy,
        records,
        frozenset(policy.dependencies) if dependencies is None else dependencies,
        now,
        eligible_models=frozenset({b"model=ExampleSpeaker"}),
        target_interface=interface,
        interface_confirmed=confirmed,
    )


def media_record(name="Speaker", service_type="_airplay._tcp", ipv4="192.0.2.20", **kwargs):
    return Record(
        name,
        service_type,
        "speaker.local.",
        7000,
        ipv4,
        (b"model=ExampleSpeaker", b"binary=\x00\xff"),
        "en0",
        1000.0,
        **kwargs,
    )


def test_import_associates_related_records_to_eligible_current_endpoint(config):
    airplay = media_record()
    raop = media_record("Example@Speaker", "_raop._tcp")
    companion = media_record("Speaker companion", "_companion-link._tcp")
    unrelated = media_record("Unrelated", "_raop._tcp", "192.0.2.21")
    result = import_records(config, (airplay, raop, companion, unrelated))
    assert len(result) == 3
    assert all(item.interface == "bridge-test" for item in result)
    assert all(item.ipv4 == "192.0.2.20" for item in result)
    assert next(item for item in result if item.name == "Speaker").txt == airplay.txt


@pytest.mark.parametrize(
    "change",
    ["old", "future", "wrong-interface", "wrong-type", "outside-lan", "loop", "wrong-model"],
)
def test_import_excludes_untrusted_or_ineligible_advertisements(config, change):
    alterations = {
        "old": {"seen_at": 800.0},
        "future": {"seen_at": 1001.0},
        "wrong-interface": {"interface": "en1"},
        "wrong-type": {"service_type": "_other._tcp"},
        "outside-lan": {"ipv4": "203.0.113.20"},
        "loop": {"hostname": "netorch-container-previous.local."},
        "wrong-model": {"txt": (b"model=Unrecognized",)},
    }
    assert import_records(config, (replace(media_record(), **alterations[change]),)) == ()


@pytest.mark.parametrize(
    "interface,confirmed,dependencies",
    [
        ("", True, None),
        ("0", True, None),
        ("bridge-test", False, None),
        ("bridge-test", True, frozenset()),
    ],
)
def test_import_fails_closed_without_interface_or_transport_dependency(
    config, interface, confirmed, dependencies
):
    assert (
        import_records(
            config,
            (media_record(),),
            interface=interface,
            confirmed=confirmed,
            dependencies=dependencies,
        )
        == ()
    )


def test_import_flood_and_duplicate_never_truncate_to_success(config):
    policy = next(item for item in config.discovery if item.id == "media-import")
    policy = replace(policy, max_records=1)
    assert (
        import_records(
            config, (media_record(), media_record("Related", "_raop._tcp")), policy=policy
        )
        == ()
    )
    assert import_records(config, (media_record(), media_record())) == ()


def test_wrong_policy_direction_rejected(config, export_record, endpoint):
    importer = next(item for item in config.discovery if item.id == "media-import")
    exporter = next(item for item in config.discovery if item.id == "camera-export")
    with pytest.raises(ValueError):
        project_export(
            config,
            importer,
            export_record,
            endpoint,
            (),
            frozenset(),
            1000,
            interface_confirmed=True,
        )
    with pytest.raises(ValueError):
        select_imports(
            config,
            exporter,
            (),
            frozenset(),
            1000,
            eligible_models=frozenset(),
            target_interface="bridge-test",
            interface_confirmed=True,
        )


def test_txt_json_round_trip_is_lossless_without_shell_encoding():
    values = (b"plain", b"binary=\x00\xff\x80", b"quotes=\"'`$", b"")
    assert txt_from_json(txt_to_json(values)) == values
    with pytest.raises(ValueError):
        txt_from_json(["not valid base64!"])


@pytest.mark.parametrize(
    "change",
    [
        "port-low",
        "port-high",
        "bool-port",
        "blank-name",
        "blank-host",
        "large-txt",
        "txt-type",
        "nan-time",
        "negative-time",
    ],
)
def test_record_validation_rejects_invalid_native_boundary_data(change):
    alterations = {
        "port-low": {"port": 0},
        "port-high": {"port": 65536},
        "bool-port": {"port": True},
        "blank-name": {"name": ""},
        "blank-host": {"hostname": ""},
        "large-txt": {"txt": (b"x" * 256,)},
        "txt-type": {"txt": (1,)},
        "nan-time": {"seen_at": float("nan")},
        "negative-time": {"seen_at": -1.0},
    }
    with pytest.raises(ValueError):
        replace(media_record(), **alterations[change])


def test_import_does_not_associate_unrelated_hostname_on_shared_address(config):
    source = media_record()
    related = media_record("Related", "_raop._tcp")
    unrelated = replace(media_record("Other", "_raop._tcp"), hostname="other.local.")
    result = import_records(config, (source, related, unrelated))
    assert {record.name for record in result} == {source.name, related.name}


def test_import_does_not_reimport_its_own_projection(config):
    source = replace(media_record(), hostname="netorch-lan-previous.local.")
    assert import_records(config, (source,)) == ()


@pytest.mark.parametrize(
    "source_host,related_host,expected",
    [
        ("Speaker.LOCAL.", "speaker.local.", 2),
        ("Åpeaker.local.", "åpeaker.local.", 1),
        ("Straße.local.", "strasse.local.", 1),
    ],
)
def test_import_dns_hostname_comparison_is_ascii_only_and_preserves_output(
    config, source_host, related_host, expected
):
    source = replace(media_record(), hostname=source_host)
    related = replace(media_record("Related", "_raop._tcp"), hostname=related_host)
    result = import_records(config, (source, related))
    assert len(result) == expected
    assert next(record for record in result if record.name == source.name).hostname == source_host
    if expected == 2:
        assert (
            next(record for record in result if record.name == related.name).hostname
            == related_host
        )


@pytest.mark.parametrize("prefix", ["NeToRcH-CoNtAiNeR-", "NETORCH-LAN-"])
@pytest.mark.parametrize("field", ["name", "hostname"])
def test_import_projection_prefix_exclusion_uses_ascii_dns_case(config, prefix, field):
    source = replace(media_record(), **{field: prefix + "previous.local."})
    assert import_records(config, (source,)) == ()


@pytest.mark.parametrize("prefix", ["NeToRcH-CoNtAiNeR-", "NETORCH-LAN-"])
@pytest.mark.parametrize("field", ["name", "hostname"])
def test_export_projection_prefix_exclusion_uses_ascii_dns_case(
    config, export_record, endpoint, prefix, field
):
    record = replace(export_record, **{field: prefix + "previous.local."})
    result = export(config, record, endpoint, (camera_publication(config),))
    assert (result.state, result.reason) == ("absent", "loop-excluded")

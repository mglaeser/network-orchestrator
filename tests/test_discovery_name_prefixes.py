"""The prefixes of projected host names come from the policy, as one pair for the site.

A policy that does not name the pair keeps its canonical bytes and every digest.
Addresses are RFC 5737, names are invented, and no native tool is started.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch import discovery_plan
from netorch.cli import main
from netorch.codec import canonical_bytes, canonical_json, strict_load, strict_loads
from netorch.config import (
    ConfigError,
    config_digest,
    load_config,
    parse_config,
    profile_digest,
    to_dict,
    validate_config,
)
from netorch.derive import derive
from netorch.discovery import Record
from netorch.discovery_plan import discovery_digest
from netorch.mock import simulate
from netorch.model import Config
from netorch.state import Intent, Observation, snapshot_to_dict
from netorch.storage import Store
from tests.test_bonjour_owner import (
    candidate_request,
    config,
    media_record,
    policy,
    settings,
    snapshot,
)
from tests.test_discovery import (
    camera_publication,
    endpoint,
    export,
    export_record,
    import_records,
)
from tests.test_discovery import media_record as lan_record

__all__ = ["config", "endpoint", "export_record", "settings"]

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
SHIPPED = ("network.json", "network-dns-fallback.json")
DEFAULT = {"export_prefix": "netorch-container-", "import_prefix": "netorch-lan-"}
NAMES = {"export_prefix": "example-guest-", "import_prefix": "example-link-"}

# Printed by the unchanged base tree (c419a62) for the two shipped policies.
BASE: dict[str, dict[str, Any]] = {
    "network.json": {
        "canonical_sha256": "1fbb9601273c11e82d26781b31e9b2754340e10695b26980c470f2534b99d432",
        "config_digest": "bfb7a0957461cf456564604ee10a94f3af0253c980dde45c73a1c7ed355548f5",
        "profiles": {
            "camera-web": "15180d8db52f7551664e23914523a7184181ad118e4b96953f960b77fd38e12d",
            "dns-tcp": "e7eb1670ea57d2f18c5cc67eff0115f731308b26a66a968d7a837134308e0b50",
            "dns-udp": "99e950f630af1e1011d053afb465e98d5a9edd88a6c3ac0e181c7a59a7580bbc",
            "media-udp": "edf2ef7ac815bc595d7ee83dbfbfcc98be4850ef22595d35ba20f8385091651a",
            "proxy-high": "231765994c35405272f0a3d59be131552141a2737e37c5098fb496aacda44273",
            "proxy-standard": "18c0d0d684309f20fec35ed22617de1ce8b5fba76b0c985dbd3e89df6c85f67f",
        },
        "discovery": {
            "camera-export": "e24a871f7ff5f283e993455cd2413555a704a975ce90c7e045355b279803c039",
            "media-import": "d6b1f54c7ca19795462baf0069e3342863bf125586505b51f4193c18c5550d2c",
        },
        "run_sha256": "e46f255616b1569c7a2fc4900e45ae4d953645e10907e04907236d56f8b40d90",
    },
    "network-dns-fallback.json": {
        "canonical_sha256": "c6bd9e6c00b3c49229ea3aad3eb6485c0623b8320214d96f714aba46926e9219",
        "config_digest": "937f20c1c24ddefadb3d20d8ab8ee2ecf13983e1d0a800a6ff5f4142572a7651",
        "profiles": {
            "camera-web": "15180d8db52f7551664e23914523a7184181ad118e4b96953f960b77fd38e12d",
            "dns-native-tcp": "fdbad834b6e706d241ac45197246531d63a6272a6177d56c9704e2c7b3483f47",
            "dns-native-udp": "ac430273e3d43a8998c4d52fc2957677a662ef9143de9e9936feb1fe55966462",
            "dns-tcp": "4580de32bf605d52a05c29ee7399facd6cb414c0bc0dd2faf5a3ad20750d76af",
            "dns-udp": "8ad024133a236d958387b383d8b961293c7f5ebac1ea1251dca35a37cf829647",
            "media-udp": "edf2ef7ac815bc595d7ee83dbfbfcc98be4850ef22595d35ba20f8385091651a",
            "proxy-high": "231765994c35405272f0a3d59be131552141a2737e37c5098fb496aacda44273",
            "proxy-standard": "18c0d0d684309f20fec35ed22617de1ce8b5fba76b0c985dbd3e89df6c85f67f",
        },
        "discovery": {
            "camera-export": "e24a871f7ff5f283e993455cd2413555a704a975ce90c7e045355b279803c039",
            "media-import": "d6b1f54c7ca19795462baf0069e3342863bf125586505b51f4193c18c5550d2c",
        },
        "run_sha256": "4d1ce2210f134499e8485ae5f04da3a934ccc58ec0d924e9a78f694b9cb135bf",
    },
}


@pytest.fixture
def base_numbering(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hash every discovery object under the version number the base tree gave it.

    The base numbers the object 3, so here this changes nothing. It keeps the
    literals above the base's own when that number is raised for another reason:
    everything else of the object, and of a run that quotes its digest, must
    still be what the base produced.
    """
    real = discovery_plan.digest
    monkeypatch.setattr(
        discovery_plan, "digest", lambda value: real({**value, "digest_version": 3})
    )


def shipped(name: str = "network.json") -> dict[str, Any]:
    data: dict[str, Any] = strict_load(EXAMPLES / name)
    return data


def with_names(names: Any, name: str = "network.json") -> Config:
    """The shipped policy plus the object, through the real parser."""
    return parse_config(canonical_bytes({**shipped(name), "discovery_names": names}))


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def camera_record(**changes: Any) -> Record:
    """What the example's camera guest advertises on the guest network."""
    record: Record = media_record(
        name="Camera",
        service_type="_hap._tcp",
        hostname="camera.local.",
        ipv4="198.51.100.13",
        interface="bridge-test",
        port=9443,
    )
    return replace(record, **changes)


def imported(
    policy_config: Config, own: owner.BonjourSettings, *records: Record
) -> tuple[Record, ...]:
    result: tuple[Record, ...] = owner.project_records(
        policy_config,
        policy(policy_config),
        records,
        snapshot(policy_config),
        frozenset({"media-udp"}),
        own,
        1000,
    )
    return result


def exported(
    policy_config: Config, own: owner.BonjourSettings, *records: Record
) -> tuple[Record, ...]:
    result: tuple[Record, ...] = owner.project_records(
        policy_config,
        policy(policy_config, "camera-export"),
        records,
        snapshot(policy_config),
        frozenset({"camera-web"}),
        own,
        1000,
    )
    return result


def first_label(record: Record) -> str:
    assert record.hostname.endswith(".local.")
    return record.hostname.removesuffix(".local.")


def mixed(text: str) -> str:
    return "".join(c.upper() if index % 2 else c for index, c in enumerate(text))


SPELLINGS: tuple[Callable[[str], str], ...] = (str.lower, str.upper, mixed)


def hashed_objects(monkeypatch: pytest.MonkeyPatch, policy_config: Config) -> dict[str, Any]:
    """The object each declaration's discovery digest is taken of."""
    seen: list[Any] = []
    real = discovery_plan.digest

    def record(value: Any) -> str:
        seen.append(value)
        return real(value)

    result = {}
    with monkeypatch.context() as patch:
        patch.setattr(discovery_plan, "digest", record)
        for item in policy_config.discovery:
            assert discovery_digest(policy_config, item) == real(seen[-1])
            result[item.id] = seen[-1]
    return result


# A policy that does not name the pair is unchanged


@pytest.mark.parametrize("name", SHIPPED)
def test_shipped_policy_keeps_its_canonical_bytes_and_transport_digests(name: str) -> None:
    policy_config = load_config(EXAMPLES / name)
    assert sha256(canonical_bytes(to_dict(policy_config))) == BASE[name]["canonical_sha256"]
    assert config_digest(policy_config) == BASE[name]["config_digest"]
    assert {
        item.id: profile_digest(policy_config, item) for item in policy_config.profiles
    } == BASE[name]["profiles"]


@pytest.mark.usefixtures("base_numbering")
@pytest.mark.parametrize("name", SHIPPED)
def test_shipped_policy_keeps_every_discovery_digest(name: str) -> None:
    policy_config = load_config(EXAMPLES / name)
    assert {
        item.id: discovery_digest(policy_config, item) for item in policy_config.discovery
    } == BASE[name]["discovery"]


@pytest.mark.usefixtures("base_numbering")
@pytest.mark.parametrize("name", SHIPPED)
def test_example_run_is_byte_identical(name: str) -> None:
    run = canonical_json(simulate(load_config(EXAMPLES / name)))
    assert sha256(run.encode()) == BASE[name]["run_sha256"]


@pytest.mark.parametrize("name", SHIPPED)
def test_spelling_the_default_pair_is_the_same_policy(name: str) -> None:
    plain = load_config(EXAMPLES / name)
    assert asdict(plain.discovery_names) == DEFAULT
    assert "discovery_names" not in to_dict(plain)
    spelled = with_names(DEFAULT, name)
    assert spelled == plain
    assert canonical_bytes(to_dict(spelled)) == canonical_bytes(to_dict(plain))
    assert config_digest(spelled) == BASE[name]["config_digest"]


def test_policy_schema_gains_one_optional_top_level_member() -> None:
    schema = strict_load(ROOT / "schemas/network.schema.json")
    assert schema["required"] == [
        "schema_version",
        "site",
        "scopes",
        "owners",
        "services",
        "profiles",
        "discovery",
    ]
    assert set(schema["properties"]) - set(schema["required"]) == {"discovery_names"}
    assert schema["additionalProperties"] is False
    pair = schema["$defs"]["discovery_names"]
    assert pair["additionalProperties"] is False
    assert sorted(pair["required"]) == sorted(pair["properties"]) == sorted(DEFAULT)


# A named pair is part of the policy and of every discovery digest


@pytest.mark.parametrize("name", SHIPPED)
def test_named_pair_round_trips_and_leaves_transport_admissions_alone(name: str) -> None:
    named = with_names(NAMES, name)
    assert asdict(named.discovery_names) == NAMES
    assert to_dict(named)["discovery_names"] == NAMES
    assert parse_config(canonical_bytes(to_dict(named))) == named
    validate_config(named)
    assert config_digest(named) != BASE[name]["config_digest"]
    assert {item.id: profile_digest(named, item) for item in named.profiles} == BASE[name][
        "profiles"
    ]


def test_discovery_digest_gains_the_pair_only_when_it_is_named(
    monkeypatch: pytest.MonkeyPatch, config: Config
) -> None:
    plain = hashed_objects(monkeypatch, config)
    assert plain and all("names" not in value for value in plain.values())
    assert hashed_objects(monkeypatch, with_names(DEFAULT)) == plain
    named = hashed_objects(monkeypatch, with_names(NAMES))
    assert named == {key: {**value, "names": NAMES} for key, value in plain.items()}


@pytest.mark.parametrize("member", sorted(NAMES))
def test_each_prefix_changes_every_discovery_digest(config: Config, member: str) -> None:
    named = with_names(NAMES)
    other = with_names({**NAMES, member: "example-other-"})
    for item in config.discovery:
        digests = {discovery_digest(candidate, item) for candidate in (config, named, other)}
        assert len(digests) == 3


def test_owner_refuses_a_lease_made_under_another_pair(
    config: Config, settings: owner.BonjourSettings
) -> None:
    named = with_names(NAMES)
    current = snapshot(config)
    assert snapshot(named) == current
    for made, enforced in ((config, named), (named, config)):
        request, candidate = candidate_request(made, settings, current, media_record())
        fences = (current, Intent(), frozenset({"media-udp"}), 1000)
        assert owner.lease_records(made, policy(made), request, candidate, *fences)
        assert owner.lease_records(enforced, policy(enforced), request, candidate, *fences) is None


def test_owner_refuses_readback_and_requests_made_under_another_pair(
    monkeypatch: pytest.MonkeyPatch, config: Config, settings: owner.BonjourSettings
) -> None:
    monkeypatch.setattr(owner.time, "time", lambda: 1000)
    named = with_names(NAMES)
    current = snapshot(config)
    store = Store(settings.state_dir)
    made = {
        item.id: Observation(
            "present",
            "verified",
            1000,
            current.services[item.service].generation,
            {
                "policy_digest": discovery_digest(config, item),
                "network_generation": current.network_generation,
                "service_generation": current.services[item.service].generation,
                "interface_confirmed": True,
            },
        )
        for item in config.discovery
    }
    store.write("readback.json", snapshot_to_dict(replace(current, profiles=made)))
    assert all(
        item.state == "present"
        for item in owner.readback(config, settings, store, 1000).profiles.values()
    )
    assert all(
        (item.state, item.reason) == ("unknown", "identity-mismatch")
        for item in owner.readback(named, settings, store, 1000).profiles.values()
    )
    request = {
        "protocol_version": 1,
        "operation": "reconcile-discovery",
        "owner": settings.owner,
        "policy_digest": config_digest(config),
        "discovery_digest": discovery_digest(config, policy(config)),
        "discovery": policy(config).id,
        "active": True,
        "config": to_dict(config),
        "service_generation": current.services[policy(config).service].generation,
        "network_generation": current.network_generation,
    }
    with pytest.raises(ValueError, match="invalid fixed discovery request"):
        owner.endpoint(named, settings, store, request)
    assert not (settings.state_dir / "requests.json").exists()


def test_example_run_completes_with_a_named_pair() -> None:
    assert simulate(with_names(NAMES))["all_verified"] is True


def test_cli_validates_a_policy_that_names_the_pair(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(canonical_bytes({**shipped(), "discovery_names": NAMES}))
    assert main(["validate", "--config", str(path)]) == 0
    result = strict_loads(capfd.readouterr().out)
    assert result["valid"] is True
    assert result["policy_digest"] == config_digest(with_names(NAMES))
    assert result["policy_digest"] != BASE["network.json"]["config_digest"]


def test_static_import_fills_the_pair_from_an_owner_literal_file(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_bytes(canonical_bytes(shipped()))
    (tmp_path / "names.json").write_bytes(
        canonical_bytes({"discovery_names": {"export_prefix": None, "import_prefix": None}})
    )
    (tmp_path / "owner.env").write_text(
        "EXPORT_PREFIX=example-guest-\nIMPORT_PREFIX=example-link-\n"
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(
        canonical_bytes(
            {
                "schema_version": 1,
                "sources": [
                    {"path": "policy.json", "format": "json"},
                    {"path": "names.json", "format": "json"},
                    {
                        "path": "owner.env",
                        "format": "literal-env",
                        "mapping": {
                            "EXPORT_PREFIX": "/discovery_names/export_prefix",
                            "IMPORT_PREFIX": "/discovery_names/import_prefix",
                        },
                    },
                ],
            }
        )
    )
    assert derive(manifest) == with_names(NAMES)


# Both projected host names


def test_projected_host_names_carry_the_named_prefixes(
    config: Config, settings: owner.BonjourSettings
) -> None:
    named = with_names(NAMES)
    for project, record, member in (
        (imported, media_record(), "import_prefix"),
        (exported, camera_record(), "export_prefix"),
    ):
        (before,) = project(config, settings, record)
        (after,) = project(named, settings, record)
        assert first_label(before).startswith(DEFAULT[member])
        assert first_label(after).startswith(NAMES[member])
        # Only the prefix differs: the rest of the label and of the record are the same.
        assert first_label(after).removeprefix(NAMES[member]) == first_label(before).removeprefix(
            DEFAULT[member]
        )
        assert replace(after, hostname=before.hostname) == before


def test_pure_export_projection_uses_the_named_prefix(
    config: Config, export_record: Record, endpoint: Observation
) -> None:
    named = with_names(NAMES)
    result = export(named, export_record, endpoint, (camera_publication(named),))
    assert result.record is not None
    assert result.record.hostname == NAMES["export_prefix"] + "camera.local."


def test_longest_prefix_fills_one_label_with_what_the_owner_appends(
    config: Config, settings: owner.BonjourSettings
) -> None:
    (lan_side,) = imported(config, settings, media_record())
    (guest_side,) = exported(config, settings, camera_record())
    appended = {
        len(first_label(lan_side).removeprefix(DEFAULT["import_prefix"])),
        len(first_label(guest_side).removeprefix(DEFAULT["export_prefix"])),
    }
    assert len(appended) == 1
    room = 63 - appended.pop()
    schema = strict_load(ROOT / "schemas/network.schema.json")
    assert schema["$defs"]["label_prefix"]["maxLength"] == room
    longest = with_names({"export_prefix": "e" * room, "import_prefix": "i" * room})
    (lan_side,) = imported(longest, settings, media_record())
    (guest_side,) = exported(longest, settings, camera_record())
    assert len(first_label(lan_side).encode()) == len(first_label(guest_side).encode()) == 63
    for member in NAMES:
        with pytest.raises(ConfigError):
            with_names({**NAMES, member: "x" * (room + 1)})


# Validation


@pytest.mark.parametrize(
    "names",
    [
        {"export_prefix": "x", "import_prefix": "y"},
        {"export_prefix": "guest0", "import_prefix": "link0"},
        {"export_prefix": "example--guest-", "import_prefix": "example-0-"},
    ],
)
def test_lower_case_label_prefixes_are_accepted(names: dict[str, str]) -> None:
    assert to_dict(with_names(names))["discovery_names"] == names


@pytest.mark.parametrize(
    "value",
    [
        "",
        "Example-guest-",
        "EXAMPLE-GUEST-",
        "0example-",
        "-example-",
        "example_guest-",
        "example.guest-",
        "example guest-",
        "example-guest-\n",
        "example-gu" + chr(0xE9) + "st-",
        "example-guest-.local.",
        5,
        None,
        True,
        ["example-guest-"],
    ],
)
@pytest.mark.parametrize("member", sorted(NAMES))
def test_prefix_must_be_a_lower_case_label_prefix(member: str, value: Any) -> None:
    assert with_names(NAMES)
    with pytest.raises(ConfigError):
        with_names({**NAMES, member: value})


@pytest.mark.parametrize(
    "names",
    [
        None,
        [],
        "example-guest-",
        {},
        {"export_prefix": "example-guest-"},
        {"import_prefix": "example-link-"},
        {**NAMES, "label": "example"},
        {"export_prefix": "example-", "import_prefix": "example-"},
        {"export_prefix": "example-", "import_prefix": "example-link-"},
        {"export_prefix": "example-guest-", "import_prefix": "example-"},
        {"export_prefix": DEFAULT["export_prefix"], "import_prefix": DEFAULT["export_prefix"]},
    ],
)
def test_pair_is_closed_complete_and_tells_the_two_directions_apart(names: Any) -> None:
    assert with_names(NAMES)
    with pytest.raises(ConfigError):
        with_names(names)


def test_one_default_and_one_named_prefix_is_a_named_pair() -> None:
    names = {**DEFAULT, "import_prefix": "example-link-"}
    assert to_dict(with_names(names))["discovery_names"] == names


@pytest.mark.parametrize(
    "names",
    [
        {"export_prefix": "Example-guest-", "import_prefix": "example-link-"},
        {"export_prefix": "example-", "import_prefix": "example-link-"},
        {"export_prefix": "example-guest-", "import_prefix": "x" * 48},
        None,
    ],
)
def test_constructed_model_is_validated_like_loaded_input(config: Config, names: Any) -> None:
    pair = type(config.discovery_names)
    validate_config(replace(config, discovery_names=pair(**NAMES)))
    with pytest.raises(ConfigError):
        validate_config(replace(config, discovery_names=names and pair(**names)))


# The loop exclusion reads the pair


@pytest.mark.parametrize("field", ["name", "hostname"])
@pytest.mark.parametrize("spell", SPELLINGS)
@pytest.mark.parametrize("member", sorted(NAMES))
def test_owner_excludes_both_named_prefixes_in_both_directions(
    settings: owner.BonjourSettings, member: str, spell: Callable[[str], str], field: str
) -> None:
    named = with_names(NAMES)
    change = {field: spell(NAMES[member]) + "previous.local."}
    assert len(imported(named, settings, media_record())) == 1
    assert imported(named, settings, media_record(**change)) == ()
    assert len(exported(named, settings, camera_record())) == 1
    assert exported(named, settings, camera_record(**change)) == ()


@pytest.mark.parametrize("field", ["name", "hostname"])
@pytest.mark.parametrize("spell", SPELLINGS)
@pytest.mark.parametrize("member", sorted(NAMES))
def test_pure_contracts_exclude_both_named_prefixes_in_both_directions(
    export_record: Record,
    endpoint: Observation,
    member: str,
    spell: Callable[[str], str],
    field: str,
) -> None:
    named = with_names(NAMES)
    change = {field: spell(NAMES[member]) + "previous.local."}
    assert len(import_records(named, (lan_record(),))) == 1
    assert import_records(named, (replace(lan_record(), **change),)) == ()
    result = export(named, replace(export_record, **change), endpoint, (camera_publication(named),))
    assert (result.state, result.reason) == ("absent", "loop-excluded")


@pytest.mark.parametrize("field", ["name", "hostname"])
@pytest.mark.parametrize("spell", SPELLINGS)
@pytest.mark.parametrize("member", sorted(DEFAULT))
def test_default_prefix_is_an_ordinary_name_once_another_pair_is_named(
    config: Config,
    settings: owner.BonjourSettings,
    export_record: Record,
    endpoint: Observation,
    member: str,
    spell: Callable[[str], str],
    field: str,
) -> None:
    named = with_names(NAMES)
    change = {field: spell(DEFAULT[member]) + "previous.local."}
    # Excluded while the pair is the default, as before ...
    assert imported(config, settings, media_record(**change)) == ()
    assert exported(config, settings, camera_record(**change)) == ()
    assert import_records(config, (replace(lan_record(), **change),)) == ()
    # ... and a record like any other under the named pair.
    assert len(imported(named, settings, media_record(**change))) == 1
    assert len(exported(named, settings, camera_record(**change))) == 1
    assert len(import_records(named, (replace(lan_record(), **change),))) == 1
    result = export(named, replace(export_record, **change), endpoint, (camera_publication(named),))
    assert (result.state, result.reason) == ("present", "verified")


def test_exclusion_compares_ascii_case_only(settings: owner.BonjourSettings) -> None:
    named = with_names(NAMES)
    # U+212A KELVIN SIGN lower-cases to "k" under Unicode rules; DNS does not fold it.
    kelvin = NAMES["import_prefix"].replace("k", chr(0x212A))
    assert kelvin.lower() == NAMES["import_prefix"] and kelvin != NAMES["import_prefix"]
    assert len(imported(named, settings, media_record(hostname=kelvin + "previous.local."))) == 1


def test_record_left_under_another_pair_is_projected_at_most_once(
    config: Config, settings: owner.BonjourSettings
) -> None:
    """After a change of the pair an earlier run's records are ordinary records.

    An export that the earlier run left on the LAN can be imported like any
    eligible device there. What this run then projects carries its own prefix,
    which it refuses in both directions, so nothing is projected a second time.
    An import the earlier run left on the guest network is never exported: its
    address is not the guest's.
    """
    named = with_names(NAMES)
    scope = named.scope(policy(named).scope)
    left_export = media_record(
        hostname=DEFAULT["export_prefix"] + "0123456789abcdef.local.", ipv4=scope.host_ipv4
    )
    assert imported(config, settings, left_export) == ()
    (reflected,) = imported(named, settings, left_export)
    assert first_label(reflected).startswith(NAMES["import_prefix"])
    assert imported(named, settings, replace(reflected, interface=scope.interface)) == ()
    assert exported(named, settings, reflected) == ()
    left_import = media_record(
        hostname=DEFAULT["import_prefix"] + "0123456789abcdef.local.",
        interface=settings.scopes[0].guest_interface,
        service_type="_hap._tcp",
        port=9443,
    )
    assert exported(named, settings, left_import) == ()


def test_scan_pass_and_lease_carry_the_named_prefixes(
    monkeypatch: pytest.MonkeyPatch, settings: owner.BonjourSettings
) -> None:
    named = with_names(NAMES)
    current = snapshot(named)
    ready = frozenset({"media-udp", "camera-web"})
    clock = type(
        "Clock", (), {"time": staticmethod(lambda: 1000), "monotonic": staticmethod(lambda: 10)}
    )()
    monkeypatch.setattr(owner, "time", clock)
    monkeypatch.setattr(owner, "independent_snapshot", lambda *_args: (current, Intent(), ready))
    monkeypatch.setattr(owner, "_interfaces", lambda *_args: {settings.scopes[0].id: (7, 9)})

    def scan(interface: str, _index: int, kind: str, *_bounds: Any) -> tuple[Record, ...]:
        if kind == "_airplay._tcp":
            return (media_record(),)
        if kind == "_hap._tcp":
            return (camera_record(interface=interface),)
        return ()

    monkeypatch.setattr(owner, "scan", scan)
    store = Store(settings.state_dir)
    owner.scan_pass(named, settings, store)
    candidates = store.read("candidates.json")["policies"]
    for identifier, member in (
        ("media-import", "import_prefix"),
        ("camera-export", "export_prefix"),
    ):
        item = policy(named, identifier)
        request = {
            "active": True,
            "policy_digest": discovery_digest(named, item),
            "service_generation": current.services[item.service].generation,
            "network_generation": current.network_generation,
            "requested_at": 1000,
        }
        leased = owner.lease_records(
            named, item, request, candidates[identifier], current, Intent(), ready, 1000
        )
        assert leased is not None and len(leased) == 1
        assert first_label(leased[0]).startswith(NAMES[member])

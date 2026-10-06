"""`return_path: "independent"`: a discovery import that does not wait for a UDP return path.

The setting exists in the instance (a discovery selection) and in the retained
policy (a discovery entry). Without it nothing changes. The digests in ``BASE``
were computed on the tree before the member existed, for the shipped examples
as they were then, so the tests that only use them also pass on that tree. They
are here to show that a document without the setting keeps its bytes and digests.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch import host_report
from netorch.bonjour_process import DiscoveryFailure
from netorch.codec import canonical_bytes, digest
from netorch.config import (
    ConfigError,
    config_digest,
    parse_config,
    profile_digest,
    to_dict,
    validate_config,
)
from netorch.discovery_plan import discovery_digest
from netorch.instance import (
    InstanceError,
    canonical_instance_bytes,
    instance_contract_digest,
    instance_digest,
    instance_to_dict,
    load_instance,
    resolved_discovery_digest,
    validate_instance,
)
from netorch.instance_model import DiscoverySelection, Instance
from netorch.model import Config, Discovery
from netorch.requirements import REQUIREMENTS
from netorch.state import Intent, Observation, Snapshot
from netorch.storage import Store
from tests.test_bonjour_owner import media_record, old_discovery_digest
from tests.test_bonjour_owner import snapshot as verified_transport
from tests.test_discovery_plan import decisions, ready_snapshot
from tests.test_report_guards import attest, parsed, platform, ready, report, status

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
AUDIO = ("HEARD-AUDIO", "MULTI-RECEIVER")
# On the base tree the retained discovery digest has version 3. Open changes to the
# owner's runtime behaviour raise that number to 4 and hash the same members.
POLICY_DIGEST_VERSIONS = (3, 4)
BASE: dict[str, dict[str, Any]] = {
    "instance.json": {
        "instance_digest": "f0adf2a76ad106f1ed758b0ab9f05388a15b4e11934f37faa68e377190ff732e",
        "contract_digest": "bc7d92900c617507a7d1dfe150df3600fff3d5ad29c1a0a72b467779f16f7a9c",
        "discovery": {
            "example-export": "a87cb58580aef982e565caa79bb489da0f3996ac5e1c3c45709c3811c6f1ff86",
            "example-import": "3a399f2f69074be0231e436d0902815936a10c506b77ec7c6cdf609e002c7af3",
        },
    },
    "instance-structural.json": {
        "instance_digest": "345a770371a6dc244234050cd606dd5222d277782a2c27529bc568f5fb92bb23",
        "contract_digest": "6489191df8f66f366323fcd61091c69a45bc2676f5f215e25f6a218674a3fa5e",
        "discovery": {
            "example-export": "397d48b2f0097fe344366050efc7ff1ffa9e9178445189ed3d8819c3c766e54d",
        },
    },
    "network.json": {
        "canonical_sha256": "1fbb9601273c11e82d26781b31e9b2754340e10695b26980c470f2534b99d432",
        "config_digest": "bfb7a0957461cf456564604ee10a94f3af0253c980dde45c73a1c7ed355548f5",
        "discovery": {
            "camera-export": "e24a871f7ff5f283e993455cd2413555a704a975ce90c7e045355b279803c039",
            "media-import": "d6b1f54c7ca19795462baf0069e3342863bf125586505b51f4193c18c5550d2c",
        },
    },
    "network-dns-fallback.json": {
        "canonical_sha256": "c6bd9e6c00b3c49229ea3aad3eb6485c0623b8320214d96f714aba46926e9219",
        "config_digest": "937f20c1c24ddefadb3d20d8ab8ee2ecf13983e1d0a800a6ff5f4142572a7651",
        "discovery": {
            "camera-export": "e24a871f7ff5f283e993455cd2413555a704a975ce90c7e045355b279803c039",
            "media-import": "d6b1f54c7ca19795462baf0069e3342863bf125586505b51f4193c18c5550d2c",
        },
    },
}


def shipped(name: str = "instance.json") -> dict[str, Any]:
    """A shipped instance as it was when ``BASE`` was taken.

    A release changes the release pin of the examples and nothing else.
    """
    data: dict[str, Any] = json.loads((EXAMPLES / name).read_bytes())
    data["framework"]["version"] = "0.3.2"
    return data


def selection(data: dict[str, Any], direction: str = "import") -> dict[str, Any]:
    found: dict[str, Any] = next(
        item for item in data["discovery"] if item["direction"] == direction
    )
    return found


def independent(data: dict[str, Any]) -> dict[str, Any]:
    selection(data).update(dependencies=[], return_path="independent")
    return data


def without_return_profile(data: dict[str, Any]) -> dict[str, Any]:
    data["transport"] = [
        item for item in data["transport"] if item["strategy"] != "guest-udp-range-forward"
    ]
    return data


def resolved(data: dict[str, Any]) -> dict[str, str]:
    instance = parsed(data)
    return {item.id: resolved_discovery_digest(instance, item) for item in instance.discovery}


# ---- a document written before the member existed keeps its bytes and digests


@pytest.mark.parametrize("name", ["instance.json", "instance-structural.json"])
def test_shipped_instances_keep_their_bytes_and_every_digest(name: str) -> None:
    raw = (EXAMPLES / name).read_bytes()
    live = load_instance(EXAMPLES / name)
    assert canonical_instance_bytes(live) == raw
    assert instance_to_dict(live) == json.loads(raw)
    instance = parsed(shipped(name))
    assert instance_digest(instance) == BASE[name]["instance_digest"]
    assert instance_contract_digest(instance) == BASE[name]["contract_digest"]
    assert resolved(shipped(name)) == BASE[name]["discovery"]


def entry_digest(config: Config, entry: dict[str, Any], version: int) -> str:
    """What the base tree hashed for one entry: the entry as written, and nothing else."""
    service = config.service(entry["service"])
    return digest(
        {
            "digest_version": version,
            "schema_version": config.schema_version,
            "discovery": entry,
            "scope": asdict(config.scope(entry["scope"])),
            "service": asdict(service),
            "service_owner": asdict(config.owner(service.owner)),
            "owner": asdict(config.owner(entry["owner"])),
            "dependencies": {
                identifier: profile_digest(config, config.profile(identifier))
                for identifier in sorted(entry["dependencies"])
            },
        }
    )


@pytest.mark.parametrize("name", ["network.json", "network-dns-fallback.json"])
def test_shipped_policies_keep_their_canonical_form_and_digests(name: str) -> None:
    written = json.loads((EXAMPLES / name).read_bytes())
    config = parse_config(canonical_bytes(written))
    canonical = to_dict(config)
    assert hashlib.sha256(canonical_bytes(canonical)).hexdigest() == BASE[name]["canonical_sha256"]
    assert config_digest(config) == BASE[name]["config_digest"]
    assert all("return_path" not in item for item in canonical["discovery"])
    for item, entry in zip(config.discovery, written["discovery"], strict=True):
        assert "return_path" not in entry
        # The literal ties this formula to what the base tree returned for the entry.
        assert entry_digest(config, entry, 3) == BASE[name]["discovery"][item.id]
        assert discovery_digest(config, item) in {
            entry_digest(config, entry, version) for version in POLICY_DIGEST_VERSIONS
        }


@pytest.mark.parametrize("name", ["network.json", "network-dns-fallback.json"])
def test_frozen_prior_envelope_of_the_owner_tests_is_what_the_base_tree_hashed(name: str) -> None:
    # tests/test_bonjour_owner.py refuses approvals of earlier digest versions with this
    # envelope. It stays exact only while no later member of the model enters it.
    config = parse_config((EXAMPLES / name).read_bytes())
    for item in config.discovery:
        assert old_discovery_digest(config, item, 3) == BASE[name]["discovery"][item.id]


@pytest.mark.parametrize("value", ["required", None, "", "Independent", True, ["independent"]])
@pytest.mark.parametrize("direction", ["import", "export"])
def test_the_default_has_no_spelling_in_the_instance(direction: str, value: Any) -> None:
    data = shipped()
    selection(data, direction)["return_path"] = value
    with pytest.raises(InstanceError, match="closed versioned schema"):
        parsed(data)


# ---- the instance: an import that says it does not depend on the return path


def test_import_without_a_return_path_is_said_explicitly() -> None:
    data = shipped()
    selection(data)["dependencies"] = []
    with pytest.raises(InstanceError, match="transport dependency"):
        parsed(data)  # leaving the dependency out silently is refused as before
    selection(data)["return_path"] = "independent"
    instance = parsed(data)
    chosen = next(item for item in instance.discovery if item.direction == "import")
    assert (chosen.return_path, chosen.dependencies) == ("independent", ())
    assert canonical_instance_bytes(instance) == canonical_bytes(data) + b"\n"
    assert instance_to_dict(instance)["discovery"] == data["discovery"]
    digests = resolved(data)
    assert digests["example-export"] == BASE["instance.json"]["discovery"]["example-export"]
    assert digests["example-import"] != BASE["instance.json"]["discovery"]["example-import"]


def test_independent_import_lists_no_return_path_and_is_no_export_setting() -> None:
    data = shipped()
    selection(data)["return_path"] = "independent"
    with pytest.raises(InstanceError, match="lists no return-path dependency"):
        parsed(data)
    data = shipped()
    selection(data, "export")["return_path"] = "independent"
    with pytest.raises(InstanceError, match="only an import"):
        parsed(data)
    # Nothing else is lifted: what the selection lists must still be declared.
    data = independent(shipped())
    selection(data)["dependencies"] = ["example-missing"]
    with pytest.raises(InstanceError, match="does not identify declared data"):
        parsed(data)
    selection(data)["dependencies"] = ["example-publication"]
    assert parsed(data).discovery[1].dependencies == ("example-publication",)


def test_constructed_selection_is_validated_like_a_parsed_one() -> None:
    instance = parsed(shipped())
    export, imported = instance.discovery

    def having(changed: DiscoverySelection) -> Instance:
        return replace(
            instance,
            discovery=tuple(
                changed if item.id == changed.id else item for item in (export, imported)
            ),
        )

    validate_instance(having(replace(imported, return_path="independent", dependencies=())))
    for changed, reason in (
        (replace(imported, return_path="independent"), "lists no return-path dependency"),
        (replace(export, return_path="independent"), "only an import"),
        (replace(imported, return_path="optional", dependencies=()), "closed versioned schema"),
        (replace(imported, return_path=None, dependencies=()), "closed versioned schema"),
    ):
        with pytest.raises(InstanceError, match=reason):
            validate_instance(having(changed))


@pytest.mark.parametrize(
    "change",
    [
        "container-name",
        "reconcile-interval",
        "health-interval",
        "discovery-interval",
        "discovery-misses",
        "read-timeout",
        "account-uid",
        "account-gid",
        "runtime-network",
        "runtime-version",
        "macos-build",
        "macos-version",
        "framework-artifact",
    ],
)
def test_independent_import_binds_its_target_and_supervision_itself(
    tmp_path: Path, change: str
) -> None:
    # A selection binds these through the resolved digest of its required
    # dependency. An import without one must not lose them.
    data = independent(shipped())
    attest(data, tmp_path, "DISCOVERY-IMPORT", "cold-application-scan", 5, "example-import")
    members = ready(data)
    before = report(data, platform(), members, evidence_directory=tmp_path)
    assert before["current_ready"]
    assert status(before, "DISCOVERY-IMPORT") == "fulfilled-verified"
    digest_before = resolved(data)["example-import"]
    if change == "container-name":
        data["workloads"][1]["name"] = "example-renamed-media"
    elif change == "framework-artifact":
        data["framework"]["artifact_sha256"] = "1" * 64
    elif change.startswith("account-"):
        data["host"]["account"][change.removeprefix("account-")] += 1
    elif change == "runtime-network":
        data["host"]["runtime"]["network"] = "example-other-network"
    elif change == "runtime-version":
        data["host"]["runtime"]["version"] = "1.2.0"
    elif change == "macos-build":
        data["host"]["platform"]["macos_build"] = "26A435"
    elif change == "macos-version":
        data["host"]["platform"]["macos_version"] = "27.0.2"
    else:
        setting = {
            "reconcile-interval": "reconcile_seconds",
            "health-interval": "health_seconds",
            "discovery-interval": "discovery_seconds",
            "discovery-misses": "discovery_misses",
            "read-timeout": "read_timeout_seconds",
        }[change]
        data["supervision"][setting] += 1
    assert resolved(data)["example-import"] != digest_before
    after = report(data, platform(), members, evidence_directory=tmp_path)
    assert not after["current_ready"]
    assert status(after, "DISCOVERY-IMPORT") != "fulfilled-verified"


def composites(result: dict[str, Any]) -> dict[str, str]:
    return {row["id"]: row["composite"] for row in result["discovery_profiles"]}


def test_report_row_of_an_import_without_dependencies_claims_none_present() -> None:
    coupled = shipped()
    assert composites(report(coupled)) == {
        "example-export": "discovery-unknown, dependencies-unknown",
        "example-import": "discovery-unknown, dependencies-unknown",
    }
    assert composites(report(coupled, members=ready(coupled))) == {
        "example-export": "discovery-present, dependencies-present",
        "example-import": "discovery-present, dependencies-present",
    }
    data = independent(shipped())
    assert report(data)["discovery_profiles"][1]["dependencies"] == []
    assert composites(report(data))["example-import"] == "discovery-unknown, dependencies-none"
    current = report(data, members=ready(data))
    assert composites(current) == {
        "example-export": "discovery-present, dependencies-present",
        "example-import": "discovery-present, dependencies-none",
    }
    assert current["current_ready"]


# ---- the two requirements about audible playback


def applicable(result: dict[str, Any], identifier: str) -> bool:
    return status(result, identifier) != "not-applicable"


def test_audible_playback_is_asked_only_where_the_workload_has_a_return_path() -> None:
    coupled = report(shipped())
    assert all(applicable(coupled, key) for key in (*AUDIO, "IMPORT-VISIBILITY"))
    # The import no longer lists the return path, the workload still declares it.
    separate = report(independent(shipped()))
    assert all(applicable(separate, key) for key in AUDIO)
    alone = report(without_return_profile(independent(shipped())))
    assert not any(applicable(alone, key) for key in AUDIO)
    assert applicable(alone, "IMPORT-VISIBILITY") and applicable(alone, "DISCOVERY-IMPORT")
    assert applicable(alone, "DISCOVERY-LEASES") and applicable(alone, "CONSENT-IDENTITY")


def test_audio_acceptance_counts_only_imports_that_have_a_return_path(tmp_path: Path) -> None:
    def mixed() -> dict[str, Any]:
        data = shipped()
        data["discovery"].append(
            {
                "id": "example-web-import",
                "service": "example-web",
                "profile": "apple-media-import",
                "version": 1,
                "direction": "import",
                "dependencies": [],
                "return_path": "independent",
            }
        )
        return data

    def heard(data: dict[str, Any], *profiles: str) -> str:
        for profile in profiles:
            attest(data, tmp_path, "HEARD-AUDIO", "heard-audio", 5, profile, context="host-person")
        return status(report(data, platform(), evidence_directory=tmp_path), "HEARD-AUDIO")

    def scanned(data: dict[str, Any], *profiles: str) -> str:
        for profile in profiles:
            attest(data, tmp_path, "DISCOVERY-IMPORT", "cold-application-scan", 5, profile)
        return status(report(data, platform(), evidence_directory=tmp_path), "DISCOVERY-IMPORT")

    # One import has a return path, the other cannot play audio at all.
    assert heard(mixed(), "example-import") == "fulfilled-verified"
    assert heard(mixed(), "example-web-import") != "fulfilled-verified"
    # Every other requirement about imports still asks for both.
    assert scanned(mixed(), "example-import") != "fulfilled-verified"
    assert scanned(mixed(), "example-import", "example-web-import") == "fulfilled-verified"


@pytest.mark.parametrize("name", ["instance.json", "instance-structural.json"])
def test_reports_of_the_shipped_instances_do_not_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    data = json.loads((EXAMPLES / name).read_bytes())
    attested = copy.deepcopy(data)
    for item in attested["discovery"]:
        if item["direction"] == "import":
            attest(
                attested,
                tmp_path,
                "HEARD-AUDIO",
                "heard-audio",
                5,
                item["id"],
                context="host-person",
            )
            attest(attested, tmp_path, "MULTI-RECEIVER", "port-budget", 5, item["id"])

    def reports() -> list[dict[str, Any]]:
        return [
            report(data),
            report(attested, platform(), ready(attested), evidence_directory=tmp_path),
        ]

    current = reports()
    if name == "instance.json":
        assert all(status(current[1], key) == "fulfilled-verified" for key in AUDIO)
    else:
        assert not any(applicable(current[1], key) for key in AUDIO)
    # The same reports with the applicability the two requirements had before.
    former = tuple(
        replace(item, applicability="imports") if item.id in AUDIO else item
        for item in REQUIREMENTS
    )
    monkeypatch.setattr(host_report, "REQUIREMENTS", former)
    assert reports() == current


# ---- the retained policy says the same thing in its own words


def policy() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((EXAMPLES / "network.json").read_bytes())
    return data


def entry(data: dict[str, Any], direction: str = "import") -> dict[str, Any]:
    return selection(data, direction)


def independent_policy() -> dict[str, Any]:
    data = policy()
    entry(data).update(dependencies=[], return_path="independent")
    return data


def media(config: Config) -> Discovery:
    return next(item for item in config.discovery if item.direction == "import")


def test_policy_import_is_independent_only_when_it_says_so() -> None:
    data = policy()
    entry(data)["dependencies"] = []
    with pytest.raises(ConfigError, match="UDP return dependency"):
        parse_config(json.dumps(data))  # leaving the dependency out silently is refused as before
    config = parse_config(json.dumps(independent_policy()))
    chosen = media(config)
    assert (chosen.return_path, chosen.dependencies) == ("independent", ())
    validate_config(config)
    canonical = to_dict(config)
    assert entry(canonical)["return_path"] == "independent"
    assert "return_path" not in entry(canonical, "export")
    assert parse_config(canonical_bytes(canonical)) == config
    original = parse_config(json.dumps(policy()))
    assert config_digest(config) != config_digest(original)
    export = next(item for item in config.discovery if item.direction == "export")
    assert discovery_digest(config, export) == discovery_digest(original, export)
    # Neither the coupled entry nor the same entry without the setting has this digest.
    assert discovery_digest(config, chosen) != discovery_digest(original, media(original))
    assert discovery_digest(config, chosen) != discovery_digest(
        config, replace(chosen, return_path="required")
    )


@pytest.mark.parametrize("direction", ["import", "export"])
def test_policy_default_can_be_written_and_equals_leaving_it_out(direction: str) -> None:
    data = policy()
    entry(data, direction)["return_path"] = "required"
    config = parse_config(json.dumps(data))
    original = parse_config(json.dumps(policy()))
    assert config == original
    assert to_dict(config) == to_dict(original)
    assert config_digest(config) == BASE["network.json"]["config_digest"]


def test_policy_refuses_the_setting_for_an_export_or_beside_a_return_dependency() -> None:
    data = policy()
    entry(data)["return_path"] = "independent"  # still lists its return path
    with pytest.raises(ConfigError, match="independent of the return path"):
        parse_config(json.dumps(data))
    data = policy()
    entry(data, "export")["return_path"] = "independent"
    with pytest.raises(ConfigError, match="independent of the return path"):
        parse_config(json.dumps(data))
    # Nothing else is lifted: what the entry lists must still be declared.
    data = independent_policy()
    entry(data)["dependencies"] = ["missing"]
    with pytest.raises(ConfigError, match="Unknown profile"):
        parse_config(json.dumps(data))


@pytest.mark.parametrize("value", [None, "", "Independent", True, ["independent"]])
def test_policy_setting_is_one_of_two_words(value: Any) -> None:
    data = independent_policy()
    entry(data)["return_path"] = value
    with pytest.raises(ConfigError, match="Schema violation"):
        parse_config(json.dumps(data))
    config = parse_config(json.dumps(independent_policy()))
    changed = replace(media(config), return_path=value)
    with pytest.raises(ConfigError, match="Schema violation"):
        validate_config(replace(config, discovery=(changed, *config.discovery[1:])))


def test_setting_is_hashed_even_where_no_return_path_was_required() -> None:
    data = policy()
    entry(data).update(types=["_companion-link._tcp"], dependencies=[])
    plain = parse_config(json.dumps(data))  # accepted before, without the setting
    entry(data)["return_path"] = "independent"
    said = parse_config(json.dumps(data))
    assert discovery_digest(said, media(said)) != discovery_digest(plain, media(plain))


# ---- the retained planner and the bundled owner need no change


def return_unverified(config: Config, snapshot: Snapshot) -> Snapshot:
    """The same observations, with every UDP return profile unobserved."""
    return replace(
        snapshot,
        profiles={
            key: value
            if key not in {item.id for item in config.profiles if item.kind == "udp-return"}
            else Observation("unknown", "unobserved", snapshot.observed_at, None)
            for key, value in snapshot.profiles.items()
        },
    )


def test_independent_import_is_planned_while_the_return_path_is_not_verified() -> None:
    coupled = parse_config(json.dumps(policy()))
    action = decisions(coupled, return_unverified(coupled, ready_snapshot(coupled)))["media-import"]
    assert (action.active, action.reason) == (False, "transport-unverified")
    config = parse_config(json.dumps(independent_policy()))
    action = decisions(config, return_unverified(config, ready_snapshot(config)))["media-import"]
    assert (action.active, action.reason) == (True, "ready")
    assert action.policy_digest == discovery_digest(config, media(config))


def owner_settings(tmp_path: Path) -> owner.BonjourSettings:
    return owner.BonjourSettings(
        "bonjour-manager",
        tmp_path / "network.json",
        tmp_path / "bindings.json",
        tmp_path / "admissions.json",
        tmp_path / "intent.json",
        tmp_path / "state",
        (owner.GuestInterface("wired-lan", "bridge-test", "198.51.100.1"),),
    )


def test_bundled_owner_projects_an_independent_import_without_the_return_path(
    tmp_path: Path,
) -> None:
    nothing_ready: frozenset[str] = frozenset()
    coupled = parse_config(json.dumps(policy()))
    current = return_unverified(coupled, verified_transport(coupled))
    assert not owner.dependencies_ready(
        coupled, media(coupled), current, Intent(), nothing_ready, 1000
    )
    with pytest.raises(DiscoveryFailure):
        owner.project_records(
            coupled,
            media(coupled),
            (media_record(),),
            current,
            nothing_ready,
            owner_settings(tmp_path),
            1000,
        )
    config = parse_config(json.dumps(independent_policy()))
    current = return_unverified(config, verified_transport(config))
    assert owner.dependencies_ready(config, media(config), current, Intent(), nothing_ready, 1000)
    projected = owner.project_records(
        config,
        media(config),
        (media_record(),),
        current,
        nothing_ready,
        owner_settings(tmp_path),
        1000,
    )
    assert [(item.name, item.interface) for item in projected] == [
        (media_record().name, "bridge-test")
    ]
    # Its other gates stay: a paused owner, or a consumer that is not present, projects nothing.
    assert not owner.dependencies_ready(
        config, media(config), current, Intent(operator_paused=True), nothing_ready, 1000
    )
    absent = replace(current, services={})
    assert not owner.dependencies_ready(
        config, media(config), absent, Intent(), nothing_ready, 1000
    )


@pytest.mark.parametrize("prior", ["coupled", "same-entry-without-the-setting"])
@pytest.mark.parametrize("field", ["request", "candidate", "endpoint"])
def test_bundled_owner_refuses_an_approval_given_without_the_setting(
    tmp_path: Path, field: str, prior: str
) -> None:
    config = parse_config(json.dumps(independent_policy()))
    chosen = media(config)
    current = return_unverified(config, verified_transport(config))
    coupled = parse_config(json.dumps(policy()))
    old = (
        discovery_digest(coupled, media(coupled))
        if prior == "coupled"
        else discovery_digest(config, replace(chosen, return_path="required"))
    )
    settings = owner_settings(tmp_path)
    records = owner.project_records(
        config, chosen, (media_record(),), current, frozenset(), settings, 1000
    )
    common = {
        "policy_digest": discovery_digest(config, chosen),
        "service_generation": current.services[chosen.service].generation,
        "network_generation": current.network_generation,
    }
    request = {**common, "active": True, "requested_at": 1000}
    candidate = {
        **common,
        "records": [owner.record_to_dict(item) for item in records],
        "interface_confirmed": True,
        "observed_at": 1000,
    }

    def leased() -> Any:
        return owner.lease_records(
            config, chosen, request, candidate, current, Intent(), frozenset(), 1000
        )

    assert leased() == records
    if field == "endpoint":
        fixed = {
            "protocol_version": 1,
            "operation": "reconcile-discovery",
            "owner": settings.owner,
            "policy_digest": config_digest(config),
            "discovery_digest": old,
            "discovery": chosen.id,
            "active": True,
            "config": to_dict(config),
            "service_generation": current.services[chosen.service].generation,
            "network_generation": current.network_generation,
        }
        with pytest.raises(ValueError, match="invalid fixed discovery request"):
            owner.endpoint(config, settings, Store(settings.state_dir), fixed)
        assert not (settings.state_dir / "requests.json").exists()
    else:
        (request if field == "request" else candidate)["policy_digest"] = old
        assert leased() is None

"""`misses` on a discovery entry: that policy's own miss tolerance.

The bundled discovery owner has one `miss_tolerance` for all its policies. An
entry of the policy that states `misses` (1 to 8) replaces it for that policy
alone; an entry without the member follows the owner's setting as before. The
values in ``BASE`` were computed on the tree before the member existed, so the
tests that only use them pass there too: they show that a policy without the
member keeps its bytes and both digests. Addresses are RFC 5737, names are
invented, the clock and every native read are fakes.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest

from netorch import bonjour_owner as owner
from netorch.codec import canonical_bytes, digest, strict_load
from netorch.config import (
    ConfigError,
    config_digest,
    parse_config,
    profile_digest,
    to_dict,
    validate_config,
)
from netorch.discovery_plan import discovery_digest
from netorch.model import Config, Owner
from netorch.state import Intent
from tests.test_bonjour_miss_tolerance import (
    EXPORT,
    IMPORT,
    LEASE,
    READY,
    START,
    Passes,
    camera,
    leased,
    names,
    observed,
    serve,
    settings_file,
    speaker,
    tolerant,
)
from tests.test_bonjour_owner import (
    FakeRegistration,
    candidate_request,
    config,
    media_record,
    policy,
    publisher,
    settings,
    snapshot,
)

__all__ = ["config", "settings"]

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
# Taken on the base tree: the canonical form of each shipped policy, its policy
# digest and the discovery digest (version 4) of each of its entries.
BASE: dict[str, dict[str, Any]] = {
    "network.json": {
        "canonical_sha256": "1fbb9601273c11e82d26781b31e9b2754340e10695b26980c470f2534b99d432",
        "config_digest": "bfb7a0957461cf456564604ee10a94f3af0253c980dde45c73a1c7ed355548f5",
        "discovery": {
            "media-import": "c33c9b2eb6a5941a65aa2e35f421d4b00166a2105c12923d7271599987eb1ab0",
            "camera-export": "87d3a5b31c5862bc68c9390a73cf13582b81f098d9ee09c1643c7fc7a12f267c",
        },
    },
    "network-dns-fallback.json": {
        "canonical_sha256": "c6bd9e6c00b3c49229ea3aad3eb6485c0623b8320214d96f714aba46926e9219",
        "config_digest": "937f20c1c24ddefadb3d20d8ab8ee2ecf13983e1d0a800a6ff5f4142572a7651",
        "discovery": {
            "media-import": "c33c9b2eb6a5941a65aa2e35f421d4b00166a2105c12923d7271599987eb1ab0",
            "camera-export": "87d3a5b31c5862bc68c9390a73cf13582b81f098d9ee09c1643c7fc7a12f267c",
        },
    },
}


def written(name: str = "network.json") -> dict[str, Any]:
    data: dict[str, Any] = json.loads((EXAMPLES / name).read_bytes())
    return data


def entry(data: dict[str, Any], identifier: str) -> dict[str, Any]:
    found: dict[str, Any] = next(item for item in data["discovery"] if item["id"] == identifier)
    return found


def parsed(data: dict[str, Any]) -> Config:
    return parse_config(canonical_bytes(data))


def sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def tolerating(identifier: str, misses: Any, name: str = "network.json") -> dict[str, Any]:
    """A shipped policy, as JSON, whose one entry states a tolerance of its own."""
    data = written(name)
    entry(data, identifier)["misses"] = misses
    return data


def stating(config: Config, tolerances: dict[str, int]) -> Config:
    """The policy with a miss tolerance of its own on the named discovery entries."""
    return replace(
        config,
        discovery=tuple(
            replace(item, misses=tolerances[item.id]) if item.id in tolerances else item
            for item in config.discovery
        ),
    )


def entry_digest(config: Config, item: dict[str, Any], version: int = 5) -> str:
    """The versioned envelope around one entry exactly as the policy file writes it."""
    service = config.service(item["service"])
    return digest(
        {
            "digest_version": version,
            "schema_version": config.schema_version,
            "discovery": item,
            "scope": asdict(config.scope(item["scope"])),
            "service": asdict(service),
            "service_owner": asdict(config.owner(service.owner)),
            "owner": asdict(config.owner(item["owner"])),
            "dependencies": {
                identifier: profile_digest(config, config.profile(identifier))
                for identifier in sorted(item["dependencies"])
            },
        }
    )


# A policy written before the member existed keeps its bytes and both digests


@pytest.mark.parametrize("name", sorted(BASE))
def test_shipped_policies_keep_their_canonical_form_and_both_digests(name: str) -> None:
    data = written(name)
    config = parsed(data)
    canonical = to_dict(config)
    assert sha256(canonical) == BASE[name]["canonical_sha256"]
    assert config_digest(config) == BASE[name]["config_digest"]
    assert all("misses" not in item for item in canonical["discovery"])
    for item, as_written in zip(config.discovery, data["discovery"], strict=True):
        assert discovery_digest(config, item) == entry_digest(config, as_written)
        assert discovery_digest(config, item) != BASE[name]["discovery"][item.id]
        # The literal ties the formula below to what the base tree hashed.
        assert entry_digest(config, as_written, 4) == BASE[name]["discovery"][item.id]


def test_entry_without_the_member_has_none_and_a_constructed_one_validates(
    config: Config,
) -> None:
    assert [item.misses for item in config.discovery] == [None, None]
    validate_config(config)
    assert "misses" not in json.dumps(to_dict(config))


# The member


def test_policy_schema_gains_one_optional_member_of_a_discovery_entry() -> None:
    schema = strict_load(ROOT / "schemas/network.schema.json")["$defs"]["discovery"]
    assert schema["properties"]["misses"] == {"type": "integer", "minimum": 1, "maximum": 8}
    assert "misses" not in schema["required"]
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) - set(schema["required"]) == {"return_path", "misses"}


@pytest.mark.parametrize("identifier", [IMPORT, EXPORT])
@pytest.mark.parametrize("misses", [1, 2, 3, 4, 5, 6, 7, 8])
def test_entry_may_state_its_own_tolerance(identifier: str, misses: int) -> None:
    data = tolerating(identifier, misses)
    config = parsed(data)
    other = EXPORT if identifier == IMPORT else IMPORT
    assert (policy(config, identifier).misses, policy(config, other).misses) == (misses, None)
    validate_config(config)
    # The canonical form reads back, and the stated member is all that it adds
    # to the canonical form of the policy without it.
    canonical = to_dict(config)
    assert parsed(canonical) == config and to_dict(parsed(canonical)) == canonical
    assert entry(canonical, identifier).pop("misses") == misses
    assert "misses" not in entry(canonical, other)
    assert sha256(canonical) == BASE["network.json"]["canonical_sha256"]
    # A stated tolerance is a new input: another policy digest, another digest
    # of that entry, and the entry that states nothing keeps its current digest.
    base = BASE["network.json"]
    assert config_digest(config) != base["config_digest"]
    stated = discovery_digest(config, policy(config, identifier))
    assert stated != base["discovery"][identifier]
    assert stated == entry_digest(config, entry(data, identifier))
    default = parsed(written())
    assert discovery_digest(config, policy(config, other)) == discovery_digest(
        default, policy(default, other)
    )
    another = parsed(tolerating(identifier, 2 if misses == 1 else 1))
    assert discovery_digest(another, policy(another, identifier)) != stated


REFUSED = [
    (0, "misses (minimum)"),
    (9, "misses (maximum)"),
    (-1, "misses (minimum)"),
    (True, "misses (type)"),
    ("3", "misses (type)"),
    ([3], "misses (type)"),
    (1.5, "misses (type)"),
    # A whole number written with a fraction satisfies the schema's "integer".
    (2.0, "a miss tolerance is an integer from 1 to 8"),
]


@pytest.mark.parametrize(("misses", "reason"), [*REFUSED, (None, "misses (type)")])
@pytest.mark.parametrize("identifier", [IMPORT, EXPORT])
def test_tolerance_is_a_json_integer_from_one_to_eight(
    identifier: str, misses: Any, reason: str
) -> None:
    assert parsed(tolerating(identifier, 2))
    with pytest.raises(ConfigError, match=re.escape(reason)):
        parsed(tolerating(identifier, misses))


@pytest.mark.parametrize(("misses", "reason"), REFUSED)
def test_constructed_entry_is_validated_like_a_parsed_one(
    config: Config, misses: Any, reason: str
) -> None:
    validate_config(stating(config, {IMPORT: 1, EXPORT: 8}))
    with pytest.raises(ConfigError, match=re.escape(reason)):
        validate_config(stating(config, {EXPORT: misses}))


def test_evidence_for_the_entry_without_the_member_is_refused_for_the_one_with_it(
    config: Config, settings: owner.BonjourSettings
) -> None:
    current = snapshot(config)
    stated = stating(config, {IMPORT: 3})
    arguments = (current, Intent(), frozenset({"media-udp"}), 1000)
    plain = candidate_request(config, settings, current, media_record())
    own = candidate_request(stated, settings, current, media_record())
    assert owner.lease_records(config, policy(config), *plain, *arguments)
    assert owner.lease_records(stated, policy(stated), *own, *arguments)
    # Neither an approval nor a candidate made for the other entry carries over.
    assert owner.lease_records(stated, policy(stated), *plain, *arguments) is None
    assert owner.lease_records(config, policy(config), *own, *arguments) is None
    for mixed in ((plain[0], own[1]), (own[0], plain[1])):
        assert owner.lease_records(stated, policy(stated), *mixed, *arguments) is None


# The scanner: each policy counts with its own number


def scanner_memory(
    monkeypatch: pytest.MonkeyPatch, config: Config, settings: owner.BonjourSettings
) -> Any:
    """The memory the scanner process itself builds for this policy and these settings."""
    given: list[Any] = []
    with monkeypatch.context() as patch:
        serve(patch, config, settings, lambda *arguments: given.append(arguments[3]), 1)
    return given[0]


def scanner_passes(
    monkeypatch: pytest.MonkeyPatch, config: Config, settings: owner.BonjourSettings
) -> Passes:
    memory = scanner_memory(monkeypatch, config, settings)
    passes = Passes(monkeypatch, config, settings)
    passes.memory = memory
    return passes


@pytest.mark.parametrize(
    ("owner_tolerance", "stated", "expected"),
    [
        # The owner tolerates nothing and no entry says otherwise: no memory, as before.
        (1, {}, None),
        (1, {IMPORT: 1, EXPORT: 1}, None),
        (3, {}, 3),
        # One entry that tolerates a miss is enough for a memory.
        (1, {EXPORT: 3}, 1),
        (1, {IMPORT: 2, EXPORT: 1}, 1),
        (3, {IMPORT: 1}, 3),
        # The owner's setting alone builds none where no policy follows it.
        (3, {IMPORT: 1, EXPORT: 1}, None),
    ],
)
def test_scanner_has_a_memory_when_any_owned_policy_tolerates_a_miss(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    owner_tolerance: int,
    stated: dict[str, int],
    expected: int | None,
) -> None:
    memory = scanner_memory(
        monkeypatch, stating(leased(config), stated), tolerant(settings, owner_tolerance)
    )
    if expected is None:
        assert memory is None
    else:
        # The memory holds the owner's setting; begin() takes each policy's own.
        assert isinstance(memory, owner.MissMemory) and memory.tolerance == expected


@pytest.mark.parametrize(("first", "following"), [(IMPORT, EXPORT), (EXPORT, IMPORT)])
def test_policy_that_states_one_withdraws_at_the_first_miss_under_a_tolerant_owner(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    first: str,
    following: str,
) -> None:
    passes = scanner_passes(monkeypatch, stating(leased(config), {first: 1}), tolerant(settings, 3))
    seen = passes.run(speaker(), camera())
    assert len(seen[first]["records"]) == len(seen[following]["records"]) == 1
    for _ in range(2):
        missed = passes.miss()
        assert missed[first]["records"] == [] and "reason" not in missed[first]
        # The policy without the member follows the owner's setting of three.
        assert missed[following]["records"] == seen[following]["records"]
    assert passes.miss()[following]["records"] == []


@pytest.mark.parametrize(("stated", "following"), [(IMPORT, EXPORT), (EXPORT, IMPORT)])
def test_policy_that_states_three_keeps_its_records_under_an_owner_without_tolerance(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    stated: str,
    following: str,
) -> None:
    assert settings.miss_tolerance == 1
    passes = scanner_passes(monkeypatch, stating(leased(config), {stated: 3}), settings)
    seen = passes.run(speaker(), camera())
    assert len(seen[stated]["records"]) == len(seen[following]["records"]) == 1
    for _ in range(2):
        missed = passes.miss()
        assert missed[stated]["records"] == seen[stated]["records"]
        assert missed[stated]["records"][0]["seen_at"] == START
        # The policy without the member follows the owner: the first miss withdraws.
        assert missed[following]["records"] == [] and "reason" not in missed[following]
    assert passes.miss()[stated]["records"] == []


def test_each_policy_counts_with_its_own_number(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = scanner_passes(
        monkeypatch, stating(leased(config), {IMPORT: 4}), tolerant(settings, 2)
    )
    passes.run(speaker(), camera())
    kept = [
        (names(candidates[IMPORT]), names(candidates[EXPORT]))
        for candidates in (passes.miss() for _ in range(4))
    ]
    assert kept == [
        (["Example speaker"], ["Camera"]),
        (["Example speaker"], []),
        (["Example speaker"], []),
        ([], []),
    ]


def test_policy_that_tolerates_no_miss_takes_the_path_without_a_memory(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_config = stating(leased(config), {IMPORT: 1})
    own = tolerant(settings, 3)
    passes = scanner_passes(monkeypatch, policy_config, own)
    remembering = passes.run(speaker(), camera())
    memory = passes.memory
    assert memory is not None
    # Nothing of it is remembered ...
    assert list(memory.listed) == [EXPORT]
    # ... and the same pass without any memory writes the same candidate for it.
    owner.scan_pass(policy_config, own, passes.store)
    plain = passes.store.read("candidates.json")["policies"]
    assert remembering[IMPORT]["records"] and "reason" not in remembering[IMPORT]
    assert canonical_bytes(remembering[IMPORT]) == canonical_bytes(plain[IMPORT])
    # Its pass is handed nothing that could add a source; the other policy's is.
    fence = ("digest", "guest", "network")
    assert memory.begin(policy(policy_config, IMPORT), fence, START) is None
    assert memory.begin(policy(policy_config, EXPORT), fence, START) is not None


def test_changed_tolerance_is_another_policy_and_drops_the_memory(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = scanner_passes(monkeypatch, stating(leased(config), {EXPORT: 3}), settings)
    passes.run(camera())
    assert names(passes.miss()[EXPORT]) == ["Camera"]
    # One miss of four would be kept; what was read under the other digest is not.
    passes.config = stating(passes.config, {EXPORT: 4})
    after = passes.miss()[EXPORT]
    assert after["records"] == [] and "reason" not in after
    assert after["policy_digest"] == discovery_digest(passes.config, policy(passes.config, EXPORT))


def test_lease_condition_is_evaluated_with_the_policy_own_tolerance(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_config = stating(leased(config), {IMPORT: 8})
    horizon = owner.carry_horizon(policy_config, settings)
    last = START + LEASE - horizon
    passes = scanner_passes(monkeypatch, policy_config, settings)
    passes.run(speaker(), camera(), at=START)
    carried = passes.miss(at=last - 1)
    assert names(carried[IMPORT]) == ["Example speaker"]
    # The other policy follows the owner, which tolerates nothing.
    assert carried[EXPORT]["records"] == []
    # Missed twice of eight: the lease decides, not the tolerance.
    assert passes.miss(at=last)[IMPORT]["records"] == []


def test_publisher_withdraws_each_policy_at_its_own_count(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_config = stating(leased(config), {IMPORT: 1})
    own = tolerant(settings, 3)
    passes = scanner_passes(monkeypatch, policy_config, own)
    current = snapshot(policy_config)
    passes.store.write(
        "requests.json",
        {
            "schema_version": 1,
            "policies": {
                item.id: {
                    "active": True,
                    "policy_digest": discovery_digest(policy_config, item),
                    "service_generation": current.services[item.service].generation,
                    "network_generation": current.network_generation,
                    "requested_at": START,
                }
                for item in policy_config.discovery
            },
        },
    )
    manager = publisher()

    def tick() -> dict[str, tuple[str, int]]:
        proof = (observed(policy_config, passes.now), Intent(), READY, {"wired-lan": (7, 9)})
        result = owner.publisher_tick(
            policy_config, own, passes.store, manager, proof, 0, passes.now
        )
        return {
            key: (item.state, item.data["record_count"]) for key, item in result.profiles.items()
        }

    passes.run(speaker(), camera())
    assert tick() == {IMPORT: ("present", 1), EXPORT: ("present", 1)}
    clients = {item.record.service_type: item for item in FakeRegistration.made}
    assert sorted(clients) == ["_airplay._tcp", "_hap._tcp"]
    for _ in range(2):
        passes.miss()
        # The import's client is closed in the first pass that misses its source.
        assert tick() == {IMPORT: ("present", 0), EXPORT: ("present", 1)}
        assert clients["_airplay._tcp"].closed and not clients["_hap._tcp"].closed
        assert len(FakeRegistration.made) == 2
    passes.miss()
    assert tick() == {IMPORT: ("present", 0), EXPORT: ("present", 0)}
    assert clients["_hap._tcp"].closed and not manager.children


# The settings: a tolerance that could never keep anything is refused


def least_lease(config: Config, settings: owner.BonjourSettings) -> int:
    """A missed record is at least one rest old and must outlast a rest and two passes."""
    return settings.pass_interval + owner.carry_horizon(config, settings)


def test_settings_load_with_a_tolerance_that_only_the_policy_states(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    stated = stating(leased(config), {EXPORT: 3, IMPORT: 1})
    loaded = owner.load_settings(settings_file(tmp_path, stated, settings))
    assert loaded == settings and loaded.miss_tolerance == 1
    installed = parse_config(settings.config.read_bytes())
    assert [item.misses for item in installed.discovery] == [1, 3]


def test_stated_tolerance_is_refused_where_its_own_lease_could_never_carry(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    least = least_lease(config, settings)
    assert all(item.max_age_seconds <= least for item in config.discovery)

    def load(policy_config: Config, **keys: Any) -> owner.BonjourSettings:
        return owner.load_settings(settings_file(tmp_path, policy_config, settings, **keys))

    # A stated tolerance of one needs no room: it is today's withdrawal.
    assert load(stating(config, {EXPORT: 1, IMPORT: 1}))
    with pytest.raises(ValueError, match="outlasts two passes"):
        load(stating(config, {EXPORT: 2}))
    with pytest.raises(ValueError, match="outlasts two passes"):
        load(stating(leased(config, least, only=EXPORT), {EXPORT: 2}))
    assert load(stating(leased(config, least + 1, only=EXPORT), {EXPORT: 2}))
    # The room is the policy's own: another policy's long lease does not stand in,
    # with or without a tolerance of the owner that this other policy follows.
    elsewhere = stating(leased(config, least + 1, only=IMPORT), {EXPORT: 2})
    with pytest.raises(ValueError, match="outlasts two passes"):
        load(elsewhere)
    with pytest.raises(ValueError, match="outlasts two passes"):
        load(elsewhere, miss_tolerance=3)
    assert load(stating(leased(config, least + 1), {EXPORT: 2}), miss_tolerance=3)


def test_owner_tolerance_needs_room_in_a_policy_that_follows_it(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    least = least_lease(config, settings)

    def load(policy_config: Config, tolerance: int) -> owner.BonjourSettings:
        return owner.load_settings(
            settings_file(tmp_path, policy_config, settings, miss_tolerance=tolerance)
        )

    # As before the member: one owned lease with room is enough for the setting.
    roomy_export = leased(config, least + 1, only=EXPORT)
    assert load(roomy_export, 2) == tolerant(settings, 2)
    # A policy that states its own number does not follow the setting, so its
    # room does not count for it: nothing the setting applies to could be kept.
    assert load(stating(roomy_export, {EXPORT: 3}), 1)
    with pytest.raises(ValueError, match="outlasts two passes"):
        load(stating(roomy_export, {EXPORT: 3}), 2)
    with pytest.raises(ValueError, match="outlasts two passes"):
        load(stating(roomy_export, {EXPORT: 1}), 2)
    # A following policy has room from the same second on as before the member.
    with pytest.raises(ValueError, match="outlasts two passes"):
        load(stating(leased(config, least), {EXPORT: 1}), 2)
    assert load(stating(leased(config, least + 1), {EXPORT: 1}), 2)
    # Where every owned policy states its own, the setting governs none of them
    # and is compared with no lease.
    everywhere = leased(config, least + 1)
    assert load(stating(everywhere, {EXPORT: 3}), 2)
    assert load(stating(everywhere, {EXPORT: 3, IMPORT: 2}), 2) == tolerant(settings, 2)
    assert load(stating(everywhere, {EXPORT: 3, IMPORT: 2}), 1)


def test_owner_tolerance_refuses_nothing_where_every_owned_policy_states_its_own(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    least = least_lease(config, settings)
    roomy = leased(config, least + 1)

    def load(policy_config: Config, tolerance: int) -> owner.BonjourSettings:
        return owner.load_settings(
            settings_file(tmp_path, policy_config, settings, miss_tolerance=tolerance)
        )

    # The setting governs the entries that state no number. Here there is none:
    # the entries may repeat it, undercut it or exceed it, and it loads as given.
    for stated in ({EXPORT: 3, IMPORT: 3}, {EXPORT: 3, IMPORT: 1}, {EXPORT: 8, IMPORT: 2}):
        assert load(stating(roomy, stated), 3) == tolerant(settings, 3)
    # No lease is asked for the setting then: an entry that states 1 needs no room.
    assert all(item.max_age_seconds <= least for item in config.discovery)
    assert load(stating(config, {EXPORT: 1, IMPORT: 1}), 8) == tolerant(settings, 8)
    # Each stated number is still checked against its own lease, with its own reason.
    short_import = leased(roomy, least, only=IMPORT)
    with pytest.raises(ValueError, match="a policy's miss tolerance needs a lease"):
        load(stating(short_import, {EXPORT: 3, IMPORT: 2}), 3)
    # As soon as one entry follows the setting, the setting needs room in it.
    with pytest.raises(ValueError, match="Bonjour miss tolerance needs a lease"):
        load(stating(short_import, {EXPORT: 3}), 3)
    assert load(stating(roomy, {EXPORT: 3}), 3) == tolerant(settings, 3)


# The stated number replaces the owner's, whichever of the two is larger


def missed_passes_kept(passes: Passes) -> dict[str, int]:
    """For each policy, how many consecutive passes that miss its record still list it."""
    kept = {IMPORT: 0, EXPORT: 0}
    for _ in range(9):
        missed = passes.miss()
        for identifier in kept:
            kept[identifier] += bool(missed[identifier]["records"])
    return kept


@pytest.mark.parametrize("stating_entry", [IMPORT, EXPORT])
@pytest.mark.parametrize(
    ("owner_tolerance", "stated"),
    [
        # Below the owner's number and above 1: the entry's number, not the larger one.
        (4, 2),
        (8, 2),
        (8, 3),
        (3, 2),
        # Above the owner's number.
        (2, 3),
        (2, 8),
        (1, 2),
        # The ends: no tolerance under a tolerant owner, and the owner's own number.
        (5, 1),
        (5, 5),
    ],
)
def test_stated_number_replaces_the_owner_number_whichever_is_larger(
    config: Config,
    settings: owner.BonjourSettings,
    monkeypatch: pytest.MonkeyPatch,
    stating_entry: str,
    owner_tolerance: int,
    stated: int,
) -> None:
    following = EXPORT if stating_entry == IMPORT else IMPORT
    passes = scanner_passes(
        monkeypatch,
        stating(leased(config), {stating_entry: stated}),
        tolerant(settings, owner_tolerance),
    )
    seen = passes.run(speaker(), camera())
    assert len(seen[stating_entry]["records"]) == len(seen[following]["records"]) == 1
    # A record is kept for one pass fewer than its policy tolerates.
    assert missed_passes_kept(passes) == {stating_entry: stated - 1, following: owner_tolerance - 1}


def test_owner_number_counts_for_no_policy_that_states_its_own(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    passes = scanner_passes(
        monkeypatch, stating(leased(config), {EXPORT: 2, IMPORT: 1}), tolerant(settings, 5)
    )
    passes.run(speaker(), camera())
    assert missed_passes_kept(passes) == {EXPORT: 1, IMPORT: 0}


def test_policy_that_follows_an_owner_without_tolerance_is_not_remembered(
    config: Config, settings: owner.BonjourSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert settings.miss_tolerance == 1
    policy_config = stating(leased(config), {EXPORT: 3})
    passes = scanner_passes(monkeypatch, policy_config, settings)
    passes.run(speaker(), camera())
    memory = passes.memory
    assert memory is not None
    # The memory exists for the export alone. The import states nothing and its
    # owner tolerates nothing: its pass is handed no memory and leaves nothing in it.
    assert list(memory.listed) == [EXPORT]
    fence = ("digest", "guest", "network")
    assert memory.begin(policy(policy_config, IMPORT), fence, START) is None
    assert memory.begin(policy(policy_config, EXPORT), fence, START) is not None


# Only this owner's own policies count


def second_owner(config: Config, *identifiers: str) -> Config:
    """The policy with the named discovery entries handed to another discovery owner."""
    other = Owner("other-discovery", "user", ("discovery",))
    return replace(
        config,
        owners=(*config.owners, other),
        discovery=tuple(
            replace(item, owner=other.id) if item.id in identifiers else item
            for item in config.discovery
        ),
    )


def test_refusals_look_at_the_policies_of_this_owner_only(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    foreign = second_owner(config, EXPORT)
    validate_config(foreign)
    assert [item.owner for item in foreign.discovery] == [settings.owner, "other-discovery"]
    least = least_lease(foreign, settings)
    assert all(item.max_age_seconds <= least for item in foreign.discovery)

    def load(policy_config: Config, **keys: Any) -> owner.BonjourSettings:
        return owner.load_settings(settings_file(tmp_path, policy_config, settings, **keys))

    # Another owner's entry that states a tolerance its lease cannot carry is
    # that owner's to refuse, not this one's.
    assert load(stating(foreign, {EXPORT: 3})) == settings
    # Another owner's roomy lease does not stand in for a lease of this owner ...
    roomy_foreign = leased(foreign, least + 1, only=EXPORT)
    with pytest.raises(ValueError, match="Bonjour miss tolerance needs a lease"):
        load(roomy_foreign, miss_tolerance=2)
    # ... and an owned lease with room is enough, whatever the other owner's is.
    roomy_owned = leased(foreign, least + 1, only=IMPORT)
    assert load(roomy_owned, miss_tolerance=2) == tolerant(settings, 2)
    # Another owner's entry that states nothing does not follow this owner's
    # setting: with a number on every owned entry the setting governs nothing.
    assert load(stating(roomy_owned, {IMPORT: 3}), miss_tolerance=2) == tolerant(settings, 2)


def test_owner_tolerance_without_any_owned_policy_is_refused_as_before(
    config: Config, settings: owner.BonjourSettings, tmp_path: Path
) -> None:
    nothing_owned = second_owner(leased(config), IMPORT, EXPORT)
    validate_config(nothing_owned)

    def load(**keys: Any) -> owner.BonjourSettings:
        return owner.load_settings(settings_file(tmp_path, nothing_owned, settings, **keys))

    assert load() == settings
    # No owned lease at all: the setting could never keep anything, as before the member.
    with pytest.raises(ValueError, match="Bonjour miss tolerance needs a lease"):
        load(miss_tolerance=2)

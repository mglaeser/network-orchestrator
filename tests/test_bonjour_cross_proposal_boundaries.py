"""Cross-proposal counterexamples; synthetic records and no native networking."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from netorch import bonjour_owner as owner
from netorch import bonjour_process as native
from netorch.state import Intent
from netorch.storage import Store
from tests.test_bonjour_miss_tolerance import Passes, leased, names, tolerant
from tests.test_bonjour_owner import config, settings, snapshot
from tests.test_bonjour_record_expiry import (
    CONFIRMED,
    REMOVED,
    Child,
    ended_registration,
    lease,
    publisher,
    two_records,
)
from tests.test_bonjour_record_isolation import KITCHEN, ODD, UNUSABLE, Client

__all__ = ["config", "settings"]


def test_no_current_registration_is_not_verified_during_renewal(config, settings):
    current = snapshot(config)
    requests, candidates = lease(config, settings, current, two_records(), 1000)
    store = Store(settings.state_dir)
    store.write("requests.json", requests)
    store.write("candidates.json", candidates)
    proof = (current, Intent(), frozenset({"media-udp"}), {"wired-lan": (7, 9)})
    manager = publisher()
    assert (
        owner.publisher_tick(config, settings, store, manager, proof, 0, 1000)
        .profiles["media-import"]
        .state
        == "present"
    )
    for child in tuple(Child.made):
        child.end = native.RegistrationExpired()
    fact = owner.publisher_tick(config, settings, store, manager, proof, 0, 1001).profiles[
        "media-import"
    ]
    assert not any(child.active for child in manager.children.values())
    assert (fact.state, fact.reason) == ("unknown", "unobserved")
    assert (
        owner.publisher_tick(config, settings, store, manager, proof, 0, 1002)
        .profiles["media-import"]
        .state
        == "present"
    )


@pytest.mark.parametrize("unusable", UNUSABLE.values(), ids=UNUSABLE)
def test_miss_tolerance_cannot_revive_an_explicitly_rejected_instance(
    config, settings, monkeypatch, unusable
):
    passes = Passes(monkeypatch, leased(config), tolerant(settings, 3))
    clients = [Client(KITCHEN, ODD)]

    def scan(interface, index, kind, limit, seconds, now, **keywords):
        return native.scan(interface, index, kind, limit, seconds, now, clients[0], **keywords)

    monkeypatch.setattr(owner, "scan", scan)
    first = passes.run()["media-import"]
    assert names(first) == [KITCHEN.name, ODD.name]
    clients[0] = Client(KITCHEN, unusable)
    refused = passes.run()["media-import"]
    assert names(refused) == [KITCHEN.name]
    # A subsequent empty browse cannot resurrect the rejected source either.
    clients[0] = Client()
    assert ODD.name not in names(passes.run()["media-import"])


@pytest.mark.parametrize("ended", [False, True])
def test_an_extra_foreign_interface_line_invalidates_registration(ended):
    registration = ended_registration(0, 30, CONFIRMED + b"Using interface 8\n")
    if not ended:
        registration.process = SimpleNamespace(poll=lambda: None)
    with pytest.raises(native.DiscoveryFailure) as caught:
        registration.poll()
    assert not isinstance(caught.value, native.RegistrationExpired)


def test_unfinished_sibling_read_cannot_resurrect_an_answer_explicitly_refused(
    config, settings, monkeypatch
):
    own = replace(tolerant(settings, 3), failed_pass="miss")
    passes = Passes(monkeypatch, leased(config), own)
    clients = [Client(KITCHEN, ODD)]
    interrupted = [False]

    def scan(interface, index, kind, limit, seconds, now, **keywords):
        if interrupted[0] and kind == "_raop._tcp":
            raise native.DiscoveryFailure("malformed", unfinished=True)
        return native.scan(interface, index, kind, limit, seconds, now, clients[0], **keywords)

    monkeypatch.setattr(owner, "scan", scan)
    assert names(passes.run()["media-import"]) == [KITCHEN.name, ODD.name]
    clients[0] = Client(KITCHEN, replace(ODD, port=0))
    interrupted[0] = True
    carried = passes.run()["media-import"]
    assert carried["tolerated_failure"] == "malformed"
    assert names(carried) == [KITCHEN.name]


def test_timer_exit_cannot_hide_a_removal_beyond_the_first_pipe_read(monkeypatch):
    # A completed client's pipe can hold more than one read. The first block
    # is valid; the final callback invalidates its formerly confirmed name.
    chunks = [CONFIRMED, REMOVED, b""]
    registration = ended_registration(0, 30, b"")

    class Ready:
        def select(self, _timeout):
            return [(SimpleNamespace(fd=42, fileobj=42), None)] if chunks else []

        def unregister(self, _fileobj):
            pass

    registration.selector = Ready()
    monkeypatch.setattr(native.os, "read", lambda _fd, _size: chunks.pop(0))
    with pytest.raises(native.DiscoveryFailure) as caught:
        registration.poll()
    assert not isinstance(caught.value, native.RegistrationExpired)

"""Native metadata alignment must not weaken service-table or identity proof."""

from __future__ import annotations

import pytest

from netorch.launchd_inventory import domain_services
from tests.test_apple_runtime import domain_report

DOMAIN = "system"
LABEL = "com.apple.container.example-runtime.example-camera"


@pytest.mark.parametrize("tabs", [2, 3, 9])
def test_extra_tab_alignment_of_discarded_metadata_preserves_every_service(tabs):
    report = (
        domain_report(DOMAIN, (LABEL,))
        .decode()
        .replace("\tservices = {", "\t" * tabs + "descriptive = discarded\n\tservices = {")
    )
    assert domain_services(report, DOMAIN) == {LABEL}


@pytest.mark.parametrize("field", ["type", "handle", "service count"])
@pytest.mark.parametrize("tabs", [2, 3])
def test_required_identity_fields_cannot_use_metadata_alignment(field, tabs):
    report = (
        domain_report(DOMAIN, (LABEL,))
        .decode()
        .replace(f"\t{field} = ", "\t" * tabs + f"{field} = ")
    )
    with pytest.raises(ValueError):
        domain_services(report, DOMAIN)


@pytest.mark.parametrize("field", ["services = {", "services = ignored"])
def test_services_field_cannot_use_metadata_alignment(field):
    report = domain_report(DOMAIN, (LABEL,)).decode().replace("\tservices = {", "\t\t" + field)
    with pytest.raises(ValueError):
        domain_services(report, DOMAIN)


@pytest.mark.parametrize("tabs", [1, 2, 3])
def test_a_displaced_service_row_after_aligned_metadata_is_never_discarded(tabs):
    report = (
        domain_report(DOMAIN, (LABEL,))
        .decode()
        .replace(
            "\tservices = {",
            "\t\tdescriptive = discarded\n" + "\t" * tabs + "0 - example.displaced\n\tservices = {",
        )
    )
    with pytest.raises(ValueError):
        domain_services(report, DOMAIN)


def test_an_unknown_block_header_cannot_use_metadata_alignment():
    report = (
        domain_report(DOMAIN, (LABEL,))
        .decode()
        .replace("\tservices = {", "\t\tother = {\n\t\t}\n\tservices = {")
    )
    with pytest.raises(ValueError):
        domain_services(report, DOMAIN)


def test_aligned_metadata_still_requires_a_complete_scalar_assignment():
    report = (
        domain_report(DOMAIN, (LABEL,))
        .decode()
        .replace("\tservices = {", "\t\tdescriptive discarded\n\tservices = {")
    )
    with pytest.raises(ValueError):
        domain_services(report, DOMAIN)

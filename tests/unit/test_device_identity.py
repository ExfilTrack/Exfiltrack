"""Unit tests for device identity normalization (issue #70).

The reference data is a real Kingston DataTraveler 3.0 as seen by the two
sources: the DriverFrameworks event log (WPD-wrapped) and the registry
USBSTOR key (mixed case).
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from exfiltrack.normalization.device_identity import (
    canonical_device_id,
    is_probable_storage_device,
    prefer_event_log_boundaries,
    resolve_device_identities,
)
from tests.unit.factories import make_device, make_insert_event, make_remove_event, utc

KINGSTON_WPD = (
    r"SWD\WPDBUSENUM\_??_USBSTOR#DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_0000"
    r"#2CFDA1BBB44D18A179080708&0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}"
)
KINGSTON_REGISTRY = (
    r"USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_0000\2CFDA1BBB44D18A179080708&0"
)
KINGSTON_CANONICAL = (
    r"USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_0000\2CFDA1BBB44D18A179080708&0"
)

BASE = utc(2026, 3, 1, 9, 0, 0)


def _wpd_device():
    """The Kingston as the event log sees it: raw id, no human-readable fields."""
    return make_device(
        device_id=KINGSTON_WPD, serial_number="", vendor="", product="", friendly_name=""
    )


def _registry_device():
    """The same Kingston as the registry sees it, with its friendly name."""
    return make_device(
        device_id=KINGSTON_REGISTRY,
        serial_number="2CFDA1BBB44D18A179080708&0",
        vendor="Kingston",
        product="DataTraveler 3.0",
        friendly_name="Kingston DataTraveler 3.0",
    )


@pytest.mark.unit
def test_wpd_wrapped_id_unwraps_to_canonical_usbstor() -> None:
    assert canonical_device_id(KINGSTON_WPD) == KINGSTON_CANONICAL


@pytest.mark.unit
def test_registry_form_canonicalizes_to_the_same_id() -> None:
    assert canonical_device_id(KINGSTON_REGISTRY) == KINGSTON_CANONICAL
    assert canonical_device_id(KINGSTON_CANONICAL) == KINGSTON_CANONICAL  # idempotent


@pytest.mark.unit
@pytest.mark.parametrize(
    ("device_id", "expected"),
    [
        (KINGSTON_WPD, True),
        (KINGSTON_REGISTRY, True),
        (KINGSTON_CANONICAL, True),
        # Bare USB\VID&PID ids may be a storage stick's parent PDO; never
        # dropped on a guess (documented limitation).
        (r"USB\VID_046D&PID_C534\KB1234567", True),
        (r"HID\VID_046D&PID_C534&MI_00\8&2A1B3C4D&0&0000", False),
        (r"SWD\DEVICECONTROL\1&2A3B4C5D&0&0000", False),
        (r"PCI\VEN_8086&DEV_1237\3&11583659&0&00", False),
    ],
)
def test_is_probable_storage_device(device_id: str, expected: bool) -> None:
    assert is_probable_storage_device(device_id) is expected


@pytest.mark.unit
def test_resolve_merges_registry_identity_onto_event_log_device() -> None:
    events = [
        make_insert_event(BASE, _wpd_device(), source_artifact="evidence/evtx/dfu.evtx"),
        make_insert_event(
            BASE,
            _registry_device(),
            source_artifact="evidence/registry/SYSTEM",
            details={"records_most_recent_only": True},
        ),
    ]

    resolved = resolve_device_identities(events)

    assert len(resolved) == 2
    for event in resolved:
        assert event.device is not None
        assert event.device.device_id == KINGSTON_CANONICAL
        assert event.device.friendly_name == "Kingston DataTraveler 3.0"
        assert event.device.display_name == "Kingston DataTraveler 3.0"
    # The raw spellings stay traceable to their artifacts.
    assert resolved[0].details["reported_device_id"] == KINGSTON_WPD
    assert resolved[1].details["reported_device_id"] == KINGSTON_REGISTRY


@pytest.mark.unit
def test_resolve_derives_display_fields_when_registry_is_silent() -> None:
    events = [make_insert_event(BASE, _wpd_device())]

    [event] = resolve_device_identities(events)

    assert event.device is not None
    assert event.device.friendly_name == ""  # no fabricated friendly name
    assert event.device.vendor == "KINGSTON"
    assert event.device.product == "DATATRAVELER_3.0"
    assert event.device.serial_number == "2CFDA1BBB44D18A179080708&0"
    # Displays as the product, not the raw SWD\WPDBUSENUM string.
    assert event.device.display_name == "DATATRAVELER_3.0"


@pytest.mark.unit
def test_resolve_passes_non_storage_ids_through_uppercased() -> None:
    keyboard = make_device(
        device_id=r"HID\VID_046D&PID_C534&MI_00\8&2a1b3c4d&0&0000",
        serial_number="",
        vendor="",
        product="",
        friendly_name="",
    )
    [event] = resolve_device_identities([make_insert_event(BASE, keyboard)])
    assert event.device is not None
    assert event.device.device_id == r"HID\VID_046D&PID_C534&MI_00\8&2A1B3C4D&0&0000"
    assert event.device.friendly_name == ""


@pytest.mark.unit
def test_prefer_event_log_boundaries_drops_registry_duplicate() -> None:
    events = [
        make_insert_event(BASE, _wpd_device(), source_artifact="evidence/evtx/dfu.evtx"),
        make_insert_event(
            BASE + timedelta(seconds=4),
            _registry_device(),
            source_artifact="evidence/registry/SYSTEM",
            details={"records_most_recent_only": True},
        ),
    ]

    kept = prefer_event_log_boundaries(events)

    assert kept == events[:1]


@pytest.mark.unit
def test_prefer_event_log_boundaries_keeps_distinct_registry_record() -> None:
    """Beyond the tolerance, the registry record is a different real plug-in."""
    events = [
        make_insert_event(BASE, _wpd_device()),
        make_insert_event(
            BASE + timedelta(minutes=2),
            _registry_device(),
            details={"records_most_recent_only": True},
        ),
    ]

    assert prefer_event_log_boundaries(events) == events


@pytest.mark.unit
def test_prefer_event_log_boundaries_keeps_registry_when_channel_was_off() -> None:
    """Registry boundaries are the only session evidence without the channel."""
    events = [
        make_insert_event(BASE, _registry_device(), details={"records_most_recent_only": True}),
        make_remove_event(
            BASE + timedelta(minutes=10),
            _registry_device(),
            details={"records_most_recent_only": True},
        ),
    ]

    assert prefer_event_log_boundaries(events) == events


@pytest.mark.unit
def test_resolve_does_not_mutate_input_events() -> None:
    wpd_device = _wpd_device()
    event = make_insert_event(BASE, wpd_device)
    resolve_device_identities([event])
    assert event.device is wpd_device
    assert "reported_device_id" not in event.details

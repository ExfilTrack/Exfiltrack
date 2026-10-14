"""USB storage device identity normalization.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #70 - Normalize WPD-wrapped device IDs to friendly device names

The same physical stick appears under different instance-id spellings in
different sources: registry hives carry ``USBSTOR\\Disk&Ven_Kingston&...``
(mixed case, with a friendly name alongside), while the DriverFrameworks
event log wraps the USBSTOR id in the WPD bus enumerator:
``SWD\\WPDBUSENUM\\_??_USBSTOR#DISK&VEN_KINGSTON&...#{<volume guid>}``.
Grouped on the raw strings, one stick becomes several "devices" in the
report. This module canonicalizes the ids, merges what each source knows
about the device, and tells session reconstruction which events can belong
to USB storage at all (:func:`is_probable_storage_device`).

Merging is strictly exact-match: two events share a device only when their
canonical ids are identical. No fuzzy matching -- a wrong merge would
misattribute evidence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from exfiltrack.normalization.event_model import EventType, NormalizedEvent, UsbDevice

# SWD\WPDBUSENUM\_??_<wrapped id>#{<volume guid>} -- the DriverFrameworks log's
# spelling of a USBSTOR device. The wrapped part uses '#' for the backslashes
# the registry form has.
_WPD_WRAPPED = re.compile(
    r"^SWD\\WPDBUSENUM\\_\?\?_(?P<inner>.+?)"
    r"#\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$"
)

_BOUNDARY_TYPES = (EventType.USB_INSERT.value, EventType.USB_REMOVE.value)

# The registry property write and the event-log record of the same physical
# (un)plug land within seconds of each other. The window cannot merge two
# distinct real connections by mistake: registry properties 0066/0067 record
# only the most recent instant, so they never produce a second, earlier
# timestamp that a tolerance could swallow.
BOUNDARY_DUPLICATE_TOLERANCE = timedelta(seconds=30)


def canonical_device_id(device_id: str) -> str:
    """Return the canonical identity of a device instance id.

    WPD-wrapped ids are unwrapped to their USBSTOR form (``#`` back to
    ``\\``). Everything is uppercased: Windows device ids are
    case-insensitive, and the registry spells the same stick in mixed case
    while the event log uppercases it. Non-wrapped ids pass through
    uppercased but otherwise unchanged.
    """
    candidate = device_id.strip()
    match = _WPD_WRAPPED.match(candidate)
    if match:
        candidate = match.group("inner").replace("#", "\\")
    return candidate.upper()


def is_probable_storage_device(device_id: str) -> bool:
    """``True`` for ids that can denote a USB storage device.

    ``USBSTOR\\`` ids (either spelling) are certain. Bare
    ``USB\\VID_xxxx&PID_xxxx\\serial`` ids are kept too: they can be a storage
    stick's parent PDO, and dropping a real stick on a guess is worse than
    keeping an ambiguous one. Everything else -- HID, PCI, ACPI, SWD entries
    that did not unwrap to USBSTOR -- is driver/system noise for this tool's
    purposes and never reconstructs a session.
    """
    return canonical_device_id(device_id).startswith(("USBSTOR\\", "USB\\"))


def _derive_from_usbstor_id(canonical_id: str) -> tuple[str, str, str]:
    """Best-effort (serial, vendor, product) parsed from a canonical USBSTOR id.

    Used only when no registry identity is available; the values come from
    the evidence itself, just from the id string rather than the hive's
    FriendlyName value.
    """
    parts = canonical_id.split("\\")
    if len(parts) != 3 or parts[0] != "USBSTOR":
        return ("", "", "")
    vendor = product = ""
    for chunk in parts[1].split("&"):
        if chunk.startswith("VEN_"):
            vendor = chunk[4:]
        elif chunk.startswith("PROD_"):
            product = chunk[5:]
    return (parts[2], vendor, product)


def _identity_score(device: UsbDevice) -> int:
    """Rank an identity by how much human-readable identity it carries."""
    if device.friendly_name:
        return 2
    if device.vendor or device.product:
        return 1
    return 0


def resolve_device_identities(events: Iterable[NormalizedEvent]) -> list[NormalizedEvent]:
    """Merge per-source device identities for the same physical device.

    For every canonical device key, the identity carrying the most
    human-readable information wins (a registry ``FriendlyName`` beats
    vendor/product fields, which beat a bare event-log id). Every event's
    ``device`` is rewritten to the canonical id plus the best-known display
    fields; when the event's original id differed (e.g. the WPD-wrapped
    spelling), the raw value is preserved in ``details["reported_device_id"]``
    so the report's canonical identity stays traceable to the artifact.

    When no registry identity exists, vendor/product/serial are derived from
    the USBSTOR id itself, so an event-log-only stick still displays as e.g.
    "DATATRAVELER_3.0" rather than the raw ``SWD\\WPDBUSENUM\\...`` string.

    Returns a new list; the input events are frozen and never mutated.
    """
    best: dict[str, UsbDevice] = {}
    for event in events:
        if event.device is None:
            continue
        key = canonical_device_id(event.device.device_id)
        current = best.get(key)
        if current is None or _identity_score(event.device) > _identity_score(current):
            best[key] = event.device

    resolved: list[NormalizedEvent] = []
    for event in events:
        if event.device is None:
            resolved.append(event)
            continue
        key = canonical_device_id(event.device.device_id)
        chosen = best[key]
        serial, vendor, product = chosen.serial_number, chosen.vendor, chosen.product
        if not (vendor or product):
            derived_serial, derived_vendor, derived_product = _derive_from_usbstor_id(key)
            serial = serial or derived_serial
            vendor = vendor or derived_vendor
            product = product or derived_product
        merged = UsbDevice(
            device_id=key,
            serial_number=serial,
            vendor=vendor,
            product=product,
            friendly_name=chosen.friendly_name,
        )
        changes: dict[str, Any] = {"device": merged}
        if event.device.device_id != key:
            details = dict(event.details)
            details["reported_device_id"] = event.device.device_id
            changes["details"] = details
        resolved.append(replace(event, **changes))
    return resolved


def prefer_event_log_boundaries(
    events: Iterable[NormalizedEvent],
    tolerance: timedelta = BOUNDARY_DUPLICATE_TOLERANCE,
) -> list[NormalizedEvent]:
    """Drop registry-property boundary records that duplicate an event-log one.

    Registry properties 0066/0067 record the *same* most-recent (un)plug that
    a DriverFrameworks 2003/2102 event records; grouped together they would
    otherwise read as two boundaries and double a session. Where an event-log
    boundary of the same type exists for the device within ``tolerance``, the
    registry record yields to it (the #35 ``records_most_recent_only`` marker
    already names registry-derived boundaries as the weaker kind). Registry
    boundaries with no event-log counterpart are kept -- they are the only
    session evidence when the channel was disabled.

    Intended for the session-reconstruction input only: the full timeline
    keeps every parsed event.
    """
    strong: dict[tuple[str, str], list[datetime]] = {}
    for event in events:
        if (
            event.device is not None
            and event.event_type in _BOUNDARY_TYPES
            and not event.details.get("records_most_recent_only")
        ):
            key = (canonical_device_id(event.device.device_id), event.event_type)
            strong.setdefault(key, []).append(event.timestamp_utc)

    kept: list[NormalizedEvent] = []
    for event in events:
        if (
            event.device is not None
            and event.event_type in _BOUNDARY_TYPES
            and event.details.get("records_most_recent_only")
        ):
            key = (canonical_device_id(event.device.device_id), event.event_type)
            if any(abs(stamp - event.timestamp_utc) <= tolerance for stamp in strong.get(key, [])):
                continue
        kept.append(event)
    return kept

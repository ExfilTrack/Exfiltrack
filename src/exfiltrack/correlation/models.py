"""Shared data contracts for the correlation layer.

Owner: Maheesha (Dabarera G. D. M.)

``UsbDevice`` and ``NormalizedEvent`` are a narrow, duck-type-compatible
stand-in for the shared contract Thabrew defines in issue #7
(``exfiltrack.normalization.event_model``). ``docs/task-assignments.md``
directs this work to proceed against hand-written fixtures rather than
block on #7:

    "You depend on #7. Until it merges, build against a small hand-written
    list of NormalizedEvent fixtures rather than waiting."

Field names and meaning exactly match the contract documented in
docs/task-assignments.md ("The Shared Contract"). When #7 merges:

    1. Delete ``UsbDevice`` and ``NormalizedEvent`` from this file.
    2. Import both from ``exfiltrack.normalization.event_model`` instead.
       Nothing in ``sessions.py``, ``scoring.py``, ``confidence.py``, or the
       ``reporting/`` package should need to change beyond that import, since
       every field used here is already part of the documented contract.

Do not add fields to ``UsbDevice`` or ``NormalizedEvent`` that are not
already part of the documented contract. If correlation or reporting code
needs a new field, raise it in the issue #7 thread first, per the
coordination rule in docs/task-assignments.md -- do not add it locally.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


class EventType(str, enum.Enum):
    """Canonical ``event_type`` values consumed by the correlation layer.

    Only the values the correlation layer acts on are enumerated here. A
    parser may emit additional device-lifecycle event types (for example a
    driver-level mount/unmount pair from the EVTX parser); anything meaning
    "the device became available" or "the device became unavailable"
    should either be mapped to ``USB_INSERT`` / ``USB_REMOVE`` at the
    parser boundary, or passed explicitly to
    :func:`exfiltrack.correlation.sessions.reconstruct_sessions` via its
    ``insert_types`` / ``remove_types`` arguments.
    """

    USB_INSERT = "usb_insert"
    USB_REMOVE = "usb_remove"
    FILE_ACCESS = "file_access"


def _require_utc(field_name: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be a timezone-aware UTC datetime, got {value!r}.")


@dataclass(frozen=True)
class UsbDevice:
    """Identity of a USB storage device, as established by the registry parser.

    Attributes:
        device_id: Stable identifier used to group events by physical
            device (for example a registry ``USBSTOR`` instance ID). This
            is the grouping key session reconstruction uses -- two events
            sharing a ``device_id`` are assumed to be the same physical
            device.
        serial_number: Device serial number, when the artifact records one.
        vendor: Vendor string, when the artifact records one.
        product: Product string, when the artifact records one.
        friendly_name: Human-assigned device name, when available.
    """

    device_id: str
    serial_number: str = ""
    vendor: str = ""
    product: str = ""
    friendly_name: str = ""

    def __post_init__(self) -> None:
        if not self.device_id.strip():
            raise ValueError("UsbDevice.device_id must not be empty.")

    @property
    def display_name(self) -> str:
        """Human-readable label for the report: prefer the friendliest name available."""
        return self.friendly_name or self.product or self.device_id


@dataclass(frozen=True)
class NormalizedEvent:
    """One event on the unified timeline.

    See docs/task-assignments.md, "The Shared Contract", for the
    authoritative field list. ``details`` carries artifact-specific extras
    for the report appendix and must contain only JSON-serialisable values.
    """

    event_type: str
    timestamp_utc: datetime
    raw_timestamp: str
    source_artifact: str
    parser_name: str
    parser_version: str
    device: UsbDevice | None = None
    file_path: str | None = None
    file_size_bytes: int | None = None
    details: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_utc("timestamp_utc", self.timestamp_utc)
        if not self.source_artifact.strip():
            raise ValueError("NormalizedEvent.source_artifact must not be empty (no provenance).")
        if not self.parser_name.strip() or not self.parser_version.strip():
            raise ValueError(
                "NormalizedEvent must carry parser_name and parser_version (no provenance)."
            )
        insert_or_remove = (EventType.USB_INSERT.value, EventType.USB_REMOVE.value)
        if self.event_type in insert_or_remove and self.device is None:
            raise ValueError(f"'{self.event_type}' events must carry a device.")
        if self.event_type == EventType.FILE_ACCESS.value and not self.file_path:
            raise ValueError("'file_access' events must carry a file_path.")

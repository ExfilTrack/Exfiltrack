"""Hand-written NormalizedEvent/UsbDevice factories for correlation and
reporting tests.

Owner: Maheesha (Dabarera G. D. M.)

These fixtures stand in for real parser output while issue #7 (Event
Normalization Model) is still in progress, per the guidance in
docs/task-assignments.md: "build against a small hand-written list of
NormalizedEvent fixtures rather than waiting." Once #7 lands, these
factories can keep constructing the real
``exfiltrack.normalization.event_model.NormalizedEvent`` -- only the
import in ``exfiltrack.correlation.models`` needs to change.
"""

from __future__ import annotations

from datetime import datetime, timezone

from exfiltrack.correlation.models import EventType, NormalizedEvent, UsbDevice

PARSER_NAME = "synthetic_fixture"
PARSER_VERSION = "0.0.0"


def utc(*args: int) -> datetime:
    """Build a timezone-aware UTC datetime from (year, month, day, hour, minute, second)."""
    return datetime(*args, tzinfo=timezone.utc)


def make_device(
    device_id: str = "USB\\VID_1234&PID_5678\\SERIAL001", **overrides: str
) -> UsbDevice:
    defaults = {
        "device_id": device_id,
        "serial_number": "SERIAL001",
        "vendor": "SanDisk",
        "product": "Cruzer Blade",
        "friendly_name": "SanDisk Cruzer Blade",
    }
    defaults.update(overrides)
    return UsbDevice(**defaults)


def make_insert_event(
    timestamp: datetime,
    device: UsbDevice,
    *,
    source_artifact: str = "evidence/logs/System.evtx",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_type=EventType.USB_INSERT.value,
        timestamp_utc=timestamp,
        raw_timestamp=timestamp.isoformat(),
        source_artifact=source_artifact,
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        device=device,
    )


def make_remove_event(
    timestamp: datetime,
    device: UsbDevice,
    *,
    source_artifact: str = "evidence/logs/System.evtx",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_type=EventType.USB_REMOVE.value,
        timestamp_utc=timestamp,
        raw_timestamp=timestamp.isoformat(),
        source_artifact=source_artifact,
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        device=device,
    )


def make_file_event(
    timestamp: datetime,
    file_path: str,
    *,
    source_artifact: str = "evidence/lnk/Recent.lnk",
    file_size_bytes: int | None = 1024,
    sha256: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_type=EventType.FILE_ACCESS.value,
        timestamp_utc=timestamp,
        raw_timestamp=timestamp.isoformat(),
        source_artifact=source_artifact,
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        file_path=file_path,
        file_size_bytes=file_size_bytes,
        details={} if sha256 is None else {"sha256": sha256},
    )

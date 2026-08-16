"""Common normalized event model shared by parsers and correlation."""

from __future__ import annotations

import enum
import heapq
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta


class EventType(str, enum.Enum):
    """Canonical event types consumed by the correlation layer."""

    USB_INSERT = "usb_insert"
    USB_REMOVE = "usb_remove"
    FILE_ACCESS = "file_access"


def _require_utc(field_name: str, value: datetime) -> None:
    """Reject non-datetime, naive, and non-UTC timeline values."""
    if not isinstance(value, datetime):
        raise ValueError(f"{field_name} must be a datetime, got {type(value).__name__}.")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be a timezone-aware UTC datetime, got {value!r}.")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be strictly UTC, got offset {value.utcoffset()}.")


@dataclass(frozen=True)
class UsbDevice:
    """Identity of a USB storage device, as recorded by registry evidence."""

    device_id: str
    serial_number: str = ""
    vendor: str = ""
    product: str = ""
    friendly_name: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.device_id, str) or not self.device_id.strip():
            raise ValueError("UsbDevice.device_id must not be empty.")

    @property
    def display_name(self) -> str:
        """Return the most useful human-readable identity available."""
        return self.friendly_name or self.product or self.device_id


@dataclass(frozen=True)
class NormalizedEvent:
    """One timestamped event in the unified, provenance-preserving timeline."""

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
        if not isinstance(self.raw_timestamp, str) or not self.raw_timestamp.strip():
            raise ValueError("NormalizedEvent.raw_timestamp must not be empty.")
        if not isinstance(self.source_artifact, str) or not self.source_artifact.strip():
            raise ValueError("NormalizedEvent.source_artifact must not be empty (no provenance).")
        if (
            not isinstance(self.parser_name, str)
            or not self.parser_name.strip()
            or not isinstance(self.parser_version, str)
            or not self.parser_version.strip()
        ):
            raise ValueError(
                "NormalizedEvent must carry parser_name and parser_version (no provenance)."
            )
        if (
            self.event_type in (EventType.USB_INSERT.value, EventType.USB_REMOVE.value)
            and self.device is None
        ):
            raise ValueError(f"'{self.event_type}' events must carry a device.")
        if self.event_type == EventType.FILE_ACCESS.value and not self.file_path:
            raise ValueError("'file_access' events must carry a file_path.")


def _sort_key(event: NormalizedEvent) -> tuple[object, ...]:
    """Return the documented total ordering key shared by sorting and merging."""
    return (
        event.timestamp_utc,
        event.event_type,
        event.source_artifact,
        event.file_path or "",
        event.device.device_id if event.device else "",
        event.parser_name,
        event.parser_version,
        event.raw_timestamp,
    )


def sort_events(events: Iterable[NormalizedEvent]) -> list[NormalizedEvent]:
    """Return events in deterministic timeline order.

    Exact-key ties retain the input iterable's order because :func:`sorted` is stable.
    """
    return sorted(events, key=_sort_key)


def merge_streams(*streams: Iterable[NormalizedEvent]) -> Iterator[NormalizedEvent]:
    """Lazily merge streams already sorted by :func:`_sort_key`.

    Every input stream must already use the exact ordering implemented by
    :func:`sort_events`; unsorted streams cannot produce a globally ordered
    merge. Exact-key ties retain per-stream order, and earlier stream arguments
    win ties between streams.
    """
    return heapq.merge(*streams, key=_sort_key)

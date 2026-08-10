"""Read-only parser for Windows EVTX device and object-access evidence.

The parser recognizes a deliberately small, documented set of events.  See
``docs/evidence-sources.md`` for their evidentiary meaning and limitations.
Unsupported, well-formed events are not findings; malformed records and
selected records missing required fields raise :class:`EvtxParseError`.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import Evtx.Evtx as evtx

from exfiltrack.config import ExfilTrackError
from exfiltrack.normalization.event_model import EventType, NormalizedEvent, UsbDevice
from exfiltrack.normalization.timestamps import parse_iso8601


class EvtxParseError(ExfilTrackError):
    """Raised when an EVTX file or a relevant record is malformed."""


PARSER_NAME = "evtx_parser"
PARSER_VERSION = "1.1.0"

_NS = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
_DFU_PROVIDER = "Microsoft-Windows-DriverFrameworks-UserMode"
_KERNEL_PNP_PROVIDER = "Microsoft-Windows-Kernel-PnP"
_SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
# These lifecycle labels retain evidence that is useful to an investigator but
# must not be treated as a completed insertion/removal by session reconstruction.
DEVICE_INSTALL = "usb_device_install"
DEVICE_REMOVE_PENDING = "usb_remove_pending"


def _parse_timestamp(raw_timestamp: str | None) -> datetime:
    """Wrapper to maintain parser-specific error for missing timestamp."""
    if not raw_timestamp:
        raise EvtxParseError("Missing SystemTime in Event/System/TimeCreated")
    try:
        return parse_iso8601(raw_timestamp)
    except ValueError as exc:
        raise EvtxParseError(str(exc)) from exc


def parse_evtx(file_path: Path | str) -> Iterator[NormalizedEvent]:
    """Yield normalized events from an EVTX file opened read-only.

    Args:
        file_path: Path to an exported Windows Event Log.

    Yields:
        Supported device-lifecycle and Security 4663 file-object events.

    Raises:
        EvtxParseError: If the EVTX file cannot be read or a record is malformed.
    """
    path = Path(file_path)
    source_artifact = path.as_posix()
    try:
        with evtx.Evtx(str(path)) as log:
            for record in log.records():
                try:
                    root = ET.fromstring(record.xml())
                except ET.ParseError as exc:
                    raise EvtxParseError(f"Malformed XML in '{source_artifact}': {exc}") from exc

                event = _process_record(root, source_artifact)
                if event is not None:
                    yield event
    except EvtxParseError:
        raise
    except Exception as exc:
        raise EvtxParseError(f"Failed to parse EVTX file '{path}': {exc}") from exc


def _process_record(root: ET.Element, source_artifact: str) -> NormalizedEvent | None:
    """Convert one parsed Event XML element into a supported event, if any."""
    system = root.find("ns:System", _NS)
    if system is None:
        raise EvtxParseError("Missing System element")

    provider_element = system.find("ns:Provider", _NS)
    event_id_element = system.find("ns:EventID", _NS)
    time_element = system.find("ns:TimeCreated", _NS)
    provider = provider_element.attrib.get("Name") if provider_element is not None else None
    event_id = (
        event_id_element.text.strip()
        if event_id_element is not None and event_id_element.text
        else None
    )
    raw_timestamp = time_element.attrib.get("SystemTime") if time_element is not None else None

    if not provider:
        raise EvtxParseError("Missing System/Provider Name")
    if not event_id:
        raise EvtxParseError("Missing System/EventID")
    if raw_timestamp is None:
        raise EvtxParseError("Missing SystemTime in Event/System/TimeCreated")

    details = _system_details(system, provider, event_id)
    if provider == _DFU_PROVIDER:
        if event_id == "2003":
            return _build_device_event(
                root, EventType.USB_INSERT.value, source_artifact, raw_timestamp, details
            )
        if event_id == "2100":
            return _build_device_event(
                root, DEVICE_REMOVE_PENDING, source_artifact, raw_timestamp, details
            )
        if event_id == "2102":
            return _build_device_event(
                root, EventType.USB_REMOVE.value, source_artifact, raw_timestamp, details
            )
    elif provider == _KERNEL_PNP_PROVIDER and event_id in {"20001", "20003"}:
        # These record driver-install stages; they must not be relabelled as a
        # physical insertion because a driver install can occur independently.
        return _build_device_event(root, DEVICE_INSTALL, source_artifact, raw_timestamp, details)
    elif provider == _SECURITY_PROVIDER and event_id == "4663":
        return _build_file_access_event(root, source_artifact, raw_timestamp, details)

    return None


def _system_details(system: ET.Element, provider: str, event_id: str) -> dict[str, object]:
    """Return serialisable system fields needed to trace an EVTX record."""
    details: dict[str, object] = {"provider": provider, "event_id": event_id}
    for element_name, detail_name in (("EventRecordID", "record_id"), ("Channel", "channel")):
        element = system.find(f"ns:{element_name}", _NS)
        if element is not None and element.text:
            details[detail_name] = element.text.strip()
    return details


def _event_data(root: ET.Element) -> dict[str, str]:
    """Return named EventData values, rejecting duplicate field names."""
    event_data = root.find("ns:EventData", _NS)
    if event_data is None:
        return {}

    values: dict[str, str] = {}
    for data in event_data.findall("ns:Data", _NS):
        name = data.attrib.get("Name")
        if not name or data.text is None:
            continue
        if name in values:
            raise EvtxParseError(f"Duplicate EventData field '{name}'")
        values[name] = data.text
    return values


def _device_instance_id(root: ET.Element) -> str | None:
    """Extract the device instance identifier from EventData or UserData."""
    values = _event_data(root)
    for field_name in ("DeviceInstanceId", "DeviceInstanceID", "InstanceId", "DeviceId"):
        if values.get(field_name):
            return values[field_name]

    user_data = root.find("ns:UserData", _NS)
    if user_data is not None:
        for element in user_data.iter():
            local_name = element.tag.rsplit("}", maxsplit=1)[-1]
            if (
                local_name in {"DeviceInstanceId", "DeviceInstanceID", "InstanceId", "DeviceId"}
                and element.text
            ):
                return element.text
    return None


def _build_device_event(
    root: ET.Element,
    event_type: str,
    source_artifact: str,
    raw_timestamp: str,
    details: dict[str, object],
) -> NormalizedEvent:
    """Build a device event after requiring a device instance identifier."""
    device_id = _device_instance_id(root)
    if not device_id:
        raise EvtxParseError(f"Missing device instance ID for device event in '{source_artifact}'")

    return NormalizedEvent(
        event_type=event_type,
        timestamp_utc=_parse_timestamp(raw_timestamp),
        raw_timestamp=raw_timestamp,
        source_artifact=source_artifact,
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        device=UsbDevice(device_id=device_id),
        details=details,
    )


def _build_file_access_event(
    root: ET.Element,
    source_artifact: str,
    raw_timestamp: str,
    details: dict[str, object],
) -> NormalizedEvent | None:
    """Build a file-access event from Security 4663, excluding non-file objects."""
    values = _event_data(root)
    object_type = values.get("ObjectType")
    if object_type is None:
        raise EvtxParseError(f"Missing ObjectType in Security 4663 event in '{source_artifact}'")
    if object_type.casefold() != "file":
        return None

    object_name = values.get("ObjectName")
    if not object_name:
        raise EvtxParseError(f"Missing ObjectName in Security 4663 event in '{source_artifact}'")

    for field_name in ("AccessMask", "AccessList", "ProcessName", "ProcessId", "SubjectUserName"):
        if values.get(field_name):
            details[field_name] = values[field_name]

    return NormalizedEvent(
        event_type=EventType.FILE_ACCESS.value,
        timestamp_utc=_parse_timestamp(raw_timestamp),
        raw_timestamp=raw_timestamp,
        source_artifact=source_artifact,
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        file_path=object_name,
        details=details,
    )

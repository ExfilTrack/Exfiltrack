"""Read-only parser for Windows Registry USB storage evidence.

Owner: Milindu Weerawarna
Related issue: #3 - Registry Artifact Parser

The parser establishes *device identity* from offline registry hives and emits
:class:`~exfiltrack.correlation.models.NormalizedEvent` values only. Raw
``Registry`` objects never leave this module.

See ``docs/evidence-sources.md`` for what each key proves versus merely
suggests. Two limitations are structural and shape the code below:

* Registry *values* carry no timestamp of their own; only *keys* record a
  LastWrite time. Events derived from a key's LastWrite therefore bound when
  the key was last modified, not when the recorded activity occurred, and are
  tagged with ``timestamp_from_key_lastwrite`` in ``details``.
* The device property timestamps record only the *most recent* arrival and
  removal. Absence of earlier sessions is not evidence that none occurred.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from Registry import Registry
from Registry import RegistryParse as registry_parse

from exfiltrack.config import ExfilTrackError
from exfiltrack.normalization.event_model import EventType, NormalizedEvent, UsbDevice, sort_events
from exfiltrack.normalization.timestamps import parse_filetime

PARSER_NAME = "registry_parser"
PARSER_VERSION = "1.0.0"


class RegistryParseError(ExfilTrackError):
    """Raised when a hive is missing, corrupt, or structurally unusable."""


# ---------------------------------------------------------------------------
# Event type labels
# ---------------------------------------------------------------------------

# Only USB_INSERT and USB_REMOVE are session boundaries for correlation. The
# labels below preserve evidence for the report appendix without asserting that
# a device became available at that moment.
DEVICE_FIRST_INSTALL = "usb_device_first_install"
DEVICE_REGISTERED = "usb_device_registered"
DRIVE_LETTER_ASSIGNED = "usb_drive_letter_assigned"
USER_MOUNT = "usb_user_mount"

# ---------------------------------------------------------------------------
# Registry paths and constants
# ---------------------------------------------------------------------------

_SELECT_KEY = "Select"
_USBSTOR_SUBPATH = r"Enum\USBSTOR"
_MOUNTED_DEVICES_KEY = "MountedDevices"
_PORTABLE_DEVICES_KEY = r"Microsoft\Windows Portable Devices\Devices"
_MOUNTPOINTS2_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"

# Device property GUID holding install/arrival/removal FILETIMEs (Windows 8+).
_DEVICE_TIMESTAMP_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
_PROP_FIRST_INSTALL = "0064"
_PROP_LAST_ARRIVAL = "0066"
_PROP_LAST_REMOVAL = "0067"

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_FILETIME_TICKS_PER_SECOND = 10_000_000

# A MountedDevices value shorter than this holds an MBR/GPT signature rather
# than a UTF-16LE device path.
_MIN_DEVICE_PATH_BYTES = 8


# ---------------------------------------------------------------------------
# Hive access
# ---------------------------------------------------------------------------


def _open_hive(path: Path) -> Registry.Registry:
    """Open a hive read-only, converting every failure into an explicit error."""
    if not path.is_file():
        raise RegistryParseError(f"Registry hive not found: '{path}'")
    try:
        return Registry.Registry(str(path))
    except registry_parse.RegistryException as exc:
        raise RegistryParseError(f"Corrupt registry hive '{path}': {exc}") from exc
    except (struct.error, ValueError) as exc:
        raise RegistryParseError(f"Truncated registry hive '{path}': {exc}") from exc
    except OSError as exc:
        raise RegistryParseError(f"Cannot read registry hive '{path}': {exc}") from exc


def _find_key(hive: Registry.Registry, path: str) -> Registry.RegistryKey | None:
    """Return the key at *path*, or ``None`` when it is absent.

    An absent key is not an error: a machine with no USB history legitimately
    has no ``USBSTOR`` subtree.
    """
    try:
        return hive.open(path)
    except Registry.RegistryKeyNotFoundException:
        return None


def _value_or_none(key: Registry.RegistryKey, name: str) -> Any | None:
    """Return the named value's data, or ``None`` when the value is absent."""
    try:
        return key.value(name).value()
    except Registry.RegistryValueNotFoundException:
        return None


def _subkey_or_none(key: Registry.RegistryKey, name: str) -> Registry.RegistryKey | None:
    """Return the named subkey, or ``None`` when it is absent."""
    try:
        return key.subkey(name)
    except Registry.RegistryKeyNotFoundException:
        return None


def _key_timestamp(key: Registry.RegistryKey) -> datetime:
    """Return a key's LastWrite time as timezone-aware UTC.

    ``python-registry`` returns a naive datetime that already represents UTC,
    so the zone is attached rather than converted.
    """
    raw = key.timestamp()
    if raw.tzinfo is None:
        return raw.replace(tzinfo=timezone.utc)
    return raw.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Control set resolution
# ---------------------------------------------------------------------------


def resolve_control_set(hive: Registry.Registry) -> str:
    """Return the active control set key name, for example ``ControlSet001``.

    ``CurrentControlSet`` is a runtime symlink that does not exist in an
    offline hive. Reading ``Select\\Current`` is the only way to know which
    control set was active; guessing ``ControlSet001`` silently analyses a
    stale control set on a machine that last booted from another one.
    """
    select = _find_key(hive, _SELECT_KEY)
    if select is None:
        raise RegistryParseError(
            "SYSTEM hive has no 'Select' key; cannot determine the active control set."
        )

    current = _value_or_none(select, "Current")
    if not isinstance(current, int) or current <= 0:
        raise RegistryParseError(
            f"'Select\\Current' is missing or not a positive integer (got {current!r})."
        )
    return f"ControlSet{current:03d}"


# ---------------------------------------------------------------------------
# Device identity helpers
# ---------------------------------------------------------------------------


def parse_device_key_name(name: str) -> dict[str, str]:
    """Split a ``USBSTOR`` device key name into its labelled components.

    A device key is named ``Disk&Ven_<vendor>&Prod_<product>&Rev_<revision>``.
    Fields the key omits are returned as empty strings rather than guessed.
    """
    fields = {"device_class": "", "vendor": "", "product": "", "revision": ""}
    prefixes = (
        ("Ven_", "vendor"),
        ("Prod_", "product"),
        ("Rev_", "revision"),
    )
    for index, part in enumerate(name.split("&")):
        if index == 0:
            fields["device_class"] = part
            continue
        for prefix, field_name in prefixes:
            if part.startswith(prefix):
                fields[field_name] = part[len(prefix) :].replace("_", " ").strip()
                break
    return fields


def is_windows_generated_serial(serial: str) -> bool:
    """Return whether *serial* was generated by Windows rather than the device.

    Windows synthesises an instance ID when a device reports no unique serial,
    marking it with ``&`` as the second character. Such a value identifies the
    *port path* the device was attached to, not the device, so it cannot
    attribute activity to a physical device across machines.
    """
    return len(serial) > 1 and serial[1] == "&"


def _filetime_to_utc(raw: object) -> tuple[datetime, str] | None:
    """Convert a registry FILETIME to UTC, returning ``(utc, raw_text)``.

    Returns ``None`` when the value is absent or zero, which the registry uses
    to mean "never recorded" rather than 1601-01-01.
    """
    if raw is None:
        return None

    if isinstance(raw, int):
        if raw == 0:
            return None
        ticks = raw
    elif isinstance(raw, bytes):
        if len(raw) == 0:
            return None
        if len(raw) != 8:
            raise RegistryParseError(
                f"Malformed FILETIME value: expected 8 bytes, got {len(raw)} bytes"
            )
        ticks = struct.unpack("<Q", raw)[0]
        if ticks == 0:
            return None
    else:
        raise RegistryParseError(f"Malformed FILETIME value: unsupported type {type(raw)}")

    try:
        return parse_filetime(ticks), str(ticks)
    except ValueError as exc:
        raise RegistryParseError(f"Malformed FILETIME value: {exc}") from exc


def _device_property_timestamp(
    serial_key: Registry.RegistryKey, property_id: str
) -> tuple[datetime, str] | None:
    """Read one device-property FILETIME, tolerating absent property subtrees."""
    properties = _subkey_or_none(serial_key, "Properties")
    if properties is None:
        return None
    guid_key = _subkey_or_none(properties, _DEVICE_TIMESTAMP_GUID)
    if guid_key is None:
        return None
    property_key = _subkey_or_none(guid_key, property_id)
    if property_key is None:
        return None

    for value in property_key.values():
        converted = _filetime_to_utc(value.value())
        if converted is not None:
            return converted
    return None


def _build_device(device_key_name: str, serial: str, friendly_name: str = "") -> UsbDevice:
    """Assemble the device identity used to group events across artifacts."""
    fields = parse_device_key_name(device_key_name)
    return UsbDevice(
        device_id=rf"USBSTOR\{device_key_name}\{serial}",
        serial_number=serial,
        vendor=fields["vendor"],
        product=fields["product"],
        friendly_name=friendly_name,
    )


# ---------------------------------------------------------------------------
# SYSTEM hive
# ---------------------------------------------------------------------------


def _usbstor_events(
    hive: Registry.Registry, control_set: str, source_artifact: str
) -> Iterator[NormalizedEvent]:
    """Yield device identity and lifecycle events from ``Enum\\USBSTOR``."""
    usbstor = _find_key(hive, rf"{control_set}\{_USBSTOR_SUBPATH}")
    if usbstor is None:
        return

    for device_key in usbstor.subkeys():
        for serial_key in device_key.subkeys():
            yield from _serial_key_events(device_key.name(), serial_key, source_artifact)


def _serial_key_events(
    device_key_name: str, serial_key: Registry.RegistryKey, source_artifact: str
) -> Iterator[NormalizedEvent]:
    """Yield every event derivable from one device instance (serial) key."""
    serial = serial_key.name()
    friendly_name = _value_or_none(serial_key, "FriendlyName") or ""
    device = _build_device(device_key_name, serial, str(friendly_name))

    base_details: dict[str, object] = {
        "registry_key": serial_key.path(),
        "device_class": parse_device_key_name(device_key_name)["device_class"],
        "revision": parse_device_key_name(device_key_name)["revision"],
        "windows_generated_serial": is_windows_generated_serial(serial),
    }
    device_desc = _value_or_none(serial_key, "DeviceDesc")
    if device_desc:
        base_details["device_desc"] = str(device_desc)

    emitted_property_event = False
    for property_id, event_type in (
        (_PROP_FIRST_INSTALL, DEVICE_FIRST_INSTALL),
        (_PROP_LAST_ARRIVAL, EventType.USB_INSERT.value),
        (_PROP_LAST_REMOVAL, EventType.USB_REMOVE.value),
    ):
        converted = _device_property_timestamp(serial_key, property_id)
        if converted is None:
            continue
        timestamp_utc, raw_timestamp = converted
        details = dict(base_details)
        details["device_property"] = f"{_DEVICE_TIMESTAMP_GUID}\\{property_id}"
        if event_type in (EventType.USB_INSERT.value, EventType.USB_REMOVE.value):
            details["records_most_recent_only"] = True
        yield NormalizedEvent(
            event_type=event_type,
            timestamp_utc=timestamp_utc,
            raw_timestamp=raw_timestamp,
            source_artifact=source_artifact,
            parser_name=PARSER_NAME,
            parser_version=PARSER_VERSION,
            device=device,
            details=details,
        )
        emitted_property_event = True

    if emitted_property_event:
        return

    # Windows 7 and earlier record no device-property timestamps. The key's
    # LastWrite still proves the device was enumerated on this machine.
    details = dict(base_details)
    details["timestamp_from_key_lastwrite"] = True
    yield NormalizedEvent(
        event_type=DEVICE_REGISTERED,
        timestamp_utc=_key_timestamp(serial_key),
        raw_timestamp=serial_key.timestamp().isoformat(),
        source_artifact=source_artifact,
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        device=device,
        details=details,
    )


def _decode_mounted_device_target(raw: bytes) -> str | None:
    """Decode a ``MountedDevices`` value into a device path, when it holds one.

    Fixed disks store a 12-byte MBR signature or GPT identifier here; only
    removable and volume entries store a UTF-16LE device path.
    """
    if len(raw) < _MIN_DEVICE_PATH_BYTES or raw[1] != 0:
        return None
    try:
        decoded = raw.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return None
    return decoded if decoded.startswith("\\") else None


def _mounted_devices_events(
    hive: Registry.Registry, source_artifact: str
) -> Iterator[NormalizedEvent]:
    """Yield drive-letter to volume mappings from ``MountedDevices``.

    ``MountedDevices`` is a flat value table with a single LastWrite time on
    the parent key, so every event here shares that timestamp. It bounds when
    the table was last modified and must not be read as the moment this
    particular letter was assigned.
    """
    mounted = _find_key(hive, _MOUNTED_DEVICES_KEY)
    if mounted is None:
        return

    timestamp_utc = _key_timestamp(mounted)
    raw_timestamp = mounted.timestamp().isoformat()

    for value in mounted.values():
        name = value.name()
        raw = value.raw_data()
        if not isinstance(raw, bytes):
            continue
        target = _decode_mounted_device_target(raw)
        if target is None or "USBSTOR" not in target.upper():
            continue

        details: dict[str, object] = {
            "registry_key": mounted.path(),
            "mount_entry": name,
            "device_path": target,
            "timestamp_from_key_lastwrite": True,
        }
        drive_letter = _drive_letter(name)
        if drive_letter:
            details["drive_letter"] = drive_letter
        # A "\DosDevices\E:" entry carries the GUID in its target path, while a
        # "\??\Volume{...}" entry carries it in its own name.
        volume_guid = _volume_guid(name) or _volume_guid(target)
        if volume_guid:
            details["volume_guid"] = volume_guid

        device = _device_from_device_path(target)
        if device is None:
            continue
        yield NormalizedEvent(
            event_type=DRIVE_LETTER_ASSIGNED,
            timestamp_utc=timestamp_utc,
            raw_timestamp=raw_timestamp,
            source_artifact=source_artifact,
            parser_name=PARSER_NAME,
            parser_version=PARSER_VERSION,
            device=device,
            details=details,
        )


def _drive_letter(entry_name: str) -> str:
    """Return the drive letter in a ``\\DosDevices\\E:`` entry name, if present."""
    marker = "\\DosDevices\\"
    if entry_name.startswith(marker):
        return entry_name[len(marker) :]
    return ""


def _volume_guid(entry_name: str) -> str:
    """Return the volume GUID in a ``\\??\\Volume{...}`` entry name, if present."""
    start = entry_name.find("{")
    end = entry_name.find("}", start + 1)
    if start != -1 and end != -1:
        return entry_name[start : end + 1]
    return ""


def _device_from_device_path(device_path: str) -> UsbDevice | None:
    """Build a device identity from a ``USBSTOR#Disk&Ven_...#serial#{guid}`` path.

    The same instance appears with ``#`` separators here and ``\\`` separators
    under ``Enum\\USBSTOR``; normalising to backslashes keeps ``device_id``
    consistent so events from both keys group onto one device.
    """
    parts = [part for part in device_path.replace("\\", "#").split("#") if part]
    for index, part in enumerate(parts):
        if part.upper() != "USBSTOR":
            continue
        remainder = parts[index + 1 :]
        if len(remainder) < 2:
            return None
        return _build_device(remainder[0], remainder[1])
    return None


def parse_system_hive(file_path: Path | str) -> list[NormalizedEvent]:
    """Parse a ``SYSTEM`` hive read-only and return its USB events.

    Args:
        file_path: Path to an exported ``SYSTEM`` hive.

    Returns:
        Deterministically ordered events from ``Enum\\USBSTOR`` and
        ``MountedDevices``.

    Raises:
        RegistryParseError: If the hive is missing, corrupt, or has no
            resolvable control set.
    """
    path = Path(file_path)
    source_artifact = path.as_posix()
    hive = _open_hive(path)
    control_set = resolve_control_set(hive)

    events = list(_usbstor_events(hive, control_set, source_artifact))
    events.extend(_mounted_devices_events(hive, source_artifact))
    return sort_events(events)


# ---------------------------------------------------------------------------
# SOFTWARE hive
# ---------------------------------------------------------------------------


def parse_software_hive(file_path: Path | str) -> list[NormalizedEvent]:
    """Parse a ``SOFTWARE`` hive read-only for Portable Devices friendly names.

    Each ``Windows Portable Devices\\Devices`` subkey names a device instance
    and carries the volume label a user would recognise. The subkey's LastWrite
    is the only available timestamp.

    Raises:
        RegistryParseError: If the hive is missing or corrupt.
    """
    path = Path(file_path)
    source_artifact = path.as_posix()
    hive = _open_hive(path)

    devices_key = _find_key(hive, _PORTABLE_DEVICES_KEY)
    if devices_key is None:
        return []

    events: list[NormalizedEvent] = []
    for entry in devices_key.subkeys():
        device = _device_from_device_path(entry.name())
        if device is None:
            continue
        friendly_name = _value_or_none(entry, "FriendlyName")
        if friendly_name:
            device = UsbDevice(
                device_id=device.device_id,
                serial_number=device.serial_number,
                vendor=device.vendor,
                product=device.product,
                friendly_name=str(friendly_name),
            )
        events.append(
            NormalizedEvent(
                event_type=DEVICE_REGISTERED,
                timestamp_utc=_key_timestamp(entry),
                raw_timestamp=entry.timestamp().isoformat(),
                source_artifact=source_artifact,
                parser_name=PARSER_NAME,
                parser_version=PARSER_VERSION,
                device=device,
                details={
                    "registry_key": entry.path(),
                    "portable_device_entry": entry.name(),
                    "timestamp_from_key_lastwrite": True,
                },
            )
        )
    return sort_events(events)


# ---------------------------------------------------------------------------
# NTUSER.DAT hive
# ---------------------------------------------------------------------------


def parse_ntuser_hive(file_path: Path | str) -> list[NormalizedEvent]:
    """Parse an ``NTUSER.DAT`` hive read-only for per-user volume mounts.

    ``MountPoints2`` records the volumes a specific user account mounted, which
    is what ties a device to a person rather than to the machine. Each subkey's
    LastWrite correlates with a mount but does not prove one: any write to the
    key updates it.

    Raises:
        RegistryParseError: If the hive is missing or corrupt.
    """
    path = Path(file_path)
    source_artifact = path.as_posix()
    hive = _open_hive(path)

    mount_points = _find_key(hive, _MOUNTPOINTS2_KEY)
    if mount_points is None:
        return []

    events: list[NormalizedEvent] = []
    for entry in mount_points.subkeys():
        name = entry.name()
        volume_guid = _volume_guid(name)
        details: dict[str, object] = {
            "registry_key": entry.path(),
            "mount_point_entry": name,
            "timestamp_from_key_lastwrite": True,
        }
        if volume_guid:
            details["volume_guid"] = volume_guid
        else:
            details["mount_point_kind"] = "drive_letter_or_share"

        events.append(
            NormalizedEvent(
                event_type=USER_MOUNT,
                timestamp_utc=_key_timestamp(entry),
                raw_timestamp=entry.timestamp().isoformat(),
                source_artifact=source_artifact,
                parser_name=PARSER_NAME,
                parser_version=PARSER_VERSION,
                details=details,
            )
        )
    return sort_events(events)


# ---------------------------------------------------------------------------
# Dispatch and ordering
# ---------------------------------------------------------------------------


# sort_events is imported from exfiltrack.normalization.event_model


def parse_registry_hive(file_path: Path | str) -> list[NormalizedEvent]:
    """Parse any supported hive read-only, dispatching on its content.

    The hive's role is detected by probing for the keys that define it rather
    than by trusting the file name, since exported hives are routinely renamed
    during acquisition.

    Raises:
        RegistryParseError: If the hive is missing, corrupt, or is not a
            SYSTEM, SOFTWARE, or NTUSER.DAT hive.
    """
    path = Path(file_path)
    hive = _open_hive(path)

    if _find_key(hive, _SELECT_KEY) is not None:
        return parse_system_hive(path)
    if _find_key(hive, _PORTABLE_DEVICES_KEY) is not None:
        return parse_software_hive(path)
    if _find_key(hive, _MOUNTPOINTS2_KEY) is not None:
        return parse_ntuser_hive(path)

    raise RegistryParseError(
        f"'{path}' is a valid hive but contains none of the keys this parser "
        "consumes (Select, Windows Portable Devices\\Devices, MountPoints2)."
    )

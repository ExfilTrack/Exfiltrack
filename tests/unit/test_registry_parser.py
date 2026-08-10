"""Unit tests for the registry parser, using synthetic hive doubles.

A valid ``regf`` hive cannot be constructed in code, and a real exported hive
carries the acquiring machine's genuine device serial numbers, which
``tests/fixtures/README.md`` forbids committing. Tests therefore drive the
parser through a double of the small ``python-registry`` surface it uses
(``open``, ``subkey``, ``subkeys``, ``value``, ``values``, ``timestamp``,
``path``, ``name``), which keeps the mapping and ordering logic under test
while remaining runnable on the Linux CI image.

``test_real_hive_api_matches_the_double`` guards the risk that approach leaves
open: that the double and the real library disagree. It runs only when a
synthetic hive fixture is present.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest
from Registry import Registry
from Registry import RegistryParse as registry_parse

from exfiltrack.correlation.models import EventType
from exfiltrack.parsers.registry_parser import (
    DEVICE_FIRST_INSTALL,
    DEVICE_REGISTERED,
    DRIVE_LETTER_ASSIGNED,
    PARSER_NAME,
    PARSER_VERSION,
    USER_MOUNT,
    RegistryParseError,
    is_windows_generated_serial,
    parse_device_key_name,
    parse_ntuser_hive,
    parse_registry_hive,
    parse_software_hive,
    parse_system_hive,
    resolve_control_set,
)

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

DEVICE_KEY = "Disk&Ven_Synthetic&Prod_TestStick&Rev_1.0"
REAL_SERIAL = "FAKESERIAL001"
GENERATED_SERIAL = "7&1a2b3c4d&0"
VOLUME_GUID = "{11111111-2222-3333-4444-555555555555}"
DEVICE_PATH = rf"\??\USBSTOR#{DEVICE_KEY}#{REAL_SERIAL}#{VOLUME_GUID}"
EXPECTED_DEVICE_ID = rf"USBSTOR\{DEVICE_KEY}\{REAL_SERIAL}"

FIRST_INSTALL = datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc)
LAST_ARRIVAL = datetime(2026, 3, 2, 9, 30, 0, tzinfo=timezone.utc)
LAST_REMOVAL = datetime(2026, 3, 2, 10, 45, 0, tzinfo=timezone.utc)
KEY_WRITE_TIME = datetime(2026, 3, 3, 11, 0, 0, tzinfo=timezone.utc)


def _filetime(value: datetime) -> int:
    """Return *value* as 100-nanosecond intervals since 1601-01-01."""
    return int((value - _FILETIME_EPOCH).total_seconds()) * 10_000_000


# ---------------------------------------------------------------------------
# Synthetic hive doubles
# ---------------------------------------------------------------------------


class _Value:
    def __init__(self, name: str, value: object, raw: bytes | None = None) -> None:
        self._name = name
        self._value = value
        self._raw = raw if raw is not None else value

    def name(self) -> str:
        return self._name

    def value(self) -> object:
        return self._value

    def raw_data(self) -> object:
        return self._raw


class _Key:
    """Stand-in for ``Registry.RegistryKey``."""

    def __init__(
        self,
        name: str,
        subkeys: list[_Key] | None = None,
        values: list[_Value] | None = None,
        timestamp: datetime = KEY_WRITE_TIME,
        path: str | None = None,
    ) -> None:
        self._name = name
        self._subkeys = subkeys or []
        self._values = values or []
        # python-registry returns a naive datetime that already means UTC.
        self._timestamp = timestamp.replace(tzinfo=None)
        self._path = path if path is not None else name

    def name(self) -> str:
        return self._name

    def path(self) -> str:
        return self._path

    def timestamp(self) -> datetime:
        return self._timestamp

    def subkeys(self) -> list[_Key]:
        return self._subkeys

    def values(self) -> list[_Value]:
        return self._values

    def subkey(self, name: str) -> _Key:
        for candidate in self._subkeys:
            if candidate.name().lower() == name.lower():
                return candidate
        raise Registry.RegistryKeyNotFoundException(name)

    def value(self, name: str) -> _Value:
        for candidate in self._values:
            if candidate.name().lower() == name.lower():
                return candidate
        raise Registry.RegistryValueNotFoundException(name)

    def find_key(self, path: str) -> _Key:
        if not path:
            return self
        immediate, _, remainder = path.partition("\\")
        return self.subkey(immediate).find_key(remainder)


class _Hive:
    """Stand-in for ``Registry.Registry``."""

    def __init__(self, root: _Key) -> None:
        self._root = root

    def open(self, path: str) -> _Key:
        return self._root.find_key(path)


def _properties_key(
    first_install: datetime | None = FIRST_INSTALL,
    last_arrival: datetime | None = LAST_ARRIVAL,
    last_removal: datetime | None = LAST_REMOVAL,
) -> _Key:
    """Build the device-property subtree holding install/arrival/removal times."""
    property_keys: list[_Key] = []
    for property_id, moment in (
        ("0064", first_install),
        ("0066", last_arrival),
        ("0067", last_removal),
    ):
        if moment is None:
            continue
        packed = struct.pack("<Q", _filetime(moment))
        property_keys.append(_Key(property_id, values=[_Value("(default)", packed, packed)]))

    return _Key(
        "Properties",
        subkeys=[_Key("{83da6326-97a6-4088-9453-a1923f573b29}", subkeys=property_keys)],
    )


def _serial_key(
    serial: str = REAL_SERIAL,
    *,
    with_properties: bool = True,
    friendly_name: str = "Synthetic Test Stick",
) -> _Key:
    values = [_Value("DeviceDesc", "USB Mass Storage Device")]
    if friendly_name:
        values.append(_Value("FriendlyName", friendly_name))
    return _Key(
        serial,
        subkeys=[_properties_key()] if with_properties else [],
        values=values,
        path=rf"\ControlSet001\Enum\USBSTOR\{DEVICE_KEY}\{serial}",
    )


def _system_hive(
    *,
    current: object = 1,
    with_select: bool = True,
    serial_keys: list[_Key] | None = None,
    mounted_values: list[_Value] | None = None,
) -> _Hive:
    """Assemble a SYSTEM hive double."""
    usbstor = _Key(
        "USBSTOR",
        subkeys=[_Key(DEVICE_KEY, subkeys=serial_keys or [_serial_key()])],
    )
    control_set = _Key("ControlSet001", subkeys=[_Key("Enum", subkeys=[usbstor])])
    root_subkeys = [control_set]
    if with_select:
        root_subkeys.append(_Key("Select", values=[_Value("Current", current)]))
    if mounted_values is not None:
        root_subkeys.append(_Key("MountedDevices", values=mounted_values, path=r"\MountedDevices"))
    return _Hive(_Key("ROOT", subkeys=root_subkeys))


def _patch_hive(monkeypatch: pytest.MonkeyPatch, hive: _Hive) -> None:
    """Route the parser's hive opener at the synthetic hive."""
    monkeypatch.setattr(
        "exfiltrack.parsers.registry_parser._open_hive",
        lambda _path: hive,
    )


@pytest.fixture
def hive_path(tmp_path: Path) -> Path:
    """A real file so path handling runs, whose bytes the double replaces."""
    path = tmp_path / "SYSTEM"
    path.write_bytes(b"regf" + b"\x00" * 60)
    return path


# ---------------------------------------------------------------------------
# Provenance and declared constants
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parser_declares_provenance_constants() -> None:
    assert PARSER_NAME == "registry_parser"
    assert PARSER_VERSION == "1.0.0"


@pytest.mark.unit
def test_every_event_carries_parser_provenance(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    _patch_hive(monkeypatch, _system_hive())
    events = parse_system_hive(hive_path)

    assert events
    for event in events:
        assert event.parser_name == PARSER_NAME
        assert event.parser_version == PARSER_VERSION
        assert event.source_artifact == hive_path.as_posix()
        assert event.timestamp_utc.tzinfo is not None


# ---------------------------------------------------------------------------
# Control set resolution
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(("current", "expected"), [(1, "ControlSet001"), (2, "ControlSet002")])
def test_resolve_control_set_reads_select_current(current: int, expected: str) -> None:
    assert resolve_control_set(_system_hive(current=current)) == expected


@pytest.mark.unit
def test_resolve_control_set_raises_when_select_is_missing() -> None:
    with pytest.raises(RegistryParseError, match="no 'Select' key"):
        resolve_control_set(_system_hive(with_select=False))


@pytest.mark.unit
@pytest.mark.parametrize("current", [0, -1, "one", None])
def test_resolve_control_set_rejects_unusable_current(current: object) -> None:
    with pytest.raises(RegistryParseError, match="not a positive integer"):
        resolve_control_set(_system_hive(current=current))


@pytest.mark.unit
def test_control_set_two_is_used_when_select_says_so(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    """A hive whose active set is 002 must not fall back to reading 001."""
    hive = _system_hive(current=2)
    _patch_hive(monkeypatch, hive)

    assert parse_system_hive(hive_path) == []


# ---------------------------------------------------------------------------
# Device key name parsing and serial classification
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_device_key_name_splits_labelled_fields() -> None:
    fields = parse_device_key_name("Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.26")

    assert fields == {
        "device_class": "Disk",
        "vendor": "SanDisk",
        "product": "Cruzer Blade",
        "revision": "1.26",
    }


@pytest.mark.unit
def test_parse_device_key_name_leaves_absent_fields_empty() -> None:
    fields = parse_device_key_name("Disk&Ven_&Prod_USB_DISK")

    assert fields["vendor"] == ""
    assert fields["product"] == "USB DISK"
    assert fields["revision"] == ""


@pytest.mark.unit
@pytest.mark.parametrize("serial", ["7&1a2b3c4d&0", "0&0"])
def test_windows_generated_serials_are_detected(serial: str) -> None:
    assert is_windows_generated_serial(serial) is True


@pytest.mark.unit
@pytest.mark.parametrize("serial", ["FAKESERIAL001", "AA040012700036221216", "X", ""])
def test_device_reported_serials_are_not_flagged(serial: str) -> None:
    assert is_windows_generated_serial(serial) is False


@pytest.mark.unit
def test_generated_serial_is_flagged_in_event_details(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    """A Windows-generated serial must be marked, since it cannot identify a device."""
    _patch_hive(monkeypatch, _system_hive(serial_keys=[_serial_key(GENERATED_SERIAL)]))
    events = parse_system_hive(hive_path)

    assert events
    assert all(event.details["windows_generated_serial"] is True for event in events)


# ---------------------------------------------------------------------------
# USBSTOR events
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_usbstor_emits_install_arrival_and_removal(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    _patch_hive(monkeypatch, _system_hive())
    events = parse_system_hive(hive_path)

    by_type = {event.event_type: event for event in events}
    assert by_type[DEVICE_FIRST_INSTALL].timestamp_utc == FIRST_INSTALL
    assert by_type[EventType.USB_INSERT.value].timestamp_utc == LAST_ARRIVAL
    assert by_type[EventType.USB_REMOVE.value].timestamp_utc == LAST_REMOVAL


@pytest.mark.unit
def test_usbstor_events_carry_device_identity(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    _patch_hive(monkeypatch, _system_hive())
    event = parse_system_hive(hive_path)[0]

    assert event.device is not None
    assert event.device.device_id == EXPECTED_DEVICE_ID
    assert event.device.serial_number == REAL_SERIAL
    assert event.device.vendor == "Synthetic"
    assert event.device.product == "TestStick"
    assert event.device.friendly_name == "Synthetic Test Stick"


@pytest.mark.unit
def test_arrival_and_removal_are_marked_as_most_recent_only(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    """These properties are overwritten each session; earlier ones are unrecoverable."""
    _patch_hive(monkeypatch, _system_hive())
    events = parse_system_hive(hive_path)

    for event in events:
        if event.event_type in (EventType.USB_INSERT.value, EventType.USB_REMOVE.value):
            assert event.details["records_most_recent_only"] is True


@pytest.mark.unit
def test_device_without_property_timestamps_falls_back_to_key_lastwrite(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    """Windows 7 records no device properties, but enumeration still happened."""
    _patch_hive(
        monkeypatch,
        _system_hive(serial_keys=[_serial_key(with_properties=False)]),
    )
    events = parse_system_hive(hive_path)

    assert len(events) == 1
    assert events[0].event_type == DEVICE_REGISTERED
    assert events[0].timestamp_utc == KEY_WRITE_TIME
    assert events[0].details["timestamp_from_key_lastwrite"] is True


@pytest.mark.unit
def test_zero_filetime_is_treated_as_never_recorded(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    """A zero FILETIME means "no value", not 1601-01-01."""
    zero = struct.pack("<Q", 0)
    properties = _Key(
        "Properties",
        subkeys=[
            _Key(
                "{83da6326-97a6-4088-9453-a1923f573b29}",
                subkeys=[_Key("0066", values=[_Value("(default)", zero, zero)])],
            )
        ],
    )
    serial = _Key(REAL_SERIAL, subkeys=[properties], values=[])
    _patch_hive(monkeypatch, _system_hive(serial_keys=[serial]))

    events = parse_system_hive(hive_path)

    assert [event.event_type for event in events] == [DEVICE_REGISTERED]
    assert all(event.timestamp_utc.year != 1601 for event in events)


# ---------------------------------------------------------------------------
# MountedDevices
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_mounted_devices_maps_drive_letter_to_device(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    encoded = DEVICE_PATH.encode("utf-16-le")
    _patch_hive(
        monkeypatch,
        _system_hive(mounted_values=[_Value(r"\DosDevices\E:", encoded, encoded)]),
    )

    events = [
        event for event in parse_system_hive(hive_path) if event.event_type == DRIVE_LETTER_ASSIGNED
    ]

    assert len(events) == 1
    assert events[0].details["drive_letter"] == "E:"
    assert events[0].details["volume_guid"] == VOLUME_GUID
    assert events[0].details["timestamp_from_key_lastwrite"] is True
    assert events[0].device is not None
    assert events[0].device.device_id == EXPECTED_DEVICE_ID


@pytest.mark.unit
def test_mounted_devices_groups_onto_the_same_device_as_usbstor(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    """The '#'-separated path and the Enum\\USBSTOR key must yield one device_id."""
    encoded = DEVICE_PATH.encode("utf-16-le")
    _patch_hive(
        monkeypatch,
        _system_hive(mounted_values=[_Value(r"\DosDevices\E:", encoded, encoded)]),
    )

    device_ids = {event.device.device_id for event in parse_system_hive(hive_path) if event.device}

    assert device_ids == {EXPECTED_DEVICE_ID}


@pytest.mark.unit
def test_mounted_devices_ignores_fixed_disk_signatures(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    """A 12-byte MBR signature is not a UTF-16LE device path."""
    mbr = struct.pack("<I", 0xA1B2C3D4) + b"\x00" * 8
    _patch_hive(
        monkeypatch,
        _system_hive(mounted_values=[_Value(r"\DosDevices\C:", mbr, mbr)]),
    )

    assert not [
        event for event in parse_system_hive(hive_path) if event.event_type == DRIVE_LETTER_ASSIGNED
    ]


@pytest.mark.unit
def test_mounted_devices_ignores_non_usb_volumes(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    encoded = r"\??\IDE#DiskSAMSUNG_SSD#0000".encode("utf-16-le")
    _patch_hive(
        monkeypatch,
        _system_hive(mounted_values=[_Value(r"\DosDevices\C:", encoded, encoded)]),
    )

    assert not [
        event for event in parse_system_hive(hive_path) if event.event_type == DRIVE_LETTER_ASSIGNED
    ]


# ---------------------------------------------------------------------------
# SOFTWARE hive
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_software_hive_extracts_friendly_names(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    entry = _Key(
        rf"USBSTOR#{DEVICE_KEY}#{REAL_SERIAL}#{VOLUME_GUID}",
        values=[_Value("FriendlyName", "EVIDENCE_STICK")],
        path=r"\Microsoft\Windows Portable Devices\Devices\entry",
    )
    devices = _Key("Devices", subkeys=[entry])
    root = _Key(
        "ROOT",
        subkeys=[
            _Key(
                "Microsoft",
                subkeys=[_Key("Windows Portable Devices", subkeys=[devices])],
            )
        ],
    )
    _patch_hive(monkeypatch, _Hive(root))

    events = parse_software_hive(hive_path)

    assert len(events) == 1
    assert events[0].event_type == DEVICE_REGISTERED
    assert events[0].device is not None
    assert events[0].device.friendly_name == "EVIDENCE_STICK"
    assert events[0].device.device_id == EXPECTED_DEVICE_ID
    assert events[0].details["timestamp_from_key_lastwrite"] is True


@pytest.mark.unit
def test_software_hive_without_portable_devices_returns_no_events(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    _patch_hive(monkeypatch, _Hive(_Key("ROOT", subkeys=[_Key("Microsoft")])))

    assert parse_software_hive(hive_path) == []


# ---------------------------------------------------------------------------
# NTUSER.DAT hive
# ---------------------------------------------------------------------------


def _ntuser_hive(entries: list[_Key]) -> _Hive:
    mount_points = _Key("MountPoints2", subkeys=entries)
    explorer = _Key("Explorer", subkeys=[mount_points])
    return _Hive(
        _Key(
            "ROOT",
            subkeys=[
                _Key(
                    "Software",
                    subkeys=[
                        _Key(
                            "Microsoft",
                            subkeys=[
                                _Key(
                                    "Windows",
                                    subkeys=[_Key("CurrentVersion", subkeys=[explorer])],
                                )
                            ],
                        )
                    ],
                )
            ],
        )
    )


@pytest.mark.unit
def test_ntuser_hive_extracts_per_user_volume_guids(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    entry = _Key(
        f"##?#Volume{VOLUME_GUID}",
        path=r"\Software\...\MountPoints2\volume",
    )
    _patch_hive(monkeypatch, _ntuser_hive([entry]))

    events = parse_ntuser_hive(hive_path)

    assert len(events) == 1
    assert events[0].event_type == USER_MOUNT
    assert events[0].details["volume_guid"] == VOLUME_GUID
    assert events[0].details["timestamp_from_key_lastwrite"] is True


@pytest.mark.unit
def test_ntuser_hive_labels_non_guid_mount_points(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    _patch_hive(monkeypatch, _ntuser_hive([_Key("E", path=r"\...\MountPoints2\E")]))

    events = parse_ntuser_hive(hive_path)

    assert events[0].details["mount_point_kind"] == "drive_letter_or_share"
    assert "volume_guid" not in events[0].details


@pytest.mark.unit
def test_ntuser_events_carry_no_device_identity(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    """MountPoints2 records a volume, which is not itself a device identity."""
    entry = _Key(f"##?#Volume{VOLUME_GUID}", path=r"\...\MountPoints2\volume")
    _patch_hive(monkeypatch, _ntuser_hive([entry]))

    assert parse_ntuser_hive(hive_path)[0].device is None


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_output_order_is_independent_of_registry_enumeration_order(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    """Hive cell layout must not affect output order."""
    serials = [_serial_key("SERIAL_B"), _serial_key("SERIAL_A")]
    _patch_hive(monkeypatch, _system_hive(serial_keys=serials))
    forward = parse_system_hive(hive_path)

    _patch_hive(monkeypatch, _system_hive(serial_keys=list(reversed(serials))))
    reversed_order = parse_system_hive(hive_path)

    assert [(e.timestamp_utc, e.event_type, e.device.device_id) for e in forward if e.device] == [
        (e.timestamp_utc, e.event_type, e.device.device_id) for e in reversed_order if e.device
    ]


@pytest.mark.unit
def test_repeated_parses_are_byte_identical(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    _patch_hive(monkeypatch, _system_hive())
    first = parse_system_hive(hive_path)
    _patch_hive(monkeypatch, _system_hive())
    second = parse_system_hive(hive_path)

    assert first == second


# ---------------------------------------------------------------------------
# Explicit failure on missing and corrupt hives
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_missing_hive_raises_explicit_error(tmp_path: Path) -> None:
    with pytest.raises(RegistryParseError, match="not found"):
        parse_system_hive(tmp_path / "absent" / "SYSTEM")


@pytest.mark.unit
def test_directory_in_place_of_hive_raises_explicit_error(tmp_path: Path) -> None:
    target = tmp_path / "SYSTEM"
    target.mkdir()

    with pytest.raises(RegistryParseError, match="not found"):
        parse_system_hive(target)


@pytest.mark.unit
def test_corrupt_hive_raises_explicit_error(tmp_path: Path) -> None:
    """A file that is not a hive must fail loudly, not return zero events."""
    target = tmp_path / "SYSTEM"
    target.write_bytes(b"this is not a registry hive" * 20)

    with pytest.raises(RegistryParseError, match="Corrupt registry hive"):
        parse_system_hive(target)


@pytest.mark.unit
def test_truncated_hive_raises_explicit_error(tmp_path: Path) -> None:
    target = tmp_path / "SYSTEM"
    target.write_bytes(b"reg")

    with pytest.raises(RegistryParseError, match="Truncated|Corrupt"):
        parse_system_hive(target)


@pytest.mark.unit
def test_registry_parse_error_is_an_exfiltrack_error() -> None:
    from exfiltrack.config import ExfilTrackError

    assert issubclass(RegistryParseError, ExfilTrackError)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_dispatch_detects_system_hive_by_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A renamed hive is still identified, since acquisition often renames files."""
    renamed = tmp_path / "hive_01.bin"
    renamed.write_bytes(b"regf" + b"\x00" * 60)
    _patch_hive(monkeypatch, _system_hive())

    events = parse_registry_hive(renamed)

    assert events
    assert events[0].source_artifact == renamed.as_posix()


@pytest.mark.unit
def test_dispatch_rejects_a_hive_with_no_consumed_keys(
    monkeypatch: pytest.MonkeyPatch, hive_path: Path
) -> None:
    _patch_hive(monkeypatch, _Hive(_Key("ROOT", subkeys=[_Key("SAM")])))

    with pytest.raises(RegistryParseError, match="contains none of the keys"):
        parse_registry_hive(hive_path)


# ---------------------------------------------------------------------------
# Guard: the double must match the real library
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.requires_fixtures
def test_real_hive_api_matches_the_double(fixtures_dir: Path) -> None:
    """Confirm ``python-registry`` exposes the surface the doubles emulate.

    Generate the fixture on Windows with only synthetic names:

        reg add "HKCU\\Software\\ExfilTrackFixture\\Select" /v Current /t REG_DWORD /d 1
        reg save "HKCU\\Software\\ExfilTrackFixture" \\
            tests/fixtures/registry/system_synthetic.hiv
    """
    fixture = fixtures_dir / "registry" / "system_synthetic.hiv"
    if not fixture.is_file():
        pytest.skip(f"synthetic hive fixture not present: {fixture}")

    hive = Registry.Registry(str(fixture))
    select = hive.open("Select")

    assert isinstance(select.timestamp(), datetime)
    assert isinstance(select.value("Current").value(), int)
    assert resolve_control_set(hive).startswith("ControlSet")


@pytest.mark.unit
def test_corrupt_hive_exception_type_is_still_what_the_parser_catches() -> None:
    """Guard the assumption behind the corrupt-hive handler.

    If ``python-registry`` changes which exception an invalid REGF raises, the
    handler in ``_open_hive`` would stop converting it into a
    ``RegistryParseError`` and the failure would escape as a raw library error.
    """
    import io

    with pytest.raises(registry_parse.RegistryException):
        Registry.Registry(io.BytesIO(b"notahive" * 100))

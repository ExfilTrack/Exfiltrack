"""Unit tests for the EVTX parser, using synthetic Event XML fixtures."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from exfiltrack.correlation.models import EventType
from exfiltrack.parsers.evtx_parser import (
    DEVICE_INSTALL,
    DEVICE_REMOVE_PENDING,
    PARSER_NAME,
    PARSER_VERSION,
    EvtxParseError,
    parse_evtx,
)


class _SyntheticRecord:
    def __init__(self, xml: str) -> None:
        self._xml = xml

    def xml(self) -> str:
        return self._xml


class _SyntheticLog:
    def __init__(self, records: Iterable[str]) -> None:
        self._records = [_SyntheticRecord(record) for record in records]

    def __enter__(self) -> _SyntheticLog:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def records(self) -> list[_SyntheticRecord]:
        return self._records


def _parse_synthetic(monkeypatch: pytest.MonkeyPatch, records: list[str]) -> list[Any]:
    monkeypatch.setattr(
        "exfiltrack.parsers.evtx_parser.evtx.Evtx", lambda _: _SyntheticLog(records)
    )
    return list(parse_evtx("evidence/logs/System.evtx"))


def _fixture(fixtures_dir: Path, name: str) -> str:
    return (fixtures_dir / "evtx" / name).read_text(encoding="utf-8")


@pytest.mark.unit
def test_parse_dfu_connection_preserves_event_provenance(
    monkeypatch: pytest.MonkeyPatch, fixtures_dir: Path
) -> None:
    events = _parse_synthetic(monkeypatch, [_fixture(fixtures_dir, "dfu_connect.xml")])

    assert len(events) == 1
    event = events[0]
    assert event.event_type == EventType.USB_INSERT.value
    assert event.device is not None
    assert event.device.device_id == r"USB\VID_1234&PID_5678\SERIAL001"
    assert event.timestamp_utc == datetime(2021, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert event.raw_timestamp == "2021-01-01T12:00:00.0000000Z"
    assert event.source_artifact == "evidence/logs/System.evtx"
    assert event.parser_name == PARSER_NAME
    assert event.parser_version == PARSER_VERSION
    assert event.details == {
        "provider": "Microsoft-Windows-DriverFrameworks-UserMode",
        "event_id": "2003",
        "record_id": "42",
        "channel": "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    }


@pytest.mark.unit
@pytest.mark.parametrize(
    ("fixture_name", "expected_type"),
    [
        ("dfu_remove_pending.xml", DEVICE_REMOVE_PENDING),
        ("dfu_disconnect.xml", EventType.USB_REMOVE.value),
        ("kernel_pnp_install.xml", DEVICE_INSTALL),
    ],
)
def test_parse_documented_device_lifecycle_events(
    monkeypatch: pytest.MonkeyPatch,
    fixtures_dir: Path,
    fixture_name: str,
    expected_type: str,
) -> None:
    events = _parse_synthetic(monkeypatch, [_fixture(fixtures_dir, fixture_name)])

    assert len(events) == 1
    assert events[0].event_type == expected_type
    assert events[0].device is not None


@pytest.mark.unit
def test_parse_security_file_object_access(
    monkeypatch: pytest.MonkeyPatch, fixtures_dir: Path
) -> None:
    events = _parse_synthetic(monkeypatch, [_fixture(fixtures_dir, "security_file_access.xml")])

    assert len(events) == 1
    event = events[0]
    assert event.event_type == EventType.FILE_ACCESS.value
    assert event.file_path == r"E:\secret.txt"
    assert event.details["AccessMask"] == "0x1"
    assert event.details["ProcessName"] == r"C:\Windows\explorer.exe"


@pytest.mark.unit
def test_security_non_file_object_is_not_misclassified(
    monkeypatch: pytest.MonkeyPatch, fixtures_dir: Path
) -> None:
    events = _parse_synthetic(monkeypatch, [_fixture(fixtures_dir, "security_registry_access.xml")])

    assert events == []


@pytest.mark.unit
def test_unsupported_well_formed_event_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    event = """<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
    <System><Provider Name=\"Example\"/><EventID>1</EventID>
    <TimeCreated SystemTime=\"2021-01-01T12:00:00Z\"/></System></Event>"""

    assert _parse_synthetic(monkeypatch, [event]) == []


@pytest.mark.unit
def test_malformed_xml_raises_explicit_error(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(EvtxParseError, match="Malformed XML"):
        _parse_synthetic(monkeypatch, ["<Event><System>unclosed tag"])


@pytest.mark.unit
def test_relevant_event_missing_timestamp_raises_error(monkeypatch: pytest.MonkeyPatch) -> None:
    event = """<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
    <System><Provider Name=\"Microsoft-Windows-DriverFrameworks-UserMode\"/>
    <EventID>2003</EventID></System><EventData>
    <Data Name=\"DeviceInstanceId\">USB\\VID_1234</Data></EventData></Event>"""

    with pytest.raises(EvtxParseError, match="Missing SystemTime"):
        _parse_synthetic(monkeypatch, [event])


@pytest.mark.unit
def test_relevant_event_missing_device_identity_raises_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = """<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
    <System><Provider Name=\"Microsoft-Windows-DriverFrameworks-UserMode\"/>
    <EventID>2003</EventID><TimeCreated SystemTime=\"2021-01-01T12:00:00Z\"/>
    </System><EventData/></Event>"""

    with pytest.raises(EvtxParseError, match="Missing device instance ID"):
        _parse_synthetic(monkeypatch, [event])


@pytest.mark.unit
def test_security_4663_without_object_type_raises_error(monkeypatch: pytest.MonkeyPatch) -> None:
    event = """<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
    <System><Provider Name=\"Microsoft-Windows-Security-Auditing\"/><EventID>4663</EventID>
    <TimeCreated SystemTime=\"2021-01-01T12:00:00Z\"/></System>
    <EventData><Data Name=\"ObjectName\">C:\\secret.txt</Data></EventData></Event>"""

    with pytest.raises(EvtxParseError, match="Missing ObjectType"):
        _parse_synthetic(monkeypatch, [event])

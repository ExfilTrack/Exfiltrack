"""Tests for the centralized event model.

Owner: Thabrew
"""

from datetime import datetime, timedelta, timezone

import pytest

import exfiltrack.correlation.models as compat_models
from exfiltrack.normalization.event_model import (
    EventType,
    NormalizedEvent,
    UsbDevice,
    merge_streams,
    sort_events,
)


def test_compatibility_identity():
    assert compat_models.NormalizedEvent is NormalizedEvent
    assert compat_models.UsbDevice is UsbDevice
    assert compat_models.EventType is EventType


def test_normalized_event_validation_success():
    device = UsbDevice(device_id="dev1")
    event = NormalizedEvent(
        event_type=EventType.USB_INSERT.value,
        timestamp_utc=datetime(2023, 1, 1, tzinfo=timezone.utc),
        raw_timestamp="123",
        source_artifact="file.evtx",
        parser_name="p",
        parser_version="1",
        device=device,
    )
    assert event.event_type == EventType.USB_INSERT.value


def test_normalized_event_rejects_naive_datetime():
    with pytest.raises(ValueError, match="timezone-aware"):
        NormalizedEvent(
            event_type=EventType.USB_INSERT.value,
            timestamp_utc=datetime(2023, 1, 1),
            raw_timestamp="123",
            source_artifact="file.evtx",
            parser_name="p",
            parser_version="1",
            device=UsbDevice(device_id="dev1"),
        )


def test_normalized_event_rejects_non_utc():
    # Offset aware, but not UTC
    tz = timezone(timedelta(hours=5))
    with pytest.raises(ValueError, match="strictly UTC"):
        NormalizedEvent(
            event_type=EventType.USB_INSERT.value,
            timestamp_utc=datetime(2023, 1, 1, tzinfo=tz),
            raw_timestamp="123",
            source_artifact="file.evtx",
            parser_name="p",
            parser_version="1",
            device=UsbDevice(device_id="dev1"),
        )


def test_normalized_event_missing_provenance():
    with pytest.raises(ValueError, match="no provenance"):
        NormalizedEvent(
            event_type=EventType.USB_INSERT.value,
            timestamp_utc=datetime(2023, 1, 1, tzinfo=timezone.utc),
            raw_timestamp="123",
            source_artifact="",
            parser_name="p",
            parser_version="1",
            device=UsbDevice(device_id="dev1"),
        )

    with pytest.raises(ValueError, match="raw_timestamp"):
        NormalizedEvent(
            event_type=EventType.USB_INSERT.value,
            timestamp_utc=datetime(2023, 1, 1, tzinfo=timezone.utc),
            raw_timestamp=" ",
            source_artifact="file.evtx",
            parser_name="p",
            parser_version="1",
            device=UsbDevice(device_id="dev1"),
        )

    with pytest.raises(ValueError, match="no provenance"):
        NormalizedEvent(
            event_type=EventType.USB_INSERT.value,
            timestamp_utc=datetime(2023, 1, 1, tzinfo=timezone.utc),
            raw_timestamp="123",
            source_artifact="file.evtx",
            parser_name="p",
            parser_version="",
            device=UsbDevice(device_id="dev1"),
        )


def test_normalized_event_retains_existing_contract_guards():
    timestamp = datetime(2023, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="must carry a device"):
        NormalizedEvent(
            event_type=EventType.USB_INSERT.value,
            timestamp_utc=timestamp,
            raw_timestamp="1",
            source_artifact="source",
            parser_name="parser",
            parser_version="1",
        )
    with pytest.raises(ValueError, match="must carry a file_path"):
        NormalizedEvent(
            event_type=EventType.FILE_ACCESS.value,
            timestamp_utc=timestamp,
            raw_timestamp="1",
            source_artifact="source",
            parser_name="parser",
            parser_version="1",
        )
    with pytest.raises(ValueError, match="device_id"):
        UsbDevice(device_id=" ")


def test_usb_device_display_name_prefers_human_friendly_values():
    assert UsbDevice(device_id="device").display_name == "device"
    assert UsbDevice(device_id="device", product="USB Drive").display_name == "USB Drive"
    assert (
        UsbDevice(
            device_id="device", product="USB Drive", friendly_name="Evidence Disk"
        ).display_name
        == "Evidence Disk"
    )


def test_normalized_event_rejects_non_datetime_timestamp():
    with pytest.raises(ValueError, match="must be a datetime"):
        NormalizedEvent(
            event_type=EventType.USB_INSERT.value,
            timestamp_utc="2023-01-01T00:00:00Z",  # type: ignore[arg-type]
            raw_timestamp="1",
            source_artifact="source",
            parser_name="parser",
            parser_version="1",
            device=UsbDevice("device"),
        )
    with pytest.raises(ValueError, match="no provenance"):
        NormalizedEvent(
            event_type=EventType.USB_INSERT.value,
            timestamp_utc=datetime(2023, 1, 1, tzinfo=timezone.utc),
            raw_timestamp="123",
            source_artifact="file.evtx",
            parser_name="",
            parser_version="1",
            device=UsbDevice(device_id="dev1"),
        )


def _make_event(
    timestamp_utc,
    event_type,
    source_artifact,
    file_path=None,
    device=None,
    raw_timestamp="123",
):
    return NormalizedEvent(
        event_type=event_type,
        timestamp_utc=timestamp_utc,
        raw_timestamp=raw_timestamp,
        source_artifact=source_artifact,
        parser_name="p",
        parser_version="1",
        device=device,
        file_path=file_path,
    )


def test_sort_events():
    t1 = datetime(2023, 1, 1, tzinfo=timezone.utc)
    t2 = datetime(2023, 1, 2, tzinfo=timezone.utc)

    e1 = _make_event(t2, EventType.USB_INSERT.value, "a", device=UsbDevice("1"))
    e2 = _make_event(t1, EventType.USB_INSERT.value, "b", device=UsbDevice("1"))
    e3 = _make_event(t1, EventType.FILE_ACCESS.value, "a", file_path="f")

    # Expected sort order: e3 (t1, file_access), e2 (t1, usb_insert), e1 (t2)
    sorted_evs = sort_events([e1, e2, e3])
    assert sorted_evs == [e3, e2, e1]


def test_sort_events_uses_the_documented_tie_breakers():
    timestamp = datetime(2023, 1, 1, tzinfo=timezone.utc)
    first = _make_event(
        timestamp,
        "custom",
        "source",
        file_path="a.txt",
        device=UsbDevice("z"),
        raw_timestamp="z",
    )
    second = _make_event(
        timestamp,
        "custom",
        "source",
        file_path="b.txt",
        device=UsbDevice("a"),
        raw_timestamp="a",
    )
    assert sort_events([second, first]) == [first, second]


def test_sort_events_uses_parser_metadata_then_raw_timestamp():
    timestamp = datetime(2023, 1, 1, tzinfo=timezone.utc)
    later_parser = NormalizedEvent(
        event_type="custom",
        timestamp_utc=timestamp,
        raw_timestamp="z",
        source_artifact="source",
        parser_name="z_parser",
        parser_version="2",
    )
    earlier_parser = NormalizedEvent(
        event_type="custom",
        timestamp_utc=timestamp,
        raw_timestamp="a",
        source_artifact="source",
        parser_name="a_parser",
        parser_version="9",
    )
    assert sort_events([later_parser, earlier_parser]) == [earlier_parser, later_parser]


def test_sort_events_preserves_exact_key_input_order():
    timestamp = datetime(2023, 1, 1, tzinfo=timezone.utc)
    first = NormalizedEvent("custom", timestamp, "1", "source", "parser", "1")
    second = NormalizedEvent("custom", timestamp, "1", "source", "parser", "1")
    first.details["id"] = "first"
    second.details["id"] = "second"
    assert sort_events([second, first]) == [second, first]


def test_merge_streams():
    t1 = datetime(2023, 1, 1, tzinfo=timezone.utc)
    t2 = datetime(2023, 1, 2, tzinfo=timezone.utc)

    stream1 = [
        _make_event(t1, EventType.USB_INSERT.value, "a", device=UsbDevice("1")),
        _make_event(t2, EventType.USB_INSERT.value, "a", device=UsbDevice("2")),
    ]

    stream2 = [
        _make_event(t1, EventType.FILE_ACCESS.value, "b", file_path="f"),
    ]

    merged = list(merge_streams(stream1, stream2))
    assert merged[0].event_type == EventType.FILE_ACCESS.value
    assert merged[1].event_type == EventType.USB_INSERT.value
    assert merged[2].device.device_id == "2"


def test_merge_streams_stability():
    t1 = datetime(2023, 1, 1, tzinfo=timezone.utc)
    e1 = NormalizedEvent(
        event_type="custom",
        timestamp_utc=t1,
        raw_timestamp="1",
        source_artifact="a",
        parser_name="p",
        parser_version="1",
    )
    e2 = NormalizedEvent(
        event_type="custom",
        timestamp_utc=t1,
        raw_timestamp="1",
        source_artifact="a",
        parser_name="p",
        parser_version="1",
    )
    e1.details["id"] = 1
    e2.details["id"] = 2

    stream1 = [e1]
    stream2 = [e2]

    merged = list(merge_streams(stream1, stream2))
    assert merged[0].details["id"] == 1
    assert merged[1].details["id"] == 2

    merged2 = list(merge_streams(stream2, stream1))
    assert merged2[0].details["id"] == 2
    assert merged2[1].details["id"] == 1


def test_merge_streams_laziness():
    t1 = datetime(2023, 1, 1, tzinfo=timezone.utc)

    def lazy_stream():
        yield _make_event(t1, EventType.USB_INSERT.value, "a", device=UsbDevice("1"))
        raise RuntimeError("Stream was over-consumed")

    merged = merge_streams(lazy_stream())
    # Grab the first element without fully consuming
    item = next(merged)
    assert item.device.device_id == "1"


def test_normalized_event_preserves_raw_timestamp():
    raw = "116444736000000009"
    event = _make_event(
        datetime(1970, 1, 1, tzinfo=timezone.utc),
        EventType.USB_INSERT.value,
        "a",
        device=UsbDevice("1"),
        raw_timestamp=raw,
    )
    assert event.raw_timestamp == raw

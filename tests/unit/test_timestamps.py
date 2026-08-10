"""Tests for timestamp normalization.

Owner: Thabrew
"""

from datetime import datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo

import pytest

from exfiltrack.normalization.timestamps import parse_dos_datetime, parse_filetime, parse_iso8601


class DummyTz(tzinfo):
    def utcoffset(self, dt):
        return timedelta(hours=-5)

    def dst(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "EST"


def test_parse_filetime_valid():
    # 1601-01-01T00:00:00Z
    assert parse_filetime(0) == datetime(1601, 1, 1, tzinfo=timezone.utc)
    # 1970-01-01T00:00:00Z -> 11644473600 seconds -> 116444736000000000 intervals
    assert parse_filetime(116444736000000000) == datetime(1970, 1, 1, tzinfo=timezone.utc)
    # Sub-microsecond (1 interval = 100 ns, 9 intervals = 900 ns). Truncated.
    assert parse_filetime(9) == datetime(1601, 1, 1, tzinfo=timezone.utc)
    assert parse_filetime(10) == datetime(1601, 1, 1, 0, 0, 0, 1, tzinfo=timezone.utc)


def test_parse_filetime_invalid():
    with pytest.raises(ValueError):
        parse_filetime(-1)
    with pytest.raises(ValueError):
        parse_filetime(True)  # type: ignore
    with pytest.raises(ValueError):
        parse_filetime("123")  # type: ignore
    with pytest.raises(ValueError, match="overflow"):
        parse_filetime(10**20)  # beyond Python datetime range


def test_parse_dos_datetime_valid():
    # March 8, 2020 01:30:00
    # Date: 2020 -> offset 40 (0x28). Month 3. Day 8.
    # 0x28 << 9 | 3 << 5 | 8 = 0x5000 | 0x60 | 0x8 = 0x5068
    dos_date = 0x5068
    # Time: 1 hour, 30 min, 0 sec -> 1 << 11 | 30 << 5 | 0 = 0x0800 | 0x03C0 | 0 = 0x0BC0
    dos_time = 0x0BC0

    dt = parse_dos_datetime(dos_date, dos_time, DummyTz())
    # Should be 01:30 EST -> 06:30 UTC
    assert dt == datetime(2020, 3, 8, 6, 30, tzinfo=timezone.utc)


def test_parse_dos_datetime_invalid():
    with pytest.raises(ValueError):
        parse_dos_datetime(0, 0, DummyTz())  # Zero date is invalid
    with pytest.raises(ValueError):
        parse_dos_datetime(True, 0x0BC0, DummyTz())  # type: ignore
    with pytest.raises(ValueError):
        parse_dos_datetime(0x5068, 0x0BC0, None)  # type: ignore
    with pytest.raises(ValueError):
        parse_dos_datetime(0x10021, 0, DummyTz())
    with pytest.raises(ValueError):
        parse_dos_datetime(0x0021, 0x10000, DummyTz())
    with pytest.raises(ValueError):
        parse_dos_datetime(0x0021, 0, "UTC")  # type: ignore
    with pytest.raises(ValueError):
        parse_dos_datetime((40 << 9) | (13 << 5) | 1, 0, DummyTz())
    with pytest.raises(ValueError):
        parse_dos_datetime((40 << 9) | (1 << 5), 0, DummyTz())
    with pytest.raises(ValueError):
        parse_dos_datetime(0x0021, (24 << 11), DummyTz())
    with pytest.raises(ValueError):
        parse_dos_datetime(0x0021, (60 << 5), DummyTz())


def test_parse_dos_datetime_dst_overlap():
    # Nov 1, 2020 01:30:00 (America/New_York)
    dos_date = (40 << 9) | (11 << 5) | 1
    dos_time = (1 << 11) | (30 << 5) | 0

    # Due to fold=0 default, it picks the first occurrence (-4 offset EDT).
    # 01:30 UTC-4 -> 05:30 UTC.
    dt = parse_dos_datetime(dos_date, dos_time, ZoneInfo("America/New_York"))
    assert dt == datetime(2020, 11, 1, 5, 30, tzinfo=timezone.utc)


def test_parse_dos_datetime_dst_gap():
    # March 8, 2020 02:30:00 (nonexistent local time in America/New_York)
    dos_date = (40 << 9) | (3 << 5) | 8
    dos_time = (2 << 11) | (30 << 5) | 0

    with pytest.raises(ValueError, match="Nonexistent"):
        parse_dos_datetime(dos_date, dos_time, ZoneInfo("America/New_York"))


def test_parse_iso8601_valid():
    dt = parse_iso8601("2023-01-01T12:00:00Z")
    assert dt == datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    # High precision
    dt2 = parse_iso8601("2023-01-01T12:00:00.1234567Z")
    assert dt2 == datetime(2023, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)
    assert parse_iso8601(" 2023-01-01T12:00:00Z ") == datetime(
        2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc
    )


def test_parse_iso8601_invalid():
    with pytest.raises(ValueError):
        parse_iso8601("2023-01-01T12:00:00")  # Naive
    with pytest.raises(ValueError):
        parse_iso8601(True)  # type: ignore
    with pytest.raises(ValueError):
        parse_iso8601(1)  # type: ignore
    with pytest.raises(ValueError):
        parse_iso8601("")


def test_parse_iso8601_offset_conversion():
    # 2023-01-01T14:00:00+02:00 -> 2023-01-01T12:00:00Z
    dt = parse_iso8601("2023-01-01T14:00:00+02:00")
    assert dt == datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

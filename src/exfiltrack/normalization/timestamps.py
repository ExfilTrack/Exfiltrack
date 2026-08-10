"""Timestamp conversion functions for Windows forensic artifacts."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_ISO_FRACTION = re.compile(r"(?P<prefix>.+\.)(?P<fraction>\d+)(?P<offset>[+-]\d{2}:\d{2})$")


def parse_filetime(filetime: int) -> datetime:
    """Convert Windows FILETIME ticks to a timezone-aware UTC datetime."""
    if isinstance(filetime, bool) or not isinstance(filetime, int):
        raise ValueError(f"FILETIME must be an integer, got {type(filetime).__name__}.")
    if filetime < 0:
        raise ValueError(f"FILETIME cannot be negative, got {filetime}.")
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
    except OverflowError as exc:
        raise ValueError(f"FILETIME overflow: {filetime}") from exc


def parse_dos_datetime(dos_date: int, dos_time: int, source_tz: tzinfo) -> datetime:
    """Parse a packed DOS local timestamp and convert it to UTC.

    Ambiguous DST-overlap values use ``fold=0``. Nonexistent local times, such
    as values inside a DST spring-forward gap, raise :class:`ValueError`.
    """
    if isinstance(dos_date, bool) or not isinstance(dos_date, int):
        raise ValueError("DOS date must be an integer.")
    if isinstance(dos_time, bool) or not isinstance(dos_time, int):
        raise ValueError("DOS time must be an integer.")
    if not isinstance(source_tz, tzinfo):
        raise ValueError("source_tz must be a tzinfo object.")
    if not 0 < dos_date <= 0xFFFF or not 0 <= dos_time <= 0xFFFF:
        raise ValueError(f"DOS date/time is outside the 16-bit range: {dos_date}, {dos_time}.")

    day = dos_date & 0x1F
    month = (dos_date >> 5) & 0x0F
    year = 1980 + ((dos_date >> 9) & 0x7F)
    second = (dos_time & 0x1F) * 2
    minute = (dos_time >> 5) & 0x3F
    hour = (dos_time >> 11) & 0x1F
    try:
        local_naive = datetime(year, month, day, hour, minute, second, fold=0)
    except ValueError as exc:
        raise ValueError(f"Malformed DOS date/time fields: {exc}") from exc

    try:
        local_aware = local_naive.replace(tzinfo=source_tz, fold=0)
        utc_value = local_aware.astimezone(timezone.utc)
        round_trip = utc_value.astimezone(source_tz).replace(tzinfo=None)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError(f"Could not apply source timezone: {exc}") from exc
    if round_trip != local_naive:
        raise ValueError("Nonexistent local time in source timezone.")
    return utc_value


def parse_iso8601(timestamp_str: str) -> datetime:
    """Parse an offset-bearing ISO-8601 timestamp and normalize it to UTC."""
    if not isinstance(timestamp_str, str):
        raise ValueError("ISO-8601 timestamp must be a string.")
    timestamp = timestamp_str.strip()
    if timestamp.endswith("Z"):
        timestamp = f"{timestamp[:-1]}+00:00"
    fractional_match = _ISO_FRACTION.fullmatch(timestamp)
    if fractional_match and len(fractional_match["fraction"]) > 6:
        timestamp = (
            f"{fractional_match['prefix']}{fractional_match['fraction'][:6]}"
            f"{fractional_match['offset']}"
        )
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ValueError(f"Malformed ISO-8601 timestamp: {timestamp_str}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"ISO-8601 timestamp has no UTC offset: {timestamp_str}")
    return parsed.astimezone(timezone.utc)

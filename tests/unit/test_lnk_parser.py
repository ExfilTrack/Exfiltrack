"""Unit tests for defensive parsing of synthetic Windows shortcut files."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from exfiltrack.parsers.lnk_parser import (
    PARSER_NAME,
    PARSER_VERSION,
    LnkParseError,
    parse_lnk,
)

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime(value: datetime) -> int:
    return int((value - _FILETIME_EPOCH).total_seconds() * 10_000_000)


def _synthetic_lnk() -> bytes:
    """Build a small valid LNK with a removable-volume LinkInfo section."""
    creation = _filetime(datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    access = _filetime(datetime(2024, 1, 2, 4, 5, 6, tzinfo=timezone.utc))
    modification = _filetime(datetime(2024, 1, 2, 5, 6, 7, tzinfo=timezone.utc))
    header = bytearray(0x4C)
    header[0:4] = (0x4C).to_bytes(4, "little")
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    header[0x14:0x18] = (0x00000002).to_bytes(4, "little")  # HasLinkInfo
    header[0x18:0x1C] = (0x00000021).to_bytes(4, "little")  # read-only + archive
    header[0x1C:0x24] = creation.to_bytes(8, "little")
    header[0x24:0x2C] = access.to_bytes(8, "little")
    header[0x2C:0x34] = modification.to_bytes(8, "little")
    header[0x34:0x38] = (123_456).to_bytes(4, "little")

    volume = bytearray(16)
    volume[0:4] = (16).to_bytes(4, "little")
    volume[4:8] = (2).to_bytes(4, "little")  # DRIVE_REMOVABLE
    volume[8:12] = (0xA1B2C3D4).to_bytes(4, "little")
    volume[12:16] = (16).to_bytes(4, "little")
    base = b"E:\\Evidence\\" + b"\x00"
    suffix = b"plans.txt\x00"
    link_info_size = 0x1C + len(volume) + len(base) + len(suffix)
    link_info = bytearray(link_info_size)
    link_info[0:4] = link_info_size.to_bytes(4, "little")
    link_info[4:8] = (0x1C).to_bytes(4, "little")
    link_info[8:12] = (1).to_bytes(4, "little")
    link_info[12:16] = (0x1C).to_bytes(4, "little")
    link_info[16:20] = (0x1C + len(volume)).to_bytes(4, "little")
    link_info[24:28] = (0x1C + len(volume) + len(base)).to_bytes(4, "little")
    link_info[0x1C : 0x1C + len(volume)] = volume
    base_offset = 0x1C + len(volume)
    link_info[base_offset : base_offset + len(base)] = base
    suffix_offset = base_offset + len(base)
    link_info[suffix_offset : suffix_offset + len(suffix)] = suffix
    return bytes(header + link_info)


@pytest.mark.unit
def test_parse_synthetic_lnk_emits_normalized_timestamped_events(tmp_path: Path) -> None:
    shortcut = tmp_path / "Recent.lnk"
    shortcut.write_bytes(_synthetic_lnk())

    events = list(parse_lnk(shortcut))

    assert [event.event_type for event in events] == [
        "file_created",
        "file_access",
        "file_modified",
    ]
    access_event = events[1]
    assert access_event.timestamp_utc == datetime(2024, 1, 2, 4, 5, 6, tzinfo=timezone.utc)
    assert access_event.raw_timestamp == "133486419060000000"
    assert access_event.file_path == r"E:\Evidence\plans.txt"
    assert access_event.file_size_bytes == 123_456
    assert access_event.source_artifact == shortcut.as_posix()
    assert access_event.parser_name == PARSER_NAME
    assert access_event.parser_version == PARSER_VERSION
    assert access_event.details == {
        "timestamp_kind": "access",
        "target_file_attributes": ["read_only", "archive"],
        "target_file_attributes_raw": 0x21,
        "volume_serial_number": "A1B2C3D4",
        "drive_type": "removable",
        "drive_type_code": 2,
    }


@pytest.mark.unit
def test_parse_lnk_never_resolves_the_extracted_target_path(tmp_path: Path) -> None:
    shortcut = tmp_path / "Recent.lnk"
    shortcut.write_bytes(_synthetic_lnk())

    events = list(parse_lnk(shortcut))

    assert all(event.file_path == r"E:\Evidence\plans.txt" for event in events)
    assert not (tmp_path / "E:" / "Evidence" / "plans.txt").exists()


@pytest.mark.unit
def test_truncated_lnk_raises_explicit_error(tmp_path: Path) -> None:
    shortcut = tmp_path / "truncated.lnk"
    shortcut.write_bytes(_synthetic_lnk()[:80])

    with pytest.raises(LnkParseError, match="Truncated LNK|Invalid or truncated"):
        list(parse_lnk(shortcut))

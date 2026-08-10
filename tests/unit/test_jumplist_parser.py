"""Unit tests for the Jump List parser."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from exfiltrack.correlation.models import NormalizedEvent
from exfiltrack.parsers.jumplist_parser import (
    PARSER_NAME,
    PARSER_VERSION,
    JumpListParseError,
    parse_jumplist,
)
from exfiltrack.parsers.lnk_parser import LnkParseError, _ShortcutMetadata


@pytest.fixture
def mock_metadata() -> _ShortcutMetadata:
    return _ShortcutMetadata(
        target_path="C:\\Users\\LOQ\\Documents\\test.txt",
        file_size_bytes=1024,
        file_attributes=0,
        creation_time=132800000000000000,
        access_time=132800000000000000,
        modification_time=132800000000000000,
        volume_serial_number=12345678,
        drive_type=3,
    )


@patch("exfiltrack.parsers.jumplist_parser._parse_shortcut")
@patch("exfiltrack.parsers.jumplist_parser.olefile.isOleFile")
@patch("exfiltrack.parsers.jumplist_parser.olefile.OleFileIO")
def test_parse_automatic_destinations(
    mock_ole_io: MagicMock,
    mock_is_ole: MagicMock,
    mock_parse_shortcut: MagicMock,
    mock_metadata: _ShortcutMetadata,
    tmp_path: Path,
) -> None:
    # Setup
    mock_is_ole.return_value = True
    mock_ole = MagicMock()
    mock_ole.listdir.return_value = [["DestList"], ["1"], ["2"]]
    mock_stream = MagicMock()
    mock_stream.read.return_value = b"dummy_lnk_data"
    mock_ole.openstream.return_value.__enter__.return_value = mock_stream
    mock_ole_io.return_value.__enter__.return_value = mock_ole

    mock_parse_shortcut.return_value = mock_metadata

    file_path = tmp_path / "1b4dd67f29cb1962.automaticDestinations-ms"
    file_path.write_bytes(b"dummy ole content")

    # Execute
    events: list[NormalizedEvent] = list(parse_jumplist(file_path))

    # Assert
    assert mock_parse_shortcut.call_count == 2
    assert len(events) == 6  # 2 valid LNKs * 3 timestamps each

    event = events[0]
    assert event.parser_name == PARSER_NAME
    assert event.parser_version == PARSER_VERSION
    assert event.source_artifact == file_path.as_posix()
    assert event.file_path == "C:\\Users\\LOQ\\Documents\\test.txt"
    assert event.details["app_id"] == "1b4dd67f29cb1962"
    assert event.details["application"] == "Windows Explorer"
    assert event.details["stream_name"] == "1"


def test_invalid_filename(tmp_path: Path) -> None:
    file_path = tmp_path / "invalid_name.txt"
    with pytest.raises(JumpListParseError, match="Invalid Jump List filename"):
        list(parse_jumplist(file_path))


@patch("exfiltrack.parsers.jumplist_parser._parse_shortcut")
def test_parse_custom_destinations(
    mock_parse_shortcut: MagicMock,
    mock_metadata: _ShortcutMetadata,
    tmp_path: Path,
) -> None:
    # Setup
    mock_parse_shortcut.return_value = mock_metadata

    # Create dummy custom destinations with 2 valid signatures and 1 junk
    signature = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    content = signature + b"data1" + b"junk_between" + signature + b"data2"

    file_path = tmp_path / "918e0ecb43d17e23.customDestinations-ms"
    file_path.write_bytes(content)

    # Execute
    events: list[NormalizedEvent] = list(parse_jumplist(file_path))

    # Assert
    assert mock_parse_shortcut.call_count == 2
    assert len(events) == 6

    event = events[0]
    assert event.details["app_id"] == "918e0ecb43d17e23"
    assert event.details["application"] == "Notepad"
    assert "stream_name" not in event.details


@patch("exfiltrack.parsers.jumplist_parser._parse_shortcut")
def test_custom_destinations_skip_corrupt(
    mock_parse_shortcut: MagicMock,
    mock_metadata: _ShortcutMetadata,
    tmp_path: Path,
) -> None:
    # Setup
    # First call fails, second succeeds
    mock_parse_shortcut.side_effect = [LnkParseError("Corrupt"), mock_metadata]

    signature = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    content = signature + b"corrupt" + signature + b"valid"

    file_path = tmp_path / "0000000000000000.customDestinations-ms"
    file_path.write_bytes(content)

    # Execute
    events: list[NormalizedEvent] = list(parse_jumplist(file_path))

    # Assert
    assert mock_parse_shortcut.call_count == 2
    assert len(events) == 3

    event = events[0]
    assert event.details["app_id"] == "0000000000000000"
    assert event.details["application"] == "unknown (0000000000000000)"


def test_invalid_custom_destinations(tmp_path: Path) -> None:
    file_path = tmp_path / "1b4dd67f29cb1962.customDestinations-ms"
    file_path.write_bytes(b"no valid signatures here")

    with pytest.raises(JumpListParseError, match="No valid LNK entries found"):
        list(parse_jumplist(file_path))


@patch("exfiltrack.parsers.jumplist_parser.olefile.isOleFile")
def test_invalid_automatic_destinations(mock_is_ole: MagicMock, tmp_path: Path) -> None:
    mock_is_ole.return_value = False
    file_path = tmp_path / "1b4dd67f29cb1962.automaticDestinations-ms"
    file_path.write_bytes(b"not an ole file")

    with pytest.raises(JumpListParseError, match="not a valid OLE Compound File"):
        list(parse_jumplist(file_path))

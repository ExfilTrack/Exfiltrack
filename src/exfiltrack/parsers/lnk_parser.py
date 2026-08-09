"""Read-only, defensive parser for Windows shortcut (``.lnk``) evidence.

The parser consumes only the Shell Link header, LinkInfo, and StringData
structures needed for target-path and volume attribution.  It never opens,
stats, resolves, or otherwise consults the extracted target path: it is
artifact data, not a path on the examiner's live filesystem.

Shortcut timestamps describe properties recorded in the shortcut.  In
particular, an access timestamp is evidence of access, *not* evidence that
the target was copied.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from exfiltrack.config import ExfilTrackError
from exfiltrack.correlation.models import NormalizedEvent


class LnkParseError(ExfilTrackError):
    """Raised when a shortcut is truncated or violates the Shell Link layout."""


PARSER_NAME = "lnk_parser"
PARSER_VERSION = "1.0.0"

_HEADER_SIZE = 0x4C
_HEADER_CLSID = bytes.fromhex("0114020000000000c000000000000046")
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_LINK_FLAG_HAS_ID_LIST = 0x00000001
_LINK_FLAG_HAS_LINK_INFO = 0x00000002
_LINK_FLAG_HAS_NAME = 0x00000004
_LINK_FLAG_HAS_RELATIVE_PATH = 0x00000008
_LINK_FLAG_HAS_WORKING_DIR = 0x00000010
_LINK_FLAG_HAS_ARGUMENTS = 0x00000020
_LINK_FLAG_HAS_ICON_LOCATION = 0x00000040
_LINK_FLAG_IS_UNICODE = 0x00000080
_LINK_INFO_VOLUME_ID_AND_LOCAL_BASE_PATH = 0x00000001
_WINDOWS_PATH_SEPARATOR = "\\"

_ATTRIBUTE_NAMES = {
    0x00000001: "read_only",
    0x00000002: "hidden",
    0x00000004: "system",
    0x00000010: "directory",
    0x00000020: "archive",
    0x00000040: "device",
    0x00000080: "normal",
    0x00000100: "temporary",
    0x00000200: "sparse_file",
    0x00000400: "reparse_point",
    0x00000800: "compressed",
    0x00001000: "offline",
    0x00002000: "not_content_indexed",
    0x00004000: "encrypted",
}
_DRIVE_TYPES = {
    0: "unknown",
    1: "no_root_directory",
    2: "removable",
    3: "fixed",
    4: "remote",
    5: "cdrom",
    6: "ramdisk",
}


class _Reader:
    """Small bounds-checking view over untrusted binary input."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    @property
    def size(self) -> int:
        return len(self._data)

    def require(self, offset: int, length: int, field: str) -> None:
        if offset < 0 or length < 0 or offset > self.size or length > self.size - offset:
            raise LnkParseError(
                f"Truncated LNK while reading {field} at offset {offset} (file size {self.size})"
            )

    def bytes(self, offset: int, length: int, field: str) -> bytes:
        self.require(offset, length, field)
        return self._data[offset : offset + length]

    def u16(self, offset: int, field: str) -> int:
        return int.from_bytes(self.bytes(offset, 2, field), "little")

    def u32(self, offset: int, field: str) -> int:
        return int.from_bytes(self.bytes(offset, 4, field), "little")

    def u64(self, offset: int, field: str) -> int:
        return int.from_bytes(self.bytes(offset, 8, field), "little")


@dataclass(frozen=True)
class _ShortcutMetadata:
    target_path: str
    file_size_bytes: int
    file_attributes: int
    creation_time: int
    access_time: int
    modification_time: int
    volume_serial_number: int | None
    drive_type: int | None


def parse_lnk(file_path: Path | str) -> Iterator[NormalizedEvent]:
    """Yield timestamped file-activity events recorded in one shortcut.

    The source shortcut is opened in binary read-only mode.  One event is
    emitted for each non-zero creation, access, or modification FILETIME.  A
    ``file_access`` event represents the shortcut's access timestamp; the
    ``file_created`` and ``file_modified`` labels preserve the other two
    metadata timestamps without conflating them with access activity.

    Raises:
        LnkParseError: The shortcut cannot be read, is truncated, malformed,
            or has no target path represented by the supported structures.
    """
    source = Path(file_path)
    source_artifact = source.as_posix()
    try:
        with source.open("rb") as evidence_file:
            data = evidence_file.read()
    except OSError as exc:
        raise LnkParseError(f"Could not read LNK file '{source_artifact}': {exc}") from exc

    metadata = _parse_shortcut(data)
    timestamps = (
        ("file_created", "creation", metadata.creation_time),
        ("file_access", "access", metadata.access_time),
        ("file_modified", "modification", metadata.modification_time),
    )
    emitted = False
    for event_type, timestamp_kind, raw_filetime in timestamps:
        if raw_filetime == 0:
            continue
        emitted = True
        yield NormalizedEvent(
            event_type=event_type,
            timestamp_utc=_filetime_to_utc(raw_filetime, timestamp_kind),
            raw_timestamp=str(raw_filetime),
            source_artifact=source_artifact,
            parser_name=PARSER_NAME,
            parser_version=PARSER_VERSION,
            file_path=metadata.target_path,
            file_size_bytes=metadata.file_size_bytes,
            details=_details(metadata, timestamp_kind),
        )
    if not emitted:
        raise LnkParseError("LNK header contains no creation, access, or modification timestamp")


def _parse_shortcut(data: bytes) -> _ShortcutMetadata:
    reader = _Reader(data)
    reader.require(0, _HEADER_SIZE, "Shell Link Header")
    if reader.u32(0, "Shell Link Header size") != _HEADER_SIZE:
        raise LnkParseError("Invalid Shell Link Header size")
    if reader.bytes(4, 16, "Shell Link CLSID") != _HEADER_CLSID:
        raise LnkParseError("Invalid Shell Link CLSID")

    flags = reader.u32(0x14, "LinkFlags")
    metadata = _ShortcutMetadata(
        target_path="",
        file_size_bytes=reader.u32(0x34, "FileSize"),
        file_attributes=reader.u32(0x18, "FileAttributes"),
        creation_time=reader.u64(0x1C, "CreationTime"),
        access_time=reader.u64(0x24, "AccessTime"),
        modification_time=reader.u64(0x2C, "WriteTime"),
        volume_serial_number=None,
        drive_type=None,
    )

    offset = _HEADER_SIZE
    if flags & _LINK_FLAG_HAS_ID_LIST:
        id_list_size = reader.u16(offset, "LinkTargetIDList size")
        offset += 2
        reader.require(offset, id_list_size, "LinkTargetIDList")
        offset += id_list_size

    target_path = ""
    volume_serial_number: int | None = None
    drive_type: int | None = None
    if flags & _LINK_FLAG_HAS_LINK_INFO:
        target_path, volume_serial_number, drive_type, offset = _parse_link_info(reader, offset)

    strings, _ = _parse_string_data(reader, offset, flags)
    if not target_path:
        target_path = strings.get("relative_path", "")
    if not target_path:
        raise LnkParseError("LNK contains no target path in LinkInfo or RelativePath StringData")

    return _ShortcutMetadata(
        target_path=target_path,
        file_size_bytes=metadata.file_size_bytes,
        file_attributes=metadata.file_attributes,
        creation_time=metadata.creation_time,
        access_time=metadata.access_time,
        modification_time=metadata.modification_time,
        volume_serial_number=volume_serial_number,
        drive_type=drive_type,
    )


def _parse_link_info(reader: _Reader, offset: int) -> tuple[str, int | None, int | None, int]:
    reader.require(offset, 0x1C, "LinkInfo header")
    size = reader.u32(offset, "LinkInfoSize")
    header_size = reader.u32(offset + 4, "LinkInfoHeaderSize")
    if size < 0x1C:
        raise LnkParseError("Invalid LinkInfoSize (smaller than mandatory header)")
    reader.require(offset, size, "LinkInfo")
    if header_size < 0x1C or header_size > size:
        raise LnkParseError("Invalid LinkInfoHeaderSize")

    flags = reader.u32(offset + 8, "LinkInfoFlags")
    volume_offset = reader.u32(offset + 12, "VolumeIDOffset")
    local_base_offset = reader.u32(offset + 16, "LocalBasePathOffset")
    suffix_offset = reader.u32(offset + 24, "CommonPathSuffixOffset")
    local_base_unicode_offset = 0
    suffix_unicode_offset = 0
    if header_size >= 0x24:
        local_base_unicode_offset = reader.u32(offset + 28, "LocalBasePathOffsetUnicode")
        suffix_unicode_offset = reader.u32(offset + 32, "CommonPathSuffixOffsetUnicode")

    target_path = ""
    if local_base_unicode_offset:
        local_base_start = _link_info_offset(
            offset, local_base_unicode_offset, header_size, size, "LocalBasePathOffsetUnicode"
        )
        local_base = _null_terminated_string(
            reader, local_base_start, offset + size, "utf-16-le", "LocalBasePathUnicode"
        )
        suffix = (
            _null_terminated_string(
                reader,
                _link_info_offset(
                    offset,
                    suffix_unicode_offset,
                    header_size,
                    size,
                    "CommonPathSuffixOffsetUnicode",
                ),
                offset + size,
                "utf-16-le",
                "CommonPathSuffixUnicode",
            )
            if suffix_unicode_offset
            else ""
        )
        target_path = _join_target_path(local_base, suffix)
    elif local_base_offset:
        local_base_start = _link_info_offset(
            offset, local_base_offset, header_size, size, "LocalBasePathOffset"
        )
        local_base = _null_terminated_string(
            reader, local_base_start, offset + size, "cp1252", "LocalBasePath"
        )
        suffix = (
            _null_terminated_string(
                reader,
                _link_info_offset(
                    offset, suffix_offset, header_size, size, "CommonPathSuffixOffset"
                ),
                offset + size,
                "cp1252",
                "CommonPathSuffix",
            )
            if suffix_offset
            else ""
        )
        target_path = _join_target_path(local_base, suffix)

    volume_serial_number = None
    drive_type = None
    if flags & _LINK_INFO_VOLUME_ID_AND_LOCAL_BASE_PATH:
        if not volume_offset:
            raise LnkParseError("LinkInfo requires VolumeID but VolumeIDOffset is zero")
        volume_serial_number, drive_type = _parse_volume_id(
            reader,
            _link_info_offset(offset, volume_offset, header_size, size, "VolumeIDOffset"),
            offset + size,
        )

    return target_path, volume_serial_number, drive_type, offset + size


def _link_info_offset(
    link_info_start: int, relative_offset: int, header_size: int, size: int, field: str
) -> int:
    """Validate a LinkInfo-relative offset before converting it to an absolute one."""
    if relative_offset < header_size or relative_offset >= size:
        raise LnkParseError(f"{field} points outside LinkInfo payload")
    return link_info_start + relative_offset


def _parse_volume_id(reader: _Reader, offset: int, limit: int) -> tuple[int, int]:
    reader.require(offset, 16, "VolumeID header")
    size = reader.u32(offset, "VolumeIDSize")
    if size < 16 or offset > limit or size > limit - offset:
        raise LnkParseError("Invalid or truncated VolumeID")
    drive_type = reader.u32(offset + 4, "DriveType")
    serial = reader.u32(offset + 8, "DriveSerialNumber")
    return serial, drive_type


def _parse_string_data(reader: _Reader, offset: int, flags: int) -> tuple[dict[str, str], int]:
    encoding = "utf-16-le" if flags & _LINK_FLAG_IS_UNICODE else "cp1252"
    fields = (
        (_LINK_FLAG_HAS_NAME, "name"),
        (_LINK_FLAG_HAS_RELATIVE_PATH, "relative_path"),
        (_LINK_FLAG_HAS_WORKING_DIR, "working_dir"),
        (_LINK_FLAG_HAS_ARGUMENTS, "arguments"),
        (_LINK_FLAG_HAS_ICON_LOCATION, "icon_location"),
    )
    values: dict[str, str] = {}
    for flag, name in fields:
        if not flags & flag:
            continue
        character_count = reader.u16(offset, f"StringData {name} length")
        offset += 2
        byte_count = character_count * (2 if encoding == "utf-16-le" else 1)
        raw = reader.bytes(offset, byte_count, f"StringData {name}")
        offset += byte_count
        try:
            values[name] = raw.decode(encoding)
        except UnicodeDecodeError as exc:
            raise LnkParseError(f"Invalid {encoding} StringData {name}") from exc
    return values, offset


def _null_terminated_string(
    reader: _Reader, offset: int, limit: int, encoding: str, field: str
) -> str:
    if offset < 0 or offset >= limit:
        raise LnkParseError(f"{field} offset is outside LinkInfo")
    if encoding == "utf-16-le":
        if (limit - offset) % 2:
            raise LnkParseError(f"{field} has an odd-length UTF-16 range")
        end = offset
        while end + 1 < limit:
            if reader.bytes(end, 2, field) == b"\x00\x00":
                try:
                    return reader.bytes(offset, end - offset, field).decode(encoding)
                except UnicodeDecodeError as exc:
                    raise LnkParseError(f"Invalid UTF-16 text in {field}") from exc
            end += 2
    else:
        end = offset
        while end < limit:
            if reader.bytes(end, 1, field) == b"\x00":
                try:
                    return reader.bytes(offset, end - offset, field).decode(encoding)
                except UnicodeDecodeError as exc:
                    raise LnkParseError(f"Invalid text in {field}") from exc
            end += 1
    raise LnkParseError(f"{field} is not null-terminated within LinkInfo")


def _join_target_path(base: str, suffix: str) -> str:
    if not suffix or base.casefold().endswith(suffix.casefold()):
        return base
    return (
        f"{base.rstrip(_WINDOWS_PATH_SEPARATOR)}{_WINDOWS_PATH_SEPARATOR}"
        f"{suffix.lstrip(_WINDOWS_PATH_SEPARATOR)}"
    )


def _filetime_to_utc(value: int, field: str) -> datetime:
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError as exc:
        raise LnkParseError(f"{field} FILETIME is outside Python's datetime range") from exc


def _details(metadata: _ShortcutMetadata, timestamp_kind: str) -> dict[str, object]:
    return {
        "timestamp_kind": timestamp_kind,
        "target_file_attributes": [
            name for mask, name in _ATTRIBUTE_NAMES.items() if metadata.file_attributes & mask
        ],
        "target_file_attributes_raw": metadata.file_attributes,
        "volume_serial_number": (
            f"{metadata.volume_serial_number:08X}"
            if metadata.volume_serial_number is not None
            else None
        ),
        "drive_type": _DRIVE_TYPES.get(metadata.drive_type, "unrecognized")
        if metadata.drive_type is not None
        else None,
        "drive_type_code": metadata.drive_type,
    }

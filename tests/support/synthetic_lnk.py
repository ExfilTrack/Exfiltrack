"""Build genuinely valid, minimal Shell Link (``.lnk``) binaries.

Unlike EVTX and the registry hives, a well-formed ``.lnk`` file can be
constructed directly from the documented Shell Link (MS-SHLLINK) header and
LinkInfo structures, so nothing here needs to be mocked:
:func:`exfiltrack.parsers.lnk_parser.parse_lnk` parses the bytes this module
builds for real.

Adapted from ``tests/unit/test_lnk_parser.py``'s ``_synthetic_lnk``, with the
target path and timestamps parameterised so each scenario fixture can
describe its own file.
"""

from __future__ import annotations

from datetime import datetime, timezone

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

DRIVE_REMOVABLE = 2
DEFAULT_VOLUME_SERIAL = 0xA1B2C3D4
_ATTR_READ_ONLY_ARCHIVE = 0x00000021


def _filetime(value: datetime) -> int:
    return int((value - _FILETIME_EPOCH).total_seconds() * 10_000_000)


def _split_target(target_path: str) -> tuple[bytes, bytes]:
    """Split a Windows path into a null-terminated base and file-name suffix."""
    if "\\" in target_path:
        base_str, _, suffix_str = target_path.rpartition("\\")
        base_str += "\\"
    else:
        base_str, suffix_str = "", target_path
    return base_str.encode("ascii") + b"\x00", suffix_str.encode("ascii") + b"\x00"


def build_lnk_bytes(
    target_path: str,
    *,
    creation: datetime,
    access: datetime,
    modification: datetime,
    file_size_bytes: int = 123_456,
    volume_serial: int = DEFAULT_VOLUME_SERIAL,
    drive_type: int = DRIVE_REMOVABLE,
    attributes: int = _ATTR_READ_ONLY_ARCHIVE,
) -> bytes:
    """Build a minimal Shell Link with a removable-volume LinkInfo section.

    Args:
        target_path: Windows-style path recorded as the link target, e.g.
            ``r"E:\\Evidence\\plans.txt"``.
        creation, access, modification: Timestamps recorded in the header.
            ``access`` is the one that becomes a ``file_access``
            ``NormalizedEvent`` and is therefore the one session
            reconstruction and scoring see (``exfiltrack.parsers.lnk_parser``
            labels the other two ``file_created`` / ``file_modified``, which
            are not session-relevant).
        volume_serial: Recorded in the LinkInfo VolumeID; must match a
            ``destination_file_hashes`` scenario's expectations if attribution
            to a specific removable volume matters to the test.
        drive_type: One of the ``DRIVE_*`` constants understood by
            ``exfiltrack.parsers.lnk_parser`` (``DRIVE_REMOVABLE`` = 2).
    """
    creation_ft = _filetime(creation)
    access_ft = _filetime(access)
    modification_ft = _filetime(modification)

    header = bytearray(0x4C)
    header[0:4] = (0x4C).to_bytes(4, "little")
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    header[0x14:0x18] = (0x00000002).to_bytes(4, "little")  # HasLinkInfo
    header[0x18:0x1C] = attributes.to_bytes(4, "little")
    header[0x1C:0x24] = creation_ft.to_bytes(8, "little")
    header[0x24:0x2C] = access_ft.to_bytes(8, "little")
    header[0x2C:0x34] = modification_ft.to_bytes(8, "little")
    header[0x34:0x38] = file_size_bytes.to_bytes(4, "little")

    volume = bytearray(16)
    volume[0:4] = (16).to_bytes(4, "little")
    volume[4:8] = drive_type.to_bytes(4, "little")
    volume[8:12] = volume_serial.to_bytes(4, "little")
    volume[12:16] = (16).to_bytes(4, "little")

    base, suffix = _split_target(target_path)
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

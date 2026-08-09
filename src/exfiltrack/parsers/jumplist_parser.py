"""Jump List parser.

Owner: Thabrew
Related issue: #6 - Jump List Parser

Parse automaticDestinations-ms and customDestinations-ms files read-only.
Map application IDs to known applications.
Extract recently and frequently accessed file paths per application.
Emit normalized events with parser name and version.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import olefile

from exfiltrack.config import ExfilTrackError
from exfiltrack.correlation.models import NormalizedEvent
from exfiltrack.parsers.lnk_parser import (
    LnkParseError,
    _details,
    _filetime_to_utc,
    _parse_shortcut,
)

PARSER_NAME = "jumplist_parser"
PARSER_VERSION = "0.1.0"

KNOWN_APP_IDS = {
    "1b4dd67f29cb1962": "Windows Explorer",
    "f01b4d95cf55d32a": "Windows Explorer",
    "918e0ecb43d17e23": "Notepad",
    "5b0a6ed0f523a518": "Microsoft Word",
    "b8ab77100df80ab2": "Microsoft Excel",
    "28c8b86deab549a1": "Internet Explorer",
    "5a4bc032130dfcde": "Mozilla Firefox",
    "74d7f43c1561fc1c": "Microsoft Edge",
}


class JumpListParseError(ExfilTrackError):
    """Raised when a Jump List is truncated, malformed, or unreadable."""


def parse_jumplist(file_path: Path | str) -> Iterator[NormalizedEvent]:
    """Parse a Jump List file and yield normalized file-activity events."""
    source = Path(file_path)
    source_artifact = source.as_posix()
    filename = source.name

    # Extract AppID from filename (16 hex chars)
    match = re.match(
        r"^([a-fA-F0-9]{16})\.(automaticDestinations-ms|customDestinations-ms)$",
        filename,
        re.IGNORECASE,
    )
    if not match:
        raise JumpListParseError(f"Invalid Jump List filename: {filename}")

    app_id = match.group(1).lower()
    file_ext = match.group(2).lower()
    resolved_app = KNOWN_APP_IDS.get(app_id, f"unknown ({app_id})")

    if file_ext == "automaticdestinations-ms":
        yield from _parse_automatic(source, source_artifact, app_id, resolved_app)
    elif file_ext == "customdestinations-ms":
        yield from _parse_custom(source, source_artifact, app_id, resolved_app)
    else:
        # Unreachable due to regex, but satisfies type checker or future changes
        raise JumpListParseError(f"Unsupported Jump List extension: {file_ext}")


def _parse_automatic(
    source: Path, source_artifact: str, app_id: str, resolved_app: str
) -> Iterator[NormalizedEvent]:
    try:
        with source.open("rb") as f:
            if not olefile.isOleFile(f):
                raise JumpListParseError("File is not a valid OLE Compound File")
            f.seek(0)

            with olefile.OleFileIO(f) as ole:
                streams = ole.listdir(streams=True, storages=False)
                valid_entries = 0

                for stream_path in streams:
                    stream_name = stream_path[-1]
                    if stream_name.lower() == "destlist":
                        continue

                    try:
                        with ole.openstream(stream_path) as stream:
                            data = stream.read()
                    except OSError as exc:
                        raise JumpListParseError(f"Could not read stream {stream_name}") from exc

                    try:
                        metadata = _parse_shortcut(data)
                        yield from _emit_events(
                            metadata, source_artifact, app_id, resolved_app, stream_name=stream_name
                        )
                        valid_entries += 1
                    except LnkParseError:
                        # Skip corrupt embedded entries
                        continue

                if valid_entries == 0:
                    raise JumpListParseError(
                        "No valid LNK entries found in automaticDestinations-ms container"
                    )

    except OSError as exc:
        raise JumpListParseError(
            f"Could not read Jump List file '{source_artifact}': {exc}"
        ) from exc


def _parse_custom(
    source: Path, source_artifact: str, app_id: str, resolved_app: str
) -> Iterator[NormalizedEvent]:
    try:
        with source.open("rb") as f:
            data = f.read()
    except OSError as exc:
        raise JumpListParseError(
            f"Could not read Jump List file '{source_artifact}': {exc}"
        ) from exc

    # MS-SHLLINK header signature: 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46
    signature = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

    offset = 0
    valid_entries = 0
    while True:
        idx = data.find(signature, offset)
        if idx == -1:
            break

        slice_data = data[idx:]
        try:
            metadata = _parse_shortcut(slice_data)
            yield from _emit_events(
                metadata, source_artifact, app_id, resolved_app, stream_name=None
            )
            valid_entries += 1
        except LnkParseError:
            # Corrupt candidate, ignore and continue
            pass

        # Move past the signature to search for the next
        offset = idx + len(signature)

    if valid_entries == 0:
        raise JumpListParseError("No valid LNK entries found in customDestinations-ms container")


def _emit_events(
    metadata, source_artifact: str, app_id: str, resolved_app: str, stream_name: str | None
) -> Iterator[NormalizedEvent]:
    timestamps = (
        ("file_created", "creation", metadata.creation_time),
        ("file_access", "access", metadata.access_time),
        ("file_modified", "modification", metadata.modification_time),
    )
    for event_type, timestamp_kind, raw_filetime in timestamps:
        if raw_filetime == 0:
            continue

        event_details = _details(metadata, timestamp_kind)
        event_details["app_id"] = app_id
        event_details["application"] = resolved_app
        if stream_name:
            event_details["stream_name"] = stream_name

        yield NormalizedEvent(
            event_type=event_type,
            timestamp_utc=_filetime_to_utc(raw_filetime, timestamp_kind),
            raw_timestamp=str(raw_filetime),
            source_artifact=source_artifact,
            parser_name=PARSER_NAME,
            parser_version=PARSER_VERSION,
            file_path=metadata.target_path,
            file_size_bytes=metadata.file_size_bytes,
            details=event_details,
        )

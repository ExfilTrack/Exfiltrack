"""Shared helpers for building synthetic EVTX evidence without a Windows VM.

``python-evtx`` has no writer, so a genuine EVTX binary cannot be
constructed in code -- the same constraint ``tests/unit/test_registry_parser.py``
documents for ``regf`` hives. These helpers use the same technique
``tests/unit/test_evtx_parser.py`` already uses at the unit level: a double
for the tiny ``python-evtx`` surface :func:`exfiltrack.parsers.evtx_parser.parse_evtx`
actually touches (a context manager whose ``records()`` yields objects with
an ``.xml()`` method), installed via ``monkeypatch`` so ``parse_evtx`` runs
completely unmodified against synthetic Event XML.

Files written to disk still carry the real ``ElfFile\\x00`` magic header (see
:func:`placeholder_evtx_file`), so evidence intake and classification
(:func:`exfiltrack.evidence.intake.discover_artifacts`) and hashing run for
real. Only the EVTX record *content* is synthetic -- everything upstream of
``parse_evtx`` and everything downstream of it in the pipeline is exercised
against real code paths.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Real EVTX magic bytes (see exfiltrack.evidence.intake._MAGIC), so a
# placeholder file classifies as ArtifactType.EVTX at intake without needing
# genuine EVTX content.
EVTX_MAGIC = b"ElfFile\x00"


def placeholder_evtx_file(path: Path) -> None:
    """Write a file that classifies as an EVTX artifact at intake.

    Padded past the header so hashing and size reporting behave like a real,
    if tiny, evidence file. Parent directories are created as needed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(EVTX_MAGIC + b"\x00" * 56)


def _iso(when: datetime) -> str:
    return when.isoformat().replace("+00:00", "Z")


def device_lifecycle_xml(
    *,
    event_id: str,
    device_instance_id: str,
    when: datetime,
    record_id: int,
    provider: str = "Microsoft-Windows-DriverFrameworks-UserMode",
) -> str:
    """Build a DriverFrameworks device-lifecycle Event XML record.

    ``event_id`` is ``"2003"`` (insert), ``"2100"`` (remove pending), or
    ``"2102"`` (remove) -- see ``exfiltrack.parsers.evtx_parser``.
    """
    return (
        f'<Event xmlns="{_NS}">'
        f"<System>"
        f'<Provider Name="{provider}" />'
        f"<EventID>{event_id}</EventID>"
        f'<TimeCreated SystemTime="{_iso(when)}" />'
        f"<EventRecordID>{record_id}</EventRecordID>"
        f"<Channel>{provider}/Operational</Channel>"
        f"</System>"
        f"<EventData>"
        f'<Data Name="DeviceInstanceId">{escape(device_instance_id)}</Data>'
        f"</EventData>"
        f"</Event>"
    )


def file_access_xml(
    *,
    object_name: str,
    when: datetime,
    record_id: int,
    access_mask: str = "0x1",
    process_name: str = "C:\\Windows\\explorer.exe",
) -> str:
    """Build a Security 4663 (object access) Event XML record for a file."""
    return (
        f'<Event xmlns="{_NS}">'
        f"<System>"
        f'<Provider Name="Microsoft-Windows-Security-Auditing" />'
        f"<EventID>4663</EventID>"
        f'<TimeCreated SystemTime="{_iso(when)}" />'
        f"<EventRecordID>{record_id}</EventRecordID>"
        f"<Channel>Security</Channel>"
        f"</System>"
        f"<EventData>"
        f'<Data Name="ObjectType">File</Data>'
        f'<Data Name="ObjectName">{escape(object_name)}</Data>'
        f'<Data Name="AccessMask">{escape(access_mask)}</Data>'
        f'<Data Name="ProcessName">{escape(process_name)}</Data>'
        f"</EventData>"
        f"</Event>"
    )


class _SyntheticRecord:
    def __init__(self, xml: str) -> None:
        self._xml = xml

    def xml(self) -> str:
        return self._xml


class _SyntheticLog:
    def __init__(self, records: Iterable[str]) -> None:
        self._records = [_SyntheticRecord(r) for r in records]

    def __enter__(self) -> _SyntheticLog:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def records(self) -> list[_SyntheticRecord]:
        return self._records


class SyntheticEvtxReader:
    """Drop-in replacement for ``Evtx.Evtx.Evtx``, keyed by resolved file path.

    Install with::

        monkeypatch.setattr(
            "exfiltrack.parsers.evtx_parser.evtx.Evtx",
            SyntheticEvtxReader(records_by_path),
        )

    Every EVTX artifact the pipeline discovers is routed through here by its
    resolved, POSIX-form path -- exactly what
    ``exfiltrack.parsers.evtx_parser.parse_evtx`` passes to ``evtx.Evtx(str(path))``
    for a real file, so a scenario with several EVTX files (e.g. a separate
    ``System.evtx`` and ``Security.evtx``) routes each to its own record set.
    """

    def __init__(self, records_by_path: dict[str, list[str]]) -> None:
        self._records_by_path = records_by_path

    def __call__(self, path: str) -> _SyntheticLog:
        key = Path(path).as_posix()
        try:
            records = self._records_by_path[key]
        except KeyError as exc:
            raise AssertionError(
                f"No synthetic EVTX records registered for '{key}'. "
                f"Registered paths: {sorted(self._records_by_path)}"
            ) from exc
        return _SyntheticLog(records)

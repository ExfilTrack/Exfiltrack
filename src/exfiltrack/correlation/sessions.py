"""USB connection session reconstruction.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #8 - USB Session Reconstruction

Groups per-device insert/remove events into probable connection sessions,
inferring a session boundary with the configured idle gap whenever no
explicit event establishes it, and attaches file activity that falls
inside each session's time window.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from exfiltrack.config import ExfilTrackError, SessionConfig
from exfiltrack.correlation.models import EventType, NormalizedEvent, UsbDevice

DEFAULT_INSERT_TYPES: frozenset[str] = frozenset({EventType.USB_INSERT.value})
DEFAULT_REMOVE_TYPES: frozenset[str] = frozenset({EventType.USB_REMOVE.value})


class SessionReconstructionError(ExfilTrackError):
    """Raised when device events cannot be grouped into sessions.

    This is an explicit error rather than a silent skip (forensic
    soundness requirement 6): a device-lifecycle event with no device
    identity is malformed input, not something to drop quietly.
    """


@dataclass(frozen=True)
class SessionBoundary:
    """One edge (start or end) of a reconstructed USB session.

    Attributes:
        timestamp_utc: The boundary's UTC timestamp.
        observed: ``True`` if this boundary is backed by an explicit
            insert/remove event (audit-log evidence). ``False`` if it was
            inferred -- from the configured idle gap when no removal event
            exists, or counting backwards from an orphaned removal event.
            The report must render observed and inferred boundaries
            distinctly (Definition of Done, #8 and #11).
        source_event: The event that established an *observed* boundary.
            ``None`` for an inferred boundary, since there is no single
            artifact to cite for a value the tool assumed rather than saw.
    """

    timestamp_utc: datetime
    observed: bool
    source_event: NormalizedEvent | None = None

    def __post_init__(self) -> None:
        if self.observed and self.source_event is None:
            raise ValueError("An observed boundary must cite the event that established it.")


@dataclass
class UsbSession:
    """A probable USB device connection window.

    ``session_id`` is derived deterministically from the device id and the
    start timestamp -- never a random UUID -- so that repeated runs
    against identical evidence produce byte-identical output (forensic
    soundness requirement 7).
    """

    session_id: str
    device: UsbDevice
    start: SessionBoundary
    end: SessionBoundary
    file_events: list[NormalizedEvent] = field(default_factory=list)

    @property
    def duration(self) -> timedelta:
        """Wall-clock span between the (possibly inferred) start and end."""
        return self.end.timestamp_utc - self.start.timestamp_utc

    @property
    def is_fully_observed(self) -> bool:
        """``True`` only if both boundaries are backed by an explicit event."""
        return self.start.observed and self.end.observed


def _session_id(device_id: str, start_ts: datetime) -> str:
    """Deterministic session identifier: device id plus ISO-8601 start time."""
    return f"{device_id}:{start_ts.isoformat()}"


def reconstruct_sessions(
    events: Sequence[NormalizedEvent],
    *,
    config: SessionConfig | None = None,
    insert_types: frozenset[str] = DEFAULT_INSERT_TYPES,
    remove_types: frozenset[str] = DEFAULT_REMOVE_TYPES,
) -> list[UsbSession]:
    """Group *events* into probable USB connection sessions.

    Parameters:
        events: The full normalized event timeline (device and file
            events mixed together; this function separates them).
        config: Session-reconstruction tuning, notably ``idle_gap``.
            Defaults to :class:`~exfiltrack.config.SessionConfig` with its
            default idle gap.
        insert_types: ``event_type`` values that mark a device becoming
            available. Defaults to ``{"usb_insert"}``.
        remove_types: ``event_type`` values that mark a device becoming
            unavailable. Defaults to ``{"usb_remove"}``.

    Returns:
        Sessions across every device, ordered deterministically by start
        time, then device id, then session id. Sessions from different
        devices may legitimately overlap in time; each is reconstructed
        independently, so overlap is preserved rather than merged away.

    Raises:
        SessionReconstructionError: If a device-lifecycle event carries no
            device identity.
    """
    cfg = config or SessionConfig()

    device_events: dict[str, list[NormalizedEvent]] = {}
    devices_by_id: dict[str, UsbDevice] = {}
    file_events: list[NormalizedEvent] = []

    for event in events:
        if event.event_type in insert_types or event.event_type in remove_types:
            if event.device is None:
                raise SessionReconstructionError(
                    f"Device event '{event.event_type}' from '{event.source_artifact}' "
                    "carries no device identity and cannot be assigned to a session."
                )
            device_events.setdefault(event.device.device_id, []).append(event)
            devices_by_id.setdefault(event.device.device_id, event.device)
        elif event.event_type == EventType.FILE_ACCESS.value:
            file_events.append(event)
        # Other event types are not session-relevant here and are ignored;
        # they still flow through the rest of the pipeline untouched.

    sessions: list[UsbSession] = []
    for device_id, dev_events in device_events.items():
        ordered = sorted(dev_events, key=lambda e: (e.timestamp_utc, e.source_artifact))
        sessions.extend(
            _reconstruct_device_sessions(
                device_id=device_id,
                device=devices_by_id[device_id],
                ordered_events=ordered,
                insert_types=insert_types,
                remove_types=remove_types,
                idle_gap=cfg.idle_gap,
            )
        )

    _attach_file_activity(sessions, file_events)

    sessions.sort(key=lambda s: (s.start.timestamp_utc, s.device.device_id, s.session_id))
    return sessions


def _reconstruct_device_sessions(
    *,
    device_id: str,
    device: UsbDevice,
    ordered_events: list[NormalizedEvent],
    insert_types: frozenset[str],
    remove_types: frozenset[str],
    idle_gap: timedelta,
) -> list[UsbSession]:
    """Reconstruct sessions for a single device from its sorted event list.

    Handles the well-formed insert/remove pair as well as two anomalies
    that real evidence produces:

    * A removal event with no matching prior insertion ("orphan removal"):
      the start is inferred one idle gap *before* the removal, rather than
      asserting an unknown connection time as if it were exactly known.
    * A second insertion with no intervening removal ("double insert"):
      the previous session is closed with an inferred end at the new
      insertion's timestamp, since that is the last moment the tool can be
      sure the previous connection was still active.
    """
    sessions: list[UsbSession] = []
    pending_start: SessionBoundary | None = None

    for event in ordered_events:
        if event.event_type in insert_types:
            if pending_start is not None:
                sessions.append(
                    UsbSession(
                        session_id=_session_id(device_id, pending_start.timestamp_utc),
                        device=device,
                        start=pending_start,
                        end=SessionBoundary(event.timestamp_utc, observed=False),
                    )
                )
            pending_start = SessionBoundary(event.timestamp_utc, observed=True, source_event=event)

        elif event.event_type in remove_types:
            if pending_start is not None:
                sessions.append(
                    UsbSession(
                        session_id=_session_id(device_id, pending_start.timestamp_utc),
                        device=device,
                        start=pending_start,
                        end=SessionBoundary(event.timestamp_utc, observed=True, source_event=event),
                    )
                )
                pending_start = None
            else:
                inferred_start_ts = event.timestamp_utc - idle_gap
                sessions.append(
                    UsbSession(
                        session_id=_session_id(device_id, inferred_start_ts),
                        device=device,
                        start=SessionBoundary(inferred_start_ts, observed=False),
                        end=SessionBoundary(event.timestamp_utc, observed=True, source_event=event),
                    )
                )

    if pending_start is not None:
        inferred_end_ts = pending_start.timestamp_utc + idle_gap
        sessions.append(
            UsbSession(
                session_id=_session_id(device_id, pending_start.timestamp_utc),
                device=device,
                start=pending_start,
                end=SessionBoundary(inferred_end_ts, observed=False),
            )
        )

    return sessions


def _attach_file_activity(sessions: list[UsbSession], file_events: list[NormalizedEvent]) -> None:
    """Attach each file event to every session whose window contains it.

    A file event that falls inside two overlapping sessions from different
    devices is attached to both: with only a time window to go on, the
    tool cannot know which device it belongs to, and silently picking one
    would misrepresent the evidence.
    """
    ordered_files = sorted(file_events, key=lambda e: (e.timestamp_utc, e.source_artifact))
    for session in sessions:
        session.file_events = [
            fe
            for fe in ordered_files
            if session.start.timestamp_utc <= fe.timestamp_utc <= session.end.timestamp_utc
        ]

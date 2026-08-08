"""Unit tests for USB session reconstruction.

Related issue: #8 - USB Session Reconstruction
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from exfiltrack.config import SessionConfig
from exfiltrack.correlation.sessions import (
    SessionReconstructionError,
    reconstruct_sessions,
)
from tests.unit.factories import (
    make_device,
    make_file_event,
    make_insert_event,
    make_remove_event,
    utc,
)


@pytest.mark.unit
def test_normal_insert_remove_pair_is_observed_both_ends() -> None:
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 9, 30, 0), device),
    ]

    sessions = reconstruct_sessions(events)

    assert len(sessions) == 1
    session = sessions[0]
    assert session.start.observed is True
    assert session.end.observed is True
    assert session.is_fully_observed is True
    assert session.start.timestamp_utc == utc(2026, 1, 1, 9, 0, 0)
    assert session.end.timestamp_utc == utc(2026, 1, 1, 9, 30, 0)


@pytest.mark.unit
def test_no_removal_event_infers_end_using_idle_gap() -> None:
    """Required scenario: no removal event exists (#8 Definition of Done)."""
    device = make_device()
    insert_ts = utc(2026, 1, 1, 9, 0, 0)
    events = [make_insert_event(insert_ts, device)]
    config = SessionConfig(idle_gap=timedelta(minutes=20))

    sessions = reconstruct_sessions(events, config=config)

    assert len(sessions) == 1
    session = sessions[0]
    assert session.start.observed is True
    assert session.end.observed is False
    assert session.end.source_event is None
    assert session.end.timestamp_utc == insert_ts + timedelta(minutes=20)
    assert session.is_fully_observed is False


@pytest.mark.unit
def test_orphan_removal_infers_start_before_removal() -> None:
    device = make_device()
    removal_ts = utc(2026, 1, 1, 9, 45, 0)
    events = [make_remove_event(removal_ts, device)]
    config = SessionConfig(idle_gap=timedelta(minutes=10))

    sessions = reconstruct_sessions(events, config=config)

    assert len(sessions) == 1
    session = sessions[0]
    assert session.start.observed is False
    assert session.end.observed is True
    assert session.start.timestamp_utc == removal_ts - timedelta(minutes=10)


@pytest.mark.unit
def test_double_insert_closes_previous_session_with_inferred_end() -> None:
    device = make_device()
    first_insert = utc(2026, 1, 1, 9, 0, 0)
    second_insert = utc(2026, 1, 1, 10, 0, 0)
    events = [
        make_insert_event(first_insert, device),
        make_insert_event(second_insert, device),
    ]

    sessions = reconstruct_sessions(events)

    assert len(sessions) == 2
    first_session, second_session = sorted(sessions, key=lambda s: s.start.timestamp_utc)
    assert first_session.end.observed is False
    assert first_session.end.timestamp_utc == second_insert
    assert second_session.start.observed is True
    assert second_session.end.observed is False


@pytest.mark.unit
def test_overlapping_sessions_from_multiple_devices_are_handled_independently() -> None:
    """Required scenario: overlapping sessions from multiple devices (#8)."""
    device_a = make_device(device_id="USB\\DEVICE_A", friendly_name="Device A")
    device_b = make_device(device_id="USB\\DEVICE_B", friendly_name="Device B")

    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device_a),
        make_insert_event(utc(2026, 1, 1, 9, 10, 0), device_b),
        make_remove_event(utc(2026, 1, 1, 9, 40, 0), device_a),
        make_remove_event(utc(2026, 1, 1, 9, 50, 0), device_b),
        # Falls inside both devices' windows.
        make_file_event(utc(2026, 1, 1, 9, 20, 0), r"C:\Users\dev\Documents\shared.docx"),
    ]

    sessions = reconstruct_sessions(events)

    assert len(sessions) == 2
    session_a = next(s for s in sessions if s.device.device_id == "USB\\DEVICE_A")
    session_b = next(s for s in sessions if s.device.device_id == "USB\\DEVICE_B")

    # Both devices' windows genuinely overlap and neither was merged away.
    assert session_a.start.timestamp_utc < session_b.start.timestamp_utc
    assert session_a.end.timestamp_utc < session_b.end.timestamp_utc
    assert session_a.start.timestamp_utc < session_b.end.timestamp_utc  # overlap

    # The ambiguous file event is attached to both, since a time window
    # alone cannot disambiguate which device it belongs to.
    assert len(session_a.file_events) == 1
    assert len(session_b.file_events) == 1
    assert session_a.file_events[0].file_path == session_b.file_events[0].file_path


@pytest.mark.unit
def test_session_with_zero_file_activity_is_not_an_error() -> None:
    """Required scenario: a session with zero file activity (#8)."""
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 9, 30, 0), device),
    ]

    sessions = reconstruct_sessions(events)

    assert len(sessions) == 1
    assert sessions[0].file_events == []


@pytest.mark.unit
def test_file_activity_outside_every_window_is_attached_nowhere() -> None:
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 9, 30, 0), device),
        make_file_event(utc(2026, 1, 1, 12, 0, 0), r"C:\Users\dev\Documents\unrelated.docx"),
    ]

    sessions = reconstruct_sessions(events)

    assert sessions[0].file_events == []


@pytest.mark.unit
def test_session_ids_are_deterministic_across_runs() -> None:
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 9, 30, 0), device),
    ]

    first_run = reconstruct_sessions(events)
    second_run = reconstruct_sessions(events)

    assert [s.session_id for s in first_run] == [s.session_id for s in second_run]


@pytest.mark.unit
def test_sessions_are_returned_in_deterministic_start_time_order() -> None:
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 12, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 12, 5, 0), device),
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 9, 5, 0), device),
    ]

    sessions = reconstruct_sessions(events)

    starts = [s.start.timestamp_utc for s in sessions]
    assert starts == sorted(starts)


@pytest.mark.unit
def test_device_event_without_device_identity_raises() -> None:
    device = make_device()
    bad_event = make_insert_event(utc(2026, 1, 1, 9, 0, 0), device)
    object.__setattr__(bad_event, "device", None)

    with pytest.raises(SessionReconstructionError):
        reconstruct_sessions([bad_event])

"""Unit tests for the partial-coverage boundary marker (issue #35).

The Definition of Done asks for a session bounded by DriverFrameworks events
and one bounded only by registry properties; a gap-inferred boundary is the
third case. The confidence-cap decision (do NOT cap; disclose instead) is
pinned down by test_confidence_is_not_capped_by_the_marker.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from exfiltrack.correlation.confidence import ConfidenceLevel, evaluate_confidence
from exfiltrack.correlation.scoring import score_session
from exfiltrack.correlation.sessions import reconstruct_sessions
from tests.unit.factories import (
    make_device,
    make_file_event,
    make_insert_event,
    make_remove_event,
    utc,
)

# The tag the registry parser sets on events derived from the 0066/0067
# device properties (see registry_parser.py).
MOST_RECENT_ONLY = {"records_most_recent_only": True}


def _registry_bounded_events():
    """A session whose boundaries come from registry properties 0066/0067."""
    device = make_device()
    base = utc(2026, 3, 1, 9, 0, 0)
    return [
        make_insert_event(base, device, details=dict(MOST_RECENT_ONLY)),
        make_file_event(base + timedelta(seconds=5), r"E:\Confidential\db_dump.sql"),
        make_file_event(base + timedelta(seconds=12), r"E:\Confidential\keys.pem"),
        make_remove_event(
            base + timedelta(minutes=10), device, details=dict(MOST_RECENT_ONLY)
        ),
    ]


@pytest.mark.unit
def test_event_log_bounded_session_has_no_marker() -> None:
    """The DoD's DriverFrameworks-bounded session: no partial-coverage marker."""
    device = make_device()
    base = utc(2026, 3, 1, 9, 0, 0)
    events = [
        make_insert_event(base, device),
        make_remove_event(base + timedelta(minutes=10), device),
    ]
    [session] = reconstruct_sessions(events)

    assert session.boundary_sources == ("event_log", "event_log")
    assert session.partial_coverage_reasons == ()
    assert session.partial_coverage is False


@pytest.mark.unit
def test_registry_property_bounded_session_is_marked() -> None:
    """The DoD's registry-properties session: marker names 0066/0067."""
    [session] = reconstruct_sessions(_registry_bounded_events())

    assert session.boundary_sources == ("registry_properties", "registry_properties")
    assert session.partial_coverage is True
    assert len(session.partial_coverage_reasons) == 2
    assert all("0066/0067" in reason for reason in session.partial_coverage_reasons)
    assert any("most recent" in reason for reason in session.partial_coverage_reasons)


@pytest.mark.unit
def test_inferred_boundary_is_marked() -> None:
    """An orphan removal: the start is idle-gap-inferred, the end observed."""
    device = make_device()
    base = utc(2026, 3, 1, 9, 0, 0)
    [session] = reconstruct_sessions([make_remove_event(base, device)])

    assert session.boundary_sources == ("inferred", "event_log")
    assert session.partial_coverage is True
    assert len(session.partial_coverage_reasons) == 1
    assert "inferred" in session.partial_coverage_reasons[0]


@pytest.mark.unit
def test_scored_session_propagates_the_marker() -> None:
    """The marker must travel with the scored session (issue #35 scope)."""
    [session] = reconstruct_sessions(_registry_bounded_events())
    scored = score_session(session)

    assert scored.boundary_sources == session.boundary_sources
    assert scored.partial_coverage_reasons == session.partial_coverage_reasons


@pytest.mark.unit
def test_confidence_is_not_capped_by_the_marker() -> None:
    """The recorded decision: disclose, do not cap.

    A registry-bounded session counts as observed (the registry read is
    real), so a strong score still reaches High -- the marker beside the
    level is what discloses the weaker boundaries (issue #35 discussion).
    """
    [session] = reconstruct_sessions(_registry_bounded_events())
    scored = score_session(session)
    confidence = evaluate_confidence(scored)

    assert scored.total_score == 95
    assert confidence.level is ConfidenceLevel.HIGH
    assert scored.partial_coverage is True

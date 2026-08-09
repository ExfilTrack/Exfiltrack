"""Unit tests for the confidence evaluation model.

Related issue: #10 - Confidence Evaluation Model
"""

from __future__ import annotations

import pytest

from exfiltrack.config import ConfidenceThresholds, ScoringWeights
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

WEIGHTS = ScoringWeights(protected_directories=(r"C:\Projects\confidential",))


def _scored_session(*, observed_end: bool, file_events: list, weights: ScoringWeights = WEIGHTS):
    device = make_device()
    insert_ts = utc(2026, 1, 1, 9, 0, 0)
    events = [make_insert_event(insert_ts, device), *file_events]
    if observed_end:
        events.append(make_remove_event(utc(2026, 1, 1, 10, 0, 0), device))
    session = reconstruct_sessions(events)[0]
    return score_session(session, weights)


@pytest.mark.unit
def test_no_contributions_is_confidence_none() -> None:
    scored = _scored_session(observed_end=True, file_events=[])

    result = evaluate_confidence(scored)

    assert result.level == ConfidenceLevel.NONE


@pytest.mark.unit
def test_a_single_weak_signal_is_low() -> None:
    # Outside both timing windows (600s > 5min) but inside the session, so
    # only sensitive_extension (15 points) fires: above zero, below Medium.
    scored = _scored_session(
        observed_end=True,
        file_events=[make_file_event(utc(2026, 1, 1, 9, 10, 0), r"C:\Users\dev\dump.sql")],
    )
    assert 0 < scored.total_score < ConfidenceThresholds().medium  # sanity check on the fixture

    result = evaluate_confidence(scored)

    assert result.level == ConfidenceLevel.LOW


@pytest.mark.unit
def test_multiple_confidential_files_reaches_medium_even_below_score_threshold() -> None:
    # Deliberately small weights so two confidential files plus the
    # aggregate rule still land below the (default) Medium score
    # threshold, isolating multiple_confidential_files as the reason.
    low_weights = ScoringWeights(sensitive_extension=5, multiple_confidential_files=10)
    scored = _scored_session(
        observed_end=True,
        file_events=[
            make_file_event(utc(2026, 1, 1, 9, 20, 0), r"C:\Users\dev\a.sql"),
            make_file_event(utc(2026, 1, 1, 9, 30, 0), r"C:\Users\dev\b.sql"),
        ],
        weights=low_weights,
    )
    assert scored.total_score < ConfidenceThresholds().medium  # sanity check on the fixture

    result = evaluate_confidence(scored)

    assert result.level == ConfidenceLevel.MEDIUM


@pytest.mark.unit
def test_high_requires_both_a_high_score_and_fully_observed_boundaries() -> None:
    file_events = [
        make_file_event(utc(2026, 1, 1, 9, 0, 10), r"C:\Projects\confidential\a.sql"),
        make_file_event(utc(2026, 1, 1, 9, 0, 15), r"C:\Projects\confidential\b.sql"),
    ]

    observed = _scored_session(observed_end=True, file_events=file_events)
    inferred = _scored_session(observed_end=False, file_events=file_events)
    assert observed.total_score == inferred.total_score  # same score, different observedness
    assert observed.total_score >= ConfidenceThresholds().high  # sanity check on the fixture

    assert evaluate_confidence(observed).level == ConfidenceLevel.HIGH
    assert evaluate_confidence(inferred).level == ConfidenceLevel.MEDIUM


@pytest.mark.unit
def test_maximum_score_finding_without_hash_match_does_not_reach_confirmed() -> None:
    """Required scenario (#10 Definition of Done): score alone never reaches Confirmed."""
    file_events = [
        make_file_event(utc(2026, 1, 1, 9, 0, 5), r"C:\Projects\confidential\a.sql"),
        make_file_event(utc(2026, 1, 1, 9, 0, 10), r"C:\Projects\confidential\b.zip"),
        make_file_event(utc(2026, 1, 1, 9, 0, 15), r"C:\Projects\confidential\c.pem"),
    ]
    scored = _scored_session(observed_end=True, file_events=file_events)

    result = evaluate_confidence(scored)

    assert result.level != ConfidenceLevel.CONFIRMED
    assert result.level == ConfidenceLevel.HIGH


@pytest.mark.unit
def test_destination_hash_match_reaches_confirmed_regardless_of_score() -> None:
    digest = "d" * 64
    device = make_device()
    insert_ts = utc(2026, 1, 1, 9, 0, 0)
    events = [
        make_insert_event(insert_ts, device),
        make_remove_event(utc(2026, 1, 1, 10, 0, 0), device),
        make_file_event(utc(2026, 1, 1, 9, 5, 0), r"C:\Users\dev\report.docx", sha256=digest),
    ]
    session = reconstruct_sessions(events)[0]
    scored = score_session(session, WEIGHTS, destination_file_hashes=frozenset({digest}))

    result = evaluate_confidence(scored)

    assert result.level == ConfidenceLevel.CONFIRMED


@pytest.mark.unit
def test_confidence_levels_are_ordered() -> None:
    assert ConfidenceLevel.CONFIRMED > ConfidenceLevel.HIGH > ConfidenceLevel.MEDIUM
    assert ConfidenceLevel.MEDIUM > ConfidenceLevel.LOW > ConfidenceLevel.NONE


@pytest.mark.unit
def test_confidence_thresholds_reject_invalid_ordering() -> None:
    from exfiltrack.config import ConfigError

    with pytest.raises(ConfigError):
        ConfidenceThresholds(medium=60, high=40)

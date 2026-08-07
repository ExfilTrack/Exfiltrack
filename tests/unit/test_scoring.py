"""Unit tests for the risk scoring engine.

Related issue: #9 - Risk Scoring Engine

Each rule is asserted in isolation first (Definition of Done), then one
combined case exercises several rules together.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from exfiltrack.config import ScoringWeights
from exfiltrack.correlation.scoring import (
    ACTIVITY_WITHIN_5MIN,
    ACTIVITY_WITHIN_30S,
    DESTINATION_HASH_MATCH,
    MULTIPLE_CONFIDENTIAL_FILES,
    PROTECTED_DIRECTORY,
    SENSITIVE_EXTENSION,
    score_session,
)
from exfiltrack.correlation.sessions import reconstruct_sessions
from tests.unit.factories import (
    make_device,
    make_file_event,
    make_insert_event,
    make_remove_event,
    utc,
)

WEIGHTS = ScoringWeights(protected_directories=(r"C:\Projects\confidential",))


def _single_file_session(file_path: str, delay_seconds: int, **file_kwargs: object):
    device = make_device()
    insert_ts = utc(2026, 1, 1, 9, 0, 0)
    events = [
        make_insert_event(insert_ts, device),
        make_remove_event(utc(2026, 1, 1, 10, 0, 0), device),
        make_file_event(insert_ts + timedelta(seconds=delay_seconds), file_path, **file_kwargs),
    ]
    return reconstruct_sessions(events)[0]


@pytest.mark.unit
def test_activity_within_30_seconds_scores_in_isolation() -> None:
    session = _single_file_session(r"C:\Users\dev\notes.txt", delay_seconds=10)

    scored = score_session(session, WEIGHTS)

    assert scored.total_score == WEIGHTS.activity_within_30s
    assert scored.contributions[0].rule == ACTIVITY_WITHIN_30S


@pytest.mark.unit
def test_activity_within_5_minutes_scores_in_isolation_and_does_not_stack_with_30s() -> None:
    session = _single_file_session(r"C:\Users\dev\notes.txt", delay_seconds=120)

    scored = score_session(session, WEIGHTS)

    assert scored.total_score == WEIGHTS.activity_within_5min
    assert [c.rule for c in scored.contributions] == [ACTIVITY_WITHIN_5MIN]


@pytest.mark.unit
def test_activity_outside_5_minutes_scores_nothing_for_timing_rules() -> None:
    session = _single_file_session(r"C:\Users\dev\notes.txt", delay_seconds=600)

    scored = score_session(session, WEIGHTS)

    assert scored.total_score == 0


@pytest.mark.unit
def test_sensitive_extension_scores_in_isolation() -> None:
    # 600s is outside the 5-minute timing window but still inside the
    # session (which runs 9:00-10:00), so no timing rule fires alongside it.
    session = _single_file_session(r"C:\Users\dev\dump.sql", delay_seconds=600)

    scored = score_session(session, WEIGHTS)

    assert scored.total_score == WEIGHTS.sensitive_extension
    assert scored.contributions[0].rule == SENSITIVE_EXTENSION


@pytest.mark.unit
def test_protected_directory_scores_in_isolation() -> None:
    session = _single_file_session(r"C:\Projects\confidential\design.docx", delay_seconds=600)

    scored = score_session(session, WEIGHTS)

    assert scored.total_score == WEIGHTS.protected_directory
    assert scored.contributions[0].rule == PROTECTED_DIRECTORY


@pytest.mark.unit
def test_destination_hash_match_scores_in_isolation() -> None:
    digest = "a" * 64
    session = _single_file_session(r"C:\Users\dev\report.docx", delay_seconds=600, sha256=digest)

    scored = score_session(session, WEIGHTS, destination_file_hashes=frozenset({digest}))

    assert scored.total_score == WEIGHTS.destination_hash_match
    assert scored.contributions[0].rule == DESTINATION_HASH_MATCH


@pytest.mark.unit
def test_destination_hash_match_requires_an_actual_match() -> None:
    session = _single_file_session(r"C:\Users\dev\report.docx", delay_seconds=9999, sha256="a" * 64)

    scored = score_session(session, WEIGHTS, destination_file_hashes=frozenset({"b" * 64}))

    assert scored.total_score == 0


@pytest.mark.unit
def test_multiple_confidential_files_scores_once_per_session() -> None:
    device = make_device()
    insert_ts = utc(2026, 1, 1, 9, 0, 0)
    events = [
        make_insert_event(insert_ts, device),
        make_remove_event(utc(2026, 1, 1, 10, 0, 0), device),
        make_file_event(utc(2026, 1, 1, 9, 20, 0), r"C:\Projects\confidential\a.docx"),
        make_file_event(utc(2026, 1, 1, 9, 25, 0), r"C:\Projects\confidential\b.docx"),
        make_file_event(utc(2026, 1, 1, 9, 30, 0), r"C:\Projects\confidential\c.docx"),
    ]
    session = reconstruct_sessions(events)[0]

    scored = score_session(session, WEIGHTS)

    multi_file_hits = [c for c in scored.contributions if c.rule == MULTIPLE_CONFIDENTIAL_FILES]
    assert len(multi_file_hits) == 1
    assert len(multi_file_hits[0].source_artifacts) == 3


@pytest.mark.unit
def test_combined_case_sums_every_matching_rule() -> None:
    """One combined case exercising several rules together (#9 Definition of Done)."""
    device = make_device()
    insert_ts = utc(2026, 1, 1, 9, 0, 0)
    digest = "c" * 64
    events = [
        make_insert_event(insert_ts, device),
        make_remove_event(utc(2026, 1, 1, 10, 0, 0), device),
        # Sensitive extension + protected directory + within 30s + hash match.
        make_file_event(
            utc(2026, 1, 1, 9, 0, 10),
            r"C:\Projects\confidential\secrets.env",
            sha256=digest,
        ),
        # A second confidential file, outside the 5-minute timing window so
        # only multiple_confidential_files is added on its account.
        make_file_event(
            utc(2026, 1, 1, 9, 10, 0),
            r"C:\Projects\confidential\archive.zip",
        ),
    ]
    session = reconstruct_sessions(events)[0]

    scored = score_session(session, WEIGHTS, destination_file_hashes=frozenset({digest}))

    fired = {c.rule for c in scored.contributions}
    assert fired == {
        ACTIVITY_WITHIN_30S,
        SENSITIVE_EXTENSION,
        PROTECTED_DIRECTORY,
        DESTINATION_HASH_MATCH,
        MULTIPLE_CONFIDENTIAL_FILES,
    }
    expected_total = (
        WEIGHTS.activity_within_30s
        + WEIGHTS.sensitive_extension * 2  # both files match a sensitive extension
        + WEIGHTS.protected_directory * 2  # both files are in the protected directory
        + WEIGHTS.destination_hash_match
        + WEIGHTS.multiple_confidential_files
    )
    assert scored.total_score == expected_total


@pytest.mark.unit
def test_session_with_no_file_activity_scores_zero() -> None:
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 9, 30, 0), device),
    ]
    session = reconstruct_sessions(events)[0]

    scored = score_session(session, WEIGHTS)

    assert scored.total_score == 0
    assert scored.contributions == ()


@pytest.mark.unit
def test_scoring_weights_reject_negative_values() -> None:
    from exfiltrack.config import ConfigError

    with pytest.raises(ConfigError):
        ScoringWeights(activity_within_30s=-1)

"""End-to-end pipeline tests for the four controlled scenarios (#13).

Each scenario runs synthetic evidence through the full pipeline --
:func:`exfiltrack.pipeline.run_pipeline` -- and checks the specific outcome
the proposal and ``tests/fixtures/README.md`` define for it. These are the
same four scenarios ``docs/scoring-model.md``'s Calibration and Evaluation
section reports results for.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from exfiltrack.correlation.confidence import ConfidenceLevel
from exfiltrack.correlation.scoring import (
    ACTIVITY_WITHIN_30S,
    MULTIPLE_CONFIDENTIAL_FILES,
    SENSITIVE_EXTENSION,
)
from exfiltrack.evidence.manifest import IntegrityVerdict
from tests.integration.conftest import DEVICE_ID, run_scenario
from tests.support.synthetic_evtx import device_lifecycle_xml, file_access_xml

BASE = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)


def _insert(when: datetime, record_id: int) -> str:
    return device_lifecycle_xml(
        event_id="2003", device_instance_id=DEVICE_ID, when=when, record_id=record_id
    )


def _remove(when: datetime, record_id: int) -> str:
    return device_lifecycle_xml(
        event_id="2102", device_instance_id=DEVICE_ID, when=when, record_id=record_id
    )


@pytest.mark.integration
@pytest.mark.requires_fixtures
def test_scenario_normal_usage_produces_no_high_or_confirmed_findings(
    monkeypatch: pytest.MonkeyPatch, evidence_dir, case_output_dir
) -> None:
    """Scenario 1: non-suspicious USB use. Measures the false-positive rate."""
    removed_at = BASE + timedelta(hours=2, minutes=5)
    records = {
        "logs/System.evtx": [_insert(BASE, 1), _remove(removed_at, 2)],
        "logs/Security.evtx": [
            # A plain document, opened long after the 5-minute correlation
            # window and with no sensitive extension: ordinary use of the
            # drive, not staging.
            file_access_xml(
                object_name=r"E:\notes.txt", when=BASE + timedelta(hours=2), record_id=10
            ),
        ],
    }

    result = run_scenario(monkeypatch, evidence_dir, case_output_dir, records)

    assert len(result.sessions) == 1
    assert len(result.findings) == 1
    assert result.findings[0].confidence.level not in (
        ConfidenceLevel.HIGH,
        ConfidenceLevel.CONFIRMED,
    )
    assert result.manifest.integrity_verdict is IntegrityVerdict.VERIFIED


@pytest.mark.integration
@pytest.mark.requires_fixtures
def test_scenario_simulated_theft_produces_a_high_confidence_finding(
    monkeypatch: pytest.MonkeyPatch, evidence_dir, case_output_dir
) -> None:
    """Scenario 2: synthetic confidential files copied moments after insertion."""
    records = {
        "logs/System.evtx": [_insert(BASE, 1), _remove(BASE + timedelta(minutes=10), 2)],
        "logs/Security.evtx": [
            file_access_xml(
                object_name=r"E:\Confidential\db_dump.sql",
                when=BASE + timedelta(seconds=5),
                record_id=10,
            ),
            file_access_xml(
                object_name=r"E:\Confidential\keys.pem",
                when=BASE + timedelta(seconds=12),
                record_id=11,
            ),
        ],
    }

    result = run_scenario(monkeypatch, evidence_dir, case_output_dir, records)

    assert len(result.findings) == 1
    finding = result.findings[0]
    rule_names = {c.rule for c in finding.scored_session.contributions}
    assert ACTIVITY_WITHIN_30S in rule_names
    assert SENSITIVE_EXTENSION in rule_names
    assert MULTIPLE_CONFIDENTIAL_FILES in rule_names
    assert finding.scored_session.total_score >= 60
    assert finding.session.is_fully_observed
    assert finding.confidence.level is ConfidenceLevel.HIGH


@pytest.mark.integration
@pytest.mark.requires_fixtures
def test_scenario_archive_staging_and_deletion_produces_medium_or_high(
    monkeypatch: pytest.MonkeyPatch, evidence_dir, case_output_dir
) -> None:
    """Scenario 3: an archive is staged, then deleted, inside one session."""
    archive = r"E:\Staging\project_export.zip"
    records = {
        "logs/System.evtx": [_insert(BASE, 1), _remove(BASE + timedelta(minutes=15), 2)],
        "logs/Security.evtx": [
            # Created/copied moments after insertion.
            file_access_xml(
                object_name=archive,
                when=BASE + timedelta(seconds=10),
                record_id=10,
                access_mask="0x2",  # write
            ),
            # Deleted a few minutes later, still inside the session.
            file_access_xml(
                object_name=archive,
                when=BASE + timedelta(minutes=3),
                record_id=11,
                access_mask="0x10000",  # delete
            ),
        ],
    }

    result = run_scenario(monkeypatch, evidence_dir, case_output_dir, records)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.scored_session.total_score >= 40
    assert finding.confidence.level in (ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH)


@pytest.mark.integration
@pytest.mark.requires_fixtures
def test_scenario_unrelated_activity_attributes_nothing_to_a_device(
    monkeypatch: pytest.MonkeyPatch, evidence_dir, case_output_dir
) -> None:
    """Scenario 4: recent-file activity with no USB ever connected.

    No device-lifecycle event exists in this evidence at all, so session
    reconstruction has nothing to build a session from -- the file event is
    parsed (it is real evidence, and Non-Negotiable #4 forbids dropping it
    silently) but produces no session and therefore no finding.
    """
    records = {
        "logs/Security.evtx": [
            file_access_xml(
                object_name=r"C:\Users\analyst\Documents\quarterly_report.docx",
                when=BASE,
                record_id=1,
            ),
        ],
    }

    result = run_scenario(monkeypatch, evidence_dir, case_output_dir, records)

    assert len(result.events) == 1
    assert result.events[0].event_type == "file_access"
    assert result.sessions == ()
    assert result.findings == ()

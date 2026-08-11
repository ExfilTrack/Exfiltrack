"""Unit tests for the CSV findings table.

Related issue: #12 - JSON/CSV Export
"""

from __future__ import annotations

import csv
import io

import pytest

from exfiltrack.config import ScoringWeights
from exfiltrack.correlation.sessions import reconstruct_sessions
from exfiltrack.reporting.csv_report import FINDINGS_COLUMNS, render_findings_csv
from exfiltrack.reporting.model import assemble_findings
from tests.unit.factories import (
    make_device,
    make_file_event,
    make_insert_event,
    make_remove_event,
    utc,
)

WEIGHTS = ScoringWeights(protected_directories=(r"C:\Projects\confidential",))


def _rows(csv_text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(csv_text)))


def _findings_with_activity():
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 10, 0, 0), device),
        make_file_event(utc(2026, 1, 1, 9, 0, 10), r"C:\Projects\confidential\secrets.env"),
    ]
    sessions = reconstruct_sessions(events)
    return assemble_findings(sessions, weights=WEIGHTS)


@pytest.mark.unit
def test_header_matches_the_stable_column_order() -> None:
    text = render_findings_csv([])

    header = text.splitlines()[0].split(",")
    assert header == list(FINDINGS_COLUMNS)


@pytest.mark.unit
def test_one_row_per_score_contribution() -> None:
    findings = _findings_with_activity()
    expected_contribution_count = len(findings[0].scored_session.contributions)

    rows = _rows(render_findings_csv(findings))

    assert len(rows) == expected_contribution_count
    assert expected_contribution_count > 1  # sanity check on the fixture
    assert {r["session_id"] for r in rows} == {findings[0].session.session_id}


@pytest.mark.unit
def test_zero_score_session_still_gets_one_row() -> None:
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 9, 30, 0), device),
    ]
    sessions = reconstruct_sessions(events)
    findings = assemble_findings(sessions, weights=WEIGHTS)

    rows = _rows(render_findings_csv(findings))

    assert len(rows) == 1
    assert rows[0]["rule"] == ""
    assert rows[0]["total_score"] == "0"


@pytest.mark.unit
def test_multiple_source_artifacts_are_semicolon_joined() -> None:
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 10, 0, 0), device),
        make_file_event(utc(2026, 1, 1, 9, 20, 0), r"C:\Projects\confidential\a.docx"),
        make_file_event(utc(2026, 1, 1, 9, 25, 0), r"C:\Projects\confidential\b.docx"),
    ]
    sessions = reconstruct_sessions(events)
    findings = assemble_findings(sessions, weights=WEIGHTS)

    rows = _rows(render_findings_csv(findings))

    multi_file_row = next(r for r in rows if r["rule"] == "multiple_confidential_files")
    assert ";" in multi_file_row["rule_source_artifacts"]


@pytest.mark.unit
def test_empty_findings_produces_header_only() -> None:
    text = render_findings_csv([])

    assert len(text.splitlines()) == 1


@pytest.mark.unit
def test_output_is_byte_identical_across_runs_on_identical_input() -> None:
    """Required scenario (#12 Definition of Done): deterministic, byte-identical output."""
    findings = _findings_with_activity()

    first = render_findings_csv(findings)
    second = render_findings_csv(findings)

    assert first == second


@pytest.mark.unit
def test_confidence_and_boundary_observedness_are_included() -> None:
    findings = _findings_with_activity()

    rows = _rows(render_findings_csv(findings))

    assert rows[0]["confidence_level"] in {"NONE", "LOW", "MEDIUM", "HIGH", "CONFIRMED"}
    assert rows[0]["start_observed"] == "True"
    assert rows[0]["end_observed"] == "True"

"""Unit tests for the HTML report generator.

Related issue: #11 - HTML Report Generator
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from exfiltrack.config import ScoringWeights
from exfiltrack.correlation.sessions import reconstruct_sessions
from exfiltrack.evidence.manifest import CaseManifest, IntegrityVerdict, ParserRecord
from exfiltrack.reporting.html_report import ReportError, render_html_report
from exfiltrack.reporting.model import assemble_findings
from tests.unit.factories import (
    make_device,
    make_file_event,
    make_insert_event,
    make_remove_event,
    utc,
)

WEIGHTS = ScoringWeights(protected_directories=(r"C:\Projects\confidential",))
LIMITATIONS_TEXT = "Temporal correlation alone does not prove that a file was copied."


def _manifest(**overrides: object) -> CaseManifest:
    defaults: dict[str, object] = {
        "case_id": "CASE-001",
        "examiner": "J. Doe",
        "start_time": utc(2026, 1, 1, 8, 0, 0),
    }
    defaults.update(overrides)
    return CaseManifest(**defaults)  # type: ignore[arg-type]


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
def test_report_renders_without_error_for_a_normal_case() -> None:
    html = render_html_report(_findings_with_activity(), _manifest(), LIMITATIONS_TEXT)

    assert "<!DOCTYPE html>" in html
    assert "CASE-001" in html
    assert "J. Doe" in html


@pytest.mark.unit
def test_report_renders_without_error_for_zero_findings() -> None:
    html = render_html_report([], _manifest(), LIMITATIONS_TEXT)

    assert "No USB sessions were reconstructed" in html


@pytest.mark.unit
def test_report_never_contains_forbidden_proof_language() -> None:
    html = render_html_report(_findings_with_activity(), _manifest(), LIMITATIONS_TEXT)

    lowered = html.lower()
    for phrase in ("proved", "confirmed theft", "stole", "definitely exfiltrated"):
        assert phrase not in lowered


@pytest.mark.unit
def test_report_always_contains_the_required_disclaimer() -> None:
    html = render_html_report(_findings_with_activity(), _manifest(), LIMITATIONS_TEXT)

    assert "consistent with possible exfiltration" in html.lower()


@pytest.mark.unit
def test_observed_and_inferred_boundaries_are_visually_distinct() -> None:
    device = make_device()
    # Insert only: end boundary is inferred, no removal event.
    events = [make_insert_event(utc(2026, 1, 1, 9, 0, 0), device)]
    sessions = reconstruct_sessions(events)
    findings = assemble_findings(sessions, weights=WEIGHTS)

    html = render_html_report(findings, _manifest(), LIMITATIONS_TEXT)

    assert "badge-observed" in html
    assert "badge-inferred" in html
    assert 'class="badge badge-observed">\n                  Observed' in html or "Observed" in html
    assert "Inferred" in html


@pytest.mark.unit
def test_every_finding_cites_its_source_artifact() -> None:
    findings = _findings_with_activity()

    html = render_html_report(findings, _manifest(), LIMITATIONS_TEXT)

    source_artifact = findings[0].scored_session.contributions[0].source_artifacts[0]
    assert source_artifact in html


@pytest.mark.unit
def test_evidence_derived_values_are_escaped_not_executed() -> None:
    """A file path containing HTML/script syntax must never render as markup."""
    device = make_device()
    malicious_path = r"C:\Users\dev\<script>alert(1)</script>.txt"
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 10, 0, 0), device),
        make_file_event(utc(2026, 1, 1, 9, 30, 0), malicious_path),
    ]
    sessions = reconstruct_sessions(events)
    findings = assemble_findings(sessions, weights=WEIGHTS)

    html = render_html_report(findings, _manifest(), LIMITATIONS_TEXT)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


@pytest.mark.unit
def test_limitations_section_is_embedded_not_linked() -> None:
    html = render_html_report(_findings_with_activity(), _manifest(), LIMITATIONS_TEXT)

    assert LIMITATIONS_TEXT in html
    assert 'id="limitations"' in html


@pytest.mark.unit
def test_manifest_chain_of_custody_fields_are_present() -> None:
    manifest = _manifest(
        parser_records=[ParserRecord(name="evtx_parser", version="1.1.0")],
        integrity_verdict=IntegrityVerdict.VERIFIED,
    )

    html = render_html_report(_findings_with_activity(), manifest, LIMITATIONS_TEXT)

    assert "evtx_parser" in html
    assert "1.1.0" in html
    assert "verified" in html.lower()


@pytest.mark.unit
def test_zero_file_activity_session_renders_without_error() -> None:
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 9, 30, 0), device),
    ]
    sessions = reconstruct_sessions(events)
    findings = assemble_findings(sessions, weights=WEIGHTS)

    html = render_html_report(findings, _manifest(), LIMITATIONS_TEXT)

    assert "No file activity fell within this session" in html
    assert "No scoring rule fired" in html


@pytest.mark.unit
def test_missing_stylesheet_raises_report_error(tmp_path) -> None:
    (tmp_path / "report.html.j2").write_text("<html></html>", encoding="utf-8")

    with pytest.raises(ReportError):
        render_html_report([], _manifest(), LIMITATIONS_TEXT, templates_dir=tmp_path)


@pytest.mark.unit
def test_render_is_deterministic_given_the_same_inputs() -> None:
    findings = _findings_with_activity()
    manifest = _manifest()
    fixed_time = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)

    first = render_html_report(findings, manifest, LIMITATIONS_TEXT, generated_at=fixed_time)
    second = render_html_report(findings, manifest, LIMITATIONS_TEXT, generated_at=fixed_time)

    assert first == second

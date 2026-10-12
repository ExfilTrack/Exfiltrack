"""Unit tests for the HTML report generator.

Related issue: #11 - HTML Report Generator
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from markupsafe import escape

from exfiltrack.config import ScoringWeights
from exfiltrack.correlation.sessions import reconstruct_sessions
from exfiltrack.evidence.manifest import CaseManifest, IntegrityVerdict, ParserRecord
from exfiltrack.reporting.html_report import (
    ReportError,
    _rollup_contributions,
    build_finding_views,
    render_html_report,
    summarize_views,
    write_html_report,
)
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


def _acquisition_record(status: str = "collected", **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "category": "registry",
        "source": r"HKLM\SYSTEM",
        "method": "reg_save",
        "status": status,
        "started_at": "2026-01-01T08:00:05+00:00",
        "finished_at": "2026-01-01T08:00:10+00:00",
    }
    if status == "collected":
        record.update(destination="registry/SYSTEM", sha256="a" * 64)
    record.update(overrides)
    return record


def _acquisition(
    coverage: str = "complete", records: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "case_id": "CASE-001",
        "examiner": "Collection Examiner",
        "computer_name": "COLLECTION-VM",
        "start_time": "2026-01-01T08:00:00+00:00",
        "end_time": "2026-01-01T08:02:00+00:00",
        "coverage": coverage,
        "records": records if records is not None else [_acquisition_record()],
    }


def _parser_error(**overrides: str) -> dict[str, str]:
    record = {
        "source_artifact": "eventlogs/Security.evtx",
        "artifact_type": "evtx",
        "parser_name": "evtx_parser",
        "parser_version": "1.2.3",
        "error_type": "EvtxParseError",
        "message": "Record could not be decoded.",
    }
    record.update(overrides)
    return record


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

    with pytest.raises(ReportError, match="Cannot read stylesheet"):
        render_html_report([], _manifest(), LIMITATIONS_TEXT, templates_dir=tmp_path)


@pytest.mark.unit
def test_render_is_deterministic_given_the_same_inputs() -> None:
    findings = _findings_with_activity()
    manifest = _manifest()
    fixed_time = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)

    first = render_html_report(findings, manifest, LIMITATIONS_TEXT, generated_at=fixed_time)
    second = render_html_report(findings, manifest, LIMITATIONS_TEXT, generated_at=fixed_time)

    assert first == second


@pytest.mark.unit
@pytest.mark.parametrize(
    "overrides",
    [{}, {"acquisition": None}, {"parser_errors": []}, {"acquisition": None, "parser_errors": []}],
)
def test_manual_report_has_no_acquisition_section_or_live_disclaimer(overrides) -> None:
    fixed_time = utc(2026, 1, 2, 0, 0, 0)
    html = render_html_report([], _manifest(**overrides), LIMITATIONS_TEXT, generated_at=fixed_time)

    assert 'id="evidence-coverage"' not in html
    assert 'class="coverage-warning"' not in html
    assert "Live collection creates activity" not in html
    assert 'id="analysis-coverage"' not in html
    assert 'class="analysis-warning"' not in html
    assert "Partial analysis." not in html
    assert 'id="findings"' in html
    assert 'id="chain-of-custody"' in html
    assert 'id="limitations"' in html
    assert html == render_html_report([], _manifest(), LIMITATIONS_TEXT, generated_at=fixed_time)


@pytest.mark.unit
def test_complete_coverage_renders_collection_provenance_and_snapshots() -> None:
    acquisition = _acquisition(
        records=[
            _acquisition_record(metadata={"size_bytes": 2048}),
            _acquisition_record(
                category="event_log",
                source="Security",
                method="wevtutil_export",
                destination="eventlogs/Security.evtx",
                sha256="b" * 64,
                message="Collection completed with a diagnostic.",
            ),
        ]
    )
    html = render_html_report(
        _findings_with_activity(), _manifest(acquisition=acquisition), LIMITATIONS_TEXT
    )
    coverage = html.split('id="evidence-coverage"', 1)[1].split("</section>", 1)[0]

    assert "Evidence Coverage" in coverage
    assert 'class="badge badge-coverage-complete">Complete</span>' in coverage
    assert 'class="coverage-warning"' not in html
    for field in (
        "schema_version",
        "case_id",
        "examiner",
        "computer_name",
        "start_time",
        "end_time",
    ):
        assert acquisition[field] in coverage
    for record in acquisition["records"]:
        for field in (
            "category",
            "source",
            "method",
            "status",
            "started_at",
            "finished_at",
            "destination",
            "sha256",
        ):
            assert record[field] in coverage
    assert "Destination (relative to evidence root)" in coverage
    assert "SHA-256" in coverage
    assert "Collection completed with a diagnostic." in coverage
    assert "size_bytes" in coverage
    assert "2048" in coverage
    assert html.index('id="evidence-coverage"') < html.index('id="findings"')


@pytest.mark.unit
@pytest.mark.parametrize("status", ["missing", "unavailable", "error", "empty"])
def test_partial_coverage_highlights_uncollected_sources_before_findings(status: str) -> None:
    diagnostic = f"Collection diagnostic for {status}."
    acquisition = _acquisition(
        "partial",
        records=[
            _acquisition_record(),
            _acquisition_record(
                status,
                category="event_log",
                source="Security",
                method="wevtutil_export",
                message=diagnostic,
            ),
        ],
    )
    html = render_html_report(
        _findings_with_activity(), _manifest(acquisition=acquisition), LIMITATIONS_TEXT
    )
    coverage = html.split('id="evidence-coverage"', 1)[1].split("</section>", 1)[0]

    assert "Partial evidence coverage." in coverage
    assert 'class="badge badge-coverage-partial">Partial</span>' in coverage
    assert f'class="badge badge-acquisition-{status}">{status}</span>' in coverage
    assert diagnostic in coverage
    assert coverage.count("Destination (relative to evidence root)") == 1
    assert coverage.count("SHA-256") == 1
    assert html.index('class="coverage-warning"') < html.index('id="findings"')


@pytest.mark.unit
@pytest.mark.parametrize("coverage", ["complete", "partial"])
def test_live_collection_disclaimer_explains_snapshot_and_historical_limits(coverage: str) -> None:
    html = render_html_report([], _manifest(acquisition=_acquisition(coverage)), LIMITATIONS_TEXT)

    assert "Live collection creates activity on the collection machine." in html
    assert "Snapshots are not atomic." in html
    assert "The integrity verdict applies to collected snapshots" in html
    assert "Absent evidence does not mean absence of activity." in html
    assert "Enabling logging afterward cannot recover past events." in html
    assert "not completeness of historical activity" in html
    assert "consistent with possible exfiltration" in html


@pytest.mark.unit
@pytest.mark.parametrize("status", ["collected", "error"])
def test_acquisition_sources_diagnostics_and_metadata_are_autoescaped(status: str) -> None:
    source = r'C:\Users\<script>alert("source")</script>&.dat'
    message = '<img src=x onerror="alert(1)"> & diagnostic'
    destination = "<b>snapshot</b>.dat"
    metadata_key = "<b>detail</b>"
    metadata_value = '<script>alert("metadata")</script>'
    computer_name = '<img src=x onerror="alert(2)">'
    examiner = "<b>Collection Examiner</b>"
    method = "<b>copy</b>"
    acquisition = _acquisition(
        "complete" if status == "collected" else "partial",
        records=[
            _acquisition_record(
                status,
                source=source,
                method=method,
                destination=destination,
                message=message,
                metadata={metadata_key: metadata_value},
            )
        ],
    )
    acquisition.update(computer_name=computer_name, examiner=examiner)
    html = render_html_report([], _manifest(acquisition=acquisition), LIMITATIONS_TEXT)
    coverage = html.split('id="evidence-coverage"', 1)[1].split("</section>", 1)[0]

    for value in (source, message, metadata_key, metadata_value, computer_name, examiner, method):
        assert value not in coverage
        assert str(escape(value)) in coverage
    if status == "collected":
        assert destination not in coverage
        assert str(escape(destination)) in coverage
    assert "<script>" not in html
    assert "<img " not in html


@pytest.mark.unit
def test_partial_coverage_without_records_is_visible_with_no_findings() -> None:
    html = render_html_report(
        [], _manifest(acquisition=_acquisition("partial", records=[])), LIMITATIONS_TEXT
    )

    assert "Partial evidence coverage." in html
    assert "No acquisition records were supplied." in html
    assert "No USB sessions were reconstructed" in html
    assert html.index('class="coverage-warning"') < html.index('id="findings"')


@pytest.mark.unit
def test_explicit_template_directory_overrides_both_template_and_stylesheet(tmp_path: Path) -> None:
    (tmp_path / "report.html.j2").write_text(
        '{% include "heading.html.j2" %}<style>{{ inline_css }}</style>'
        "<p>Activity consistent with possible exfiltration.</p>"
        "<p>{{ limitations_text }}</p>",
        encoding="utf-8",
    )
    (tmp_path / "heading.html.j2").write_text(
        "<h1>Custom report: {{ manifest.case_id }}</h1>", encoding="utf-8"
    )
    custom_css = ".custom-report { color: purple; }"
    (tmp_path / "styles.css").write_text(custom_css, encoding="utf-8")

    html = render_html_report(
        [], _manifest(case_id="<b>CASE-OVERRIDE</b>"), LIMITATIONS_TEXT, templates_dir=tmp_path
    )

    assert "Custom report: &lt;b&gt;CASE-OVERRIDE&lt;/b&gt;" in html
    assert f"<style>{custom_css}</style>" in html
    assert LIMITATIONS_TEXT in html
    assert "--ink:" not in html
    assert "ExfilTrack Report" not in html


@pytest.mark.unit
def test_missing_override_template_raises_without_falling_back_to_package(tmp_path: Path) -> None:
    (tmp_path / "styles.css").write_text("body { color: purple; }", encoding="utf-8")

    with pytest.raises(ReportError, match="Cannot load template"):
        render_html_report([], _manifest(), LIMITATIONS_TEXT, templates_dir=tmp_path)


@pytest.mark.unit
def test_write_html_report_uses_packaged_resources_for_live_coverage(tmp_path: Path) -> None:
    manifest = _manifest(acquisition=_acquisition("partial"))
    generated_at = utc(2026, 1, 2, 0, 0, 0)
    output_dir = tmp_path / "case-output"

    destination = write_html_report(
        [], manifest, LIMITATIONS_TEXT, output_dir, generated_at=generated_at
    )

    assert destination == output_dir.resolve() / "report.html"
    assert destination.read_text(encoding="utf-8") == render_html_report(
        [], manifest, LIMITATIONS_TEXT, generated_at=generated_at
    )
    assert "Partial evidence coverage." in destination.read_text(encoding="utf-8")


@pytest.mark.unit
def test_acquisition_diagnostics_do_not_bypass_the_wording_guard() -> None:
    acquisition = _acquisition(
        "partial", records=[_acquisition_record("error", message="confirmed theft")]
    )

    with pytest.raises(ReportError, match="forbidden phrase 'confirmed theft'"):
        render_html_report([], _manifest(acquisition=acquisition), LIMITATIONS_TEXT)


@pytest.mark.unit
@pytest.mark.parametrize("coverage", [None, "complete", "partial"])
def test_parser_errors_warn_before_findings_independent_of_acquisition(
    coverage: str | None,
) -> None:
    record = _parser_error()
    acquisition = _acquisition(coverage) if coverage is not None else None
    manifest = _manifest(acquisition=acquisition, parser_errors=[record])

    html = render_html_report(_findings_with_activity(), manifest, LIMITATIONS_TEXT)
    analysis = html.split('id="analysis-coverage"', 1)[1].split("</section>", 1)[0]

    assert "Partial analysis." in analysis
    assert 'class="analysis-warning"' in analysis
    for value in record.values():
        assert value in analysis
    assert html.index('class="analysis-warning"') < html.index('id="findings"')
    if coverage is None:
        assert 'id="evidence-coverage"' not in html
    else:
        assert f'class="badge badge-coverage-{coverage}"' in html


@pytest.mark.unit
@pytest.mark.parametrize(
    "field",
    ["source_artifact", "artifact_type", "parser_name", "parser_version", "error_type", "message"],
)
def test_parser_error_fields_are_autoescaped(field: str) -> None:
    payload = '<script>alert("parser error")</script> & diagnostic'
    record = _parser_error(**{field: payload})

    html = render_html_report([], _manifest(parser_errors=[record]), LIMITATIONS_TEXT)
    analysis = html.split('id="analysis-coverage"', 1)[1].split("</section>", 1)[0]

    assert payload not in analysis
    assert str(escape(payload)) in analysis
    assert "<script>" not in html
    assert "Partial analysis." in analysis


@pytest.mark.unit
def test_parser_errors_remain_visible_when_no_findings_were_reconstructed() -> None:
    record = _parser_error()

    html = render_html_report([], _manifest(parser_errors=[record]), LIMITATIONS_TEXT)

    assert "Partial analysis." in html
    assert record["source_artifact"] in html
    assert record["parser_version"] in html
    assert "No USB sessions were reconstructed" in html
    assert html.index('class="analysis-warning"') < html.index('id="findings"')


@pytest.mark.unit
def test_acquisition_specific_limitations_are_displayed_and_autoescaped() -> None:
    limitations = [
        "Only standard Recent folders were examined.",
        '<script>alert("limitation")</script> & collection diagnostic',
    ]
    acquisition = _acquisition()
    acquisition["limitations"] = limitations

    html = render_html_report([], _manifest(acquisition=acquisition), LIMITATIONS_TEXT)
    coverage = html.split('id="evidence-coverage"', 1)[1].split("</section>", 1)[0]

    assert "Acquisition Limitations" in coverage
    for limitation in limitations:
        assert f"<li>{escape(limitation)}</li>" in coverage
    assert limitations[1] not in coverage
    assert "<script>" not in html
    assert "Snapshots are not atomic." in coverage


@pytest.mark.unit
@pytest.mark.parametrize("limitations", [None, []])
def test_missing_or_empty_acquisition_limitations_do_not_change_report(limitations) -> None:
    acquisition = _acquisition()
    if limitations is not None:
        acquisition["limitations"] = limitations
    when = utc(2026, 1, 2, 0, 0, 0)

    html = render_html_report(
        [], _manifest(acquisition=acquisition), LIMITATIONS_TEXT, generated_at=when
    )

    assert "Acquisition Limitations" not in html
    assert html == render_html_report(
        [], _manifest(acquisition=_acquisition()), LIMITATIONS_TEXT, generated_at=when
    )


# ---------------------------------------------------------------------------
# Restructured layout: executive summary, risk ordering, collapsed evidence
# ---------------------------------------------------------------------------


def _two_sessions_risk_order():
    """Two observed sessions: the chronologically earlier one is risk-free.

    The later session scores 60 (30s activity + sensitive extension +
    protected directory), reaching High; the earlier one scores 0 (None).
    Chronological order and risk order therefore disagree, which is what the
    restructured layout must resolve in the reader's favor.
    """
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 8, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 8, 30, 0), device),
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 10, 0, 0), device),
        make_file_event(utc(2026, 1, 1, 9, 0, 10), r"C:\Projects\confidential\secrets.env"),
    ]
    sessions = reconstruct_sessions(events)
    return assemble_findings(sessions, weights=WEIGHTS)


def _findings_section(html: str) -> str:
    return html.split('id="findings"', 1)[1]


def _session_blocks(html: str) -> list[str]:
    return _findings_section(html).split('<details class="session"')[1:]


@pytest.mark.unit
def test_executive_summary_reports_case_level_figures_before_findings() -> None:
    html = render_html_report(_two_sessions_risk_order(), _manifest(), LIMITATIONS_TEXT)
    summary = html.split('id="summary"', 1)[1].split("</section>", 1)[0]

    assert "2 USB session(s)" in summary
    assert "1 device(s)" in summary
    assert "1 file event(s)" in summary
    assert "Highest confidence:" in summary
    assert 'class="badge badge-confidence-high">High</span>' in summary
    assert "Highest session score: <strong>60</strong>" in summary
    assert html.index('id="summary"') < html.index('id="findings"')


@pytest.mark.unit
def test_summary_table_lists_sessions_highest_risk_first_with_anchor_links() -> None:
    html = render_html_report(_two_sessions_risk_order(), _manifest(), LIMITATIONS_TEXT)
    table = html.split('class="summary-table"', 1)[1].split("</table>", 1)[0]

    assert table.index('href="#session-1"') < table.index('href="#session-2"')
    # The riskiest session is the later (High) one, so session-1 carries its score.
    first_row = table.split("</thead>", 1)[1].split("</tr>", 1)[0]
    assert ">60</td>" in first_row
    assert "badge-confidence-high" in first_row


@pytest.mark.unit
def test_findings_are_ordered_highest_risk_first_with_stable_anchors() -> None:
    findings = _two_sessions_risk_order()
    # assemble_findings returns chronological order; the view must re-order.
    assert findings[0].scored_session.total_score == 0

    views = build_finding_views(findings)

    assert [view.anchor for view in views] == ["session-1", "session-2"]
    assert views[0].finding.scored_session.total_score == 60
    assert views[1].finding.scored_session.total_score == 0

    html = render_html_report(findings, _manifest(), LIMITATIONS_TEXT)
    blocks = _session_blocks(html)
    assert len(blocks) == 2
    assert "secrets.env" in blocks[0]
    assert "secrets.env" not in blocks[1]


@pytest.mark.unit
def test_only_the_highest_risk_session_is_expanded_by_default() -> None:
    html = render_html_report(_two_sessions_risk_order(), _manifest(), LIMITATIONS_TEXT)

    assert '<details class="session" id="session-1" open>' in html
    assert '<details class="session" id="session-2">' in html


@pytest.mark.unit
def test_zero_findings_summary_and_no_sessions_render() -> None:
    html = render_html_report([], _manifest(), LIMITATIONS_TEXT)

    assert 'id="summary"' in html
    assert "<details" not in _findings_section(html)
    assert "No USB sessions were reconstructed" in html


@pytest.mark.unit
def test_repeated_rule_firings_are_aggregated_and_fully_retained() -> None:
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 10, 0, 0), device),
        make_file_event(utc(2026, 1, 1, 9, 0, 10), r"C:\Projects\confidential\a.env"),
        make_file_event(utc(2026, 1, 1, 9, 0, 20), r"C:\Projects\confidential\b.env"),
    ]
    findings = assemble_findings(reconstruct_sessions(events), weights=WEIGHTS)
    contributions = findings[0].scored_session.contributions

    rollups = {rollup.rule: rollup for rollup in _rollup_contributions(contributions)}

    assert len(rollups["sensitive_extension"].firings) == 2
    assert rollups["sensitive_extension"].total_points == 30
    assert len(rollups["activity_within_30s"].firings) == 2
    assert rollups["activity_within_30s"].total_points == 50
    assert len(rollups["multiple_confidential_files"].firings) == 1
    # The rollup is a view concern only: every firing survives in the data.
    assert len(contributions) == 7

    html = render_html_report(findings, _manifest(), LIMITATIONS_TEXT)

    assert html.count("Show 2 firings") == 3
    # Collapsed, but every firing's explanation and path is still present.
    assert "a.env" in html and "b.env" in html
    assert "within the 30-second window" in html


@pytest.mark.unit
def test_long_file_activity_tables_are_collapsed_but_complete() -> None:
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 23, 59, 0), device),
    ]
    for minute in range(25):
        events.append(
            make_file_event(utc(2026, 1, 1, 12, minute, 0), rf"C:\data\file_{minute:02d}.txt")
        )
    findings = assemble_findings(reconstruct_sessions(events), weights=WEIGHTS)

    html = render_html_report(findings, _manifest(), LIMITATIONS_TEXT)

    assert "25 file events fell within this session's" in html
    assert "Show the remaining 5 events" in html
    # Collapsed rows are still rendered: nothing is truncated out of the report.
    assert "file_00.txt" in html
    assert "file_24.txt" in html


@pytest.mark.unit
def test_short_file_activity_tables_render_without_collapsing() -> None:
    html = render_html_report(_findings_with_activity(), _manifest(), LIMITATIONS_TEXT)

    assert "more-events" not in _findings_section(html)
    assert "secrets.env" in html


@pytest.mark.unit
def test_nav_links_to_every_rendered_section() -> None:
    manifest = _manifest(acquisition=_acquisition(), parser_errors=[_parser_error()])
    html = render_html_report(_findings_with_activity(), manifest, LIMITATIONS_TEXT)
    nav = html.split('class="report-nav"', 1)[1].split("</nav>", 1)[0]

    for anchor in (
        "#summary",
        "#evidence-coverage",
        "#analysis-coverage",
        "#findings",
        "#chain-of-custody",
        "#limitations",
    ):
        assert f'href="{anchor}"' in nav


@pytest.mark.unit
def test_nav_omits_sections_that_are_not_rendered() -> None:
    html = render_html_report([], _manifest(), LIMITATIONS_TEXT)
    nav = html.split('class="report-nav"', 1)[1].split("</nav>", 1)[0]

    assert "#evidence-coverage" not in nav
    assert "#analysis-coverage" not in nav
    assert "#findings" in nav


@pytest.mark.unit
def test_summary_surfaces_partial_coverage_and_parser_errors_up_front() -> None:
    manifest = _manifest(
        acquisition=_acquisition("partial", records=[_acquisition_record("missing")]),
        parser_errors=[_parser_error()],
    )

    html = render_html_report(_findings_with_activity(), manifest, LIMITATIONS_TEXT)
    summary = html.split('id="summary"', 1)[1].split("</section>", 1)[0]

    assert "Analysis is partial" in summary
    assert "Evidence collection coverage is partial" in summary
    assert 'href="#analysis-coverage"' in summary
    assert 'href="#evidence-coverage"' in summary


@pytest.mark.unit
def test_summarize_views_handles_zero_findings() -> None:
    summary = summarize_views(build_finding_views([]))

    assert summary.session_count == 0
    assert summary.device_count == 0
    assert summary.highest_confidence == ""


@pytest.mark.unit
def test_risk_order_ties_fall_back_to_start_time_for_determinism() -> None:
    first = make_device(device_id="USB\\VID_0001&PID_0001\\SERIALAAA", serial_number="SERIALAAA")
    second = make_device(device_id="USB\\VID_0002&PID_0002\\SERIALBBB", serial_number="SERIALBBB")
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), second),
        make_remove_event(utc(2026, 1, 1, 9, 30, 0), second),
        make_insert_event(utc(2026, 1, 1, 8, 0, 0), first),
        make_remove_event(utc(2026, 1, 1, 8, 30, 0), first),
    ]
    findings = assemble_findings(reconstruct_sessions(events), weights=WEIGHTS)

    views = build_finding_views(findings)

    # Equal risk on both: the earlier session must come first, every time.
    assert views[0].finding.session.start.timestamp_utc == utc(2026, 1, 1, 8, 0, 0)
    assert views[1].finding.session.start.timestamp_utc == utc(2026, 1, 1, 9, 0, 0)

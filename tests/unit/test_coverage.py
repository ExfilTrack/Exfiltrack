"""Unit tests for the evidence coverage model and its report rendering.

Related issue: #34 - Add Evidence Coverage section to reports

The Definition-of-Done scenarios are: a full-coverage run, a run with
missing sources (the "missing-directory" case), and a supplied-but-empty
EVTX run. Rendering and pipeline wiring tests live at the bottom.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from exfiltrack.evidence.intake import ArtifactRecord, ArtifactType
from exfiltrack.reporting.coverage import (
    EVTX_DRIVERFRAMEWORKS,
    EVTX_OTHER,
    EVTX_SECURITY,
    JUMPLISTS,
    LNK,
    REGISTRY,
    EvidenceCoverage,
    SourceCoverage,
    SourceStatus,
    build_coverage,
)
from tests.unit.factories import make_device, make_file_event, make_insert_event, utc

LIMITATIONS_TEXT = "Temporal correlation alone does not prove that a file was copied."


def _artifact(tmp_path: Path, name: str, artifact_type: ArtifactType) -> ArtifactRecord:
    """An intake record for *name*; the file need not exist for coverage math."""
    return ArtifactRecord(
        path=tmp_path / "evidence" / name,
        artifact_type=artifact_type,
        size_bytes=100,
        intake_digest="ab" * 32,
    )


def _by_source(coverage: EvidenceCoverage) -> dict[str, SourceCoverage]:
    return {row.source: row for row in coverage.sources}


@pytest.mark.unit
def test_full_coverage_run_marks_every_source_present(tmp_path: Path) -> None:
    artifacts = [
        _artifact(tmp_path, "SYSTEM", ArtifactType.REGISTRY),
        _artifact(
            tmp_path,
            "Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",
            ArtifactType.EVTX,
        ),
        _artifact(tmp_path, "Security.evtx", ArtifactType.EVTX),
        _artifact(tmp_path, "doc.lnk", ArtifactType.LNK),
        _artifact(tmp_path, "app.automaticDestinations-ms", ArtifactType.JUMP_LIST),
    ]
    device = make_device()
    events = [
        make_insert_event(
            utc(2026, 3, 1, 9, 0, 0), device, source_artifact=artifacts[0].path.as_posix()
        ),
        make_insert_event(
            utc(2026, 3, 1, 9, 0, 1), device, source_artifact=artifacts[1].path.as_posix()
        ),
        make_file_event(
            utc(2026, 3, 1, 9, 0, 5), r"E:\a.sql", source_artifact=artifacts[2].path.as_posix()
        ),
        make_file_event(
            utc(2026, 3, 1, 9, 0, 6), r"E:\b.txt", source_artifact=artifacts[3].path.as_posix()
        ),
        make_file_event(
            utc(2026, 3, 1, 9, 0, 7), r"E:\c.txt", source_artifact=artifacts[4].path.as_posix()
        ),
    ]

    coverage = build_coverage(artifacts, events)

    assert coverage.is_complete
    by_source = _by_source(coverage)
    assert set(by_source) == {REGISTRY, EVTX_DRIVERFRAMEWORKS, EVTX_SECURITY, LNK, JUMPLISTS}
    assert all(row.status is SourceStatus.PRESENT for row in coverage.sources)
    assert all(row.note == "" for row in coverage.sources)
    assert by_source[EVTX_SECURITY].event_count == 1
    assert by_source[REGISTRY].supplied == 1

    payload = coverage.to_dict()
    assert payload["complete"] is True
    assert [row["source"] for row in payload["sources"]] == [
        REGISTRY,
        EVTX_DRIVERFRAMEWORKS,
        EVTX_SECURITY,
        LNK,
        JUMPLISTS,
    ]


@pytest.mark.unit
def test_missing_sources_are_absent_with_named_causes(tmp_path: Path) -> None:
    """The 'missing-directory' run: only registry and DriverFrameworks supplied."""
    artifacts = [
        _artifact(tmp_path, "SYSTEM", ArtifactType.REGISTRY),
        _artifact(tmp_path, "driverframeworks_operational.evtx", ArtifactType.EVTX),
    ]
    device = make_device()
    events = [
        make_insert_event(
            utc(2026, 3, 1, 9, 0, 0), device, source_artifact=artifacts[1].path.as_posix()
        )
    ]

    coverage = build_coverage(artifacts, events)

    assert not coverage.is_complete
    by_source = _by_source(coverage)
    assert by_source[REGISTRY].status is SourceStatus.EMPTY  # supplied, but no events
    assert by_source[EVTX_DRIVERFRAMEWORKS].status is SourceStatus.PRESENT
    assert by_source[EVTX_SECURITY].status is SourceStatus.ABSENT
    assert "SACL" in by_source[EVTX_SECURITY].note
    assert by_source[LNK].status is SourceStatus.ABSENT
    assert "deleted" in by_source[LNK].note
    assert by_source[JUMPLISTS].status is SourceStatus.ABSENT


@pytest.mark.unit
def test_absent_driverframeworks_names_the_disabled_channel(tmp_path: Path) -> None:
    coverage = build_coverage([_artifact(tmp_path, "SYSTEM", ArtifactType.REGISTRY)], [])
    row = _by_source(coverage)[EVTX_DRIVERFRAMEWORKS]
    assert row.status is SourceStatus.ABSENT
    assert "disabled by default" in row.note
    assert "wevtutil" in row.note


@pytest.mark.unit
def test_supplied_but_empty_evtx_distinguishes_empty_from_absent(tmp_path: Path) -> None:
    """The 'supplied-but-empty EVTX' run: a parsed log with no records of interest."""
    artifacts = [_artifact(tmp_path, "Security.evtx", ArtifactType.EVTX)]

    coverage = build_coverage(artifacts, [])

    security = _by_source(coverage)[EVTX_SECURITY]
    assert security.status is SourceStatus.EMPTY
    assert security.supplied == 1
    assert security.parsed == 1
    assert security.event_count == 0
    assert "object-access auditing" in security.note


@pytest.mark.unit
def test_parse_failure_lowers_parsed_but_keeps_supplied(tmp_path: Path) -> None:
    artifacts = [
        _artifact(
            tmp_path,
            "Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",
            ArtifactType.EVTX,
        ),
        _artifact(tmp_path, "driverframeworks-copy.evtx", ArtifactType.EVTX),
    ]
    device = make_device()
    events = [
        make_insert_event(
            utc(2026, 3, 1, 9, 0, 0), device, source_artifact=artifacts[0].path.as_posix()
        )
    ]
    errors = [{"source_artifact": artifacts[1].path.as_posix(), "message": "bad XML"}]

    row = _by_source(build_coverage(artifacts, events, parser_errors=errors))[EVTX_DRIVERFRAMEWORKS]
    assert row.status is SourceStatus.PRESENT
    assert row.supplied == 2
    assert row.parsed == 1
    assert "1 artifact(s) failed to parse" in row.note


@pytest.mark.unit
def test_unknown_artifacts_are_not_coverage_sources(tmp_path: Path) -> None:
    coverage = build_coverage([_artifact(tmp_path, "readme.txt", ArtifactType.UNKNOWN)], [])
    assert all(row.supplied == 0 for row in coverage.sources)
    assert not coverage.is_complete


@pytest.mark.unit
def test_other_evtx_bucket_appears_only_when_supplied(tmp_path: Path) -> None:
    without_other = build_coverage([], [])
    assert EVTX_OTHER not in _by_source(without_other)

    artifact = _artifact(tmp_path, "System.evtx", ArtifactType.EVTX)
    device = make_device()
    events = [
        make_insert_event(
            utc(2026, 3, 1, 9, 0, 0), device, source_artifact=artifact.path.as_posix()
        )
    ]
    with_other = _by_source(build_coverage([artifact], events))
    assert with_other[EVTX_OTHER].status is SourceStatus.PRESENT
    assert with_other[EVTX_OTHER].event_count == 1


# ---------------------------------------------------------------------------
# Rendering: HTML section and CSV table
# ---------------------------------------------------------------------------


def _mixed_coverage() -> EvidenceCoverage:
    return EvidenceCoverage(
        sources=(
            SourceCoverage(REGISTRY, SourceStatus.PRESENT, 2, 2, 150),
            SourceCoverage(
                EVTX_DRIVERFRAMEWORKS,
                SourceStatus.ABSENT,
                0,
                0,
                0,
                "The DriverFrameworks channel is disabled by default.",
            ),
            SourceCoverage(
                EVTX_SECURITY,
                SourceStatus.EMPTY,
                1,
                1,
                0,
                "Supplied but contained 0 file-access events.",
            ),
            SourceCoverage(LNK, SourceStatus.PRESENT, 37, 37, 37),
            SourceCoverage(JUMPLISTS, SourceStatus.ABSENT, 0, 0, 0, "No Jump Lists supplied."),
        )
    )


@pytest.mark.unit
def test_html_report_renders_source_coverage_section() -> None:
    from exfiltrack.evidence.manifest import CaseManifest
    from exfiltrack.reporting.html_report import render_html_report

    manifest = CaseManifest(
        case_id="CASE-001", examiner="J. Doe", start_time=utc(2026, 1, 1, 8, 0, 0)
    )
    manifest.coverage = _mixed_coverage().to_dict()

    html = render_html_report([], manifest, LIMITATIONS_TEXT)

    section = html.split('id="source-coverage"', 1)[1].split("</section>", 1)[0]
    assert "Evidence Coverage by Source" in section
    assert "Evidence coverage is not complete." in section
    assert 'badge-source-present' in section
    assert 'badge-source-absent' in section
    assert 'badge-source-empty' in section
    assert "disabled by default" in section
    assert "registry" in section


@pytest.mark.unit
def test_html_report_omits_source_coverage_when_manifest_has_none() -> None:
    from exfiltrack.evidence.manifest import CaseManifest
    from exfiltrack.reporting.html_report import render_html_report

    manifest = CaseManifest(
        case_id="CASE-001", examiner="J. Doe", start_time=utc(2026, 1, 1, 8, 0, 0)
    )
    html = render_html_report([], manifest, LIMITATIONS_TEXT)
    assert 'id="source-coverage"' not in html


@pytest.mark.unit
def test_html_report_hides_coverage_warning_when_complete() -> None:
    from exfiltrack.evidence.manifest import CaseManifest
    from exfiltrack.reporting.html_report import render_html_report

    manifest = CaseManifest(
        case_id="CASE-001", examiner="J. Doe", start_time=utc(2026, 1, 1, 8, 0, 0)
    )
    manifest.coverage = EvidenceCoverage(
        sources=(SourceCoverage(REGISTRY, SourceStatus.PRESENT, 1, 1, 3),)
    ).to_dict()
    html = render_html_report([], manifest, LIMITATIONS_TEXT)
    section = html.split('id="source-coverage"', 1)[1].split("</section>", 1)[0]
    assert "Evidence coverage is not complete." not in section


@pytest.mark.unit
def test_coverage_csv_round_trips_all_rows(tmp_path: Path) -> None:
    import csv as csv_module

    from exfiltrack.reporting.csv_report import render_coverage_csv, write_coverage_csv

    coverage = _mixed_coverage()
    text = render_coverage_csv(coverage)
    rows = list(csv_module.DictReader(text.splitlines()))
    assert [row["source"] for row in rows] == [
        REGISTRY,
        EVTX_DRIVERFRAMEWORKS,
        EVTX_SECURITY,
        LNK,
        JUMPLISTS,
    ]
    assert rows[1]["status"] == "absent"
    assert rows[1]["supplied"] == "0"
    assert "disabled by default" in rows[1]["note"]
    assert render_coverage_csv(coverage) == text  # deterministic

    written = write_coverage_csv(coverage, tmp_path)
    assert written.name == "coverage.csv"
    assert written.read_text(encoding="utf-8") == text

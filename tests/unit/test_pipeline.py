"""Unit tests for the pipeline orchestration added for #13.

These check the wiring's own behaviour in isolation (empty evidence, an
unrecognised file, ``write_reports=False``). The four controlled scenarios
and the reproducibility/integrity checks live in ``tests/integration/``,
since they exercise the pipeline end to end rather than one seam at a time.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from exfiltrack.config import CaseConfig
from exfiltrack.evidence.hashing import hash_file
from exfiltrack.evidence.intake import ArtifactType
from exfiltrack.parsers.evtx_parser import EvtxParseError
from exfiltrack.pipeline import _DISPATCH, PipelineError, run_pipeline
from tests.support.synthetic_evtx import (
    SyntheticEvtxReader,
    device_lifecycle_xml,
    placeholder_evtx_file,
)

WHEN = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)


@pytest.mark.unit
def test_run_pipeline_raises_on_empty_evidence_directory(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    config = CaseConfig(
        evidence_dir=evidence_dir,
        case_output_dir=tmp_path / "case",
        case_id="CASE-0001",
        examiner="M. Weerawarna",
    )

    with pytest.raises(PipelineError, match="No evidence artifacts found"):
        run_pipeline(config)


@pytest.mark.unit
def test_run_pipeline_skips_unrecognised_files_without_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    # An artifact discover_artifacts cannot classify: no known magic bytes,
    # no name-based suffix. It must still be discovered and hashed into the
    # manifest (Non-Negotiable #4), just contribute no events.
    (evidence_dir / "readme.txt").write_bytes(b"not forensic evidence")

    evtx_path = evidence_dir / "logs" / "System.evtx"
    placeholder_evtx_file(evtx_path)
    record = device_lifecycle_xml(
        event_id="2003",
        device_instance_id=r"USB\VID_1234&PID_5678\SERIAL001",
        when=WHEN,
        record_id=1,
    )
    monkeypatch.setattr(
        "exfiltrack.parsers.evtx_parser.evtx.Evtx",
        SyntheticEvtxReader({evtx_path.resolve().as_posix(): [record]}),
    )

    config = CaseConfig(
        evidence_dir=evidence_dir,
        case_output_dir=tmp_path / "case",
        case_id="CASE-0002",
        examiner="M. Weerawarna",
    )

    result = run_pipeline(config, write_reports=False)

    assert len(result.artifacts) == 2
    assert len(result.manifest.intake_digests) == 2
    assert len(result.events) == 1
    assert result.events[0].event_type == "usb_insert"


@pytest.mark.unit
def test_run_pipeline_with_write_reports_false_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    case_output_dir = tmp_path / "case"

    evtx_path = evidence_dir / "System.evtx"
    placeholder_evtx_file(evtx_path)
    record = device_lifecycle_xml(
        event_id="2003",
        device_instance_id=r"USB\VID_1234&PID_5678\SERIAL001",
        when=WHEN,
        record_id=1,
    )
    monkeypatch.setattr(
        "exfiltrack.parsers.evtx_parser.evtx.Evtx",
        SyntheticEvtxReader({evtx_path.resolve().as_posix(): [record]}),
    )

    config = CaseConfig(
        evidence_dir=evidence_dir,
        case_output_dir=case_output_dir,
        case_id="CASE-0003",
        examiner="M. Weerawarna",
    )

    result = run_pipeline(config, write_reports=False)

    assert result.report_paths == {}
    assert not case_output_dir.exists()


DEVICE = r"USB\VID_1234&PID_5678\SERIAL001"


def _two_artifact_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[CaseConfig, Path, Path]:
    """Evidence with one parsable System.evtx and one unparsable Security.evtx."""
    evidence_dir = tmp_path / "evidence"
    good = evidence_dir / "System.evtx"
    bad = evidence_dir / "Security.evtx"
    placeholder_evtx_file(good)
    placeholder_evtx_file(bad)
    record = device_lifecycle_xml(
        event_id="2003", device_instance_id=DEVICE, when=WHEN, record_id=1
    )
    # Security.evtx is deliberately not registered: the double raises for it, which
    # parse_evtx reports as an EvtxParseError, as it would for a corrupt log.
    monkeypatch.setattr(
        "exfiltrack.parsers.evtx_parser.evtx.Evtx",
        SyntheticEvtxReader({good.resolve().as_posix(): [record]}),
    )
    config = CaseConfig(
        evidence_dir=evidence_dir,
        case_output_dir=tmp_path / "case",
        case_id="CASE-0004",
        examiner="M. Weerawarna",
    )
    return config, good, bad


def _acquisition_for(*paths: Path, root: Path) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "case_id": "CASE-0004",
        "examiner": "M. Weerawarna",
        "computer_name": "SYNTHETIC-VM",
        "start_time": "2026-03-01T09:00:00+00:00",
        "end_time": "2026-03-01T09:00:05+00:00",
        "coverage": "complete",
        "records": [
            {
                "category": "evtx",
                "source": path.stem,
                "method": "wevtutil epl",
                "status": "collected",
                "started_at": "2026-03-01T09:00:00+00:00",
                "finished_at": "2026-03-01T09:00:01+00:00",
                "destination": path.relative_to(root).as_posix(),
                "sha256": hash_file(path),
                "metadata": {},
            }
            for path in paths
        ],
    }


@pytest.mark.unit
def test_strict_run_aborts_on_the_first_parser_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, _good, _bad = _two_artifact_evidence(monkeypatch, tmp_path)

    with pytest.raises(EvtxParseError, match="Security.evtx"):
        run_pipeline(config, write_reports=False)


@pytest.mark.unit
def test_continue_on_parser_error_records_failure_and_keeps_other_events(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, _good, bad = _two_artifact_evidence(monkeypatch, tmp_path)

    result = run_pipeline(config, write_reports=False, continue_on_parser_error=True)

    assert [e.event_type for e in result.events] == ["usb_insert"]
    [error] = result.manifest.parser_errors
    assert error["source_artifact"] == bad.resolve().as_posix()
    assert error["artifact_type"] == "evtx_log"
    assert error["parser_name"] == "evtx_parser"
    assert error["parser_version"]
    assert error["error_type"] == "EvtxParseError"
    assert "Security.evtx" in error["message"]
    assert result.manifest.to_dict()["parser_errors"] == [error]


@pytest.mark.unit
def test_manual_manifest_layout_has_no_acquisition_or_parser_error_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence_dir = tmp_path / "evidence"
    evtx_path = evidence_dir / "System.evtx"
    placeholder_evtx_file(evtx_path)
    record = device_lifecycle_xml(
        event_id="2003", device_instance_id=DEVICE, when=WHEN, record_id=1
    )
    monkeypatch.setattr(
        "exfiltrack.parsers.evtx_parser.evtx.Evtx",
        SyntheticEvtxReader({evtx_path.resolve().as_posix(): [record]}),
    )
    config = CaseConfig(
        evidence_dir=evidence_dir,
        case_output_dir=tmp_path / "case",
        case_id="CASE-0005",
        examiner="M. Weerawarna",
    )

    result = run_pipeline(config)

    payload = json.loads(result.report_paths["manifest"].read_text(encoding="utf-8"))
    assert "acquisition" not in payload
    assert "parser_errors" not in payload


@pytest.mark.unit
def test_acquisition_is_embedded_in_manifest_and_reports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, good, bad = _two_artifact_evidence(monkeypatch, tmp_path)
    acquisition = _acquisition_for(good, bad, root=config.evidence_dir)

    result = run_pipeline(config, acquisition=acquisition, continue_on_parser_error=True)

    manifest_json = json.loads(result.report_paths["manifest"].read_text(encoding="utf-8"))
    assert manifest_json["acquisition"]["computer_name"] == "SYNTHETIC-VM"
    findings_json = json.loads(result.report_paths["json"].read_text(encoding="utf-8"))
    assert findings_json["manifest"]["acquisition"] == manifest_json["acquisition"]
    assert findings_json["manifest"]["parser_errors"] == manifest_json["parser_errors"]
    assert "Evidence Coverage" in result.report_paths["html"].read_text(encoding="utf-8")


@pytest.mark.unit
@pytest.mark.parametrize("problem", ["modified", "deleted", "extra"])
def test_acquisition_mismatch_is_refused_before_any_parsing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, problem: str
) -> None:
    config, good, bad = _two_artifact_evidence(monkeypatch, tmp_path)
    acquisition = _acquisition_for(good, bad, root=config.evidence_dir)
    if problem == "modified":
        bad.write_bytes(bad.read_bytes() + b"tampered")
    elif problem == "deleted":
        bad.unlink()
    else:
        (config.evidence_dir / "planted.txt").write_bytes(b"not collected")

    parsed: list[Path] = []

    def record_parse(path: Path) -> list[object]:
        parsed.append(path)
        return []

    monkeypatch.setitem(_DISPATCH, ArtifactType.EVTX, record_parse)

    with pytest.raises(PipelineError, match="no longer matches the acquisition manifest"):
        run_pipeline(
            config, write_reports=False, acquisition=acquisition, continue_on_parser_error=True
        )

    assert parsed == []
    assert not (tmp_path / "case").exists()


@pytest.mark.unit
def test_run_pipeline_reports_monotonic_stage_progress(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The GUI's percentage bar rides on these fractions (issue #65)."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evtx_path = evidence_dir / "System.evtx"
    placeholder_evtx_file(evtx_path)
    record = device_lifecycle_xml(
        event_id="2003",
        device_instance_id=r"USB\VID_1234&PID_5678\SERIAL001",
        when=WHEN,
        record_id=1,
    )
    monkeypatch.setattr(
        "exfiltrack.parsers.evtx_parser.evtx.Evtx",
        SyntheticEvtxReader({evtx_path.resolve().as_posix(): [record]}),
    )
    config = CaseConfig(
        evidence_dir=evidence_dir,
        case_output_dir=tmp_path / "case",
        case_id="CASE-PROG",
        examiner="J. Doe",
    )

    calls: list[tuple[str, float]] = []
    run_pipeline(config, progress=lambda stage, fraction: calls.append((stage, fraction)))

    stages = [stage for stage, _ in calls]
    fractions = [fraction for _, fraction in calls]
    assert fractions[0] == 0.0
    assert fractions[-1] == 1.0
    assert fractions == sorted(fractions)  # monotonically non-decreasing
    assert all(0.0 <= fraction <= 1.0 for fraction in fractions)
    assert "Parsing 1/1" in stages
    assert "Writing reports" in stages


@pytest.mark.unit
def test_run_pipeline_without_progress_callback_still_works(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The hook is optional: existing callers (the CLI) are unaffected."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evtx_path = evidence_dir / "System.evtx"
    placeholder_evtx_file(evtx_path)
    record = device_lifecycle_xml(
        event_id="2003",
        device_instance_id=r"USB\VID_1234&PID_5678\SERIAL001",
        when=WHEN,
        record_id=1,
    )
    monkeypatch.setattr(
        "exfiltrack.parsers.evtx_parser.evtx.Evtx",
        SyntheticEvtxReader({evtx_path.resolve().as_posix(): [record]}),
    )
    config = CaseConfig(
        evidence_dir=evidence_dir,
        case_output_dir=tmp_path / "case",
        case_id="CASE-NOPROG",
        examiner="J. Doe",
    )
    result = run_pipeline(config, write_reports=False)
    assert len(result.events) == 1


# ---------------------------------------------------------------------------
# Analysis window (issue #68)
# ---------------------------------------------------------------------------

_OLD = datetime(2026, 1, 10, 9, 0, 0, tzinfo=timezone.utc)
_CUTOFF = datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc)


def _window_scenario(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[CaseConfig, dict[str, list[str]]]:
    """One pre-cutoff insert and one post-cutoff insert/remove pair."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    sys_log = evidence_dir / "System.evtx"
    placeholder_evtx_file(sys_log)
    records = {
        sys_log.resolve().as_posix(): [
            device_lifecycle_xml(
                event_id="2003",
                device_instance_id=r"USB\VID_1234&PID_5678\OLDSTICK",
                when=_OLD,
                record_id=1,
            ),
            device_lifecycle_xml(
                event_id="2003",
                device_instance_id=r"USB\VID_1234&PID_5678\NEWSTICK",
                when=WHEN,
                record_id=2,
            ),
            device_lifecycle_xml(
                event_id="2102",
                device_instance_id=r"USB\VID_1234&PID_5678\NEWSTICK",
                when=WHEN + timedelta(minutes=5),
                record_id=3,
            ),
        ]
    }
    monkeypatch.setattr("exfiltrack.parsers.evtx_parser.evtx.Evtx", SyntheticEvtxReader(records))
    config = CaseConfig(
        evidence_dir=evidence_dir,
        case_output_dir=tmp_path / "case",
        case_id="CASE-WINDOW",
        examiner="J. Doe",
    )
    return config, records


@pytest.mark.unit
def test_events_since_filters_timeline_and_records_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, _records = _window_scenario(monkeypatch, tmp_path)
    result = run_pipeline(config, events_since=_CUTOFF)

    assert len(result.events) == 2
    assert all(event.timestamp_utc >= _CUTOFF for event in result.events)
    assert result.manifest.analysis_window == {
        "since": _CUTOFF.isoformat(),
        "excluded_events": 1,
    }
    assert len(result.sessions) == 1
    assert result.sessions[0].boundary_sources == ("event_log", "event_log")

    payload = json.loads(result.report_paths["manifest"].read_text(encoding="utf-8"))
    assert payload["analysis_window"]["since"] == _CUTOFF.isoformat()
    assert payload["analysis_window"]["excluded_events"] == 1
    html = result.report_paths["html"].read_text(encoding="utf-8")
    assert "Analysis window" in html
    assert _CUTOFF.isoformat() in html


@pytest.mark.unit
def test_events_since_straddling_session_reconstructs_as_orphan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Insert before the cutoff + removal after it: the start is inferred and
    the #35 partial-coverage marker discloses it."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    sys_log = evidence_dir / "System.evtx"
    placeholder_evtx_file(sys_log)
    device = r"USB\VID_1234&PID_5678\STRADDLE"
    records = {
        sys_log.resolve().as_posix(): [
            device_lifecycle_xml(
                event_id="2003", device_instance_id=device, when=_OLD, record_id=1
            ),
            device_lifecycle_xml(
                event_id="2102",
                device_instance_id=device,
                when=WHEN + timedelta(minutes=5),
                record_id=2,
            ),
        ]
    }
    monkeypatch.setattr("exfiltrack.parsers.evtx_parser.evtx.Evtx", SyntheticEvtxReader(records))
    config = CaseConfig(
        evidence_dir=evidence_dir,
        case_output_dir=tmp_path / "case",
        case_id="CASE-STRADDLE",
        examiner="J. Doe",
    )
    result = run_pipeline(config, events_since=_CUTOFF, write_reports=False)

    [session] = result.sessions
    assert session.boundary_sources == ("inferred", "event_log")
    assert session.partial_coverage


@pytest.mark.unit
def test_events_since_rejects_naive_datetime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, _records = _window_scenario(monkeypatch, tmp_path)
    with pytest.raises(PipelineError, match="timezone-aware UTC"):
        run_pipeline(config, events_since=datetime(2026, 2, 1), write_reports=False)


@pytest.mark.unit
def test_without_window_the_manifest_has_no_window_field(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config, _records = _window_scenario(monkeypatch, tmp_path)
    result = run_pipeline(config)
    payload = json.loads(result.report_paths["manifest"].read_text(encoding="utf-8"))
    assert "analysis_window" not in payload
    assert len(result.events) == 3

"""Unit tests for the pipeline orchestration added for #13.

These check the wiring's own behaviour in isolation (empty evidence, an
unrecognised file, ``write_reports=False``). The four controlled scenarios
and the reproducibility/integrity checks live in ``tests/integration/``,
since they exercise the pipeline end to end rather than one seam at a time.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from exfiltrack.config import CaseConfig
from exfiltrack.pipeline import PipelineError, run_pipeline
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

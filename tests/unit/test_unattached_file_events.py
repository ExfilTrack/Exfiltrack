"""Regression tests: recorded file activity outside session windows is disclosed.

A file access recorded just after the removal event (or otherwise outside
every reconstructed session window) used to vanish from the findings entirely,
so a report could show fewer files than the evidence recorded. These events
are still never attributed to a session or scored -- the correlation window is
what the evidence shows -- but they are disclosed in the pipeline result and
in every report format under "outside sessions".
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from exfiltrack.config import CaseConfig
from exfiltrack.pipeline import run_pipeline
from tests.support.synthetic_evtx import (
    SyntheticEvtxReader,
    device_lifecycle_xml,
    file_access_xml,
    placeholder_evtx_file,
)

WHEN = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
DEVICE = r"USB\VID_1234&PID_5678\SERIAL001"
EARLY = r"E:\Confidential\early.sql"
LATE = r"E:\Confidential\late.sql"


def _run_case(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, late_event: bool):
    """One 10-minute session; ``early.sql`` inside it, ``late.sql`` 1s after removal."""
    evidence_dir = tmp_path / "evidence"
    system_log = evidence_dir / "logs" / "System.evtx"
    security_log = evidence_dir / "logs" / "Security.evtx"
    placeholder_evtx_file(system_log)
    placeholder_evtx_file(security_log)
    security_records = [
        file_access_xml(object_name=EARLY, when=WHEN + timedelta(seconds=30), record_id=10),
    ]
    if late_event:
        security_records.append(
            file_access_xml(
                object_name=LATE,
                when=WHEN + timedelta(minutes=10, seconds=1),
                record_id=11,
            )
        )
    records = {
        system_log.resolve().as_posix(): [
            device_lifecycle_xml(
                event_id="2003", device_instance_id=DEVICE, when=WHEN, record_id=1
            ),
            device_lifecycle_xml(
                event_id="2102",
                device_instance_id=DEVICE,
                when=WHEN + timedelta(minutes=10),
                record_id=2,
            ),
        ],
        security_log.resolve().as_posix(): security_records,
    }
    monkeypatch.setattr("exfiltrack.parsers.evtx_parser.evtx.Evtx", SyntheticEvtxReader(records))
    return run_pipeline(
        CaseConfig(
            evidence_dir=evidence_dir,
            case_output_dir=tmp_path / "case",
            case_id="CASE-LATE",
            examiner="J. Doe",
        )
    )


@pytest.mark.unit
def test_out_of_window_file_event_is_disclosed_not_dropped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _run_case(monkeypatch, tmp_path, late_event=True)

    [session] = result.sessions
    assert [Path(e.file_path).name for e in session.file_events] == ["early.sql"]
    # Never attributed to the session, but never silently dropped either.
    assert [Path(e.file_path).name for e in result.unattached_file_events] == ["late.sql"]

    payload = json.loads(result.report_paths["json"].read_text(encoding="utf-8"))
    assert [e["file_path"] for e in payload["unattached_file_events"]] == [LATE]

    html = result.report_paths["html"].read_text(encoding="utf-8")
    assert 'id="unattached-file-activity"' in html
    assert "late.sql" in html

    rows = list(
        csv.DictReader(result.report_paths["timeline_csv"].read_text(encoding="utf-8").splitlines())
    )
    by_name = {Path(row["file_path"]).name: row for row in rows}
    assert by_name["late.sql"]["session_id"] == ""
    assert by_name["early.sql"]["session_id"] == session.session_id


@pytest.mark.unit
def test_no_outside_session_section_when_all_activity_is_inside(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _run_case(monkeypatch, tmp_path, late_event=False)

    assert result.unattached_file_events == ()

    payload = json.loads(result.report_paths["json"].read_text(encoding="utf-8"))
    assert payload["unattached_file_events"] == []

    html = result.report_paths["html"].read_text(encoding="utf-8")
    assert 'id="unattached-file-activity"' not in html

    rows = list(
        csv.DictReader(result.report_paths["timeline_csv"].read_text(encoding="utf-8").splitlines())
    )
    assert all(row["session_id"] for row in rows)


@pytest.mark.unit
def test_unattached_events_do_not_change_scoring(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with_late = _run_case(monkeypatch, tmp_path / "with", late_event=True)
    without_late = _run_case(monkeypatch, tmp_path / "without", late_event=False)

    assert (
        with_late.findings[0].scored_session.total_score
        == without_late.findings[0].scored_session.total_score
    )
    assert with_late.findings[0].confidence == without_late.findings[0].confidence

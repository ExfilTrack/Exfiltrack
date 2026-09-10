"""Unit tests for the ``exfiltrack`` command line interface."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from exfiltrack import __tool_name__, __version__
from exfiltrack.cli import main
from tests.support.synthetic_evtx import (
    SyntheticEvtxReader,
    device_lifecycle_xml,
    placeholder_evtx_file,
)

WHEN = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
DEVICE_ID = r"USB\VID_1234&PID_5678\SERIAL001"


def _install_one_artifact(monkeypatch: pytest.MonkeyPatch, evidence_dir: Path) -> Path:
    """Write one synthetic EVTX artifact and route it through the reader double."""
    evtx_path = evidence_dir / "System.evtx"
    placeholder_evtx_file(evtx_path)
    record = device_lifecycle_xml(
        event_id="2003", device_instance_id=DEVICE_ID, when=WHEN, record_id=1
    )
    monkeypatch.setattr(
        "exfiltrack.parsers.evtx_parser.evtx.Evtx",
        SyntheticEvtxReader({evtx_path.resolve().as_posix(): [record]}),
    )
    return evtx_path


@pytest.mark.unit
def test_version_command_prints_tool_name_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["version"])

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == f"{__tool_name__} {__version__}"


@pytest.mark.unit
def test_analyze_command_runs_pipeline_and_writes_reports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    case_dir = tmp_path / "case"
    _install_one_artifact(monkeypatch, evidence_dir)

    exit_code = main(
        [
            "analyze",
            "--evidence",
            str(evidence_dir),
            "--case-dir",
            str(case_dir),
            "--case-id",
            "CASE-CLI-0001",
            "--examiner",
            "Tester",
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Findings:" in out
    assert (case_dir / "case_manifest.json").exists()
    assert (case_dir / "report.html").exists()
    assert (case_dir / "findings.json").exists()


@pytest.mark.unit
def test_analyze_command_reports_pipeline_error_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()  # empty: no artifacts at all

    exit_code = main(
        [
            "analyze",
            "--evidence",
            str(evidence_dir),
            "--case-dir",
            str(tmp_path / "case"),
            "--case-id",
            "CASE-CLI-0002",
            "--examiner",
            "Tester",
        ]
    )

    assert exit_code == 1
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert "No evidence artifacts found" in err


@pytest.mark.unit
def test_analyze_command_reports_config_error_for_overlapping_directories(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()

    exit_code = main(
        [
            "analyze",
            "--evidence",
            str(evidence_dir),
            "--case-dir",
            str(evidence_dir / "case"),  # inside the evidence directory
            "--case-id",
            "CASE-CLI-0003",
            "--examiner",
            "Tester",
        ]
    )

    assert exit_code == 1
    assert "error:" in capsys.readouterr().err


@pytest.mark.unit
def test_verify_command_passes_when_evidence_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    case_dir = tmp_path / "case"
    _install_one_artifact(monkeypatch, evidence_dir)
    main(
        [
            "analyze",
            "--evidence",
            str(evidence_dir),
            "--case-dir",
            str(case_dir),
            "--case-id",
            "CASE-CLI-0004",
            "--examiner",
            "Tester",
        ]
    )
    capsys.readouterr()  # discard analyze's output

    exit_code = main(["verify", "--case-dir", str(case_dir)])

    assert exit_code == 0
    assert "INTEGRITY VERIFIED" in capsys.readouterr().out


@pytest.mark.unit
def test_verify_command_fails_when_evidence_was_modified(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    case_dir = tmp_path / "case"
    evtx_path = _install_one_artifact(monkeypatch, evidence_dir)
    main(
        [
            "analyze",
            "--evidence",
            str(evidence_dir),
            "--case-dir",
            str(case_dir),
            "--case-id",
            "CASE-CLI-0005",
            "--examiner",
            "Tester",
        ]
    )
    capsys.readouterr()

    evtx_path.write_bytes(evtx_path.read_bytes() + b"tampered")

    exit_code = main(["verify", "--case-dir", str(case_dir)])

    assert exit_code == 1
    assert "INTEGRITY FAILED" in capsys.readouterr().out


@pytest.mark.unit
def test_verify_command_reports_missing_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty_case_dir = tmp_path / "case"
    empty_case_dir.mkdir()

    exit_code = main(["verify", "--case-dir", str(empty_case_dir)])

    assert exit_code == 1
    assert "error:" in capsys.readouterr().err

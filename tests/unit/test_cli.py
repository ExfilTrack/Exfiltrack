"""Unit tests for the ``exfiltrack`` command line interface."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from exfiltrack import __tool_name__, __version__
from exfiltrack.cli import main
from exfiltrack.evidence.hashing import hash_file
from exfiltrack.evidence.live import AcquisitionError, AcquisitionResult
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
@pytest.mark.parametrize("help_flag", ["-h", "--help"])
def test_top_level_help_includes_command_options_and_examples(
    help_flag: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main([help_flag])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    for text in (
        "Analyze command:",
        "Verify command:",
        "--evidence DIR",
        "--case-dir DIR",
        "--case-id CASE_ID",
        "--examiner EXAMINER",
        "Directory of offline Windows artifacts",
        "case_manifest.json",
        "exfiltrack analyze --evidence ./evidence",
        '--examiner "Your Name"',
        "exfiltrack verify --case-dir ./cases/CASE-001",
        "exfiltrack version",
        "exfiltrack <command> --help",
    ):
        assert text in captured.out


@pytest.mark.unit
@pytest.mark.parametrize("command", ["analyze", "verify", "version"])
@pytest.mark.parametrize("help_flag", ["-h", "--help"])
def test_command_help_remains_specific_to_the_command(
    command: str, help_flag: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main([command, help_flag])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert f"usage: exfiltrack {command}" in captured.out
    assert "Analyze command:" not in captured.out
    assert "Examples:" not in captured.out
    assert ("--evidence" in captured.out) == (command == "analyze")
    assert ("--case-dir" in captured.out) == (command in {"analyze", "verify"})


@pytest.mark.unit
def test_analyze_still_requires_all_case_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["analyze"])

    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    for flag in ("--case-dir", "--case-id", "--examiner"):
        assert flag in captured.err


@pytest.mark.unit
def test_analyze_requires_an_evidence_source(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["analyze", "--case-dir", "c", "--case-id", "X", "--examiner", "E"])

    assert exc_info.value.code == 2
    err = capsys.readouterr().err
    assert "--evidence" in err and "--auto" in err


@pytest.mark.unit
def test_auto_and_evidence_are_mutually_exclusive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    collect_calls: list[object] = []
    monkeypatch.setattr("exfiltrack.cli.collect_live_evidence", collect_calls.append)

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "analyze",
                "--auto",
                "--evidence",
                str(tmp_path),
                "--case-dir",
                str(tmp_path / "case"),
                "--case-id",
                "X",
                "--examiner",
                "E",
            ]
        )

    assert exc_info.value.code == 2
    assert "not allowed with" in capsys.readouterr().err
    assert collect_calls == []


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


def _install_fake_collector(
    monkeypatch: pytest.MonkeyPatch,
    case_dir: Path,
    *,
    tamper_after_collection: bool = False,
    extra_records: tuple[dict[str, Any], ...] = (),
    broken_artifact: bool = False,
) -> list[dict[str, Any]]:
    """Replace live collection with a fake that lays out a real fresh case.

    Records every call so tests can assert on the arguments the CLI passed.
    """
    calls: list[dict[str, Any]] = []
    evtx_path = case_dir / "evidence" / "evtx" / "System.evtx"
    record = device_lifecycle_xml(
        event_id="2003", device_instance_id=DEVICE_ID, when=WHEN, record_id=1
    )
    monkeypatch.setattr(
        "exfiltrack.parsers.evtx_parser.evtx.Evtx",
        SyntheticEvtxReader({evtx_path.resolve().as_posix(): [record]}),
    )

    def fake_collect(path: Path, *, case_id: str, examiner: str) -> AcquisitionResult:
        calls.append({"case_dir": path, "case_id": case_id, "examiner": examiner})
        evidence_dir, reports_dir = path / "evidence", path / "reports"
        reports_dir.mkdir(parents=True)
        placeholder_evtx_file(evtx_path)
        records: list[dict[str, Any]] = [
            {
                "category": "evtx",
                "source": "System",
                "method": "wevtutil epl",
                "status": "collected",
                "started_at": "2026-03-01T09:00:00+00:00",
                "finished_at": "2026-03-01T09:00:01+00:00",
                "destination": "evtx/System.evtx",
                "sha256": hash_file(evtx_path),
                "metadata": {},
            },
            *extra_records,
        ]
        if broken_artifact:
            broken = evidence_dir / "evtx" / "Security.evtx"
            broken.write_bytes(b"ElfFile\x00" + b"\xff" * 64)
            records.append(
                {
                    **records[0],
                    "source": "Security",
                    "destination": "evtx/Security.evtx",
                    "sha256": hash_file(broken),
                }
            )
        manifest = {
            "schema_version": "1.0",
            "case_id": case_id,
            "examiner": examiner,
            "computer_name": "SYNTHETIC-VM",
            "start_time": "2026-03-01T09:00:00+00:00",
            "end_time": "2026-03-01T09:00:05+00:00",
            "coverage": (
                "partial"
                if any(r["status"] in {"missing", "unavailable", "error"} for r in records)
                else "complete"
            ),
            "records": records,
            "limitations": ["Synthetic acquisition for tests."],
        }
        manifest_path = path / "acquisition_manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        if tamper_after_collection:
            evtx_path.write_bytes(evtx_path.read_bytes() + b"tampered")
        return AcquisitionResult(path, evidence_dir, reports_dir, manifest_path, manifest)

    monkeypatch.setattr("exfiltrack.cli.collect_live_evidence", fake_collect)
    return calls


def _auto_args(case_dir: Path) -> list[str]:
    return [
        "analyze",
        "--auto",
        "--case-dir",
        str(case_dir),
        "--case-id",
        "CASE-AUTO-1",
        "--examiner",
        "Tester",
    ]


@pytest.mark.unit
def test_auto_collects_then_analyzes_and_writes_reports_into_reports_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    case_dir = tmp_path / "case"
    calls = _install_fake_collector(monkeypatch, case_dir)

    exit_code = main(_auto_args(case_dir))

    out = capsys.readouterr().out
    assert exit_code == 0
    assert calls == [{"case_dir": case_dir, "case_id": "CASE-AUTO-1", "examiner": "Tester"}]
    assert "Collection coverage:  complete" in out
    assert "Evidence integrity: verified" in out
    reports = case_dir / "reports"
    for name in ("case_manifest.json", "report.html", "findings.json"):
        assert (reports / name).exists()
    assert (case_dir / "acquisition_manifest.json").exists()
    # Nothing generated may land inside the collected evidence.
    assert sorted(p.name for p in (case_dir / "evidence").rglob("*") if p.is_file()) == [
        "System.evtx"
    ]
    manifest = json.loads((reports / "case_manifest.json").read_text(encoding="utf-8"))
    assert manifest["acquisition"]["computer_name"] == "SYNTHETIC-VM"
    findings = json.loads((reports / "findings.json").read_text(encoding="utf-8"))
    assert findings["manifest"]["acquisition"]["coverage"] == "complete"
    html = (reports / "report.html").read_text(encoding="utf-8")
    assert "Evidence Coverage" in html and "SYNTHETIC-VM" in html


@pytest.mark.unit
def test_auto_reports_collection_gaps_and_partial_coverage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    case_dir = tmp_path / "case"
    gap = {
        "category": "evtx",
        "source": "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
        "method": "wevtutil epl",
        "status": "error",
        "started_at": "2026-03-01T09:00:01+00:00",
        "finished_at": "2026-03-01T09:00:02+00:00",
        "message": "Command failed with exit code 15007.",
        "metadata": {},
    }
    _install_fake_collector(monkeypatch, case_dir, extra_records=(gap,))

    exit_code = main(_auto_args(case_dir))

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Collection coverage:  partial" in out
    assert "gap: [evtx] Microsoft-Windows-DriverFrameworks-UserMode/Operational" in out
    assert "exit code 15007" in out
    html = (case_dir / "reports" / "report.html").read_text(encoding="utf-8")
    assert "Partial evidence coverage" in html


@pytest.mark.unit
def test_auto_records_parser_failures_and_continues(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    case_dir = tmp_path / "case"
    # Security.evtx is not registered with the reader double, so parsing it fails
    # exactly as a corrupt log would: parse_evtx wraps it in EvtxParseError.
    _install_fake_collector(monkeypatch, case_dir, broken_artifact=True)

    exit_code = main(_auto_args(case_dir))

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "could not be parsed; results are PARTIAL" in out
    assert "Security.evtx" in out
    manifest = json.loads((case_dir / "reports" / "case_manifest.json").read_text(encoding="utf-8"))
    [error] = manifest["parser_errors"]
    assert error["source_artifact"].endswith("evtx/Security.evtx")
    assert error["parser_name"] == "evtx_parser"
    assert error["error_type"] == "EvtxParseError"
    html = (case_dir / "reports" / "report.html").read_text(encoding="utf-8")
    assert "Partial analysis" in html


@pytest.mark.unit
def test_auto_refuses_to_analyze_snapshots_changed_after_collection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    case_dir = tmp_path / "case"
    _install_fake_collector(monkeypatch, case_dir, tamper_after_collection=True)

    exit_code = main(_auto_args(case_dir))

    assert exit_code == 1
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert "no longer matches the acquisition manifest" in err
    assert not (case_dir / "reports" / "report.html").exists()


@pytest.mark.unit
def test_auto_reports_acquisition_failure_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> AcquisitionResult:
        raise AcquisitionError("Live acquisition requires an elevated administrator token.")

    monkeypatch.setattr("exfiltrack.cli.collect_live_evidence", refuse)

    exit_code = main(_auto_args(tmp_path / "case"))

    assert exit_code == 1
    err = capsys.readouterr().err
    assert err.startswith("error:") and "elevated" in err
    assert not (tmp_path / "case").exists()


@pytest.mark.unit
def test_verify_accepts_an_auto_case_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    case_dir = tmp_path / "case"
    _install_fake_collector(monkeypatch, case_dir)
    main(_auto_args(case_dir))
    capsys.readouterr()

    exit_code = main(["verify", "--case-dir", str(case_dir)])

    assert exit_code == 0
    assert "INTEGRITY VERIFIED" in capsys.readouterr().out


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

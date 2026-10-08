"""Unit tests for the ExfilTrack GUI.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #47 - Desktop GUI for analyze, verify, and results review

The controller tests run everywhere, including headless CI: the controller
imports no GUI toolkit by design. The tkinter widget tests at the bottom
skip cleanly when tkinter or a display is unavailable.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from exfiltrack.config import CaseConfig, ConfigError, ExfilTrackError, PathOverlapError
from exfiltrack.correlation.sessions import reconstruct_sessions
from exfiltrack.evidence.hashing import hash_file
from exfiltrack.evidence.manifest import MANIFEST_FILENAME, CaseManifest, IntegrityVerdict
from exfiltrack.gui import controller
from exfiltrack.pipeline import PipelineResult
from exfiltrack.reporting.model import assemble_findings
from tests.unit.factories import (
    make_device,
    make_file_event,
    make_insert_event,
    make_remove_event,
    utc,
)


def _case_config(tmp_path: Path) -> CaseConfig:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    return CaseConfig(
        evidence_dir=evidence,
        case_output_dir=tmp_path / "case",
        case_id="CASE-001",
        examiner="Examiner",
    )


def _result_with_one_finding(config: CaseConfig, tmp_path: Path) -> PipelineResult:
    """A realistic PipelineResult: one fully observed session with two sensitive files."""
    device = make_device()
    base = utc(2026, 3, 1, 9, 0, 0)
    events = [
        make_insert_event(base, device),
        make_file_event(base + timedelta(seconds=5), r"E:\Confidential\db_dump.sql"),
        make_file_event(base + timedelta(seconds=12), r"E:\Confidential\keys.pem"),
        make_remove_event(base + timedelta(minutes=10), device),
    ]
    sessions = reconstruct_sessions(events)
    findings = assemble_findings(sessions)
    manifest = CaseManifest.from_config(config, [], start_time=utc(2026, 3, 1, 10, 0, 0))
    manifest.integrity_verdict = IntegrityVerdict.VERIFIED
    return PipelineResult(
        manifest=manifest,
        artifacts=(),
        events=tuple(events),
        sessions=tuple(sessions),
        findings=tuple(findings),
        report_paths={"html": tmp_path / "case" / "report.html"},
    )


def _write_manifest(case_dir: Path, payload: dict[str, Any]) -> Path:
    case_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = case_dir / MANIFEST_FILENAME
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    return manifest_path


# ---------------------------------------------------------------------------
# Form validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_build_offline_config_returns_case_config(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    config = controller.build_offline_config(
        evidence_dir=str(evidence),
        case_output_dir=str(tmp_path / "case"),
        case_id="CASE-001",
        examiner="Examiner",
    )
    assert config.resolved_evidence_dir == evidence.resolve()
    assert config.case_id == "CASE-001"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("case_id", "examiner", "match"),
    [("", "Examiner", "case_id"), ("CASE-001", " ", "examiner")],
)
def test_build_offline_config_rejects_empty_case_fields(
    tmp_path: Path, case_id: str, examiner: str, match: str
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with pytest.raises(ConfigError, match=match):
        controller.build_offline_config(
            evidence_dir=str(evidence),
            case_output_dir=str(tmp_path / "case"),
            case_id=case_id,
            examiner=examiner,
        )


@pytest.mark.unit
def test_build_offline_config_rejects_missing_evidence_dir(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="does not exist"):
        controller.build_offline_config(
            evidence_dir=str(tmp_path / "not-there"),
            case_output_dir=str(tmp_path / "case"),
            case_id="CASE-001",
            examiner="Examiner",
        )


@pytest.mark.unit
def test_build_offline_config_rejects_output_inside_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    with pytest.raises(PathOverlapError):
        controller.build_offline_config(
            evidence_dir=str(evidence),
            case_output_dir=str(evidence / "case"),
            case_id="CASE-001",
            examiner="Examiner",
        )


@pytest.mark.unit
def test_validate_live_case_dir_rejects_existing_directory(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="already exists"):
        controller.validate_live_case_dir(str(tmp_path))


@pytest.mark.unit
def test_validate_live_case_dir_rejects_empty_value() -> None:
    with pytest.raises(ConfigError, match="must not be empty"):
        controller.validate_live_case_dir("   ")


# ---------------------------------------------------------------------------
# run_analysis
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_run_analysis_rejects_unknown_mode(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Unknown analysis mode"):
        controller.run_analysis(
            mode="sideways",
            evidence_dir=str(tmp_path),
            case_dir=str(tmp_path / "case"),
            case_id="CASE-001",
            examiner="Examiner",
        )


@pytest.mark.unit
def test_run_analysis_offline_invokes_pipeline_like_the_cli(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _case_config(tmp_path)
    captured: dict[str, Any] = {}
    sentinel = object()

    def fake_run_pipeline(passed_config: CaseConfig, **kwargs: Any) -> Any:
        captured["config"] = passed_config
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(controller, "run_pipeline", fake_run_pipeline)
    messages: list[str] = []
    result = controller.run_analysis(
        mode=controller.OFFLINE_MODE,
        evidence_dir=str(config.evidence_dir),
        case_dir=str(config.case_output_dir),
        case_id="CASE-001",
        examiner="Examiner",
        progress=messages.append,
    )
    assert result is sentinel
    assert captured["continue_on_parser_error"] is True
    assert captured["config"].case_id == "CASE-001"
    assert any("read-only" in message for message in messages)


@pytest.mark.unit
def test_run_analysis_live_collects_then_analyzes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    case_dir = tmp_path / "CASE-NEW"  # deliberately not created: live mode needs it fresh
    acquisition = SimpleNamespace(
        evidence_dir=case_dir / "evidence",
        reports_dir=case_dir / "reports",
        manifest_path=case_dir / "acquisition_manifest.json",
        manifest={
            "coverage": "partial",
            "records": [
                {
                    "status": "missing",
                    "category": "evtx",
                    "source": "DriverFrameworks channel",
                    "message": "channel disabled",
                    "metadata": {},
                }
            ],
        },
    )
    captured: dict[str, Any] = {}
    sentinel = object()

    def fake_collect(target: Path, *, case_id: str, examiner: str) -> Any:
        captured["target"] = target
        return acquisition

    def fake_run_pipeline(passed_config: CaseConfig, **kwargs: Any) -> Any:
        captured["config"] = passed_config
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(controller, "collect_live_evidence", fake_collect)
    monkeypatch.setattr(controller, "run_pipeline", fake_run_pipeline)
    messages: list[str] = []
    result = controller.run_analysis(
        mode=controller.LIVE_MODE,
        evidence_dir="",
        case_dir=str(case_dir),
        case_id="CASE-002",
        examiner="Examiner",
        progress=messages.append,
    )
    assert result is sentinel
    assert captured["target"] == case_dir
    assert captured["acquisition"] == acquisition.manifest
    assert captured["continue_on_parser_error"] is True
    assert captured["config"].evidence_dir == acquisition.evidence_dir
    assert captured["config"].case_output_dir == acquisition.reports_dir
    assert any("Collection coverage: partial" in message for message in messages)
    assert any("DriverFrameworks channel" in message for message in messages)


@pytest.mark.unit
def test_collection_gap_lines_flags_gaps_and_disabled_channels() -> None:
    manifest = {
        "records": [
            {"status": "collected", "category": "evtx", "source": "System", "metadata": {}},
            {"status": "missing", "category": "registry", "source": "SOFTWARE", "metadata": {}},
            {
                "status": "collected",
                "category": "evtx",
                "source": "DriverFrameworks",
                "message": "channel disabled at collection time",
                "metadata": {"channel_enabled": False},
            },
        ]
    }
    lines = controller.collection_gap_lines(manifest)
    assert len(lines) == 2
    assert "[registry] SOFTWARE: missing" in lines
    assert "[evtx] DriverFrameworks: channel disabled at collection time" in lines


# ---------------------------------------------------------------------------
# summarize_result
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_summarize_result_flattens_findings_for_display(tmp_path: Path) -> None:
    config = _case_config(tmp_path)
    summary = controller.summarize_result(_result_with_one_finding(config, tmp_path))

    assert summary.case_id == "CASE-001"
    assert summary.events == 4
    assert summary.sessions == 1
    assert summary.integrity_verdict == "verified"
    assert summary.confidence_counts == (("High", 1),)
    assert summary.html_report == tmp_path / "case" / "report.html"
    assert summary.output_dir == config.resolved_case_output_dir

    [row] = summary.findings
    assert row.device == "SanDisk Cruzer Blade"
    assert row.total_score == 95  # 2 x (30s window 25 + sensitive extension 15) + 15 aggregate
    assert row.confidence == "High"
    assert row.boundaries == "start observed, end observed"
    assert row.reason  # #10: every finding records why it received its level
    assert any("activity_within_30s (+25)" in line for line in row.contributions)


@pytest.mark.unit
def test_summarize_result_formats_parser_errors_as_partial(tmp_path: Path) -> None:
    config = _case_config(tmp_path)
    result = _result_with_one_finding(config, tmp_path)
    result.manifest.parser_errors.append(
        {"source_artifact": "evtx/Security.evtx", "message": "bad XML"}
    )
    summary = controller.summarize_result(result)
    assert summary.parser_errors == ("evtx/Security.evtx: bad XML",)


@pytest.mark.unit
def test_summarize_result_without_reports_has_no_html(tmp_path: Path) -> None:
    config = _case_config(tmp_path)
    result = _result_with_one_finding(config, tmp_path)
    summary = controller.summarize_result(
        PipelineResult(
            manifest=result.manifest,
            artifacts=result.artifacts,
            events=result.events,
            sessions=result.sessions,
            findings=result.findings,
        )
    )
    assert summary.html_report is None
    assert summary.report_paths == ()
    # Output directory still resolves from the manifest's config snapshot.
    assert summary.output_dir == config.resolved_case_output_dir


# ---------------------------------------------------------------------------
# verify_case
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_verify_case_passes_when_digests_match(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "a.bin").write_bytes(b"synthetic evidence")
    manifest_path = _write_manifest(
        tmp_path / "case",
        {
            "config": {"evidence_dir": str(evidence)},
            "intake_digests": [{"path": "a.bin", "digest": hash_file(evidence / "a.bin")}],
        },
    )
    summary = controller.verify_case(tmp_path / "case")
    assert summary.verified
    assert summary.total == 1
    assert summary.failures == ()
    assert summary.manifest_path == manifest_path


@pytest.mark.unit
def test_verify_case_finds_manifest_in_auto_case_layout(tmp_path: Path) -> None:
    evidence = tmp_path / "case" / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "a.bin").write_bytes(b"synthetic evidence")
    _write_manifest(
        tmp_path / "case" / "reports",
        {
            "config": {"evidence_dir": str(evidence)},
            "intake_digests": [{"path": "a.bin", "digest": hash_file(evidence / "a.bin")}],
        },
    )
    summary = controller.verify_case(tmp_path / "case")
    assert summary.verified
    assert summary.manifest_path.parent.name == "reports"


@pytest.mark.unit
def test_verify_case_reports_tampered_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    artifact = evidence / "a.bin"
    artifact.write_bytes(b"synthetic evidence")
    _write_manifest(
        tmp_path / "case",
        {
            "config": {"evidence_dir": str(evidence)},
            "intake_digests": [{"path": "a.bin", "digest": hash_file(artifact)}],
        },
    )
    artifact.write_bytes(b"tampered")
    summary = controller.verify_case(tmp_path / "case")
    assert not summary.verified
    assert len(summary.failures) == 1
    assert "a.bin" in summary.failures[0]


@pytest.mark.unit
def test_verify_case_rejects_missing_manifest(tmp_path: Path) -> None:
    with pytest.raises(ExfilTrackError, match=MANIFEST_FILENAME):
        controller.verify_case(tmp_path)


@pytest.mark.unit
def test_verify_case_rejects_manifest_without_digests(tmp_path: Path) -> None:
    _write_manifest(tmp_path / "case", {"config": {"evidence_dir": str(tmp_path)}})
    with pytest.raises(ExfilTrackError, match="no intake digests"):
        controller.verify_case(tmp_path / "case")


# ---------------------------------------------------------------------------
# tkinter smoke tests (skip when tkinter or a display is unavailable)
# ---------------------------------------------------------------------------


def _build_app_or_skip() -> Any:
    """Create a withdrawn main window, skipping on headless machines.

    Tk initialisation is retried once: a first-attempt ``TclError`` in a
    fresh pytest process is occasionally transient on Windows.
    """
    tk = pytest.importorskip("tkinter")
    from exfiltrack.gui.app import ExfilTrackApp

    root = None
    for _attempt in range(2):
        try:
            root = tk.Tk()
            break
        except tk.TclError:
            continue
    if root is None:
        pytest.skip("no display available (tkinter TclError)")
    root.withdraw()
    return root, ExfilTrackApp(root)


@pytest.mark.unit
def test_app_builds_and_disclaimer_is_mandated_text() -> None:
    pytest.importorskip("tkinter")
    from exfiltrack import __tool_name__
    from exfiltrack.gui import app as gui_app

    root, _window = _build_app_or_skip()
    try:
        assert __tool_name__ in root.title()
        assert (
            "Temporal correlation alone does not prove that a file was copied" in gui_app.DISCLAIMER
        )
    finally:
        root.destroy()


@pytest.mark.unit
def test_app_mode_switch_disables_evidence_picker_in_live_mode() -> None:
    root, window = _build_app_or_skip()
    try:
        assert str(window.evidence_entry.cget("state")) == "normal"
        window.mode_var.set(controller.LIVE_MODE)
        window._on_mode_changed()
        assert str(window.evidence_entry.cget("state")) == "disabled"
        assert window.case_dir_label_var.get() == "New case directory:"
        window.mode_var.set(controller.OFFLINE_MODE)
        window._on_mode_changed()
        assert str(window.evidence_entry.cget("state")) == "normal"
    finally:
        root.destroy()


@pytest.mark.unit
def test_app_show_summary_populates_findings_table(tmp_path: Path) -> None:
    root, window = _build_app_or_skip()
    try:
        summary = controller.summarize_result(
            _result_with_one_finding(_case_config(tmp_path), tmp_path)
        )
        window._show_summary(summary)
        children = window.findings.get_children()
        assert len(children) == 1
        values = window.findings.item(children[0], "values")
        assert str(values[0]) == "SanDisk Cruzer Blade"
        assert str(values[2]) == "95"
        assert str(values[3]) == "High"
        assert "High: 1" in window.summary_var.get()
        assert window.integrity_var.get() == "Evidence integrity: verified"
        assert str(window.open_html_button.cget("state")) == "normal"
        assert str(window.open_folder_button.cget("state")) == "normal"
    finally:
        root.destroy()


@pytest.mark.unit
def test_app_show_error_uses_dialog_not_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("tkinter")
    from exfiltrack.gui import app as gui_app

    shown: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr(gui_app.messagebox, "showerror", lambda *a, **k: shown.append((a, k)))
    root, window = _build_app_or_skip()
    try:
        window._show_error("Evidence directory 'X' does not exist.")
        assert shown and "does not exist" in shown[0][0][1]
        assert window.status_var.get() == "Failed."
    finally:
        root.destroy()

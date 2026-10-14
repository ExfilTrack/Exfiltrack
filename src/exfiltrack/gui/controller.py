"""Toolkit-independent logic behind the ExfilTrack desktop GUI.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #47 - Desktop GUI for analyze, verify, and results review

Everything the tkinter front end (:mod:`exfiltrack.gui.app`) needs that is
not drawing widgets lives here: validating the case form, invoking the
pipeline exactly the way the CLI's ``analyze`` command does, summarising a
:class:`~exfiltrack.pipeline.PipelineResult` for display, and re-verifying a
case's recorded digests the way ``exfiltrack verify`` does. Keeping this
module free of tkinter imports lets the unit tests exercise it on headless
CI machines.

The GUI adds no analysis behaviour of its own: offline runs call
:func:`~exfiltrack.pipeline.run_pipeline` with the same arguments as
``exfiltrack analyze --evidence``, and live runs mirror
``exfiltrack analyze --auto``. All forensic-soundness enforcement therefore
stays in the existing pipeline and configuration code.
"""

from __future__ import annotations

import getpass
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from exfiltrack.config import CaseConfig, ConfigError, ExfilTrackError
from exfiltrack.correlation.confidence import ConfidenceLevel
from exfiltrack.evidence.hashing import DigestMismatchError, verify_digest
from exfiltrack.evidence.live import collect_live_evidence
from exfiltrack.evidence.manifest import MANIFEST_FILENAME, utc_now
from exfiltrack.pipeline import PipelineResult, run_pipeline
from exfiltrack.reporting.model import Finding

OFFLINE_MODE = "offline"
LIVE_MODE = "live"
ANALYSIS_MODES = (OFFLINE_MODE, LIVE_MODE)

# Status values in an acquisition manifest that mean a source could not be
# collected. Mirrors the set the CLI's ``analyze --auto`` summary uses.
_GAP_STATUSES = frozenset({"missing", "unavailable", "error"})

ProgressCallback = Callable[[str], None]


# ---------------------------------------------------------------------------
# Display-ready views of pipeline results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingRow:
    """One finding, flattened into strings the results table can render.

    Attributes:
        device: Human-readable device label (``UsbDevice.display_name``).
        session_start: ISO-8601 UTC session start.
        session_end: ISO-8601 UTC session end.
        boundaries: Whether each session boundary is backed by an observed
            event or was inferred (reports must render these distinctly,
            per the #8 Definition of Done).
        total_score: Sum of every scoring rule's points for the session.
        confidence: Confidence level label (``str(ConfidenceLevel)``).
        reason: Why the finding received that level (#10 requires it).
        contributions: One formatted line per scoring rule that fired.
    """

    device: str
    session_start: str
    session_end: str
    boundaries: str
    total_score: int
    confidence: str
    reason: str
    contributions: tuple[str, ...]


@dataclass(frozen=True)
class AnalysisSummary:
    """Everything the window shows after a successful run.

    Attributes:
        case_id: Case identifier recorded in the manifest.
        examiner: Analyst recorded in the manifest.
        artifacts: Number of evidence artifacts discovered at intake.
        events: Number of normalized events parsed.
        sessions: Number of USB sessions reconstructed.
        findings: One display row per finding, in report order.
        confidence_counts: ``(level label, count)`` pairs, sorted by label.
        integrity_verdict: ``IntegrityVerdict`` value for the run.
        parser_errors: One formatted line per artifact that failed to parse
            (a run with any of these is a partial analysis).
        output_dir: Directory the manifest and reports were written to.
        report_paths: ``(name, path)`` pairs for every written report.
        html_report: Path of the HTML report, if one was written.
    """

    case_id: str
    examiner: str
    artifacts: int
    events: int
    sessions: int
    findings: tuple[FindingRow, ...]
    confidence_counts: tuple[tuple[str, int], ...]
    integrity_verdict: str
    parser_errors: tuple[str, ...]
    output_dir: Path
    report_paths: tuple[tuple[str, Path], ...]
    html_report: Path | None


@dataclass(frozen=True)
class VerificationSummary:
    """Outcome of re-checking a case's recorded evidence digests.

    Attributes:
        manifest_path: The manifest the digests were read from.
        evidence_dir: Root the recorded relative paths resolved against.
        total: How many recorded digests were checked.
        failures: One formatted line per changed or missing artifact. Empty
            means every digest still matches.
    """

    manifest_path: Path
    evidence_dir: Path
    total: int
    failures: tuple[str, ...]

    @property
    def verified(self) -> bool:
        """``True`` only if every recorded artifact is present and unchanged."""
        return not self.failures


# ---------------------------------------------------------------------------
# Form validation
# ---------------------------------------------------------------------------


def _require_text(value: str, field_name: str) -> str:
    """Return *value* stripped, rejecting empty form fields with a clear error."""
    if not value.strip():
        raise ConfigError(f"{field_name} must not be empty.")
    return value.strip()


def build_offline_config(
    *, evidence_dir: str, case_output_dir: str, case_id: str, examiner: str
) -> CaseConfig:
    """Validate the GUI case form and return the immutable run configuration.

    Parameters:
        evidence_dir: Directory of offline Windows artifacts. Must already
            exist; ``Path("")`` would silently resolve to the current working
            directory, so emptiness is rejected on the raw string first.
        case_output_dir: Where the manifest and reports are written. Must not
            be inside the evidence directory (enforced by
            :class:`~exfiltrack.config.CaseConfig`).
        case_id: Analyst-supplied case identifier.
        examiner: Full name or badge ID of the analyst running the tool.

    Raises:
        ConfigError: For empty fields or a missing evidence directory.
        PathOverlapError: If the evidence and output directories nest.
    """
    evidence = Path(_require_text(evidence_dir, "Evidence directory")).expanduser()
    output = Path(_require_text(case_output_dir, "Case output directory")).expanduser()
    if not evidence.is_dir():
        raise ConfigError(f"Evidence directory '{evidence}' does not exist or is not a directory.")
    return CaseConfig(
        evidence_dir=evidence,
        case_output_dir=output,
        case_id=case_id,
        examiner=examiner,
    )


def validate_live_case_dir(case_dir: str) -> Path:
    """Validate the target directory for a live acquisition run.

    Live acquisition mirrors ``analyze --auto``: the case directory must be
    fresh (the collector creates it and refuses to overwrite an existing
    one). Checking here gives the analyst the error before collection
    starts rather than after.
    """
    target = Path(_require_text(case_dir, "Case directory")).expanduser()
    if target.exists():
        raise ConfigError(
            f"Case directory '{target}' already exists; live acquisition requires "
            "a fresh directory that does not exist yet."
        )
    return target


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def collection_gap_lines(manifest: dict[str, Any]) -> list[str]:
    """Format the acquisition manifest's gap records for the log pane.

    A gap is a source that could not be collected, or an event channel that
    was disabled -- the same definition the CLI's ``--auto`` summary prints.
    """
    lines: list[str] = []
    for record in manifest.get("records", []):
        channel_off = record.get("metadata", {}).get("channel_enabled") is False
        if record["status"] in _GAP_STATUSES or channel_off:
            reason = record.get("message") or record["status"]
            lines.append(f"[{record['category']}] {record['source']}: {reason}")
    return lines


def run_analysis(
    *,
    mode: str,
    evidence_dir: str,
    case_dir: str,
    case_id: str,
    examiner: str,
    progress: ProgressCallback | None = None,
) -> PipelineResult:
    """Run the pipeline for the GUI, mirroring the CLI's ``analyze`` command.

    Parameters:
        mode: ``OFFLINE_MODE`` (analyze an existing evidence directory) or
            ``LIVE_MODE`` (collect from this running Windows machine, then
            analyze the snapshots).
        evidence_dir: Used only in offline mode.
        case_dir: Output directory (offline) or fresh case directory (live).
        case_id, examiner: Recorded in the chain-of-custody manifest.
        progress: Optional callback invoked with one-line status messages so
            the front end can show what stage the run is at.

    Raises:
        ConfigError: For invalid form input or an unknown mode.
        ExfilTrackError, OSError: Propagated unchanged from the pipeline or
            the live collector; the front end renders them as readable
            messages, never raw tracebacks.
    """
    report = progress if progress is not None else (lambda _message: None)
    if mode == OFFLINE_MODE:
        config = build_offline_config(
            evidence_dir=evidence_dir,
            case_output_dir=case_dir,
            case_id=case_id,
            examiner=examiner,
        )
        report("Running the analysis pipeline; evidence is opened read-only...")
        return run_pipeline(config, continue_on_parser_error=True)
    if mode == LIVE_MODE:
        target = validate_live_case_dir(case_dir)
        report("Collecting artifacts from this machine (read-only; no logging is changed)...")
        acquisition = collect_live_evidence(target, case_id=case_id, examiner=examiner)
        report(f"Collection coverage: {acquisition.manifest['coverage']}")
        for line in collection_gap_lines(acquisition.manifest):
            report(f"  gap: {line}")
        report("Analyzing the collected snapshots...")
        config = CaseConfig(
            evidence_dir=acquisition.evidence_dir,
            case_output_dir=acquisition.reports_dir,
            case_id=case_id,
            examiner=examiner,
        )
        return run_pipeline(
            config,
            acquisition=acquisition.manifest,
            continue_on_parser_error=True,
        )
    raise ConfigError(f"Unknown analysis mode: {mode!r}.")


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------


def _finding_row(finding: Finding) -> FindingRow:
    """Flatten one :class:`~exfiltrack.reporting.model.Finding` into display strings."""
    session = finding.session
    start = "observed" if session.start.observed else "inferred"
    end = "observed" if session.end.observed else "inferred"
    return FindingRow(
        device=session.device.display_name,
        session_start=session.start.timestamp_utc.isoformat(),
        session_end=session.end.timestamp_utc.isoformat(),
        boundaries=f"start {start}, end {end}",
        total_score=finding.scored_session.total_score,
        confidence=str(finding.confidence.level),
        reason=finding.confidence.reason,
        contributions=tuple(
            f"{c.rule} (+{c.points}): {c.explanation}" for c in finding.scored_session.contributions
        ),
    )


def summarize_result(result: PipelineResult) -> AnalysisSummary:
    """Build the display-ready view of a finished pipeline run.

    Mirrors the summary the CLI prints to stdout, so an analyst sees the
    same numbers whichever front end ran the case.
    """
    counts: dict[str, int] = {}
    for finding in result.findings:
        label = str(finding.confidence.level)
        counts[label] = counts.get(label, 0) + 1

    parser_errors = tuple(
        f"{error['source_artifact']}: {error['message']}" for error in result.manifest.parser_errors
    )
    report_paths = tuple(sorted(result.report_paths.items()))
    output_dir = Path(result.manifest.config.get("case_output_dir", ""))
    if not output_dir.parts and report_paths:
        output_dir = report_paths[0][1].parent

    return AnalysisSummary(
        case_id=result.manifest.case_id,
        examiner=result.manifest.examiner,
        artifacts=len(result.artifacts),
        events=len(result.events),
        sessions=len(result.sessions),
        findings=tuple(_finding_row(finding) for finding in result.findings),
        confidence_counts=tuple(sorted(counts.items())),
        integrity_verdict=result.manifest.integrity_verdict.value,
        parser_errors=parser_errors,
        output_dir=output_dir,
        report_paths=report_paths,
        html_report=result.report_paths.get("html"),
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_case(case_dir: str | Path) -> VerificationSummary:
    """Re-check a case's recorded evidence digests without re-running analysis.

    Equivalent to ``exfiltrack verify --case-dir``: reads the manifest,
    resolves each recorded relative path against the recorded evidence
    directory, and recomputes SHA-256 digests. For a live-acquisition case
    the case directory itself is accepted; its ``reports/`` folder is used.

    Raises:
        ExfilTrackError: If the directory has no manifest, the manifest is
            not valid JSON, records no digests, or names no evidence
            directory.
    """
    root = Path(case_dir).expanduser()
    if not root.is_dir():
        raise ConfigError(f"Case directory '{root}' does not exist or is not a directory.")
    manifest_path = root / MANIFEST_FILENAME
    auto_manifest_path = root / "reports" / MANIFEST_FILENAME
    if not manifest_path.exists() and auto_manifest_path.exists():
        manifest_path = auto_manifest_path
    if not manifest_path.exists():
        raise ExfilTrackError(f"'{root}' contains no {MANIFEST_FILENAME} (reports/ was checked).")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ExfilTrackError(f"'{manifest_path}' is not valid JSON: {exc}") from exc

    digests = payload.get("intake_digests") or []
    if not digests:
        raise ExfilTrackError(f"'{manifest_path}' records no intake digests; nothing to verify.")
    evidence_value = payload.get("config", {}).get("evidence_dir")
    if not evidence_value:
        raise ExfilTrackError(f"'{manifest_path}' records no evidence directory to verify against.")
    evidence_dir = Path(evidence_value)

    failures: list[str] = []
    for record in digests:
        target = evidence_dir / record["path"]
        try:
            verify_digest(target, record["digest"])
        except (DigestMismatchError, OSError) as exc:
            failures.append(f"{record['path']}: {exc}")
    return VerificationSummary(
        manifest_path=manifest_path,
        evidence_dir=evidence_dir,
        total=len(digests),
        failures=tuple(failures),
    )


# ---------------------------------------------------------------------------
# One-click analysis (issue #49)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QuickCaseSetup:
    """Auto-generated case metadata for a one-click run.

    Attributes:
        case_id: ``AUTO-<UTC timestamp>`` so runs sort chronologically and a
            human can tell them apart. Matches the case directory name.
        examiner: The logged-on user, or ``"unknown"`` if it cannot be
            determined; the analyst can still edit the manifest later, but a
            one-click run must never block on a form field.
        case_dir: Fresh directory the live collector will create.
    """

    case_id: str
    examiner: str
    case_dir: Path


def prepare_quick_case(
    base_dir: Path | None = None,
    *,
    now: datetime | None = None,
    user: str | None = None,
) -> QuickCaseSetup:
    """Generate the metadata a one-click run needs, with no form fields at all.

    Parameters:
        base_dir: Parent for the new case directory. Defaults to
            ``~/ExfilTrackCases``. Injected by tests.
        now: Timestamp used for the case ID; defaults to the current UTC
            time. Injected by tests for determinism.
        user: Examiner name; defaults to the logged-on user.

    The case ID doubles as the case directory name, and an existing
    directory bumps a numeric suffix, so the collector's "must not already
    exist" rule holds without the analyst doing anything.
    """
    stamp = now if now is not None else utc_now()
    base_id = f"AUTO-{stamp:%Y%m%d-%H%M%S}"
    if user is not None:
        examiner = user
    else:
        try:
            examiner = getpass.getuser()
        except (KeyError, OSError):
            examiner = ""
        if not examiner.strip():
            examiner = "unknown"
    root = base_dir if base_dir is not None else Path.home() / "ExfilTrackCases"
    case_id = base_id
    case_dir = root / case_id
    suffix = 2
    while case_dir.exists():
        case_id = f"{base_id}-{suffix}"
        case_dir = root / case_id
        suffix += 1
    return QuickCaseSetup(case_id=case_id, examiner=examiner, case_dir=case_dir)


def run_quick_analysis(
    *, progress: ProgressCallback | None = None, base_dir: Path | None = None
) -> AnalysisSummary:
    """One-click triage: collect from this machine, analyze, and summarize.

    The pipeline invocation is identical to a ``LIVE_MODE``
    :func:`run_analysis` call (same collector, same arguments); the only
    difference is that every form field is generated automatically.

    Parameters:
        progress: Optional callback for one-line status messages.
        base_dir: Forwarded to :func:`prepare_quick_case`; tests use it to
            keep cases inside a temporary directory.
    """
    report = progress if progress is not None else (lambda _message: None)
    setup = prepare_quick_case(base_dir)
    report(f"One-click case {setup.case_id} (examiner {setup.examiner}).")
    report(f"Case directory: {setup.case_dir}")
    result = run_analysis(
        mode=LIVE_MODE,
        evidence_dir="",
        case_dir=str(setup.case_dir),
        case_id=setup.case_id,
        examiner=setup.examiner,
        progress=progress,
    )
    return summarize_result(result)


def detection_statement(summary: AnalysisSummary) -> str:
    """Answer "was anything copied to USB?" in one carefully worded sentence.

    Wording follows the project rule: activity is only ever "consistent with
    possible" exfiltration, ``Confirmed`` is reserved for cryptographic hash
    matches, and an empty result names evidence coverage rather than reading
    as an exoneration (the failure mode issue #34 warns about).
    """
    levels = dict(summary.confidence_counts)
    confirmed = levels.get(str(ConfidenceLevel.CONFIRMED), 0)
    high = levels.get(str(ConfidenceLevel.HIGH), 0)
    medium = levels.get(str(ConfidenceLevel.MEDIUM), 0)
    total = len(summary.findings)
    if total == 0:
        return (
            "No USB sessions were reconstructed from the available evidence. This does "
            "not establish that no copying occurred - see the report's Evidence Coverage "
            "section for sources that were absent or empty."
        )
    if confirmed:
        return (
            f"{confirmed} of {total} session(s) include a cryptographic hash match to a "
            "file on the destination USB (Confirmed): those files were demonstrably "
            "present on the destination device."
        )
    if high + medium:
        return (
            f"{high + medium} of {total} reconstructed USB session(s) show activity "
            f"consistent with possible exfiltration (confidence Medium or higher: "
            f"{high} High, {medium} Medium). Temporal correlation alone does not prove "
            "that a file was copied - review the score breakdowns before acting."
        )
    return (
        f"{total} USB session(s) reconstructed; none rose above Low confidence. No "
        "activity consistent with possible exfiltration stands out in the available "
        "evidence."
    )

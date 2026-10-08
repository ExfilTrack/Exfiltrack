"""End-to-end analysis pipeline orchestration.

Owner: Milindu Weerawarna
Related issues: #1 - Repository Initialization, #13 - Integration Testing

Every module up to this point was built and unit-tested independently:
evidence intake and hashing (#2), the four artifact parsers (#3-#6), event
normalization (#7), USB session reconstruction (#8), risk scoring (#9),
confidence evaluation (#10), and report generation (#11, #12). Nothing
previously tied them into one run. :func:`run_pipeline` is that wiring, and
it is what #13's integration tests exercise end to end rather than
re-implementing the wiring themselves.

``cli.py`` drives :func:`run_pipeline` for both ``analyze --evidence`` (strict:
the first malformed artifact aborts the run) and ``analyze --auto`` (live
collection: a failing artifact is recorded and the run continues).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from types import ModuleType
from typing import Any

from exfiltrack.config import (
    CaseConfig,
    ConfidenceThresholds,
    ExfilTrackError,
    ScoringWeights,
    SessionConfig,
)
from exfiltrack.correlation.sessions import UsbSession, reconstruct_sessions
from exfiltrack.evidence.hashing import hash_file
from exfiltrack.evidence.intake import ArtifactRecord, ArtifactType, discover_artifacts
from exfiltrack.evidence.manifest import (
    CaseManifest,
    DigestRecord,
    IntegrityVerdict,
    ParserRecord,
    utc_now,
    write_manifest,
)
from exfiltrack.normalization.event_model import NormalizedEvent, sort_events
from exfiltrack.parsers import evtx_parser, jumplist_parser, lnk_parser, registry_parser
from exfiltrack.reporting.csv_report import write_csv_reports
from exfiltrack.reporting.html_report import write_html_report
from exfiltrack.reporting.json_report import write_json_report
from exfiltrack.reporting.model import Finding, assemble_findings

# Repository root, so the default limitations text can be found regardless of
# the caller's working directory: pipeline -> exfiltrack -> src -> root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LIMITATIONS_PATH = _REPO_ROOT / "docs" / "limitations.md"


class PipelineError(ExfilTrackError):
    """Raised when the end-to-end pipeline cannot complete a run."""


# ---------------------------------------------------------------------------
# Parser dispatch
# ---------------------------------------------------------------------------

# One entry point per classified artifact type. ArtifactType.UNKNOWN has no
# parser and is intentionally absent: an unrecognised file is recorded in the
# manifest's digests (it was discovered and hashed) but contributes no events.
_DISPATCH: dict[ArtifactType, Callable[[Path], Iterable[NormalizedEvent]]] = {
    ArtifactType.REGISTRY: registry_parser.parse_registry_hive,
    ArtifactType.EVTX: evtx_parser.parse_evtx,
    ArtifactType.LNK: lnk_parser.parse_lnk,
    ArtifactType.JUMP_LIST: jumplist_parser.parse_jumplist,
}

_PARSER_MODULES: dict[ArtifactType, ModuleType] = {
    ArtifactType.REGISTRY: registry_parser,
    ArtifactType.EVTX: evtx_parser,
    ArtifactType.LNK: lnk_parser,
    ArtifactType.JUMP_LIST: jumplist_parser,
}


def _verify_acquisition(manifest: CaseManifest, acquisition: dict[str, Any]) -> None:
    """Check intake digests against what live acquisition recorded it collected.

    The acquisition manifest hashed each snapshot when it was written; intake
    hashes the same files again. Any difference, missing snapshot, or extra
    file means the evidence changed between collection and analysis.

    Raises:
        PipelineError: If the evidence directory does not match the acquisition
            manifest exactly.
    """
    expected: dict[str, str] = {}
    for record in acquisition.get("records", []):
        if record.get("status") != "collected":
            continue
        destination, digest = record.get("destination"), record.get("sha256")
        if not isinstance(destination, str) or not isinstance(digest, str):
            raise PipelineError(
                "Acquisition manifest has a collected record without destination and sha256."
            )
        expected[destination] = digest.lower()
    actual = {record.path: record.digest.lower() for record in manifest.intake_digests}

    problems = [
        f"missing since collection: {path}" for path in sorted(expected.keys() - actual.keys())
    ]
    problems += [
        f"not recorded by acquisition: {path}" for path in sorted(actual.keys() - expected.keys())
    ]
    problems += [
        f"digest differs from acquisition: {path}"
        for path in sorted(expected.keys() & actual.keys())
        if expected[path] != actual[path]
    ]
    if problems:
        raise PipelineError(
            "Collected evidence no longer matches the acquisition manifest; refusing to "
            "analyze it. " + "; ".join(problems)
        )


def _default_limitations_text() -> str:
    """Return the contents of ``docs/limitations.md``, or a safe fallback.

    The HTML report requires this text and refuses to render without the
    disclaimer it carries (Non-Negotiable #7). Falling back to the
    disclaimer sentence alone -- rather than raising -- keeps the pipeline
    runnable from a packaged install where ``docs/`` was not shipped.
    """
    try:
        return DEFAULT_LIMITATIONS_PATH.read_text(encoding="utf-8")
    except OSError:
        return (
            "# Limitations\n\n"
            "ExfilTrack identifies activity consistent with possible USB-based "
            "data exfiltration. Temporal correlation alone does not prove that "
            "a file was copied.\n"
        )


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PipelineResult:
    """Everything one :func:`run_pipeline` call produced.

    Attributes:
        manifest: The completed chain-of-custody manifest, including
            post-analysis digests and the integrity verdict.
        artifacts: Every artifact discovered at intake, in discovery order.
        events: The full normalized timeline, deterministically sorted.
        sessions: Reconstructed USB sessions.
        findings: Scored, confidence-evaluated findings, one per session.
        report_paths: Absolute paths written, keyed by
            ``"manifest"``, ``"json"``, ``"findings_csv"``, ``"timeline_csv"``,
            and ``"html"``. Empty when the run was invoked with
            ``write_reports=False``.
    """

    manifest: CaseManifest
    artifacts: tuple[ArtifactRecord, ...]
    events: tuple[NormalizedEvent, ...]
    sessions: tuple[UsbSession, ...]
    findings: tuple[Finding, ...]
    report_paths: dict[str, Path] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def _sanitize_string(s: str) -> str:
    """Escape surrogate characters to avoid UnicodeEncodeError in reports."""
    return s.encode("utf-8", "backslashreplace").decode("utf-8")


def _sanitize_dict(d: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, str):
            sanitized[k] = _sanitize_string(v)
        elif isinstance(v, dict):
            sanitized[k] = _sanitize_dict(v)
        elif isinstance(v, list):
            sanitized[k] = [_sanitize_string(i) if isinstance(i, str) else i for i in v]
        else:
            sanitized[k] = v
    return sanitized


def _sanitize_event(event: NormalizedEvent) -> NormalizedEvent:
    """Sanitize surrogate unicode characters from event strings."""
    changes: dict[str, Any] = {}
    if event.file_path:
        changes["file_path"] = _sanitize_string(event.file_path)
    if event.source_artifact:
        changes["source_artifact"] = _sanitize_string(event.source_artifact)
    if event.details:
        changes["details"] = _sanitize_dict(event.details)
    if event.device:
        dev = event.device
        dev_changes = {}
        for f in ["device_id", "serial_number", "vendor", "product", "friendly_name"]:
            val = getattr(dev, f)
            if val:
                dev_changes[f] = _sanitize_string(val)
        if dev_changes:
            changes["device"] = replace(dev, **dev_changes)

    if changes:
        return replace(event, **changes)
    return event


def run_pipeline(
    config: CaseConfig,
    *,
    session_config: SessionConfig | None = None,
    scoring_weights: ScoringWeights | None = None,
    confidence_thresholds: ConfidenceThresholds | None = None,
    destination_file_hashes: frozenset[str] = frozenset(),
    limitations_text: str | None = None,
    write_reports: bool = True,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    generated_at: datetime | None = None,
    acquisition: dict[str, Any] | None = None,
    continue_on_parser_error: bool = False,
) -> PipelineResult:
    """Run the full ExfilTrack analysis pipeline for one case, start to finish.

    Stages, each consuming only the previous stage's output (see
    ``docs/architecture.md``): evidence intake and hashing, artifact parsing,
    event normalization, USB session reconstruction, correlation and risk
    scoring, and report generation.

    Parameters:
        config: Validated evidence/output locations and case identity.
        session_config, scoring_weights, confidence_thresholds: Forwarded to
            the correlation stages. Each defaults to its own documented
            defaults when omitted, per ``docs/scoring-model.md``.
        destination_file_hashes: Lowercase hex SHA-256 digests found on the
            destination USB, if that evidence is available separately from
            ``config.evidence_dir``. Forwarded to :func:`score_session
            <exfiltrack.correlation.scoring.score_session>`; empty by
            default, in which case no finding can reach ``Confirmed``.
        limitations_text: Embedded verbatim in the HTML report. Defaults to
            the contents of ``docs/limitations.md``.
        write_reports: When ``False``, the pipeline runs and returns results
            in memory without writing to ``config.case_output_dir``. Used by
            tests that only need to inspect findings.
        start_time, end_time, generated_at: Overrides for the manifest and
            report timestamps. Default to the current UTC time. Callers that
            need byte-identical output across repeated runs -- reproducibility
            is a Non-Negotiable (#5) and part of #13's Definition of Done --
            must pass fixed values here, since wall-clock time is otherwise
            not reproducible.
        acquisition: The live-acquisition manifest, when ``config.evidence_dir``
            was produced by :func:`exfiltrack.evidence.live.collect_live_evidence`.
            Intake digests are checked against it before parsing, and it is
            embedded in the case manifest and reports.
        continue_on_parser_error: When ``True``, an artifact whose parser raises
            an :class:`~exfiltrack.config.ExfilTrackError` is recorded in
            ``manifest.parser_errors`` and skipped, and the run continues with
            the remaining artifacts. It contributes no events at all (partial
            output from a failing parser is discarded). When ``False`` (the
            default, used for manual analysis) the error propagates.

    Returns:
        A :class:`PipelineResult` holding every intermediate and final
        artifact of the run.

    Raises:
        PipelineError: If evidence discovery finds nothing to analyze.
        ArtifactError, RegistryParseError, EvtxParseError, LnkParseError,
        JumpListParseError, SessionReconstructionError, ManifestError,
        ReportError: Propagated unchanged from the stage that raised them
            (Non-Negotiable #4: malformed input is never silently skipped).
    """
    evidence_dir = config.resolved_evidence_dir
    print("Discovering artifacts...")
    artifacts = discover_artifacts(evidence_dir)
    if not artifacts:
        raise PipelineError(f"No evidence artifacts found under '{evidence_dir}'.")

    print(f"Hashing {len(artifacts)} discovered artifacts for intake manifest...")
    manifest = CaseManifest.from_config(config, artifacts, start_time=start_time)
    if acquisition is not None:
        _verify_acquisition(manifest, acquisition)
        manifest.acquisition = acquisition

    events: list[NormalizedEvent] = []
    parser_records: dict[tuple[str, str], ParserRecord] = {}
    total_artifacts = len(artifacts)
    for i, artifact in enumerate(artifacts, 1):
        parse = _DISPATCH.get(artifact.artifact_type)
        if parse is None:
            # Unrecognised file: discovered and hashed into the manifest,
            # but there is no parser to route it to.
            continue
        module = _PARSER_MODULES[artifact.artifact_type]
        safe_name = artifact.path.name.encode("ascii", "backslashreplace").decode("ascii")
        print(f"Parsing {i}/{total_artifacts}: {safe_name}...")
        key = (module.PARSER_NAME, module.PARSER_VERSION)
        parser_records.setdefault(key, ParserRecord(name=key[0], version=key[1]))
        try:
            # Fully consumed before extending, so a parser that fails midway
            # contributes nothing rather than a misleading partial timeline.
            artifact_events = [_sanitize_event(ev) for ev in parse(artifact.path)]
        except ExfilTrackError as exc:
            if not continue_on_parser_error:
                raise
            manifest.parser_errors.append(
                {
                    "source_artifact": artifact.path.as_posix(),
                    "artifact_type": artifact.artifact_type.value,
                    "parser_name": key[0],
                    "parser_version": key[1],
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                }
            )
            continue
        events.extend(artifact_events)

    manifest.parser_records = [parser_records[key] for key in sorted(parser_records)]

    print(f"Normalizing and sorting {len(events)} events into timeline...")
    timeline = sort_events(events)

    print("Reconstructing USB sessions...")
    sessions = reconstruct_sessions(timeline, config=session_config)

    print(f"Scoring and evaluating confidence for {len(sessions)} sessions...")
    findings = assemble_findings(
        sessions,
        weights=scoring_weights,
        thresholds=confidence_thresholds,
        destination_file_hashes=destination_file_hashes,
    )

    print("Re-hashing evidence to verify integrity (post-analysis)...")
    manifest.post_analysis_digests = [
        DigestRecord(path=record.path, digest=hash_file(evidence_dir / record.path))
        for record in manifest.intake_digests
    ]
    manifest.integrity_verdict = (
        IntegrityVerdict.VERIFIED
        if manifest.post_analysis_digests == manifest.intake_digests
        else IntegrityVerdict.FAILED
    )
    manifest.end_time = end_time if end_time is not None else utc_now()

    report_paths: dict[str, Path] = {}
    if write_reports:
        print("Generating case reports (Manifest, JSON, CSV, HTML)...")
        output_dir = config.resolved_case_output_dir
        report_paths["manifest"] = write_manifest(manifest, output_dir)
        report_paths["json"] = write_json_report(list(findings), manifest, output_dir)
        findings_csv, timeline_csv = write_csv_reports(list(findings), output_dir)
        report_paths["findings_csv"] = findings_csv
        report_paths["timeline_csv"] = timeline_csv
        report_paths["html"] = write_html_report(
            list(findings),
            manifest,
            limitations_text if limitations_text is not None else _default_limitations_text(),
            output_dir,
            generated_at=generated_at,
        )
        print(f"Reports successfully written to: {output_dir}")

    return PipelineResult(
        manifest=manifest,
        artifacts=tuple(artifacts),
        events=tuple(timeline),
        sessions=tuple(sessions),
        findings=tuple(findings),
        report_paths=report_paths,
    )

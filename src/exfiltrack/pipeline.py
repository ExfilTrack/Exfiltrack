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

``cli.py`` still raises ``NotImplementedError``. Wiring its ``analyze``
command to :func:`run_pipeline` is a small, separate follow-up -- out of
scope for #13, which only requires the pipeline to be runnable, not that it
have a command-line front end yet.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import ModuleType

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
    artifacts = discover_artifacts(evidence_dir)
    if not artifacts:
        raise PipelineError(f"No evidence artifacts found under '{evidence_dir}'.")

    manifest = CaseManifest.from_config(config, artifacts, start_time=start_time)

    events: list[NormalizedEvent] = []
    parser_records: dict[tuple[str, str], ParserRecord] = {}
    for artifact in artifacts:
        parse = _DISPATCH.get(artifact.artifact_type)
        if parse is None:
            # Unrecognised file: discovered and hashed into the manifest,
            # but there is no parser to route it to.
            continue
        module = _PARSER_MODULES[artifact.artifact_type]
        events.extend(parse(artifact.path))
        key = (module.PARSER_NAME, module.PARSER_VERSION)
        parser_records.setdefault(key, ParserRecord(name=key[0], version=key[1]))

    manifest.parser_records = [parser_records[key] for key in sorted(parser_records)]

    timeline = sort_events(events)
    sessions = reconstruct_sessions(timeline, config=session_config)
    findings = assemble_findings(
        sessions,
        weights=scoring_weights,
        thresholds=confidence_thresholds,
        destination_file_hashes=destination_file_hashes,
    )

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

    return PipelineResult(
        manifest=manifest,
        artifacts=tuple(artifacts),
        events=tuple(timeline),
        sessions=tuple(sessions),
        findings=tuple(findings),
        report_paths=report_paths,
    )

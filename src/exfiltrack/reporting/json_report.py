"""Machine-readable JSON report generation.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #12 - JSON/CSV Export

Emits the full finding set -- every session, its score breakdown, and its
confidence level -- alongside the chain-of-custody manifest, as a single
JSON document for downstream tooling.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from exfiltrack.config import ExfilTrackError
from exfiltrack.correlation.models import NormalizedEvent
from exfiltrack.evidence.manifest import CaseManifest
from exfiltrack.reporting.model import Finding

JSON_REPORT_FILENAME = "findings.json"
JSON_SCHEMA_VERSION = "1.0"


class ReportError(ExfilTrackError):
    """Raised when the JSON report cannot be built or written."""


def _event_to_dict(event: NormalizedEvent) -> dict[str, Any]:
    """Render one file-activity event as a JSON-serialisable dict.

    ``details`` keys are sorted so output is deterministic regardless of
    the dict's original insertion order (Definition of Done, #12).
    """
    return {
        "event_type": event.event_type,
        "timestamp_utc": event.timestamp_utc.isoformat(),
        "raw_timestamp": event.raw_timestamp,
        "source_artifact": event.source_artifact,
        "parser_name": event.parser_name,
        "parser_version": event.parser_version,
        "file_path": event.file_path,
        "file_size_bytes": event.file_size_bytes,
        "details": dict(sorted(event.details.items())),
    }


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    session = finding.session
    return {
        "session_id": session.session_id,
        "device": {
            "device_id": session.device.device_id,
            "serial_number": session.device.serial_number,
            "vendor": session.device.vendor,
            "product": session.device.product,
            "friendly_name": session.device.friendly_name,
        },
        "start": {
            "timestamp_utc": session.start.timestamp_utc.isoformat(),
            "observed": session.start.observed,
        },
        "end": {
            "timestamp_utc": session.end.timestamp_utc.isoformat(),
            "observed": session.end.observed,
        },
        "file_events": [_event_to_dict(e) for e in session.file_events],
        "score": {
            "total": finding.scored_session.total_score,
            "contributions": [
                {
                    "rule": c.rule,
                    "points": c.points,
                    "source_artifacts": list(c.source_artifacts),
                    "explanation": c.explanation,
                }
                for c in finding.scored_session.contributions
            ],
        },
        "confidence": {
            "level": finding.confidence.level.name,
            "reason": finding.confidence.reason,
        },
    }


def build_json_report(findings: list[Finding], manifest: CaseManifest) -> dict[str, Any]:
    """Assemble the full machine-readable finding set as a plain dict.

    Findings are expected to already be in a deterministic order (see
    :func:`exfiltrack.reporting.model.assemble_findings`); this function
    does not re-sort them, so callers control ordering explicitly.
    """
    return {
        "schema_version": JSON_SCHEMA_VERSION,
        "manifest": manifest.to_dict(),
        "findings": [_finding_to_dict(f) for f in findings],
    }


def render_json_report(findings: list[Finding], manifest: CaseManifest) -> str:
    """Serialise the report to a deterministic JSON string.

    ``sort_keys=True`` and a fixed indent make output byte-identical across
    runs on identical input (Definition of Done, #12); nothing here relies
    on Python dict insertion order.
    """
    payload = build_json_report(findings, manifest)
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def write_json_report(
    findings: list[Finding], manifest: CaseManifest, case_output_dir: Path
) -> Path:
    """Render and write the JSON report into *case_output_dir*.

    Never writes into the evidence directory; ``case_output_dir`` is
    whatever the caller's :class:`~exfiltrack.config.CaseConfig` designates
    as the case output location.

    Returns:
        The absolute path the report was written to.
    """
    text = render_json_report(findings, manifest)
    destination = case_output_dir.resolve() / JSON_REPORT_FILENAME
    try:
        case_output_dir.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Cannot write JSON report to '{destination}': {exc}") from exc
    return destination

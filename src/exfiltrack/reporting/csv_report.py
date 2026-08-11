"""Spreadsheet-friendly CSV report generation: the flat findings table.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #12 - JSON/CSV Export

One row per score contribution, so a reviewer can filter/sort by rule in
a spreadsheet without losing the explanation behind each point. A session
with no contributions still gets one row (with empty rule columns), so a
finding with a zero score is never silently absent from the sheet.

The reconstructed timeline table is added in a follow-up change.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from exfiltrack.config import ExfilTrackError
from exfiltrack.reporting.model import Finding

FINDINGS_CSV_FILENAME = "findings.csv"

FINDINGS_COLUMNS = (
    "session_id",
    "device_id",
    "device_friendly_name",
    "start_timestamp_utc",
    "start_observed",
    "end_timestamp_utc",
    "end_observed",
    "total_score",
    "confidence_level",
    "confidence_reason",
    "rule",
    "rule_points",
    "rule_source_artifacts",
    "rule_explanation",
)


class ReportError(ExfilTrackError):
    """Raised when a CSV report cannot be built or written."""


def _findings_rows(findings: list[Finding]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for finding in findings:
        session = finding.session
        base = {
            "session_id": session.session_id,
            "device_id": session.device.device_id,
            "device_friendly_name": session.device.display_name,
            "start_timestamp_utc": session.start.timestamp_utc.isoformat(),
            "start_observed": str(session.start.observed),
            "end_timestamp_utc": session.end.timestamp_utc.isoformat(),
            "end_observed": str(session.end.observed),
            "total_score": str(finding.scored_session.total_score),
            "confidence_level": finding.confidence.level.name,
            "confidence_reason": finding.confidence.reason,
        }
        contributions = finding.scored_session.contributions
        if not contributions:
            rows.append(
                {
                    **base,
                    "rule": "",
                    "rule_points": "",
                    "rule_source_artifacts": "",
                    "rule_explanation": "",
                }
            )
            continue
        for c in contributions:
            rows.append(
                {
                    **base,
                    "rule": c.rule,
                    "rule_points": str(c.points),
                    "rule_source_artifacts": ";".join(c.source_artifacts),
                    "rule_explanation": c.explanation,
                }
            )
    return rows


def _render_csv(columns: tuple[str, ...], rows: list[dict[str, str]]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(columns), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def render_findings_csv(findings: list[Finding]) -> str:
    """Render the flat findings table.

    Column order is fixed (``FINDINGS_COLUMNS``) so diffs between runs stay
    readable, and output is byte-identical across runs on identical input
    since ``findings`` is expected to already be in a deterministic order
    (see :func:`exfiltrack.reporting.model.assemble_findings`).
    """
    return _render_csv(FINDINGS_COLUMNS, _findings_rows(findings))


def write_findings_csv(findings: list[Finding], case_output_dir: Path) -> Path:
    """Write the findings table into *case_output_dir* and return its path."""
    destination = case_output_dir.resolve() / FINDINGS_CSV_FILENAME
    try:
        case_output_dir.mkdir(parents=True, exist_ok=True)
        destination.write_text(render_findings_csv(findings), encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Cannot write findings CSV to '{destination}': {exc}") from exc
    return destination

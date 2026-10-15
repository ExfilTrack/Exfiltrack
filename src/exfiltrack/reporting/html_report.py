"""Self-contained HTML report generation.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #11 - HTML Report Generator

Renders findings, their score breakdowns, confidence levels, and the
chain-of-custody manifest into a single self-contained HTML file: no
external CSS, fonts, or scripts, since the report may be opened on a
machine with no network access.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import markdown
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from exfiltrack.config import ExfilTrackError
from exfiltrack.correlation.scoring import ScoreContribution
from exfiltrack.evidence.manifest import CaseManifest
from exfiltrack.normalization.event_model import NormalizedEvent
from exfiltrack.reporting.model import Finding

# Keep the default resources beside this module so source checkouts and
# installed wheels use the same canonical templates and stylesheet.
DEFAULT_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
REPORT_FILENAME = "report.html"
TEMPLATE_NAME = "report.html.j2"

# Phrases the report must never use: they overstate what artifacts prove
# (docs/limitations.md, templates/README.md). Checked on every render, not
# just in tests, so a future template edit that reintroduces this language
# fails loudly instead of shipping silently.
_FORBIDDEN_PHRASES = (
    "proved",
    "proof that",
    "confirmed theft",
    "stole",
    "definitely exfiltrated",
    "definitively",
)
_REQUIRED_DISCLAIMER = "consistent with possible exfiltration"

# Whole-word/whole-phrase patterns for _FORBIDDEN_PHRASES. A plain substring
# check false-positives on unrelated words that merely contain a forbidden
# one -- e.g. "proved" inside "approved" -- which is exactly the sentence
# docs/limitations.md uses for the clipboard limitation ("pasted into
# approved communication platforms"). Found via #13 integration testing,
# running this renderer against the real limitations text for the first time.
_FORBIDDEN_PATTERNS = [
    re.compile(r"\b" + re.escape(phrase) + r"\b") for phrase in _FORBIDDEN_PHRASES
]


class ReportError(ExfilTrackError):
    """Raised when a report cannot be rendered or written."""


def _fmt_ts(value: datetime) -> str:
    """Render a UTC datetime as ``YYYY-MM-DD HH:MM:SS UTC``."""
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def _humanize(rule_name: str) -> str:
    """Render a snake_case rule name (e.g. ``activity_within_30s``) for display."""
    return rule_name.replace("_", " ").title()


# ---------------------------------------------------------------------------
# Presentation view-model
#
# The report is investigator-facing: the reader needs the answer (which
# session, which device, how strong) before the evidence behind it. These
# helpers order findings by risk and roll up per-firing rule contributions
# into per-rule rows, without dropping anything: every firing and every cited
# artifact is still rendered, collapsed but present (traceability, requirement
# 4), and every ordering key is total and stable (reproducibility,
# requirement 7).
# ---------------------------------------------------------------------------

#: File-activity rows rendered directly inside an expanded session. Sessions
#: with more events keep the remainder in a collapsed table, so the document
#: stays complete without presenting a wall of rows by default.
VISIBLE_FILE_EVENT_ROWS = 20


@dataclass(frozen=True)
class RuleFiring:
    """One firing of a scoring rule: its explanation and cited artifacts."""

    explanation: str
    artifacts: tuple[str, ...]


@dataclass(frozen=True)
class RuleRollup:
    """Every firing of one scoring rule within a session, aggregated for display.

    ``artifacts`` is the ordered union across firings with duplicates removed,
    so each cited evidence file appears once no matter how often the rule fired.
    """

    rule: str
    total_points: int
    firings: tuple[RuleFiring, ...]
    artifacts: tuple[str, ...]


@dataclass(frozen=True)
class FindingView:
    """A finding plus its presentation metadata: document anchor and rollups."""

    finding: Finding
    anchor: str
    rollups: tuple[RuleRollup, ...]


@dataclass(frozen=True)
class ReportSummary:
    """Case-level figures for the executive summary strip."""

    session_count: int
    device_count: int
    total_file_events: int
    highest_confidence: str
    highest_confidence_class: str
    max_score: int


def _risk_key(finding: Finding) -> tuple[object, ...]:
    """Order findings highest-risk first, with total and stable tie-breaks."""
    return (
        -int(finding.confidence.level),
        -finding.scored_session.total_score,
        finding.session.start.timestamp_utc,
        finding.session.device.device_id,
        finding.session.session_id,
    )


def _rollup_contributions(
    contributions: Iterable[ScoreContribution],
) -> tuple[RuleRollup, ...]:
    """Group a session's contributions by rule, preserving every firing."""
    by_rule: dict[str, list[ScoreContribution]] = {}
    for contribution in contributions:
        by_rule.setdefault(contribution.rule, []).append(contribution)
    rollups = [
        RuleRollup(
            rule=rule,
            total_points=sum(item.points for item in items),
            firings=tuple(
                RuleFiring(explanation=item.explanation, artifacts=item.source_artifacts)
                for item in items
            ),
            artifacts=tuple(
                dict.fromkeys(artifact for item in items for artifact in item.source_artifacts)
            ),
        )
        for rule, items in by_rule.items()
    ]
    rollups.sort(key=lambda rollup: (-rollup.total_points, rollup.rule))
    return tuple(rollups)


def build_finding_views(findings: list[Finding]) -> tuple[FindingView, ...]:
    """Order findings by risk and pre-compute each one's per-rule rollups."""
    return tuple(
        FindingView(
            finding=finding,
            anchor=f"session-{index}",
            rollups=_rollup_contributions(finding.scored_session.contributions),
        )
        for index, finding in enumerate(sorted(findings, key=_risk_key), start=1)
    )


def summarize_views(views: tuple[FindingView, ...]) -> ReportSummary:
    """Aggregate the case-level figures shown in the executive summary."""
    if not views:
        return ReportSummary(0, 0, 0, "", "none", 0)
    highest = max(view.finding.confidence.level for view in views)
    return ReportSummary(
        session_count=len(views),
        device_count=len({view.finding.session.device.device_id for view in views}),
        total_file_events=sum(len(view.finding.session.file_events) for view in views),
        highest_confidence=str(highest),
        highest_confidence_class=highest.name.lower(),
        max_score=max(view.finding.scored_session.total_score for view in views),
    )


def _environment(templates_dir: Path) -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["fmt_ts"] = _fmt_ts
    env.filters["humanize"] = _humanize
    return env


def render_html_report(
    findings: list[Finding],
    manifest: CaseManifest,
    limitations_text: str,
    *,
    templates_dir: Path | None = None,
    generated_at: datetime | None = None,
    unattached_file_events: Iterable[NormalizedEvent] = (),
) -> str:
    """Render the investigator-facing HTML report as a string.

    Parameters:
        findings: Every reconstructed session with its score and
            confidence, typically from
            :func:`exfiltrack.reporting.model.assemble_findings`.
        manifest: The run's chain-of-custody manifest.
        limitations_text: Full text of the limitations section (normally
            the contents of ``docs/limitations.md``), embedded rather than
            linked so the report stands alone on a machine with no network
            access.
        templates_dir: Override for the templates directory. Defaults to
            the packaged ``exfiltrack.reporting/templates/`` resources.
        generated_at: Override for the report's generation timestamp.
            Defaults to now, in the manifest's timezone.
        unattached_file_events: Recorded file accesses that fell outside
            every reconstructed session window. Disclosed in their own
            section so the report never under-counts recorded file activity;
            they are never attributed to a session or scored.

    Returns:
        The complete HTML document as a string.

    Raises:
        ReportError: If the template or stylesheet cannot be read, or if
            the rendered output contains language that overstates what the
            evidence proves.

    All values sourced from evidence (file paths, device names, artifact
    paths) are rendered through Jinja2's autoescaping, since they are
    untrusted input that must never be interpreted as HTML.
    """
    dir_ = templates_dir or DEFAULT_TEMPLATES_DIR
    env = _environment(dir_)
    try:
        template = env.get_template(TEMPLATE_NAME)
    except Exception as exc:  # jinja2.TemplateError and friends
        raise ReportError(f"Cannot load template '{TEMPLATE_NAME}' from '{dir_}': {exc}") from exc

    css_path = dir_ / "styles.css"
    try:
        inline_css = css_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Cannot read stylesheet '{css_path}': {exc}") from exc

    when = generated_at or datetime.now(tz=manifest.start_time.tzinfo)
    html_limitations = Markup(
        markdown.markdown(limitations_text, extensions=["tables", "fenced_code"])
    )
    views = build_finding_views(findings)
    html = template.render(
        finding_views=views,
        summary=summarize_views(views),
        visible_file_events=VISIBLE_FILE_EVENT_ROWS,
        manifest=manifest,
        limitations_text=html_limitations,
        inline_css=inline_css,
        generated_at=when,
        tool_name=manifest.tool_name,
        tool_version=manifest.tool_version,
        unattached_file_events=list(unattached_file_events),
    )
    _assert_safe_wording(html)
    return html


def _assert_safe_wording(html: str) -> None:
    """Guard against report language that overstates what artifacts prove.

    Findings must be phrased as activity consistent with possible
    exfiltration, never as proof of it (templates/README.md,
    docs/limitations.md).
    """
    lowered = html.lower()
    for phrase, pattern in zip(_FORBIDDEN_PHRASES, _FORBIDDEN_PATTERNS, strict=True):
        if pattern.search(lowered):
            raise ReportError(
                f"Report text contains forbidden phrase '{phrase}'. Findings must be "
                "phrased as activity consistent with possible exfiltration, never as "
                "proof."
            )
    if _REQUIRED_DISCLAIMER not in lowered:
        raise ReportError(
            f"Report is missing the required disclaimer phrase '{_REQUIRED_DISCLAIMER}'."
        )


def write_html_report(
    findings: list[Finding],
    manifest: CaseManifest,
    limitations_text: str,
    case_output_dir: Path,
    *,
    templates_dir: Path | None = None,
    generated_at: datetime | None = None,
    unattached_file_events: Iterable[NormalizedEvent] = (),
) -> Path:
    """Render and write the HTML report into *case_output_dir*.

    Never writes into the evidence directory: ``case_output_dir`` is
    whatever the caller's :class:`~exfiltrack.config.CaseConfig` designates
    as the case output location, which is already validated to be disjoint
    from the evidence directory.

    Returns:
        The absolute path the report was written to.

    Raises:
        ReportError: If the report cannot be rendered, or the destination
            cannot be written.
    """
    html = render_html_report(
        findings,
        manifest,
        limitations_text,
        templates_dir=templates_dir,
        generated_at=generated_at,
        unattached_file_events=unattached_file_events,
    )
    destination = case_output_dir.resolve() / REPORT_FILENAME
    try:
        case_output_dir.mkdir(parents=True, exist_ok=True)
        destination.write_text(html, encoding="utf-8", errors="backslashreplace")
    except OSError as exc:
        raise ReportError(f"Cannot write HTML report to '{destination}': {exc}") from exc
    return destination

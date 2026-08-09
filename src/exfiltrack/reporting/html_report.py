"""Self-contained HTML report generation.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #11 - HTML Report Generator

Renders findings, their score breakdowns, confidence levels, and the
chain-of-custody manifest into a single self-contained HTML file: no
external CSS, fonts, or scripts, since the report may be opened on a
machine with no network access.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from exfiltrack.config import ExfilTrackError
from exfiltrack.evidence.manifest import CaseManifest
from exfiltrack.reporting.model import Finding

# templates/ lives at the repository root, not under src/, per
# templates/README.md. From this file: reporting -> exfiltrack -> src -> root.
DEFAULT_TEMPLATES_DIR = Path(__file__).resolve().parents[3] / "templates"
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


class ReportError(ExfilTrackError):
    """Raised when a report cannot be rendered or written."""


def _fmt_ts(value: datetime) -> str:
    """Render a UTC datetime as ``YYYY-MM-DD HH:MM:SS UTC``."""
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def _humanize(rule_name: str) -> str:
    """Render a snake_case rule name (e.g. ``activity_within_30s``) for display."""
    return rule_name.replace("_", " ").title()


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
            the repository's top-level ``templates/``.
        generated_at: Override for the report's generation timestamp.
            Defaults to now, in the manifest's timezone.

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
    html = template.render(
        findings=findings,
        manifest=manifest,
        limitations_text=limitations_text,
        inline_css=inline_css,
        generated_at=when,
        tool_name=manifest.tool_name,
        tool_version=manifest.tool_version,
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
    for phrase in _FORBIDDEN_PHRASES:
        if phrase in lowered:
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
    )
    destination = case_output_dir.resolve() / REPORT_FILENAME
    try:
        case_output_dir.mkdir(parents=True, exist_ok=True)
        destination.write_text(html, encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Cannot write HTML report to '{destination}': {exc}") from exc
    return destination

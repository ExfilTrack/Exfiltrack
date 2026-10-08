"""Installed-package HTML resources must not depend on repository paths."""

from __future__ import annotations

from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

import pytest

from exfiltrack.evidence.manifest import CaseManifest
from exfiltrack.reporting.html_report import (
    DEFAULT_TEMPLATES_DIR,
    TEMPLATE_NAME,
    render_html_report,
)


@pytest.mark.unit
@pytest.mark.parametrize("name", [TEMPLATE_NAME, "styles.css"])
def test_report_resources_are_available_from_package(name: str) -> None:
    resource = files("exfiltrack.reporting").joinpath("templates", name)

    assert resource.is_file()
    assert resource.read_text(encoding="utf-8")
    assert (DEFAULT_TEMPLATES_DIR / name).read_text(encoding="utf-8") == resource.read_text(
        encoding="utf-8"
    )


@pytest.mark.unit
def test_default_report_resources_are_independent_of_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    manifest = CaseManifest(
        case_id="PACKAGED-CASE",
        examiner="Resource Tester",
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    html = render_html_report([], manifest, "Resource test limitations.")

    assert "PACKAGED-CASE" in html
    assert "No USB sessions were reconstructed" in html
    assert "<style>" in html
    assert "--ink: #1b1f24;" in html
    assert not (tmp_path / "templates").exists()

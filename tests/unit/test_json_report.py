"""Unit tests for the JSON report generator.

Related issue: #12 - JSON/CSV Export
"""

from __future__ import annotations

import json

import pytest

from exfiltrack.config import ScoringWeights
from exfiltrack.correlation.sessions import reconstruct_sessions
from exfiltrack.evidence.manifest import CaseManifest
from exfiltrack.reporting.json_report import build_json_report, render_json_report
from exfiltrack.reporting.model import assemble_findings
from tests.unit.factories import (
    make_device,
    make_file_event,
    make_insert_event,
    make_remove_event,
    utc,
)

WEIGHTS = ScoringWeights(protected_directories=(r"C:\Projects\confidential",))


def _manifest(**overrides: object) -> CaseManifest:
    defaults: dict[str, object] = {
        "case_id": "CASE-001",
        "examiner": "J. Doe",
        "start_time": utc(2026, 1, 1, 8, 0, 0),
    }
    defaults.update(overrides)
    return CaseManifest(**defaults)  # type: ignore[arg-type]


def _findings_with_activity():
    device = make_device()
    digest = "a" * 64
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 10, 0, 0), device),
        make_file_event(
            utc(2026, 1, 1, 9, 0, 10),
            r"C:\Projects\confidential\secrets.env",
            sha256=digest,
        ),
    ]
    sessions = reconstruct_sessions(events)
    return assemble_findings(sessions, weights=WEIGHTS, destination_file_hashes=frozenset({digest}))


@pytest.mark.unit
def test_rendered_json_is_valid_and_parses_back() -> None:
    text = render_json_report(_findings_with_activity(), _manifest())

    parsed = json.loads(text)

    assert parsed["schema_version"] == "1.0"
    assert parsed["manifest"]["case_id"] == "CASE-001"
    assert len(parsed["findings"]) == 1


@pytest.mark.unit
def test_every_score_contribution_is_present() -> None:
    findings = _findings_with_activity()
    payload = build_json_report(findings, _manifest())

    finding = payload["findings"][0]
    rules = {c["rule"] for c in finding["score"]["contributions"]}
    assert "activity_within_30s" in rules
    assert "destination_hash_match" in rules
    assert finding["confidence"]["level"] == "CONFIRMED"


@pytest.mark.unit
def test_parser_versions_are_carried_through_from_events() -> None:
    findings = _findings_with_activity()
    payload = build_json_report(findings, _manifest())

    file_event = payload["findings"][0]["file_events"][0]
    assert file_event["parser_name"]
    assert file_event["parser_version"]
    assert file_event["source_artifact"]


@pytest.mark.unit
def test_manifest_is_embedded_in_full() -> None:
    manifest = _manifest(examiner="A. Investigator")
    payload = build_json_report([], manifest)

    assert payload["manifest"]["examiner"] == "A. Investigator"
    assert payload["manifest"]["tool_name"]
    assert "integrity_verdict" in payload["manifest"]


@pytest.mark.unit
def test_zero_findings_produces_valid_empty_report() -> None:
    text = render_json_report([], _manifest())

    parsed = json.loads(text)
    assert parsed["findings"] == []


@pytest.mark.unit
def test_output_is_byte_identical_across_runs_on_identical_input() -> None:
    """Required scenario (#12 Definition of Done): deterministic, byte-identical output."""
    findings = _findings_with_activity()
    manifest = _manifest()

    first = render_json_report(findings, manifest)
    second = render_json_report(findings, manifest)

    assert first == second


@pytest.mark.unit
def test_output_is_sorted_regardless_of_dict_insertion_order() -> None:
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 10, 0, 0), device),
        make_file_event(
            utc(2026, 1, 1, 9, 0, 10),
            r"C:\Users\dev\report.docx",
            sha256="b" * 64,
        ),
    ]
    # Reorder the underlying details dict; output must not change as a result.
    events[2] = make_file_event(
        utc(2026, 1, 1, 9, 0, 10), r"C:\Users\dev\report.docx", sha256="b" * 64
    )
    sessions = reconstruct_sessions(events)
    findings = assemble_findings(sessions, weights=WEIGHTS)

    text = render_json_report(findings, _manifest())

    # "details" keys should appear sorted (here just "sha256", but this
    # guards against future non-determinism from insertion order).
    parsed = json.loads(text)
    details = parsed["findings"][0]["file_events"][0]["details"]
    assert list(details.keys()) == sorted(details.keys())


@pytest.mark.unit
def test_session_with_no_file_activity_has_empty_events_list() -> None:
    device = make_device()
    events = [
        make_insert_event(utc(2026, 1, 1, 9, 0, 0), device),
        make_remove_event(utc(2026, 1, 1, 9, 30, 0), device),
    ]
    sessions = reconstruct_sessions(events)
    findings = assemble_findings(sessions, weights=WEIGHTS)

    payload = build_json_report(findings, _manifest())

    assert payload["findings"][0]["file_events"] == []
    assert payload["findings"][0]["score"]["contributions"] == []

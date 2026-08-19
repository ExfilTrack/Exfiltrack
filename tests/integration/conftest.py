"""Shared fixtures for #13 end-to-end pipeline integration tests.

Each test builds a real evidence directory, runs it through
``exfiltrack.pipeline.run_pipeline`` (the same wiring a future CLI would
use), and asserts on the result. See ``tests/support/synthetic_evtx.py``
for why EVTX content is synthetic while everything around it -- intake,
classification, hashing, dispatch, normalization, session reconstruction,
scoring, confidence evaluation, report generation, and the manifest -- runs
unmodified.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from exfiltrack.config import CaseConfig
from exfiltrack.pipeline import PipelineResult, run_pipeline
from tests.support.synthetic_evtx import SyntheticEvtxReader, placeholder_evtx_file

# Fixed so report bytes are reproducible across runs (Non-Negotiable #5);
# see docs/scoring-model.md and #13's Definition of Done.
FIXED_START = datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc)
FIXED_END = datetime(2026, 3, 1, 8, 30, 0, tzinfo=timezone.utc)
FIXED_GENERATED_AT = datetime(2026, 3, 1, 8, 30, 0, tzinfo=timezone.utc)

DEVICE_ID = r"USB\VID_1234&PID_5678\SERIAL001"


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "evidence"
    directory.mkdir()
    return directory


@pytest.fixture
def case_output_dir(tmp_path: Path) -> Path:
    return tmp_path / "case"


def run_scenario(
    monkeypatch: pytest.MonkeyPatch,
    evidence_dir: Path,
    case_output_dir: Path,
    evtx_records_by_file: dict[str, list[str]],
    *,
    case_id: str = "CASE-INTEGRATION-0001",
    examiner: str = "M. Weerawarna",
    **pipeline_kwargs: object,
) -> PipelineResult:
    """Write placeholder EVTX files, install the synthetic reader, and run the pipeline.

    Args:
        evtx_records_by_file: Maps a path relative to ``evidence_dir`` (e.g.
            ``"logs/System.evtx"``) to the Event XML records that file should
            yield -- built with
            :func:`tests.support.synthetic_evtx.device_lifecycle_xml` and
            :func:`tests.support.synthetic_evtx.file_access_xml`. An entry
            with an empty list still creates a real, empty-of-events EVTX
            artifact, so a scenario can include a log file that legitimately
            contains nothing relevant.
        pipeline_kwargs: Forwarded to :func:`run_pipeline`, overriding the
            fixed default timestamps below when a test needs to.
    """
    records_by_path: dict[str, list[str]] = {}
    for relative_name, records in evtx_records_by_file.items():
        path = evidence_dir / relative_name
        placeholder_evtx_file(path)
        records_by_path[path.resolve().as_posix()] = records

    monkeypatch.setattr(
        "exfiltrack.parsers.evtx_parser.evtx.Evtx",
        SyntheticEvtxReader(records_by_path),
    )

    config = CaseConfig(
        evidence_dir=evidence_dir,
        case_output_dir=case_output_dir,
        case_id=case_id,
        examiner=examiner,
    )
    kwargs: dict[str, object] = {
        "start_time": FIXED_START,
        "end_time": FIXED_END,
        "generated_at": FIXED_GENERATED_AT,
    }
    kwargs.update(pipeline_kwargs)
    return run_pipeline(config, **kwargs)

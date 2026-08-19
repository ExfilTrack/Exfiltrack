"""Reproducibility and evidence-integrity checks (#13 Definition of Done).

Non-Negotiable #5: "Output is deterministic. Same evidence plus same tool
version must produce identical bytes." Non-Negotiable #1: evidence is opened
read-only and never modified. These two properties are the ones an
individual scenario test cannot show on its own, so they get their own
tests here, run against scenario 2's evidence (the richest of the four).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from exfiltrack.evidence.hashing import hash_file
from exfiltrack.evidence.manifest import IntegrityVerdict
from tests.integration.conftest import DEVICE_ID, run_scenario
from tests.support.synthetic_evtx import device_lifecycle_xml, file_access_xml

BASE = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)


def _theft_records() -> dict[str, list[str]]:
    insert = device_lifecycle_xml(
        event_id="2003", device_instance_id=DEVICE_ID, when=BASE, record_id=1
    )
    remove = device_lifecycle_xml(
        event_id="2102",
        device_instance_id=DEVICE_ID,
        when=BASE + timedelta(minutes=10),
        record_id=2,
    )
    return {
        "logs/System.evtx": [insert, remove],
        "logs/Security.evtx": [
            file_access_xml(
                object_name=r"E:\Confidential\db_dump.sql",
                when=BASE + timedelta(seconds=5),
                record_id=10,
            ),
            file_access_xml(
                object_name=r"E:\Confidential\keys.pem",
                when=BASE + timedelta(seconds=12),
                record_id=11,
            ),
        ],
    }


@pytest.mark.integration
@pytest.mark.requires_fixtures
def test_identical_evidence_and_config_produce_byte_identical_reports(
    monkeypatch: pytest.MonkeyPatch, evidence_dir: Path, case_output_dir: Path
) -> None:
    """Two runs over the same evidence, config, and fixed timestamps match exactly."""
    records = _theft_records()

    first = run_scenario(monkeypatch, evidence_dir, case_output_dir, records)
    first_bytes = {name: path.read_bytes() for name, path in first.report_paths.items()}

    second = run_scenario(monkeypatch, evidence_dir, case_output_dir, records)
    second_bytes = {name: path.read_bytes() for name, path in second.report_paths.items()}

    assert first_bytes.keys() == {"manifest", "json", "findings_csv", "timeline_csv", "html"}
    assert first_bytes == second_bytes


@pytest.mark.integration
@pytest.mark.requires_fixtures
def test_full_run_leaves_evidence_digests_unchanged(
    monkeypatch: pytest.MonkeyPatch, evidence_dir: Path, case_output_dir: Path
) -> None:
    """Evidence files are byte-identical, independently re-hashed, after a full run."""
    result = run_scenario(monkeypatch, evidence_dir, case_output_dir, _theft_records())

    assert result.manifest.integrity_verdict is IntegrityVerdict.VERIFIED
    assert result.manifest.post_analysis_digests == result.manifest.intake_digests

    # Re-hash independently of the pipeline's own post-analysis check, so this
    # test does not just confirm the pipeline agrees with itself.
    for record in result.manifest.intake_digests:
        assert hash_file(evidence_dir / record.path) == record.digest

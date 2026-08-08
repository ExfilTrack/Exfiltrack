"""Unit tests for evidence intake, hashing, and manifesting.

Related issue: #2 - Evidence Intake and Hash Verification

These tests use only synthetic evidence built inside ``tmp_path``; no real
forensic images are required.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from exfiltrack.config import CaseConfig, ConfigError, ExfilTrackError, PathOverlapError
from exfiltrack.evidence.hashing import (
    CHUNK_SIZE,
    DigestMismatchError,
    IntegrityError,
    hash_file,
    verify_digest,
)
from exfiltrack.evidence.intake import (
    ArtifactError,
    ArtifactType,
    discover_artifacts,
)
from exfiltrack.evidence.manifest import (
    MANIFEST_FILENAME,
    CaseManifest,
    IntegrityVerdict,
    ManifestError,
    ParserRecord,
    build_digest_records,
    verify_manifest,
    write_manifest,
)

REGISTRY_HEADER = b"regf" + b"\x00" * 60
EVTX_HEADER = b"ElfFile\x00" + b"\x00" * 56
LNK_HEADER = b"\x4c\x00\x00\x00" + b"\x01\x14\x02\x00" + b"\x00" * 56
OLE_HEADER = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 56

EXAMINER = "Milindu Weerawarna"
CASE_ID = "CASE-2026-001"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    """A synthetic evidence tree holding one file of each artifact type."""
    root = tmp_path / "evidence"
    (root / "hives").mkdir(parents=True)
    (root / "logs").mkdir(parents=True)

    (root / "hives" / "SYSTEM").write_bytes(REGISTRY_HEADER)
    (root / "logs" / "Security.evtx").write_bytes(EVTX_HEADER)
    (root / "Recent.lnk").write_bytes(LNK_HEADER)
    (root / "1b4dd67f29cb1962.automaticDestinations-ms").write_bytes(OLE_HEADER)
    (root / "notes.txt").write_bytes(b"not an artifact")
    return root


def make_config(tmp_path: Path, evidence: Path) -> CaseConfig:
    """Build a valid CaseConfig with output held outside the evidence tree."""
    return CaseConfig(
        evidence_dir=evidence,
        case_output_dir=tmp_path / "case_output",
        case_id=CASE_ID,
        examiner=EXAMINER,
    )


# ---------------------------------------------------------------------------
# hashing
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_hash_file_returns_known_digest(tmp_path: Path) -> None:
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert hash_file(target) == expected


@pytest.mark.unit
def test_hash_file_streams_files_larger_than_one_chunk(tmp_path: Path) -> None:
    target = tmp_path / "hive.bin"
    target.write_bytes(b"A" * (CHUNK_SIZE * 2 + 17))
    digest = hash_file(target)
    assert len(digest) == 64
    assert digest == digest.lower()


@pytest.mark.unit
def test_verify_digest_accepts_unmodified_file(tmp_path: Path) -> None:
    target = tmp_path / "SYSTEM"
    target.write_bytes(REGISTRY_HEADER)
    verify_digest(target, hash_file(target).upper())


@pytest.mark.unit
def test_verify_digest_raises_when_a_single_byte_changes(tmp_path: Path) -> None:
    """Required scenario 1: a modified byte is a hard failure, not a warning."""
    target = tmp_path / "SYSTEM"
    target.write_bytes(REGISTRY_HEADER)
    intake_digest = hash_file(target)

    tampered = bytearray(REGISTRY_HEADER)
    tampered[10] ^= 0xFF
    target.write_bytes(bytes(tampered))

    with pytest.raises(DigestMismatchError) as excinfo:
        verify_digest(target, intake_digest)

    assert excinfo.value.expected == intake_digest
    assert excinfo.value.actual != intake_digest
    assert isinstance(excinfo.value, IntegrityError)
    assert isinstance(excinfo.value, ExfilTrackError)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_case_config_accepts_separate_directories(tmp_path: Path) -> None:
    config = make_config(tmp_path, tmp_path / "evidence")
    assert config.case_id == CASE_ID
    assert config.examiner == EXAMINER


@pytest.mark.unit
def test_case_config_rejects_output_inside_evidence(tmp_path: Path) -> None:
    """Required scenario 2: output must never be written into the evidence tree."""
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    with pytest.raises(PathOverlapError):
        CaseConfig(
            evidence_dir=evidence,
            case_output_dir=evidence / "case_output",
            case_id=CASE_ID,
            examiner=EXAMINER,
        )


@pytest.mark.unit
def test_case_config_rejects_evidence_inside_output(tmp_path: Path) -> None:
    output = tmp_path / "case_output"
    output.mkdir()

    with pytest.raises(PathOverlapError):
        CaseConfig(
            evidence_dir=output / "evidence",
            case_output_dir=output,
            case_id=CASE_ID,
            examiner=EXAMINER,
        )


@pytest.mark.unit
def test_case_config_rejects_identical_directories(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()

    with pytest.raises(PathOverlapError):
        CaseConfig(
            evidence_dir=shared,
            case_output_dir=shared,
            case_id=CASE_ID,
            examiner=EXAMINER,
        )


@pytest.mark.unit
@pytest.mark.parametrize(("case_id", "examiner"), [("", EXAMINER), (CASE_ID, "   ")])
def test_case_config_rejects_missing_identity(tmp_path: Path, case_id: str, examiner: str) -> None:
    with pytest.raises(ConfigError):
        CaseConfig(
            evidence_dir=tmp_path / "evidence",
            case_output_dir=tmp_path / "case_output",
            case_id=case_id,
            examiner=examiner,
        )


@pytest.mark.unit
def test_path_overlap_error_is_a_config_error() -> None:
    assert issubclass(PathOverlapError, ConfigError)
    assert issubclass(ConfigError, ExfilTrackError)


# ---------------------------------------------------------------------------
# intake
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_discover_artifacts_classifies_every_type(evidence_dir: Path) -> None:
    found = {record.path.name: record.artifact_type for record in discover_artifacts(evidence_dir)}

    assert found["SYSTEM"] is ArtifactType.REGISTRY
    assert found["Security.evtx"] is ArtifactType.EVTX
    assert found["Recent.lnk"] is ArtifactType.LNK
    assert found["1b4dd67f29cb1962.automaticDestinations-ms"] is ArtifactType.JUMP_LIST
    assert found["notes.txt"] is ArtifactType.UNKNOWN


@pytest.mark.unit
def test_discover_artifacts_records_size_and_digest(evidence_dir: Path) -> None:
    records = {record.path.name: record for record in discover_artifacts(evidence_dir)}
    hive = records["SYSTEM"]

    assert hive.size_bytes == len(REGISTRY_HEADER)
    assert hive.intake_digest == hash_file(evidence_dir / "hives" / "SYSTEM")
    assert hive.path.is_absolute()


@pytest.mark.unit
def test_discover_artifacts_identifies_renamed_hive_by_magic_bytes(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "unnamed.dat").write_bytes(REGISTRY_HEADER)

    records = discover_artifacts(evidence)
    assert [record.artifact_type for record in records] == [ArtifactType.REGISTRY]


@pytest.mark.unit
def test_discover_artifacts_raises_on_truncated_artifact(tmp_path: Path) -> None:
    """Required scenario 3a: malformed evidence is reported, never skipped."""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "Security.evtx").write_bytes(b"Elf")

    with pytest.raises(ArtifactError, match="truncated or malformed"):
        discover_artifacts(evidence)


@pytest.mark.unit
def test_discover_artifacts_raises_on_empty_jump_list(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "aa.customDestinations-ms").write_bytes(b"")

    with pytest.raises(ArtifactError, match="truncated or malformed"):
        discover_artifacts(evidence)


@pytest.mark.unit
def test_discover_artifacts_raises_on_unreadable_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Required scenario 3b: a PermissionError surfaces as ArtifactError."""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "SYSTEM").write_bytes(REGISTRY_HEADER)

    real_open = Path.open

    def deny(self: Path, *args: object, **kwargs: object) -> object:
        if self.name == "SYSTEM":
            raise PermissionError(13, "Permission denied")
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "open", deny)

    with pytest.raises(ArtifactError, match="Cannot read evidence file"):
        discover_artifacts(evidence)


@pytest.mark.unit
def test_discover_artifacts_rejects_a_file_path(tmp_path: Path) -> None:
    target = tmp_path / "SYSTEM"
    target.write_bytes(REGISTRY_HEADER)

    with pytest.raises(NotADirectoryError):
        discover_artifacts(target)


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_write_manifest_creates_case_manifest_json(tmp_path: Path, evidence_dir: Path) -> None:
    config = make_config(tmp_path, evidence_dir)
    manifest = CaseManifest.from_config(config, discover_artifacts(evidence_dir))
    manifest.parser_records.append(ParserRecord(name="registry_parser", version="0.1.0"))
    manifest.end_time = manifest.start_time + timedelta(seconds=4)

    written = write_manifest(manifest, config.case_output_dir)

    assert written.name == MANIFEST_FILENAME
    assert written.parent == config.resolved_case_output_dir
    assert not written.is_relative_to(config.resolved_evidence_dir)

    payload = json.loads(written.read_text(encoding="utf-8"))
    assert payload["case_id"] == CASE_ID
    assert payload["examiner"] == EXAMINER
    assert payload["tool_version"] == "0.1.0"
    assert payload["integrity_verdict"] == IntegrityVerdict.PENDING.value
    assert payload["parser_records"] == [{"name": "registry_parser", "version": "0.1.0"}]
    assert payload["config"]["case_id"] == CASE_ID
    assert len(payload["intake_digests"]) == 5


@pytest.mark.unit
def test_manifest_records_relative_posix_paths(tmp_path: Path, evidence_dir: Path) -> None:
    config = make_config(tmp_path, evidence_dir)
    manifest = CaseManifest.from_config(config, discover_artifacts(evidence_dir))

    recorded = {record.path for record in manifest.intake_digests}
    assert "hives/SYSTEM" in recorded
    assert "logs/Security.evtx" in recorded


@pytest.mark.unit
def test_manifest_rejects_naive_timestamps() -> None:
    with pytest.raises(ManifestError, match="timezone-aware"):
        CaseManifest(
            case_id=CASE_ID,
            examiner=EXAMINER,
            start_time=datetime(2026, 1, 1, 12, 0, 0),  # noqa: DTZ001
        )


@pytest.mark.unit
def test_build_digest_records_rejects_artifacts_outside_evidence(
    tmp_path: Path,
    evidence_dir: Path,
) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "SYSTEM").write_bytes(REGISTRY_HEADER)

    with pytest.raises(ManifestError, match="outside the evidence directory"):
        build_digest_records(discover_artifacts(outside), evidence_dir)


@pytest.mark.unit
def test_verify_manifest_passes_for_untouched_evidence(
    tmp_path: Path,
    evidence_dir: Path,
) -> None:
    config = make_config(tmp_path, evidence_dir)
    manifest = CaseManifest.from_config(config, discover_artifacts(evidence_dir))

    assert verify_manifest(manifest, evidence_dir) is True


@pytest.mark.unit
def test_verify_manifest_fails_when_evidence_is_modified(
    tmp_path: Path,
    evidence_dir: Path,
) -> None:
    config = make_config(tmp_path, evidence_dir)
    manifest = CaseManifest.from_config(config, discover_artifacts(evidence_dir))

    (evidence_dir / "hives" / "SYSTEM").write_bytes(REGISTRY_HEADER + b"tampered")

    assert verify_manifest(manifest, evidence_dir) is False


@pytest.mark.unit
def test_verify_manifest_fails_when_evidence_is_missing(
    tmp_path: Path,
    evidence_dir: Path,
) -> None:
    config = make_config(tmp_path, evidence_dir)
    manifest = CaseManifest.from_config(config, discover_artifacts(evidence_dir))

    (evidence_dir / "Recent.lnk").unlink()

    assert verify_manifest(manifest, evidence_dir) is False


@pytest.mark.unit
def test_verify_manifest_refuses_to_pass_an_empty_manifest() -> None:
    manifest = CaseManifest(
        case_id=CASE_ID,
        examiner=EXAMINER,
        start_time=datetime.now(timezone.utc),
    )

    with pytest.raises(ManifestError, match="nothing to verify"):
        verify_manifest(manifest, Path.cwd())

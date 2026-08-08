"""Chain-of-custody manifest generation.

Owner: Milindu Weerawarna
Related issue: #2 - Evidence Intake and Hash Verification

The manifest is the artifact that makes a run defensible: it records who ran
the tool, against which evidence, with which parser versions, and proves via
SHA-256 digests taken before and after analysis that the evidence was not
modified.
"""

from __future__ import annotations

import enum
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from exfiltrack import __tool_name__, __version__
from exfiltrack.config import CaseConfig, ExfilTrackError
from exfiltrack.evidence.hashing import DigestMismatchError, verify_digest
from exfiltrack.evidence.intake import ArtifactRecord

MANIFEST_FILENAME = "case_manifest.json"
MANIFEST_SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ManifestError(ExfilTrackError):
    """Raised when a manifest cannot be built, written, or read back."""


# ---------------------------------------------------------------------------
# Manifest components
# ---------------------------------------------------------------------------


class IntegrityVerdict(enum.Enum):
    """Outcome of comparing post-analysis digests against intake digests."""

    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"


@dataclass(frozen=True)
class ParserRecord:
    """Name and version of a parser that contributed to the run."""

    name: str
    version: str

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-serialisable view of this record."""
        return {"name": self.name, "version": self.version}


@dataclass(frozen=True)
class DigestRecord:
    """SHA-256 digest of one evidence file.

    ``path`` is stored relative to the evidence directory in POSIX form so a
    manifest stays valid when the evidence set is moved or re-mounted under a
    different root.
    """

    path: str
    digest: str

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-serialisable view of this record."""
        return {"path": self.path, "digest": self.digest}


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def build_digest_records(
    artifacts: Sequence[ArtifactRecord],
    evidence_dir: Path,
) -> list[DigestRecord]:
    """Convert intake records into manifest digest records.

    Parameters
    ----------
    artifacts:
        Records produced by :func:`exfiltrack.evidence.intake.discover_artifacts`.
    evidence_dir:
        Root the recorded paths are made relative to.

    Raises
    ------
    ManifestError
        If an artifact lies outside *evidence_dir*.
    """
    root = evidence_dir.resolve()
    records: list[DigestRecord] = []
    for artifact in artifacts:
        resolved = artifact.path.resolve()
        if not resolved.is_relative_to(root):
            raise ManifestError(
                f"Artifact '{resolved}' is outside the evidence directory '{root}' "
                "and cannot be recorded in the manifest."
            )
        records.append(
            DigestRecord(
                path=resolved.relative_to(root).as_posix(),
                digest=artifact.intake_digest,
            )
        )
    return records


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


@dataclass
class CaseManifest:
    """Chain-of-custody record for a single ExfilTrack run.

    Attributes
    ----------
    case_id, examiner:
        Case identity, copied from :class:`~exfiltrack.config.CaseConfig`.
    tool_name, tool_version:
        Provenance of the software that produced the run, so results can be
        reproduced against the same version.
    start_time, end_time:
        Timezone-aware UTC bounds of the run. ``end_time`` is ``None`` until
        the run finishes.
    config:
        Snapshot of the configuration the run was launched with.
    parser_records:
        Every parser invoked, with its version.
    intake_digests:
        Digests taken before analysis.
    post_analysis_digests:
        Digests taken after analysis; compared against ``intake_digests``.
    integrity_verdict:
        ``PENDING`` until digests are compared, then ``VERIFIED`` or ``FAILED``.
    """

    case_id: str
    examiner: str
    start_time: datetime
    end_time: datetime | None = None
    tool_name: str = __tool_name__
    tool_version: str = __version__
    config: dict[str, str] = field(default_factory=dict)
    parser_records: list[ParserRecord] = field(default_factory=list)
    intake_digests: list[DigestRecord] = field(default_factory=list)
    post_analysis_digests: list[DigestRecord] = field(default_factory=list)
    integrity_verdict: IntegrityVerdict = IntegrityVerdict.PENDING

    def __post_init__(self) -> None:
        self._require_utc("start_time", self.start_time)
        if self.end_time is not None:
            self._require_utc("end_time", self.end_time)

    @staticmethod
    def _require_utc(field_name: str, value: datetime) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ManifestError(
                f"{field_name} must be timezone-aware; manifest times are recorded in UTC."
            )

    @classmethod
    def from_config(
        cls,
        config: CaseConfig,
        artifacts: Sequence[ArtifactRecord] = (),
        start_time: datetime | None = None,
    ) -> CaseManifest:
        """Build a manifest from *config* and the artifacts seen at intake."""
        return cls(
            case_id=config.case_id,
            examiner=config.examiner,
            start_time=start_time if start_time is not None else utc_now(),
            config=snapshot_config(config),
            intake_digests=build_digest_records(artifacts, config.evidence_dir),
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable view of the whole manifest."""
        return {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "case_id": self.case_id,
            "examiner": self.examiner,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "config": dict(self.config),
            "parser_records": [record.to_dict() for record in self.parser_records],
            "intake_digests": [record.to_dict() for record in self.intake_digests],
            "post_analysis_digests": [record.to_dict() for record in self.post_analysis_digests],
            "integrity_verdict": self.integrity_verdict.value,
        }


def snapshot_config(config: CaseConfig) -> dict[str, str]:
    """Return a flat, serialisable snapshot of *config* for the manifest."""
    return {
        "evidence_dir": str(config.resolved_evidence_dir),
        "case_output_dir": str(config.resolved_case_output_dir),
        "case_id": config.case_id,
        "examiner": config.examiner,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def write_manifest(manifest: CaseManifest, case_output_dir: Path) -> Path:
    """Serialise *manifest* to ``case_manifest.json`` inside *case_output_dir*.

    The output directory is created if it does not exist. It is never inside
    the evidence directory: :class:`~exfiltrack.config.CaseConfig` rejects that
    configuration before a run starts.

    Returns
    -------
    Path
        Absolute path to the written manifest.

    Raises
    ------
    ManifestError
        If the directory or file cannot be written.
    """
    destination = case_output_dir.resolve() / MANIFEST_FILENAME
    payload = json.dumps(manifest.to_dict(), indent=2)
    try:
        case_output_dir.mkdir(parents=True, exist_ok=True)
        destination.write_text(payload + "\n", encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"Cannot write manifest to '{destination}': {exc}") from exc
    return destination


def verify_manifest(manifest: CaseManifest, evidence_dir: Path) -> bool:
    """Recompute every recorded intake digest and report whether all still match.

    Parameters
    ----------
    manifest:
        Manifest holding the digests captured at intake.
    evidence_dir:
        Root the recorded relative paths are resolved against.

    Returns
    -------
    bool
        ``True`` only if every recorded artifact is present and its digest is
        unchanged. A missing or unreadable artifact counts as a failure, not
        as a skipped entry.

    Raises
    ------
    ManifestError
        If the manifest records no intake digests, since an empty verification
        must not be reported as a pass.
    """
    if not manifest.intake_digests:
        raise ManifestError("Manifest records no intake digests; there is nothing to verify.")

    root = evidence_dir.resolve()
    for record in manifest.intake_digests:
        try:
            verify_digest(root / record.path, record.digest)
        except (DigestMismatchError, OSError):
            return False
    return True

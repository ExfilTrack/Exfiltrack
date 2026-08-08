"""Read-only evidence intake and artifact discovery.

Owner: Milindu Weerawarna
Related issue: #2 - Evidence Intake and Hash Verification
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path

from exfiltrack.config import ExfilTrackError
from exfiltrack.evidence.hashing import hash_file

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ArtifactError(ExfilTrackError):
    """Raised for unreadable or malformed evidence files.

    A malformed or inaccessible artifact is always a reported error — it is
    never silently skipped (forensic soundness requirement 6).
    """


# ---------------------------------------------------------------------------
# Artifact classification
# ---------------------------------------------------------------------------


class ArtifactType(enum.Enum):
    REGISTRY = "registry_hive"
    EVTX = "evtx_log"
    LNK = "lnk_shortcut"
    JUMP_LIST = "jump_list"
    UNKNOWN = "unknown"


# Magic-byte signatures for binary classification.
# Keyed by ArtifactType; value is (offset, expected_bytes).
_MAGIC: dict[ArtifactType, tuple[int, bytes]] = {
    ArtifactType.REGISTRY: (0, b"regf"),
    ArtifactType.EVTX: (0, b"ElfFile\x00"),
    ArtifactType.LNK: (0, b"\x4c\x00\x00\x00"),
}

# Enough bytes to cover the longest signature above.
_MAGIC_READ_SIZE = 8

# Name-based patterns that imply artifact type without magic bytes.
_NAME_SUFFIXES: dict[ArtifactType, tuple[str, ...]] = {
    ArtifactType.EVTX: (".evtx",),
    ArtifactType.LNK: (".lnk",),
    ArtifactType.JUMP_LIST: (
        ".automaticDestinations-ms",
        ".customDestinations-ms",
    ),
}

# Smallest plausible size for a file whose name claims a structured type.
# Anything shorter is truncated rather than merely unrecognised.
_MIN_STRUCTURED_SIZE = 8


def _read_header(path: Path, n_bytes: int) -> bytes:
    """Return the first *n_bytes* from *path* opened read-only."""
    with path.open("rb") as fh:
        return fh.read(n_bytes)


def _match_magic(header: bytes) -> ArtifactType:
    """Return the artifact type implied by *header*, or UNKNOWN."""
    for artifact_type, (offset, magic) in _MAGIC.items():
        end = offset + len(magic)
        if len(header) >= end and header[offset:end] == magic:
            return artifact_type
    return ArtifactType.UNKNOWN


def _classify_by_name(path: Path) -> ArtifactType:
    """Return the artifact type implied by the file name, or UNKNOWN."""
    name_lower = path.name.lower()
    for artifact_type, suffixes in _NAME_SUFFIXES.items():
        if any(name_lower.endswith(sfx.lower()) for sfx in suffixes):
            return artifact_type
    return ArtifactType.UNKNOWN


def _classify(path: Path, size_bytes: int) -> ArtifactType:
    """Classify *path* using its magic bytes and its name convention.

    Magic bytes take precedence, so a renamed hive is still recognised. The
    name is used for Jump Lists, which have no single reliable signature, and
    as a cross-check: a file whose name claims a signed type but whose header
    disagrees is truncated or malformed and is reported rather than downgraded
    to ``UNKNOWN``.

    Raises
    ------
    ArtifactError
        If the file contradicts the type its name declares.
    OSError
        If the header cannot be read.
    """
    header = _read_header(path, _MAGIC_READ_SIZE)
    by_magic = _match_magic(header)
    if by_magic is not ArtifactType.UNKNOWN:
        return by_magic

    by_name = _classify_by_name(path)
    if by_name is ArtifactType.UNKNOWN:
        return ArtifactType.UNKNOWN

    if by_name in _MAGIC:
        _, expected = _MAGIC[by_name]
        raise ArtifactError(
            f"'{path}' is named as a {by_name.value} but starts with {header!r} "
            f"instead of {expected!r}; the file is truncated or malformed."
        )

    if size_bytes < _MIN_STRUCTURED_SIZE:
        raise ArtifactError(
            f"'{path}' is named as a {by_name.value} but holds only {size_bytes} bytes; "
            "the file is truncated or malformed."
        )

    return by_name


# ---------------------------------------------------------------------------
# Artifact record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArtifactRecord:
    """Immutable record for a single evidence file captured at intake.

    Attributes
    ----------
    path:
        Absolute, resolved path to the artifact inside the evidence directory.
    artifact_type:
        Classified artifact type.
    size_bytes:
        File size at the moment of intake.
    intake_digest:
        SHA-256 hex digest computed at intake.  This value is recorded in the
        chain-of-custody manifest and re-verified after analysis.
    """

    path: Path
    artifact_type: ArtifactType
    size_bytes: int
    intake_digest: str


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_artifacts(evidence_dir: Path) -> list[ArtifactRecord]:
    """Walk *evidence_dir* and return an intake record for every file found.

    Every file in the tree is processed — none are silently skipped.  If a
    file is unreadable or cannot be hashed, an :exc:`ArtifactError` is raised
    immediately with a message that identifies the offending path.

    Parameters
    ----------
    evidence_dir:
        Root of the (offline) evidence directory.  Must be a directory.

    Returns
    -------
    list[ArtifactRecord]
        One record per file, sorted by path for reproducible runs.

    Raises
    ------
    ArtifactError
        If any file inside *evidence_dir* cannot be read, cannot be hashed, or
        contradicts the artifact type its name declares.
    NotADirectoryError
        If *evidence_dir* is not a directory.
    """
    if not evidence_dir.is_dir():
        raise NotADirectoryError(f"Evidence path is not a directory: '{evidence_dir}'")

    return [_intake_file(entry) for entry in sorted(evidence_dir.rglob("*")) if entry.is_file()]


def _intake_file(path: Path) -> ArtifactRecord:
    """Classify and hash a single evidence file, opened read-only."""
    try:
        size_bytes = path.stat().st_size
        artifact_type = _classify(path, size_bytes)
        digest = hash_file(path)
    except OSError as exc:
        raise ArtifactError(
            f"Cannot read evidence file '{path}': {exc}. "
            "Unreadable evidence is reported explicitly rather than skipped."
        ) from exc

    return ArtifactRecord(
        path=path.resolve(),
        artifact_type=artifact_type,
        size_bytes=size_bytes,
        intake_digest=digest,
    )

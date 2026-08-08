"""SHA-256 integrity hashing for evidence files.

Owner: Milindu Weerawarna
Related issue: #2 - Evidence Intake and Hash Verification
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from exfiltrack.config import ExfilTrackError

# Stream evidence in 64 KB chunks so large registry hives are never
# loaded whole into memory.
CHUNK_SIZE = 65_536


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class IntegrityError(ExfilTrackError):
    """Raised when an evidence integrity check fails."""


class DigestMismatchError(IntegrityError):
    """Raised when a recomputed SHA-256 digest does not match the recorded one.

    A mismatch means the file was modified after intake — this is a hard
    failure that stops the run rather than a warning that continues it.
    """

    def __init__(self, path: Path, expected: str, actual: str) -> None:
        self.path = path
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Integrity failure for '{path}': "
            f"expected {expected!r} but got {actual!r}. "
            "The file may have been modified after intake."
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def hash_file(path: Path) -> str:
    """Compute the SHA-256 digest of *path* by streaming it in chunks.

    The file is opened strictly read-only. Large files (e.g. registry hives
    or EVTX logs) are never loaded whole into memory.

    Parameters
    ----------
    path:
        Absolute path to the file to hash.

    Returns
    -------
    str
        Lowercase hexadecimal SHA-256 digest.

    Raises
    ------
    OSError
        If the file cannot be opened or read.
    """
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def verify_digest(path: Path, expected: str) -> None:
    """Recompute the SHA-256 digest of *path* and compare it to *expected*.

    Parameters
    ----------
    path:
        Absolute path to the file to verify.
    expected:
        Lowercase hexadecimal SHA-256 digest recorded at intake.

    Raises
    ------
    DigestMismatchError
        If the recomputed digest does not match *expected*. This is treated
        as a hard failure — the caller must not continue processing.
    OSError
        If the file cannot be read.
    """
    actual = hash_file(path)
    if actual != expected.lower():
        raise DigestMismatchError(path=path, expected=expected.lower(), actual=actual)

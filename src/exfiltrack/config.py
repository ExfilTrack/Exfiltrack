"""Configuration and shared constants for ExfilTrack.

Owner: Milindu Weerawarna
Related issue: #2 - Evidence Intake and Hash Verification
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class ExfilTrackError(Exception):
    """Base exception for all ExfilTrack errors."""


class ConfigError(ExfilTrackError):
    """Raised for invalid or unsafe configuration values."""


class PathOverlapError(ConfigError):
    """Raised when the case output directory is inside the evidence directory.

    Writing analysis output into the evidence tree would modify the evidence,
    violating forensic soundness requirement 2.
    """


# ---------------------------------------------------------------------------
# Case configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseConfig:
    """Immutable configuration for a single ExfilTrack analysis run.

    Parameters
    ----------
    evidence_dir:
        Directory containing the offline Windows artifacts to analyse.
        Must exist and be readable.
    case_output_dir:
        Directory where the case manifest, reports, and parser output are
        written.  Must NOT be inside ``evidence_dir`` — that would modify
        the evidence tree.
    case_id:
        Analyst-supplied identifier recorded in the chain-of-custody manifest.
    examiner:
        Full name or badge ID of the analyst running the tool.
    """

    evidence_dir: Path
    case_output_dir: Path
    case_id: str
    examiner: str

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if not self.case_id.strip():
            raise ConfigError("case_id must not be empty.")
        if not self.examiner.strip():
            raise ConfigError("examiner must not be empty.")

        evidence = self.evidence_dir.resolve()
        output = self.case_output_dir.resolve()

        if output.is_relative_to(evidence):
            raise PathOverlapError(
                f"case_output_dir '{output}' is inside evidence_dir '{evidence}'. "
                "Analysis output must be written to a separate location so the "
                "evidence tree is never modified."
            )

        if evidence.is_relative_to(output):
            raise PathOverlapError(
                f"evidence_dir '{evidence}' is inside case_output_dir '{output}'. "
                "The evidence directory must not be nested inside the output directory."
            )

    @property
    def resolved_evidence_dir(self) -> Path:
        """Absolute, symlink-resolved evidence directory."""
        return self.evidence_dir.resolve()

    @property
    def resolved_case_output_dir(self) -> Path:
        """Absolute, symlink-resolved case output directory."""
        return self.case_output_dir.resolve()

        return self.case_output_dir.resolve()


# ---------------------------------------------------------------------------
# Correlation and reporting configuration
#
# Owner: Dabarera G. D. M. (Maheesha)
# Related issues: #8 - USB Session Reconstruction, #9 - Risk Scoring Engine,
#                  #10 - Confidence Evaluation Model
#
# These live alongside CaseConfig rather than in correlation/ so every
# tunable value the correlation engine uses is readable from one place, and
# so #13 (Integration Testing) can vary them without touching scoring logic.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionConfig:
    """Tunable parameters for USB session reconstruction (issue #8).

    Attributes:
        idle_gap: When a device has no explicit removal event, the session
            end is inferred as ``start + idle_gap`` (Definition of Done,
            #8). The default is deliberately larger than the risk-scoring
            engine's 5-minute activity window (#9), so an inferred session
            boundary never truncates the window the scoring rules depend
            on.
    """

    idle_gap: timedelta = timedelta(minutes=15)

    def __post_init__(self) -> None:
        if self.idle_gap <= timedelta(0):
            raise ConfigError("SessionConfig.idle_gap must be a positive duration.")


@dataclass(frozen=True)
class ScoringWeights:
    """Calibrated point values for the risk-scoring rules (issue #9).

    Values match the initial calibration documented in
    ``docs/scoring-model.md``. They are read from here, never hardcoded in
    ``correlation/scoring.py``, so #13 (Integration Testing) can measure how
    weight changes affect the false-positive rate without touching scoring
    logic.

    Attributes:
        activity_within_30s: Points for file activity within 30 seconds of
            the session start.
        activity_within_5min: Points for file activity within 5 minutes of
            the session start. Mutually exclusive with
            ``activity_within_30s`` for a given file: the 5-minute window
            contains the 30-second one, so only the narrower match scores
            (see ``docs/scoring-model.md``).
        sensitive_extension: Points for a file whose extension appears in
            ``sensitive_extensions``.
        protected_directory: Points for a file whose path matches one of
            ``protected_directories``.
        multiple_confidential_files: Points awarded once per session when
            two or more distinct confidential files were accessed.
        destination_hash_match: Points for a file whose SHA-256 digest
            matches a file found on the destination USB. This is also the
            only rule that can push a finding's confidence to ``Confirmed``
            (issue #10) -- never through score alone.
        sensitive_extensions: Case-insensitive file extensions treated as
            sensitive.
        protected_directories: Path fragments (matched case-insensitively,
            with ``\\`` and ``/`` treated as equivalent) that mark a file as
            being inside a protected project directory. Empty by default;
            populate with paths meaningful to the deployment, e.g.
            ``("\\\\source\\\\", "\\\\repos\\\\")``.
    """

    activity_within_30s: int = 25
    activity_within_5min: int = 15
    sensitive_extension: int = 15
    protected_directory: int = 20
    multiple_confidential_files: int = 15
    destination_hash_match: int = 50
    sensitive_extensions: frozenset[str] = field(
        default_factory=lambda: frozenset({".sql", ".pem", ".env", ".zip"})
    )
    protected_directories: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "activity_within_30s",
            "activity_within_5min",
            "sensitive_extension",
            "protected_directory",
            "multiple_confidential_files",
            "destination_hash_match",
        ):
            if getattr(self, name) < 0:
                raise ConfigError(f"ScoringWeights.{name} must not be negative.")

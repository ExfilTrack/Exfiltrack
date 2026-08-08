"""Configuration and shared constants for ExfilTrack.

Owner: Milindu Weerawarna
Related issue: #2 - Evidence Intake and Hash Verification
"""

from __future__ import annotations

from dataclasses import dataclass
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

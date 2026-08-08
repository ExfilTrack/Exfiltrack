"""Explainable rule-based risk scoring engine.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #9 - Risk Scoring Engine

Applies the calibrated rules documented in docs/scoring-model.md to a
reconstructed session and records every contribution with its rule name
and the source artifact that triggered it, so a score can always be
explained line by line.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import PureWindowsPath

from exfiltrack.config import ScoringWeights
from exfiltrack.correlation.sessions import UsbSession

# Rule names. These are also the values stored in ScoreContribution.rule and
# are used verbatim in docs/scoring-model.md and in report output, so they
# must not change without updating both.
ACTIVITY_WITHIN_30S = "activity_within_30s"
ACTIVITY_WITHIN_5MIN = "activity_within_5min"
SENSITIVE_EXTENSION = "sensitive_extension"
PROTECTED_DIRECTORY = "protected_directory"
MULTIPLE_CONFIDENTIAL_FILES = "multiple_confidential_files"
DESTINATION_HASH_MATCH = "destination_hash_match"


@dataclass(frozen=True)
class ScoreContribution:
    """One line of an explainable score: a rule, its points, and why.

    Attributes:
        rule: One of the module-level rule name constants.
        points: Points this contribution adds to the session's total.
        source_artifacts: Every evidence file that triggered this
            contribution. Per-file rules cite exactly one path; the
            session-level ``multiple_confidential_files`` rule cites every
            file it counted, so a reviewer can see the whole basis for the
            aggregate points.
        explanation: A human-readable sentence explaining the finding.
    """

    rule: str
    points: int
    source_artifacts: tuple[str, ...]
    explanation: str


@dataclass(frozen=True)
class ScoredSession:
    """A reconstructed session together with its explainable score."""

    session: UsbSession
    contributions: tuple[ScoreContribution, ...]

    @property
    def total_score(self) -> int:
        """Sum of every contribution's points."""
        return sum(c.points for c in self.contributions)


def _matches_extension(file_path: str, extensions: frozenset[str]) -> bool:
    suffix = PureWindowsPath(file_path).suffix.lower()
    return suffix in extensions


def _matches_protected_directory(file_path: str, protected_dirs: tuple[str, ...]) -> bool:
    normalized = file_path.replace("\\", "/").lower()
    return any(pattern.replace("\\", "/").lower() in normalized for pattern in protected_dirs)


def _is_confidential(file_path: str, weights: ScoringWeights) -> bool:
    return _matches_extension(
        file_path, weights.sensitive_extensions
    ) or _matches_protected_directory(file_path, weights.protected_directories)


def score_session(
    session: UsbSession,
    weights: ScoringWeights | None = None,
    destination_file_hashes: frozenset[str] = frozenset(),
) -> ScoredSession:
    """Score one reconstructed session using the rules in docs/scoring-model.md.

    Design decisions, per the #9 Definition of Done:

    * The 30-second and 5-minute activity rules do NOT stack. The 5-minute
      window contains the 30-second window, so a file inside both is
      scored only once, under the narrower (higher-value) rule.
    * Per-file rules (the activity-timing rules, sensitive_extension,
      protected_directory, and destination_hash_match) are NOT capped per
      session: each qualifying file is independent evidence, so a session
      with five confidential files copied scores higher than one with a
      single file.
    * ``multiple_confidential_files`` is a session-level rule and fires at
      most once per session, when two or more *distinct* files in that
      session are confidential (matched by ``sensitive_extension`` or
      ``protected_directory``).

    Parameters:
        session: A session from
            :func:`exfiltrack.correlation.sessions.reconstruct_sessions`.
        weights: Rule weights and pattern configuration. Defaults to
            :class:`~exfiltrack.config.ScoringWeights` with its documented
            defaults.
        destination_file_hashes: Lowercase hex SHA-256 digests found on the
            destination USB (from evidence intake, issue #2). A file event
            whose ``details["sha256"]`` matches one of these triggers
            ``destination_hash_match``.

    Returns:
        The session paired with every score contribution it earned, in the
        order file events were processed (session file-event order is
        already deterministic; see #8), so output is reproducible.
    """
    active_weights = weights or ScoringWeights()
    contributions: list[ScoreContribution] = []
    confidential_files: list[str] = []

    for file_event in session.file_events:
        if file_event.file_path is None:
            continue
        path = file_event.file_path

        delta = file_event.timestamp_utc - session.start.timestamp_utc
        if timedelta(0) <= delta <= timedelta(seconds=30):
            contributions.append(
                ScoreContribution(
                    rule=ACTIVITY_WITHIN_30S,
                    points=active_weights.activity_within_30s,
                    source_artifacts=(file_event.source_artifact,),
                    explanation=(
                        f"'{path}' was accessed {delta.total_seconds():.0f}s after the "
                        "session started, within the 30-second window."
                    ),
                )
            )
        elif timedelta(0) <= delta <= timedelta(minutes=5):
            contributions.append(
                ScoreContribution(
                    rule=ACTIVITY_WITHIN_5MIN,
                    points=active_weights.activity_within_5min,
                    source_artifacts=(file_event.source_artifact,),
                    explanation=(
                        f"'{path}' was accessed {delta.total_seconds():.0f}s after the "
                        "session started, within the 5-minute window."
                    ),
                )
            )

        if _matches_extension(path, active_weights.sensitive_extensions):
            contributions.append(
                ScoreContribution(
                    rule=SENSITIVE_EXTENSION,
                    points=active_weights.sensitive_extension,
                    source_artifacts=(file_event.source_artifact,),
                    explanation=f"'{path}' has a sensitive extension.",
                )
            )

        if _matches_protected_directory(path, active_weights.protected_directories):
            contributions.append(
                ScoreContribution(
                    rule=PROTECTED_DIRECTORY,
                    points=active_weights.protected_directory,
                    source_artifacts=(file_event.source_artifact,),
                    explanation=f"'{path}' is located in a protected project directory.",
                )
            )

        sha256 = file_event.details.get("sha256")
        if isinstance(sha256, str) and sha256.lower() in destination_file_hashes:
            contributions.append(
                ScoreContribution(
                    rule=DESTINATION_HASH_MATCH,
                    points=active_weights.destination_hash_match,
                    source_artifacts=(file_event.source_artifact,),
                    explanation=(
                        f"'{path}' has a SHA-256 hash matching a file found on the "
                        "destination USB."
                    ),
                )
            )

        if _is_confidential(path, active_weights):
            confidential_files.append(path)

    distinct_confidential = sorted(set(confidential_files))
    if len(distinct_confidential) >= 2:
        contributions.append(
            ScoreContribution(
                rule=MULTIPLE_CONFIDENTIAL_FILES,
                points=active_weights.multiple_confidential_files,
                source_artifacts=tuple(distinct_confidential),
                explanation=(
                    f"{len(distinct_confidential)} distinct confidential files were "
                    "accessed in this session."
                ),
            )
        )

    return ScoredSession(session=session, contributions=tuple(contributions))

"""Confidence level evaluation.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #10 - Confidence Evaluation Model

Assigns a calibrated Low / Medium / High / Confirmed confidence level to a
scored session. This is the rule that keeps ExfilTrack defensible: a tool
that declares its findings as definitive theft on temporal correlation
alone is both technically wrong and unusable in any HR or legal context.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from exfiltrack.config import ConfidenceThresholds
from exfiltrack.correlation.scoring import (
    DESTINATION_HASH_MATCH,
    MULTIPLE_CONFIDENTIAL_FILES,
    ScoredSession,
)


class ConfidenceLevel(enum.IntEnum):
    """Calibrated confidence levels, per docs/scoring-model.md.

    Backed by ``IntEnum`` (rather than plain ``Enum``) so levels can be
    compared and sorted (``ConfidenceLevel.HIGH > ConfidenceLevel.LOW``)
    when building summary views across many findings.
    """

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CONFIRMED = 4

    def __str__(self) -> str:
        return self.name.title()


@dataclass(frozen=True)
class ConfidenceResult:
    """The confidence level assigned to a finding, with the reason why.

    Every finding records why it received its level (Definition of Done,
    #10), so ``reason`` is not optional.
    """

    level: ConfidenceLevel
    reason: str


def evaluate_confidence(
    scored: ScoredSession,
    thresholds: ConfidenceThresholds | None = None,
) -> ConfidenceResult:
    """Assign a calibrated confidence level to a scored session.

    ``Confirmed`` is reached only through a ``destination_hash_match``
    contribution -- never through score alone, regardless of how high the
    score is (Definition of Done, #10). That check runs first and
    unconditionally overrides every threshold below it.

    See ``docs/scoring-model.md`` for the full reasoning behind the
    thresholds and why ``High`` additionally requires both session
    boundaries to be observed rather than inferred.
    """
    cfg = thresholds or ConfidenceThresholds()
    rules_fired = {contribution.rule for contribution in scored.contributions}
    score = scored.total_score

    if DESTINATION_HASH_MATCH in rules_fired:
        return ConfidenceResult(
            level=ConfidenceLevel.CONFIRMED,
            reason=(
                "A cryptographic hash match was found between a source file and a file "
                "on the destination USB."
            ),
        )

    if score >= cfg.high and scored.session.is_fully_observed:
        return ConfidenceResult(
            level=ConfidenceLevel.HIGH,
            reason=(
                f"Score {score} meets the High threshold ({cfg.high}) and both session "
                "boundaries are backed by an observed device event, not inferred."
            ),
        )

    if score >= cfg.medium or MULTIPLE_CONFIDENTIAL_FILES in rules_fired:
        return ConfidenceResult(
            level=ConfidenceLevel.MEDIUM,
            reason=(
                f"Score {score} meets the Medium threshold ({cfg.medium}), or multiple "
                "related files were accessed shortly after insertion, consistent with "
                "staging behaviour."
            ),
        )

    if score > 0:
        return ConfidenceResult(
            level=ConfidenceLevel.LOW,
            reason=(
                f"Score {score} is above zero but below the Medium threshold " f"({cfg.medium})."
            ),
        )

    return ConfidenceResult(
        level=ConfidenceLevel.NONE,
        reason="No scoring rule fired for this session.",
    )

"""Data assembly shared by the HTML, JSON, and CSV report generators.

Owner: Maheesha (Dabarera G. D. M.)
Related issues: #11 - HTML Report Generator, #12 - JSON/CSV Export

Neither #11 nor #12 individually needs a "score every session and evaluate
its confidence" step of its own -- both need the same one. This module is
the single place that does it, so the three report formats can never
disagree about what a finding is.
"""

from __future__ import annotations

from dataclasses import dataclass

from exfiltrack.config import ConfidenceThresholds, ScoringWeights
from exfiltrack.correlation.confidence import ConfidenceResult, evaluate_confidence
from exfiltrack.correlation.scoring import ScoredSession, score_session
from exfiltrack.correlation.sessions import UsbSession


@dataclass(frozen=True)
class Finding:
    """One reconstructed session together with its score and confidence.

    This is the unit every report format (HTML, JSON, CSV) renders one of.
    """

    scored_session: ScoredSession
    confidence: ConfidenceResult

    @property
    def session(self) -> UsbSession:
        return self.scored_session.session


def assemble_findings(
    sessions: list[UsbSession],
    weights: ScoringWeights | None = None,
    thresholds: ConfidenceThresholds | None = None,
    destination_file_hashes: frozenset[str] = frozenset(),
) -> list[Finding]:
    """Score and evaluate confidence for every session, deterministically ordered.

    Parameters:
        sessions: Typically the output of
            :func:`exfiltrack.correlation.sessions.reconstruct_sessions`.
        weights: Forwarded to
            :func:`exfiltrack.correlation.scoring.score_session`.
        thresholds: Forwarded to
            :func:`exfiltrack.correlation.confidence.evaluate_confidence`.
        destination_file_hashes: Forwarded to
            :func:`exfiltrack.correlation.scoring.score_session`.

    Returns:
        One :class:`Finding` per session, ordered by session start time then
        device id. Sessions are typically already in this order (#8), but
        this function re-sorts defensively so report output is
        deterministic regardless of caller order.
    """
    active_weights = weights or ScoringWeights()
    active_thresholds = thresholds or ConfidenceThresholds()

    findings: list[Finding] = []
    for session in sessions:
        scored = score_session(session, active_weights, destination_file_hashes)
        confidence = evaluate_confidence(scored, active_thresholds)
        findings.append(Finding(scored_session=scored, confidence=confidence))

    findings.sort(key=lambda f: (f.session.start.timestamp_utc, f.session.device.device_id))
    return findings

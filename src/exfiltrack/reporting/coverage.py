"""Evidence coverage model: which expected sources were present, absent, or empty.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #34 - Add Evidence Coverage section to reports

ExfilTrack does not error when an artifact was never created or has been
wiped: it runs normally, finds nothing, and produces a clean report. Without
a coverage record, a clean report from an unconfigured endpoint reads exactly
like an exoneration. This model records, per expected evidence source, how
many artifacts were supplied, how many parsed, and how many events they
contributed, so absent evidence and absent activity stay distinguishable in
every output (HTML, JSON, CSV, and the case manifest).

The expected sources and the notes attached to absent/empty states follow
``docs/evidence-sources.md`` and ``docs/organizational-prerequisites.md``;
the two sources that are off by default (the DriverFrameworks channel and
Security 4663) always name their likely configuration cause.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from exfiltrack.evidence.intake import ArtifactRecord, ArtifactType
from exfiltrack.normalization.event_model import NormalizedEvent

REGISTRY = "registry"
EVTX_DRIVERFRAMEWORKS = "evtx/DriverFrameworks"
EVTX_SECURITY = "evtx/Security"
EVTX_OTHER = "evtx/other"
LNK = "lnk"
JUMPLISTS = "jumplists"

# Fixed display/serialization order. ``evtx/other`` is emitted only when at
# least one non-DriverFrameworks, non-Security log was supplied, and always
# sorts last.
_SOURCE_ORDER = (REGISTRY, EVTX_DRIVERFRAMEWORKS, EVTX_SECURITY, LNK, JUMPLISTS, EVTX_OTHER)

_ABSENT_NOTES = {
    REGISTRY: (
        "No registry hives supplied; device identity and most-recent-connection "
        "evidence is unavailable."
    ),
    EVTX_DRIVERFRAMEWORKS: (
        "The DriverFrameworks channel is disabled by default; without it there are no "
        "usb_insert/usb_remove session boundaries. It must be enabled before the incident "
        "(wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true) and "
        "the log exported."
    ),
    EVTX_SECURITY: (
        "Security 4663 file-access events exist only when Object Access auditing is "
        "enabled and a SACL is set on the target directories."
    ),
    LNK: (
        "No .lnk shortcuts supplied; they live in the user profile and may have been "
        "deleted or never exported."
    ),
    JUMPLISTS: (
        "No Jump Lists supplied; they live in the user profile and may have been "
        "deleted or never exported."
    ),
    EVTX_OTHER: "",
}

_EMPTY_NOTES = {
    REGISTRY: "Supplied but produced no relevant records.",
    EVTX_DRIVERFRAMEWORKS: (
        "Supplied but contained no insert/remove events; the channel may have been "
        "disabled at collection time."
    ),
    EVTX_SECURITY: (
        "Supplied but contained 0 file-access events; object-access auditing may not "
        "have been configured."
    ),
    LNK: "Supplied but contained no recent-file records.",
    JUMPLISTS: "Supplied but contained no recently-used-file records.",
    EVTX_OTHER: "Supplied but produced no recognized events.",
}


class SourceStatus(enum.Enum):
    """Per-source coverage state.

    ``ABSENT`` means the source was not supplied at all; ``EMPTY`` means it
    was supplied and parsed but contained no records of interest -- the two
    must never be conflated (Definition of Done, #34).
    """

    PRESENT = "present"
    ABSENT = "absent"
    EMPTY = "empty"


@dataclass(frozen=True)
class SourceCoverage:
    """Coverage of one expected evidence source.

    Attributes:
        source: Stable label, e.g. ``registry`` or ``evtx/Security``.
        status: present / absent / empty, per :class:`SourceStatus`.
        supplied: Artifacts of this class found at intake.
        parsed: Supplied artifacts whose parser completed; lower than
            ``supplied`` when a run continuing past parser errors skipped
            some of them.
        event_count: Normalized events attributed to this source.
        note: Likely configuration cause when the source is absent or empty,
            or a parse-failure pointer; empty when nothing needs saying.
    """

    source: str
    status: SourceStatus
    supplied: int
    parsed: int
    event_count: int
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable view of this row."""
        return {
            "source": self.source,
            "status": self.status.value,
            "supplied": self.supplied,
            "parsed": self.parsed,
            "event_count": self.event_count,
            "note": self.note,
        }


@dataclass(frozen=True)
class EvidenceCoverage:
    """The run's per-source coverage, in a fixed, deterministic order."""

    sources: tuple[SourceCoverage, ...]

    @property
    def is_complete(self) -> bool:
        """``True`` only if every expected source produced evidence.

        ``evtx/other`` is not an expected source (it is reported only when
        supplied) and never counts against completeness.
        """
        return all(
            source.status is SourceStatus.PRESENT
            for source in self.sources
            if source.source != EVTX_OTHER
        )

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serialisable view embedded in the case manifest."""
        return {
            "complete": self.is_complete,
            "sources": [source.to_dict() for source in self.sources],
        }


def _bucket_for(artifact: ArtifactRecord) -> str | None:
    """Map an intake artifact to its coverage source, or ``None`` for UNKNOWN files."""
    if artifact.artifact_type is ArtifactType.REGISTRY:
        return REGISTRY
    if artifact.artifact_type is ArtifactType.EVTX:
        return _evtx_bucket(artifact.path.name)
    if artifact.artifact_type is ArtifactType.LNK:
        return LNK
    if artifact.artifact_type is ArtifactType.JUMP_LIST:
        return JUMPLISTS
    return None


def _evtx_bucket(file_name: str) -> str:
    """Classify an event log by name.

    Offline exports use ``Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx``
    and live acquisition ``...UserMode_Operational.evtx``; both contain
    "driverframeworks". Anything that is neither that channel nor Security is
    reported under ``evtx/other`` (e.g. a System.evtx carrying Kernel-PnP
    install events).
    """
    lowered = file_name.lower()
    if "driverframeworks" in lowered:
        return EVTX_DRIVERFRAMEWORKS
    if "security" in lowered:
        return EVTX_SECURITY
    return EVTX_OTHER


def _event_key(path: Path) -> str:
    """Match key between an artifact path and an event's ``source_artifact``.

    Mirrors the pipeline's surrogate-escaping of event strings, so events
    still count toward their artifact when a filename carried unprintable
    characters.
    """
    return path.as_posix().encode("utf-8", "backslashreplace").decode("utf-8")


def build_coverage(
    artifacts: Iterable[ArtifactRecord],
    events: Iterable[NormalizedEvent],
    parser_errors: Iterable[dict[str, str]] = (),
) -> EvidenceCoverage:
    """Compute per-source coverage from intake records, parsed events, and errors.

    Parameters:
        artifacts: Intake records from
            :func:`exfiltrack.evidence.intake.discover_artifacts`.
        events: The run's normalized events (any order).
        parser_errors: ``CaseManifest.parser_errors`` entries; a failed
            artifact lowers its source's ``parsed`` count but still counts as
            supplied.

    Returns:
        An :class:`EvidenceCoverage` with the five expected sources in fixed
        order, plus ``evtx/other`` when such logs were supplied. The result
        depends only on its inputs, so identical evidence yields identical
        coverage (reproducibility, requirement 7).
    """
    event_counts: dict[str, int] = {}
    for event in events:
        event_counts[event.source_artifact] = event_counts.get(event.source_artifact, 0) + 1
    failed = {error["source_artifact"] for error in parser_errors}

    supplied = dict.fromkeys(_SOURCE_ORDER, 0)
    parsed = dict.fromkeys(_SOURCE_ORDER, 0)
    counts = dict.fromkeys(_SOURCE_ORDER, 0)
    for artifact in artifacts:
        bucket = _bucket_for(artifact)
        if bucket is None:
            continue
        supplied[bucket] += 1
        if artifact.path.as_posix() not in failed:
            parsed[bucket] += 1
        counts[bucket] += event_counts.get(_event_key(artifact.path), 0)

    rows: list[SourceCoverage] = []
    for bucket in _SOURCE_ORDER:
        if bucket == EVTX_OTHER and supplied[bucket] == 0:
            continue
        note = ""
        if supplied[bucket] == 0:
            status = SourceStatus.ABSENT
            note = _ABSENT_NOTES[bucket]
        elif counts[bucket] == 0:
            status = SourceStatus.EMPTY
            note = _EMPTY_NOTES[bucket]
        else:
            status = SourceStatus.PRESENT
        failed_here = supplied[bucket] - parsed[bucket]
        if failed_here:
            suffix = f"{failed_here} artifact(s) failed to parse; see the parser errors."
            note = f"{note} {suffix}".strip()
        rows.append(
            SourceCoverage(
                source=bucket,
                status=status,
                supplied=supplied[bucket],
                parsed=parsed[bucket],
                event_count=counts[bucket],
                note=note,
            )
        )
    return EvidenceCoverage(sources=tuple(rows))

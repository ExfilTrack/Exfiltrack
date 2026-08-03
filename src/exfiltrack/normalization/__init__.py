"""Normalization of heterogeneous artifacts into a single event model.

Owner: Thabrew

Parsers emit artifact-specific structures. This package converts them into
the common :class:`~exfiltrack.normalization.event_model.NormalizedEvent`
shape and normalizes all timestamps to UTC while preserving the original
raw timestamp value for forensic traceability.
"""

__all__ = ["event_model", "timestamps"]

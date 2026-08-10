"""Shared data contracts for the correlation layer.

Owner: Maheesha (Dabarera G. D. M.)

This module now serves as a compatibility re-export of the centralized event model
implemented in issue #7.
"""

from exfiltrack.normalization.event_model import EventType, NormalizedEvent, UsbDevice

__all__ = ["EventType", "NormalizedEvent", "UsbDevice"]

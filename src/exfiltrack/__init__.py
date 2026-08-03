"""ExfilTrack - a forensically sound USB exfiltration triage tool.

ExfilTrack ingests offline Windows forensic artifacts in read-only mode,
normalizes them into a single event timeline, reconstructs probable USB
connection sessions, and reports activity that is *consistent with* possible
USB-based data exfiltration.

Forensic note
-------------
Temporal correlation alone does not prove that a file was copied. Every
finding produced by this package carries an explicit confidence level and
cites the source artifact it was derived from.
"""

__version__ = "0.1.0"
__tool_name__ = "ExfilTrack"

__all__ = ["__version__", "__tool_name__"]

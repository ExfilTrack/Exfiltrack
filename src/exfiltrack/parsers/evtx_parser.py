"""Windows Event Log (.evtx) parser.

Owner: Thabrew
Related issue: #4 - EVTX Parser

Planned scope:
    - Parse System.evtx and Security.evtx read-only
    - Detect storage driver mount and unmount events
    - Detect device install and removal events
    - Emit normalized events with parser name and version

Not implemented yet.
"""

PARSER_NAME = "evtx_parser"
PARSER_VERSION = "0.0.0"

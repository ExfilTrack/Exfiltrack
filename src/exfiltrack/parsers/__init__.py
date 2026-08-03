"""Windows artifact parsers.

Owners:
    registry_parser  - Milindu Weerawarna
    evtx_parser      - Thabrew
    lnk_parser       - Thabrew
    jumplist_parser  - Thabrew

Every parser must declare a stable ``PARSER_NAME`` and ``PARSER_VERSION`` so
that findings can cite the exact parser that produced them, and must open
evidence strictly read-only.
"""

__all__ = ["evtx_parser", "jumplist_parser", "lnk_parser", "registry_parser"]

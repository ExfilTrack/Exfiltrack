"""Windows Registry artifact parser.

Owner: Milindu Weerawarna
Related issue: #3 - Registry Artifact Parser

Planned scope:
    - Parse SYSTEM, SOFTWARE, and NTUSER.DAT hives read-only
    - Extract USB storage devices, vendor/product data, and serial numbers
    - Extract volume GUIDs, drive letter mappings, and first/last seen times
    - Emit normalized events with parser name and version

Not implemented yet.
"""

PARSER_NAME = "registry_parser"
PARSER_VERSION = "0.0.0"

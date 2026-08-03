"""Evidence intake, integrity hashing, and chain-of-custody manifesting.

Owner: Milindu Weerawarna

This package is the only entry point through which evidence enters
ExfilTrack. It is responsible for enforcing read-only access, computing
SHA-256 digests before and after analysis, and recording a manifest that
documents the chain of custody for a case.
"""

__all__ = ["hashing", "intake", "manifest"]

"""Shared pytest fixtures for ExfilTrack tests.

Add fixtures here as modules are implemented. Keep evidence fixtures synthetic;
see tests/fixtures/README.md.
"""

from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Absolute path to the synthetic evidence fixture directory."""
    return Path(__file__).parent / "fixtures"

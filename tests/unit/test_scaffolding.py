"""Smoke tests for the package scaffolding.

Replace or extend these as real modules land. They exist so CI has something
meaningful to run before any feature work is merged.
"""

import pytest

import exfiltrack


@pytest.mark.unit
def test_package_exposes_version() -> None:
    assert exfiltrack.__version__ == "0.1.0"


@pytest.mark.unit
def test_package_exposes_tool_name() -> None:
    assert exfiltrack.__tool_name__ == "ExfilTrack"


@pytest.mark.unit
@pytest.mark.parametrize(
    "module_path",
    [
        "exfiltrack.cli",
        "exfiltrack.config",
        "exfiltrack.evidence.hashing",
        "exfiltrack.evidence.intake",
        "exfiltrack.evidence.manifest",
        "exfiltrack.parsers.registry_parser",
        "exfiltrack.parsers.evtx_parser",
        "exfiltrack.parsers.lnk_parser",
        "exfiltrack.parsers.jumplist_parser",
        "exfiltrack.normalization.event_model",
        "exfiltrack.normalization.timestamps",
        "exfiltrack.correlation.sessions",
        "exfiltrack.correlation.scoring",
        "exfiltrack.correlation.confidence",
        "exfiltrack.reporting.html_report",
        "exfiltrack.reporting.json_report",
        "exfiltrack.reporting.csv_report",
    ],
)
def test_every_module_imports(module_path: str) -> None:
    """Every scaffolded module must import cleanly.

    This guards against syntax errors and broken imports reaching develop.
    """
    __import__(module_path)


@pytest.mark.unit
@pytest.mark.parametrize(
    "module_path",
    [
        "exfiltrack.parsers.registry_parser",
        "exfiltrack.parsers.evtx_parser",
        "exfiltrack.parsers.lnk_parser",
        "exfiltrack.parsers.jumplist_parser",
    ],
)
def test_parsers_declare_provenance_constants(module_path: str) -> None:
    """Every parser must declare its name and version.

    Findings cite the parser that produced them, so these constants are part of
    the forensic contract rather than a convention.
    """
    module = __import__(module_path, fromlist=["PARSER_NAME", "PARSER_VERSION"])
    assert isinstance(module.PARSER_NAME, str) and module.PARSER_NAME
    assert isinstance(module.PARSER_VERSION, str) and module.PARSER_VERSION

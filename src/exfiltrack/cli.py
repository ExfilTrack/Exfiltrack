"""ExfilTrack command line interface.

Owner: Milindu Weerawarna
Related issues: #1 - Repository Initialization, #13 - Integration Testing

Commands::

    exfiltrack analyze --evidence <dir> --case-dir <dir> --case-id <id> --examiner <name>
    exfiltrack verify  --case-dir <dir>
    exfiltrack version

``analyze`` runs the full pipeline (:func:`exfiltrack.pipeline.run_pipeline`)
against an offline evidence directory and writes the case manifest and
reports. ``verify`` re-checks a previously written case's evidence digests
without re-running analysis, for a later chain-of-custody check. Domain
errors (:class:`~exfiltrack.config.ExfilTrackError` and its subclasses --
malformed evidence, an invalid case configuration, a failed report render)
are reported as a one-line message on stderr and exit code 1, never a raw
traceback: the analyst running this is not expected to be a Python
developer.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from exfiltrack import __tool_name__, __version__
from exfiltrack.config import CaseConfig, ExfilTrackError
from exfiltrack.evidence.hashing import DigestMismatchError, verify_digest
from exfiltrack.evidence.manifest import MANIFEST_FILENAME
from exfiltrack.pipeline import PipelineResult, run_pipeline

_EXIT_OK = 0
_EXIT_ERROR = 1


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exfiltrack",
        description="Offline, read-only triage for possible USB-based data exfiltration.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze", help="Run the full pipeline against an offline evidence directory."
    )
    analyze.add_argument(
        "--evidence",
        required=True,
        type=Path,
        metavar="DIR",
        help="Directory of offline Windows artifacts, opened read-only.",
    )
    analyze.add_argument(
        "--case-dir",
        required=True,
        type=Path,
        metavar="DIR",
        help="Output directory for the manifest and reports. Must not be inside --evidence.",
    )
    analyze.add_argument("--case-id", required=True, help="Analyst-supplied case identifier.")
    analyze.add_argument(
        "--examiner", required=True, help="Full name or badge ID of the analyst running the tool."
    )

    verify = subparsers.add_parser(
        "verify", help="Re-check evidence digests recorded in a previously written case manifest."
    )
    verify.add_argument(
        "--case-dir",
        required=True,
        type=Path,
        metavar="DIR",
        help=f"Case directory containing {MANIFEST_FILENAME}.",
    )

    subparsers.add_parser("version", help="Print the tool name and version.")
    return parser


def _run_analyze(args: argparse.Namespace) -> int:
    config = CaseConfig(
        evidence_dir=args.evidence,
        case_output_dir=args.case_dir,
        case_id=args.case_id,
        examiner=args.examiner,
    )
    result = run_pipeline(config)
    _print_analyze_summary(result)
    return _EXIT_OK


def _print_analyze_summary(result: PipelineResult) -> None:
    manifest = result.manifest
    print(f"Case {manifest.case_id!r}  Examiner: {manifest.examiner}")
    print(f"Artifacts discovered: {len(result.artifacts)}")
    print(f"Events normalized:    {len(result.events)}")
    print(f"USB sessions:         {len(result.sessions)}")
    print(f"Findings:             {len(result.findings)}")

    counts: dict[str, int] = {}
    for finding in result.findings:
        label = str(finding.confidence.level)
        counts[label] = counts.get(label, 0) + 1
    for label in sorted(counts):
        print(f"  {label}: {counts[label]}")

    print(f"Evidence integrity: {manifest.integrity_verdict.value}")
    for name in sorted(result.report_paths):
        print(f"  {name}: {result.report_paths[name]}")


def _run_verify(args: argparse.Namespace) -> int:
    """Re-verify a case's recorded evidence digests without re-running analysis.

    Reads ``case_manifest.json`` directly rather than reconstructing a full
    :class:`~exfiltrack.evidence.manifest.CaseManifest`, since only the
    recorded evidence directory and intake digests are needed to answer
    "has this evidence changed since the run that produced this manifest".
    """
    case_dir = args.case_dir.resolve()
    manifest_path = case_dir / MANIFEST_FILENAME
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ExfilTrackError(f"'{manifest_path}' is not valid JSON: {exc}") from exc

    digests = payload.get("intake_digests") or []
    if not digests:
        raise ExfilTrackError(f"'{manifest_path}' records no intake digests; nothing to verify.")

    evidence_dir = Path(payload["config"]["evidence_dir"])
    failures: list[str] = []
    for record in digests:
        target = evidence_dir / record["path"]
        try:
            verify_digest(target, record["digest"])
        except (DigestMismatchError, OSError) as exc:
            failures.append(f"{record['path']}: {exc}")

    if failures:
        print(
            f"INTEGRITY FAILED: {len(failures)} of {len(digests)} artifact(s) changed or missing."
        )
        for line in failures:
            print(f"  - {line}")
        return _EXIT_ERROR

    print(f"INTEGRITY VERIFIED: all {len(digests)} artifact digest(s) match the manifest.")
    return _EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point declared in ``pyproject.toml``."""
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "analyze":
            return _run_analyze(args)
        if args.command == "verify":
            return _run_verify(args)
        if args.command == "version":
            print(f"{__tool_name__} {__version__}")
            return _EXIT_OK
        parser.error(
            f"Unknown command: {args.command!r}"
        )  # pragma: no cover - argparse guards this
        return _EXIT_ERROR
    except ExfilTrackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())

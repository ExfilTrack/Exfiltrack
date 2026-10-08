"""ExfilTrack command line interface.

Owner: Milindu Weerawarna
Related issues: #1 - Repository Initialization, #13 - Integration Testing

Commands::

    exfiltrack analyze --evidence <dir> --case-dir <dir> --case-id <id> --examiner <name>
    exfiltrack analyze --auto          --case-dir <dir> --case-id <id> --examiner <name>
    exfiltrack verify  --case-dir <dir>
    exfiltrack version

``analyze --evidence`` runs the full pipeline (:func:`exfiltrack.pipeline.run_pipeline`)
against an offline evidence directory and writes the case manifest and
reports. ``analyze --auto`` first collects the relevant artifacts from the
running, elevated Windows machine into a new case directory
(:func:`exfiltrack.evidence.live.collect_live_evidence`), then runs the same
pipeline on those snapshots; ``--case-dir`` is then the case root holding
``evidence/``, ``reports/`` and ``acquisition_manifest.json``. ``verify`` re-checks a previously written case's evidence digests
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
from exfiltrack.evidence.live import collect_live_evidence
from exfiltrack.evidence.manifest import MANIFEST_FILENAME
from exfiltrack.pipeline import PipelineResult, run_pipeline

_EXIT_OK = 0
_EXIT_ERROR = 1


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exfiltrack",
        description="Offline, read-only triage for possible USB-based data exfiltration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze", help="Run the full pipeline against an offline evidence directory."
    )
    source = analyze.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--evidence",
        type=Path,
        metavar="DIR",
        help="Directory of offline Windows artifacts, opened read-only.",
    )
    source.add_argument(
        "--auto",
        action="store_true",
        help=(
            "Collect the relevant artifacts from this running Windows machine "
            "(requires an elevated terminal), then analyze them. Logging and "
            "auditing are never enabled or changed."
        ),
    )
    analyze.add_argument(
        "--case-dir",
        required=True,
        type=Path,
        metavar="DIR",
        help=(
            "With --evidence: output directory for the manifest and reports, which must "
            "not be inside --evidence. With --auto: a new case directory that must not "
            "already exist; reports are written to its reports/ folder."
        ),
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
        help=(
            f"Case directory containing {MANIFEST_FILENAME} (for an --auto case, the case "
            "directory itself is accepted; its reports/ folder is used)."
        ),
    )

    subparsers.add_parser("version", help="Print the tool name and version.")
    parser.epilog = (
        "Analyze command:\n"
        f"{analyze.format_help()}\n"
        "Verify command:\n"
        f"{verify.format_help()}\n"
        "Examples:\n"
        "  exfiltrack analyze --evidence ./evidence --case-dir ./cases/CASE-001 "
        '--case-id CASE-001 --examiner "Your Name"\n'
        "  exfiltrack analyze --auto --case-dir ./cases/CASE-002 "
        '--case-id CASE-002 --examiner "Your Name"   (elevated Windows terminal)\n'
        "  exfiltrack verify --case-dir ./cases/CASE-001\n"
        "  exfiltrack version\n\n"
        "For command-specific help, use: exfiltrack <command> --help"
    )
    return parser


def _run_analyze(args: argparse.Namespace) -> int:
    if args.auto:
        return _run_auto(args)
    config = CaseConfig(
        evidence_dir=args.evidence,
        case_output_dir=args.case_dir,
        case_id=args.case_id,
        examiner=args.examiner,
    )
    result = run_pipeline(config)
    _print_analyze_summary(result)
    return _EXIT_OK


def _run_auto(args: argparse.Namespace) -> int:
    """Collect artifacts from this machine into a fresh case, then analyze them.

    Collection and analysis stay separate: the pipeline only ever reads the
    collected snapshots, never the live files. Parser failures on individual
    snapshots are recorded and reported rather than discarding the whole case.
    """
    print("Collecting artifacts from this machine (read-only; no logging is changed)...")
    acquisition = collect_live_evidence(args.case_dir, case_id=args.case_id, examiner=args.examiner)
    gaps = [
        record
        for record in acquisition.manifest["records"]
        if record["status"] in {"missing", "unavailable", "error"}
        or record.get("metadata", {}).get("channel_enabled") is False
    ]
    collected = sum(1 for r in acquisition.manifest["records"] if r["status"] == "collected")
    print(f"Collection coverage:  {acquisition.manifest['coverage']}")
    print(f"Sources collected:    {collected}")
    for record in gaps:
        reason = record.get("message") or record["status"]
        print(f"  gap: [{record['category']}] {record['source']}: {reason}")
    print(f"Acquisition manifest: {acquisition.manifest_path}")

    config = CaseConfig(
        evidence_dir=acquisition.evidence_dir,
        case_output_dir=acquisition.reports_dir,
        case_id=args.case_id,
        examiner=args.examiner,
    )
    result = run_pipeline(
        config,
        acquisition=acquisition.manifest,
        continue_on_parser_error=True,
    )
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

    if manifest.parser_errors:
        print(
            f"WARNING: {len(manifest.parser_errors)} artifact(s) could not be parsed; "
            "results are PARTIAL."
        )
        for error in manifest.parser_errors:
            print(f"  parser error: {error['source_artifact']}: {error['message']}")
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
    auto_manifest_path = case_dir / "reports" / MANIFEST_FILENAME
    if not manifest_path.exists() and auto_manifest_path.exists():
        manifest_path = auto_manifest_path
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

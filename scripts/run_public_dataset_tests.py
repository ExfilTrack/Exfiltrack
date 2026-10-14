"""Automated test runner for ExfilTrack using public dataset test evidence cases.

Tests each case in public_datasets/test_evidence_suite/ against ExfilTrack's
end-to-end analysis and verification pipeline via the CLI entrypoint.
"""

from __future__ import annotations

import sys
import shutil
from pathlib import Path

# Add project root and src to path
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from exfiltrack.cli import main as cli_main


def run_tests():
    print("=" * 70)
    print("ExfilTrack Public Dataset Test Suite Runner")
    print("=" * 70)

    suite_dir = REPO_ROOT / "public_datasets" / "test_evidence_suite"
    output_base = REPO_ROOT / "cases-outputs" / "public_dataset_runs"

    if not suite_dir.exists():
        print(f"Error: Test evidence suite not found at {suite_dir}")
        sys.exit(1)

    cases = sorted([d for d in suite_dir.iterdir() if d.is_dir() and d.name.startswith("case_")])
    print(f"Found {len(cases)} test cases to run:\n")

    summary = []

    for case_dir in cases:
        case_name = case_dir.name
        case_id = f"PUB-{case_name.upper().replace('_', '-')}"
        out_dir = output_base / case_name

        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        print(f"[{case_name}] Starting analysis...")
        print(f"  Evidence: {case_dir.relative_to(REPO_ROOT)}")
        print(f"  Case ID:  {case_id}")
        print(f"  Output:   {out_dir.relative_to(REPO_ROOT)}")

        # 1. Run 'analyze'
        analyze_args = [
            "analyze",
            "--evidence",
            str(case_dir),
            "--case-dir",
            str(out_dir),
            "--case-id",
            case_id,
            "--examiner",
            "Automated Dataset Tester",
        ]
        ret_analyze = cli_main(analyze_args)

        if ret_analyze != 0:
            print(f"  [FAIL] {case_name}: analyze exited with code {ret_analyze}\n")
            summary.append(
                {
                    "case": case_name,
                    "analyze": "FAIL",
                    "verify": "SKIPPED",
                }
            )
            continue

        # 2. Run 'verify'
        verify_args = [
            "verify",
            "--case-dir",
            str(out_dir),
        ]
        ret_verify = cli_main(verify_args)
        status_verify = "PASS" if ret_verify == 0 else "FAIL"

        print(f"  [PASS] {case_name} (Analyze: PASS, Verify: {status_verify})\n")
        summary.append(
            {
                "case": case_name,
                "analyze": "PASS",
                "verify": status_verify,
            }
        )

    print("=" * 70)
    print("Test Suite Summary")
    print("=" * 70)
    for res in summary:
        print(f"  {res['case']:<35} | Analyze: {res['analyze']:<5} | Verify: {res['verify']}")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()

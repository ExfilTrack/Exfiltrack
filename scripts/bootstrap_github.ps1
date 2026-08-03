#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Bootstraps the ExfilTrack GitHub repository: labels, milestones, and issues.

.DESCRIPTION
    Creates the 5 project milestones, the label set, and all 14 tracking issues
    described in docs/task-assignments.md.

    Idempotent: existing labels, milestones, and issues with the same title are
    skipped rather than duplicated.

.PREREQUISITES
    1. GitHub CLI installed:  https://cli.github.com/
    2. Authenticated:         gh auth login
    3. Run from the repository root.

.EXAMPLE
    ./scripts/bootstrap_github.ps1
    ./scripts/bootstrap_github.ps1 -DryRun
#>

[CmdletBinding()]
param(
    [string]$Repo = "ExfilTrack/Exfiltrack",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------
# GitHub usernames. UPDATE THESE before running.
# Issues are created unassigned if a value is left empty.
# ------------------------------------------------------------------
$UserMilindu  = "Milindu-Weerawarna"
$UserThabrew  = "Thabrew-DCL"
$UserMaheesha = "Maheesha-GDM"

function Test-GhCli {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw "GitHub CLI (gh) not found. Install from https://cli.github.com/ then run: gh auth login"
    }
    gh auth status 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "GitHub CLI is not authenticated. Run: gh auth login"
    }
}

function Invoke-Gh {
    param([string[]]$Arguments, [string]$Description)
    if ($DryRun) {
        Write-Host "[dry-run] gh $($Arguments -join ' ')" -ForegroundColor DarkGray
        return $null
    }
    Write-Host "  -> $Description" -ForegroundColor Cyan
    $output = & gh @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "     skipped or failed: $output" -ForegroundColor Yellow
        return $null
    }
    return $output
}

# ------------------------------------------------------------------
# Labels
# ------------------------------------------------------------------
$labels = @(
    @{ Name = "milestone-1";     Color = "0e8a16"; Description = "Artifact Collection Layer" }
    @{ Name = "milestone-2";     Color = "1d76db"; Description = "Correlation Engine" }
    @{ Name = "milestone-3";     Color = "5319e7"; Description = "Reporting Layer" }
    @{ Name = "milestone-4";     Color = "fbca04"; Description = "Testing and Evaluation" }
    @{ Name = "milestone-5";     Color = "b60205"; Description = "Final Release" }
    @{ Name = "evidence";        Color = "c2e0c6"; Description = "Evidence intake, hashing, manifest" }
    @{ Name = "parser";          Color = "bfd4f2"; Description = "Windows artifact parsing" }
    @{ Name = "normalization";   Color = "d4c5f9"; Description = "Event model and timestamps" }
    @{ Name = "correlation";     Color = "f9d0c4"; Description = "Sessions, scoring, confidence" }
    @{ Name = "reporting";       Color = "fef2c0"; Description = "HTML, JSON, CSV output" }
    @{ Name = "documentation";   Color = "0075ca"; Description = "Documentation work" }
    @{ Name = "testing";         Color = "d93f0b"; Description = "Tests and evaluation" }
    @{ Name = "forensic-soundness"; Color = "000000"; Description = "Affects evidence integrity or chain of custody" }
    @{ Name = "blocked";         Color = "e11d21"; Description = "Waiting on another issue" }
)

# ------------------------------------------------------------------
# Milestones
# ------------------------------------------------------------------
$milestones = @(
    @{ Title = "Milestone 1: Artifact Collection Layer"; Description = "Evidence intake, SHA-256 hashing and manifesting, and all four Windows artifact parsers." }
    @{ Title = "Milestone 2: Correlation Engine";        Description = "Event normalization, USB session reconstruction, risk scoring, and confidence evaluation." }
    @{ Title = "Milestone 3: Reporting Layer";           Description = "HTML, JSON, and CSV report generation." }
    @{ Title = "Milestone 4: Testing and Evaluation";    Description = "Integration tests, the four controlled scenarios, accuracy and false-positive metrics." }
    @{ Title = "Milestone 5: Final Release";             Description = "Final documentation, packaging, and demonstration." }
)

# ------------------------------------------------------------------
# Issues
# ------------------------------------------------------------------
$issues = @(
    @{
        Title = "Repository Initialization"
        Assignee = $UserMilindu
        Milestone = "Milestone 1: Artifact Collection Layer"
        Labels = @("milestone-1", "documentation")
        Body = @"
Set up the repository scaffolding, tooling, and team process.

## Scope
- Python src-layout package structure under ``src/exfiltrack/``
- ``pyproject.toml`` with runtime and dev dependencies, black/ruff/mypy/pytest config
- ``.gitignore`` that blocks real evidence from ever being committed
- ``README.md``, ``CONTRIBUTING.md``, ``SECURITY.md``, ``LICENSE``
- ``.github/`` CODEOWNERS, PR template, issue templates, CI workflow
- ``develop`` and ``main`` branches with protection rules
- ``docs/task-assignments.md`` working brief

## Definition of Done
- [ ] ``pip install -e ".[dev]"`` succeeds
- [ ] ``pytest``, ``ruff check``, ``black --check``, ``mypy src/`` all run clean
- [ ] CI passes on ``develop``
- [ ] ``main`` requires a PR and one approving review
- [ ] Every team member can clone, install, and run the checks

## Reference
See ``docs/task-assignments.md``.
"@
    },
    @{
        Title = "Evidence Intake and Hash Verification"
        Assignee = $UserMilindu
        Milestone = "Milestone 1: Artifact Collection Layer"
        Labels = @("milestone-1", "evidence", "forensic-soundness")
        Body = @"
Implement the single gateway through which evidence enters ExfilTrack.

## Files
- ``src/exfiltrack/evidence/intake.py``
- ``src/exfiltrack/evidence/hashing.py``
- ``src/exfiltrack/evidence/manifest.py``
- ``src/exfiltrack/config.py``

## Definition of Done
- [ ] Artifacts discovered and classified by name convention **and** magic bytes
- [ ] All evidence opened strictly read-only
- [ ] Large files streamed in chunks; a registry hive is never loaded whole into memory
- [ ] SHA-256 computed at intake and again after analysis
- [ ] A digest mismatch is a hard failure, not a warning
- [ ] ``case_manifest.json`` records case id, examiner, tool version, start/end time, config snapshot, parser records, both digest sets, and the integrity verdict
- [ ] Run refuses to start if the case directory is inside the evidence directory
- [ ] Malformed or unreadable evidence produces an explicit error, never a silent skip
- [ ] Unit tests cover digest mismatch, path overlap rejection, and malformed input

## Forensic Requirements
Requirements 1, 2, 3, and 6 in the README are enforced here.
"@
    },
    @{
        Title = "Registry Artifact Parser"
        Assignee = $UserMilindu
        Milestone = "Milestone 1: Artifact Collection Layer"
        Labels = @("milestone-1", "parser")
        Body = @"
Parse Windows registry hives to identify USB storage devices.

## File
``src/exfiltrack/parsers/registry_parser.py``

## Keys in Scope
- ``SYSTEM\CurrentControlSet\Enum\USBSTOR`` - device instances, vendor/product strings, serial numbers
- ``SYSTEM\MountedDevices`` - drive letter to volume mappings
- ``SOFTWARE\Microsoft\Windows Portable Devices\Devices`` - friendly names
- ``NTUSER.DAT ... \MountPoints2`` - per-user volume GUIDs

## Definition of Done
- [ ] Hives opened read-only
- [ ] ``PARSER_NAME`` and ``PARSER_VERSION`` declared
- [ ] Emits ``NormalizedEvent`` values, never raw registry structures
- [ ] Missing or corrupt hives raise an explicit error
- [ ] Output deterministically ordered
- [ ] ``docs/evidence-sources.md`` documents what each key proves versus merely suggests
- [ ] Unit tests against synthetic hive fixtures

## Depends On
#7 for the event model.
"@
    },
    @{
        Title = "EVTX Parser"
        Assignee = $UserThabrew
        Milestone = "Milestone 1: Artifact Collection Layer"
        Labels = @("milestone-1", "parser")
        Body = @"
Parse Windows Event Logs for storage device events.

## File
``src/exfiltrack/parsers/evtx_parser.py``

## Scope
- ``System.evtx`` and ``Security.evtx``
- Storage driver mount and unmount events
- Device install and removal events

## Definition of Done
- [ ] Logs opened read-only
- [ ] ``PARSER_NAME`` and ``PARSER_VERSION`` declared
- [ ] Event IDs and providers used are documented, along with what each actually proves
- [ ] Emits ``NormalizedEvent`` values with UTC-normalized timestamps
- [ ] Malformed records raise rather than being skipped silently
- [ ] ``docs/limitations.md`` records that these channels are frequently disabled by default, so absence of an event is not absence of the activity
- [ ] Unit tests against synthetic EVTX fixtures

## Depends On
#7 for the event model.
"@
    },
    @{
        Title = "LNK Parser"
        Assignee = $UserThabrew
        Milestone = "Milestone 1: Artifact Collection Layer"
        Labels = @("milestone-1", "parser")
        Body = @"
Parse Windows shortcut files for recent file activity.

## File
``src/exfiltrack/parsers/lnk_parser.py``

## Scope
- Target file path, size, and attributes
- Creation, access, and modification timestamps
- Volume serial number and drive type, to attribute a file to a removable volume

## Definition of Done
- [ ] Files opened read-only
- [ ] ``PARSER_NAME`` and ``PARSER_VERSION`` declared
- [ ] All reads bounds-checked; the format is treated as hostile input
- [ ] Never resolves an extracted path against the live filesystem
- [ ] Emits ``NormalizedEvent`` values with UTC-normalized timestamps
- [ ] Truncated or malformed shortcuts raise an explicit error
- [ ] Unit tests against synthetic ``.lnk`` fixtures, including a truncated file

## Depends On
#7 for the event model.

## Note
Access timestamps record access, not copying. Document that distinction.
"@
    },
    @{
        Title = "Jump List Parser"
        Assignee = $UserThabrew
        Milestone = "Milestone 1: Artifact Collection Layer"
        Labels = @("milestone-1", "parser")
        Body = @"
Parse Jump Lists for per-application file activity.

## File
``src/exfiltrack/parsers/jumplist_parser.py``

## Scope
- ``automaticDestinations-ms`` - recent and frequent entries
- ``customDestinations-ms`` - application-defined entries
- AppID to application mapping

## Definition of Done
- [ ] Files opened read-only
- [ ] ``PARSER_NAME`` and ``PARSER_VERSION`` declared
- [ ] Unknown AppIDs are reported, not dropped
- [ ] Emits ``NormalizedEvent`` values with UTC-normalized timestamps
- [ ] Malformed containers raise an explicit error
- [ ] Unit tests against synthetic Jump List fixtures

## Depends On
#7 for the event model.
"@
    },
    @{
        Title = "Event Normalization Model"
        Assignee = $UserThabrew
        Milestone = "Milestone 2: Correlation Engine"
        Labels = @("milestone-2", "normalization", "forensic-soundness")
        Body = @"
Define the single event shape shared by all parsers and consumed by the correlation engine.

**This is the highest-priority issue after #2. Issues #3, #4, #5, #6, #8, #9, and #10 all depend on it.**

## Files
- ``src/exfiltrack/normalization/event_model.py``
- ``src/exfiltrack/normalization/timestamps.py``

## Definition of Done
- [ ] ``NormalizedEvent`` and ``UsbDevice`` defined
- [ ] Validator rejects events missing provenance or carrying timezone-naive timestamps
- [ ] Windows FILETIME conversion
- [ ] Packed DOS date/time conversion
- [ ] EVTX ISO-8601 parsing
- [ ] Original raw timestamp preserved alongside the UTC value
- [ ] Deterministic timeline sort with documented tie-breaking
- [ ] Stream merge combining per-parser output into one timeline
- [ ] Unparseable timestamps raise rather than defaulting to a placeholder
- [ ] Unit tests covering epoch boundaries, naive-datetime rejection, and sort stability

## Coordination
Any field added to ``NormalizedEvent`` must be raised in this thread first. Do not add fields locally and merge.
"@
    },
    @{
        Title = "USB Session Reconstruction"
        Assignee = $UserMaheesha
        Milestone = "Milestone 2: Correlation Engine"
        Labels = @("milestone-2", "correlation")
        Body = @"
Group device events into probable USB connection sessions.

## File
``src/exfiltrack/correlation/sessions.py``

## Definition of Done
- [ ] Device events grouped into sessions per device
- [ ] Session end inferred using the configured idle gap when no removal event exists
- [ ] **Inferred boundaries flagged distinctly from observed ones**, and the report shows which is which
- [ ] File activity falling inside a session window attached to that session
- [ ] Overlapping sessions from multiple devices handled correctly
- [ ] Deterministic session ordering
- [ ] Unit tests covering: no removal event, overlapping devices, and a session with zero file activity

## Depends On
#7 for the event model. Build against hand-written event fixtures until parsers land.
"@
    },
    @{
        Title = "Risk Scoring Engine"
        Assignee = $UserMaheesha
        Milestone = "Milestone 2: Correlation Engine"
        Labels = @("milestone-2", "correlation", "forensic-soundness")
        Body = @"
Implement the explainable rule-based risk score.

## File
``src/exfiltrack/correlation/scoring.py``

## Rules
| Rule | Points |
| --- | --- |
| File activity within 30 seconds of USB insertion | +25 |
| File activity within 5 minutes of USB insertion | +15 |
| Sensitive extension (.sql, .pem, .env, .zip) | +15 |
| File in a protected project directory | +20 |
| Multiple confidential files in one session | +15 |
| Matching file hash on the destination USB | +50 |

## Definition of Done
- [ ] Weights read from ``config.py``, never hardcoded, so #13 can measure how weight changes affect the false-positive rate
- [ ] Every contribution records its rule name and the source artifact that triggered it
- [ ] Documented decision on whether the 30-second and 5-minute rules stack
- [ ] Documented decision on whether repeated hits within one session are capped
- [ ] No black-box logic; a score must be explainable line by line
- [ ] ``docs/scoring-model.md`` updated with the final thresholds
- [ ] Unit tests asserting the exact score for each rule in isolation, plus one combined case

## Depends On
#8.
"@
    },
    @{
        Title = "Confidence Evaluation Model"
        Assignee = $UserMaheesha
        Milestone = "Milestone 2: Correlation Engine"
        Labels = @("milestone-2", "correlation", "forensic-soundness")
        Body = @"
Assign calibrated confidence levels to findings.

## File
``src/exfiltrack/correlation/confidence.py``

## Levels
| Level | Meaning |
| --- | --- |
| Low | A USB was connected and a sensitive-looking file was accessed in the same general window |
| Medium | Multiple related files were accessed shortly after insertion, consistent with staging behaviour |
| High | Supporting audit-log or destination-device evidence is present |
| Confirmed | A cryptographic hash match exists between the source file and a file on the destination USB |

## Definition of Done
- [ ] **``Confirmed`` requires a hash match. Score alone can never reach it.**
- [ ] Score thresholds for Low, Medium, and High documented with the reasoning behind each
- [ ] Every finding records why it received its level
- [ ] Unit test asserting that a maximum-score finding without a hash match does **not** reach ``Confirmed``

## Why This Matters
This is the rule that keeps ExfilTrack defensible. A tool that declares "theft confirmed" on temporal correlation alone is both technically wrong and unusable in any HR or legal context.

## Depends On
#9.
"@
    },
    @{
        Title = "HTML Report Generator"
        Assignee = $UserMaheesha
        Milestone = "Milestone 3: Reporting Layer"
        Labels = @("milestone-3", "reporting")
        Body = @"
Generate the investigator-facing HTML report.

## Files
- ``src/exfiltrack/reporting/html_report.py``
- ``templates/``

## Definition of Done
- [ ] Self-contained HTML, readable by a non-technical manager
- [ ] Per-session findings with a line-by-line score breakdown
- [ ] Confidence level shown for every finding
- [ ] Every finding cites its source artifact
- [ ] Chain-of-custody manifest included
- [ ] Limitations section included
- [ ] Inferred session boundaries visually distinguished from observed ones
- [ ] Wording expresses activity consistent with possible exfiltration, never proof
- [ ] Written to the case directory, never the evidence directory
- [ ] Unit tests asserting the report renders and that forbidden phrasing is absent

## Depends On
#10.
"@
    },
    @{
        Title = "JSON/CSV Export"
        Assignee = $UserMaheesha
        Milestone = "Milestone 3: Reporting Layer"
        Labels = @("milestone-3", "reporting")
        Body = @"
Generate machine-readable and spreadsheet-friendly output.

## Files
- ``src/exfiltrack/reporting/json_report.py``
- ``src/exfiltrack/reporting/csv_report.py``

## Definition of Done
- [ ] JSON carries the full finding set, case manifest, parser versions, and every score contribution
- [ ] CSV provides a flat findings table plus a separate timeline table
- [ ] Column order stable so diffs between runs stay readable
- [ ] **Byte-identical output across runs on identical evidence**
- [ ] Written to the case directory, never the evidence directory
- [ ] Unit test running the same input twice and asserting identical bytes

## Depends On
#10.
"@
    },
    @{
        Title = "Integration Testing"
        Assignee = ""
        Milestone = "Milestone 4: Testing and Evaluation"
        Labels = @("milestone-4", "testing")
        Body = @"
End-to-end pipeline tests against synthetic evidence.

**Assigned to: all members.**

## Scenarios
1. Normal, non-suspicious USB use - measures the false-positive rate
2. Simulated theft of synthetic confidential files
3. Archive staging and deletion
4. Unrelated recent-file activity with no USB copy - confirms no false accusations

## Definition of Done
- [ ] Synthetic fixture set committed under ``tests/fixtures/``
- [ ] All four scenarios run end to end via ``tests/integration/``
- [ ] Scenario 1 produces no High or Confirmed findings
- [ ] Scenario 4 produces no findings attributing activity to a USB device
- [ ] Reproducibility: two runs over identical evidence produce identical output
- [ ] Integrity: evidence digests unchanged after a full run
- [ ] Detection accuracy and false-positive rate recorded in ``docs/scoring-model.md``
- [ ] CI runs the integration suite

## Note
No real evidence. Synthetic fixtures only.
"@
    },
    @{
        Title = "Final Documentation"
        Assignee = ""
        Milestone = "Milestone 5: Final Release"
        Labels = @("milestone-5", "documentation")
        Body = @"
Complete all documentation for submission.

**Assigned to: all members. Each owns their own documents.**

## Definition of Done
- [ ] Every ``_To document:_`` placeholder across ``docs/`` filled in
- [ ] ``docs/architecture.md`` matches the implemented design (Milindu)
- [ ] ``docs/evidence-sources.md`` documents every artifact and its reliability (Thabrew)
- [ ] ``docs/scoring-model.md`` records final weights, thresholds, and calibration results (Maheesha)
- [ ] ``docs/user-guide.md`` covers installation, evidence preparation, running, and interpreting output (Maheesha)
- [ ] ``docs/limitations.md`` complete, including every limitation discovered during implementation (all)
- [ ] ``README.md`` reflects the shipped tool, not the plan
- [ ] Evaluation results recorded: detection accuracy, false-positive rate, reproducibility
- [ ] Sample case output committed under ``examples/synthetic/``

## Requirement
The statement "ExfilTrack identifies activity consistent with possible USB-based data exfiltration. Temporal correlation alone does not prove that a file was copied." must appear in the README and in every generated report.
"@
    }
)

# ------------------------------------------------------------------
# Execute
# ------------------------------------------------------------------
Write-Host ""
Write-Host "ExfilTrack GitHub Bootstrap" -ForegroundColor Green
Write-Host "Repository: $Repo"
if ($DryRun) { Write-Host "Mode: DRY RUN (nothing will be created)" -ForegroundColor Yellow }
Write-Host ""

if (-not $DryRun) { Test-GhCli }

Write-Host "Creating labels..." -ForegroundColor Green
foreach ($label in $labels) {
    Invoke-Gh -Arguments @(
        "label", "create", $label.Name,
        "--repo", $Repo,
        "--color", $label.Color,
        "--description", $label.Description,
        "--force"
    ) -Description "label: $($label.Name)" | Out-Null
}

Write-Host ""
Write-Host "Creating milestones..." -ForegroundColor Green
foreach ($milestone in $milestones) {
    if ($DryRun) {
        Write-Host "[dry-run] milestone: $($milestone.Title)" -ForegroundColor DarkGray
        continue
    }
    Write-Host "  -> milestone: $($milestone.Title)" -ForegroundColor Cyan
    $encodedTitle = [uri]::EscapeDataString($milestone.Title)
    $encodedDesc  = [uri]::EscapeDataString($milestone.Description)
    $result = & gh api "repos/$Repo/milestones" -X POST -f "title=$($milestone.Title)" -f "description=$($milestone.Description)" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "     skipped (may already exist)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Creating issues..." -ForegroundColor Green
$issueNumber = 1
foreach ($issue in $issues) {
    $arguments = @(
        "issue", "create",
        "--repo", $Repo,
        "--title", $issue.Title,
        "--body", $issue.Body,
        "--milestone", $issue.Milestone
    )
    foreach ($label in $issue.Labels) {
        $arguments += @("--label", $label)
    }
    if ($issue.Assignee) {
        $arguments += @("--assignee", $issue.Assignee)
    }
    Invoke-Gh -Arguments $arguments -Description "#$issueNumber $($issue.Title)" | Out-Null
    $issueNumber++
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "  1. Verify issue numbers match docs/task-assignments.md (#1 through #14)."
Write-Host "  2. Assign #13 and #14 to all three members manually."
Write-Host "  3. Run ./scripts/setup_branch_protection.ps1 to protect main and develop."
Write-Host ""

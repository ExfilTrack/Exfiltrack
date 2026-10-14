# User Guide

**Owner:** Dabarera G. D. M. (Maheesha)
**Tracking issue:** #14 - Final Documentation

Status: maintained. This guide covers the command-line workflow and the desktop GUI.

---

## Who This Guide Is For

Authorized investigators and internal IT security staff without a dedicated forensics unit. It assumes familiarity with Windows and the command line, but not with forensic artifact formats.

## Before You Start

Read [limitations.md](limitations.md). ExfilTrack produces leads, not verdicts.

## Installation

Choose the standalone executable for routine Windows triage, or install from
source when you need a Python environment, development tools, or a version that
is not yet packaged as a release.

### Standalone Windows Executable (Recommended for Triage)

For forensic workstations, triage VMs, or machines without a Python
environment:

1. Open the [latest ExfilTrack release](https://github.com/ExfilTrack/Exfiltrack/releases/latest)
   and download the `ExfilTrack.exe` asset from that release. This link follows
   the newest published version and remains valid when future releases are
   published.
2. Store the executable in a trusted tools directory. Before using it in an
   investigation, record the release version and verify the download against
   the checksums or release notes provided for that version.
3. Double-click `ExfilTrack.exe`, or launch it from an elevated PowerShell
   when live collection is required. The executable requests UAC Administrator
   privileges for live artifact collection (`--auto` / Live mode).
4. Use the GUI for guided case setup, or use the executable's command-line
   interface where supported.

No Python runtime, Git installation, or virtual environment is required. The
standalone executable is intended for Windows; use the source installation
below for Linux and macOS workflows.

### Installation from Source

Requires Python 3.10 or newer.

```bash
git clone https://github.com/ExfilTrack/Exfiltrack.git
cd Exfiltrack
python -m venv .venv
.venv\Scripts\Activate.ps1     # Windows
source .venv/bin/activate       # Linux / macOS
pip install -e ".[dev]"
```

## Preparing Evidence

For prerequisites and source-specific export procedures, see
[evidence-sources.md §6.2](evidence-sources.md#62-export-procedures).

Expected layout:

```
evidence/
├── registry/
│   ├── SYSTEM
│   ├── SOFTWARE
│   └── NTUSER.DAT
├── evtx/
│   ├── System.evtx
│   ├── Security.evtx
│   └── Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx
├── lnk/
└── jumplists/
```

Rules:

- Work from copies, never the original disk.
- Keep the evidence directory separate from the case output directory. ExfilTrack refuses to write inside the evidence directory.

## Running an Analysis

```bash
exfiltrack analyze \
  --evidence ./evidence \
  --case-dir ./cases/CASE-001 \
  --case-id CASE-001 \
  --examiner "Your Name"
```

Add `--since YYYY-MM-DD` to restrict analysis to events on/after that date (UTC) — typically the date the laptop was handed to the employee. The cutoff and the number of excluded events are recorded in `case_manifest.json` and shown in the report, so a scoped run can never be mistaken for a full one.

_To document: full flag reference, exit codes, and what appears on stdout._

## Automatic Collection on a Live Windows Machine (`--auto`)

Instead of exporting evidence by hand, `--auto` collects the relevant artifacts from the machine it runs on, stores them as snapshots in a new case, and analyzes those snapshots.

```powershell
# Run from an elevated (Administrator) terminal
exfiltrack analyze --auto --case-dir D:\Cases\CASE-002 --case-id CASE-002 --examiner "Your Name"
```

`--auto` replaces `--evidence`; the two cannot be combined. `--case-dir` must **not already exist** and must not be inside a Windows or user-profile directory. ExfilTrack creates:

```
CASE-002/
├── evidence/                 collected snapshots (never modified afterwards)
│   ├── evtx/                 System, Security, DriverFrameworks-UserMode/Operational
│   ├── registry/             SYSTEM, SOFTWARE
│   └── users/<SID>/          NTUSER.DAT, Recent/*.lnk, Recent/*Destinations/*
├── reports/                  report.html, findings.json, findings.csv, timeline.csv, case_manifest.json
└── acquisition_manifest.json what was collected, how, and what could not be
```

Only standard locations are examined (event logs via `wevtutil`, `SYSTEM`/`SOFTWARE` and loaded user hives via `reg save`, and each registered profile's `NTUSER.DAT`, `Recent`, and Jump List folders). There is no full-disk scan.

**What auto mode does not do**

- It never enables logging or auditing and never clears or modifies logs. If a channel such as `Microsoft-Windows-DriverFrameworks-UserMode/Operational` is disabled, it is collected anyway and flagged in the report. Events that were never recorded cannot be recovered by enabling logging afterwards, so configure auditing (see [organizational-prerequisites.md](organizational-prerequisites.md)) **before** the activity you want to investigate.
- It does not verify that file-access auditing or SACLs were in effect; absence of file-access events is not evidence that no files were accessed.
- Collection is not an atomic snapshot, and running it creates activity on the machine. The integrity verdict covers the collected snapshots, not the live system.

**Reading the result.** The console and the report's *Evidence Coverage* section show `complete` or `partial` coverage and list each source that was missing, denied, or failed. If an individual snapshot cannot be parsed, it is listed as a parser error, the report is marked *Partial analysis*, and the remaining artifacts are still analyzed. Before parsing, every snapshot is re-hashed against `acquisition_manifest.json`; if any file changed or was added since collection, analysis is refused.

## Verifying Integrity

```bash
exfiltrack verify --case-dir ./cases/CASE-001
```

For an `--auto` case, pass the case directory itself; its `reports/case_manifest.json` is used.

_To document: what a pass and a failure look like, and what to do if digests do not match._

## Graphical Interface

A desktop GUI wraps the same pipeline; it adds no new behaviour and no new dependencies (tkinter ships with Python on Windows).

```bash
exfiltrack-gui
# or, without the entry point:
python -m exfiltrack.gui
```

**Fastest path — One-Click Report.** Click **One-Click Report (this machine)** and confirm the prompt: ExfilTrack generates the case ID, examiner, and a fresh case directory under `~/ExfilTrackCases/` by itself, collects this machine's logs (read-only — exactly what `analyze --auto` does), analyzes them, states in the window whether any reconstructed session is consistent with possible USB exfiltration, and opens the HTML report. Run from an elevated terminal for full coverage; without it, the sources that could not be collected are listed in the report's *Evidence Coverage* section.

For a case you want to control yourself (existing evidence exports, specific case directory):

1. Enter the **case ID** and **examiner** name.
2. Choose the mode:
   - **Offline evidence directory** — equivalent to `analyze --evidence`. Pick the evidence folder prepared earlier.
   - **Live acquisition** — equivalent to `analyze --auto`. Run from an elevated terminal and pick a **case directory that does not exist yet**; the evidence picker is disabled because artifacts are collected from the machine.
3. Pick the **case output directory** (offline mode). It must not be inside the evidence directory; the GUI rejects that before a run starts.
4. Optionally set **Analyze events from (UTC)** — e.g. the date the laptop was handed to the employee. Events before that date are excluded from analysis, and the cutoff is disclosed in the manifest and report. Leave empty for the full evidence set.
5. Click **Run Analysis**. The run executes in the background; the bar shows the current stage and the percentage of work done, and any parser warnings appear in the log pane.
6. Review the findings table — device, session start, risk score, confidence, and whether session boundaries were observed or inferred. **Double-click a row** for the confidence reason and the per-rule score breakdown.
7. Use **Open HTML Report** or **Open Output Folder** to reach the full report, and **Verify Case Integrity...** to re-check a case's recorded digests (equivalent to `exfiltrack verify`).

All CLI rules apply unchanged: evidence is opened read-only, output is never written inside the evidence tree, and errors are shown as messages, not tracebacks. The mandated wording — *"ExfilTrack identifies activity consistent with possible USB-based data exfiltration. Temporal correlation alone does not prove that a file was copied."* — is shown at the bottom of the window.

### GUI walkthrough

![ExfilTrack desktop interface](images/exfiltrack-gui-overview.png)

The desktop interface is organized as a guided case workflow:

| Area | Purpose |
| --- | --- |
| **Quick triage** | Collect and analyze the current machine without completing the case form. |
| **Case** | Identify the case, choose offline or live mode, select folders, and start a run. |
| **Progress** | Show the active stage, percentage, status, and parser messages. |
| **Findings** | Summarize reconstructed USB sessions and open score details. |

#### One-Click Report

Use this option for a fast triage of the computer currently running ExfilTrack.

1. Start the GUI from an elevated terminal.
2. Select **One-Click Report (this machine)**.
3. Confirm the collection prompt.
4. Wait for the progress area to complete. ExfilTrack collects supported artifacts
   read-only, hashes them, analyzes them, and generates the reports.
5. Review the summary and select **Open HTML Report**.

The one-click workflow is equivalent to `analyze --auto`. ExfilTrack creates the
case ID, examiner label, and a new case directory below `~/ExfilTrackCases/`.
Run elevated for the best collection coverage. Any unavailable source appears
under **Evidence Coverage** in the report.

#### Analyze exported evidence

1. Enter a descriptive **Case ID**, such as `INC-2026-014`.
2. Enter the **Examiner** name or team identifier.
3. Leave **Offline evidence directory** selected.
4. Select **Browse...** beside **Evidence directory** and choose the evidence
   folder, not an individual hive or event-log file.
5. Select **Browse...** beside **Case output directory** and choose a separate
   output location, such as `D:\Cases\INC-2026-014`.
6. Select **Run Analysis** and monitor the progress and log areas.
7. Review the **Findings** table. It shows the device, session start in UTC,
   risk score, confidence, and whether boundaries were observed or inferred.
8. Double-click a finding to open its confidence reason and per-rule score
   breakdown.
9. Select **Open HTML Report** or **Open Output Folder**.

The output directory must not be inside the evidence directory. A successful
run creates `report.html`, `findings.json`, `findings.csv`, `timeline.csv`,
`coverage.csv`, and `case_manifest.json`.

#### Live acquisition

1. Start the GUI as Administrator.
2. Complete **Case ID** and **Examiner**.
3. Select **Live acquisition (this machine; run elevated)**.
4. Choose a case output directory that does not already exist. The evidence
   field is disabled because artifacts are collected from the machine.
5. Select **Run Analysis** and monitor the progress and log areas.
6. Review **Evidence Coverage** and **Analysis Coverage** before interpreting
   any finding.

Live acquisition is equivalent to `analyze --auto`. It does not perform a
full-disk scan, enable logging, or recover events that were never recorded.

#### Verification and follow-up

- Select **Verify Case Integrity...** to verify the case's recorded SHA-256
  digests; this is equivalent to `exfiltrack verify --case-dir`.
- Use **Open HTML Report** for the investigator-facing narrative.
- Use **Open Output Folder** to inspect or preserve the complete case package.
- Keep the evidence directory, case output directory, and tool version together
  for review and reproducibility.

## Reading the Report

Read the HTML report from top to bottom the first time. It presents the
conclusion first and the supporting evidence below it.

1. **Executive Summary** — Check the number of reconstructed sessions and
   devices, highest confidence, highest score, and integrity verdict.
2. **Evidence Coverage** — Confirm which expected sources were supplied and
   whether collection was complete or partial.
3. **Findings** — Expand a session to see its device ID, UTC boundaries,
   observed/inferred labels, score rules, and file events.
4. **Source artifacts** — Follow each artifact path and parser citation back to
   the evidence package. A citation explains where a signal came from; it does
   not make that signal conclusive by itself.
5. **Chain of Custody** — Confirm the case identity, tool version, input
   digests, output location, and integrity verdict.
6. **Limitations** — Read this section before sharing or acting on a finding.

An observed session boundary comes from a recognized device lifecycle event. An
inferred boundary is a conservative estimate used when the evidence does not
contain a complete insert/remove pair. Treat inferred windows as investigative
leads, not exact connection times. Technical USB identifiers are stronger
grouping keys than friendly names such as “Kingston DataTraveler 3.0 USB
Device,” which are not unique physical identifiers by themselves.

The legacy checklist below is retained as a quick reference:

- Session view: what one reconstructed USB session contains
- Score breakdown: how to read the per-rule contributions
- Confidence levels: what Low, Medium, High, and Confirmed each justify
- Source citations: how to trace a finding back to its artifact
- Manifest: how to confirm the run was forensically sound

## Interpreting Results Responsibly

| Confidence | What it justifies |
| --- | --- |
| Low | Note it. Do not act on it alone. |
| Medium | Worth investigating further. |
| High | Supporting evidence exists. Escalate per your incident-response process. |
| Confirmed | A hash match was found. This is the only level indicating a file was demonstrably present on the destination device. |

A high score is not an accusation. It means several weak signals aligned.

## Troubleshooting

| Message or symptom | Likely cause | Recommended action |
| --- | --- | --- |
| **Evidence directory is required** | Offline mode has no evidence folder. | Select the directory containing the exported artifacts. |
| **Case output directory is inside evidence** | The output path could contaminate evidence. | Choose a separate case directory. |
| **Live acquisition requires elevation** | The GUI was not started as Administrator. | Relaunch it from an elevated terminal. |
| **Case directory already exists** | Live acquisition protects against overwriting a case. | Choose a new directory or use offline mode. |
| **No USB sessions reconstructed** | Lifecycle events were absent or the source was not supplied. | Check **Evidence Coverage**, then confirm the expected EVTX and registry files. |
| **Partial evidence coverage** | A source was missing, empty, denied, or unavailable. | Read the coverage table before treating a negative result as meaningful. |
| **Partial analysis** | An artifact could not be parsed. | Preserve the parser error, inspect the named artifact, and validate the evidence copy. |
| **Integrity verification failed** | A case artifact changed after the manifest was created. | Stop interpretation, preserve the case, and document the discrepancy. |
| GUI actions remain disabled | No completed analysis is available or a run is active. | Wait for completion, then reopen the relevant action. |

If a run fails, preserve the case directory and progress log. Do not edit
evidence files to make a run succeed; correct the acquisition or export process
and create a new case copy.

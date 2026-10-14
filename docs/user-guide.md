# User Guide

**Owner:** Dabarera G. D. M. (Maheesha)
**Tracking issue:** #14 - Final Documentation

Status: outline. `analyze` (manual and `--auto`), `verify`, and `version` are implemented; sections marked _To document_ are still being written.

---

## Who This Guide Is For

Authorized investigators and internal IT security staff without a dedicated forensics unit. It assumes familiarity with Windows and the command line, but not with forensic artifact formats.

## Before You Start

Read [limitations.md](limitations.md). ExfilTrack produces leads, not verdicts.

## Installation

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
4. Click **Run Analysis**. The run executes in the background; progress and any parser warnings appear in the log pane.
5. Review the findings table — device, session start, risk score, confidence, and whether session boundaries were observed or inferred. **Double-click a row** for the confidence reason and the per-rule score breakdown.
6. Use **Open HTML Report** or **Open Output Folder** to reach the full report, and **Verify Case Integrity...** to re-check a case's recorded digests (equivalent to `exfiltrack verify`).

All CLI rules apply unchanged: evidence is opened read-only, output is never written inside the evidence tree, and errors are shown as messages, not tracebacks. The mandated wording — *"ExfilTrack identifies activity consistent with possible USB-based data exfiltration. Temporal correlation alone does not prove that a file was copied."* — is shown at the bottom of the window.

## Reading the Report

_To document, once the HTML report exists:_

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

_To document: common errors and their causes, including malformed artifacts, missing hives, and disabled event channels._

# User Guide

**Owner:** Dabarera G. D. M. (Maheesha)
**Tracking issue:** #14 - Final Documentation

Status: outline. The CLI is not implemented yet, so the commands below describe the planned interface. Fill in real output as features land.

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

## Verifying Integrity

```bash
exfiltrack verify --case-dir ./cases/CASE-001
```

_To document: what a pass and a failure look like, and what to do if digests do not match._

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

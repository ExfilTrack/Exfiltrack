# ExfilTrack

**A Forensically Sound USB Exfiltration Triage Tool**

> ExfilTrack identifies activity consistent with possible USB-based data exfiltration. Temporal correlation alone does not prove that a file was copied.

---

## Project Objective

Modern software companies issue company-managed laptops to developers who work with proprietary source code and confidential client data. An employee with legitimate access can copy that data to a personal USB device before leaving the organization, with no malware, no external attacker, and no network intrusion involved.

Windows passively records substantial evidence of device connections and file activity even when no DLP software is installed. That evidence is scattered across the Registry, Windows Event Logs, shortcut files, and Jump Lists. Investigating a suspected incident currently means extracting and cross-referencing each source by hand, which is slow, error-prone, and inconsistent between investigators.

ExfilTrack automates the collection, normalization, and correlation of these artifacts into a single evidence-backed investigative timeline, and expresses its findings as calibrated risk scores and confidence levels rather than accusations.

## Status

Pre-alpha. The repository is scaffolded and the module layout is fixed, but the pipeline is not yet implemented. Each module carries a docstring describing its planned scope and the issue that tracks it.

## Forensic Soundness Requirements

These requirements are non-negotiable and apply to every contribution:

1. **Evidence is never modified.** All evidence is opened strictly read-only.
2. **Output is isolated.** Analysis output is written to a separate case directory, never inside the evidence directory.
3. **Integrity is proven.** SHA-256 digests are computed before and after analysis to demonstrate no tampering occurred.
4. **Findings are traceable.** Every finding cites its source artifact, and every parser records its name and version.
5. **Timestamps are preserved.** Original timestamps are retained unmodified alongside UTC-normalized values used for correlation.
6. **Errors are explicit.** Malformed evidence produces a reported error rather than being silently skipped.
7. **Runs are reproducible.** The same evidence through the same tool version produces identical results.

## Supported Evidence Sources

| Source | Purpose |
| --- | --- |
| Registry hives (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`) | Identify USB storage devices, vendor/product data, and device identifiers |
| Windows Event Logs (`System.evtx`, `Security.evtx`) | Detect storage-driver mount and unmount events |
| Shortcut files (`.lnk`) | Extract target file paths, sizes, and access/modification timestamps |
| Jump Lists | Identify recently and frequently accessed documents per application |

See [docs/evidence-sources.md](docs/evidence-sources.md) for detail.

## Architecture

ExfilTrack is an offline pipeline. Each stage consumes the previous stage's output only, which keeps parsers independent of scoring logic.

```
+-------------------------------------------------------------+
|                     Offline Evidence Set                    |
|   registry hives | .evtx exports | .lnk files | Jump Lists   |
+----------------------------+--------------------------------+
                             | read-only
                             v
+-------------------------------------------------------------+
| 1. Evidence Intake            src/exfiltrack/evidence/      |
|    discover, classify, open read-only                       |
+----------------------------+--------------------------------+
                             v
+-------------------------------------------------------------+
| 2. Hash Generation & Verification    evidence/hashing.py    |
|    SHA-256 before analysis -> case_manifest.json            |
+----------------------------+--------------------------------+
                             v
+-------------------------------------------------------------+
| 3. Artifact Parsing            src/exfiltrack/parsers/      |
|  registry_parser | evtx_parser | lnk_parser | jumplist      |
+----------------------------+--------------------------------+
                             v
+-------------------------------------------------------------+
| 4. Event Normalization      src/exfiltrack/normalization/   |
|    one event model, timestamps normalized to UTC            |
+----------------------------+--------------------------------+
                             v
+-------------------------------------------------------------+
| 5. USB Session Reconstruction    correlation/sessions.py    |
|    group device events into probable connection sessions    |
+----------------------------+--------------------------------+
                             v
+-------------------------------------------------------------+
| 6. Correlation & Risk Scoring                               |
|    correlation/scoring.py  +  correlation/confidence.py     |
|    explainable rules -> score -> Low/Medium/High/Confirmed  |
+----------------------------+--------------------------------+
                             v
+-------------------------------------------------------------+
| 7. Report Generation          src/exfiltrack/reporting/     |
|    html_report | json_report | csv_report                   |
+----------------------------+--------------------------------+
                             v
+-------------------------------------------------------------+
|      Case Output Directory (separate from evidence)         |
|   report.html | report.json | report.csv | manifest.json    |
+-------------------------------------------------------------+
```

Full detail in [docs/architecture.md](docs/architecture.md).

## Risk Scoring

Rather than treating any single artifact as proof, ExfilTrack combines multiple individually weak signals into an explainable score:

| Indicator | Contribution |
| --- | --- |
| File activity within 30 seconds of USB insertion | +25 |
| File activity within 5 minutes of USB insertion | +15 |
| Sensitive file extension (`.sql`, `.pem`, `.env`, `.zip`) | +15 |
| File located in a protected project directory | +20 |
| Multiple confidential files accessed in one session | +15 |
| Matching file hash found on destination USB | +50 |

Each finding also carries a confidence level: **Low** → **Medium** → **High** → **Confirmed**. `Confirmed` is reached only through a cryptographic hash match between a source file and a file on the destination device, never through score alone. See [docs/scoring-model.md](docs/scoring-model.md).

## Limitations

ExfilTrack is an offline, post-incident artifact-analysis tool. It does not monitor systems in real time, does not intercept network or clipboard traffic, and cannot decrypt password-protected archives. Its conclusions are risk scores and confidence levels, not definitive proof. Read [docs/limitations.md](docs/limitations.md) before relying on any output.

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/ExfilTrack/Exfiltrack.git
cd Exfiltrack

python -m venv .venv
# Windows
.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate

pip install -e ".[dev]"
```

Verify the toolchain:

```bash
pytest
ruff check src/ tests/
black --check src/ tests/
```

## Usage

The CLI is not implemented yet. The planned interface is:

```bash
exfiltrack analyze --evidence ./evidence --case-dir ./cases/CASE-001 --case-id CASE-001
exfiltrack verify  --case-dir ./cases/CASE-001
```

See [docs/user-guide.md](docs/user-guide.md).

## Development Workflow

Branches:

```
main       protected, release-ready only, no direct commits
develop    integration branch, all features merge here first
```

Feature branches are named by owner:

```
feature/milindu-*
feature/thabrew-*
feature/maheesha-*
```

All work flows in one direction:

```
feature branch  ->  develop  ->  main
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(parser): add registry USB parser
feat(correlation): implement session reconstruction
docs(architecture): add system design
test(reporting): add HTML report tests
```

Allowed types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`.

## Contribution Workflow

1. Pick an open issue and assign yourself.
2. Branch from `develop` using your owner prefix.
3. Commit using Conventional Commits.
4. Open a PR into `develop` and fill out the template completely.
5. Request review. **At least one approving review is required.**
6. Merge only after CI passes and review is approved.

Details in [CONTRIBUTING.md](CONTRIBUTING.md).

## Team

| Member | Index | Responsibilities |
| --- | --- | --- |
| **Milindu Weerawarna** (Project Lead) | 230699E | Evidence intake, SHA-256 hashing and manifesting, registry parsing, configuration, architecture documentation, project coordination |
| **Thabrew D. C. L.** | 230631P | EVTX parsing, `.lnk` parsing, Jump List parsing, event normalization, evidence source documentation |
| **Dabarera G. D. M.** (Maheesha) | 230111X | Correlation engine, risk and confidence scoring, report generation, scoring model documentation, user guide |

All members contribute jointly to testing, documentation, and the final demonstration.

## Milestones

| # | Milestone | Scope |
| --- | --- | --- |
| 1 | Artifact Collection Layer | Evidence intake, hashing, all four parsers |
| 2 | Correlation Engine | Normalization, session reconstruction, scoring, confidence |
| 3 | Reporting Layer | HTML, JSON, and CSV report generation |
| 4 | Testing and Evaluation | Integration tests, controlled scenarios, accuracy metrics |
| 5 | Final Release | Documentation, packaging, demonstration |

## Ethical Use

ExfilTrack analyzes artifacts that may include personal file names and USB device history. Its use should be governed by organizational policy and applicable law regarding employee monitoring and data forensics. The tool is designed for authorized investigators working on company-owned equipment as part of a defined incident-response process, not for covert or unauthorized surveillance.

## License

MIT. See [LICENSE](LICENSE).

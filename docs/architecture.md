# Architecture

**Owner:** Milindu Weerawarna
**Tracking issue:** #14 - Final Documentation

Status: outline. Sections are placeholders to be filled as the pipeline is implemented.

---

## 1. Design Goals

- Offline, post-incident analysis only. No live monitoring, no network capture.
- Strict read-only access to evidence.
- Explainable correlation. No black-box scoring.
- Reproducible output for a given evidence set and tool version.

## 2. Pipeline Overview

Seven stages, each consuming only the previous stage's output:

1. Evidence intake
2. Hash generation and verification
3. Artifact parsing
4. Event normalization
5. USB session reconstruction
6. Correlation and risk scoring
7. Report generation

_To document: stage inputs, outputs, and failure behaviour._

## 3. Module Map

| Module | Responsibility | Owner |
| --- | --- | --- |
| `evidence/intake.py` | Discover and classify artifacts, enforce read-only | Milindu |
| `evidence/hashing.py` | SHA-256 digests before and after analysis | Milindu |
| `evidence/manifest.py` | Chain-of-custody record | Milindu |
| `config.py` | Case configuration, scoring weights, thresholds | Milindu |
| `parsers/registry_parser.py` | USB devices from registry hives | Milindu |
| `parsers/evtx_parser.py` | Mount/unmount events from event logs | Thabrew |
| `parsers/lnk_parser.py` | Target paths and timestamps from shortcuts | Thabrew |
| `parsers/jumplist_parser.py` | Per-application file activity | Thabrew |
| `normalization/event_model.py` | Shared event shape | Thabrew |
| `normalization/timestamps.py` | UTC normalization | Thabrew |
| `correlation/sessions.py` | Probable USB connection sessions | Maheesha |
| `correlation/scoring.py` | Rule-based risk score | Maheesha |
| `correlation/confidence.py` | Low / Medium / High / Confirmed | Maheesha |
| `reporting/html_report.py` | Investigator-facing HTML report | Maheesha |
| `reporting/json_report.py` | Machine-readable output | Maheesha |
| `reporting/csv_report.py` | Spreadsheet-friendly output | Maheesha |
| `cli.py` | Command line entry point | Milindu |

## 4. Data Flow

The `NormalizedEvent` model acts as the single, strict contract between the artifact parsers (Stage 3) and the correlation engine (Stages 5-6). Parsers must transform artifact-specific formats (e.g., EVTX XML, LNK binary structures, Windows Registry types) into standard normalized events.

Key constraints:
- All temporal values must be strictly normalized to timezone-aware UTC `datetime` objects with a 0-offset.
- Every event carries mandatory provenance (`source_artifact`, `parser_name`, `parser_version`) establishing a direct chain back to the original evidence.
- The original raw timestamp string is preserved unmodified to allow investigators to verify the conversion.

## 5. Chain of Custody

_To document: manifest contents, when it is written, and how a reviewer verifies a run._

## 6. Forensic Soundness Enforcement

_To document: where each of the seven requirements in the README is enforced in code._

## 7. Reproducibility

Reproducibility guarantees that identical evidence always yields identical correlation and scoring results. Non-determinism is eliminated by:
- **Timestamp Ties:** Real-world artifacts often record multiple events at the exact same sub-second timestamp. The `NormalizedEvent` sorting uses a deterministic multi-field tie-breaker: `(timestamp_utc, event_type, source_artifact, raw_timestamp, device_id, file_path)`. This guarantees stability regardless of parser execution order.
- **Merge Laziness:** Event streams from individual parsers are lazily merged (`heapq.merge`) rather than collected in bulk, preserving the stable order of ties across streams where earlier stream arguments systematically win.

## 8. Error Handling Strategy

_To document: which failures abort a run versus which are recorded as parser errors in the manifest._

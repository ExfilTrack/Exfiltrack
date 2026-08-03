# Task Assignments

**Owner:** Milindu Weerawarna (Project Lead)
**Tracking issue:** #1 - Repository Initialization

This is the working brief for the team. Each section below corresponds to a GitHub issue. Implement your own modules however you judge best, but the **contracts** and **definition of done** are fixed, because other members' code depends on them.

---

## Non-Negotiables for Everyone

These apply to every issue. A PR that violates one will be sent back in review.

1. **Evidence is opened read-only.** No `"w"`, `"a"`, `"r+"`, no in-place edits, no writes anywhere under the evidence directory.
2. **Every parser exposes `PARSER_NAME` and `PARSER_VERSION`.** Bump the version whenever output changes.
3. **Every event and finding carries its provenance:** source artifact path, parser name, parser version.
4. **Malformed input raises an explicit exception.** Never `except: pass`. Never silently skip a record.
5. **Output is deterministic.** Same evidence plus same tool version must produce identical bytes. Sort anything derived from a filesystem walk or a dict.
6. **Timestamps:** keep the original raw value, and store a timezone-aware UTC value beside it.
7. **Language discipline:** "consistent with possible exfiltration". Never "proved", "confirmed theft", or "stole".
8. **Type hints on every public function.** Google-style docstrings on every public module, class, and function.
9. **Tests land in the same PR as the code.** Unit tests for new behaviour, regression test for any bug fix.
10. **No real evidence in git.** Synthetic fixtures only, under `tests/fixtures/`.

Run before every push:

```bash
black src/ tests/
ruff check --fix src/ tests/
mypy src/
pytest
```

---

## The Shared Contract

Everything hinges on one type. Thabrew defines it in issue #7, and **it must land before scoring work begins**.

```
NormalizedEvent
├── event_type        what happened (usb_insert, file_access, ...)
├── timestamp_utc     timezone-aware UTC, used for correlation
├── raw_timestamp     original value, exactly as stored in the artifact
├── source_artifact   path of the evidence file it came from
├── parser_name       which parser produced it
├── parser_version    which version of that parser
├── device            USB device identity, when device-related
├── file_path         target path, when file-related
├── file_size_bytes   when the artifact records it
└── details           artifact-specific extras for the report appendix
```

Parsers produce these. The correlation engine consumes only these. That boundary is what lets the four parsers and the scoring engine be built in parallel.

**Coordination rule:** if you need a field added to `NormalizedEvent`, raise it in the issue thread first. Do not add it locally and merge.

---

## Milindu Weerawarna - Project Lead

Branch prefix: `feature/milindu-*`

### #1 Repository Initialization
Scaffolding, tooling, CI, branch protection, and this brief. Also: keep `docs/architecture.md` current as the design settles, and coordinate the merge order below.

### #2 Evidence Intake and Hash Verification
`evidence/intake.py`, `evidence/hashing.py`, `evidence/manifest.py`, plus `config.py`.

Definition of done:
- Discovers and classifies artifacts by name convention **and** magic bytes, since exported artifacts get renamed during acquisition.
- Streams large files in chunks when hashing. A registry hive must not be loaded whole into memory.
- Computes digests at intake and again after analysis; a mismatch is a hard failure, not a warning.
- Writes `case_manifest.json` into the case directory containing: case id, examiner, tool version, start and end time, config snapshot, parser records, both digest sets, and the integrity verdict.
- Refuses to run if the case directory is inside the evidence directory.
- Reports unreadable or malformed evidence explicitly.

### #3 Registry Artifact Parser
`parsers/registry_parser.py`.

Definition of done:
- Parses `SYSTEM`, `SOFTWARE`, and `NTUSER.DAT` read-only.
- Extracts from `USBSTOR`: device instances, vendor and product strings, serial numbers.
- Extracts drive letter mappings from `MountedDevices`, friendly names from Portable Devices, per-user volume GUIDs from `MountPoints2`.
- Emits `NormalizedEvent` values, never raw registry structures.
- Documents in `docs/evidence-sources.md` what each key proves versus merely suggests.

**You are also the integration point.** Own the merge order, keep `develop` green, and make the call when two members' assumptions conflict.

---

## Thabrew D. C. L.

Branch prefix: `feature/thabrew-*`

**Do #7 first.** Maheesha is blocked until the event model exists.

### #7 Event Normalization Model
`normalization/event_model.py`, `normalization/timestamps.py`.

Definition of done:
- `NormalizedEvent` and `UsbDevice` defined, with a validator that rejects events missing provenance or carrying naive timestamps.
- Converters for Windows FILETIME, packed DOS date/time, and EVTX ISO-8601.
- Deterministic timeline sort with documented tie-breaking.
- Stream merge that combines per-parser output into one timeline.
- Unparseable timestamps raise rather than defaulting. A silently wrong timestamp corrupts every downstream score.

### #4 EVTX Parser
`parsers/evtx_parser.py`.

Definition of done:
- Parses `System.evtx` and `Security.evtx` read-only.
- Detects storage-driver mount and unmount events, and device install and removal events.
- Documents the event IDs and providers used, and what each actually proves.
- **Documents in `docs/limitations.md`** that the relevant channels are often disabled by default, so absence of an event is not absence of the activity.

### #5 LNK Parser
`parsers/lnk_parser.py`.

Definition of done:
- Parses `.lnk` files read-only, with bounds-checked reads. Treat the format as hostile input.
- Extracts target path, size, attributes, and the creation/access/modification timestamps.
- Extracts volume serial number and drive type, so a file can be attributed to a removable volume.
- Never resolves an extracted path against the live filesystem.

### #6 Jump List Parser
`parsers/jumplist_parser.py`.

Definition of done:
- Parses `automaticDestinations-ms` and `customDestinations-ms` read-only.
- Maps AppIDs to known applications, and reports unknown AppIDs rather than dropping them.
- Extracts recent and frequent entries per application.

---

## Dabarera G. D. M. (Maheesha)

Branch prefix: `feature/maheesha-*`

You depend on #7. Until it merges, build against a small hand-written list of `NormalizedEvent` fixtures rather than waiting.

### #8 USB Session Reconstruction
`correlation/sessions.py`.

Definition of done:
- Groups device events into probable connection sessions per device.
- Infers session end when no explicit removal event exists, using the configured idle gap.
- **Flags inferred boundaries distinctly from observed ones.** The report must show which is which.
- Attaches file activity falling inside each session window.

### #9 Risk Scoring Engine
`correlation/scoring.py`.

Implement exactly the weights in `docs/scoring-model.md`:

| Rule | Points |
| --- | --- |
| File activity within 30 seconds of USB insertion | +25 |
| File activity within 5 minutes of USB insertion | +15 |
| Sensitive extension (`.sql`, `.pem`, `.env`, `.zip`) | +15 |
| File in a protected project directory | +20 |
| Multiple confidential files in one session | +15 |
| Matching file hash on the destination USB | +50 |

Definition of done:
- Weights read from `config.py`, never hardcoded, so #13 can measure how weight changes affect the false-positive rate.
- Every contribution records its rule name and the source artifact that triggered it. If you cannot explain a score line by line, the rule is wrong.
- Decide and document whether the 30-second and 5-minute rules stack, and whether repeated hits in one session are capped.

### #10 Confidence Evaluation Model
`correlation/confidence.py`.

Definition of done:
- Assigns Low / Medium / High / Confirmed per the definitions in `docs/scoring-model.md`.
- **`Confirmed` requires a hash match. Score alone can never reach it.** This is the single most important rule in the project; it is what keeps the tool defensible.
- Records why each finding received its level.

### #11 HTML Report Generator
`reporting/html_report.py`, templates in `templates/`.

Definition of done:
- Self-contained HTML, readable by a non-technical manager.
- Per-session findings with a line-by-line score breakdown and confidence level.
- Every finding cites its source artifact.
- Includes the chain-of-custody manifest and the limitations section.
- No wording that overstates what the artifacts prove.

### #12 JSON/CSV Export
`reporting/json_report.py`, `reporting/csv_report.py`.

Definition of done:
- JSON carries the full finding set, manifest, parser versions, and every score contribution.
- CSV gives a flat findings table plus a separate timeline table, with stable column order.
- Byte-identical output across runs on identical evidence.

---

## Shared - All Members

### #13 Integration Testing
End-to-end runs against synthetic fixtures, covering the four proposal scenarios:

1. Normal, non-suspicious USB use, to measure false positives
2. Simulated theft of synthetic confidential files
3. Archive staging and deletion
4. Unrelated recent-file activity with no USB copy, to confirm no false accusations

Also verify: reproducibility (two runs, identical output) and integrity (evidence digests unchanged after a full run).

### #14 Final Documentation
Fill in every `_To document:_` placeholder across `docs/`. Record evaluation results: detection accuracy, false-positive rate, reproducibility. Every member completes their own owned docs.

---

## Merge Order

Dependencies are real. Merging out of order will cause rework.

```
#1  scaffolding                     (done)
#2  evidence intake + config        Milindu    ─┐
#7  event model + timestamps        Thabrew    ─┤ these two unblock everything
                                                │
#3  registry parser    Milindu   ───────────────┤
#4  evtx parser        Thabrew   ───────────────┤ parallel, all need #7
#5  lnk parser         Thabrew   ───────────────┤
#6  jumplist parser    Thabrew   ───────────────┘
                                                │
#8  session reconstruction    Maheesha  ────────┤ needs #7, real data from parsers
#9  risk scoring              Maheesha  ────────┤ needs #8
#10 confidence model          Maheesha  ────────┘ needs #9
                                                │
#11 HTML report      Maheesha   ────────────────┤
#12 JSON/CSV export  Maheesha   ────────────────┘
                                                │
#13 integration testing   All   ────────────────┤
#14 final documentation   All   ────────────────┘
```

## Keeping the Codebase Clean

- **One issue, one branch, one PR.** Do not bundle unrelated changes.
- **Small PRs.** A 200-line PR gets a real review; a 2000-line PR gets a rubber stamp.
- **Do not reformat files you did not otherwise change.** It buries the real diff.
- **Do not edit another member's module to make your code work.** Open an issue or comment on theirs. `CODEOWNERS` will request their review automatically, and that review is required.
- **Rebase on `develop` before opening a PR**, so CI tests what will actually be merged.
- **Leave no commented-out code and no stray debug prints.** Delete it; git remembers.
- **Update the docstring when you change behaviour.** A stale docstring is worse than none.
- **If you discover a design problem, say so in the issue thread.** Do not work around it silently.

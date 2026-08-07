# Scoring Model

**Owner:** Dabarera G. D. M. (Maheesha)
**Tracking issues:** #9, #10

Status: outline. Weights below are the proposal's initial calibration and are expected to change during evaluation (#13).

---

## Design Principle

No single artifact is treated as proof. Multiple individually weak signals are combined into an explainable score. Every point contribution is traceable to a named rule and a source artifact, so a reviewer can reconstruct exactly why a finding scored what it did.

## Score Contributions

| Rule | Indicator | Contribution |
| --- | --- | --- |
| `activity_within_30s` | File activity within 30 seconds of USB insertion | +25 |
| `activity_within_5min` | File activity within 5 minutes of USB insertion | +15 |
| `sensitive_extension` | Sensitive file extension (`.sql`, `.pem`, `.env`, `.zip`) | +15 |
| `protected_directory` | File located in a protected project directory | +20 |
| `multiple_confidential_files` | Multiple confidential files accessed in one session | +15 |
| `destination_hash_match` | Matching file hash found on the destination USB | +50 |

**Stacking.** The 30-second and 5-minute rules do not stack. The 5-minute window contains the 30-second window, so a single file access is scored under exactly one of them — the narrower, higher-value rule wins when both would otherwise match.

**Capping.** Per-file rules (both activity-timing rules, `sensitive_extension`, `protected_directory`, `destination_hash_match`) are not capped within a session: each qualifying file is independent evidence, so a session touching five confidential files scores higher than one touching a single file. `multiple_confidential_files` is the one session-level (not per-file) rule and fires at most once per session, when two or more *distinct* files in that session are confidential (matched by `sensitive_extension` or `protected_directory`).

## Confidence Levels

| Level | Meaning |
| --- | --- |
| **Low** | A USB was connected and a sensitive-looking file was accessed in the same general window |
| **Medium** | Multiple related files were accessed shortly after insertion, consistent with staging behaviour |
| **High** | Supporting audit-log or destination-device evidence is present |
| **Confirmed** | A cryptographic hash match exists between the source file and a file on the destination USB |

`Confirmed` is never reached by score alone. It requires the hash match.

**Thresholds** (`exfiltrack.config.ConfidenceThresholds`, issue #10):

| Level | Rule |
| --- | --- |
| Low | Total score > 0 and none of the conditions below are met |
| Medium | Total score ≥ 40, **or** `multiple_confidential_files` fired |
| High | Total score ≥ 60 **and** both session boundaries are observed (not inferred) |
| Confirmed | `destination_hash_match` fired — independent of score |

40 was chosen because two independent file-level rules alone (for example `sensitive_extension` + `protected_directory` = 15 + 20 = 35) should not read as Medium; three should. 60 was chosen so High requires several rules corroborating each other, e.g. `activity_within_30s` + `protected_directory` + `multiple_confidential_files` (25 + 20 + 15), and additionally requires that the session's insertion *and* removal were both directly observed in the audit log rather than inferred, which is the "supporting audit-log ... evidence" the Confidence Evaluation Model (#10) describes. These are the proposal's initial calibration and, like the rule weights above, are expected to be revisited once #13 measures the false-positive rate against the four controlled scenarios.

## Reporting Language

Output is phrased as "evidence consistent with possible exfiltration", never as a definitive accusation. This distinction matters for technical accuracy and for any downstream HR or legal use of the report.

## Calibration and Evaluation

_To document: false-positive rate measured against the four controlled scenarios in the proposal, and any weight adjustments that resulted._

Controlled scenarios:

1. Normal, non-suspicious USB use
2. Simulated theft of synthetic confidential files
3. Archive staging and deletion
4. Unrelated recent-file activity with no USB copy

## Known Weaknesses

_To document: cases where the model over-scores or under-scores, and the reasoning behind accepting each._

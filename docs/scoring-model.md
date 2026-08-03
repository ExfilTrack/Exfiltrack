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

_To document: whether the 30-second and 5-minute rules are mutually exclusive, and how repeated hits within one session are capped._

## Confidence Levels

| Level | Meaning |
| --- | --- |
| **Low** | A USB was connected and a sensitive-looking file was accessed in the same general window |
| **Medium** | Multiple related files were accessed shortly after insertion, consistent with staging behaviour |
| **High** | Supporting audit-log or destination-device evidence is present |
| **Confirmed** | A cryptographic hash match exists between the source file and a file on the destination USB |

`Confirmed` is never reached by score alone. It requires the hash match.

_To document: exact score thresholds for Low, Medium, and High, and how they were chosen._

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

"""Confidence level evaluation.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #10 - Confidence Evaluation Model

Planned scope:
    - Assign Low / Medium / High / Confirmed to each finding
    - Confirmed requires a cryptographic hash match between the source file
      and a file on the destination device, never score alone
    - Record the reason a finding received its confidence level

Confidence definitions:
    Low       a USB was connected and a sensitive-looking file was accessed
              in the same general window
    Medium    multiple related files were accessed shortly after insertion,
              consistent with staging behaviour
    High      supporting audit log or destination device evidence is present
    Confirmed a hash match exists between the source file and a file on the
              destination USB

Not implemented yet.
"""

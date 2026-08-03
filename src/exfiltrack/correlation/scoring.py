"""Explainable rule-based risk scoring engine.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #9 - Risk Scoring Engine

Planned scope:
    - Apply the calibrated rules documented in docs/scoring-model.md
    - Record every score contribution with its rule name and source artifact
    - Keep the model transparent and configurable, never a black box

Rules to implement:
    file activity within 30 seconds of USB insertion    +25
    file activity within 5 minutes of USB insertion     +15
    sensitive file extension (.sql, .pem, .env, .zip)   +15
    file located in a protected project directory       +20
    multiple confidential files in one session          +15
    matching file hash found on destination USB         +50

Not implemented yet.
"""

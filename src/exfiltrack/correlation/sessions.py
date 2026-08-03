"""USB connection session reconstruction.

Owner: Maheesha (Dabarera G. D. M.)
Related issue: #8 - USB Session Reconstruction

Planned scope:
    - Group device events into probable connection sessions
    - Infer session start and end when explicit removal events are absent
    - Attach file activity that falls inside each session window
    - Flag sessions whose boundaries are inferred rather than observed

Not implemented yet.
"""

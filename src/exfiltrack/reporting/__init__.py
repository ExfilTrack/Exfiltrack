"""Report generation in HTML, JSON, and CSV formats.

Owner: Maheesha (Dabarera G. D. M.)

Reports are written to a case output directory that is always separate from
the evidence directory. Report wording must express findings as activity
*consistent with* possible exfiltration, never as proof of it.
"""

__all__ = ["csv_report", "html_report", "json_report"]

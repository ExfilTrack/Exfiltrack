# Report Templates

Jinja2 templates for the HTML report (issue #11, owner: Maheesha).

Planned files:

```
report.html.j2      top-level report
_session.html.j2    one reconstructed USB session
_finding.html.j2    one finding with its score breakdown
_manifest.html.j2   chain-of-custody section
styles.css          inlined into the output so the report is self-contained
```

## Requirements

- The report must be self-contained. No external CSS, fonts, or scripts, because it will be opened on machines with no network access.
- Every finding cites its source artifact.
- Inferred session boundaries are visually distinct from observed ones.
- The limitations section is included in every report, not linked.
- Escape all values taken from evidence. File paths and device names are untrusted input and must never be rendered as raw HTML.
- Wording expresses activity consistent with possible exfiltration. Never "proof", "confirmed theft", or "stole".

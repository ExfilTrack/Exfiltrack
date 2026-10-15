# Report Templates

The canonical HTML report resources live in
[`src/exfiltrack/reporting/templates/`](../src/exfiltrack/reporting/templates/):

- `report.html.j2` — the Jinja2 report template.
- `styles.css` — inlined into the output so the report is self-contained.

These resources are packaged with `exfiltrack.reporting` for installed wheels.
Edit them there; this directory contains no duplicate templates or stylesheet.
To use custom resources, pass a directory containing both files through the
report renderer's existing `templates_dir` argument.

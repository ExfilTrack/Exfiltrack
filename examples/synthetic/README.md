# Synthetic Examples

Sample case output generated from synthetic evidence, committed as a deliverable (issue #14).

**Synthetic data only.** No real file names, user names, machine names, or device serial numbers.

Planned contents:

```
synthetic/
├── evidence/          synthetic evidence set used to produce the sample
└── case_output/
    ├── report.html
    ├── report.json
    ├── report.csv
    └── case_manifest.json
```

Regenerate with:

```bash
exfiltrack analyze \
  --evidence examples/synthetic/evidence \
  --case-dir examples/synthetic/case_output \
  --case-id SAMPLE-001 \
  --examiner "ExfilTrack Team"
```

Because output is required to be reproducible, regenerating from unchanged evidence with the same tool version should produce no diff. A diff means either the evidence changed or reproducibility has regressed.

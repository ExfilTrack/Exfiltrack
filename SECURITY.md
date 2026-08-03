# Security Policy

## Scope

ExfilTrack is an academic forensic analysis tool. It processes untrusted input by design: registry hives, event logs, shortcut files, and Jump Lists taken from a machine that may have been tampered with.

## Handling Evidence

**Never commit real case evidence to this repository.**

Real evidence may contain personal file names, user account names, USB device serial numbers, and organizational data. The `.gitignore` blocks common evidence extensions, but that is a safety net, not a substitute for care.

Only synthetic fixtures belong in the repository:

```
tests/fixtures/        synthetic evidence for automated tests
examples/synthetic/    synthetic case data for demonstrations
```

If evidence is committed by mistake, do not simply delete it in a follow-up commit. Notify the project lead so the history can be rewritten before the branch is shared.

## Threat Model for the Tool Itself

Because ExfilTrack parses attacker-influenceable binary formats, parser code must assume input is hostile:

- Never trust length or offset fields without bounds checking.
- Never allocate a buffer sized directly by an untrusted field.
- Never resolve a path from an artifact and then read that path from the live filesystem.
- Fail loudly on malformed structures rather than guessing at recovery.
- Never execute, deserialize, or evaluate content extracted from evidence.

## Reporting a Vulnerability

Report security issues affecting ExfilTrack privately to the project lead rather than opening a public issue:

- **Milindu Weerawarna** (Project Lead)

Include a description of the issue, the affected component, and a synthetic reproduction if possible. Do not attach real evidence.

## Ethical Use

ExfilTrack is intended for authorized investigators operating on company-owned equipment as part of a defined incident-response process. Its use is subject to organizational policy and applicable law regarding employee monitoring and data forensics. It is not intended for covert or unauthorized surveillance.

## Output Accuracy

Misrepresenting the tool's findings is itself a safety concern. Any change that causes ExfilTrack to state or imply that a file was proven to be copied, when the underlying artifacts only show temporal correlation, is treated as a defect and must be reported.

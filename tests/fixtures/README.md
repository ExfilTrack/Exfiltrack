# Synthetic Test Fixtures

**Synthetic evidence only. Never commit real case data.**

Real evidence contains personal file names, user account names, and USB device serial numbers. See `SECURITY.md`.

## Layout

```
fixtures/
├── registry/      synthetic SYSTEM, SOFTWARE, NTUSER.DAT hives
├── evtx/          synthetic System.evtx, Security.evtx
├── lnk/           synthetic .lnk files, including malformed cases
├── jumplists/     synthetic automaticDestinations-ms files
└── scenarios/     complete evidence sets for the four integration scenarios
```

## Scenario Fixtures

Issue #13 requires four complete evidence sets:

| Scenario | Purpose | Expected result |
| --- | --- | --- |
| `normal_usage/` | Non-suspicious USB use | No High or Confirmed findings |
| `simulated_theft/` | Confidential files copied after insertion | High findings expected |
| `archive_staging/` | Archive created, moved, then deleted | Medium to High findings |
| `unrelated_activity/` | File access with no USB connected | No findings attributing activity to a device |

## Adding a Fixture

1. Generate it in a disposable Windows VM using only synthetic file names.
2. Confirm no real user names, machine names, or device serials are present.
3. Keep it small. Fixtures are read on every CI run.
4. Document what it contains and what it is meant to prove, in the test that uses it.

Malformed fixtures are valuable: parsers must raise explicit errors rather than skipping records silently.

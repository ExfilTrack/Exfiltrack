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

**Implementation note (#13).** These four scenarios are currently built
programmatically rather than committed as static files here, in
`tests/integration/test_scenarios.py`, using the builders in
`tests/support/synthetic_evtx.py` and `tests/support/synthetic_lnk.py`:

- EVTX evidence is a real file carrying the genuine `ElfFile\0` magic header
  (so intake and classification run for real), with its record content
  supplied through a `monkeypatch` double for the small `python-evtx` surface
  `parse_evtx` touches -- the same technique
  `tests/unit/test_evtx_parser.py` already uses, since `python-evtx` has no
  writer and a real EVTX binary cannot be constructed in code.
- `.lnk` evidence, where used, is a genuinely valid Shell Link binary built
  directly from the MS-SHLLINK layout (`build_lnk_bytes`), parsed for real
  with no mocking.
- Registry and Jump List evidence are **not yet** part of the scenario
  fixtures: a valid `regf` hive cannot be constructed in code either (see
  `tests/unit/test_registry_parser.py`'s docstring), and Jump Lists are only
  exercised via a mocked OLE surface at the unit level so far. Extending the
  scenarios to cover them -- either with real VM-exported hives (see #36) or
  a shared registry double promoted out of `test_registry_parser.py` -- is a
  natural follow-up, not required by #13's Definition of Done, which asks
  for the four *scenarios* to run end to end, not for every artifact type to
  appear in every scenario.

## Adding a Fixture

1. Generate it in a disposable Windows VM using only synthetic file names.
2. Confirm no real user names, machine names, or device serials are present.
3. Keep it small. Fixtures are read on every CI run.
4. Document what it contains and what it is meant to prove, in the test that uses it.

Malformed fixtures are valuable: parsers must raise explicit errors rather than skipping records silently.

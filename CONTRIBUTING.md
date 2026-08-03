# Contributing to ExfilTrack

This is a university software engineering project with three contributors. The rules below keep the history readable and the tool forensically defensible.

## Ground Rules

1. **No direct commits to `main`.** Ever.
2. **No real evidence in the repository.** Only synthetic fixtures under `tests/fixtures/` and `examples/synthetic/`.
3. **Evidence is read-only.** Any code path that opens an evidence file for writing will be rejected in review.
4. **Findings cite sources.** If a finding cannot name the artifact it came from, it does not ship.

## Branch Strategy

```
main       protected. release-ready code only. no direct commits.
develop    integration branch. all feature work merges here first.
```

Feature branches carry the owner's prefix so ownership is visible in the branch list:

```
feature/milindu-<short-description>
feature/thabrew-<short-description>
feature/maheesha-<short-description>
```

Other prefixes:

```
fix/<owner>-<short-description>
chore/<short-description>
docs/<short-description>
```

Work flows in exactly one direction:

```
feature branch  ->  develop  ->  main
```

### Starting Work

```bash
git checkout develop
git pull origin develop
git checkout -b feature/milindu-evidence-intake
```

### Finishing Work

```bash
git push -u origin feature/milindu-evidence-intake
```

Then open a pull request into `develop`.

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/).

```
<type>(<scope>): <subject>
```

Allowed types:

| Type | Use for |
| --- | --- |
| `feat` | A new capability |
| `fix` | A bug fix |
| `docs` | Documentation only |
| `test` | Tests only |
| `refactor` | Restructuring with no behaviour change |
| `chore` | Tooling, config, dependencies |

Suggested scopes: `evidence`, `parser`, `normalization`, `correlation`, `scoring`, `reporting`, `cli`, `config`, `architecture`, `ci`.

Examples:

```
feat(parser): add registry USB parser
feat(correlation): implement session reconstruction
docs(architecture): add system design
test(reporting): add HTML report tests
fix(normalization): correct FILETIME epoch offset
chore(ci): add mypy to lint job
```

Rules for the subject line:

- Imperative mood: "add parser", not "added parser".
- Lowercase first letter, no trailing period.
- Keep it under 72 characters.
- One logical change per commit.

## Pull Request Process

Every PR must:

1. Target `develop` (only release PRs target `main`).
2. Link its issue with `Closes #N`.
3. Fill out every section of the PR template.
4. Pass CI (ruff, black, mypy, pytest).
5. Receive **at least one approving review** from another team member.

Reviewers check for:

- Read-only evidence access
- Provenance on every finding
- Report wording that does not overstate what artifacts prove
- Tests that cover the new behaviour
- Docstrings and relevant `docs/` updates

## Code Standards

- **Python 3.10+**, type hints on all public functions.
- **Line length 100**, enforced by `black` and `ruff`.
- **Google-style docstrings** on every public module, class, and function.
- Every parser exposes `PARSER_NAME` and `PARSER_VERSION` constants.
- Malformed input raises an explicit exception. Never silently skip.
- Output ordering must be deterministic so runs are reproducible.

Before pushing:

```bash
black src/ tests/
ruff check --fix src/ tests/
mypy src/
pytest
```

## Testing

```
tests/unit/          fast, isolated, no filesystem evidence required
tests/integration/   end-to-end pipeline runs against synthetic fixtures
tests/fixtures/      synthetic evidence, safe to commit
```

New features need unit tests. Bug fixes need a regression test that fails before the fix.

## Team Ownership

Ownership is enforced by `.github/CODEOWNERS`. Changes to a file automatically request review from its owner.

| Area | Owner |
| --- | --- |
| `src/exfiltrack/evidence/`, `registry_parser.py`, `config.py`, `docs/architecture.md` | Milindu Weerawarna |
| `evtx_parser.py`, `lnk_parser.py`, `jumplist_parser.py`, `src/exfiltrack/normalization/`, `docs/evidence-sources.md` | Thabrew D. C. L. |
| `src/exfiltrack/correlation/`, `src/exfiltrack/reporting/`, `docs/scoring-model.md`, `docs/user-guide.md` | Dabarera G. D. M. (Maheesha) |
| `tests/`, `docs/limitations.md` | All members |

Touching someone else's area is fine, but their review is required.

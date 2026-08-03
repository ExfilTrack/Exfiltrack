# Scripts

Repository automation. All scripts are idempotent and support `-DryRun`.

## Prerequisites

[GitHub CLI](https://cli.github.com/) installed and authenticated:

```powershell
winget install --id GitHub.cli
gh auth login
```

## `bootstrap_github.ps1`

Creates the label set, the 5 milestones, and all 14 tracking issues from `docs/task-assignments.md`.

```powershell
./scripts/bootstrap_github.ps1 -DryRun   # preview
./scripts/bootstrap_github.ps1           # apply
```

**Before running, update the GitHub usernames at the top of the script:**

```powershell
$UserMilindu  = "Milindu-Weerawarna"
$UserThabrew  = "Thabrew-DCL"
$UserMaheesha = "Maheesha-GDM"
```

Those placeholders also appear in `.github/CODEOWNERS`, which must be updated to match or code owner review requests will silently fail.

Issues are created in order, so they receive numbers #1 through #14 matching `docs/task-assignments.md`. Run this on a repository with no existing issues.

## `setup_branch_protection.ps1`

Applies the branch strategy from `CONTRIBUTING.md`: no direct commits to `main`, one approving review required, CI must pass, stale approvals dismissed.

```powershell
./scripts/setup_branch_protection.ps1 -DryRun
./scripts/setup_branch_protection.ps1
```

Requires admin permission. Branch protection on private repositories requires a paid GitHub plan; on the free plan, use a public repository or rely on team discipline plus CODEOWNERS.

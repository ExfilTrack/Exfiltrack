#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Applies branch protection rules to main and develop.

.DESCRIPTION
    Enforces the branch strategy in CONTRIBUTING.md:
      - No direct commits to main
      - At least one approving review required
      - CI must pass before merge
      - Stale approvals dismissed on new commits

.PREREQUISITES
    1. GitHub CLI installed and authenticated (gh auth login)
    2. Admin permission on the repository
    3. Branch protection requires a public repo or a paid plan for private repos

.EXAMPLE
    ./scripts/setup_branch_protection.ps1
#>

[CmdletBinding()]
param(
    [string]$Repo = "ExfilTrack/Exfiltrack",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI (gh) not found. Install from https://cli.github.com/"
}

function Protect-Branch {
    param(
        [string]$Branch,
        [int]$RequiredReviews,
        [bool]$EnforceAdmins
    )

    $payload = @{
        required_status_checks = @{
            strict   = $true
            contexts = @("Lint", "Test (Python 3.12)")
        }
        enforce_admins                = $EnforceAdmins
        required_pull_request_reviews = @{
            required_approving_review_count = $RequiredReviews
            dismiss_stale_reviews           = $true
            require_code_owner_reviews      = $true
        }
        restrictions        = $null
        allow_force_pushes  = $false
        allow_deletions     = $false
        required_conversation_resolution = $true
    } | ConvertTo-Json -Depth 10

    Write-Host "  -> protecting '$Branch' ($RequiredReviews review(s) required)" -ForegroundColor Cyan

    if ($DryRun) {
        Write-Host $payload -ForegroundColor DarkGray
        return
    }

    $tempFile = New-TemporaryFile
    try {
        Set-Content -LiteralPath $tempFile -Value $payload -Encoding utf8
        $result = & gh api "repos/$Repo/branches/$Branch/protection" `
            -X PUT `
            -H "Accept: application/vnd.github+json" `
            --input $tempFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "     failed: $result" -ForegroundColor Yellow
            Write-Host "     note: private repos need a paid plan for branch protection." -ForegroundColor Yellow
        } else {
            Write-Host "     ok" -ForegroundColor Green
        }
    }
    finally {
        Remove-Item -LiteralPath $tempFile -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "ExfilTrack Branch Protection" -ForegroundColor Green
Write-Host "Repository: $Repo"
if ($DryRun) { Write-Host "Mode: DRY RUN" -ForegroundColor Yellow }
Write-Host ""

# main is strict: admins included, no exceptions
Protect-Branch -Branch "main" -RequiredReviews 1 -EnforceAdmins $true

# develop allows admins to unblock integration when needed
Protect-Branch -Branch "develop" -RequiredReviews 1 -EnforceAdmins $false

Write-Host ""
Write-Host "Also set manually in Settings > General:" -ForegroundColor Green
Write-Host "  - Default branch: develop"
Write-Host "  - Allow squash merging only (keeps history linear)"
Write-Host "  - Automatically delete head branches after merge"
Write-Host ""

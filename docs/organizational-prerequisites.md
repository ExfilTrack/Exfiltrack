# Organizational Prerequisites

**Owner:** Thabrew D. C. L.
**Tracking issue:** #37

Parts 1–5 are maintained separately. This document currently records the
evidence-acquisition verification required by Part 6.

## Part 6

### Verification Script

Save the following script as `verify-evidence-prerequisites.ps1`, then run it
from an elevated PowerShell prompt. Pass every directory whose file access must
be recorded; the script verifies that each directory has a success-auditing
SACL.

```powershell
param(
    [Parameter(Mandatory)]
    [string[]]$TargetDirectories
)

# 1. Verify DriverFrameworks Operational channel is enabled.
$dfChannel = wevtutil gl Microsoft-Windows-DriverFrameworks-UserMode/Operational | Select-String "enabled: true"
if ($dfChannel) { 
    Write-Host "[PASS] DriverFrameworks Operational channel is enabled." -ForegroundColor Green
} else { 
    Write-Host "[FAIL] DriverFrameworks Operational channel is NOT enabled." -ForegroundColor Red
}

# 2. Verify Advanced Audit Policy for File System (Success).
$auditPolicy = auditpol /get /category:"Object Access" | Select-String "File System.*Success"
if ($auditPolicy) { 
    Write-Host "[PASS] File System audit policy is enabled for Success." -ForegroundColor Green
} else { 
    Write-Host "[FAIL] File System audit policy is NOT enabled for Success." -ForegroundColor Red
}

# 3. Verify a success-auditing SACL exists on every monitored directory.
foreach ($directory in $TargetDirectories) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        Write-Host "[FAIL] Target directory does not exist: $directory" -ForegroundColor Red
        continue
    }

    try {
        $auditRules = (Get-Acl -LiteralPath $directory).Audit
        $successRule = $auditRules | Where-Object {
            ($_.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success) -ne 0
        } | Select-Object -First 1

        if ($successRule) {
            Write-Host "[PASS] Success-auditing SACL found: $directory" -ForegroundColor Green
        } else {
            Write-Host "[FAIL] No success-auditing SACL found: $directory" -ForegroundColor Red
        }
    } catch {
        Write-Host "[FAIL] Could not read the SACL for $directory. Run PowerShell as Administrator." -ForegroundColor Red
    }
}

# 4. Verify NoRecentDocsHistory is 0 or absent.
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$noRecentDocs = (Get-ItemProperty -Path $regPath -Name "NoRecentDocsHistory" -ErrorAction SilentlyContinue).NoRecentDocsHistory
if ($null -eq $noRecentDocs -or $noRecentDocs -eq 0) { 
    Write-Host "[PASS] NoRecentDocsHistory is 0 or absent." -ForegroundColor Green
} else { 
    Write-Host "[FAIL] NoRecentDocsHistory is set to $noRecentDocs." -ForegroundColor Red
}

# 5. Verify Start_TrackDocs is 1.
$startTrackDocs = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -ErrorAction SilentlyContinue).Start_TrackDocs
if ($startTrackDocs -eq 1) { 
    Write-Host "[PASS] Start_TrackDocs is 1." -ForegroundColor Green
} else { 
    Write-Host "[FAIL] Start_TrackDocs is NOT 1." -ForegroundColor Red
}
```

For example:

```powershell
.\verify-evidence-prerequisites.ps1 -TargetDirectories "C:\TestData", "D:\SharedFiles"
```

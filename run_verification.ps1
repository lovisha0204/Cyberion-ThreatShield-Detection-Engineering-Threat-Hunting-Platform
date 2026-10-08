<#
.SYNOPSIS
    Cyberion Defense Labs - One-Click Verification Launcher (PowerShell)
.DESCRIPTION
    Executes the master verification script, runs rule validation tests, and outputs compliance status.
#>
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host " CYBERION DEFENSE LABS -- ONE-CLICK VERIFICATION LAUNCHER (PowerShell)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

Set-Location $ScriptDir

$pythonCandidates = @(
    "C:\Users\Hp\AppData\Local\Python\bin\python.exe",
    "python.exe",
    "py.exe"
)

$pythonExe = $null
foreach ($cand in $pythonCandidates) {
    if (Test-Path $cand) {
        $pythonExe = $cand
        break
    }
}

if (-not $pythonExe) {
    $pythonExe = "python"
}

& $pythonExe verify_all.py
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "[+] ALL DELIVERABLES AND INTEGRITY TESTS PASSED SUCCESSFULLY!" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "[!] VERIFICATION FAILED WITH EXIT CODE $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

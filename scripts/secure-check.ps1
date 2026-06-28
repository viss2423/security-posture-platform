# Phase 2: secure-check without make. Run from repo root.
# Usage: .\scripts\secure-check.ps1 [-IncludeDast] [-IncludeKnip]

param(
    [switch]$IncludeDast,
    [switch]$IncludeKnip
)

$ErrorActionPreference = "Continue"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "=== Gitleaks (secrets) ==="
pre-commit run gitleaks --all-files 2>&1

Write-Host "`n=== Semgrep (SAST) ==="
pre-commit run semgrep --all-files 2>&1

Write-Host "`n=== pip-audit (Python deps) ==="
Push-Location services\api
try { pip-audit 2>&1 } catch { Write-Host "  (pip-audit not run or no issues)" }
Pop-Location

Write-Host "`n=== npm audit (frontend) ==="
Push-Location services\frontend
try { npm audit 2>&1 } catch { Write-Host "  (npm audit not run or no issues)" }
Pop-Location

if ($IncludeKnip) {
    Write-Host "`n=== Knip (dead code / unused deps) ==="
    Push-Location services\frontend
    try { npx knip 2>&1 } catch { Write-Host "  (knip not configured or no issues)" }
    Pop-Location
}

if ($IncludeDast) {
    Write-Host "`n=== OWASP ZAP (DAST baseline) ==="
    Write-Host "  Requires Docker + platform running on localhost:3002"
    & "$PSScriptRoot\zap-baseline.ps1" -Target "http://host.docker.internal:3002"
}

Write-Host "`n=== secure-check done ==="

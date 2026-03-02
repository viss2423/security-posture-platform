# Phase 2: secure-check without make. Run from repo root.
# Usage: .\scripts\secure-check.ps1

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

Write-Host "`n=== secure-check done ==="

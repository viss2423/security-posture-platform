# Full repo security scan (gitleaks + semgrep + osv-scanner).
# Run from repo root, or we cd there so hook/manual both work.
# Exits with same code as first failing tool so hooks/CI see failure.
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repoRoot

function ExitIfFailed { if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }

Write-Host "== FULL REPO SECURITY SCAN =="

Write-Host "`n[1/3] Secrets scan (gitleaks)"
gitleaks detect --redact --exit-code 1
ExitIfFailed

Write-Host "`n[2/3] SAST scan (Semgrep, full repo)"
$env:PYTHONUTF8 = "1"
semgrep scan --config p/ci --error --metrics=off .
ExitIfFailed

Write-Host "`n[3/3] Dependency vulnerabilities (OSV-Scanner)"
osv-scanner --recursive .
ExitIfFailed

Write-Host "`n✅ Full repo security scan passed."

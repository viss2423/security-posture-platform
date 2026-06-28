# ZAP baseline scan — runs OWASP ZAP DAST against a running target.
# Usage: .\scripts\zap-baseline.ps1 [-Target http://host.docker.internal:3002] [-ReportDir reports/zap]
# Requires: Docker (ZAP runs in a container; no local install needed).
#
# The baseline scan:
#   - Spiders the target for a few minutes
#   - Runs passive scanning (no active attacks)
#   - Reports alerts grouped by risk level
#   - Exits non-zero on HIGH alerts (CI-friendly)
#
# For a full active scan: use zap-full-scan.py instead (takes 30+ min).

param(
    [string]$Target = "http://host.docker.internal:3002",
    [string]$ReportDir = "reports/zap"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

# --- Prerequisites -------------------------------------------------
$dockerAvailable = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerAvailable) {
    Write-Host "[ZAP] Docker not found. ZAP requires Docker to run (no local install)." -ForegroundColor Red
    Write-Host "       Install: winget install Docker.DockerDesktop" -ForegroundColor Yellow
    exit 1
}

# ZAP moved from Docker Hub to GitHub Container Registry in 2023.
# ghcr.io/zaproxy/zaproxy:stable ships zap-baseline.py and zap-full-scan.py unchanged.
$zapImage = "ghcr.io/zaproxy/zaproxy:stable"

Write-Host "[ZAP] Pulling $zapImage (if not cached)..." -ForegroundColor Cyan
docker pull $zapImage 2>&1 | Out-Null

# --- Output directory ----------------------------------------------
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
# Host paths (for reading results after scan completes).
$reportFile = Join-Path $ReportDir "zap-baseline.html"
$jsonFile   = Join-Path $ReportDir "zap-baseline.json"
# Container paths (zap-baseline.py runs inside /zap/wrk).
$containerReport = "zap-baseline.html"
$containerJson   = "zap-baseline.json"

# --- Run baseline scan ---------------------------------------------
Write-Host "[ZAP] Baseline scan against: $Target" -ForegroundColor Cyan
Write-Host "[ZAP] Report: $reportFile" -ForegroundColor DarkGray
Write-Host "[ZAP] This takes 2–5 minutes..." -ForegroundColor DarkGray

$exitCode = 0

docker run --rm `
    -v "${PWD}/$ReportDir:/zap/wrk:rw" `
    -t $zapImage `
    zap-baseline.py `
        -t "$Target" `
        -r "$containerReport" `
        -J "$containerJson" `
        --auto `

if ($LASTEXITCODE -ne 0) {
    $exitCode = $LASTEXITCODE
}

# --- Summarise results ---------------------------------------------
Write-Host ""

if (Test-Path $jsonFile) {
    try {
        $results = Get-Content $jsonFile -Raw | ConvertFrom-Json
        $byRisk = @{}
        foreach ($site in $results.site) {
            foreach ($alert in $site.alerts) {
                $risk = $alert.riskcode
                # PowerShell: $null + 1 = 1, counts correctly (no null-coalesce needed)
                $byRisk[$risk] = $byRisk[$risk] + 1
            }
        }
        # ZAP risk codes: 0=Informational, 1=Low, 2=Medium, 3=High
        $riskLabels = @{ "0" = "Info"; "1" = "Low"; "2" = "Medium"; "3" = "High" }
        Write-Host "[ZAP] Results:" -ForegroundColor White
        foreach ($risk in @("3", "2", "1", "0")) {
            $count = $byRisk[$risk]
            if ($count) {
                $label = $riskLabels[$risk]
                $color = switch ($risk) {
                    "3" { "Red" }
                    "2" { "Yellow" }
                    "1" { "DarkYellow" }
                    default { "DarkGray" }
                }
                Write-Host "       $label`: $count" -ForegroundColor $color
            }
        }
    } catch {
        Write-Host "[ZAP] Could not parse results JSON." -ForegroundColor Yellow
    }
}

# --- Exit ----------------------------------------------------------
if ($exitCode -ne 0) {
    Write-Host "[ZAP] Scan found HIGH alerts (exit $exitCode)." -ForegroundColor Red
    Write-Host "       Open report: $reportFile" -ForegroundColor DarkGray
} else {
    Write-Host "[ZAP] Baseline scan complete — no HIGH alerts." -ForegroundColor Green
}

exit $exitCode

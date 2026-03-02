# Smoke test for corporate roadmap (Phase 0 + 1 + 2 placeholders).
# Run from repo root: .\scripts\smoke-roadmap.ps1
# Optional: .\scripts\smoke-roadmap.ps1 -Build   to rebuild images (slower).
param([switch]$Build)
$ErrorActionPreference = "Stop"
$repoRoot = $PSScriptRoot | Split-Path -Parent
if (-not (Test-Path (Join-Path $repoRoot "docker-compose.yml"))) {
    throw "Repo root not found (no docker-compose.yml in $repoRoot). Run from security-posture-platform root."
}
Set-Location $repoRoot
if ($Build) {
    Write-Host "Building and starting stack (this can take 1-2 min)..."
    docker compose up -d --build 2>&1
} else {
    Write-Host "Starting stack (no rebuild; use -Build to rebuild)..."
    docker compose up -d 2>&1
}
Write-Host "Waiting 8s for API/Redis..."
Start-Sleep -Seconds 8
Write-Host "Checking API health and X-Request-Id..."
$h = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing
if ($h.StatusCode -ne 200) { throw "API health failed: $($h.StatusCode)" }
if (-not $h.Headers["X-Request-Id"]) { Write-Warning "Missing X-Request-Id" }
Write-Host "Checking Redis..."
docker compose exec redis redis-cli PING
if ($LASTEXITCODE -ne 0) { throw "Redis PING failed" }
Write-Host "Phase 0 + 1 smoke OK"
Write-Host "Starting roadmap profile (deriver, notifier)..."
docker compose --profile roadmap up -d deriver notifier 2>&1
Start-Sleep -Seconds 2
docker logs secplat-deriver --tail 1
docker logs secplat-notifier --tail 1
Write-Host "Phase 2 placeholders OK"
Write-Host "Smoke done."

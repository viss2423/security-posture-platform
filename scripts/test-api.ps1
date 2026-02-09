# Test posture API from PowerShell (no jq required).
# Run: .\scripts\test-api.ps1
# Or from repo root: .\scripts\test-api.ps1

$base = "http://localhost:8000"

# 1. Login, get token
$loginBody = @{ username = "admin"; password = "admin" }
$login = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -Body $loginBody -ContentType "application/x-www-form-urlencoded"
$token = $login.access_token
Write-Host "Token obtained." -ForegroundColor Green

$headers = @{ Authorization = "Bearer $token" }

# 2. Summary (includes down_assets)
Write-Host "`n--- POSTURE SUMMARY ---" -ForegroundColor Cyan
$summary = Invoke-RestMethod -Uri "$base/posture/summary" -Headers $headers
$summary | ConvertTo-Json

# 3. List first item
Write-Host "`n--- FIRST ASSET ---" -ForegroundColor Cyan
$list = Invoke-RestMethod -Uri "$base/posture" -Headers $headers
if ($list.items.Count -gt 0) {
    $list.items[0] | ConvertTo-Json
} else {
    Write-Host "No items."
}

# 4. One asset (use first asset_id if juice-shop not present)
$assetKey = if ($list.items.Count -gt 0) { $list.items[0].asset_key } else { "juice-shop" }
Write-Host "`n--- ASSET DETAIL: $assetKey ---" -ForegroundColor Cyan
try {
    $detail = Invoke-RestMethod -Uri "$base/posture/$assetKey" -Headers $headers
    $detail | ConvertTo-Json
} catch {
    Write-Host $_.Exception.Message
}

# 5. CSV export (raw response)
$csvPath = "posture.csv"
$csvResp = Invoke-WebRequest -Uri "$base/posture?format=csv" -Headers $headers -UseBasicParsing
[System.IO.File]::WriteAllText((Join-Path (Get-Location) $csvPath), $csvResp.Content)
Write-Host "`nCSV saved to $csvPath" -ForegroundColor Green

# 6. Alert send (Slack when down_assets; no-op if SLACK_WEBHOOK_URL not set or no down assets)
Write-Host "`n--- POSTURE ALERT SEND ---" -ForegroundColor Cyan
try {
    $alert = Invoke-RestMethod -Uri "$base/posture/alert/send" -Method Post -Headers $headers
    $alert | ConvertTo-Json
} catch {
    Write-Host $_.Exception.Message
}

param(
    [ValidateSet("compose", "k8s")]
    [string]$Lane = "compose",
    [string]$SecretPath = "",
    [switch]$FollowLogs,
    [string[]]$ComposeLogServices = @("frontend", "api")
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$cutoverScript = Join-Path $PSScriptRoot "runtime-lane-cutover.ps1"
$k8Launcher = Join-Path $PSScriptRoot "start-k8-with-docker-infra.ps1"

function Wait-HttpOk {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [int]$TimeoutSeconds = 240
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            & curl.exe -fsS --max-time 5 $Url *> $null
            if ($LASTEXITCODE -eq 0) {
                return
            }
        } catch {
            Start-Sleep -Seconds 2
            continue
        }
        Start-Sleep -Seconds 2
    }
    throw "Timed out waiting for $Url"
}

if (-not (Test-Path $cutoverScript)) {
    throw "Missing required script: $cutoverScript"
}

Push-Location $repoRoot
try {
    if ($Lane -eq "compose") {
        Write-Output "Switching to Compose lane..."
        & $cutoverScript -To compose -StopOtherLane
        Wait-HttpOk -Url "http://127.0.0.1:8000/health"
        Wait-HttpOk -Url "http://127.0.0.1:8000/ready"
        Wait-HttpOk -Url "http://127.0.0.1:3000"
        Write-Output "Compose lane ready."
        Write-Output "Frontend container URL: http://127.0.0.1:3000"
        Write-Output "Frontend dev URL (after npm run dev): http://127.0.0.1:3000"
        if ($FollowLogs) {
            Write-Output "Streaming logs (Ctrl+C to stop log streaming; containers keep running)..."
            docker compose logs -f --tail 120 $ComposeLogServices
        }
        exit 0
    }

    if (-not (Test-Path $k8Launcher)) {
        throw "Missing required script: $k8Launcher"
    }

    Write-Output "Switching to Kubernetes lane..."
    if ($SecretPath) {
        & $k8Launcher -SecretPath $SecretPath
    } else {
        & $k8Launcher
    }
    Write-Output "Kubernetes lane ready."
} finally {
    Pop-Location
}

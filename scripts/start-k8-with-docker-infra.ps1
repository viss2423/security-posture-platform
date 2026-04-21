param(
    [string]$SecretPath = "",
    [switch]$SkipCutover
)

$ErrorActionPreference = "Stop"

function Require-Command {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

function Wait-ForDockerDaemon {
    param(
        [int]$TimeoutSeconds = 90
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            docker info | Out-Null
            if ($LASTEXITCODE -eq 0) {
                return
            }
        } catch {
        }
        Start-Sleep -Seconds 2
    }
    throw "Docker Desktop is not running. Start Docker Desktop and wait until the engine is healthy, then rerun this script."
}

function Wait-ForKubernetesCluster {
    param(
        [int]$TimeoutSeconds = 180
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            kubectl cluster-info | Out-Null
            if ($LASTEXITCODE -eq 0) {
                return
            }
        } catch {
        }
        Start-Sleep -Seconds 3
    }
    throw "Kubernetes is not reachable from the current kubectl context. In Docker Desktop, enable Kubernetes and wait until it shows as running, then rerun this script."
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$overlayDir = Join-Path $repoRoot "infra/k8s/overlays/docker-desktop"
$defaultSecret = Join-Path $overlayDir "secret.local.yaml"
$exampleSecret = Join-Path $overlayDir "secret.local.example.yaml"
$cutoverScript = Join-Path $PSScriptRoot "runtime-lane-cutover.ps1"

Require-Command -Name "docker"
Require-Command -Name "kubectl"
Wait-ForDockerDaemon

if (-not (Test-Path $cutoverScript)) {
    throw "Missing required script: $cutoverScript"
}

$secretToApply = ""
if ($SecretPath) {
    $secretToApply = Resolve-Path $SecretPath
} elseif (Test-Path $defaultSecret) {
    $secretToApply = Resolve-Path $defaultSecret
} elseif (Test-Path $exampleSecret) {
    $secretToApply = Resolve-Path $exampleSecret
    Write-Warning "Using example secret file. Create infra/k8s/overlays/docker-desktop/secret.local.yaml for real credentials."
} else {
    throw "No secret file found. Expected one of: $defaultSecret or $exampleSecret"
}

Push-Location $repoRoot
try {
    Write-Output "Starting Docker infra services..."
    docker compose up -d postgres redis opensearch verify-web juiceshop | Out-Null

    Write-Output "Waiting for Kubernetes API..."
    Wait-ForKubernetesCluster

    Write-Output "Applying namespace and Kubernetes overlay..."
    kubectl apply -f infra/k8s/namespace.yaml | Out-Null
    kubectl -n secplat apply -f $secretToApply | Out-Null
    kubectl kustomize infra/k8s/overlays/docker-desktop --load-restrictor LoadRestrictionsNone | kubectl apply -f - | Out-Null

    if (-not $SkipCutover) {
        Write-Output "Switching to Kubernetes app lane..."
        & $cutoverScript -To k8s -StopOtherLane
    } else {
        Write-Output "SkipCutover enabled: infra and manifests applied, app-lane switch skipped."
    }

    Write-Output "Done. Current Kubernetes workloads:"
    kubectl -n secplat get deploy,cronjob
} finally {
    Pop-Location
}

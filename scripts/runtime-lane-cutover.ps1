param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("compose", "k8s")]
    [string]$To,

    [switch]$StopOtherLane,
    [switch]$PreflightOnly
)

$ErrorActionPreference = "Stop"

$composeAppServices = @(
    "api",
    "frontend",
    "ingestion",
    "worker-web",
    "scanner",
    "web",
    "grafana",
    "deriver",
    "notifier",
    "correlator"
)

$k8Namespace = "secplat"
$k8Deployments = @(
    "secplat-api",
    "secplat-worker-web",
    "secplat-deriver",
    "secplat-notifier",
    "secplat-correlator"
)
$k8CronJobs = @(
    "secplat-ingestion-health",
    "secplat-report-snapshot"
)
$k8ReplicaTarget = @{
    "secplat-api" = 1
    "secplat-worker-web" = 1
    "secplat-deriver" = 1
    "secplat-notifier" = 1
    "secplat-correlator" = 1
}

function Get-ComposeActiveServices {
    $running = @()
    try {
        $running = @(docker compose ps --services --filter status=running 2>$null)
    } catch {
        return @()
    }
    return @($running | Where-Object { $composeAppServices -contains $_ } | Sort-Object -Unique)
}

function Get-K8ActiveDeployments {
    $active = @()
    foreach ($name in $k8Deployments) {
        try {
            $value = kubectl -n $k8Namespace get deploy $name -o jsonpath='{.status.availableReplicas}' 2>$null
        } catch {
            continue
        }
        $replicas = 0
        if ([int]::TryParse("$value", [ref]$replicas) -and $replicas -gt 0) {
            $active += "$name($replicas)"
        }
    }
    return $active
}

function Get-K8ActiveCronJobs {
    $active = @()
    foreach ($name in $k8CronJobs) {
        try {
            $suspend = kubectl -n $k8Namespace get cronjob $name -o jsonpath='{.spec.suspend}' 2>$null
        } catch {
            continue
        }
        if ("$suspend" -ne "true") {
            $active += $name
        }
    }
    return $active
}

function Stop-ComposeLane {
    docker compose stop $composeAppServices | Out-Null
}

function Stop-K8Lane {
    foreach ($name in $k8Deployments) {
        kubectl -n $k8Namespace scale deployment $name --replicas=0 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to scale deployment $name to 0"
        }
    }
    Set-K8CronJobsSuspend -Suspend $true
}

function Start-ComposeLane {
    docker compose up -d --build | Out-Null
}

function Start-K8Lane {
    foreach ($name in $k8Deployments) {
        if (-not $k8ReplicaTarget.ContainsKey($name)) {
            continue
        }
        $replicas = [int]$k8ReplicaTarget[$name]
        kubectl -n $k8Namespace scale deployment $name --replicas=$replicas | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to scale deployment $name to $replicas"
        }
    }
    kubectl -n $k8Namespace rollout status deployment/secplat-api --timeout=180s | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Timed out waiting for secplat-api rollout before unsuspending CronJobs"
    }
    Set-K8CronJobsSuspend -Suspend $false
}

function Set-K8CronJobsSuspend {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Suspend
    )

    $suspendJson = if ($Suspend) { '{"spec":{"suspend":true}}' } else { '{"spec":{"suspend":false}}' }
    $patchFile = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllText($patchFile, $suspendJson, [System.Text.Encoding]::ASCII)
    foreach ($name in $k8CronJobs) {
        try {
            kubectl -n $k8Namespace get cronjob $name | Out-Null
        } catch {
            continue
        }
        kubectl -n $k8Namespace patch cronjob $name --type merge --patch-file $patchFile | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Remove-Item -Force $patchFile -ErrorAction SilentlyContinue
            throw "Failed to set suspend=$Suspend for cronjob $name"
        }
    }
    Remove-Item -Force $patchFile -ErrorAction SilentlyContinue
}

if ($To -eq "compose") {
    $oppositeDeployments = Get-K8ActiveDeployments
    $oppositeCronJobs = Get-K8ActiveCronJobs
    if ((($oppositeDeployments.Count -gt 0) -or ($oppositeCronJobs.Count -gt 0)) -and -not $StopOtherLane) {
        $details = @()
        if ($oppositeDeployments.Count -gt 0) {
            $details += "deployments: $($oppositeDeployments -join ', ')"
        }
        if ($oppositeCronJobs.Count -gt 0) {
            $details += "cronjobs: $($oppositeCronJobs -join ', ')"
        }
        Write-Error "Preflight failed: active Kubernetes lane detected ($($details -join '; ')). Use -StopOtherLane to continue."
    }
    if ($StopOtherLane) {
        Stop-K8Lane
    }
    if ($PreflightOnly) {
        Write-Output "Preflight passed for compose lane."
        exit 0
    }
    Start-ComposeLane
    Write-Output "Compose lane started."
    exit 0
}

$oppositeCompose = Get-ComposeActiveServices
if ($oppositeCompose.Count -gt 0 -and -not $StopOtherLane) {
    Write-Error "Preflight failed: active Compose lane detected ($($oppositeCompose -join ', ')). Use -StopOtherLane to continue."
}
if ($StopOtherLane) {
    Stop-ComposeLane
}
if ($PreflightOnly) {
    Write-Output "Preflight passed for k8s lane."
    exit 0
}
Start-K8Lane
Write-Output "Kubernetes lane resumed."

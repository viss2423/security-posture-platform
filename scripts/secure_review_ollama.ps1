# Security review: collect findings + staged diff, send to Ollama.
# Run from repo root. Usage: .\scripts\secure_review_ollama.ps1 [model] [-KeepPrompt] [-PromptOnly]
# -PromptOnly: save prompt and exit (no wait). Then: ollama run <model> and paste the prompt file.
# Requires: Ollama installed, model pulled (e.g. ollama run codellama).

param([string]$Model = "codellama", [switch]$KeepPrompt, [switch]$PromptOnly)

$ErrorActionPreference = "Continue"
# Use UTF-8 so capture doesn't trigger charmap errors (semgrep/gitleaks on Windows).
$OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$root = git rev-parse --show-toplevel 2>$null
if ($root) { Set-Location $root }

$out = Join-Path $env:TEMP "secure_review_$PID"
New-Item -ItemType Directory -Force -Path $out | Out-Null

try {
  Write-Host "Collecting findings and staged diff..."

  pre-commit run gitleaks --all-files 2>&1 | Out-File -FilePath "$out\gitleaks.txt" -Encoding utf8

  # On Windows, pre-commit semgrep often fails (broken venv path). Prefer direct semgrep if available.
  $semgrepCmd = Get-Command semgrep -ErrorAction SilentlyContinue
  if ($semgrepCmd) {
    $env:PYTHONIOENCODING = "utf-8"
    $env:PYTHONUTF8 = "1"
    & semgrep scan --config auto --error --disable-version-check --skip-unknown-extensions . 2>&1 | Out-File -FilePath "$out\semgrep.txt" -Encoding utf8
  } else {
    pre-commit run semgrep --all-files 2>&1 | Out-File -FilePath "$out\semgrep.txt" -Encoding utf8
  }

  git diff --staged 2>$null | Out-File -FilePath "$out\staged.diff" -Encoding utf8

  $gitleaks = Get-Content "$out\gitleaks.txt" -Raw -Encoding utf8 -ErrorAction SilentlyContinue; if (-not $gitleaks) { $gitleaks = "(none)" }
  $semgrep = Get-Content "$out\semgrep.txt" -Raw -Encoding utf8 -ErrorAction SilentlyContinue; if (-not $semgrep) { $semgrep = "(none)" }
  $staged = Get-Content "$out\staged.diff" -Raw -Encoding utf8 -ErrorAction SilentlyContinue; if (-not $staged) { $staged = "(no staged changes)" }

  $prompt = @"
You are a security-focused code reviewer. Below are: (1) secret-scan output, (2) SAST output, (3) the staged git diff. If Gitleaks says "Passed", there are no secret findings. For each real finding, briefly explain the risk and suggest a concrete fix. Keep answers concise.

--- Gitleaks (secrets) ---
$gitleaks

--- Semgrep (SAST) ---
$semgrep

--- Staged diff ---
$staged
"@
  $prompt | Out-File -FilePath "$out\prompt.txt" -Encoding utf8 -NoNewline

  $ollamaExe = $null
  $ollama = Get-Command ollama -ErrorAction SilentlyContinue
  if ($ollama) {
    $ollamaExe = $ollama.Source
  } else {
    $tryPaths = @(
      "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe",
      "$env:ProgramFiles\Ollama\ollama.exe",
      "${env:ProgramFiles(x86)}\Ollama\ollama.exe"
    )
    foreach ($p in $tryPaths) {
      if (Test-Path -LiteralPath $p) { $ollamaExe = $p; break }
    }
  }

  if ($PromptOnly) {
    Write-Host "Prompt saved to: $out\prompt.txt"
    if ($ollamaExe) {
      Write-Host "Pipe to Ollama: Get-Content '$out\prompt.txt' -Raw | & '$ollamaExe' run $Model"
    } else {
      Write-Host "Run: ollama run $Model , then paste the file contents"
    }
    return
  }

  if (-not $ollamaExe) {
    Write-Host "Ollama not found. Install from https://ollama.com and pull a model (e.g. ollama run codellama)."
    Write-Host "Prompt saved to: $out\prompt.txt"
    exit 1
  }

  Write-Host "Sending to Ollama (model: $Model)... (may take 1-3 min for large prompts)"
  if ($KeepPrompt) { Write-Host "Prompt saved to: $out\prompt.txt | Pipe: Get-Content '$out\prompt.txt' -Raw | & '$ollamaExe' run $Model" }
  Get-Content "$out\prompt.txt" -Raw -Encoding utf8 | & $ollamaExe run $Model
} finally {
  if (-not $KeepPrompt -and -not $PromptOnly) { Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue }
}

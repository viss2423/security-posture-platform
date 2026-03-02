# Overwrites the commit message file (arg 1) with a single line. Used as GIT_EDITOR to strip co-author.
param([string]$MessageFile = $args[0])
$msg = "Corporate roadmap Phase 1-3.2: Redis queue, deriver, notifier, correlator, maintenance and suppression"
if ($MessageFile -and (Test-Path $MessageFile)) {
  [System.IO.File]::WriteAllText($MessageFile, $msg + "`n")
}
exit 0

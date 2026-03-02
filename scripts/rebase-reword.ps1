# Replaces "pick" with "reword" in the rebase todo file (arg 1). Used as GIT_SEQUENCE_EDITOR.
param([string]$TodoFile = $args[0])
if ($TodoFile -and (Test-Path $TodoFile)) {
  (Get-Content $TodoFile -Raw) -replace '^pick ', 'reword ' | Set-Content $TodoFile -NoNewline
}
exit 0

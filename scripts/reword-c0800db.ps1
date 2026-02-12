# GIT_SEQUENCE_EDITOR: change "pick c0800db" to "reword c0800db" so we edit that commit's message.
param([string]$TodoFile = $args[0])
if ($TodoFile -and (Test-Path $TodoFile)) {
  (Get-Content $TodoFile) -replace '^pick (c0800db\s)', 'reword $1' | Set-Content $TodoFile
}
exit 0

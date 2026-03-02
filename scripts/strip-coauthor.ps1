# Used as GIT_EDITOR during rebase: removes "Co-authored-by: Cursor..." from commit message file.
# Git passes the message file path as first argument.
param([string]$MessageFile = $args[0])
if ($MessageFile -and (Test-Path $MessageFile)) {
  $content = Get-Content $MessageFile -Raw
  $newContent = $content -replace '(?m)^Co-authored-by:\s*Cursor\s*<[^>]+>\s*[\r\n]*', ''
  [System.IO.File]::WriteAllText($MessageFile, $newContent.TrimEnd() + "`n")
}
exit 0

#!/usr/bin/env bash
# Security review: collect findings + staged diff, send to Ollama for explanation.
# Run from repo root. Usage: scripts/secure_review_ollama.sh [model]
# Requires: Ollama installed, model pulled (e.g. ollama run codellama).

set -e
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"
MODEL="${1:-codellama}"
TMPDIR="${TMPDIR:-/tmp}"
OUT="$TMPDIR/secure_review_$$"
mkdir -p "$OUT"
trap 'rm -rf "$OUT"' EXIT

echo "Collecting findings and staged diff..."

# Scanners (capture output; non-zero exit is ok)
pre-commit run gitleaks --all-files 2>&1 > "$OUT/gitleaks.txt" || true
pre-commit run semgrep --all-files 2>&1 > "$OUT/semgrep.txt" || true
git diff --staged > "$OUT/staged.diff" 2>/dev/null || true

# Build prompt
{
  echo "You are a security-focused code reviewer. Below are: (1) secret-scan findings, (2) SAST findings, (3) the staged git diff. For each finding, briefly explain the risk and suggest a concrete fix. Keep answers concise."
  echo ""
  echo "--- Gitleaks (secrets) ---"
  cat "$OUT/gitleaks.txt" 2>/dev/null || echo "(none)"
  echo ""
  echo "--- Semgrep (SAST) ---"
  cat "$OUT/semgrep.txt" 2>/dev/null || echo "(none)"
  echo ""
  echo "--- Staged diff ---"
  cat "$OUT/staged.diff" 2>/dev/null || echo "(no staged changes)"
} > "$OUT/prompt.txt"

if ! command -v ollama &>/dev/null; then
  echo "Ollama not found. Install from https://ollama.com and pull a model (e.g. ollama run codellama)."
  echo "Prompt saved to: $OUT/prompt.txt"
  exit 1
fi

echo "Sending to Ollama (model: $MODEL)..."
cat "$OUT/prompt.txt" | ollama run "$MODEL"

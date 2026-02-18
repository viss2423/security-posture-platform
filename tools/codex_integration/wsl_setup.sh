#!/usr/bin/env bash
# WSL setup helper: prepares a Python venv, installs dependencies, and makes `bin/codex` executable.
# Run this inside WSL from the repo root: bash tools/codex_integration/wsl_setup.sh

set -euo pipefail

echo "WSL Codex setup: starting"

# Ensure python3 and venv available
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python3 not found. Install it (Ubuntu): sudo apt update && sudo apt install -y python3 python3-venv python3-pip" >&2
  exit 1
fi

REPO_ROOT="$(pwd)"

echo "Creating venv at $REPO_ROOT/.venv (if missing)"
if [ ! -d "$REPO_ROOT/.venv" ]; then
  python3 -m venv .venv
fi

echo "Activating venv and installing requirements"
. .venv/bin/activate
pip install --upgrade pip
pip install -r tools/codex_integration/requirements.txt

echo "Making bin/codex executable"
chmod +x "$REPO_ROOT/bin/codex"

echo "Optionally add the repo 'bin' directory to your PATH for this user."
echo "Appending PATH update to ~/.profile (will take effect on next login)."
grep -qxF "# add repo codex bin" ~/.profile 2>/dev/null || cat >> ~/.profile <<'EOF'
# add repo codex bin
if [ -d "${PWD}/bin" ]; then
  export PATH="${PWD}/bin:$PATH"
fi
EOF

echo
echo "Done. To use in this session:"
echo "  source .venv/bin/activate" 
echo "  export OPENAI_API_KEY='sk-...'  # do not commit this"
echo "  bin/codex --prompt \"Write a Python function that reverses a string\""

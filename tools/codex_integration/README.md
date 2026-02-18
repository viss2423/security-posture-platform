# Codex integration helper

This folder contains a minimal integration to call OpenAI Codex/completion models from this repository.

Quick start

- Install dependencies (prefer a venv):

```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\Activate on Windows PowerShell
pip install -r tools/codex_integration/requirements.txt
```

- Set your API key (example):

```bash
export OPENAI_API_KEY=sk-...    # on Windows PowerShell: $env:OPENAI_API_KEY = 'sk-...'
```

- Run the helper:

```bash
python scripts/codex_client.py --prompt "Write a Python function that checks whether a string is a palindrome"
```

Notes
- The script uses the `openai` Python package and the Completion endpoint (Codex-capable models). Configure `OPENAI_MODEL` in your environment to override the default.
- Keep your API key secret and do not commit it.

IDE / Windows PowerShell setup

- Do NOT paste API keys into repository files. Instead set the environment variable in your PowerShell session before launching VS Code or running tasks:

```powershell
# Set for the current session
$env:OPENAI_API_KEY = 'sk-...'
# Optionally set model
$env:OPENAI_MODEL = 'code-davinci-002'
```

- You can also set the environment variable permanently via Windows System settings or a credential manager.

- This repo includes a sample VS Code launch configuration and task that reference `OPENAI_API_KEY` from your environment. Launch the configuration `Run Codex helper: prompt input` from the Run view, or run the task `Run Codex helper (ask)` from the Command Palette (type `Tasks: Run Task`).

Local `.env` file option

- You can store your key in a local file copied from `.env.local.example`:

```powershell
Copy-Item .env.local.example .env.local
# then edit .env.local and paste your key into OPENAI_API_KEY
```

- The helper will automatically load `.env.local` (or `.env`) if present, or you can pass `--env-file path/to/file` to `scripts/codex_client.py`.

Security reminder

- Never commit `.env.local` or your API key. `.env*` is ignored by the repo's `.gitignore`.

WSL (recommended for Windows users)

This repository includes a small POSIX wrapper and a WSL setup helper so you can run Codex from VS Code using Remote - WSL.

1) In Windows install the VS Code extension `Remote - WSL` and open your distro.
2) In VS Code: Ctrl+Shift+P → `WSL: Open Folder` → choose this repository folder.
3) In the WSL integrated terminal run the setup script:

```bash
bash tools/codex_integration/wsl_setup.sh
```

The script will:
- create/activate a `.venv` and install `tools/codex_integration/requirements.txt`
- make `bin/codex` executable
- offer to add the repo `bin` directory to your `~/.profile` so `codex` is on your PATH

After running the script, in the WSL terminal you can do:

```bash
# session-only
source .venv/bin/activate
export OPENAI_API_KEY='sk-...'   # do NOT commit
codex --prompt "Write a Python function that reverses a string"
```

If you prefer a local env file instead of session variables, copy `.env.local.example` to `.env.local` and paste your key there. The wrapper will source `.env.local` if present.

Security reminder: never commit API keys or paste them into public places. Use session-only env vars or a secret manager for persistence.



# Security Workflow Implementation Plan

**Goal:** Fast local checks on commit, heavy checks on push/PR, optional AI review, CI as the gate. All free, reproducible via pre-commit, professional.

**Repo structure (confirmed):**
- **Python:** `services/api/` (FastAPI), `services/worker-web/` (worker)
- **Node:** `services/frontend/` (Next.js), root `package.json` (orchestration only)
- **Other:** `scripts/`, `infra/` — no security tooling there today; no `.github/` yet

---

## Phase 1 — Pre-commit (commit-time, fast)

**Purpose:** Every clone gets the same hooks; one command to install. Only fast checks so commits don’t feel slow.

### 1.1 Add `.pre-commit-config.yaml` at repo root

**Hooks (in order):**
1. **gitleaks** — secrets in repo (no config needed for default).
2. **semgrep** — `--config=auto`, `--error`; restrict to `\.(py|js|ts|tsx)$` so we don’t scan infra/random files.
3. **ruff** (lint + format) — Python in `services/api/` and `services/worker-web/`. Use `ruff check` + `ruff format`; scope via `files: \.(py)$` and pass `--config` if we put config under `services/api/` or root.
4. **eslint** — frontend only; `files: \.(js|ts|tsx)$`, run from repo root with `cwd: services/frontend` so it uses that package’s config.

**Details to decide:**
- **Semgrep:** Run on **staged files only** — pre-commit runs on staged by default, so we’re good as long as we don’t add `--no-staging` or run extra commands that pull in whole tree.
- **Ruff:** Single config at root (e.g. `pyproject.toml` or `ruff.toml`) that applies to both `services/api` and `services/worker-web`, or one config per service. Recommendation: one root `ruff.toml` or root `pyproject.toml` with `[tool.ruff]` so pre-commit stays simple.
- **ESLint:** Ensure `services/frontend` has a working ESLint config (Next.js often has one); pre-commit hook `cwd: services/frontend` and `files` at root so only changed frontend files are passed.

**Deliverable:** `.pre-commit-config.yaml` committed; README or RUN-WINDOWS.md step: `pip install pre-commit && pre-commit install`.

### 1.2 Ruff config (if not already)

- Add `[tool.ruff]` and `[tool.ruff.format]` to root or to `services/api/pyproject.toml` and symlink/copy for worker, or one root config. Pre-commit will use it.

### 1.3 ESLint

- Confirm `services/frontend` has `eslint` and a config; add to `devDependencies` if missing. Pre-commit hook runs in `services/frontend` so it uses that config.

**Exit criteria:** From repo root, `pre-commit run --all-files` passes (or only known exceptions). New clones run `pre-commit install` and get the same behavior.

---

## Phase 2 — Makefile (on-demand + optional heavier local checks)

**Purpose:** 
- `make secure-check` — run scanners only (no AI); fast gate.
- `make secure-review` — scanners + Ollama explanation (optional, not blocking commit).

Nothing in the Makefile should block `git commit`; pre-commit does that. Makefile is for “when I want to check” and “when I want AI explanation”.

### 2.1 Create `Makefile` at repo root

**Targets:**

| Target | What it runs | When to use |
|--------|----------------|-------------|
| `secure-check` | gitleaks + semgrep (e.g. staged or whole tree, same as pre-commit) + optionally pip-audit (api) + npm audit (frontend) | Before push or when you want a fuller local check |
| `secure-review` | `secure-check` then script that: takes only **new** findings + **staged diff** + line snippets, calls Ollama, prints explanation | On demand when you want AI help |
| (optional) `lint` / `format` | ruff, eslint | Convenience; pre-commit already does these on commit |

**Implementation notes:**
- `secure-check` can call the same tools as pre-commit (gitleaks, semgrep) plus:
  - `pip-audit` in `services/api/` (and optionally `services/worker-web/` if it has its own deps).
  - `npm audit` in `services/frontend/`.
- Keep `secure-review` as a wrapper that:
  1. Runs `secure-check` (or at least gitleaks + semgrep) and captures output.
  2. Feeds a **curated** input to Ollama: only new findings, staged diff, and relevant line ranges (from Semgrep JSON if available).
  3. Does **not** block commit; it’s optional.

**Deliverable:** Root `Makefile` with `secure-check` and `secure-review`; both work on Windows (use `make` from Git Bash/WSL or document that Windows users run the underlying commands/scripts).

### 2.2 Script: `scripts/secure_review_ollama.sh` (or `.ps1` for Windows)

**Responsibilities:**
- Run gitleaks + semgrep (or consume their output from `make secure-check`).
- Reduce to **new findings only** (e.g. from current run; optional: compare to baseline).
- Get **staged diff** only: `git diff --staged`.
- For Semgrep: use `--json` and pass file:line snippets to the prompt.
- Build a short, structured prompt (findings + snippets + “explain and suggest fixes”).
- Call Ollama (e.g. `ollama run <model>`) with that prompt; stream or print response.

**Deliverable:** Script that works from repo root; `make secure-review` invokes it. Prefer one script that works on both Unix and Windows (e.g. Bash in Git Bash) or add `scripts/secure_review_ollama.ps1` and Makefile targets that call the right one.

---

## Phase 3 — CI (GitHub Actions): the real gate

**Purpose:** Branch protection requires these jobs to pass. This is the “permanent enforcement” layer.

### 3.1 Create `.github/workflows/security.yml`

**Jobs (can be one workflow or split):**

1. **codeql** (CodeQL Analysis)
   - Language: `python` and `javascript-typescript` (or split into two jobs).
   - Paths: `services/api`, `services/worker-web` for Python; `services/frontend` for JS/TS. Use `paths` filter so only relevant changes trigger.

2. **secrets**
   - gitleaks (e.g. `gitleaks/gitleaks-action` or run binary). Run on full repo or `${{ github.sha }}`.

3. **sast**
   - Semgrep with `--config=auto --error`; same file extensions as pre-commit. Optionally upload SARIF.

4. **deps**
   - **Python:** `pip-audit` in `services/api` (and worker if it has requirements).
   - **Node:** `npm audit` in `services/frontend` (and root if you add root deps later).
   - **Optional:** `osv-scanner` for repo-wide dependency scan (single tool for both ecosystems).

5. **container / infra** (optional but recommended)
   - Trivy: scan Dockerfiles and/or built images. Paths: e.g. `services/*/Dockerfile`, `infra/**`.

6. **tests**
   - Python: `pytest` in `services/api` (and `services/worker-web` if it has tests).
   - Frontend: `npm run build` and optionally `npm test` in `services/frontend`.

**Conventions:**
- Use `actions/checkout` and set up Python/Node in matrix or separate jobs.
- Cache pip and npm to speed runs.
- Fail the workflow on any failing step (secrets, SAST, deps, tests). CodeQL can be “best effort” or required depending on policy.

**Deliverable:** `.github/workflows/security.yml` (or `codeql.yml` + `security-checks.yml` if you prefer split). Branch protection rule: require “security” (or the workflow name) to pass before merge.

---

## Phase 4 — Clean inputs for AI (better prompts)

**Purpose:** So that `secure-review` gives accurate, relevant advice.

### 4.1 Semgrep JSON + snippets

- In `scripts/secure_review_ollama.sh`: run Semgrep with `--json` (e.g. to a file).
- Parse JSON and for each finding include: path, line range, message, rule id, and a small snippet (e.g. ±2 lines). Put only these into the prompt; avoid dumping full file contents.

### 4.2 Gitleaks

- Run gitleaks with JSON output if available; include only finding location and rule name in the prompt.

### 4.3 Staged diff only

- Use `git diff --staged` as the “code change” context so the model focuses on what’s being committed, not the whole codebase.

**Deliverable:** Updated `secure_review_ollama` script (and Makefile if needed) that builds the prompt from:
- New findings (Semgrep JSON + snippets, Gitleaks JSON).
- Staged diff only.
- Short instruction: “Explain these findings and suggest concrete fixes.”

---

## Phase 5 — Auto-fixes where safe (optional but nice)

**Purpose:** Automate style and dependency updates; never auto-fix logic/security.

### 5.1 Formatting/lint already in pre-commit

- Ruff format and ESLint (with `--fix` where safe) are already running on commit; no extra step.

### 5.2 Dependabot

- In GitHub: repo → Security → Dependabot → Enable.
- Add `.github/dependabot.yml`:
  - `package-ecosystem: "pip"`, directory: `services/api` (and worker if separate deps).
  - `package-ecosystem: "npm"`, directory: `services/frontend`.
  - Schedule: e.g. weekly; open PRs for version and security updates.

**Deliverable:** `.github/dependabot.yml`; Dependabot enabled. No automatic logic/security fixes in repo; only Dependabot PRs and human review.

---

## Phase 6 — Documentation and onboarding

### 6.1 README or RUN-WINDOWS.md

- Add a short “Security workflow” section:
  - **Commit:** Pre-commit runs (gitleaks, semgrep, ruff, eslint). Install once: `pip install pre-commit && pre-commit install`.
  - **Optional local:** `make secure-check` (scanners); `make secure-review` (scanners + Ollama). Not required to commit.
  - **Push/PR:** CI runs CodeQL, gitleaks, Semgrep, pip-audit, npm audit, optional Trivy, tests. Branch protection requires these to pass.
  - **Dependabot:** Enabled; review and merge dependency PRs.

### 6.2 Optional: CONTRIBUTING.md

- One paragraph pointing to the same: use pre-commit, run `make secure-check` before push if you want, rely on CI as the gate.

---

## Execution order (how to proceed)

| Step | Action | Dependency |
|------|--------|------------|
| 1 | Add Ruff config (root or api) + ensure ESLint in frontend | — |
| 2 | Add `.pre-commit-config.yaml` and test `pre-commit run --all-files` | Step 1 |
| 3 | Document in README/RUN-WINDOWS: install pre-commit, run `pre-commit install` | Step 2 |
| 4 | Create root `Makefile` with `secure-check` (gitleaks, semgrep, pip-audit, npm audit) | — |
| 5 | Add `scripts/secure_review_ollama.sh` (and optional `.ps1`) using staged diff + Semgrep JSON + gitleaks | Step 4 |
| 6 | Add `make secure-review` that runs secure-check then the script | Step 5 |
| 7 | Create `.github/workflows/security.yml` with CodeQL, gitleaks, Semgrep, pip-audit, npm audit, optional osv-scanner, optional Trivy, tests | — |
| 8 | Enable Dependabot + add `.github/dependabot.yml` | — |
| 9 | Refine Ollama script: only new findings, snippets, staged diff (Phase 4) | Step 5–6 |
| 10 | Update docs (Phase 6) | All above |

**Suggested first PR:** Steps 1–3 (pre-commit only).  
**Second PR:** Steps 4–6 (Makefile + secure-review script).  
**Third PR:** Step 7 (CI).  
**Fourth PR:** Steps 8–10 (Dependabot + script refinement + docs).

---

## Summary: what runs where

| When | What | Blocking? |
|------|------|-----------|
| **Commit** | gitleaks, semgrep (staged), ruff, eslint | Yes (pre-commit) |
| **On demand** | `make secure-check` (optional pip-audit, npm audit) | No |
| **On demand** | `make secure-review` (scanners + Ollama) | No |
| **Push/PR** | CodeQL, gitleaks, Semgrep, pip-audit, npm audit, optional osv/Trivy, tests | Yes (branch protection) |
| **Scheduled** | Dependabot PRs | No (human merge) |

This keeps “real scanners detect, local AI explains, you fix, CI enforces” without making every commit slow or blocking on AI.

# Security workflow: on-demand checks (do not block commit; pre-commit does that).
# Usage: make secure-check | make secure-review
# On Windows: use Git Bash or "make" from WSL.

.PHONY: secure-check secure-review perf-check dast knip

# Run scanners only (no AI). Use before push or when you want a fuller local check.
secure-check:
	@echo "=== Gitleaks (secrets) ==="
	@pre-commit run gitleaks --all-files || true
	@echo "\n=== Semgrep (SAST) ==="
	@pre-commit run semgrep --all-files || true
	@echo "\n=== pip-audit (Python deps) ==="
	@(cd services/api && pip-audit 2>/dev/null) || echo "  (pip-audit not run or no issues)"
	@echo "\n=== npm audit (frontend) ==="
	@(cd services/frontend && npm audit 2>/dev/null) || echo "  (npm audit not run or no issues)"
	@echo "\n=== secure-check done ==="

# Run scanners (captured) + staged diff, send to Ollama for explanation.
# Requires: Ollama installed and a model pulled (e.g. ollama run codellama).
OLLAMA_MODEL ?= codellama
secure-review:
	@bash scripts/secure_review_ollama.sh "$(OLLAMA_MODEL)"

# Run the frontend production build and enforce basic bundle/build budgets.
perf-check:
	@node scripts/frontend-performance-check.cjs

# DAST: run OWASP ZAP baseline scan against the running frontend.
# Requires: Docker, and the platform must be running (docker compose up).
# Target defaults to http://host.docker.internal:3002 (frontend).
# Override: make dast TARGET_URL=http://host.docker.internal:8000
TARGET_URL ?= http://host.docker.internal:3002
dast:
	@powershell -ExecutionPolicy Bypass -File scripts/zap-baseline.ps1 -Target "$(TARGET_URL)"

# Detect dead code, unused exports, and orphan dependencies across the monorepo.
knip:
	@cd services/frontend && npx knip

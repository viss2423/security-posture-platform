# Security workflow: on-demand checks (do not block commit; pre-commit does that).
# Usage: make secure-check | make secure-review
# On Windows: use Git Bash or "make" from WSL.

.PHONY: secure-check secure-review

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

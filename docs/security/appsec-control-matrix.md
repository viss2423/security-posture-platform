# AppSec Control Matrix (Phase 2)

| Area | Framework anchor | Implementation in repo | Evidence |
| --- | --- | --- | --- |
| Secure SDLC baseline | NIST SSDF | CI security scan, auth hardening, audit logging | `.github/workflows/security-scan.yml`, `services/api/app/routers/auth.py` |
| Maturity tracking | OWASP SAMM | Maturity plan and phased targets | `docs/maturity-plan.md` |
| Verification requirements | OWASP ASVS | Route tests for authz/authn/audit/error conventions | `services/api/tests/test_auth_*`, `services/api/tests/test_assets_findings_rbac.py`, `services/api/tests/test_error_conventions.py` |
| API threat coverage | OWASP API Top 10 (2023) | Object-level auth tests, rate limiting, validation, secure defaults | `services/api/tests/test_assets_findings_rbac.py`, `services/api/app/rate_limit.py`, `services/api/app/errors.py` |
| Vulnerability disclosure | RFC 9116 + ISO/IEC 29147 process | `security.txt` endpoint + workflow policy | `services/api/app/routers/security.py`, `docs/security/vulnerability-disclosure.md` |

# Compliance Control Register

This register maps customer-facing trust controls to the repo-owned evidence that verifies them.

| Control Area | Primary Framework Lens | Repo Evidence | Verification Path |
| --- | --- | --- | --- |
| Secure SDLC governance | NIST SSDF, OWASP SAMM | `docs/security/appsec-control-matrix.md`, `docs/security/vulnerability-disclosure.md` | `py services/api/scripts/build_compliance_evidence_pack.py` |
| Application verification | OWASP ASVS, OWASP API Security Top 10 | auth/RBAC/audit/privacy tests under `services/api/tests/` | `py -3.13 -m pytest -q services/api/tests/test_security_program.py services/api/tests/test_privacy_dsar_routes.py` |
| Reliability and release discipline | SRE error-budget policy, SOC 2 Availability | `docs/contracts/stability-contract.md`, `services/api/app/stability.py`, `/.github/workflows/supply-chain.yml` | `py -3.13 -m pytest -q services/api/tests/test_platform_stability.py` |
| Observability and telemetry | OpenTelemetry, golden-signal operations | `docs/observability/otel-semantic-conventions.md`, `infra/observability/alerts.yml` | `py services/api/scripts/build_readiness_evidence.py` |
| Supply-chain integrity | SLSA, SBOM, Sigstore/Cosign | `/.github/workflows/supply-chain.yml`, `infra/policy/kyverno/verify-secplat-images.yaml` | `py services/api/scripts/render_release_bundle.py ...` |
| Backup and recovery | NIST contingency planning, SOC 2 Availability | `docs/operations/backup-restore-verification.md`, `/.github/workflows/recovery-drill.yml` | `py -3.13 -m pytest -q services/api/tests/test_verify_backup_restore_script.py` |
| Tenant isolation and privacy | Privacy by design, least privilege | `docs/security/tenant-isolation-and-privacy.md`, `services/api/app/routers/privacy.py` | `py -3.13 -m pytest -q services/api/tests/test_posture_tenant_filters.py services/api/tests/test_telemetry_opensearch_doc.py` |
| AI safety guardrails | OWASP LLM guidance, human approval controls | `services/api/app/routers/ai.py`, `services/frontend/app/(app)/alerts/page.tsx` | `npm test --prefix services/frontend` |

Use this register as the source file for evidence-pack generation and customer-trust reviews.

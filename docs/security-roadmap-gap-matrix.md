# Security Roadmap Gap Matrix (Customer Stability Program)

Last audited: `2026-03-09`

Canonical phase tracker: [ga-sequential-phase-plan.md](./ga-sequential-phase-plan.md)

Status legend:
- `done`: implemented and operational
- `partial`: baseline exists, but key customer-readiness outcomes are missing
- `missing`: little or no implementation

Audit method:
- Static code + docs review across `services/api`, workers, `infra/k8s`, `.github/workflows`, and `docs/`
- Script checks run locally:
  - `py services/api/scripts/check_upgrade_contract.py` -> `ok: true`
  - `py services/api/scripts/check_upgrade_compatibility.py` -> `ok: true`
  - `py services/api/scripts/check_release_gate.py --allow-sample-fallback` -> `ship_allowed`
  - `py services/api/scripts/check_contract_parity.py` -> `ok: true`
  - `py services/api/scripts/check_k8s_image_pinning.py` -> `ok: true`
  - `py services/api/scripts/check_postmortem_evidence.py` -> `ok: true`
  - `py services/api/scripts/provision_runtime_db_role.py --admin-dsn ...` -> `ok: true`
  - `py services/api/scripts/check_db_runtime_role.py` -> `skipped` when DSN is not configured, enforceable with `--require-dsn`
  - `py services/api/scripts/build_readiness_evidence.py` -> `ok: true`
  - `py services/api/scripts/verify_backup_restore.py --backup-file posture.csv --dry-run` -> validates backup freshness + dry-run contract

## Implementation Snapshot

| Capability Area | Status | Estimated Coverage | Evidence | Main Gaps |
| --- | --- | --- | --- | --- |
| Security SDLC baseline (SSDF/SAMM/ASVS narrative) | partial | 65% | `services/api/app/security_program.py`, `docs/security/appsec-control-matrix.md`, auth/RBAC/audit tests | Framework mapping is mostly declarative; no control-owner/evidence automation for audits |
| Vulnerability disclosure (RFC 9116 path + process) | done | 88% | `/.well-known/security.txt` in `services/api/app/routers/security.py`, `docs/security/vulnerability-disclosure.md` | Public intake tooling integration remains optional follow-on work |
| SLOs + release gate/error budget policy | done | 92% | `services/api/app/stability.py`, persisted `platform_sli_samples`, `/platform/release-gate/*`, CI gate script + strict matrix profile | Strict no-fallback gate mode is enforced when strict profile is enabled (`SECPLAT_STRICT_RELEASE_PROFILE=true`) |
| Observability (OpenTelemetry-level) | done | 78% | `services/api/app/otel.py`, request/db/queue/AI spans, `docs/observability/otel-semantic-conventions.md` | OTLP export is environment-gated; collector endpoint must be configured per deployment |
| Incident operations and support readiness | done | 82% | `docs/operations/incident-severity-and-escalation.md`, `docs/operations/postmortems/*`, `check_postmortem_evidence.py`, readiness contract endpoint | Runbook depth for rarer failure modes can still be expanded over time |
| Supply chain trust (SLSA/SBOM/signing/provenance) | done | 90% | `.github/workflows/supply-chain.yml` baseline+strict matrix, `check_k8s_image_pinning.py`, strict digest mode, `infra/policy/kyverno/verify-secplat-images.yaml` | Cluster-side Kyverno rollout and key policy rotation remain operational rollout work |
| Upgrade safety and compatibility | done | 79% | `docs/contracts/upgrade-policy.md`, `/platform/upgrade-policy`, `check_upgrade_contract.py`, `check_upgrade_compatibility.py` | Mixed-version canary execution still depends on environment-specific test harnesses |
| Multi-tenancy and data isolation | done | 88% | Tenant context + DB tenant GUC propagation (`db.py`), runtime/migration DSN split, `org_id` + RLS enforcement in startup migration/tests, `check_db_runtime_role.py` | OpenSearch tenant partitioning remains deployment-specific and should be configured before SaaS multi-tenant rollout |
| Privacy/GDPR operational features | done | 74% | Retention endpoint, DSAR endpoints (`/privacy/dsar/export`, `/privacy/dsar/delete`), pseudonymization workflow, privacy docs | Data-classification and field-level minimization policies should continue expanding by integration type |
| Backup/restore resilience | done | 90% | `verify_backup_restore.py`, recovery contract endpoint, `.github/workflows/recovery-drill.yml`, runtime-role precheck in drill workflow | Restore target infrastructure still needs operator-owned credentials/secrets lifecycle |
| Kubernetes hardening baseline | done | 90% | Digest-pinned manifests, kyverno verify policy, CI pinning checks, strict real-digest check mode | Release process must provide signed digest promotion inputs to enable strict mode globally |
| AI trust guardrails | done | 84% | Prompt redaction in `ai_client.py`, tenant-scoped AI context queries in `routers/ai.py`, explicit `requires_human_approval` for mutating AI actions | Human approval signaling is explicit in API; downstream UI/workflow should enforce final operator acknowledgement UX |

## Phase-by-Phase Execution Plan

## Phase 1 - Close trust-contract correctness gaps (immediate)

Status: `done`

Already implemented:
- Stability, upgrade, recovery, readiness, and security-program endpoints under `/platform/*`
- Queue/event envelope baseline and idempotency docs
- Event envelope contract now includes `notify.requested` (runtime parity)
- Kubernetes API readiness probe now targets `/ready`
- CI now validates release-gate contract script in `.github/workflows/supply-chain.yml`

Completed:
- CI gate now supports environment-driven SLI sources (`SECPLAT_SLI_REPORT_JSON` / `SECPLAT_SLI_REPORT_PATH`) with controlled sample fallback.
- Added parity contract script (`check_contract_parity.py`) for event schema/runtime parity, k8s readiness probe contract, and CI wiring.
- Supply-chain CI now supports a strict profile matrix lane (`SECPLAT_STRICT_RELEASE_PROFILE=true`) that enforces no-fallback release input and strict policy checks.

Exit criteria:
- Contracts and runtime behavior are consistent and validated in CI

## Phase 2 - Make observability production-grade

Status: `done`

Already implemented:
- Request/trace correlation IDs and structured logs
- Queue trace propagation and API metrics endpoint

Completed:
- Added OpenTelemetry runtime module with safe no-op fallback and OTLP exporter wiring.
- Added span coverage for API request lifecycle, DB query execution, queue publish, and AI provider calls.
- Updated observability conventions doc with runtime controls and semantic span coverage.

Exit criteria:
- Single request/incident is traceable end-to-end across API + workers + correlator + notifier

## Phase 3 - Enforce release reliability with real SLIs

Status: `done`

Already implemented:
- SLO contract object and release gate evaluator

Completed:
- Added live operational SLI computation from telemetry, alerts, and jobs.
- Added persisted SLI samples (`platform_sli_samples`) with `/platform/sli/current` and `/platform/release-gate/current` wiring.
- Release gate now uses measured SLI values by default and stores evidence snapshots.

Exit criteria:
- Release gate uses real measured SLIs and blocks feature rollout when budgets are exhausted

## Phase 4 - Multi-tenant isolation and privacy hardening

Status: `done`

Already implemented:
- Tenant context propagation in request/queue layers

Completed:
- Added datastore tenant context propagation in DB layer (`secplat.tenant_id`).
- Added `org_id` + forced RLS policy enforcement across core operational tables with startup migration support.
- Added tenant-enforcement tests and AI query-path tenant filters for context extraction.

Exit criteria:
- Cross-tenant access is prevented by datastore constraints plus authz tests, not only headers/context

## Phase 5 - Supply chain and deployment trust

Status: `done`

Already implemented:
- SBOM generation and signed artifact/provenance workflow

Completed:
- Replaced mutable `:latest` workload images with digest-pinned references in `infra/k8s`.
- Added Kyverno admission policy artifact for digest/signature verification.
- Added CI enforcement script (`check_k8s_image_pinning.py`) and workflow gate.

Exit criteria:
- Only verified, attested images are deployable

## Phase 6 - Recovery and backup drills as product features

Status: `done`

Already implemented:
- Backup helper + dry-run verification + recovery contract values

Completed:
- Extended `verify_backup_restore.py` to support real non-dry-run restore validation.
- Added SQL restore execution path with expected-table validation against target DSN.
- Added extended tests for non-dry-run restore controls and failure modes.

Exit criteria:
- Recurring restore drills pass with evidence artifacts and measured RPO/RTO

## Phase 7 - AI subsystem trust controls

Status: `done`

Already implemented:
- Evidence-grounded outputs with fallback and guardrail tests
- Versioned AI summaries/guidance and context signature staleness checks

Completed:
- Added prompt redaction/DLP sanitization in AI client before provider calls.
- Added tenant-scoped AI context queries and tenant-scoped AI cache table access.
- Added explicit `requires_human_approval` and `approval_mode` contract fields for mutating AI alert recommendations.

Exit criteria:
- AI output is bounded, auditable, and cannot drive high-risk actions without approval

## Phase 8 - Runtime role and recovery drill hardening

Status: `done`

Completed:
- Added DB runtime role posture checker (`check_db_runtime_role.py`) to detect superuser/BYPASSRLS runtime misconfiguration.
- Added runtime role provisioning helper (`provision_runtime_db_role.py`) for repeatable least-privilege setup.
- Added runtime/migration DSN separation (`POSTGRES_DSN` + `MIGRATIONS_POSTGRES_DSN`) so application runtime can stay least-privilege while migrations use elevated credentials.
- Wired runtime role check into CI and pre-restore stage in `.github/workflows/recovery-drill.yml`.
- Recovery drill workflow now uploads dry-run, runtime-role, and restore evidence artifacts.

Exit criteria:
- Restore drills validate both backup mechanics and tenant-isolation-safe DB role posture

## Phase 9 - Upgrade compatibility guardrails

Status: `done`

Completed:
- Added migration compatibility lint (`check_upgrade_compatibility.py`) that blocks destructive patterns unless explicitly annotated.
- Added tests for destructive SQL detection and controlled override path.
- Wired compatibility lint into supply-chain workflow.

Exit criteria:
- Upgrade checks enforce both numbering/policy contracts and migration safety guardrails

## Phase 10 - Privacy DSAR operationalization

Status: `done`

Completed:
- Added admin-only DSAR export endpoint (`POST /privacy/dsar/export`) with source counts and optional samples.
- Added admin-only DSAR delete endpoint (`POST /privacy/dsar/delete`) with dry-run/execute modes.
- DSAR execute flow now pseudonymizes subject references, revokes/deletes refresh tokens, and disables/pseudonymizes account records.
- Added integration tests and runbook/privacy docs.

Exit criteria:
- Privacy operations include auditable export + deletion workflows rather than retention-only controls

## Phase 11 - Incident postmortem evidence pipeline

Status: `done`

Completed:
- Added postmortem evidence template and repository (`docs/operations/postmortems/`).
- Added postmortem evidence validator (`check_postmortem_evidence.py`) with section and prevention-action checks.
- Wired validator into CI and readiness evidence.

Exit criteria:
- Sev1/Sev2 postmortem evidence has a repeatable template and automated validation pipeline

## Execution Order (Completed)

1. Phase 1 (contract correctness + CI release enforcement)
2. Phase 2 (observability instrumentation)
3. Phase 3 (real SLI/error-budget enforcement)
4. Phase 4 (tenant/data isolation)
5. Phase 5 (supply-chain deploy trust)
6. Phase 6 (real restore drills)
7. Phase 7 (AI trust hardening)
8. Phase 8 (runtime-role + recovery drill hardening)
9. Phase 9 (upgrade compatibility guardrails)
10. Phase 10 (privacy DSAR operations)
11. Phase 11 (postmortem evidence pipeline)

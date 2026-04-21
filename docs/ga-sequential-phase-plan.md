# SecPlat Sequential Completion Plan

This is the canonical execution tracker for the GA and maintenance-light program.

## Defaults

- GA target: single-tenant first
- Production source of truth: Kubernetes
- Supported production package: Helm
- Strict phase exits: implement, test, fix, retest, then advance
- Observability stack target: OpenTelemetry Collector, Prometheus, Tempo, Grafana

## Phases

| Phase | Goal | Exit focus |
| --- | --- | --- |
| Phase 0 | Architecture truth and deployment alignment | Worker topology, internal job control, Kubernetes/docs parity |
| Phase 1 | Durable reliability and end-to-end observability | Durable SLIs, release gate truth, cross-service tracing |
| Phase 2 | Secure runtime, supply chain, and recovery | Runtime least privilege, signed deployment path, restore evidence |
| Phase 3 | Productization, packaging, and operator UX | Helm, onboarding, docs, frontend regression coverage |
| Phase 4 | GA verification and release candidate | Performance, resilience, external assessment, release candidate proof |
| Phase 5 | Maintenance-light operations | Self-serve upgrades, automated controls, toil reduction |

## Phase 0 Decisions

- Workers read Redis and use internal API job-control endpoints.
- Workers do not use Postgres directly in the supported production path.
- The API owns job state transitions in Postgres.
- Kustomize remains an engineering baseline; Helm is the supported production packaging target.

## Phase 0 Status

- Implemented:
  - Internal job-control endpoints: claim, heartbeat, complete, fail
  - API-side execution for `web_exposure`
  - Worker runtime migrated to Redis plus API only
  - Kubernetes worker manifest and egress policy aligned to the API-only worker path
  - Worker contract tests and API job-control tests
- Remaining for later phases:
  - Helm packaging
  - Durable SLI materialization and release-gate hardening
  - Full OTEL propagation across all services
  - Recovery drill automation with operator-owned credentials

## Current Status

- Phase 0: complete
- Phase 1: complete
- Phase 2: complete
- Phase 3: complete
- Phase 4: repo-owned validation complete; external assessment and design-partner signoff still pending
- Phase 5: repo-owned automation complete

## Phase 3 Status

- Implemented:
  - Supported Helm chart with bundled local dependencies for the Docker Desktop validation path
  - Guided onboarding flow plus frontend regression coverage
  - Demo seed/reset controls validated in both local and Helm-backed environments
  - Config and secret checksum rollouts for Helm upgrades
- Verified:
  - Fresh Helm install and upgrade in `secplat-phase3`
  - `verify_phase3_onboarding.py`
  - Frontend `lint`, `test`, `build`, and `test:e2e`

## Phase 4 Status

- Implemented:
  - Local GA verification script: `services/api/scripts/verify_phase4_local_ga.py`
  - Live Kubernetes load smoke against `/health`, `/ready`, and `/auth/config`
  - Dependency restart/recovery verification for OpenSearch, Redis, and Postgres
  - Release bundle rendering and Kyverno admission verification in `artifacts/phase4/release-bundle`
  - External closeout handoff bundle builder: `services/api/scripts/build_phase4_external_handoff.py`
  - Assessor and design-partner handoff docs:
    - `docs/operations/external-security-assessment-runbook.md`
    - `docs/operations/design-partner-signoff-template.md`
- Verified:
  - `py services/api/scripts/verify_phase4_local_ga.py --namespace secplat-phase3 --api-service secplat-api --admin-password secplat-admin-123`
  - `py services/api/scripts/render_release_bundle.py --image-map-json services/api/examples/release-images.example.json --out-dir artifacts/phase4/release-bundle --github-repository acme/security-posture-platform`
  - `py services/api/scripts/verify_kyverno_admission.py --repo-root artifacts/phase4/release-bundle --policy-file infra/policy/kyverno/verify-secplat-images.yaml --require-real-attestors`
  - `py services/api/scripts/build_readiness_evidence.py`
  - `py services/api/scripts/build_phase4_external_handoff.py --out-dir artifacts/phase4/external-handoff`
  - `node scripts/frontend-performance-check.cjs`
- Remaining external blockers:
  - External security assessment / pen test with remediation loop
  - Design-partner validation and signoff on release-candidate operability

## Phase 5 Status

- Implemented:
  - Upgrade preflight automation: `services/api/scripts/run_upgrade_preflight.py`
  - Maintenance control runbook and verification gate: `docs/operations/maintenance-control-checks.md` and `services/api/scripts/verify_phase5_maintenance.py`
  - Automated stale-job recovery drill via `POST /jobs/maintenance/recover-stale`
  - Stronger DB tenant binding on session creation plus pooled-connection tenant cache reset
- Verified:
  - `py -m pytest services/api/tests/test_request_context.py services/api/tests/test_db_tenant_setting.py -q`
  - `py -m pytest services/api/tests/test_run_upgrade_preflight_script.py services/api/tests/test_verify_phase5_maintenance_script.py -q`
  - `py services/api/scripts/verify_phase5_maintenance.py --namespace secplat-phase3 --admin-password secplat-admin-123`

## References

- [architecture.md](./architecture.md)
- [security-roadmap-gap-matrix.md](./security-roadmap-gap-matrix.md)
- [adr/0001-ga-topology-and-runtime-lane.md](./adr/0001-ga-topology-and-runtime-lane.md)

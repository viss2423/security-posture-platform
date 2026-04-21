# Maintenance Control Checks

Phase 5 maintenance-light operations use two operator-facing commands.

## Upgrade preflight

Use this before a chart upgrade or version promotion:

```bash
python services/api/scripts/run_upgrade_preflight.py \
  --api-base-url http://127.0.0.1:8000 \
  --runtime-dsn postgresql+psycopg://secplat_runtime:secplat_runtime@127.0.0.1:5432/secplat \
  --require-live
```

What it validates:

- migration numbering and upgrade policy contract
- migration compatibility guardrails
- live `/health` and `/ready`
- live `/platform/release-gate/current?strict_missing=true`
- runtime DB least-privilege posture

## Phase 5 maintenance gate

Use this against the supported Kubernetes lane:

```bash
python services/api/scripts/verify_phase5_maintenance.py \
  --namespace secplat-phase3 \
  --admin-password secplat-admin-123
```

What it validates:

- upgrade preflight
- readiness and postmortem evidence completeness
- image verification posture via the Kyverno policy
- live queue health, jobs analytics, recovery contract, and automation dashboard
- fresh backup generation from the Kubernetes PostgreSQL pod plus dry-run freshness verification
- stale running job recovery runbook: claim -> age heartbeat -> preview -> recover -> drain

Artifacts are written under `artifacts/phase5/`.

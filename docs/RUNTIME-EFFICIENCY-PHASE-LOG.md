# Runtime Efficiency Phase Log

Date: 2026-03-08
Repository: `security-posture-platform`

## Phase 0: Baseline and guardrails

### Runtime snapshot (before cutover work)

- `docker compose config`: pass
- `docker compose config --services`: `redis`, `verify-web`, `opensearch`, `postgres`, `api`, `frontend`, `ingestion`, `juiceshop`
- `kubectl -n secplat get deploy,cronjob,pods`: pass
- `GET /health`: `{"status":"ok"}`
- `GET /ready`: `{"status":"ok","checks":{"postgres":"ok","opensearch":"ok"}}`
- `GET /queue/health`: pass (`redis=ok`)
- `docker ps` container count during mixed runtime: `51`
- `docker stats --no-stream`: captured in terminal output

### Guardrail policy

- Two-lane runtime policy enabled in docs:
  - Compose lane for local/dev
  - Kubernetes lane for staged/prod
  - No parallel app-lane runtime

### Known blockers captured

- Kubernetes ingestion CronJob auth failures (`/assets` not authenticated) observed before this change set.
- Kubernetes snapshot CronJob read timeouts observed before this change set.

## Phase progression status

- Phase 0: complete
- Phase 1: complete
  - Lean Compose default confirmed: `api`, `frontend`, `ingestion`, `postgres`, `opensearch`, `redis`, `verify-web`, `juiceshop`
  - Optional services moved behind profiles: `observability`, `jobs`, `scan`, `optional-web`
- Phase 2: complete
  - Scheduler defaults switched to disabled in local lane
  - 10-minute idle check: no growth in `telemetry_import` or `network_anomaly_score` jobs
- Phase 3: complete
  - Added Compose CPU/memory caps for heavy services and workers
  - 15-minute stability window: zero container restarts
- Phase 4: complete
  - K8 right-sized: API and worker replicas to `1`, HPA min/max `1/4`
  - K8 config disables duplicate API schedulers by default
  - CronJob hardening applied (auth fallback + retry/timeouts + tuned ingestion deadline)
  - Manual and scheduled CronJob executions verified successful
- Phase 5: complete
  - Added guarded cutover script: `scripts/runtime-lane-cutover.ps1`
  - Preflight blocking validated
  - Compose->K8 and K8->Compose cutovers validated
  - Revalidation fix (2026-03-08):
    - Failure class: scheduling duplication / lane overlap
    - Root cause: cutover preflight checked only K8 deployments; unsuspended K8 CronJobs could still run while Compose lane was active
    - Corrective change: updated `runtime-lane-cutover.ps1` to include CronJobs in Compose preflight and to suspend CronJobs when stopping K8 lane, then unsuspend on K8 resume
    - Backcheck: Compose preflight now passes only when both K8 deployments are scaled to `0` and K8 CronJobs are suspended; Compose health/readiness and `scripts/test-api.ps1` pass after switch-back
  - Revalidation fix (2026-03-08, follow-up):
    - Failure class: dependency availability during cutover
    - Root cause: CronJobs were unsuspended immediately after scaling K8 deployments, so first runs could hit `secplat-api` before it was ready (`connection refused`)
    - Corrective change: `runtime-lane-cutover.ps1` now waits for `deployment/secplat-api` rollout completion before unsuspending K8 CronJobs
    - Backcheck: Compose->K8->Compose cutover succeeds, API/worker rollouts succeed in K8 lane, and Compose lane returns healthy with K8 CronJobs suspended
- Phase 6: complete
  - `npm run perf:check`: pass
  - Targeted API tests: pass (`19 passed`)
  - Worker race regression: pass (`1 passed`)
  - Compose smoke script: pass
  - K8 smoke checks and manual snapshot job: pass

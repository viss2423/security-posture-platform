# Testing the Corporate Roadmap (Phases 0–2)

Use this to verify baseline, queue, and new services. All commands assume repo root and default ports.

---

## Prerequisites

- Docker Compose v2
- PowerShell (Windows) or bash (Linux/macOS)
- Optional: `jq`, `curl` for manual checks

---

## Phase 0 - Baseline (lean local lane)

### 0.1 Stack starts clean

```powershell
docker compose up -d --build
docker compose ps
```

**Expected:** Lean lane services `Up` (postgres, opensearch, redis, api, frontend, ingestion, verify-web, juiceshop). No exits.

Optional profile services can be enabled explicitly:

```powershell
docker compose --profile observability up -d grafana
docker compose --profile jobs up -d worker-web
docker compose --profile scan up -d scanner
docker compose --profile optional-web up -d web
```

### 0.2 Request ID propagation

```powershell
$r = Invoke-WebRequest -Uri "http://localhost:8000/health" -Method Get
$r.Headers["X-Request-Id"]
```

**Expected:** A UUID string in response header `X-Request-Id`.

### 0.3 Structured logs (API)

```powershell
docker logs secplat-api --tail 5
```

**Expected:** JSON lines including keys such as:
- `ts`, `level`, `service`, `logger`, `message`
- `request_id` (for request-scoped logs)
- `action=http_request`, `method`, `path`, `status`

Example shape:
```json
{"ts":"...Z","level":"info","service":"secplat-api","logger":"secplat","message":"http_request","request_id":"...","action":"http_request","method":"GET","path":"/health","status":200}
```

### 0.4 Contracts exist

- File `docs/contracts/event-envelope.json` exists and is valid JSON.
- File `docs/contracts/idempotency-keys.md` exists.

**Expected:** No 404; JSON parses.

### 0.5 Service identities seeded

```powershell
$login = Invoke-RestMethod -Uri "http://localhost:8000/auth/login" -Method Post -ContentType "application/x-www-form-urlencoded" -Body "username=admin&password=admin"
$token = $login.access_token
Invoke-RestMethod -Uri "http://localhost:8000/auth/users" -Headers @{ Authorization = "Bearer $token" } | ConvertTo-Json
```

**Expected:** `items` includes `scanner-service`, `ingestion-service`, and `correlator-service` (or your configured `*_SERVICE_USERNAME` values).

### 0.6 OIDC verification hardening tests

```powershell
docker compose run --rm --build api pytest -q tests/test_auth_oidc.py
```

**Expected:** tests pass, including checks for discovery issuer validation, id_token signing alg allow-list, nonce verification, and `azp` validation.

---

## Phase 1 — Redis and queue

### 1.1 Redis is up

```powershell
docker compose exec redis redis-cli PING
```

**Expected:** `PONG`.

### 1.2 Queue library (local Python)

With Redis running (`docker compose up -d redis`), **from repo root**:

```powershell
cd services\queue
pip install -e .
# Windows: use py (Python launcher) if "python" is not in PATH
py -c "from secplat_queue import publish; import os; os.environ.setdefault('REDIS_URL','redis://localhost:6379/0'); publish('secplat.jobs.scan', {'job_id':'1','asset_key':'test'}); print('ok')"
cd ..\..
docker compose exec redis redis-cli XLEN secplat.jobs.scan
```

**Expected:** `ok` and no exception; `XLEN` returns at least 1. If `py` fails, use full path to your Python (e.g. `& "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe" -c "..."`).

### 1.3 Queue health

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/queue/health" | ConvertTo-Json
```

**Expected:** `redis: "ok"`, `streams` includes primary streams (scan/notify/correlation), `dlq_streams` includes `*.dlq` depths, and `pending` includes consumer-group details (e.g. pending count and oldest idle). If REDIS_URL is not set: `status: "not_configured"`.

### 1.4 Worker claim race regression (single winner under concurrency)

This validates the `fetch_job` DB claim path in worker-web and protects against duplicate claims across replicas.

```powershell
$repo = (Get-Location).Path
docker run --rm -v "${repo}:/work" -w /work security-posture-platform-worker-web:latest sh -lc "pip install -q pytest && POSTGRES_DSN=postgresql://secplat:secplat@host.docker.internal:5433/secplat pytest services/worker-web/tests/test_job_claim_race.py -q"
```

**Expected:** `1 passed` and no duplicate claim failures.

Optional local run (only if your local Python is 3.11+ and has worker deps installed):

```powershell
$env:POSTGRES_DSN = "postgresql://secplat:secplat@localhost:5433/secplat"
python -m pytest services/worker-web/tests/test_job_claim_race.py -q
```

---

## Phase 2 — Deriver and Notifier (placeholders)

### 2.1 Profile brings up deriver + notifier

```powershell
docker compose --profile roadmap up -d --build deriver notifier
docker compose ps
```

**Expected:** `secplat-deriver` and `secplat-notifier` in the list and `Up`.

### 2.2 Deriver (Phase 2.1: real derivation)

```powershell
docker compose --profile roadmap up -d --build deriver
Start-Sleep -Seconds 15
docker logs secplat-deriver --tail 5
```

**Expected:** Logs like `secplat-deriver started...`, `deriving status for N assets`, `derivation done`. After a run, `secplat-asset-status` in OpenSearch has one doc per asset (same as when ingestion runs build_asset_status.sh). Optional: set `SKIP_BUILD_ASSET_STATUS=true` for ingestion so only deriver writes asset-status.

### 2.3 Notifier (Phase 2.3: consume notify stream)

**2.3a Notifier running**

```powershell
docker logs secplat-notifier --tail 5
```

**Expected:** `secplat-notifier started stream=secplat.events.notify group=notifiers ...`

**2.3b Queue health includes notify stream**

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/queue/health" | ConvertTo-Json
```

**Expected:** `streams` includes `secplat.events.notify` (number).

**2.3c Alert/send → queued (when Redis is used)**

1. Get a token (login expects **form** body, not JSON; default admin/admin):

```powershell
$login = Invoke-RestMethod -Uri "http://localhost:8000/auth/login" -Method Post -ContentType "application/x-www-form-urlencoded" -Body "username=admin&password=admin"
$token = $login.access_token
```

2. Call alert/send:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/posture/alert/send" -Method Post -Headers @{ Authorization = "Bearer $token" } | ConvertTo-Json
```

**Expected (no red assets):** `sent: false`, `message: "No down assets; no notification sent."`  
**Expected (some assets red):** `queued: true`, `down_assets: [...]`. Then check notifier logs: `docker logs secplat-notifier --tail 10` for "slack sent" or "whatsapp sent".

**2.3d Test notifier without red assets (inject one message)**

Publish a fake notify message so the notifier consumes and tries to send (Slack/WhatsApp only if env is set). Use single quotes so PowerShell doesn’t expand `*` or the JSON:

```powershell
docker compose exec redis redis-cli XADD secplat.events.notify MAXLEN 10000 '*' type down_assets down_assets '["test-asset-1"]'
```

Then within a few seconds:

```powershell
docker logs secplat-notifier --tail 15
```

**Expected:** Log line showing handling of the message and either "slack sent" / "whatsapp sent" or "slack send failed" / "whatsapp send failed" (if URLs not set).

### 2.4 Full stack with roadmap profile

```powershell
docker compose --profile roadmap up -d --build
docker compose ps
```

**Expected:** All core services + redis + deriver + notifier + correlator running. API and frontend still work (login, overview, assets).

---

## Phase 3 — Correlator (Phase 3.1)

### 3.1 Queue health includes correlation stream

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/queue/health" | ConvertTo-Json
```

**Expected:** `streams` includes `secplat.events.correlation` and `dlq_streams` includes `secplat.events.correlation.dlq`.

### 3.2 Correlator creates incident from finding

With stack up (`--profile roadmap`), create a new finding via API; correlator should consume and create an incident.

1. Get token (form login as above).
2. Create a finding (use an existing asset_key, e.g. from authenticated `GET /assets`):

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/findings/" -Method Post -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body '{"finding_key":"test-correl-1","asset_key":"juice-shop","title":"Test finding for correlator","severity":"high"}'
```

3. Check correlator logs and incidents:

```powershell
docker logs secplat-correlator --tail 10
Invoke-RestMethod -Uri "http://localhost:8000/incidents" -Headers @{ Authorization = "Bearer $token" } | ConvertTo-Json
```

**Expected:** Correlator log "created incident id=... title=Finding: test-correl-1 on juice-shop"; GET /incidents returns at least one incident with that title (or similar).

### 3.3 Correlator creates incident from alert.triggered

When you call POST /posture/alert/send with down assets (or inject into secplat.events.notify), the API also publishes to secplat.events.correlation. Correlator consumes and creates one incident "Assets down: ..." with those asset_keys linked.

**Expected:** After triggering an alert (or injecting a notify message), correlator log "created incident id=... assets=N" and GET /incidents shows an incident with linked alerts.

### 3.4 Incident idempotency (`incident_key`)

Repeat the same create request twice:

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/incidents" -Method Post -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body '{"incident_key":"idem-test-1","title":"Idem test","severity":"medium"}'
Invoke-RestMethod -Uri "http://localhost:8000/incidents" -Method Post -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body '{"incident_key":"idem-test-1","title":"Idem test","severity":"medium"}'
```

**Expected:** first call creates (`201`, `deduped=false`), second call dedupes to same incident (`200`, `deduped=true`).

---

## Phase 3.2 — Maintenance windows + suppression rules

### 3.2a List maintenance windows (empty at first)

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/suppression/maintenance-windows" -Headers @{ Authorization = "Bearer $token" } | ConvertTo-Json
```

**Expected:** `items: []` (or list of windows).

### 3.2b Create maintenance window, then alert/send excludes that asset

1. Create a window for an asset that is currently red (e.g. juice-shop), covering now:

```powershell
$now = [DateTime]::UtcNow; $start = $now.AddMinutes(-5).ToString("o"); $end = $now.AddMinutes(60).ToString("o")
Invoke-RestMethod -Uri "http://localhost:8000/suppression/maintenance-windows" -Method Post -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body "{ \"asset_key\": \"juice-shop\", \"start_at\": \"$start\", \"end_at\": \"$end\", \"reason\": \"Test window\" }"
```

2. Call `POST /posture/alert/send` again. **Expected:** If juice-shop was the only down asset, response is "No down assets" (suppressed). If other assets were down, only non-suppressed ones are in `down_assets`.

### 3.2c Suppression rules (time-bound)

- `GET /suppression/rules` — list rules (scope: asset | finding | all).
- `POST /suppression/rules` — body: `scope`, `scope_value` (for asset/finding), `starts_at`, `ends_at`, `reason`. Assets/findings matching an active rule are excluded from alerts and from correlation (no incident created).

---

## Phase 4 — Policy-as-Code v2 (Option A: evidence + persistence)

### 4.1 Evaluate bundle and persist run

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/policy/bundles/$bundleId/evaluate" -Method Post -Headers @{ Authorization = "Bearer $token" } | ConvertTo-Json -Depth 8
```

**Expected:**
- response includes `evaluation_id`, `score`, `rules`, `violations`
- each violation has `rule_id`, `asset_key`, `timestamp`, `bundle_approved_by`, `evidence`

### 4.2 List evaluation history

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/policy/bundles/$bundleId/evaluations?limit=10" -Headers @{ Authorization = "Bearer $token" } | ConvertTo-Json
```

**Expected:** items with `id`, `evaluated_at`, `evaluated_by`, `score`, `violations_count`.

### 4.3 Fetch one persisted evaluation (full evidence payload)

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/policy/bundles/$bundleId/evaluations/$evaluationId" -Headers @{ Authorization = "Bearer $token" } | ConvertTo-Json -Depth 8
```

**Expected:** response contains `result` with full `rules` and `violations` payload that matches (or supersets) the original evaluate response.

---

## Phase 5 — Kubernetes baseline manifests

### 5.1 Render manifests via kustomize

```powershell
kubectl kustomize infra/k8s | Out-Null
```

**Expected:** command renders successfully (no YAML parse errors).

### 5.2 Validate security controls in manifests

Review these files:
- `infra/k8s/deployment-api.yaml`
- `infra/k8s/deployment-worker-web.yaml`
- `infra/k8s/networkpolicy-worker-egress.yaml`
- `infra/k8s/networkpolicy-postgres-ingress-from-api.yaml`

**Expected:**
- workloads set `runAsNonRoot`, `readOnlyRootFilesystem`, and drop Linux capabilities.
- workers egress policy does not allow port `5432`.
- Postgres ingress policy allows port `5432` only from API-labeled pods.

### 5.3 Apply to cluster (when kube context is available)

```powershell
kubectl apply -f infra/k8s/secret.yaml
kubectl apply -k infra/k8s
```

**Expected:** Deployments, HPA, CronJobs, and NetworkPolicies are created in namespace `secplat`.

### 5.4 CronJob success checks (manual run)

```powershell
$suffix = Get-Date -Format "yyyyMMddHHmmss"
kubectl -n secplat create job --from=cronjob/secplat-ingestion-health "secplat-ingestion-health-manual-$suffix"
kubectl -n secplat create job --from=cronjob/secplat-report-snapshot "secplat-report-snapshot-manual-$suffix"
kubectl -n secplat get jobs
```

**Expected:** Both manual jobs complete successfully and logs show no repeated auth failures or read timeouts.

### 5.5 No-parallel-run cutover checks

```powershell
.\scripts\runtime-lane-cutover.ps1 -To k8s -PreflightOnly
.\scripts\runtime-lane-cutover.ps1 -To compose -PreflightOnly
```

**Expected:** Preflight blocks lane switches when opposite app lane is active, and passes once opposite lane is stopped.

---

## Regression: existing behaviour

After any change, confirm:

| Test | Command / action | Expected |
|------|-------------------|----------|
| API health | `curl http://localhost:8000/health` | 200 |
| Login | `POST /auth/login` with admin/admin | 200 + `access_token` |
| Posture summary | `GET /posture/summary` with Bearer | 200 + green/amber/red |
| Jobs list | `GET /jobs` with Bearer | 200 + items |
| Enqueue job | `POST /jobs` body `{ "job_type": "web_exposure", "target_asset_id": 1 }` | 201 + job |
| Worker picks job | Wait ~5s, `GET /jobs` | One job running or done |
| OpenSearch | `curl http://localhost:9200` | 200 + cluster info |
| Redis | `docker compose exec redis redis-cli PING` | PONG |

---

## Definition of Done (per phase)

- [ ] `docker compose config` validates (no YAML errors)
- [ ] `docker compose up -d --build` brings up all services (no build failures)
- [ ] Key endpoints return expected status (see table above)
- [ ] Logs show request_id (API) and service name (deriver/notifier)
- [ ] At least one smoke test per new service (e.g. deriver logs "started", notifier logs "started")

---

## Quick smoke script (PowerShell)

Run **from repo root** (script changes to repo root automatically if you put it in `scripts/smoke-roadmap.ps1`):

```powershell
cd c:\Users\visha\Desktop\security-posture-platform
.\scripts\smoke-roadmap.ps1
```

(The script is at `scripts/smoke-roadmap.ps1`; it switches to repo root so `docker compose` works.)

**Expected:** No throws; "Phase 0 + 1 smoke OK" and "Phase 2 placeholders OK".

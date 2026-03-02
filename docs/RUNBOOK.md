# SecPlat runbook

Short procedures for common operational issues.

---

## Overview / Alerts / Audit show 404 or "Asset not found in posture index"

**Cause:** The running API process was started before routes for `/posture/overview`, `/alerts`, or `/audit` were added.

**Fix:** Restart the API so it loads the latest routes, then refresh the app.

- Local: stop and start the API (e.g. `uvicorn` or `docker compose restart api`).
- After pulling new code, always restart the API.

---

## Health and readiness

- **Liveness:** `GET /health` — API process is up. Returns 200 and `{"status":"ok"}`.
- **Readiness:** `GET /ready` — Checks Postgres and OpenSearch. Returns 200 if both are reachable, 503 otherwise with `checks.postgres` / `checks.opensearch` set to the error. Use this for load balancers and Kubernetes readiness probes.
- **Metrics:** `GET /metrics` — Prometheus text format: `http_requests_total` (by method, path template, status class), `process_uptime_seconds`. No auth; expose only on internal/metrics port if needed.

---

## Ingestion stopped

**Symptom:** Assets not updating; "Last seen" times are old; posture stays stale.

1. Check ingestion container: `docker compose ps` (or your orchestrator). Restart if needed: `docker compose restart ingestion`.
2. Check logs: `docker compose logs -f ingestion`. Look for API/OpenSearch connection errors.
3. Ensure API and OpenSearch are up: `curl -s http://localhost:8000/ready`.
4. If ingestion runs as a cron or external job, verify the job is still scheduled and the network path to API and OpenSearch is open.

---

## OpenSearch down

**Symptom:** `/ready` fails with `opensearch` error; posture endpoints return 502/503.

1. Check OpenSearch: `curl -s http://localhost:9200/_cluster/health` (or your OPENSEARCH_URL).
2. Restart: `docker compose restart opensearch` (or equivalent). Wait for the cluster to go green.
3. If the cluster is red/yellow, check disk and node availability. Inspect logs: `docker compose logs opensearch`.
4. After recovery, ingestion will repopulate asset-status on the next run; no manual re-index needed for posture.

---

## Back up Postgres

1. Use `pg_dump` (or your managed DB backup). Example using env (e.g. from `.env`):
   ```bash
   # From repo root; requires POSTGRES_* in env
   ./scripts/backup_postgres.sh
   ```
   Or manually: `pg_dump -h localhost -p ${POSTGRES_PORT:-5432} -U $POSTGRES_USER -F c -f secplat_$(date +%Y%m%d_%H%M).dump $POSTGRES_DB`
2. Store dumps off-host and on a schedule (e.g. daily cron). Restore procedure below.

---

## Restore Postgres

1. Stop the API (and any service that writes to Postgres) to avoid writes during restore.
2. Restore from your backup (e.g. `pg_restore` or `psql < backup.sql`) into the same database name / schema expected by the API.
3. Restart the API and run migrations if you use them: apply any SQL in `infra/postgres/migrations/` that are newer than the backup.
4. Verify: `curl -s http://localhost:8000/ready` and log in to the UI.

---

## Reset admin password

1. **Using plain password (dev):** Set `ADMIN_PASSWORD` in the environment and restart the API. In production, prefer `ADMIN_PASSWORD_HASH` (see below).
2. **Using bcrypt hash (prod):**  
   Generate a hash:
   ```bash
   python -c "from passlib.context import CryptContext; print(CryptContext(schemes=['bcrypt']).hash('YOUR_NEW_PASSWORD'))"
   ```
   Set `ADMIN_PASSWORD_HASH=<that-value>` in your env (and optionally unset `ADMIN_PASSWORD`). Restart the API.
3. **Production:** If `ENV=prod` and you still have `ADMIN_PASSWORD=admin`, login will return 503 until you set `ADMIN_PASSWORD_HASH` or a non-default `ADMIN_PASSWORD`.

---

## API unreachable from frontend

**Symptom:** UI shows errors or "Loading..." forever; network tab shows failed requests to `/api/...`.

1. Confirm API is up: `curl -s http://localhost:8000/health`.
2. Confirm CORS and URL: frontend must call the correct API base (e.g. `NEXT_PUBLIC_API_URL` or proxy in `next.config.js`). For local dev, API often runs on port 8000.
3. Check auth: expired JWT will 401; user must log in again. If login fails, check API logs and auth config (see "Reset admin password" above).

---

## Data retention

Retention prunes old OpenSearch events and Postgres report snapshots. Configure via `EVENTS_RETENTION_DAYS` (default 90) and `SNAPSHOTS_RETENTION_KEEP` (default 500). Apply via API (requires auth) or cron.

- **Via API:** `curl -X POST -H "Authorization: Bearer <JWT>" http://localhost:8000/retention/apply`. Returns `events_deleted` and `snapshots_deleted`; 502 if OpenSearch or Postgres step failed.
- **Cron:** Call the same endpoint daily, e.g. `0 2 * * * curl -s -X POST -H "Authorization: Bearer $TOKEN" $API_URL/retention/apply`. Obtain JWT from login or use a service-account token.

---

## Rate limiting and audit

- **Login:** Limited to `RATE_LIMIT_LOGIN_PER_MINUTE` (default 5) attempts per client IP per minute; over limit returns 429.
- **Retention:** `POST /retention/apply` limited to `RATE_LIMIT_RETENTION_PER_HOUR` (default 10) per IP per hour; returns 429 when exceeded.
- **Audit:** Sensitive actions are logged to the `secplat.audit` logger: login (success/fail with reason), retention apply (user, counts). Use your log aggregator to search for `action=login` or `action=retention_apply`.

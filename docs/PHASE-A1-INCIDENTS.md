# Phase A.1: Incidents — Implementation & Proof

This document describes what was built for **Incidents** (SOC workflow: group alerts, state machine, notes, SLA) and how to run and verify it.

---

## What was built

### 1. Database

- **Migration:** `infra/postgres/migrations/007_incidents.sql`
  - `incidents`: id, title, severity, status, assigned_to, created_at, updated_at, resolved_at, closed_at, sla_due_at, metadata
  - `incident_alerts`: incident_id, asset_key, added_at, added_by (links alerts by asset_key to an incident)
  - `incident_notes`: id, incident_id, event_type (note | state_change | alert_added | resolution), author, body, details, created_at
- **Startup:** The API runs `db_migrate.run_startup_migrations()` on boot and creates these tables if missing (so no manual migration step is required for a running stack).

### 2. API (FastAPI)

- **GET /incidents** — List incidents (optional query: status, severity, assigned_to, limit, offset). Returns `{ total, items }` with alert_count per item.
- **GET /incidents/{id}** — One incident with `alerts` and `timeline` (notes + state_change + alert_added).
- **POST /incidents** — Create incident (body: title, severity, optional assigned_to, sla_due_at, asset_keys[]). Links listed asset_keys to the new incident.
- **PATCH /incidents/{id}/status** — Update status (new → triaged → contained → resolved → closed). Sets resolved_at/closed_at when appropriate; appends state_change to timeline.
- **POST /incidents/{id}/notes** — Add a note (body: body). Appends to timeline.
- **POST /incidents/{id}/alerts** — Link an alert (body: asset_key). Appends alert_added to timeline.
- **DELETE /incidents/{id}/alerts?asset_key=...** — Unlink an alert.

All endpoints require `Authorization: Bearer <token>` (same as rest of app). Audit log: incident_create, incident_status.

### 3. Frontend (Next.js)

- **Nav:** New link “Incidents” (between Alerts and Reports).
- **/incidents** — List page: filters (status, severity), “New incident” button, table (title, severity, status, assigned, alert count, SLA due, created). Click row → detail.
- **/incidents/[id]** — Detail page: title, severity, status with state buttons (new → triaged → contained → resolved → closed), linked alerts (with Unlink), “Link alert” (asset_key input), timeline (notes + state changes + alert_added), “Add note” form, details (created/updated/resolved/closed).

### 4. Tests (pytest)

- **File:** `services/api/tests/test_incidents.py`
- **Scope:** List (with/without filters), create, get one, update status, add note, link alert, unlink alert, 404, 401 unauthorized.
- **Requirement:** `POSTGRES_DSN` (and optionally `ADMIN_USERNAME`, `ADMIN_PASSWORD`) must be set so the test client can start the app and log in.

---

## How to run the stack (for manual proof)

1. From repo root:
   ```bash
   docker compose up -d --build
   ```
2. Wait for API to be healthy:
   ```bash
   curl -s http://localhost:8000/health
   ```
3. Open the UI: http://localhost:3002 — log in (admin/admin), click **Incidents**.
4. Create an incident, open it, change status, add a note, link an alert (e.g. an asset_key from your Alerts page), then unlink.

---

## How to run the API tests (proof that endpoints work)

Tests need a running Postgres and env vars. Two options:

### Option A: Run tests inside the API container (recommended)

```bash
docker compose exec api bash -c 'cd /app && PYTHONPATH=/app pytest tests/test_incidents.py -v'
```

The API container already has `POSTGRES_DSN` and admin credentials from compose. (`PYTHONPATH=/app` is needed so `from app.main import app` resolves; it’s also set via `pythonpath = ["."]` in pyproject.toml after a rebuild.)

### Option B: Run tests on the host

1. Install API deps (from repo root): `cd services/api && pip install -e .` (or `uv sync`). This installs FastAPI, pytest, etc.
2. Ensure Postgres is reachable and migrations have run (e.g. stack was started with `docker compose up`).
3. Set env (adjust if your DSN differs):
   - **Linux/macOS:** `export POSTGRES_DSN="postgresql://secplat:secplat@127.0.0.1:5432/secplat"` (and optionally API_SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD).
   - **Windows PowerShell:** `$env:POSTGRES_DSN="postgresql://secplat:secplat@127.0.0.1:5432/secplat"`.
4. From `services/api`: `pytest tests/test_incidents.py -v`.

If `POSTGRES_DSN` is not set, the incident tests are **skipped** (see `pytestmark` in `test_incidents.py`).

---

## Test cases (what the tests assert)

| Test | What it does | Proof |
|------|----------------|------|
| `test_incidents_list` | GET /incidents with auth | 200, body has `total` and `items` |
| `test_incidents_list_with_filters` | GET /incidents?status=new&severity=medium&limit=5 | 200 |
| `test_incidents_create_and_get` | POST /incidents, then GET /incidents/{id} | 201 with title/severity/status; 200 with same id, alerts[], timeline[] |
| `test_incidents_update_status` | Create incident, PATCH status to triaged, GET again | 200, status=triaged; timeline has state_change |
| `test_incidents_add_note` | Create incident, POST note, GET incident | 201 note with body; timeline has note |
| `test_incidents_link_and_unlink_alert` | Create incident, POST link alert, GET (alerts include it), DELETE unlink, GET (alerts don’t) | 201 link; 200 unlink; alerts list updates |
| `test_incidents_get_404` | GET /incidents/999999 | 404 |
| `test_incidents_unauthorized` | GET /incidents without Authorization | 401 |

---

## Checklist for “proof it works”

- [ ] Stack starts: `docker compose up -d --build` and `curl http://localhost:8000/health` returns OK.
- [ ] Incidents tables exist: either run `007_incidents.sql` manually or restart API so startup migrations create them.
- [ ] UI: Log in at http://localhost:3002, open Incidents, create an incident, open it, change status, add note, link/unlink an alert.
- [ ] API tests: `docker compose exec api bash -c 'cd /app && pytest tests/test_incidents.py -v'` — all tests pass or skip (only skip if POSTGRES_DSN is unset).

---

## Optional: Run migration 007 by hand

If you prefer to run the SQL file yourself (e.g. for an existing DB that predates startup migrations for incidents):

```bash
psql "$POSTGRES_DSN" -f infra/postgres/migrations/007_incidents.sql
```

This adds CHECK constraints and the trigger; the API’s startup migration only ensures the tables and indexes exist.

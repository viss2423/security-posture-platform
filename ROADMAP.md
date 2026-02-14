# Corporate Upgrade Roadmap

This document tracks the enterprise wishlist and implementation status. Work is done **phase by phase** with tests and proof for each.

---

## Phase A — Fast, high impact

| # | Item | Status | Notes |
|---|------|--------|--------|
| A.1 | **Incidents** (alerts → incidents, SLA timers, notes, ownership) | ✅ Done | DB + API + UI + tests |
| A.2 | **Findings pipeline** (lifecycle + risk acceptance, expiry) | ✅ Done | DB + API + UI |
| A.3 | **Executive reports + scheduled snapshots** (PDF/CSV, “what changed”) | ✅ Done | PDF export, scheduled snapshots (env), what-changed compare |
| A.4 | **Admin: Audit log + Users** (Audit log UI, Users & Access) | ✅ Done | Audit filters + request_id + actions from API; GET /auth/users; Users page |

---

## Phase B — Enterprise hardening

| # | Item | Status | Notes |
|---|------|--------|--------|
| B.1 | **SSO (OIDC) + RBAC** (Entra/Okta/Google, viewer/analyst/admin) | ✅ Done | RBAC + OIDC: GET /auth/oidc/login, /auth/oidc/callback, /auth/config; users must exist in DB (username = IdP preferred_username or email) |
| B.2 | **Policy-as-code scoring** (YAML/Rego, bundles, approval) | ✅ Done | policy_bundles table; YAML rules (asset_status, posture_score_min, no_open_findings); CRUD, approve (admin), evaluate; Policy page |
| B.3 | **Job runner + job logs UI** (Celery/RQ/Arq, retry, logs) | ✅ Done | scan_jobs table (log_output, retry_count); GET /jobs, GET /jobs/:id, POST /jobs, POST /jobs/:id/retry; worker writes logs; Jobs page with list, detail, retry |
| B.4 | **Integrations** (Slack interactive, Jira ticket from incident) | ✅ Done | POST /incidents/:id/jira (create issue, store in metadata); POST /integrations/slack/interactions (verify signing, handle create_jira); Incident detail: Create Jira + View in Jira |

---

## Full enterprise wishlist (reference)

- **1) IAM:** SSO + SCIM + RBAC, HttpOnly cookie sessions, Users & Access, Roles & Permissions, session management
- **2) Multi-tenant:** orgs, teams, row-level scoping
- **3) Policy-as-code:** Git policies, approval workflow, versioning, simulate impact
- **4) SOC workflows:** Incidents (state machine, SLA, timeline, RCA), alert correlation/dedup, suppression rules, flapping
- **5) Controls framework:** CIS/NIST mapping, control pass rate, findings lifecycle + risk acceptance
- **6) Asset discovery:** CSV import, tags, dependency graph, blast radius
- **7) Reporting:** Scheduled reports, PDF+CSV, “what changed”, audit log v2 (tamper-evident, export)
- **8) Platform:** Job runner, OpenTelemetry, TLS, secrets, rate-limit at gateway
- **9) Integrations:** Slack interactive, Jira, webhooks, SIEM export
- **10) UI polish:** Global filters, saved views, column manager, “explain score”, compare time ranges, nav structure

---

## How to run and verify each phase

See per-phase instructions:

- **Phase A.1 (Incidents):** [docs/PHASE-A1-INCIDENTS.md](docs/PHASE-A1-INCIDENTS.md) — migrations, API, UI, test cases, proof.
- **Phase A.2 (Findings lifecycle):** DB columns `accepted_risk_*` (migration 008 + startup); API `PATCH /findings/{id}/status`, `POST /findings/{id}/accept-risk`; UI Findings page: status filter (open / in_progress / remediated / accepted_risk), status dropdown per row, “Accept risk” modal (reason + review-by date).
- **Phase A.3 (Executive reports):** API `GET /posture/reports/executive.pdf` (optional `snapshot_id`); `GET /posture/reports/what-changed?from_id=&to_id=` (to_id omitted = current); scheduled snapshots via `ENABLE_SCHEDULED_SNAPSHOTS=true` and `SCHEDULED_SNAPSHOT_INTERVAL_HOURS=24`. Reports page: Download PDF (current or snapshot), What changed (compare two snapshots or snapshot vs current), CSV export unchanged.
- **Phase A.4 (Admin):** Audit log: API returns `actions` (distinct list for filter); UI has Request ID column, action dropdown from API; audit events for `finding_status` and `accept_risk` added. Users & Access: `GET /auth/users` returns configured admin (username, role, source); Users page lists them and links to Audit log.
- **Phase B.3 (Job runner + logs):** `scan_jobs` table (job_type, target_asset_id, status queued|running|done|failed, created_at, started_at, finished_at, error, log_output, retry_count). API: GET `/jobs` (list, optional ?status=), GET `/jobs/:id` (detail with log_output), POST `/jobs` (create, analyst/admin), POST `/jobs/:id/retry` (re-queue failed/done, analyst/admin). Worker (worker-web) appends to log_output; finish_job sets status and optional log line. UI: Jobs page (list, status filter, detail with logs, Retry for failed/done).

- **Phase B.2 (Policy-as-code):** `policy_bundles` table (name, description, definition YAML, status draft|approved, approved_at/by). YAML: `rules` list with `id`, `name`, `type`, `params`. Rule types: `asset_status` (params.status), `posture_score_min` (params.min_score), `no_open_findings` (params.severity). API: GET/POST/PATCH/DELETE `/policy/bundles`, GET `/policy/bundles/:id`, POST `/policy/bundles/:id/approve` (admin), POST `/policy/bundles/:id/evaluate`. Viewers see approved only; analysts/admins create/edit drafts; admin approves. UI: Policy page (list, create, view, edit draft, approve, evaluate, delete).

- **Phase B.4 (Integrations):** Jira: set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY (or pass project_key in body). POST `/incidents/:id/jira` creates a Jira issue (summary=title, description=incident + link), stores `jira_issue_key` and `jira_issue_url` in incident metadata; returns existing if already created. UI: Incident detail shows "Create Jira ticket" (optional project key) and "View in Jira" when created. Slack interactive: set SLACK_SIGNING_SECRET; configure Slack app Interactivity & Shortcuts Request URL to `https://your-api/integrations/slack/interactions`. POST `/integrations/slack/interactions` verifies X-Slack-Signature, parses payload; on block_actions with action_id `create_jira` and value=incident_id, creates Jira ticket and optionally updates message via response_url.

- **Phase B.1 (RBAC + OIDC):** `users` table (username, role, disabled). JWT includes `role`; login from users table or config admin. OIDC: set OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI (API callback URL), FRONTEND_URL; GET /auth/config returns `oidc_enabled`; GET /auth/oidc/login redirects to IdP; GET /auth/oidc/callback exchanges code, looks up user by preferred_username/email, issues JWT, redirects to FRONTEND_URL/login#access_token=.... Users must exist in DB before SSO login.

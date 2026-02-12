# SecPlat product roadmap: MVP → product-ready

This doc maps the "professional platform" wishlist to a build order. **Phase 1** is in progress; later phases are sequenced for dependency and impact.

---

## Phase 1 — Professional dashboard (current)

**Goal:** Overview that tells a story; filters everywhere so it feels like a real tool.

- [x] Backend: filter support on `/posture` and `/posture/summary` (environment, criticality, owner, status)
- [x] Backend: `/posture/overview` (exec strip, trend vs yesterday, top drivers)
- [x] Backend: `/posture/trend` (time series from report snapshots for charts)
- [ ] Frontend: global filter bar (sticky), filter context
- [ ] Frontend: Overview v2 — exec strip, trend chart, top drivers panels
- [ ] Wire Overview + Assets (and downstream) to use global filters

**Data:** Report snapshots table + OpenSearch posture list; trend from snapshots (optional: hourly auto-snapshot for denser charts).

---

## Phase 2 — Alert lifecycle

**Goal:** Alerts as a workflow (ACK, suppress, assign, resolve).

- DB: `alert_events` or extend alerts table (state: firing | acked | suppressed | resolved, assigned_to, ack_reason, suppressed_until, resolved_at)
- API: POST ack/suppress/resolve/assign; GET alerts with state filter
- UI: Alerts page with tabs (Firing / Acknowledged / Resolved / Suppressed), actions, dedupe by asset+reason

**Depends on:** Phase 1 (filters can apply to alerts list).

---

## Phase 3 — Findings scanner + Findings UI

**Goal:** Security posture beyond uptime (TLS expiry, headers, etc.).

- Ingestion: New job producing findings (TLS expiry, HSTS, security headers, redirect, server header)
- DB: Findings already exist; ensure schema supports category/severity/confidence
- API: GET /findings (filter by asset, severity, category), GET asset detail includes findings
- UI: Findings page with filters; Asset detail "Findings" tab

**Depends on:** None; can run in parallel after Phase 1.

---

## Phase 4 — Asset console upgrade

**Goal:** Enterprise grid (column picker, saved views, bulk actions).

- API: Already have PATCH asset; add bulk PATCH (owner, criticality, is_active)
- DB: Optional `saved_views` (user_id, name, filters + column visibility)
- UI: Column picker, saved views dropdown, bulk select + actions, export selected

**Depends on:** Phase 1 (filters).

---

## Phase 5 — Asset detail tabs

**Goal:** Summary / Timeline / Findings / Evidence / Config / History as tabs.

- API: No new endpoints; reuse detail + timeline + findings
- UI: Tabbed layout; each tab clean and scannable

**Depends on:** Phase 3 for Findings tab to be meaningful.

---

## Phase 6 — Incident management

**Goal:** Alerts → incidents (timeline, impacted assets, worklog).

- DB: `incidents` (created from alert or manual), `incident_events` (worklog, state changes)
- API: CRUD incidents, add events, link to alerts/assets
- UI: Incidents list and detail (timeline, root-cause hint, evidence, worklog)

**Depends on:** Phase 2 (alert lifecycle).

---

## Phase 7 — Policy-as-code scoring

**Goal:** Configurable policies (YAML); "why score changed" and "which policies triggered".

- Config: YAML policies (stale threshold, http 5xx = red, latency p95, TLS expiry)
- API: Score explanation endpoint (which policies fired, contribution to score)
- UI: Score explanation section; optional policy editor (admin)

**Depends on:** Phase 3 (findings) for TLS/headers policies.

---

## Phase 8 — Audit log UI

**Goal:** Show audit events in the UI (login, retention, asset edits, alert ack).

- Backend: Already logging; optional store in DB or query logs
- API: GET /audit (filter by user, action, asset, time)
- UI: Audit log page with filters and table

**Depends on:** None (backend audit already in place).

---

## Phase 9 — RBAC + orgs/teams

**Goal:** Multi-tenant; roles (viewer / analyst / admin); restrict edit/retention.

- DB: orgs, teams, user_roles, resource permissions
- API: Auth returns role/org; endpoints check permission; filter data by org/team
- UI: Team/org switcher; hide/disable actions by role

**Depends on:** Cookie auth (Phase 12) recommended before RBAC.

---

## Phase 10 — Empty / loading states

**Goal:** No assets → CTA "Add asset"; no data → "Ingestion hasn't run"; API down → actionable steps.

- UI only: Copy and components for each state; reuse ApiStatusBanner and skeletons

**Depends on:** None; can be done anytime.

---

## Phase 11 — Cookie auth + refresh tokens

**Goal:** HttpOnly cookies, refresh rotation, CSRF for state-changing requests.

- Backend: Set cookie on login; refresh endpoint; CSRF token or SameSite
- Frontend: No localStorage token; send cookies; handle refresh on 401

**Depends on:** None; unblocks Phase 9 (RBAC) and hardens security.

---

## Phase 12 — Background job queue + job logs

**Goal:** Async jobs (scan now, recompute score, findings run); job states and logs in UI.

- Backend: Celery/RQ/Arq; job table (queued/running/success/fail); logs
- API: POST /jobs/scan-asset, GET /jobs, GET /jobs/:id/logs
- UI: Job list and detail; "Scan now" on asset

**Depends on:** None; ingestion can stay as-is; queue for on-demand and future scans.

---

## Phase 13 — Platform observability

**Goal:** Grafana dashboard for the platform (API latency, request rate, error rate, ingestion last run).

- Backend: /metrics already exists; optional more labels or logs correlation
- Infra: Grafana datasource for API metrics; dashboard JSON
- Logs: Request-id in logs; optional export to Loki for correlation

**Depends on:** None.

---

## Phase 14 — Docker + secrets hardening

**Goal:** Non-root, drop caps, read-only FS, no plaintext secrets in prod.

- Docker: USER, read-only root, capability drop; secrets via Docker secrets or Vault
- Env: No API_SECRET_KEY or DB URL in env in prod

**Depends on:** None.

---

## Build order summary

| Order | Phase | Focus |
|-------|--------|--------|
| 1 | **Dashboard + filters** | Overview v2, global filters, trend, top drivers |
| 2 | Alert lifecycle | ACK, suppress, assign, resolve, states |
| 3 | Findings | Scanner + Findings UI |
| 4 | Asset console | Column picker, saved views, bulk actions |
| 5 | Asset tabs | Summary / Timeline / Findings / Evidence / Config / History |
| 6 | Incidents | Alerts → incidents, worklog |
| 7 | Policy-as-code | YAML policies, score explanation |
| 8 | Audit log UI | Audit events in UI |
| 9 | RBAC + orgs | Roles, teams, multi-tenant |
| 10 | Empty/loading states | Polish |
| 11 | Cookie auth | HttpOnly, refresh, CSRF |
| 12 | Job queue | Async jobs + job logs UI |
| 13 | Platform observability | Grafana for API |
| 14 | Docker hardening | Non-root, secrets |

---

## Checklist (from wishlist)

**UI polish**

- [ ] global filters — **Phase 1**
- [ ] trends + history charts — **Phase 1**
- [ ] saved views — **Phase 4**
- [ ] asset tabs — **Phase 5**
- [ ] anomaly highlighting — **Phase 7** (with score explanation)
- [ ] score explanation — **Phase 7**

**Platform features**

- [ ] alert lifecycle + dedupe — **Phase 2**
- [ ] incidents view — **Phase 6**
- [ ] findings scanner — **Phase 3**
- [ ] policy-as-code scoring — **Phase 7**
- [ ] audit log UI — **Phase 8**
- [ ] RBAC + orgs — **Phase 9**

**Engineering**

- [ ] cookie auth + refresh tokens — **Phase 11**
- [ ] job queue + job logs — **Phase 12**
- [ ] platform monitoring dashboard — **Phase 13**
- [ ] container hardening + secrets — **Phase 14**

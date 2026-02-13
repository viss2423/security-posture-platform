# Corporate Upgrade Roadmap

This document tracks the enterprise wishlist and implementation status. Work is done **phase by phase** with tests and proof for each.

---

## Phase A — Fast, high impact

| # | Item | Status | Notes |
|---|------|--------|--------|
| A.1 | **Incidents** (alerts → incidents, SLA timers, notes, ownership) | ✅ In progress | DB + API + UI + tests |
| A.2 | **Findings pipeline** (lifecycle: open / in_progress / remediated / accepted_risk) | ⬜ Pending | |
| A.3 | **Executive reports + scheduled snapshots** (PDF/CSV, “what changed”) | ⬜ Pending | |
| A.4 | **Admin: Audit log + Users** (Audit log UI, Users & Access) | ⬜ Pending | |

---

## Phase B — Enterprise hardening

| # | Item | Status | Notes |
|---|------|--------|--------|
| B.1 | **SSO (OIDC) + RBAC** (Entra/Okta/Google, viewer/analyst/admin) | ⬜ Pending | |
| B.2 | **Policy-as-code scoring** (YAML/Rego, bundles, approval) | ⬜ Pending | |
| B.3 | **Job runner + job logs UI** (Celery/RQ/Arq, retry, logs) | ⬜ Pending | |
| B.4 | **Integrations** (Slack interactive, Jira ticket from incident) | ⬜ Pending | |

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

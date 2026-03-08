# API Baseline Contract (Frontend-Used)

This file freezes the currently supported API contract consumed by the frontend.

Baseline date: `2026-03-06`  
Contract scope: endpoints currently used by `services/frontend/lib/api.ts`.

## Compatibility Rules

1. Existing paths and HTTP methods in this document are stable.
2. Existing response fields are stable unless marked optional.
3. Breaking changes are not allowed in-place.
4. New functionality must be additive:
   - new endpoints
   - new optional request parameters
   - new optional response fields
5. Deprecations require:
   - a replacement endpoint
   - compatibility period
   - release note in `docs/`.

## Baseline Endpoint Groups

### Auth and Session
- `POST /auth/login`
- `GET /auth/config`
- `GET /auth/me`
- `GET /auth/users`
- `GET /auth/oidc/login`
- `GET /auth/oidc/callback`

### Posture and Reports
- `GET /posture`
- `GET /posture/summary`
- `GET /posture/overview`
- `GET /posture/trend`
- `GET /posture/{asset_key}`
- `GET /posture/{asset_key}/detail`
- `GET /posture/reports/summary`
- `POST /posture/reports/snapshot`
- `GET /posture/reports/history`
- `GET /posture/reports/history/{snapshot_id}`
- `GET /posture/reports/what-changed`
- `GET /posture/reports/executive.pdf`
- `POST /posture/alert/send`

### Assets
- `GET /assets/`
- `GET /assets/{asset_id}`
- `GET /assets/by-key/{asset_key}`
- `POST /assets/`
- `PATCH /assets/by-key/{asset_key}`
- `DELETE /assets/by-key/{asset_key}`
- `POST /assets/{asset_id}/verify`

### Findings and Risk Labels
- `GET /findings/`
- `POST /findings/`
- `PATCH /findings/{finding_id}/status`
- `POST /findings/{finding_id}/accept-risk`
- `GET /findings/repository-summary`
- `GET /findings/dependency-risk`
- `GET /findings/{finding_id}/risk-labels`
- `POST /findings/{finding_id}/risk-labels`

### Jobs
- `GET /jobs`
- `GET /jobs/{job_id}`
- `POST /jobs`
- `POST /jobs/{job_id}/retry`
- `POST /jobs/{job_id}/execute` (internal worker execution endpoint; service/admin only)

### Alerts
- `GET /alerts`
- `POST /alerts/ack`
- `POST /alerts/suppress`
- `POST /alerts/resolve`
- `POST /alerts/assign`

### Incidents
- `GET /incidents`
- `GET /incidents/{incident_id}`
- `POST /incidents`
- `PATCH /incidents/{incident_id}/status`
- `POST /incidents/{incident_id}/notes`
- `POST /incidents/{incident_id}/alerts`
- `DELETE /incidents/{incident_id}/alerts`
- `POST /incidents/{incident_id}/jira`

### Telemetry
- `GET /telemetry/summary`
- `GET /telemetry/events`
- `GET /telemetry/assets/{asset_key}`
- `POST /telemetry/ingest`
- `GET /telemetry/alerts`
- `POST /telemetry/alerts/ack`
- `POST /telemetry/alerts/suppress`
- `POST /telemetry/alerts/resolve`
- `POST /telemetry/alerts/assign`

### Detections
- `GET /detections/rules`
- `POST /detections/rules`
- `PATCH /detections/rules/{rule_id}`
- `POST /detections/rules/{rule_id}/test`
- `GET /detections/runs`

### Threat Intel
- `GET /threat-intel/summary`
- `GET /threat-intel/assets/{asset_key}`

### Attack Lab and Cyber Range
- `GET /attack-lab/tasks`
- `POST /attack-lab/run`
- `POST /attack-lab/scan-asset`
- `GET /attack-lab/runs`
- `GET /attack-lab/runs/{run_id}`
- `GET /cyber-range/missions`
- `POST /cyber-range/missions/{mission_id}/launch`

### Policy
- `GET /policy/bundles`
- `GET /policy/bundles/{bundle_id}`
- `POST /policy/bundles`
- `PATCH /policy/bundles/{bundle_id}`
- `POST /policy/bundles/{bundle_id}/approve`
- `POST /policy/bundles/{bundle_id}/evaluate`
- `GET /policy/bundles/{bundle_id}/evaluations`
- `GET /policy/bundles/{bundle_id}/evaluations/{evaluation_id}`
- `DELETE /policy/bundles/{bundle_id}`

### AI Endpoints
- Incident summary:
  - `GET /ai/incidents/{incident_id}/summary`
  - `POST /ai/incidents/{incident_id}/summary/generate`
- Policy summary:
  - `GET /ai/policy/evaluations/{evaluation_id}/summary`
  - `POST /ai/policy/evaluations/{evaluation_id}/summary/generate`
- Alert guidance:
  - `GET /ai/alerts/{asset_key}/guidance`
  - `POST /ai/alerts/{asset_key}/guidance/generate`
- Job triage:
  - `GET /ai/jobs/{job_id}/triage`
  - `POST /ai/jobs/{job_id}/triage/generate`
- Asset diagnosis:
  - `GET /ai/assets/{asset_key}/diagnosis`
  - `POST /ai/assets/{asset_key}/diagnose`
- Finding explanation:
  - `GET /ai/findings/{finding_id}/explanation`
  - `POST /ai/findings/{finding_id}/explain`
- Posture anomalies:
  - `GET /ai/posture/anomalies`
  - `POST /ai/posture/anomalies/detect`

### ML Risk Scoring
- `GET /ai/risk-scoring/status`
- `GET /ai/risk-scoring/evaluation`
- `GET /ai/risk-scoring/snapshots`
- `GET /ai/risk-scoring/snapshots/{snapshot_id}`
- `POST /ai/risk-scoring/snapshots`
- `POST /ai/risk-scoring/threshold`
- `POST /ai/risk-scoring/bootstrap-labels`
- `POST /ai/risk-scoring/train`

### Audit and Suppression
- `GET /audit`
- `GET /suppression/maintenance-windows`
- `POST /suppression/maintenance-windows`
- `DELETE /suppression/maintenance-windows/{window_id}`
- `GET /suppression/rules`
- `POST /suppression/rules`
- `DELETE /suppression/rules/{rule_id}`

## Additive Change Template

When adding new API surface, include:
1. endpoint path and method
2. request schema
3. response schema
4. role restrictions
5. audit action emitted
6. backward compatibility impact (must be `none` for existing clients)

# SecPlat Corporate Roadmap — Multi-Service Workflow (Phased Plan)

## Guiding Principles

1. **State vs events:** OpenSearch stores *events* and *derived state* separately (you already do this).
2. **Async by default:** heavy work runs via **jobs/queue**, not inside the API request path.
3. **Separation of concerns:** scanning, derivation, correlation, notifications are **separate services**.
4. **Failure isolation:** any worker crash must not affect API availability.
5. **Kubernetes only after** services are cleanly split and queue-based.

---

## Phase 0 — Baseline Hardening (1–2 days)

**Goal:** Stabilize the current system and set standards before splitting services.

### Deliverables

- Add/confirm:
  - consistent structured logs (JSON) across API/worker/scanner
  - request_id propagation (`X-Request-Id`)
  - error handling conventions (retryable vs non-retryable)
- Define “canonical event formats” (simple JSON schema in `/docs/contracts/`)

### Acceptance Criteria

- Every service logs: `timestamp, service, request_id, asset_key, action, status`
- API endpoints are stable and documented (OpenAPI already helps)

---

## Phase 1 — Introduce a Real Queue (Core Enabler)

**Goal:** Replace DB polling patterns for async workloads with a queue so workers can scale and recover cleanly.

### Choice (recommended)

- **Redis Streams** (simplest, lightest)  
- Alternative: RabbitMQ (classic), Kafka/Redpanda (later)

### New Services

- **secplat-queue**: Redis container (or managed later)

### New Concepts

- `job` messages go to a stream, not just `scan_jobs` DB rows
- Retry + DLQ become first-class

### Topics / Streams (initial)

- `secplat.jobs.scan`
- `secplat.jobs.derive`
- `secplat.events.notify`

### Deliverables

- A minimal queue library in Python used by workers:
  - `publish(stream, message)`
  - `consume(stream, group, handler)`
  - retry with exponential backoff
  - dead-letter stream on max retries

### Acceptance Criteria

- You can publish a scan job → worker consumes → updates DB + findings
- If worker dies mid-job, job is retried safely
- Queue depth is visible (simple API endpoint `/queue/health` or Redis INFO)

---

## Phase 2 — Service Split MVP (Corporate Minimum)

**Goal:** Split the system into the smallest set of services that feels enterprise-grade.

### 2.1 secplat-deriver (Posture Derivation Service)

Replace `build_asset_status.sh`

**Responsibilities:**

- Read latest events from `secplat-events`
- Apply derivation rules:
  - **debounce window** (avoid flapping)
  - **confidence score**
  - last-good-state tracking
- Write one doc per asset to `secplat-asset-status`

**Inputs / Outputs:**

- Input: OpenSearch `secplat-events`
- Output: OpenSearch `secplat-asset-status`

**Acceptance Criteria:**

- Down-asset alert becomes stable: no “always firing”; flapping assets are classified separately
- Deriver runs continuously OR as a CronJob

---

### 2.2 secplat-scan-workers (Worker Pool)

Replace scanner + worker-web split with a single scalable worker pool (you can keep types internally).

**Responsibilities:**

- Consume `secplat.jobs.scan`
- Run scan types: `web_exposure`, `tls_headers`, `health_http`
- Submit findings to API (`POST /findings`)
- Append logs to `scan_jobs.log_output`

**Acceptance Criteria:**

- Run N replicas and see throughput improve
- Worker never needs DB access if API handles writes (preferred)
- Scans are idempotent (same input won’t create duplicates)

---

### 2.3 secplat-notifier (Notifications)

Move Slack/Twilio/Jira outbound out of the API.

**Responsibilities:**

- Consume `secplat.events.notify`
- Send Slack/Twilio alerts
- Post updates to incident channels
- Handle rate limiting/backoff

**Acceptance Criteria:**

- API never directly calls Slack/Twilio for routine alerts
- Notification failures don’t impact API response latency

---

## Phase 3 — Corporate SOC Layer (Correlation + Noise Control)

**Goal:** Make your platform behave like a SOC tool: dedupe, correlate, incident-driven.

### 3.1 secplat-correlator (Incident Engine)

**Responsibilities:**

- Consume: new findings, posture status changes, alert events
- Cluster into incidents:
  - dedupe by `finding_key`, `asset_key`, time window
  - correlation rules (same asset, same category, same root cause)
- Manage incident lifecycle: create / update / close; attach evidence

**Acceptance Criteria:**

- Alerts page becomes “Incidents first”
- 20 repeated alerts become 1 incident with timeline

---

### 3.2 Maintenance Windows + Suppression Rules

**Deliverables:**

- DB tables: `maintenance_windows`, `suppression_rules`
- UI for: create suppression (time-bound), schedule downtime

**Acceptance Criteria:**

- Known maintenance doesn’t produce incidents/alerts
- Suppression is auditable

---

## Phase 4 — Policy-as-Code v2 (Compliance Grade)

**Goal:** Move from YAML-only evaluation to “real” compliance evaluation with evidence.

**Option A (fast, good):** Enhance existing YAML evaluator

- Add rule types: `require_header: CSP`, `tls_min_version: 1.2`, `no_critical_findings`
- Save evaluation results + evidence

**Option B (most corporate):** Add OPA/Rego service

- `secplat-policy` (OPA)
- API calls policy service to evaluate posture

**Acceptance Criteria:**

- Every policy violation has: rule id, evidence fields, timestamp, who approved policy bundle

---

## Phase 5 — Kubernetes Migration (Only Now)

**Goal:** Use K8s for scaling + isolation + reliability.

### Minimal K8s Objects

- **Deployments:** secplat-api, secplat-deriver, secplat-scan-workers (HPA), secplat-notifier, secplat-correlator
- **Stateful/External:** Postgres, OpenSearch (keep outside first if desired)
- **CronJobs:** scheduled snapshots, ingestion runs (if needed)

### Security Controls (corporate signals)

- **NetworkPolicies:** workers cannot reach Postgres; only API can reach Postgres
- **Secrets:** move from `.env` to K8s secrets
- **Pod security:** runAsNonRoot, readOnlyRootFilesystem, drop capabilities

### Acceptance Criteria

- Scale workers horizontally by queue depth
- Deriver + notifier independent rollouts
- One service failing does not degrade core API

---

## Service Contracts (Document This Once)

See [docs/contracts/](contracts/) for:

- **Standard Event Envelope** — [event-envelope.json](contracts/event-envelope.json)
- **Idempotency Keys** — [idempotency-keys.md](contracts/idempotency-keys.md)

---

## Branch Flow (per phase)

1. `feat/queue-redis-streams`
2. `feat/deriver-service`
3. `feat/scan-worker-pool`
4. `feat/notifier-service`
5. `feat/correlator-incidents`
6. `feat/policy-v2`
7. `feat/k8s-migration`

### For each branch

- implement → run secure checks → run stack locally → commit → document in README + `/docs/architecture.md`

### Definition of Done (every phase)

- docker-compose runs clean
- key endpoints stable
- logs visible
- one Grafana dashboard updated to reflect new service
- at least smoke tests per service

---

## Minimal MVP Split (implement first)

Fastest “corporate jump” with minimal risk:

1. **Redis Streams queue**
2. **Deriver service**
3. **Scan worker pool**
4. **Notifier**

After that you get: real async architecture, clear service boundaries, scalable workers, stable posture/alerts.

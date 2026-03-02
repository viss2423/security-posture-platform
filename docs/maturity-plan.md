# SecPlat Platform Maturity Plan

This document tracks the corporate-grade maturity phases and the sprint order for implementation.

---

## Phase 1 -- Zero-Trust isolation + least privilege

### Goal
-- Enforce service boundaries so compromise of one workload does not become full-platform compromise.

### Build
-- Separate service identities for worker, scanner, deriver, notifier, correlator.
-- Split OpenSearch credentials into read and write paths.
-- Restrict network paths (workers/scanners cannot access Postgres directly).
-- Require authenticated service-to-service calls on internal endpoints.

### Definition of Done
-- Worker/scanner cannot connect to Postgres directly.
-- OpenSearch writer credentials are not mounted in read-only services.
-- Audit logs capture `actor_type=service` and `actor_name`.

---

## Phase 2 -- Queue reliability (reclaim + DLQ + recovery)

### Goal
-- Ensure asynchronous jobs survive crashes, retries, and poison messages.

### Build
-- Consumer-group pending reclaim (`XPENDING` + `XAUTOCLAIM`).
-- DLQ stream for exhausted retries.
-- Bounded retries with explicit attempt count.
-- Stale-running DB recovery job (`running` past TTL -> `queued`, `retry_count++`).

### Definition of Done
-- Killing worker during processing does not lose jobs.
-- Pending messages are reclaimed automatically.
-- Poison messages land in DLQ with reason metadata.
-- Stale `running` jobs are recovered automatically.

---

## Phase 3 -- Detection engineering pipeline

### Goal
-- Treat policies and detections as versioned, testable code.

### Build
-- `rules/` structure with metadata and versions.
-- Rule unit tests with deterministic fixtures.
-- Rollout stages (`draft` -> `canary` -> `active`).
-- Rule simulator endpoint over recent historical data.

### Definition of Done
-- CI validates rule fixtures and expected fire/no-fire behavior.
-- Canary mode reports "would have fired" without creating incidents.

---

## Phase 4 -- SOC-grade correlation

### Goal
-- Collapse alert noise into context-rich incidents.

### Build
-- Dedupe and clustering by `(asset_key, category, signature, window)`.
-- Incident timeline as first-class event stream.
-- Root-cause hypothesis field from dominant evidence.
-- Blast radius expansion via asset dependency relationships.

### Definition of Done
-- Alert storms collapse into incident clusters.
-- Incident timeline is complete and evidence-linked.
-- Blast radius is computed and surfaced.

---

## Phase 5 -- Evidence-grade reporting

### Goal
-- Produce tamper-evident, audit-defensible outputs.

### Build
-- SHA-256 hash for report artifacts and evidence packs.
-- Append-only audit model (no in-place overwrite semantics).
-- Exportable evidence pack (JSON + narrative PDF).

### Definition of Done
-- Every report/export has a stored hash and reproducible evidence references.
-- Incident evidence packs can be exported and verified.

---

## Phase 6 -- Distributed observability (OpenTelemetry)

### Goal
-- Provide end-to-end traceability across API, queue, workers, correlator, notifier.

### Build
-- Trace context propagation through Redis messages.
-- Instrument spans for API, DB, OpenSearch, queue, worker processing.
-- Export traces to Tempo (and correlate with logs/metrics).

### Definition of Done
-- A single incident can be traced end-to-end across services.
-- Logs and traces share `trace_id`/`request_id`.

---

## Sprint Order

## Sprint A -- Correctness and control plane hardening
-- RBAC consistency and field redaction for sensitive resources.
-- OIDC verification correctness (issuer/audience/nonce/signature).
-- Queue reclaim + DLQ + stale-running recovery.
-- Progress: queue reclaim/DLQ now enabled on worker, notifier, and correlator; incident idempotency key wired (`incident_key`); OIDC discovery and id_token verification hardened (issuer match, secure endpoints, alg allow-list, azp checks, JWKS refresh).

## Sprint B -- Isolation and observability foundations
-- Service identities and least-privilege network/data paths.
-- Trace propagation and OTEL instrumentation.
-- Progress: service identities wired and per-role K8s egress policies split (worker/deriver/notifier/correlator/ingestion).

## Sprint C -- SOC intelligence
-- Detection engineering pipeline.
-- Correlation clustering and blast radius.

## Sprint D -- Compliance evidence
-- Tamper-evident reporting and evidence pack exports.

# ADR 0001: GA Topology and Runtime Lane

## Status

Accepted

## Context

The repository contained a contradiction in the supported worker topology:

- `worker-web` owned job claims directly in Postgres
- hardened Kubernetes policy blocked worker access to Postgres
- worker deployment still injected a worker Postgres DSN

That split made the production lane ambiguous and undermined the least-privilege posture.

## Decision

- GA path is single-tenant first.
- Kubernetes is the production source of truth.
- Workers consume Redis stream messages and use internal API job-control endpoints.
- Workers do not connect to Postgres in the supported production path.
- The API owns durable job state in Postgres.
- Helm is the supported production packaging target.
- Kustomize remains the engineering baseline and CI validation input.
- The target observability stack is OpenTelemetry Collector, Prometheus, Tempo, and Grafana.
- Loki and broader log shipping are deferred until a later phase requires them.

## Consequences

- Worker manifests and secrets no longer need `WORKER_POSTGRES_DSN`.
- Worker network policy must allow Redis, API port `8000`, DNS, and HTTP/S scan targets only.
- Startup migrations must support job claim metadata on upgraded databases.
- Worker regression coverage shifts from DB claim-race tests to API control-plane contract tests.

## Follow-on Work

- Phase 1: durable SLI storage and release-gate truth
- Phase 2: signed digest promotion and recovery evidence
- Phase 3: Helm packaging and operator onboarding

# Observability Conventions (Phase 3)

## Logging/Tracing Fields

The API emits request logs with consistent trace correlation keys:

- `request_id`
- `trace_id`
- `http.method`
- `url.path`
- `http.status_code`
- `http.latency_ms`

Queue envelopes carry:

- `request_id`
- `trace_id`
- canonical event envelope metadata (`event_id`, `event_type`, `ts`, `org_id`)

## OpenTelemetry Runtime

Tracing is optional and enabled only when all of these are configured:

- `OTEL_ENABLED=true`
- `OTEL_EXPORTER_OTLP_ENDPOINT=<collector-endpoint>`
- optional: `OTEL_SERVICE_NAME`, `OTEL_EXPORTER_OTLP_INSECURE`

Current span coverage:

- `http.server.request` for API request lifecycle
- `db.query` for SQL execution timing/error attributes
- `messaging.publish` for Redis stream publishes
- `gen_ai.request` for provider calls

## Live SLI Endpoints

- `GET /platform/sli/current` returns current API availability + p95 latency snapshots.
- `GET /platform/release-gate/current` evaluates current gate using live API SLI values plus optional query measurements for ingestion/alerts/jobs.

## Prometheus Gauges

`GET /metrics` includes:

- `secplat_api_availability_ratio`
- `secplat_api_p95_latency_ms`

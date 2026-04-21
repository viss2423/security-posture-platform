CREATE TABLE IF NOT EXISTS platform_api_runtime_snapshots (
  snapshot_id         BIGSERIAL PRIMARY KEY,
  captured_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  source              TEXT NOT NULL DEFAULT 'api_runtime',
  service_name        TEXT NOT NULL DEFAULT 'secplat-api',
  service_instance_id TEXT NOT NULL,
  request_count       BIGINT NOT NULL DEFAULT 0,
  server_error_count  BIGINT NOT NULL DEFAULT 0,
  api_availability    DOUBLE PRECISION,
  api_p95_latency_ms  DOUBLE PRECISION
);

CREATE INDEX IF NOT EXISTS idx_platform_api_runtime_snapshots_captured
  ON platform_api_runtime_snapshots(captured_at DESC);

CREATE INDEX IF NOT EXISTS idx_platform_api_runtime_snapshots_instance
  ON platform_api_runtime_snapshots(service_instance_id, captured_at DESC);

CREATE TABLE IF NOT EXISTS platform_sli_samples (
  sample_id                        BIGSERIAL PRIMARY KEY,
  captured_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  window_hours                     INTEGER NOT NULL DEFAULT 24,
  source                           TEXT NOT NULL DEFAULT 'platform_runtime',
  api_availability                 DOUBLE PRECISION,
  api_p95_latency_ms               DOUBLE PRECISION,
  ingestion_visibility_seconds     DOUBLE PRECISION,
  alert_creation_seconds           DOUBLE PRECISION,
  background_job_freshness_minutes DOUBLE PRECISION
);

CREATE INDEX IF NOT EXISTS idx_platform_sli_samples_captured
  ON platform_sli_samples(captured_at DESC);

CREATE INDEX IF NOT EXISTS idx_platform_sli_samples_source
  ON platform_sli_samples(source, captured_at DESC);

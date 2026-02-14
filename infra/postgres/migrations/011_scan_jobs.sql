-- Phase B.3: Job runner table (worker-web consumes queued jobs; API lists and retries).
CREATE TABLE IF NOT EXISTS scan_jobs (
  job_id           SERIAL PRIMARY KEY,
  job_type         TEXT NOT NULL,
  target_asset_id  INTEGER REFERENCES assets(asset_id),
  requested_by     TEXT,
  status          TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at       TIMESTAMPTZ,
  finished_at      TIMESTAMPTZ,
  error            TEXT,
  log_output       TEXT,
  retry_count      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs(created_at DESC);

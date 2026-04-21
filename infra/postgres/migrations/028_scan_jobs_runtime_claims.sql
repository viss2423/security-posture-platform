ALTER TABLE scan_jobs
  ADD COLUMN IF NOT EXISTS claimed_by TEXT;

ALTER TABLE scan_jobs
  ADD COLUMN IF NOT EXISTS claim_token TEXT;

ALTER TABLE scan_jobs
  ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_jobs_claim_token
  ON scan_jobs(claim_token) WHERE claim_token IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scan_jobs_last_heartbeat
  ON scan_jobs(last_heartbeat_at DESC) WHERE last_heartbeat_at IS NOT NULL;

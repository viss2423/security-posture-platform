ALTER TABLE scan_jobs
  ADD COLUMN IF NOT EXISTS job_params_json JSONB NOT NULL DEFAULT '{}'::jsonb;

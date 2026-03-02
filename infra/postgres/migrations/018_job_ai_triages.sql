CREATE TABLE IF NOT EXISTS job_ai_triages (
  id              SERIAL PRIMARY KEY,
  job_id          INTEGER NOT NULL UNIQUE REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
  triage_text     TEXT NOT NULL,
  provider        TEXT NOT NULL,
  model           TEXT NOT NULL,
  generated_by    TEXT,
  generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  context_json    JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_job_ai_triages_generated_at
  ON job_ai_triages(generated_at DESC);

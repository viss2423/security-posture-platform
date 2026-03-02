CREATE TABLE IF NOT EXISTS asset_ai_diagnoses (
  id              SERIAL PRIMARY KEY,
  asset_key       TEXT NOT NULL UNIQUE,
  diagnosis_text  TEXT NOT NULL,
  provider        TEXT NOT NULL,
  model           TEXT NOT NULL,
  generated_by    TEXT,
  generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  context_json    JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_asset_ai_diagnoses_generated_at
  ON asset_ai_diagnoses(generated_at DESC);

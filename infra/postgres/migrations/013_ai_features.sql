-- Phase AI-1: incident summaries, finding explanations, posture anomalies

CREATE TABLE IF NOT EXISTS incident_ai_summaries (
  id            SERIAL PRIMARY KEY,
  incident_id   INTEGER NOT NULL UNIQUE REFERENCES incidents(id) ON DELETE CASCADE,
  summary_text  TEXT NOT NULL,
  provider      TEXT NOT NULL,
  model         TEXT NOT NULL,
  generated_by  TEXT,
  generated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  context_json  JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_incident_ai_summaries_generated_at
  ON incident_ai_summaries(generated_at DESC);

CREATE TABLE IF NOT EXISTS finding_ai_explanations (
  id                 SERIAL PRIMARY KEY,
  finding_id         INTEGER NOT NULL UNIQUE REFERENCES findings(finding_id) ON DELETE CASCADE,
  explanation_text   TEXT NOT NULL,
  remediation_patch  TEXT,
  provider           TEXT NOT NULL,
  model              TEXT NOT NULL,
  generated_by       TEXT,
  generated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  context_json       JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_finding_ai_explanations_generated_at
  ON finding_ai_explanations(generated_at DESC);

CREATE TABLE IF NOT EXISTS posture_anomalies (
  id              SERIAL PRIMARY KEY,
  detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metric          TEXT NOT NULL,
  severity        TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
  current_value   DOUBLE PRECISION,
  baseline_mean   DOUBLE PRECISION,
  baseline_std    DOUBLE PRECISION,
  z_score         DOUBLE PRECISION,
  window_size     INTEGER NOT NULL DEFAULT 0,
  context_json    JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_posture_anomalies_detected_at
  ON posture_anomalies(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_posture_anomalies_metric
  ON posture_anomalies(metric);

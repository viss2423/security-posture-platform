CREATE TABLE IF NOT EXISTS risk_model_snapshots (
  id                SERIAL PRIMARY KEY,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by        TEXT,
  event_type        TEXT NOT NULL DEFAULT 'manual'
                    CHECK (event_type IN ('train', 'manual')),
  model_signature   TEXT,
  artifact_path     TEXT NOT NULL,
  threshold         DOUBLE PRECISION NOT NULL,
  recommended_threshold DOUBLE PRECISION,
  dataset_size      INTEGER,
  positive_labels   INTEGER,
  negative_labels   INTEGER,
  accuracy          DOUBLE PRECISION,
  precision         DOUBLE PRECISION,
  recall            DOUBLE PRECISION,
  f1                DOUBLE PRECISION,
  auc               DOUBLE PRECISION,
  brier_score       DOUBLE PRECISION,
  test_auc          DOUBLE PRECISION,
  drift_psi         DOUBLE PRECISION,
  summary_json      JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_risk_model_snapshots_created_at
  ON risk_model_snapshots(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_risk_model_snapshots_event_type
  ON risk_model_snapshots(event_type, created_at DESC);

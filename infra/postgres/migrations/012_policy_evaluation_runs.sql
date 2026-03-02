-- Phase 4: persist policy evaluation runs with evidence JSON.
CREATE TABLE IF NOT EXISTS policy_evaluation_runs (
  id                 SERIAL PRIMARY KEY,
  bundle_id          INTEGER NOT NULL REFERENCES policy_bundles(id) ON DELETE CASCADE,
  evaluated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  evaluated_by       TEXT,
  bundle_approved_by TEXT,
  score              DOUBLE PRECISION,
  violations_count   INTEGER NOT NULL DEFAULT 0,
  result_json        JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_policy_eval_runs_bundle_time
  ON policy_evaluation_runs(bundle_id, evaluated_at DESC);

CREATE TABLE IF NOT EXISTS policy_evaluation_ai_summaries (
  id              SERIAL PRIMARY KEY,
  evaluation_id   INTEGER NOT NULL UNIQUE REFERENCES policy_evaluation_runs(id) ON DELETE CASCADE,
  summary_text    TEXT NOT NULL,
  provider        TEXT NOT NULL,
  model           TEXT NOT NULL,
  generated_by    TEXT,
  generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  context_json    JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_policy_eval_ai_summaries_generated_at
  ON policy_evaluation_ai_summaries(generated_at DESC);

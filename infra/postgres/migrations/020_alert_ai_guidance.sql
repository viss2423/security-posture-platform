CREATE TABLE IF NOT EXISTS alert_ai_guidance (
  id                  SERIAL PRIMARY KEY,
  asset_key           TEXT NOT NULL UNIQUE,
  guidance_text       TEXT NOT NULL,
  recommended_action  TEXT,
  urgency             TEXT,
  provider            TEXT NOT NULL,
  model               TEXT NOT NULL,
  generated_by        TEXT,
  generated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  context_signature   TEXT NOT NULL DEFAULT '',
  context_json        JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_alert_ai_guidance_generated_at
  ON alert_ai_guidance(generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_alert_ai_guidance_action
  ON alert_ai_guidance(recommended_action, generated_at DESC);

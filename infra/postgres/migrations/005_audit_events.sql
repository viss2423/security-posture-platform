-- Audit log for UI: login, retention, asset edits, etc.
CREATE TABLE IF NOT EXISTS audit_events (
  id         SERIAL PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  action     TEXT NOT NULL,
  user_name  TEXT,
  asset_key  TEXT,
  details    JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_events_user ON audit_events(user_name);

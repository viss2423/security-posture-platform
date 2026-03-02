-- Alert lifecycle: ack, suppress, resolve, assign per asset
CREATE TABLE IF NOT EXISTS alert_states (
  asset_key       TEXT PRIMARY KEY,
  state           TEXT NOT NULL DEFAULT 'firing',  -- firing | acked | suppressed | resolved
  ack_reason      TEXT,
  acked_by        TEXT,
  acked_at        TIMESTAMPTZ,
  suppressed_until TIMESTAMPTZ,
  assigned_to     TEXT,
  resolved_at     TIMESTAMPTZ,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_states_state ON alert_states(state);
CREATE INDEX IF NOT EXISTS idx_alert_states_suppressed_until ON alert_states(suppressed_until) WHERE suppressed_until IS NOT NULL;

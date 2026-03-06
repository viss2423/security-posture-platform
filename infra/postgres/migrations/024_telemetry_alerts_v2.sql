CREATE TABLE IF NOT EXISTS security_events (
  event_id         BIGSERIAL PRIMARY KEY,
  source           TEXT NOT NULL,
  event_type       TEXT NOT NULL DEFAULT 'event',
  asset_id         INTEGER REFERENCES assets(asset_id) ON DELETE SET NULL,
  asset_key        TEXT,
  severity         INTEGER,
  src_ip           TEXT,
  src_port         INTEGER,
  dst_ip           TEXT,
  dst_port         INTEGER,
  domain           TEXT,
  url              TEXT,
  protocol         TEXT,
  event_time       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ti_match         BOOLEAN NOT NULL DEFAULT FALSE,
  ti_source        TEXT,
  mitre_techniques JSONB NOT NULL DEFAULT '[]'::jsonb,
  anomaly_score    DOUBLE PRECISION,
  payload_json     JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_events_source_time
  ON security_events(source, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_asset_time
  ON security_events(asset_key, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_ti_match
  ON security_events(ti_match, event_time DESC);

CREATE TABLE IF NOT EXISTS security_alerts (
  alert_id           BIGSERIAL PRIMARY KEY,
  alert_key          TEXT NOT NULL UNIQUE,
  dedupe_key         TEXT NOT NULL,
  source             TEXT NOT NULL,
  alert_type         TEXT NOT NULL DEFAULT 'detection',
  asset_id           INTEGER REFERENCES assets(asset_id) ON DELETE SET NULL,
  asset_key          TEXT,
  severity           TEXT NOT NULL DEFAULT 'medium'
                     CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  status             TEXT NOT NULL DEFAULT 'firing'
                     CHECK (status IN ('firing', 'acked', 'suppressed', 'resolved')),
  title              TEXT NOT NULL,
  description        TEXT,
  event_count        INTEGER NOT NULL DEFAULT 1,
  first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  acknowledged_by    TEXT,
  acknowledged_at    TIMESTAMPTZ,
  suppression_reason TEXT,
  suppressed_until   TIMESTAMPTZ,
  resolved_by        TEXT,
  resolved_at        TIMESTAMPTZ,
  assigned_to        TEXT,
  ti_match           BOOLEAN NOT NULL DEFAULT FALSE,
  ti_source          TEXT,
  mitre_techniques   JSONB NOT NULL DEFAULT '[]'::jsonb,
  payload_json       JSONB NOT NULL DEFAULT '{}'::jsonb,
  context_json       JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_alerts_status
  ON security_alerts(status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_alerts_source
  ON security_alerts(source, status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_alerts_asset
  ON security_alerts(asset_key, status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_alerts_dedupe
  ON security_alerts(dedupe_key);

ALTER TABLE incident_alerts
  ADD COLUMN IF NOT EXISTS alert_id BIGINT REFERENCES security_alerts(alert_id) ON DELETE CASCADE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_alerts_incident_alert_id
  ON incident_alerts(incident_id, alert_id) WHERE alert_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert_id
  ON incident_alerts(alert_id) WHERE alert_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS detection_rules (
  rule_id            SERIAL PRIMARY KEY,
  name               TEXT NOT NULL UNIQUE,
  description        TEXT,
  source             TEXT,
  rule_format        TEXT NOT NULL DEFAULT 'json' CHECK (rule_format IN ('json', 'sigma')),
  severity           TEXT NOT NULL DEFAULT 'medium'
                     CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  enabled            BOOLEAN NOT NULL DEFAULT TRUE,
  definition_json    JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by         TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_tested_at     TIMESTAMPTZ,
  last_test_matches  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled
  ON detection_rules(enabled, updated_at DESC);

CREATE TABLE IF NOT EXISTS detection_rule_runs (
  run_id             BIGSERIAL PRIMARY KEY,
  rule_id            INTEGER NOT NULL REFERENCES detection_rules(rule_id) ON DELETE CASCADE,
  executed_by        TEXT,
  lookback_hours     INTEGER NOT NULL DEFAULT 24,
  status             TEXT NOT NULL DEFAULT 'done' CHECK (status IN ('running', 'done', 'failed')),
  matches            INTEGER NOT NULL DEFAULT 0,
  started_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at        TIMESTAMPTZ,
  error              TEXT,
  results_json       JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_detection_rule_runs_rule
  ON detection_rule_runs(rule_id, started_at DESC);

CREATE TABLE IF NOT EXISTS attack_lab_runs (
  run_id             BIGSERIAL PRIMARY KEY,
  task_type          TEXT NOT NULL,
  target_asset_id    INTEGER REFERENCES assets(asset_id) ON DELETE SET NULL,
  target_asset_key   TEXT,
  target             TEXT,
  status             TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
  requested_by       TEXT,
  started_at         TIMESTAMPTZ,
  finished_at        TIMESTAMPTZ,
  error              TEXT,
  output_json        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attack_lab_runs_created
  ON attack_lab_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_lab_runs_status
  ON attack_lab_runs(status, created_at DESC);

CREATE TABLE IF NOT EXISTS asset_anomaly_scores (
  id                 BIGSERIAL PRIMARY KEY,
  asset_key          TEXT NOT NULL,
  computed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  anomaly_score      DOUBLE PRECISION NOT NULL,
  baseline_mean      DOUBLE PRECISION,
  baseline_std       DOUBLE PRECISION,
  current_value      DOUBLE PRECISION,
  source_breakdown   JSONB NOT NULL DEFAULT '{}'::jsonb,
  context_json       JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_asset_anomaly_scores_asset_time
  ON asset_anomaly_scores(asset_key, computed_at DESC);

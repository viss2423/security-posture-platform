"""Ensure audit_events and alert_states exist. Safe to run on every startup (CREATE TABLE IF NOT EXISTS)."""
import logging
from sqlalchemy import text

from app.db import engine

logger = logging.getLogger("secplat")

AUDIT_EVENTS_SQL = """
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
"""

ALERT_STATES_SQL = """
CREATE TABLE IF NOT EXISTS alert_states (
  asset_key        TEXT PRIMARY KEY,
  state            TEXT NOT NULL DEFAULT 'firing',
  ack_reason       TEXT,
  acked_by         TEXT,
  acked_at         TIMESTAMPTZ,
  suppressed_until  TIMESTAMPTZ,
  assigned_to      TEXT,
  resolved_at      TIMESTAMPTZ,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_states_state ON alert_states(state);
CREATE INDEX IF NOT EXISTS idx_alert_states_suppressed_until ON alert_states(suppressed_until) WHERE suppressed_until IS NOT NULL;
"""

# Findings: extend for scanner dedupe + status workflow (run ALTERs; safe if columns exist)
FINDINGS_EXTEND_SQL = """
ALTER TABLE findings ADD COLUMN IF NOT EXISTS finding_key TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'open';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS source TEXT;
"""
FINDINGS_UNIQUE_INDEX = "CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_finding_key ON findings(finding_key) WHERE finding_key IS NOT NULL;"


def run_startup_migrations() -> None:
    """Create audit_events and alert_states if missing (e.g. DB created before they were in init.sql)."""
    with engine.begin() as conn:
        for name, sql in [("audit_events", AUDIT_EVENTS_SQL), ("alert_states", ALERT_STATES_SQL)]:
            try:
                for stmt in sql.strip().split(";"):
                    stmt = stmt.strip()
                    if stmt:
                        conn.execute(text(stmt))
                logger.info("startup_migration: ensured table %s exists", name)
            except Exception as e:
                logger.warning("startup_migration: %s failed: %s", name, e)
                raise
        # Findings: add columns for scanner (finding_key, first_seen, last_seen, status, source)
        try:
            for stmt in FINDINGS_EXTEND_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            conn.execute(text(FINDINGS_UNIQUE_INDEX))
            logger.info("startup_migration: ensured findings extended columns exist")
        except Exception as e:
            logger.warning("startup_migration: findings extend failed: %s", e)
            raise

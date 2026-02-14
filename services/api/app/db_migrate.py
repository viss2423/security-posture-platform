"""Ensure audit_events and alert_states exist. Safe to run on every startup (CREATE TABLE IF NOT EXISTS)."""
import logging
from sqlalchemy import text

from app.db import engine
from app.settings import settings

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

# Findings: risk acceptance (Phase A.2)
FINDINGS_RISK_ACCEPTANCE_SQL = """
ALTER TABLE findings ADD COLUMN IF NOT EXISTS accepted_risk_at TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS accepted_risk_expires_at TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS accepted_risk_reason TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS accepted_risk_by TEXT;
"""

# Incidents: SOC workflow (Phase A.1)
INCIDENTS_SQL = """
CREATE TABLE IF NOT EXISTS incidents (
  id            SERIAL PRIMARY KEY,
  title         TEXT NOT NULL,
  severity      TEXT NOT NULL DEFAULT 'medium',
  status        TEXT NOT NULL DEFAULT 'new',
  assigned_to   TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at   TIMESTAMPTZ,
  closed_at     TIMESTAMPTZ,
  sla_due_at    TIMESTAMPTZ,
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);
CREATE TABLE IF NOT EXISTS incident_alerts (
  incident_id   INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  asset_key     TEXT NOT NULL,
  added_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  added_by      TEXT,
  PRIMARY KEY (incident_id, asset_key)
);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident_id ON incident_alerts(incident_id);
CREATE TABLE IF NOT EXISTS incident_notes (
  id            SERIAL PRIMARY KEY,
  incident_id   INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  event_type    TEXT NOT NULL,
  author        TEXT,
  body          TEXT,
  details       JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incident_notes_incident_id ON incident_notes(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_notes_created_at ON incident_notes(incident_id, created_at DESC);
"""

# Phase B.1: users table for RBAC
USERS_SQL = """
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  role          TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('viewer', 'analyst', 'admin')),
  password_hash TEXT,
  disabled      BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
"""
USERS_ADD_PASSWORD_COLUMN = "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;"

# Phase B.3: scan_jobs for job runner + logs
SCAN_JOBS_SQL = """
CREATE TABLE IF NOT EXISTS scan_jobs (
  job_id           SERIAL PRIMARY KEY,
  job_type         TEXT NOT NULL,
  target_asset_id  INTEGER REFERENCES assets(asset_id),
  requested_by     TEXT,
  status           TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at       TIMESTAMPTZ,
  finished_at      TIMESTAMPTZ,
  error            TEXT,
  log_output       TEXT,
  retry_count      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs(created_at DESC);
"""
ALTER_SCAN_JOBS_LOG = "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS log_output TEXT;"
ALTER_SCAN_JOBS_RETRY = "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0;"

# Phase B.2: policy bundles
POLICY_BUNDLES_SQL = """
CREATE TABLE IF NOT EXISTS policy_bundles (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  description   TEXT,
  definition    TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  approved_at   TIMESTAMPTZ,
  approved_by   TEXT
);
CREATE INDEX IF NOT EXISTS idx_policy_bundles_status ON policy_bundles(status);
"""


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
        # Findings: risk acceptance columns (Phase A.2)
        try:
            for stmt in FINDINGS_RISK_ACCEPTANCE_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            logger.info("startup_migration: ensured findings risk acceptance columns exist")
        except Exception as e:
            logger.warning("startup_migration: findings risk acceptance failed: %s", e)
            raise
        # Incidents (Phase A.1)
        try:
            for stmt in INCIDENTS_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            logger.info("startup_migration: ensured incidents tables exist")
        except Exception as e:
            logger.warning("startup_migration: incidents failed: %s", e)
            raise
        # Users table for RBAC (Phase B.1)
        try:
            for stmt in USERS_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            conn.execute(text(USERS_ADD_PASSWORD_COLUMN))
            conn.execute(
                text("INSERT INTO users (username, role) VALUES (:u, 'admin') ON CONFLICT (username) DO NOTHING"),
                {"u": settings.ADMIN_USERNAME},
            )
            # Seed viewer account (password: viewer). Pre-computed hash to avoid passlib/bcrypt
            # backend detection bug (ValueError: password cannot be longer than 72 bytes) in some envs.
            VIEWER_BCRYPT_HASH = "$2b$12$wITIujVXwHS5q4g/TLizOeTTDFWkpEC9/sAz6h20H5x4GXzz37WGW"
            conn.execute(
                text("""
                    INSERT INTO users (username, role, password_hash)
                    VALUES ('viewer', 'viewer', :ph)
                    ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
                    WHERE users.username = 'viewer'
                """),
                {"ph": VIEWER_BCRYPT_HASH},
            )
            logger.info("startup_migration: ensured users table exists, admin and viewer seeded")
        except Exception as e:
            logger.warning("startup_migration: users failed: %s", e)
            raise
        # scan_jobs (Phase B.3)
        try:
            for stmt in SCAN_JOBS_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            conn.execute(text(ALTER_SCAN_JOBS_LOG))
            conn.execute(text(ALTER_SCAN_JOBS_RETRY))
            logger.info("startup_migration: ensured scan_jobs table exists")
        except Exception as e:
            logger.warning("startup_migration: scan_jobs failed: %s", e)
            raise
        # Policy bundles (Phase B.2)
        try:
            for stmt in POLICY_BUNDLES_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            logger.info("startup_migration: ensured policy_bundles table exists")
        except Exception as e:
            logger.warning("startup_migration: policy_bundles failed: %s", e)
            raise

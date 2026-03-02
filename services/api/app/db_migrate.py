"""Ensure audit_events and alert_states exist. Safe to run on every startup (CREATE TABLE IF NOT EXISTS)."""

import logging

import bcrypt
from sqlalchemy import text

from app.db import engine
from app.risk_scoring import backfill_finding_risk_scores
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

FINDINGS_RISK_SCORING_SQL = """
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_score INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_level TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_factors_json JSONB NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON findings(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_risk_level ON findings(risk_level);
"""
FINDING_RISK_LABELS_SQL = """
CREATE TABLE IF NOT EXISTS finding_risk_labels (
  id            SERIAL PRIMARY KEY,
  finding_id    INTEGER NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
  label         TEXT NOT NULL CHECK (label IN ('incident_worthy', 'benign')),
  source        TEXT NOT NULL DEFAULT 'analyst'
                 CHECK (source IN ('analyst', 'incident_linked', 'accepted_risk', 'imported')),
  note          TEXT,
  created_by    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_finding_risk_labels_finding_id
  ON finding_risk_labels(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_risk_labels_label
  ON finding_risk_labels(label, created_at DESC);
"""
RISK_MODEL_SNAPSHOTS_SQL = """
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
"""

# Incidents: SOC workflow (Phase A.1)
INCIDENTS_SQL = """
CREATE TABLE IF NOT EXISTS incidents (
  id            SERIAL PRIMARY KEY,
  incident_key  TEXT,
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
INCIDENTS_IDEMPOTENCY_SQL = """
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS incident_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_incident_key ON incidents(incident_key);
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
ALTER_SCAN_JOBS_RETRY = (
    "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0;"
)

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

# Phase 4: persisted policy evaluation results with evidence
POLICY_EVALUATION_RUNS_SQL = """
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
"""

# Phase 3.2: Maintenance windows + suppression rules
MAINTENANCE_WINDOWS_SQL = """
CREATE TABLE IF NOT EXISTS maintenance_windows (
  id          SERIAL PRIMARY KEY,
  asset_key   TEXT NOT NULL,
  start_at    TIMESTAMPTZ NOT NULL,
  end_at      TIMESTAMPTZ NOT NULL,
  reason      TEXT,
  created_by  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_maintenance_windows_asset ON maintenance_windows(asset_key);
CREATE INDEX IF NOT EXISTS idx_maintenance_windows_times ON maintenance_windows(start_at, end_at);
"""
SUPPRESSION_RULES_SQL = """
CREATE TABLE IF NOT EXISTS suppression_rules (
  id           SERIAL PRIMARY KEY,
  scope        TEXT NOT NULL CHECK (scope IN ('asset', 'finding', 'all')),
  scope_value  TEXT,
  starts_at    TIMESTAMPTZ NOT NULL,
  ends_at      TIMESTAMPTZ NOT NULL,
  reason       TEXT,
  created_by   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_suppression_rules_scope ON suppression_rules(scope, scope_value);
CREATE INDEX IF NOT EXISTS idx_suppression_rules_times ON suppression_rules(starts_at, ends_at);
"""

# Phase AI-1: persisted AI enrichments
INCIDENT_AI_SUMMARIES_SQL = """
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
"""
POLICY_EVALUATION_AI_SUMMARIES_SQL = """
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
"""
FINDING_AI_EXPLANATIONS_SQL = """
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
"""
POSTURE_ANOMALIES_SQL = """
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
"""
ASSET_AI_DIAGNOSES_SQL = """
CREATE TABLE IF NOT EXISTS asset_ai_diagnoses (
  id              SERIAL PRIMARY KEY,
  asset_key       TEXT NOT NULL UNIQUE,
  diagnosis_text  TEXT NOT NULL,
  provider        TEXT NOT NULL,
  model           TEXT NOT NULL,
  generated_by    TEXT,
  generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  context_json    JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_asset_ai_diagnoses_generated_at
  ON asset_ai_diagnoses(generated_at DESC);
"""
JOB_AI_TRIAGES_SQL = """
CREATE TABLE IF NOT EXISTS job_ai_triages (
  id              SERIAL PRIMARY KEY,
  job_id          INTEGER NOT NULL UNIQUE REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
  triage_text     TEXT NOT NULL,
  provider        TEXT NOT NULL,
  model           TEXT NOT NULL,
  generated_by    TEXT,
  generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  context_json    JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_job_ai_triages_generated_at
  ON job_ai_triages(generated_at DESC);
"""
ALERT_AI_GUIDANCE_SQL = """
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
"""


def _bcrypt_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


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
        # Findings: contextual risk scoring (Phase AI-2)
        try:
            for stmt in FINDINGS_RISK_SCORING_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            updated = backfill_finding_risk_scores(conn)
            logger.info(
                "startup_migration: ensured findings risk scoring columns exist; backfilled=%s",
                updated,
            )
        except Exception as e:
            logger.warning("startup_migration: findings risk scoring failed: %s", e)
            raise
        try:
            for stmt in FINDING_RISK_LABELS_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            logger.info("startup_migration: ensured finding_risk_labels table exists")
        except Exception as e:
            logger.warning("startup_migration: finding_risk_labels failed: %s", e)
            raise
        try:
            for stmt in RISK_MODEL_SNAPSHOTS_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            logger.info("startup_migration: ensured risk_model_snapshots table exists")
        except Exception as e:
            logger.warning("startup_migration: risk_model_snapshots failed: %s", e)
            raise
        # Incidents (Phase A.1)
        try:
            for stmt in INCIDENTS_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            for stmt in INCIDENTS_IDEMPOTENCY_SQL.strip().split(";"):
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
                text(
                    "INSERT INTO users (username, role) VALUES (:u, 'admin') ON CONFLICT (username) DO NOTHING"
                ),
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

            service_identities = [
                (
                    settings.SCANNER_SERVICE_USERNAME,
                    settings.SCANNER_SERVICE_PASSWORD,
                    "analyst",
                ),
                (
                    settings.INGESTION_SERVICE_USERNAME,
                    settings.INGESTION_SERVICE_PASSWORD,
                    "analyst",
                ),
                (
                    settings.CORRELATOR_SERVICE_USERNAME,
                    settings.CORRELATOR_SERVICE_PASSWORD,
                    "analyst",
                ),
            ]
            for username, password, role in service_identities:
                if not username or not password:
                    continue
                conn.execute(
                    text(
                        """
                        INSERT INTO users (username, role, password_hash, disabled)
                        VALUES (:u, :r, :ph, FALSE)
                        ON CONFLICT (username) DO UPDATE
                        SET role = EXCLUDED.role,
                            password_hash = EXCLUDED.password_hash,
                            disabled = FALSE
                    """
                    ),
                    {"u": username, "r": role, "ph": _bcrypt_hash(password)},
                )

            logger.info(
                "startup_migration: ensured users table exists, admin/viewer/service identities seeded"
            )
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
        # Policy evaluation runs (Phase 4)
        try:
            for stmt in POLICY_EVALUATION_RUNS_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            logger.info("startup_migration: ensured policy_evaluation_runs table exists")
        except Exception as e:
            logger.warning("startup_migration: policy_evaluation_runs failed: %s", e)
            raise
        # Phase 3.2: maintenance_windows + suppression_rules
        for name, sql in [
            ("maintenance_windows", MAINTENANCE_WINDOWS_SQL),
            ("suppression_rules", SUPPRESSION_RULES_SQL),
        ]:
            try:
                for stmt in sql.strip().split(";"):
                    stmt = stmt.strip()
                    if stmt:
                        conn.execute(text(stmt))
                logger.info("startup_migration: ensured table %s exists", name)
            except Exception as e:
                logger.warning("startup_migration: %s failed: %s", name, e)
                raise
        for name, sql in [
            ("incident_ai_summaries", INCIDENT_AI_SUMMARIES_SQL),
            ("policy_evaluation_ai_summaries", POLICY_EVALUATION_AI_SUMMARIES_SQL),
            ("finding_ai_explanations", FINDING_AI_EXPLANATIONS_SQL),
            ("posture_anomalies", POSTURE_ANOMALIES_SQL),
            ("asset_ai_diagnoses", ASSET_AI_DIAGNOSES_SQL),
            ("job_ai_triages", JOB_AI_TRIAGES_SQL),
            ("alert_ai_guidance", ALERT_AI_GUIDANCE_SQL),
        ]:
            try:
                for stmt in sql.strip().split(";"):
                    stmt = stmt.strip()
                    if stmt:
                        conn.execute(text(stmt))
                logger.info("startup_migration: ensured table %s exists", name)
            except Exception as e:
                logger.warning("startup_migration: %s failed: %s", name, e)
                raise

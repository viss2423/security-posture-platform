"""Ensure audit_events and alert_states exist. Safe to run on every startup (CREATE TABLE IF NOT EXISTS)."""

import logging
import threading
import time
from typing import Any

import bcrypt
from sqlalchemy import text

from app.db import engine
from app.risk_scoring import backfill_finding_risk_scores
from app.settings import settings

logger = logging.getLogger("secplat")

_startup_migrations_state_lock = threading.Lock()
_startup_migrations_completed = False


class _RetryableStartupMigrationError(RuntimeError):
    """Signal that startup migrations should be retried in a fresh transaction."""


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
FINDINGS_SCANNER_METADATA_SQL = """
ALTER TABLE findings ADD COLUMN IF NOT EXISTS vulnerability_id TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS package_ecosystem TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS package_name TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS package_version TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fixed_version TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS scanner_metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS idx_findings_vulnerability_id
  ON findings(vulnerability_id) WHERE vulnerability_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_package_name
  ON findings(package_name) WHERE package_name IS NOT NULL;
"""

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
RISK_ENTITY_SNAPSHOTS_SQL = """
CREATE TABLE IF NOT EXISTS risk_entity_snapshots (
  snapshot_id      BIGSERIAL PRIMARY KEY,
  entity_type      TEXT NOT NULL
                   CHECK (entity_type IN ('asset', 'incident', 'environment')),
  entity_key       TEXT NOT NULL,
  entity_name      TEXT,
  snapshot_date    DATE NOT NULL,
  score            INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
  level            TEXT NOT NULL CHECK (level IN ('critical', 'high', 'medium', 'low')),
  drivers_json     JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata_json    JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (entity_type, entity_key, snapshot_date)
);
CREATE INDEX IF NOT EXISTS idx_risk_entity_snapshots_lookup
  ON risk_entity_snapshots(entity_type, entity_key, snapshot_date DESC);
CREATE INDEX IF NOT EXISTS idx_risk_entity_snapshots_date
  ON risk_entity_snapshots(snapshot_date DESC, entity_type, score DESC);
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
INCIDENT_RESPONSE_MATURITY_SQL = """
CREATE TABLE IF NOT EXISTS incident_evidence (
  evidence_id      SERIAL PRIMARY KEY,
  incident_id      INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  evidence_type    TEXT NOT NULL
                   CHECK (evidence_type IN ('alert', 'finding', 'asset', 'job', 'ticket', 'note', 'event', 'other')),
  ref_id           TEXT NOT NULL,
  relation         TEXT NOT NULL DEFAULT 'linked',
  summary          TEXT,
  details          JSONB NOT NULL DEFAULT '{}'::jsonb,
  added_by         TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (incident_id, evidence_type, ref_id, relation)
);
CREATE INDEX IF NOT EXISTS idx_incident_evidence_incident
  ON incident_evidence(incident_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_evidence_type_ref
  ON incident_evidence(evidence_type, ref_id);

CREATE TABLE IF NOT EXISTS incident_auto_rules (
  auto_rule_id               SERIAL PRIMARY KEY,
  name                       TEXT NOT NULL UNIQUE,
  description                TEXT,
  enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
  severity_threshold         TEXT NOT NULL DEFAULT 'high'
                             CHECK (severity_threshold IN ('critical', 'high', 'medium', 'low', 'info')),
  window_minutes             INTEGER NOT NULL DEFAULT 15,
  min_alerts                 INTEGER NOT NULL DEFAULT 2,
  require_distinct_sources   BOOLEAN NOT NULL DEFAULT FALSE,
  incident_severity          TEXT NOT NULL DEFAULT 'high'
                             CHECK (incident_severity IN ('critical', 'high', 'medium', 'low', 'info')),
  created_by                 TEXT,
  created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incident_auto_rules_enabled
  ON incident_auto_rules(enabled, updated_at DESC);

CREATE TABLE IF NOT EXISTS incident_watchers (
  incident_id      INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  username         TEXT NOT NULL,
  added_by         TEXT,
  added_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (incident_id, username)
);
CREATE INDEX IF NOT EXISTS idx_incident_watchers_incident
  ON incident_watchers(incident_id, added_at DESC);

CREATE TABLE IF NOT EXISTS incident_checklist_items (
  item_id          SERIAL PRIMARY KEY,
  incident_id      INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  title            TEXT NOT NULL,
  done             BOOLEAN NOT NULL DEFAULT FALSE,
  done_by          TEXT,
  done_at          TIMESTAMPTZ,
  created_by       TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incident_checklist_incident
  ON incident_checklist_items(incident_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_checklist_status
  ON incident_checklist_items(incident_id, done, updated_at DESC);

CREATE TABLE IF NOT EXISTS incident_decisions (
  decision_id      SERIAL PRIMARY KEY,
  incident_id      INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  decision         TEXT NOT NULL,
  rationale        TEXT,
  decided_by       TEXT,
  details          JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incident_decisions_incident
  ON incident_decisions(incident_id, created_at DESC);
"""

AUTOMATION_SQL = """
CREATE TABLE IF NOT EXISTS automation_playbooks (
  playbook_id            SERIAL PRIMARY KEY,
  title                 TEXT NOT NULL UNIQUE,
  description           TEXT,
  trigger               TEXT NOT NULL,
  conditions_json       JSONB NOT NULL DEFAULT '[]'::jsonb,
  actions_json          JSONB NOT NULL DEFAULT '[]'::jsonb,
  approval_required     BOOLEAN NOT NULL DEFAULT FALSE,
  rollback_steps_json   JSONB NOT NULL DEFAULT '[]'::jsonb,
  enabled               BOOLEAN NOT NULL DEFAULT TRUE,
  created_by            TEXT,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_automation_playbooks_trigger_enabled
  ON automation_playbooks(trigger, enabled, updated_at DESC);

CREATE TABLE IF NOT EXISTS automation_runs (
  run_id                BIGSERIAL PRIMARY KEY,
  playbook_id           INTEGER NOT NULL REFERENCES automation_playbooks(playbook_id) ON DELETE CASCADE,
  trigger_source        TEXT NOT NULL,
  trigger_payload_json  JSONB NOT NULL DEFAULT '{}'::jsonb,
  matched               BOOLEAN NOT NULL DEFAULT TRUE,
  status                TEXT NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running', 'pending_approval', 'done', 'failed', 'rejected')),
  requested_by          TEXT,
  started_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at           TIMESTAMPTZ,
  error                 TEXT,
  summary_json          JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_automation_runs_playbook_started
  ON automation_runs(playbook_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_automation_runs_status_started
  ON automation_runs(status, started_at DESC);

CREATE TABLE IF NOT EXISTS automation_run_actions (
  run_action_id         BIGSERIAL PRIMARY KEY,
  run_id                BIGINT NOT NULL REFERENCES automation_runs(run_id) ON DELETE CASCADE,
  action_index          INTEGER NOT NULL,
  action_type           TEXT NOT NULL,
  risk_tier             TEXT NOT NULL DEFAULT 'low' CHECK (risk_tier IN ('low', 'medium', 'high')),
  status                TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'pending_approval', 'approved', 'rejected', 'running', 'done', 'failed', 'rolled_back')),
  params_json           JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_json           JSONB NOT NULL DEFAULT '{}'::jsonb,
  error                 TEXT,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at            TIMESTAMPTZ,
  finished_at           TIMESTAMPTZ,
  UNIQUE (run_id, action_index)
);
CREATE INDEX IF NOT EXISTS idx_automation_run_actions_run
  ON automation_run_actions(run_id, action_index ASC);
CREATE INDEX IF NOT EXISTS idx_automation_run_actions_status
  ON automation_run_actions(status, created_at DESC);

CREATE TABLE IF NOT EXISTS automation_approvals (
  approval_id           BIGSERIAL PRIMARY KEY,
  run_action_id         BIGINT NOT NULL UNIQUE REFERENCES automation_run_actions(run_action_id) ON DELETE CASCADE,
  required_role         TEXT NOT NULL CHECK (required_role IN ('analyst', 'admin')),
  risk_tier             TEXT NOT NULL CHECK (risk_tier IN ('medium', 'high')),
  status                TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  requested_by          TEXT,
  approved_by           TEXT,
  rejected_by           TEXT,
  reason                TEXT,
  decision_note         TEXT,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at            TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_automation_approvals_status_created
  ON automation_approvals(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_automation_approvals_required_role
  ON automation_approvals(required_role, status, created_at DESC);

CREATE TABLE IF NOT EXISTS automation_rollbacks (
  rollback_id           BIGSERIAL PRIMARY KEY,
  run_action_id         BIGINT NOT NULL UNIQUE REFERENCES automation_run_actions(run_action_id) ON DELETE CASCADE,
  rollback_type         TEXT NOT NULL,
  rollback_payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  status                TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'executed', 'failed')),
  requested_by          TEXT,
  executed_by           TEXT,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  executed_at           TIMESTAMPTZ,
  error                 TEXT
);
CREATE INDEX IF NOT EXISTS idx_automation_rollbacks_status_created
  ON automation_rollbacks(status, created_at DESC);
"""

ATTACK_SURFACE_SQL = """
CREATE TABLE IF NOT EXISTS attack_surface_discovery_runs (
  run_id              BIGSERIAL PRIMARY KEY,
  status              TEXT NOT NULL DEFAULT 'running'
                      CHECK (status IN ('running', 'done', 'failed')),
  requested_by        TEXT,
  source_job_id       INTEGER,
  started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at         TIMESTAMPTZ,
  error               TEXT,
  metadata_json       JSONB NOT NULL DEFAULT '{}'::jsonb,
  summary_json        JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_attack_surface_runs_status_started
  ON attack_surface_discovery_runs(status, started_at DESC);

CREATE TABLE IF NOT EXISTS attack_surface_hosts (
  host_id             BIGSERIAL PRIMARY KEY,
  run_id              BIGINT NOT NULL REFERENCES attack_surface_discovery_runs(run_id) ON DELETE CASCADE,
  asset_key           TEXT,
  hostname            TEXT NOT NULL,
  ip_address          TEXT,
  internet_exposed    BOOLEAN NOT NULL DEFAULT FALSE,
  source              TEXT NOT NULL DEFAULT 'asset_inventory',
  discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_attack_surface_hosts_run
  ON attack_surface_hosts(run_id, host_id ASC);
CREATE INDEX IF NOT EXISTS idx_attack_surface_hosts_asset
  ON attack_surface_hosts(asset_key, discovered_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_surface_hosts_hostname
  ON attack_surface_hosts(hostname, discovered_at DESC);

CREATE TABLE IF NOT EXISTS attack_surface_services (
  service_id          BIGSERIAL PRIMARY KEY,
  run_id              BIGINT NOT NULL REFERENCES attack_surface_discovery_runs(run_id) ON DELETE CASCADE,
  host_id             BIGINT NOT NULL REFERENCES attack_surface_hosts(host_id) ON DELETE CASCADE,
  asset_key           TEXT,
  hostname            TEXT,
  port                INTEGER NOT NULL,
  protocol            TEXT NOT NULL DEFAULT 'tcp',
  service_name        TEXT,
  service_version     TEXT,
  discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_attack_surface_services_run
  ON attack_surface_services(run_id, service_id ASC);
CREATE INDEX IF NOT EXISTS idx_attack_surface_services_host_port
  ON attack_surface_services(hostname, port, discovered_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_surface_services_asset
  ON attack_surface_services(asset_key, discovered_at DESC);

CREATE TABLE IF NOT EXISTS attack_surface_certificates (
  cert_id             BIGSERIAL PRIMARY KEY,
  run_id              BIGINT NOT NULL REFERENCES attack_surface_discovery_runs(run_id) ON DELETE CASCADE,
  host_id             BIGINT NOT NULL REFERENCES attack_surface_hosts(host_id) ON DELETE CASCADE,
  asset_key           TEXT,
  hostname            TEXT,
  common_name         TEXT,
  issuer              TEXT,
  serial_number       TEXT,
  fingerprint_sha256  TEXT,
  not_before          TIMESTAMPTZ,
  not_after           TIMESTAMPTZ,
  discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_attack_surface_certs_run
  ON attack_surface_certificates(run_id, cert_id ASC);
CREATE INDEX IF NOT EXISTS idx_attack_surface_certs_hostname
  ON attack_surface_certificates(hostname, discovered_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_surface_certs_fingerprint
  ON attack_surface_certificates(fingerprint_sha256);

CREATE TABLE IF NOT EXISTS attack_surface_drift_events (
  event_id            BIGSERIAL PRIMARY KEY,
  run_id              BIGINT NOT NULL REFERENCES attack_surface_discovery_runs(run_id) ON DELETE CASCADE,
  event_type          TEXT NOT NULL
                      CHECK (event_type IN ('new_host', 'new_port', 'new_subdomain', 'unexpected_cert_change')),
  severity            TEXT NOT NULL DEFAULT 'medium'
                      CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  asset_key           TEXT,
  hostname            TEXT,
  domain              TEXT,
  port                INTEGER,
  details_json        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_attack_surface_drift_run
  ON attack_surface_drift_events(run_id, event_id DESC);
CREATE INDEX IF NOT EXISTS idx_attack_surface_drift_type
  ON attack_surface_drift_events(event_type, created_at DESC);

CREATE TABLE IF NOT EXISTS attack_surface_exposures (
  asset_key              TEXT PRIMARY KEY,
  run_id                 BIGINT REFERENCES attack_surface_discovery_runs(run_id) ON DELETE SET NULL,
  internet_exposed       BOOLEAN NOT NULL DEFAULT FALSE,
  open_port_count        INTEGER NOT NULL DEFAULT 0,
  open_management_ports  TEXT[] NOT NULL DEFAULT ARRAY[]::text[],
  service_risk           INTEGER NOT NULL DEFAULT 0,
  exposure_score         INTEGER NOT NULL DEFAULT 0,
  exposure_level         TEXT NOT NULL DEFAULT 'low'
                         CHECK (exposure_level IN ('critical', 'high', 'medium', 'low')),
  details_json           JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_attack_surface_exposures_score
  ON attack_surface_exposures(exposure_score DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_surface_exposures_level
  ON attack_surface_exposures(exposure_level, updated_at DESC);

CREATE TABLE IF NOT EXISTS attack_surface_relationships (
  relationship_id      BIGSERIAL PRIMARY KEY,
  source_asset_key     TEXT NOT NULL,
  target_asset_key     TEXT NOT NULL,
  relation_type        TEXT NOT NULL,
  confidence           DOUBLE PRECISION NOT NULL DEFAULT 0.8,
  details_json         JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_by           TEXT,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (source_asset_key, target_asset_key, relation_type)
);
CREATE INDEX IF NOT EXISTS idx_attack_surface_relationships_source
  ON attack_surface_relationships(source_asset_key, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_surface_relationships_target
  ON attack_surface_relationships(target_asset_key, updated_at DESC);
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
AUTH_REFRESH_TOKENS_SQL = """
CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
  id                BIGSERIAL PRIMARY KEY,
  token_hash        TEXT NOT NULL UNIQUE,
  username          TEXT NOT NULL,
  role              TEXT NOT NULL DEFAULT 'viewer',
  issued_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at        TIMESTAMPTZ NOT NULL,
  replaced_by_hash  TEXT,
  revoked_at        TIMESTAMPTZ,
  revoked_reason    TEXT,
  client_ip         TEXT,
  user_agent        TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_username
  ON auth_refresh_tokens(username, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_active
  ON auth_refresh_tokens(username, expires_at DESC)
  WHERE revoked_at IS NULL;
"""

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
  retry_count      INTEGER NOT NULL DEFAULT 0,
  job_params_json  JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs(created_at DESC);
"""
ALTER_SCAN_JOBS_LOG = "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS log_output TEXT;"
ALTER_SCAN_JOBS_RETRY = (
    "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0;"
)
ALTER_SCAN_JOBS_PARAMS = "ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS job_params_json JSONB NOT NULL DEFAULT '{}'::jsonb;"

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
AI_SUMMARY_VERSIONS_SQL = """
CREATE TABLE IF NOT EXISTS ai_summary_versions (
  version_id       BIGSERIAL PRIMARY KEY,
  entity_type      TEXT NOT NULL,
  entity_key       TEXT NOT NULL,
  version_no       INTEGER NOT NULL,
  content_text     TEXT NOT NULL,
  provider         TEXT,
  model            TEXT,
  generated_by     TEXT,
  source_type      TEXT NOT NULL DEFAULT 'generated',
  context_json     JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_json    JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (entity_type, entity_key, version_no)
);
CREATE INDEX IF NOT EXISTS idx_ai_summary_versions_entity
  ON ai_summary_versions(entity_type, entity_key, version_no DESC);
CREATE INDEX IF NOT EXISTS idx_ai_summary_versions_created_at
  ON ai_summary_versions(created_at DESC);
"""
AI_FEEDBACK_SQL = """
CREATE TABLE IF NOT EXISTS ai_feedback (
  feedback_id      BIGSERIAL PRIMARY KEY,
  entity_type      TEXT NOT NULL,
  entity_key       TEXT NOT NULL,
  version_id       BIGINT REFERENCES ai_summary_versions(version_id) ON DELETE SET NULL,
  feedback         TEXT NOT NULL CHECK (feedback IN ('up', 'down')),
  comment          TEXT,
  context_json     JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by       TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ai_feedback_entity
  ON ai_feedback(entity_type, entity_key, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_feedback_feedback
  ON ai_feedback(feedback, created_at DESC);
"""
THREAT_IOCS_SQL = """
CREATE TABLE IF NOT EXISTS threat_iocs (
  id              SERIAL PRIMARY KEY,
  source          TEXT NOT NULL,
  indicator       TEXT NOT NULL,
  indicator_type  TEXT NOT NULL CHECK (indicator_type IN ('ip', 'domain')),
  feed_url        TEXT,
  first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_active       BOOLEAN NOT NULL DEFAULT TRUE,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (source, indicator_type, indicator)
);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_source
  ON threat_iocs(source, indicator_type);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_active
  ON threat_iocs(is_active, last_seen_at DESC);
CREATE TABLE IF NOT EXISTS threat_ioc_asset_matches (
  id              SERIAL PRIMARY KEY,
  threat_ioc_id   INTEGER NOT NULL REFERENCES threat_iocs(id) ON DELETE CASCADE,
  asset_id        INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
  asset_key       TEXT NOT NULL,
  match_field     TEXT NOT NULL,
  matched_value   TEXT NOT NULL,
  first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (threat_ioc_id, asset_id, match_field, matched_value)
);
CREATE INDEX IF NOT EXISTS idx_threat_ioc_matches_asset
  ON threat_ioc_asset_matches(asset_key, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_ioc_matches_ioc
  ON threat_ioc_asset_matches(threat_ioc_id, last_seen_at DESC);
"""
THREAT_INTEL_WORKSPACE_SQL = """
ALTER TABLE threat_iocs
  ADD COLUMN IF NOT EXISTS confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.6;
ALTER TABLE threat_iocs
  ADD COLUMN IF NOT EXISTS confidence_label TEXT NOT NULL DEFAULT 'medium';
ALTER TABLE threat_iocs
  ADD COLUMN IF NOT EXISTS source_priority INTEGER NOT NULL DEFAULT 50;
ALTER TABLE threat_iocs
  ADD COLUMN IF NOT EXISTS campaign_tag TEXT;
ALTER TABLE threat_iocs
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE threat_iocs
  ADD COLUMN IF NOT EXISTS last_match_count INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_threat_iocs_confidence
  ON threat_iocs(confidence_score DESC, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_campaign
  ON threat_iocs(campaign_tag, is_active, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS threat_ioc_sightings (
  sighting_id       BIGSERIAL PRIMARY KEY,
  threat_ioc_id     INTEGER NOT NULL REFERENCES threat_iocs(id) ON DELETE CASCADE,
  asset_id          INTEGER REFERENCES assets(asset_id) ON DELETE SET NULL,
  asset_key         TEXT NOT NULL,
  match_field       TEXT NOT NULL,
  matched_value     TEXT NOT NULL,
  source_event_id   BIGINT,
  source_event_ref  TEXT,
  source_tool       TEXT,
  sighted_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  context_json      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_threat_ioc_sightings_ioc_time
  ON threat_ioc_sightings(threat_ioc_id, sighted_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_ioc_sightings_asset_time
  ON threat_ioc_sightings(asset_key, sighted_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_ioc_sightings_source_ref
  ON threat_ioc_sightings(source_event_ref, sighted_at DESC);

CREATE TABLE IF NOT EXISTS threat_ioc_campaigns (
  campaign_id          BIGSERIAL PRIMARY KEY,
  campaign_tag         TEXT NOT NULL UNIQUE,
  title                TEXT NOT NULL,
  description          TEXT,
  confidence_weight    DOUBLE PRECISION NOT NULL DEFAULT 1.0,
  source_priority      INTEGER NOT NULL DEFAULT 50,
  confidence_label     TEXT NOT NULL DEFAULT 'medium',
  is_active            BOOLEAN NOT NULL DEFAULT TRUE,
  created_by           TEXT,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_threat_ioc_campaigns_active
  ON threat_ioc_campaigns(is_active, updated_at DESC);
"""
TELEMETRY_SECURITY_SQL = """
CREATE TABLE IF NOT EXISTS security_events (
  event_id         BIGSERIAL PRIMARY KEY,
  source           TEXT NOT NULL,
  event_type       TEXT NOT NULL DEFAULT 'event',
  asset_id         INTEGER REFERENCES assets(asset_id) ON DELETE SET NULL,
  asset_key        TEXT,
  collector        TEXT,
  ingest_job_id    INTEGER REFERENCES scan_jobs(job_id) ON DELETE SET NULL,
  raw_offset       BIGINT,
  raw_path         TEXT,
  severity         INTEGER,
  src_ip           TEXT,
  src_port         INTEGER,
  dst_ip           TEXT,
  dst_port         INTEGER,
  domain           TEXT,
  url              TEXT,
  protocol         TEXT,
  event_time       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ingest_lag_seconds DOUBLE PRECISION,
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
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS collector TEXT;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS ingest_job_id INTEGER REFERENCES scan_jobs(job_id) ON DELETE SET NULL;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS raw_offset BIGINT;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS raw_path TEXT;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS ingest_lag_seconds DOUBLE PRECISION;
CREATE INDEX IF NOT EXISTS idx_security_events_collector_time
  ON security_events(collector, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_ingest_job
  ON security_events(ingest_job_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_raw_path_offset
  ON security_events(raw_path, raw_offset DESC);

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
  rule_key           TEXT,
  version            INTEGER NOT NULL DEFAULT 1,
  mitre_tactic       TEXT,
  mitre_technique    TEXT,
  parent_rule_id     INTEGER REFERENCES detection_rules(rule_id) ON DELETE SET NULL,
  stage              TEXT NOT NULL DEFAULT 'active'
                     CHECK (stage IN ('draft', 'canary', 'active')),
  rule_format        TEXT NOT NULL DEFAULT 'json' CHECK (rule_format IN ('json', 'yaml', 'sigma')),
  severity           TEXT NOT NULL DEFAULT 'medium'
                     CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  enabled            BOOLEAN NOT NULL DEFAULT TRUE,
  definition_yaml    TEXT,
  definition_json    JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by         TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_tested_at     TIMESTAMPTZ,
  last_test_matches  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled
  ON detection_rules(enabled, updated_at DESC);
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS rule_key TEXT;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
UPDATE detection_rules SET version = 1 WHERE version IS NULL;
ALTER TABLE detection_rules ALTER COLUMN version SET NOT NULL;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS mitre_tactic TEXT;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS mitre_technique TEXT;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS parent_rule_id INTEGER REFERENCES detection_rules(rule_id) ON DELETE SET NULL;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS stage TEXT DEFAULT 'active';
UPDATE detection_rules SET stage = 'active' WHERE stage IS NULL;
ALTER TABLE detection_rules ALTER COLUMN stage SET NOT NULL;
ALTER TABLE detection_rules DROP CONSTRAINT IF EXISTS detection_rules_stage_check;
ALTER TABLE detection_rules ADD CONSTRAINT detection_rules_stage_check
  CHECK (stage IN ('draft', 'canary', 'active'));
ALTER TABLE detection_rules DROP CONSTRAINT IF EXISTS detection_rules_rule_format_check;
ALTER TABLE detection_rules ADD CONSTRAINT detection_rules_rule_format_check
  CHECK (rule_format IN ('json', 'yaml', 'sigma'));
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS definition_yaml TEXT;
CREATE INDEX IF NOT EXISTS idx_detection_rules_stage
  ON detection_rules(stage, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_detection_rules_parent
  ON detection_rules(parent_rule_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_rules_key_version
  ON detection_rules(rule_key, version)
  WHERE rule_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS detection_rule_runs (
  run_id             BIGSERIAL PRIMARY KEY,
  rule_id            INTEGER NOT NULL REFERENCES detection_rules(rule_id) ON DELETE CASCADE,
  executed_by        TEXT,
  lookback_hours     INTEGER NOT NULL DEFAULT 24,
  status             TEXT NOT NULL DEFAULT 'done' CHECK (status IN ('running', 'done', 'failed')),
  matches            INTEGER NOT NULL DEFAULT 0,
  run_mode           TEXT NOT NULL DEFAULT 'test' CHECK (run_mode IN ('test', 'simulate', 'scheduled')),
  trigger_source     TEXT NOT NULL DEFAULT 'manual',
  schedule_ref       TEXT,
  create_alerts      BOOLEAN NOT NULL DEFAULT FALSE,
  snapshot_hash      TEXT,
  snapshot_json      JSONB NOT NULL DEFAULT '{}'::jsonb,
  rule_version       INTEGER,
  rule_stage         TEXT,
  window_start       TIMESTAMPTZ,
  window_end         TIMESTAMPTZ,
  started_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at        TIMESTAMPTZ,
  error              TEXT,
  results_json       JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_detection_rule_runs_rule
  ON detection_rule_runs(rule_id, started_at DESC);
ALTER TABLE detection_rule_runs ADD COLUMN IF NOT EXISTS run_mode TEXT DEFAULT 'test';
UPDATE detection_rule_runs SET run_mode = 'test' WHERE run_mode IS NULL;
ALTER TABLE detection_rule_runs ALTER COLUMN run_mode SET NOT NULL;
ALTER TABLE detection_rule_runs DROP CONSTRAINT IF EXISTS detection_rule_runs_run_mode_check;
ALTER TABLE detection_rule_runs ADD CONSTRAINT detection_rule_runs_run_mode_check
  CHECK (run_mode IN ('test', 'simulate', 'scheduled'));
ALTER TABLE detection_rule_runs ADD COLUMN IF NOT EXISTS trigger_source TEXT DEFAULT 'manual';
UPDATE detection_rule_runs SET trigger_source = 'manual' WHERE trigger_source IS NULL;
ALTER TABLE detection_rule_runs ALTER COLUMN trigger_source SET NOT NULL;
ALTER TABLE detection_rule_runs ADD COLUMN IF NOT EXISTS schedule_ref TEXT;
ALTER TABLE detection_rule_runs ADD COLUMN IF NOT EXISTS create_alerts BOOLEAN DEFAULT FALSE;
UPDATE detection_rule_runs SET create_alerts = FALSE WHERE create_alerts IS NULL;
ALTER TABLE detection_rule_runs ALTER COLUMN create_alerts SET NOT NULL;
ALTER TABLE detection_rule_runs ADD COLUMN IF NOT EXISTS snapshot_hash TEXT;
ALTER TABLE detection_rule_runs ADD COLUMN IF NOT EXISTS snapshot_json JSONB DEFAULT '{}'::jsonb;
UPDATE detection_rule_runs SET snapshot_json = '{}'::jsonb WHERE snapshot_json IS NULL;
ALTER TABLE detection_rule_runs ALTER COLUMN snapshot_json SET NOT NULL;
ALTER TABLE detection_rule_runs ADD COLUMN IF NOT EXISTS rule_version INTEGER;
ALTER TABLE detection_rule_runs ADD COLUMN IF NOT EXISTS rule_stage TEXT;
ALTER TABLE detection_rule_runs ADD COLUMN IF NOT EXISTS window_start TIMESTAMPTZ;
ALTER TABLE detection_rule_runs ADD COLUMN IF NOT EXISTS window_end TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_detection_rule_runs_mode_started
  ON detection_rule_runs(run_mode, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_detection_rule_runs_snapshot_hash
  ON detection_rule_runs(snapshot_hash);

CREATE TABLE IF NOT EXISTS detection_correlation_rules (
  correlation_rule_id   SERIAL PRIMARY KEY,
  name                  TEXT NOT NULL UNIQUE,
  description           TEXT,
  severity              TEXT NOT NULL DEFAULT 'high'
                        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  enabled               BOOLEAN NOT NULL DEFAULT TRUE,
  group_by              TEXT NOT NULL DEFAULT 'asset_key'
                        CHECK (group_by IN ('asset_key', 'source_ip', 'none')),
  window_minutes        INTEGER NOT NULL DEFAULT 60,
  min_distinct_sources  INTEGER NOT NULL DEFAULT 1,
  mitre_tactic          TEXT,
  mitre_technique       TEXT,
  definition_json       JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by            TEXT,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_run_at           TIMESTAMPTZ,
  last_match_count      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_detection_correlation_rules_enabled
  ON detection_correlation_rules(enabled, updated_at DESC);

CREATE TABLE IF NOT EXISTS detection_correlation_runs (
  run_id                BIGSERIAL PRIMARY KEY,
  correlation_rule_id   INTEGER NOT NULL
                        REFERENCES detection_correlation_rules(correlation_rule_id)
                        ON DELETE CASCADE,
  executed_by           TEXT,
  run_mode              TEXT NOT NULL DEFAULT 'manual'
                        CHECK (run_mode IN ('manual', 'job', 'scheduled')),
  trigger_source        TEXT NOT NULL DEFAULT 'manual',
  schedule_ref          TEXT,
  lookback_minutes      INTEGER NOT NULL DEFAULT 60,
  window_start          TIMESTAMPTZ NOT NULL,
  window_end            TIMESTAMPTZ NOT NULL,
  matched_chains        INTEGER NOT NULL DEFAULT 0,
  alerts_created        INTEGER NOT NULL DEFAULT 0,
  snapshot_hash         TEXT,
  snapshot_json         JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at           TIMESTAMPTZ,
  error                 TEXT
);
CREATE INDEX IF NOT EXISTS idx_detection_correlation_runs_rule
  ON detection_correlation_runs(correlation_rule_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_detection_correlation_runs_mode
  ON detection_correlation_runs(run_mode, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_detection_correlation_runs_snapshot
  ON detection_correlation_runs(snapshot_hash);

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
"""


def _bcrypt_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _acquire_startup_migration_lock(conn: Any) -> None:
    """Serialize startup migrations to avoid concurrent DDL deadlocks."""
    try:
        conn.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": 781245903})
    except Exception:
        # Non-Postgres engines or restricted permissions: continue best-effort.
        logger.debug("startup_migration: advisory lock unavailable", exc_info=True)


def _execute_with_deadlock_retry(
    conn: Any,
    sql: str,
    params: dict[str, Any] | None = None,
    *,
    retries: int = 4,
    initial_delay_seconds: float = 0.1,
) -> None:
    """Execute SQL and bubble retryable deadlock state to caller."""
    try:
        conn.execute(text(sql), params or {})
    except Exception as exc:
        msg = str(exc).lower()
        if "deadlock detected" in msg or "current transaction is aborted" in msg:
            raise _RetryableStartupMigrationError(
                "startup migration transaction should retry"
            ) from exc
        raise


def _is_retryable_startup_error(exc: Exception) -> bool:
    if isinstance(exc, _RetryableStartupMigrationError):
        return True
    msg = str(exc).lower()
    return "deadlock detected" in msg or "current transaction is aborted" in msg


def _column_exists(conn: Any, table_name: str, column_name: str) -> bool:
    row = (
        conn.execute(
            text(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = :table_name
                  AND column_name = :column_name
                LIMIT 1
                """
            ),
            {"table_name": table_name, "column_name": column_name},
        )
        .mappings()
        .first()
    )
    return bool(row)


def _run_startup_migrations_once() -> None:
    """Create audit_events and alert_states if missing (e.g. DB created before they were in init.sql)."""
    with engine.begin() as conn:
        _acquire_startup_migration_lock(conn)
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
        try:
            for stmt in FINDINGS_SCANNER_METADATA_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            logger.info("startup_migration: ensured findings scanner metadata columns exist")
        except Exception as e:
            logger.warning("startup_migration: findings scanner metadata failed: %s", e)
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
        # Findings: contextual risk scoring columns (Phase AI-2).
        # Backfill runs later after all dependent telemetry tables exist.
        try:
            for stmt in FINDINGS_RISK_SCORING_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            logger.info("startup_migration: ensured findings risk scoring columns exist")
        except Exception as e:
            logger.warning("startup_migration: findings risk scoring columns failed: %s", e)
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
        try:
            for stmt in RISK_ENTITY_SNAPSHOTS_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            logger.info("startup_migration: ensured risk_entity_snapshots table exists")
        except Exception as e:
            logger.warning("startup_migration: risk_entity_snapshots failed: %s", e)
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
            for stmt in INCIDENT_RESPONSE_MATURITY_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            logger.info("startup_migration: ensured incidents tables exist")
        except Exception as e:
            logger.warning("startup_migration: incidents failed: %s", e)
            raise
        try:
            for stmt in AUTOMATION_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            logger.info("startup_migration: ensured automation tables exist")
        except Exception as e:
            logger.warning("startup_migration: automation failed: %s", e)
            raise
        try:
            for stmt in ATTACK_SURFACE_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(text(stmt))
            logger.info("startup_migration: ensured attack-surface tables exist")
        except Exception as e:
            logger.warning("startup_migration: attack-surface failed: %s", e)
            raise
        # Users table for RBAC (Phase B.1)
        try:
            for stmt in USERS_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    _execute_with_deadlock_retry(conn, stmt)
            if not _column_exists(conn, "users", "password_hash"):
                _execute_with_deadlock_retry(conn, USERS_ADD_PASSWORD_COLUMN)
            _execute_with_deadlock_retry(
                conn,
                "INSERT INTO users (username, role) VALUES (:u, 'admin') ON CONFLICT (username) DO NOTHING",
                {"u": settings.ADMIN_USERNAME},
            )
            # Seed viewer account (password: viewer). Pre-computed hash to avoid passlib/bcrypt
            # backend detection bug (ValueError: password cannot be longer than 72 bytes) in some envs.
            VIEWER_BCRYPT_HASH = "$2b$12$wITIujVXwHS5q4g/TLizOeTTDFWkpEC9/sAz6h20H5x4GXzz37WGW"
            _execute_with_deadlock_retry(
                conn,
                """
                    INSERT INTO users (username, role, password_hash)
                    VALUES ('viewer', 'viewer', :ph)
                    ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
                    WHERE users.username = 'viewer'
                """,
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
                _execute_with_deadlock_retry(
                    conn,
                    """
                        INSERT INTO users (username, role, password_hash, disabled)
                        VALUES (:u, :r, :ph, FALSE)
                        ON CONFLICT (username) DO UPDATE
                        SET role = EXCLUDED.role,
                            password_hash = EXCLUDED.password_hash,
                            disabled = FALSE
                    """,
                    {"u": username, "r": role, "ph": _bcrypt_hash(password)},
                )

            logger.info(
                "startup_migration: ensured users table exists, admin/viewer/service identities seeded"
            )
        except Exception as e:
            logger.warning("startup_migration: users failed: %s", e)
            raise
        # Refresh token persistence (Phase 11 auth hardening)
        try:
            for stmt in AUTH_REFRESH_TOKENS_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    _execute_with_deadlock_retry(conn, stmt)
            logger.info("startup_migration: ensured auth_refresh_tokens table exists")
        except Exception as e:
            logger.warning("startup_migration: auth_refresh_tokens failed: %s", e)
            raise
        # scan_jobs (Phase B.3)
        try:
            for stmt in SCAN_JOBS_SQL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    _execute_with_deadlock_retry(conn, stmt)
            if not _column_exists(conn, "scan_jobs", "log_output"):
                _execute_with_deadlock_retry(conn, ALTER_SCAN_JOBS_LOG)
            if not _column_exists(conn, "scan_jobs", "retry_count"):
                _execute_with_deadlock_retry(conn, ALTER_SCAN_JOBS_RETRY)
            if not _column_exists(conn, "scan_jobs", "job_params_json"):
                _execute_with_deadlock_retry(conn, ALTER_SCAN_JOBS_PARAMS)
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
            ("ai_summary_versions", AI_SUMMARY_VERSIONS_SQL),
            ("ai_feedback", AI_FEEDBACK_SQL),
            ("threat_iocs", THREAT_IOCS_SQL),
            ("threat_intel_workspace", THREAT_INTEL_WORKSPACE_SQL),
            ("telemetry_security", TELEMETRY_SECURITY_SQL),
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
        # Run risk scoring backfill last because the context query now joins
        # telemetry and anomaly tables created above.
        try:
            updated = backfill_finding_risk_scores(conn)
            logger.info("startup_migration: findings risk scoring backfilled=%s", updated)
        except Exception as e:
            logger.warning("startup_migration: findings risk scoring backfill failed: %s", e)
            raise


def run_startup_migrations() -> None:
    """Run startup migrations with bounded full-transaction retry on deadlock."""
    global _startup_migrations_completed
    if _startup_migrations_completed:
        return
    with _startup_migrations_state_lock:
        if _startup_migrations_completed:
            return
        max_retries = 4
        initial_delay_seconds = 0.1
        for attempt in range(max_retries + 1):
            try:
                _run_startup_migrations_once()
                _startup_migrations_completed = True
                return
            except Exception as exc:
                if not _is_retryable_startup_error(exc) or attempt >= max_retries:
                    raise
                delay = initial_delay_seconds * (2**attempt)
                logger.warning(
                    "startup_migration: retrying full migration transaction after deadlock "
                    "(attempt=%s delay=%.3fs): %s",
                    attempt + 1,
                    delay,
                    exc,
                )
                time.sleep(delay)

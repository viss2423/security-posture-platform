-- Phase B.2: Policy-as-code bundles (YAML definitions, draft/approved, evaluation).
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

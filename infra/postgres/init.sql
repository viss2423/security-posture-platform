CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Single assets table matching API and migrations (asset_id for findings FK)
CREATE TABLE IF NOT EXISTS assets (
  asset_id       SERIAL PRIMARY KEY,
  asset_key      TEXT NOT NULL UNIQUE,
  type           TEXT NOT NULL,
  name           TEXT NOT NULL,
  owner          TEXT,
  owner_team     TEXT,
  owner_email    TEXT,
  asset_type     TEXT NOT NULL DEFAULT 'service',
  environment    TEXT NOT NULL DEFAULT 'dev',
  criticality    TEXT NOT NULL DEFAULT 'medium',
  verified       BOOLEAN DEFAULT FALSE,
  verification_method TEXT,
  verification_token  TEXT,
  address        TEXT,
  port           INTEGER,
  is_active      BOOLEAN NOT NULL DEFAULT TRUE,
  tags           TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_env ON assets(environment);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_assets_asset_key ON assets(asset_key);
CREATE INDEX IF NOT EXISTS idx_assets_tags ON assets USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_assets_metadata ON assets USING GIN(metadata);

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_assets_updated_at ON assets;
CREATE TRIGGER trg_assets_updated_at
BEFORE UPDATE ON assets
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS findings (
  finding_id   SERIAL PRIMARY KEY,
  asset_id     INTEGER REFERENCES assets(asset_id),
  time         TIMESTAMPTZ DEFAULT NOW(),
  category     TEXT,
  title        TEXT NOT NULL,
  severity     TEXT NOT NULL,
  confidence   TEXT NOT NULL,
  evidence     TEXT,
  remediation  TEXT
);

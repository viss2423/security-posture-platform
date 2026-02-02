CREATE TABLE IF NOT EXISTS assets (
  asset_id SERIAL PRIMARY KEY,
  type TEXT NOT NULL,
  name TEXT NOT NULL,
  owner TEXT,
  criticality INTEGER DEFAULT 3,
  verified BOOLEAN DEFAULT FALSE,
  verification_method TEXT,
  verification_token TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings (
  finding_id SERIAL PRIMARY KEY,
  asset_id INTEGER REFERENCES assets(asset_id),
  time TIMESTAMPTZ DEFAULT NOW(),
  category TEXT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  evidence TEXT,
  remediation TEXT
);

-- =========================
-- SecPlat Asset Inventory
-- =========================

-- Needed for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS assets (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Stable key used across signals + dashboards (e.g., "secplat-api", "juice-shop")
  asset_key     TEXT NOT NULL UNIQUE,

  name          TEXT NOT NULL,

  -- Examples: service, host, webapp, database, pipeline
  asset_type    TEXT NOT NULL,

  -- Examples: dev, test, stage, prod
  environment   TEXT NOT NULL DEFAULT 'dev',

  -- Examples: low, medium, high, critical
  criticality   TEXT NOT NULL DEFAULT 'medium',

  owner_team    TEXT,
  owner_email   TEXT,

  -- Where it runs / how to reach it (optional but useful)
  address       TEXT,
  port          INTEGER,

  is_active     BOOLEAN NOT NULL DEFAULT TRUE,

  -- Flexible metadata
  tags          TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,

  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_env ON assets(environment);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_assets_tags ON assets USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_assets_metadata ON assets USING GIN(metadata);

-- Auto-update updated_at
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

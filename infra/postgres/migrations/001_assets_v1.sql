-- SecPlat migration: bring existing assets table up to v1 schema (non-destructive)

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Add missing columns safely
ALTER TABLE assets
  ADD COLUMN IF NOT EXISTS name TEXT,
  ADD COLUMN IF NOT EXISTS asset_type TEXT,
  ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT 'dev',
  ADD COLUMN IF NOT EXISTS criticality TEXT NOT NULL DEFAULT 'medium',
  ADD COLUMN IF NOT EXISTS owner_team TEXT,
  ADD COLUMN IF NOT EXISTS owner_email TEXT,
  ADD COLUMN IF NOT EXISTS address TEXT,
  ADD COLUMN IF NOT EXISTS port INTEGER,
  ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Backfill name from asset_key if possible
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='assets' AND column_name='asset_key'
  ) THEN
    UPDATE assets
      SET name = COALESCE(name, asset_key)
    WHERE name IS NULL;
  END IF;
END $$;

-- Default asset_type where missing
UPDATE assets
  SET asset_type = COALESCE(asset_type, 'service')
WHERE asset_type IS NULL;

-- Indexes (will only work after columns exist)
CREATE INDEX IF NOT EXISTS idx_assets_env ON assets(environment);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_assets_tags ON assets USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_assets_metadata ON assets USING GIN(metadata);

-- updated_at trigger
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

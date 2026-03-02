-- Extend existing assets table to support inventory + OpenSearch sync

-- 1) Add missing columns
ALTER TABLE assets
  ADD COLUMN IF NOT EXISTS asset_key TEXT,
  ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- 2) Backfill asset_key for existing rows
-- Use a deterministic value derived from name if asset_key is null.
-- (You can later manually update these to nicer keys.)
UPDATE assets
SET asset_key = lower(regexp_replace(name, '[^a-zA-Z0-9]+', '-', 'g'))
WHERE asset_key IS NULL;

-- 3) Ensure asset_key is unique + not null going forward
-- If duplicates happen (two assets with same name), fix manually before enabling UNIQUE.
-- This query lets you check duplicates:
--   SELECT asset_key, COUNT(*) FROM assets GROUP BY asset_key HAVING COUNT(*) > 1;

ALTER TABLE assets
  ALTER COLUMN asset_key SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'assets_asset_key_unique'
  ) THEN
    ALTER TABLE assets ADD CONSTRAINT assets_asset_key_unique UNIQUE (asset_key);
  END IF;
END $$;

-- 4) Indexes for common filters
CREATE INDEX IF NOT EXISTS idx_assets_asset_key ON assets(asset_key);
CREATE INDEX IF NOT EXISTS idx_assets_environment ON assets(environment);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_assets_tags ON assets USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_assets_metadata ON assets USING GIN(metadata);

-- 5) updated_at trigger
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
EXECUTE FUNCTION set_updated_at()

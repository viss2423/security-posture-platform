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

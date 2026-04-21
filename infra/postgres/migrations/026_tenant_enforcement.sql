ALTER TABLE assets ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE assets SET org_id = COALESCE(NULLIF(BTRIM(org_id), ''), COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default'));
ALTER TABLE assets ALTER COLUMN org_id SET DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default');
ALTER TABLE assets ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_org_id ON assets(org_id);

ALTER TABLE findings ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE findings SET org_id = COALESCE(NULLIF(BTRIM(org_id), ''), COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default'));
ALTER TABLE findings ALTER COLUMN org_id SET DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default');
ALTER TABLE findings ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_org_id ON findings(org_id);

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE incidents SET org_id = COALESCE(NULLIF(BTRIM(org_id), ''), COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default'));
ALTER TABLE incidents ALTER COLUMN org_id SET DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default');
ALTER TABLE incidents ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_incidents_org_id ON incidents(org_id);

ALTER TABLE incident_alerts ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE incident_alerts SET org_id = COALESCE(NULLIF(BTRIM(org_id), ''), COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default'));
ALTER TABLE incident_alerts ALTER COLUMN org_id SET DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default');
ALTER TABLE incident_alerts ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_incident_alerts_org_id ON incident_alerts(org_id);

ALTER TABLE incident_notes ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE incident_notes SET org_id = COALESCE(NULLIF(BTRIM(org_id), ''), COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default'));
ALTER TABLE incident_notes ALTER COLUMN org_id SET DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default');
ALTER TABLE incident_notes ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_incident_notes_org_id ON incident_notes(org_id);

ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE scan_jobs SET org_id = COALESCE(NULLIF(BTRIM(org_id), ''), COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default'));
ALTER TABLE scan_jobs ALTER COLUMN org_id SET DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default');
ALTER TABLE scan_jobs ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_jobs_org_id ON scan_jobs(org_id);

ALTER TABLE security_events ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE security_events SET org_id = COALESCE(NULLIF(BTRIM(org_id), ''), COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default'));
ALTER TABLE security_events ALTER COLUMN org_id SET DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default');
ALTER TABLE security_events ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_events_org_id ON security_events(org_id);

ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE security_alerts SET org_id = COALESCE(NULLIF(BTRIM(org_id), ''), COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default'));
ALTER TABLE security_alerts ALTER COLUMN org_id SET DEFAULT COALESCE(NULLIF(current_setting('secplat.tenant_id', true), ''), 'default');
ALTER TABLE security_alerts ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_alerts_org_id ON security_alerts(org_id);

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_assets ON assets;
CREATE POLICY secplat_tenant_assets ON assets
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_findings ON findings;
CREATE POLICY secplat_tenant_findings ON findings
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_incidents ON incidents;
CREATE POLICY secplat_tenant_incidents ON incidents
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE incident_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_alerts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_incident_alerts ON incident_alerts;
CREATE POLICY secplat_tenant_incident_alerts ON incident_alerts
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE incident_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_notes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_incident_notes ON incident_notes;
CREATE POLICY secplat_tenant_incident_notes ON incident_notes
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_scan_jobs ON scan_jobs;
CREATE POLICY secplat_tenant_scan_jobs ON scan_jobs
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_security_events ON security_events;
CREATE POLICY secplat_tenant_security_events ON security_events
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE security_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_alerts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_security_alerts ON security_alerts;
CREATE POLICY secplat_tenant_security_alerts ON security_alerts
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

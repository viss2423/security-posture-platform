ALTER TABLE policy_bundles ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE policy_bundles SET org_id = COALESCE(org_id, COALESCE(current_setting('secplat.tenant_id', true), 'default'));
ALTER TABLE policy_bundles ALTER COLUMN org_id SET DEFAULT COALESCE(current_setting('secplat.tenant_id', true), 'default');
ALTER TABLE policy_bundles ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_policy_bundles_org_id ON policy_bundles(org_id);

ALTER TABLE policy_evaluation_runs ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE policy_evaluation_runs SET org_id = COALESCE(org_id, COALESCE(current_setting('secplat.tenant_id', true), 'default'));
ALTER TABLE policy_evaluation_runs ALTER COLUMN org_id SET DEFAULT COALESCE(current_setting('secplat.tenant_id', true), 'default');
ALTER TABLE policy_evaluation_runs ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_policy_evaluation_runs_org_id ON policy_evaluation_runs(org_id);

ALTER TABLE incident_ai_summaries ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE incident_ai_summaries SET org_id = COALESCE(org_id, COALESCE(current_setting('secplat.tenant_id', true), 'default'));
ALTER TABLE incident_ai_summaries ALTER COLUMN org_id SET DEFAULT COALESCE(current_setting('secplat.tenant_id', true), 'default');
ALTER TABLE incident_ai_summaries ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_incident_ai_summaries_org_id ON incident_ai_summaries(org_id);

ALTER TABLE policy_evaluation_ai_summaries ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE policy_evaluation_ai_summaries SET org_id = COALESCE(org_id, COALESCE(current_setting('secplat.tenant_id', true), 'default'));
ALTER TABLE policy_evaluation_ai_summaries ALTER COLUMN org_id SET DEFAULT COALESCE(current_setting('secplat.tenant_id', true), 'default');
ALTER TABLE policy_evaluation_ai_summaries ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_policy_evaluation_ai_summaries_org_id ON policy_evaluation_ai_summaries(org_id);

ALTER TABLE finding_ai_explanations ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE finding_ai_explanations SET org_id = COALESCE(org_id, COALESCE(current_setting('secplat.tenant_id', true), 'default'));
ALTER TABLE finding_ai_explanations ALTER COLUMN org_id SET DEFAULT COALESCE(current_setting('secplat.tenant_id', true), 'default');
ALTER TABLE finding_ai_explanations ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_finding_ai_explanations_org_id ON finding_ai_explanations(org_id);

ALTER TABLE asset_ai_diagnoses ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE asset_ai_diagnoses SET org_id = COALESCE(org_id, COALESCE(current_setting('secplat.tenant_id', true), 'default'));
ALTER TABLE asset_ai_diagnoses ALTER COLUMN org_id SET DEFAULT COALESCE(current_setting('secplat.tenant_id', true), 'default');
ALTER TABLE asset_ai_diagnoses ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_asset_ai_diagnoses_org_id ON asset_ai_diagnoses(org_id);

ALTER TABLE job_ai_triages ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE job_ai_triages SET org_id = COALESCE(org_id, COALESCE(current_setting('secplat.tenant_id', true), 'default'));
ALTER TABLE job_ai_triages ALTER COLUMN org_id SET DEFAULT COALESCE(current_setting('secplat.tenant_id', true), 'default');
ALTER TABLE job_ai_triages ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_job_ai_triages_org_id ON job_ai_triages(org_id);

ALTER TABLE alert_ai_guidance ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE alert_ai_guidance SET org_id = COALESCE(org_id, COALESCE(current_setting('secplat.tenant_id', true), 'default'));
ALTER TABLE alert_ai_guidance ALTER COLUMN org_id SET DEFAULT COALESCE(current_setting('secplat.tenant_id', true), 'default');
ALTER TABLE alert_ai_guidance ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alert_ai_guidance_org_id ON alert_ai_guidance(org_id);

ALTER TABLE policy_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_bundles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_policy_bundles ON policy_bundles;
CREATE POLICY secplat_tenant_policy_bundles ON policy_bundles
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE policy_evaluation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_evaluation_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_policy_evaluation_runs ON policy_evaluation_runs;
CREATE POLICY secplat_tenant_policy_evaluation_runs ON policy_evaluation_runs
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE incident_ai_summaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_ai_summaries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_incident_ai_summaries ON incident_ai_summaries;
CREATE POLICY secplat_tenant_incident_ai_summaries ON incident_ai_summaries
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE policy_evaluation_ai_summaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_evaluation_ai_summaries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_policy_eval_ai_summaries ON policy_evaluation_ai_summaries;
CREATE POLICY secplat_tenant_policy_eval_ai_summaries ON policy_evaluation_ai_summaries
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE finding_ai_explanations ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_ai_explanations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_finding_ai_explanations ON finding_ai_explanations;
CREATE POLICY secplat_tenant_finding_ai_explanations ON finding_ai_explanations
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE asset_ai_diagnoses ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_ai_diagnoses FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_asset_ai_diagnoses ON asset_ai_diagnoses;
CREATE POLICY secplat_tenant_asset_ai_diagnoses ON asset_ai_diagnoses
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE job_ai_triages ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_ai_triages FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_job_ai_triages ON job_ai_triages;
CREATE POLICY secplat_tenant_job_ai_triages ON job_ai_triages
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

ALTER TABLE alert_ai_guidance ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_ai_guidance FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secplat_tenant_alert_ai_guidance ON alert_ai_guidance;
CREATE POLICY secplat_tenant_alert_ai_guidance ON alert_ai_guidance
USING (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'))
WITH CHECK (org_id = COALESCE(current_setting('secplat.tenant_id', true), 'default'));

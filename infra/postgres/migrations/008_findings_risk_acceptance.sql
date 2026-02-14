-- Findings lifecycle: risk acceptance (Phase A.2)
-- Status flow: open | in_progress | remediated | accepted_risk

ALTER TABLE findings ADD COLUMN IF NOT EXISTS accepted_risk_at TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS accepted_risk_expires_at TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS accepted_risk_reason TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS accepted_risk_by TEXT;

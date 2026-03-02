-- Phase AI-2: contextual finding risk scoring

ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_score INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_level TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_factors_json JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON findings(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_risk_level ON findings(risk_level);

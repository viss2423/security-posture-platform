CREATE TABLE IF NOT EXISTS finding_risk_labels (
  id            SERIAL PRIMARY KEY,
  finding_id    INTEGER NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
  label         TEXT NOT NULL CHECK (label IN ('incident_worthy', 'benign')),
  source        TEXT NOT NULL DEFAULT 'analyst'
                 CHECK (source IN ('analyst', 'incident_linked', 'accepted_risk', 'imported')),
  note          TEXT,
  created_by    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_finding_risk_labels_finding_id
  ON finding_risk_labels(finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_finding_risk_labels_label
  ON finding_risk_labels(label, created_at DESC);

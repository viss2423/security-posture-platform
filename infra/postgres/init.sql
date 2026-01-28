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


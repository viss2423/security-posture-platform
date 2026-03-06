CREATE TABLE IF NOT EXISTS threat_iocs (
  id              SERIAL PRIMARY KEY,
  source          TEXT NOT NULL,
  indicator       TEXT NOT NULL,
  indicator_type  TEXT NOT NULL CHECK (indicator_type IN ('ip', 'domain')),
  feed_url        TEXT,
  first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_active       BOOLEAN NOT NULL DEFAULT TRUE,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (source, indicator_type, indicator)
);

CREATE INDEX IF NOT EXISTS idx_threat_iocs_source
  ON threat_iocs(source, indicator_type);

CREATE INDEX IF NOT EXISTS idx_threat_iocs_active
  ON threat_iocs(is_active, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS threat_ioc_asset_matches (
  id              SERIAL PRIMARY KEY,
  threat_ioc_id   INTEGER NOT NULL REFERENCES threat_iocs(id) ON DELETE CASCADE,
  asset_id        INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
  asset_key       TEXT NOT NULL,
  match_field     TEXT NOT NULL,
  matched_value   TEXT NOT NULL,
  first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (threat_ioc_id, asset_id, match_field, matched_value)
);

CREATE INDEX IF NOT EXISTS idx_threat_ioc_matches_asset
  ON threat_ioc_asset_matches(asset_key, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_threat_ioc_matches_ioc
  ON threat_ioc_asset_matches(threat_ioc_id, last_seen_at DESC);

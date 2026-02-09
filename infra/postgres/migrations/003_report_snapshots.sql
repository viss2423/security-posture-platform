-- Store posture report snapshots for history view (weekly report job or manual save).

CREATE TABLE IF NOT EXISTS posture_report_snapshots (
  id                SERIAL PRIMARY KEY,
  period            TEXT NOT NULL DEFAULT '24h',
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  uptime_pct        DOUBLE PRECISION NOT NULL DEFAULT 0,
  posture_score_avg DOUBLE PRECISION,
  avg_latency_ms    DOUBLE PRECISION,
  total_assets      INTEGER NOT NULL DEFAULT 0,
  green             INTEGER NOT NULL DEFAULT 0,
  amber             INTEGER NOT NULL DEFAULT 0,
  red               INTEGER NOT NULL DEFAULT 0,
  top_incidents     JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_report_snapshots_created_at ON posture_report_snapshots(created_at DESC);

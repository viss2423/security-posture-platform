-- Ensure default assets exist (so posture list and ingestion have juice-shop etc.)
-- Idempotent: only inserts when asset_key is missing.

INSERT INTO assets (asset_key, type, name, asset_type, environment, criticality)
VALUES
  ('secplat-api',   'app', 'secplat-api',   'service', 'dev', 'medium'),
  ('verify-web',    'app', 'verify-web',    'service', 'dev', 'medium'),
  ('example-com',   'app', 'example-com',   'service', 'dev', 'medium'),
  ('juice-shop',    'app', 'Juice Shop',    'service', 'dev', 'medium')
ON CONFLICT (asset_key) DO NOTHING;

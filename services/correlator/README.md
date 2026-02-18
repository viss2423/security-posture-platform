# secplat-correlator (Phase 3.1)

Consumes `secplat.events.correlation` and creates incidents via the API.

- **finding.created** — one incident per new finding: title "Finding: {finding_key} on {asset_key}", links that asset.
- **alert.triggered** — one incident for down-asset alert: title "Assets down: A, B, C...", links all asset_keys.

**Env:** `REDIS_URL`, `API_URL`, `CORRELATOR_USER`, `CORRELATOR_PASSWORD` (default: same as API admin). Uses consumer group `correlators` on stream `secplat.events.correlation`.

**Publishers (API):** POST /findings (new finding) and POST /posture/alert/send (down assets) publish to this stream when Redis is configured.

See [docs/SECPLAT-CORPORATE-ROADMAP.md](../../docs/SECPLAT-CORPORATE-ROADMAP.md).

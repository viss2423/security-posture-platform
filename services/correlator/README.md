# secplat-correlator (Phase 3.1)

Consumes `secplat.events.correlation` and creates incidents via the API.

- `finding.created`: one incident per finding key and asset.
- `alert.triggered`: one incident per down-assets correlation window.
- Reclaims stale pending entries with `XAUTOCLAIM`.
- Uses bounded retries and sends exhausted/invalid events to `secplat.events.correlation.dlq`.
- Uses `incident_key` idempotency to avoid duplicate incidents on retries/reclaims.

Env:
- `REDIS_URL`
- `API_URL`
- `CORRELATOR_USER`
- `CORRELATOR_PASSWORD`
- Optional tuning: `CORRELATOR_STREAM_MAX_RETRIES`, `CORRELATOR_STREAM_CLAIM_IDLE_MS`

Publishers (API):
- `POST /findings` for `finding.created`
- `POST /posture/alert/send` for `alert.triggered`

See [docs/SECPLAT-CORPORATE-ROADMAP.md](../../docs/SECPLAT-CORPORATE-ROADMAP.md).

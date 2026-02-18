# secplat-deriver (Posture Derivation Service)

**Phase 2.1.** Replaces `build_asset_status.sh`.

- Reads assets from `secplat-assets` and latest health events from `secplat-events`
- Computes status (up/stale/unknown/down), posture_score, posture_state, last_status_change
- Writes one doc per asset to `secplat-asset-status` (same schema as the shell script)

**Env:** `OPENSEARCH_URL`, `STALE_THRESHOLD_SECONDS` (default 300), `DERIVER_INTERVAL_SECONDS` (default 60).

**Run:** `docker compose --profile roadmap up -d deriver`

**Optional:** To avoid duplicate writes, run only one writer of asset-status. If deriver is running, set `SKIP_BUILD_ASSET_STATUS=true` for the ingestion service so it skips `build_asset_status.sh`.

See [docs/SECPLAT-CORPORATE-ROADMAP.md](../../docs/SECPLAT-CORPORATE-ROADMAP.md) and [docs/architecture.md](../../docs/architecture.md).

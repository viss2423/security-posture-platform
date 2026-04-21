# Stability Contract (Phase 1)

This contract defines customer-facing reliability targets and the release gate policy for this platform.

## Service Objectives

| SLO name | Comparator | Target | Meaning |
| --- | --- | --- | --- |
| `api_availability` | `>=` | `0.995` | API monthly availability ratio |
| `api_p95_latency_ms` | `<=` | `500` | p95 latency for core API paths |
| `ingestion_visibility_seconds` | `<=` | `120` | Event ingestion to searchable data latency |
| `alert_creation_seconds` | `<=` | `180` | Detection/correlation to alert creation latency |
| `background_job_freshness_minutes` | `<=` | `30` | Max age for critical scheduled job completion |

## Release Gate Policy

- Window: `28` days.
- Missing SLI values fail the gate by default.
- When `api_availability` error budget consumption is greater than `1.0`, feature releases are paused.
- In freeze mode, only reliability/security fixes may ship.

## API Endpoints

- `GET /platform/stability-contract`
- `POST /platform/release-gate/evaluate`

## CLI Check

```bash
cd services/api
python scripts/check_release_gate.py --allow-sample-fallback
```

Priority order for SLI input:

1. `--input` (path or inline JSON)
2. `SECPLAT_SLI_REPORT_JSON` (inline JSON)
3. `SECPLAT_SLI_REPORT_PATH` (path to JSON file)
4. `./examples/sli-report.json` (only if `--allow-sample-fallback` is set)

Input payload supports either:

```json
{
  "measurements": {
    "api_availability": 0.996,
    "api_p95_latency_ms": 420,
    "ingestion_visibility_seconds": 90,
    "alert_creation_seconds": 150,
    "background_job_freshness_minutes": 18
  }
}
```

or a raw JSON object with the same measurement keys at top-level.

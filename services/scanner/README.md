# SecPlat Scanner

Runs TLS and security-headers checks on targets and writes findings to the API (Postgres). Runs on a schedule (default every 6h).

## Both scope options

### 1. Internal lab only (`SCANNER_SCOPE=internal_only`)

- Scans only **internal** targets derived from env:
  - `VERIFY_WEB_URL` → `verify-web`
  - `JUICE_URL` → `juice-shop`
  - `API_URL` → `secplat-api`
- Override with `INTERNAL_TARGETS`: comma-separated `url|asset_key` (e.g. `http://verify-web|verify-web,http://juiceshop:3000|juice-shop`).
- No API call to list assets; no external domains.

### 2. Internal + verified external (`SCANNER_SCOPE=internal_and_verified`)

- Same internal targets as above.
- **Plus** assets from `GET /assets` with `verified=true` and `type=external_web`. URL from `address` or `https://{asset_key}`.
- Capped at `SCANNER_MAX_TARGETS` (default 50).
- Only verified domains (proof-of-ownership) are scanned.

## Env

| Env | Default | Description |
|-----|---------|-------------|
| `SCANNER_SCOPE` | `internal_only` | `internal_only` or `internal_and_verified` |
| `API_URL` | `http://api:8000` | API base URL |
| `SCAN_INTERVAL_SECONDS` | `21600` (6h) | Seconds between full runs |
| `VERIFY_WEB_URL`, `JUICE_URL`, `API_URL` | — | Used to build internal target list if `INTERNAL_TARGETS` unset |
| `INTERNAL_TARGETS` | (from vars above) | Optional `url\|asset_key,url\|asset_key` |
| `SCANNER_MAX_TARGETS` | `50` | Max verified external targets |
| `SCANNER_REQUEST_TIMEOUT` | `15.0` | HTTP timeout per request |

## Checks

- **TLS:** cert expiry (critical if expired, high if &lt; 14 days), verification failure, no HTTPS.
- **Headers:** missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options (each reported as a finding).

Findings are upserted by `finding_key` (dedupe); repeat runs update `last_seen`.

# SecPlat Scanner

Runs TLS/security-header checks on targets and can optionally run OSV and Trivy repository scans against the repo workspace. All findings are written to the API (Postgres) on a schedule (default every 6h).

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
| `SCANNER_API_USERNAME` | `${SCANNER_SERVICE_USERNAME}` | API login user used for protected `/assets` and `/findings` |
| `SCANNER_API_PASSWORD` | `${SCANNER_SERVICE_PASSWORD}` | API login password used for protected endpoints |
| `DEPENDENCY_SCAN_ENABLED` | `false` | When `true`, run OSV against `DEPENDENCY_SCAN_PATH` each cycle |
| `DEPENDENCY_SCAN_PATH` | `/workspace` | Repo path mounted into the scanner container for OSV source scans |
| `DEPENDENCY_SCAN_ASSET_KEY` | `secplat-repo` | Asset key used for dependency findings |
| `DEPENDENCY_SCAN_ASSET_NAME` | `SecPlat repository` | Display name for the synthetic repository asset |
| `DEPENDENCY_SCAN_ENVIRONMENT` | `dev` | Asset environment if the repository asset must be created |
| `DEPENDENCY_SCAN_CRITICALITY` | `medium` | Asset criticality if the repository asset must be created |
| `OSV_SCANNER_TIMEOUT_SECONDS` | `600` | Max runtime for one OSV scan |
| `TRIVY_SCAN_ENABLED` | `false` | When `true`, run Trivy against `TRIVY_SCAN_PATH` each cycle |
| `TRIVY_SCAN_PATH` | `/workspace` | Repo path mounted into the scanner container for Trivy filesystem scans |
| `TRIVY_SCAN_ASSET_KEY` | `secplat-repo` | Asset key used for Trivy findings |
| `TRIVY_SCAN_ASSET_NAME` | `SecPlat repository` | Display name for the synthetic repository asset |
| `TRIVY_SCAN_ENVIRONMENT` | `dev` | Asset environment if the repository asset must be created |
| `TRIVY_SCAN_CRITICALITY` | `medium` | Asset criticality if the repository asset must be created |
| `TRIVY_SCANNERS` | `vuln,misconfig` | Comma-separated Trivy scanners to run |
| `TRIVY_TIMEOUT_SECONDS` | `1200` | Max runtime for one Trivy scan |

## Checks

- **TLS:** cert expiry (critical if expired, high if &lt; 14 days), verification failure, no HTTPS.
- **Headers:** missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options (each reported as a finding).
- **Dependencies (optional):** `osv-scanner scan source -r <path> --format json`, parsed into repository findings with `vulnerability_id`, package coordinates, fixed version, and structured scanner metadata.
- **Filesystem vulnerability/misconfiguration scan (optional):** `trivy fs --format json --scanners vuln,misconfig <path>`, parsed into dependency-vulnerability and misconfiguration findings with Trivy metadata, package coordinates, and code location context where available.

Findings are upserted by `finding_key` (dedupe); repeat runs update `last_seen`. OSV and Trivy findings that disappear from a later scan of the same source are automatically marked `remediated`.

# Idempotency Keys

Use these key shapes so retries and duplicate messages do not create duplicate records.

| Entity    | Idempotency key formula              | Example / notes                                      |
|----------|--------------------------------------|------------------------------------------------------|
| **Scan** | `{scan_type}+{asset_key}+{period_bucket}` | `web_exposure+api-01+2026-02-17T19` (hour bucket)   |
| **Finding** | `finding_key` (unique per asset+category+title hash or external id) | Store in DB; reject duplicate POST with same key   |
| **Incident** | `incident_key` (e.g. asset_key + window start) | Correlation engine dedupes by this                  |

- **Scans:** When enqueueing from API, include `period_bucket` (e.g. hour) so the same scan in the same window is not enqueued twice.
- **Findings:** API `POST /findings` should accept optional `finding_key`; if present and already exists, return 200 + existing record instead of 201.
- **Incidents:** Correlator creates one incident per `incident_key`; updates append to timeline.

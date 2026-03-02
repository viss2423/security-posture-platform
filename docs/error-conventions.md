# Error Conventions (Retryable vs Non-Retryable)

This document defines error response shape and retry guidance for SecPlat services.

## Response Shape (API)

All API error responses follow this structure:

```json
{
  "error": {
    "message": "Human-readable summary",
    "status_code": 400,
    "retryable": false,
    "detail": "Optional detail (string or object)",
    "request_id": "Optional request id"
  }
}
```

Notes:
- `request_id` is set when the request passed through the API (also returned as `X-Request-Id` header).
- `detail` is optional and may be a string or object (validation errors return a list).

## Retry Guidance

Retryable status codes (client MAY retry):
- `408` Request Timeout
- `425` Too Early
- `429` Too Many Requests
- `500` Internal Server Error
- `502` Bad Gateway
- `503` Service Unavailable
- `504` Gateway Timeout

Non-retryable status codes (client SHOULD NOT retry without changes):
- `400` Bad Request
- `401` Unauthorized
- `403` Forbidden
- `404` Not Found
- `409` Conflict (resolve state first)
- `422` Unprocessable Entity (validation error)

## Queue/Worker Conventions

When consuming from Redis streams:
- Transient Redis/network errors should be retried with backoff.
- Malformed payloads should be acknowledged and dropped to avoid poison loops.
- Worker runtime exceptions must not leave jobs in `running` forever.
  - `worker-web` marks the job `failed` with `error="retryable=true|false error=..."`.
  - Redis message is ACKed after the DB job state is finalized.

## Scanner/API Client Conventions

- API clients use retry classification from:
  - `error.retryable` in API JSON responses, when present.
  - status code fallback (`408, 425, 429, 500, 502, 503, 504`).
- Scanner retries retryable failures with exponential backoff (`1s`, `2s`, ...), capped by `SCANNER_HTTP_MAX_ATTEMPTS` (default `3`).
- Non-retryable API failures are logged and dropped (no blind retry loop).

## Logging Conventions

All services emit JSON logs with:
- `ts` (UTC ISO 8601)
- `level`
- `logger`
- `message`
- `service`
- `pid`
- Optional `request_id` (API requests)
- Optional structured fields (`action`, `status`, `retryable`, `asset_key`, `job_id`, etc.) when available.

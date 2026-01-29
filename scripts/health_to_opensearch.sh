#!/usr/bin/env bash
set -euo pipefail

TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

if curl -fsS http://localhost:8000/health >/dev/null; then
  STATUS="up"
  CODE=200
else
  STATUS="down"
  CODE=0
fi

curl -sS -X POST "http://localhost:9200/secplat-events/_doc" \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "'"$TS"'",
    "service": "api",
    "level": "health",
    "message": "healthcheck",
    "status": "'"$STATUS"'",
    "code": '"$CODE"'
  }' >/dev/null

curl -sS -X POST "http://localhost:9200/secplat-events/_refresh" >/dev/null

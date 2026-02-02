#!/usr/bin/env bash
set -euo pipefail

OPENSEARCH_URL="http://localhost:9200"
INDEX="secplat-events"
HEALTH_URL="http://localhost:8000/health"

TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# Measure latency and capture HTTP status code
START_MS="$(date +%s%3N || true)"
RAW_CODE="$(curl -sS -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null || true)"
if [[ "$RAW_CODE" == "200" ]]; then
  CODE=200
  STATUS="up"
  STATUS_NUM=1
else
  CODE=0
  STATUS="down"
  STATUS_NUM=0
fi

if [[ -z "${CODE}" ]]; then CODE="000"; fi
END_MS="$(date +%s%3N || true)"

# Fallback if %3N unsupported
if [[ -z "${START_MS}" || -z "${END_MS}" || "${START_MS}" == *N || "${END_MS}" == *N ]]; then
  LATENCY_MS=0
else
  LATENCY_MS=$((END_MS - START_MS))
fi

if [[ "$CODE" == "200" ]]; then
  STATUS="up"
  STATUS_NUM=1
else
  STATUS="down"
  STATUS_NUM=0
fi

curl -sS -X POST "${OPENSEARCH_URL}/${INDEX}/_doc" \
  -H 'Content-Type: application/json' \
  -d "{
    \"@timestamp\": \"${TS}\",
    \"service\": \"api\",
    \"asset\": \"secplat-api\",
    \"level\": \"health\",
    \"message\": \"healthcheck\",
    \"status\": \"${STATUS}\",
    \"status_num\": ${STATUS_NUM},
    \"code\": ${CODE},
    \"latency_ms\": ${LATENCY_MS}
  }" >/dev/null

curl -sS -X POST "${OPENSEARCH_URL}/${INDEX}/_refresh" >/dev/null


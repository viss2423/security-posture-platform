#!/usr/bin/env bash
set -euo pipefail

OPENSEARCH_URL="${OPENSEARCH_URL:-http://localhost:9200}"
INDEX="${INDEX:-secplat-events}"
HEALTH_URL="${JUICE_URL:-${EXAMPLE_COM_URL:-http://localhost:3000}}"
ASSET="${JUICE_ASSET:-juice-shop}"
SERVICE="${JUICE_SERVICE:-juice-shop}"

TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_MS=$(date +%s%3N 2>/dev/null || echo $(date +%s)000)
START_MS=${START_MS:-0}

# Capture exit code: curl returns 0 on HTTP 200, non-zero on connection failure/timeout
CURL_OUT=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 5 "$HEALTH_URL" 2>/dev/null) || true
CODE="${CURL_OUT:-000}"
# Treat empty, 000, or any non-2xx as down
if [[ "$CODE" == "200" ]]; then
  STATUS="up"
  STATUS_NUM=1
else
  STATUS="down"
  STATUS_NUM=-2
  CODE=0
fi

END_MS=$(date +%s%3N 2>/dev/null || echo $(date +%s)000)
END_MS=${END_MS:-0}
LATENCY_MS=$((END_MS - START_MS))
[[ "${LATENCY_MS:-0}" -lt 0 ]] && LATENCY_MS=0

curl -sS -X POST "${OPENSEARCH_URL}/${INDEX}/_doc" \
  -H 'Content-Type: application/json' \
  -d "{
    \"@timestamp\": \"${TS}\",
    \"service\": \"${SERVICE}\",
    \"asset\": \"${ASSET}\",
    \"level\": \"health\",
    \"message\": \"healthcheck\",
    \"status\": \"${STATUS}\",
    \"status_num\": ${STATUS_NUM},
    \"code\": ${CODE},
    \"latency_ms\": ${LATENCY_MS}
  }" >/dev/null

curl -sS -X POST "${OPENSEARCH_URL}/${INDEX}/_refresh" >/dev/null

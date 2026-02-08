#!/usr/bin/env bash
set -euo pipefail

OPENSEARCH_URL="${OPENSEARCH_URL:-http://localhost:9200}"
INDEX="${INDEX:-secplat-events}"
HEALTH_URL="${JUICE_URL:-${EXAMPLE_COM_URL:-http://localhost:3000}}"
ASSET="${JUICE_ASSET:-juice-shop}"
SERVICE="${JUICE_SERVICE:-juice-shop}"

TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_MS=$(date +%s%3N)

CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" || echo 000)

END_MS=$(date +%s%3N)
LATENCY_MS=$((END_MS - START_MS))

if [[ "$CODE" == "200" ]]; then
  STATUS="up"
  STATUS_NUM=1
else
  STATUS="down"
  STATUS_NUM=-2
fi

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

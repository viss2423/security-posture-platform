#!/usr/bin/env bash
set -euo pipefail

OPENSEARCH_URL="${OPENSEARCH_URL:-http://localhost:9200}"
INDEX="${INDEX:-secplat-events}"

API_HEALTH_URL="${API_HEALTH_URL:-http://localhost:8000/health}"
VERIFY_WEB_URL="${VERIFY_WEB_URL:-http://localhost:8081/.well-known/secplat-verification.txt}"
EXAMPLE_COM_URL="${EXAMPLE_COM_URL:-http://localhost:3000}"

TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

now_ms() {
  # GNU date supports %3N; fallback handled by caller
  date +%s%3N 2>/dev/null || echo ""
}

calc_latency_ms() {
  local start="$1" end="$2"
  if [[ -z "${start}" || -z "${end}" || "${start}" == *N || "${end}" == *N ]]; then
    echo 0
  else
    echo $(( end - start ))
  fi
}

normalize_code() {
  # curl -w "%{http_code}" returns "000" on connection failure.
  local raw="${1:-}"
  if [[ -z "$raw" || "$raw" == "000" ]]; then
    echo 0
  else
    # raw is typically 200, 301, 404, etc.
    echo "$raw"
  fi
}

probe_url() {
  # Args: url
  local url="$1"
  local start_ms end_ms raw_code latency_ms status status_num code

  start_ms="$(now_ms)"
  raw_code="$(curl -sS -o /dev/null -w "%{http_code}" \
    --connect-timeout 2 --max-time 5 \
    "$url" 2>/dev/null || true)"
  end_ms="$(now_ms)"

  latency_ms="$(calc_latency_ms "$start_ms" "$end_ms")"
  code="$(normalize_code "$raw_code")"

  # Treat 2xx/3xx as UP; everything else is DOWN
  if [[ "$raw_code" =~ ^2[0-9]{2}$ || "$raw_code" =~ ^3[0-9]{2}$ ]]; then
    status="up"
    status_num=1
  else
    status="down"
    status_num=-2
  fi

  echo "${status}|${status_num}|${code}|${latency_ms}"
}

post_event() {
  # Args: service asset status status_num code latency_ms
  local service="$1" asset="$2" status="$3" status_num="$4" code="$5" latency_ms="$6"

  curl -sS -X POST "${OPENSEARCH_URL}/${INDEX}/_doc" \
    -H 'Content-Type: application/json' \
    -d "{
      \"@timestamp\": \"${TS}\",
      \"service\": \"${service}\",
      \"asset\": \"${asset}\",
      \"level\": \"health\",
      \"message\": \"healthcheck\",
      \"status\": \"${status}\",
      \"status_num\": ${status_num},
      \"code\": ${code},
      \"latency_ms\": ${latency_ms}
    }" >/dev/null
}

# ---- probes + events ----

# API
api="$(probe_url "$API_HEALTH_URL")"
IFS='|' read -r s sn c lm <<< "$api"
post_event "api" "secplat-api" "$s" "$sn" "$c" "$lm"

# verify-web
vw="$(probe_url "$VERIFY_WEB_URL")"
IFS='|' read -r s sn c lm <<< "$vw"
post_event "verify-web" "verify-web" "$s" "$sn" "$c" "$lm"

# example.com
ex="$(probe_url "$EXAMPLE_COM_URL")"
IFS='|' read -r s sn c lm <<< "$ex"
post_event "example-com" "example-com" "$s" "$sn" "$c" "$lm"

# Refresh index so searches see events immediately
curl -sS -X POST "${OPENSEARCH_URL}/${INDEX}/_refresh" >/dev/null

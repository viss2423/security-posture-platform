#!/usr/bin/env bash
set -euo pipefail

# URLs when running inside Docker Compose network
API_URL="${API_URL:-http://api:8000}"
OS_URL="${OS_URL:-http://opensearch:9200}"
VERIFY_WEB_URL="${VERIFY_WEB_URL:-http://verify-web/.well-known/secplat-verification.txt}"
JUICE_URL="${JUICE_URL:-http://juiceshop:3000}"
API_AUTH_USERNAME="${API_AUTH_USERNAME:-${ADMIN_USERNAME:-}}"
API_AUTH_PASSWORD="${API_AUTH_PASSWORD:-${ADMIN_PASSWORD:-}}"

export OPENSEARCH_URL="$OS_URL"
export OS_URL
export INDEX="${INDEX:-secplat-events}"
export ASSETS_INDEX="${ASSETS_INDEX:-secplat-assets}"
export EVENTS_INDEX="${EVENTS_INDEX:-secplat-events}"
export STATUS_INDEX="${STATUS_INDEX:-secplat-asset-status}"
export API_BASE_URL="${API_URL%/}"
export API_URL="${API_BASE_URL}/assets/"
export API_HEALTH_URL="${API_BASE_URL}/health"
export VERIFY_WEB_URL
# example-com probes this URL (default: example.com so it's independent of juice-shop)
export EXAMPLE_COM_URL="${EXAMPLE_COM_URL:-https://example.com}"

get_api_token() {
  if [[ -z "${API_AUTH_USERNAME}" || -z "${API_AUTH_PASSWORD}" ]]; then
    return 0
  fi
  curl -sS -X POST "${API_BASE_URL}/auth/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "username=${API_AUTH_USERNAME}" \
    --data-urlencode "password=${API_AUTH_PASSWORD}" | jq -r '.access_token // empty'
}

API_BEARER_TOKEN=""
export API_BEARER_TOKEN

refresh_api_token() {
  local refreshed
  refreshed="$(get_api_token || true)"
  if [[ -n "${refreshed}" ]]; then
    export API_BEARER_TOKEN="${refreshed}"
  fi
}

echo "[ingestion] waiting for API and OpenSearch..."
until curl -sf --connect-timeout 2 "$API_HEALTH_URL" >/dev/null 2>&1; do
  echo "[ingestion] API not ready, retrying..."
  sleep 3
done
until curl -sf --connect-timeout 2 "$OS_URL" >/dev/null 2>&1; do
  echo "[ingestion] OpenSearch not ready, retrying..."
  sleep 3
done
echo "[ingestion] API and OpenSearch up."

refresh_api_token

# Seed default assets if none exist (so build_asset_status has something to work with)
seed_assets() {
  local count
  local assets_json
  local auth_args=()
  if [[ -n "${API_BEARER_TOKEN:-}" ]]; then
    auth_args=(-H "Authorization: Bearer ${API_BEARER_TOKEN}")
  fi
  assets_json="$(curl -sS "${auth_args[@]}" "$API_URL")"
  count="$(echo "$assets_json" | jq -r 'if type == "array" then length else -1 end' 2>/dev/null || echo -1)"
  if [[ "$count" -lt 0 ]]; then
    echo "[ingestion] unable to read assets from API. Configure API_AUTH_USERNAME/API_AUTH_PASSWORD for protected /assets."
    echo "$assets_json"
    return 1
  fi
  if [[ -z "$count" || "$count" == "null" || "$count" -eq 0 ]]; then
    echo "[ingestion] seeding default assets..."
    for key in "secplat-api" "verify-web" "example-com" "juice-shop"; do
      curl -sS -X POST "${API_URL}" \
        -H "Content-Type: application/json" \
        "${auth_args[@]}" \
        -d "{\"asset_key\":\"$key\",\"type\":\"app\",\"name\":\"$key\",\"asset_type\":\"service\"}" >/dev/null || true
    done
    echo "[ingestion] seed done."
  fi
}
seed_assets

INTERVAL="${INGESTION_INTERVAL:-60}"
echo "[ingestion] running scripts every ${INTERVAL}s..."

# When deriver is running (profile roadmap), set SKIP_BUILD_ASSET_STATUS=true so only deriver writes asset-status
SKIP_BUILD_ASSET_STATUS="${SKIP_BUILD_ASSET_STATUS:-false}"

while true; do
  refresh_api_token
  INDEX=secplat-assets /app/scripts/assets_to_opensearch.sh || true
  /app/scripts/health_to_opensearch.sh || true
  /app/scripts/juice_health_to_opensearch.sh || true
  if [ "$SKIP_BUILD_ASSET_STATUS" != "true" ]; then
    /app/scripts/build_asset_status.sh || true
  fi
  sleep "$INTERVAL"
done

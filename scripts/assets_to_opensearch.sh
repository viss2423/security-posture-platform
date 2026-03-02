#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:8000/assets/}"
API_BASE_URL="${API_BASE_URL:-${API_URL%/assets/}}"
if [[ "${API_BASE_URL}" == "${API_URL}" ]]; then
  API_BASE_URL="${API_URL%/assets}"
fi
OS_URL="${OS_URL:-http://localhost:9200}"
INDEX="${INDEX:-secplat-assets}"
API_AUTH_USERNAME="${API_AUTH_USERNAME:-${ADMIN_USERNAME:-}}"
API_AUTH_PASSWORD="${API_AUTH_PASSWORD:-${ADMIN_PASSWORD:-}}"
API_BEARER_TOKEN="${API_BEARER_TOKEN:-}"

get_api_token() {
  if [[ -n "${API_BEARER_TOKEN}" ]]; then
    echo "${API_BEARER_TOKEN}"
    return 0
  fi
  if [[ -z "${API_AUTH_USERNAME}" || -z "${API_AUTH_PASSWORD}" ]]; then
    return 0
  fi
  curl -sS -X POST "${API_BASE_URL}/auth/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "username=${API_AUTH_USERNAME}" \
    --data-urlencode "password=${API_AUTH_PASSWORD}" | jq -r '.access_token // empty'
}

AUTH_TOKEN="$(get_api_token || true)"
AUTH_ARGS=()
if [[ -n "${AUTH_TOKEN}" ]]; then
  AUTH_ARGS=(-H "Authorization: Bearer ${AUTH_TOKEN}")
fi

# Fetch assets from API
assets_json="$(curl -sS "${AUTH_ARGS[@]}" "$API_URL")"

# Basic sanity check
if [[ -z "$assets_json" || "$assets_json" == "null" ]]; then
  echo "No assets returned from API"
  exit 1
fi
if ! echo "$assets_json" | jq -e 'type == "array"' >/dev/null 2>&1; then
  echo "API /assets did not return an array. Set API_AUTH_USERNAME/API_AUTH_PASSWORD or API_BEARER_TOKEN."
  echo "$assets_json"
  exit 1
fi

# Iterate assets with jq
echo "$assets_json" | jq -c '.[]' | while read -r asset; do
  asset_key="$(echo "$asset" | jq -r '.asset_key')"
  if [[ -z "$asset_key" || "$asset_key" == "null" ]]; then
    echo "Skipping asset without asset_key: $asset"
    continue
  fi

  # Upsert using _id = asset_key
  curl -sS -X PUT "$OS_URL/$INDEX/_doc/$asset_key" \
    -H "Content-Type: application/json" \
    -d "$asset" > /dev/null

  echo "upserted asset_key=$asset_key"
done

# Refresh so Grafana can see immediately
curl -sS -X POST "$OS_URL/$INDEX/_refresh" > /dev/null
echo "refreshed index=$INDEX"

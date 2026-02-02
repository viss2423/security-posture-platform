#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:8000/assets/}"
OS_URL="${OS_URL:-http://localhost:9200}"
INDEX="${INDEX:-secplat-assets}"

# Fetch assets from API
assets_json="$(curl -sS "$API_URL")"

# Basic sanity check
if [[ -z "$assets_json" || "$assets_json" == "null" ]]; then
  echo "No assets returned from API"
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


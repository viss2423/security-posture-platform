#!/usr/bin/env bash
# Validate secplat-asset-status documents have required posture fields.
# Run after: health_to_opensearch.sh, build_asset_status.sh (and assets in secplat-assets).
set -euo pipefail

OS_URL="${OS_URL:-http://localhost:9200}"
STATUS_INDEX="${STATUS_INDEX:-secplat-asset-status}"

echo "=== Validating $STATUS_INDEX ==="

# Fetch one doc
doc="$(curl -sS "$OS_URL/$STATUS_INDEX/_search?size=1&pretty" \
  -H "Content-Type: application/json" \
  -d '{"query":{"match_all":{}}}')"

if echo "$doc" | jq -e '.hits.total.value == 0' >/dev/null 2>&1; then
  echo "WARN: No documents in $STATUS_INDEX. Run assets_to_opensearch.sh then build_asset_status.sh."
  exit 1
fi

src="$(echo "$doc" | jq -r '.hits.hits[0]._source')"
missing=""

for field in asset_key status status_num last_seen posture_score posture_state staleness_seconds last_status_change; do
  if ! echo "$src" | jq -e ".\"$field\"" >/dev/null 2>&1; then
    missing="$missing $field"
  fi
done

if [[ -n "$missing" ]]; then
  echo "FAIL: Missing fields:$missing"
  echo "Sample _source:"
  echo "$src" | jq .
  exit 1
fi

echo "OK: Required posture fields present."
echo "Sample document:"
echo "$src" | jq '{ asset_key, status, status_num, posture_score, posture_state, last_seen, staleness_seconds, last_status_change }'
